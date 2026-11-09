# modules/db_file_hunter.py

import re
import time
import random
import hashlib
import itertools
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Target catalogue
# ---------------------------------------------------------------------------
#
# Every entry is a tuple:
#   (path, category, severity, evidence_patterns, description)
#
# evidence_patterns — list of regex strings matched against response body.
# An empty list means "any 200 response at this path is a hit."
# ---------------------------------------------------------------------------

_DB_TARGETS: List[Tuple[str, str, str, List[str], str]] = [

    # ── SQL dumps ──────────────────────────────────────────────────────────
    ("/dump.sql",          "sql_dump",   "critical",
     [r"(CREATE TABLE|INSERT INTO|DROP TABLE|USE \w+;)"],
     "SQL dump at root"),
    ("/backup.sql",        "sql_dump",   "critical",
     [r"(CREATE TABLE|INSERT INTO|DROP TABLE)"],
     "SQL backup dump"),
    ("/database.sql",      "sql_dump",   "critical",
     [r"(CREATE TABLE|INSERT INTO)"],
     "Generic database SQL file"),
    ("/db.sql",            "sql_dump",   "critical",
     [r"(CREATE TABLE|INSERT INTO)"],
     "Short-name SQL dump"),
    ("/data.sql",          "sql_dump",   "critical",
     [r"(CREATE TABLE|INSERT INTO)"],
     "Data export SQL file"),
    ("/export.sql",        "sql_dump",   "critical",
     [r"(CREATE TABLE|INSERT INTO)"],
     "SQL export"),
    ("/schema.sql",        "sql_dump",   "high",
     [r"(CREATE TABLE|ALTER TABLE|CREATE INDEX)"],
     "Database schema file"),
    ("/migrations.sql",    "sql_dump",   "high",
     [r"(CREATE TABLE|ALTER TABLE)"],
     "Migration SQL file"),
    ("/install.sql",       "sql_dump",   "high",
     [r"(CREATE TABLE|INSERT INTO)"],
     "Installer SQL file"),
    ("/setup.sql",         "sql_dump",   "high",
     [r"(CREATE TABLE|INSERT INTO)"],
     "Setup SQL file"),

    # ── SQLite databases ───────────────────────────────────────────────────
    ("/db.sqlite",         "sqlite",     "critical",
     [r"SQLite format 3|\x53\x51\x4c\x69"],
     "SQLite database file"),
    ("/db.sqlite3",        "sqlite",     "critical",
     [r"SQLite format 3"],
     "SQLite3 database file"),
    ("/database.sqlite",   "sqlite",     "critical",
     [r"SQLite format 3"],
     "SQLite database (named)"),
    ("/database.sqlite3",  "sqlite",     "critical",
     [r"SQLite format 3"],
     "SQLite3 database (named)"),
    ("/data.db",           "sqlite",     "critical",
     [r"SQLite format 3"],
     "Generic .db file"),
    ("/app.db",            "sqlite",     "critical",
     [r"SQLite format 3"],
     "Application SQLite db"),
    ("/storage.db",        "sqlite",     "critical",
     [r"SQLite format 3"],
     "Storage SQLite db"),
    ("/users.db",          "sqlite",     "critical",
     [r"SQLite format 3"],
     "User SQLite database"),
    ("/production.sqlite3","sqlite",     "critical",
     [r"SQLite format 3"],
     "Production SQLite database"),

    # ── JSON data dumps ────────────────────────────────────────────────────
    ("/db.json",           "json_dump",  "critical",
     [r'(\[\s*\{|\{\s*"(id|_id|user|email|password|hash|token)")',],
     "JSON database dump"),
    ("/database.json",     "json_dump",  "critical",
     [r'(\[\s*\{|\{\s*"(id|_id|user|email)")'],
     "JSON database export"),
    ("/data.json",         "json_dump",  "high",
     [r'(\[\s*\{|\{\s*"(id|_id|name|email)")'],
     "JSON data export"),
    ("/export.json",       "json_dump",  "high",
     [r'(\[\s*\{|\{\s*"(id|user|email|name)")'],
     "JSON export file"),
    ("/users.json",        "json_dump",  "critical",
     [r'("(email|username|password|hash|token)")',],
     "User data JSON dump"),
    ("/accounts.json",     "json_dump",  "critical",
     [r'("(email|username|password|hash)")'],
     "Account data JSON dump"),
    ("/backup.json",       "json_dump",  "high",
     [r'(\[\s*\{|\{\s*")'],
     "JSON backup"),
    ("/config.json",       "json_dump",  "high",
     [r'("(password|secret|key|token|db_|database)")',],
     "Config JSON with secrets"),
    ("/settings.json",     "json_dump",  "high",
     [r'("(password|secret|key|api_key|database)")',],
     "Settings JSON"),
    ("/credentials.json",  "json_dump",  "critical",
     [r'("(password|secret|key|token|credential)")'],
     "Credentials JSON file"),
    ("/secrets.json",      "json_dump",  "critical",
     [r'("(password|secret|key|token|api)")'],
     "Secrets JSON file"),
    ("/.firebase.json",    "json_dump",  "high",
     [r'"(database|storage|hosting)"'],
     "Firebase config"),
    ("/firebase.json",     "json_dump",  "high",
     [r'"(database|storage|hosting)"'],
     "Firebase config (public)"),

    # ── MongoDB / BSON / NoSQL dumps ───────────────────────────────────────
    ("/dump.bson",         "nosql_dump", "critical",
     [],
     "MongoDB BSON dump"),
    ("/backup.bson",       "nosql_dump", "critical",
     [],
     "MongoDB BSON backup"),
    ("/mongodump.gz",      "nosql_dump", "critical",
     [r"\x1f\x8b"],          # gzip magic
     "MongoDB gzipped dump"),
    ("/dump.json",         "nosql_dump", "critical",
     [r'("_id"\s*:|"\$oid")'],
     "MongoDB JSON export"),
    ("/mongoexport.json",  "nosql_dump", "critical",
     [r'("_id"\s*:|"\$oid")'],
     "mongoexport output"),

    # ── CSV / TSV data exports ─────────────────────────────────────────────
    ("/users.csv",         "csv_export", "critical",
     [r"(email|username|password|phone|address)",],
     "User CSV export"),
    ("/accounts.csv",      "csv_export", "critical",
     [r"(email|username|password|account)",],
     "Accounts CSV export"),
    ("/customers.csv",     "csv_export", "high",
     [r"(email|phone|address|customer)",],
     "Customer CSV export"),
    ("/export.csv",        "csv_export", "high",
     [r"(email|id|name|phone)"],
     "Generic CSV export"),
    ("/data.csv",          "csv_export", "high",
     [r"(email|id|name)"],
     "Data CSV export"),
    ("/backup.csv",        "csv_export", "high",
     [],
     "CSV backup"),
    ("/orders.csv",        "csv_export", "high",
     [r"(order|amount|total|address)"],
     "Order CSV export"),
    ("/transactions.csv",  "csv_export", "high",
     [r"(amount|total|transaction|payment)"],
     "Transaction CSV export"),

    # ── XML / XLS data exports ─────────────────────────────────────────────
    ("/export.xml",        "xml_export", "high",
     [r"(<(user|account|email|password|record))",],
     "XML data export"),
    ("/data.xml",          "xml_export", "high",
     [r"(<(user|account|email|record))",],
     "XML data file"),
    ("/backup.xml",        "xml_export", "high",
     [r"(<(user|account|data|record))"],
     "XML backup"),
    ("/users.xml",         "xml_export", "critical",
     [r"(<(user|email|password|username))"],
     "Users XML export"),
    ("/data.xlsx",         "xls_export", "high",
     [r"PK\x03\x04"],        # OOXML zip magic
     "Excel data export"),
    ("/export.xlsx",       "xls_export", "high",
     [r"PK\x03\x04"],
     "Excel export"),
    ("/users.xlsx",        "xls_export", "critical",
     [r"PK\x03\x04"],
     "Users Excel file"),

    # ── Archive / compressed backups ───────────────────────────────────────
    ("/backup.tar.gz",     "archive",    "critical",
     [r"\x1f\x8b"],
     "Compressed backup (tgz)"),
    ("/backup.zip",        "archive",    "critical",
     [r"PK\x03\x04"],
     "Zipped backup"),
    ("/db_backup.zip",     "archive",    "critical",
     [r"PK\x03\x04"],
     "Database backup ZIP"),
    ("/database_backup.zip","archive",   "critical",
     [r"PK\x03\x04"],
     "Database backup ZIP (named)"),
    ("/sql_backup.zip",    "archive",    "critical",
     [r"PK\x03\x04"],
     "SQL backup ZIP"),
    ("/dump.tar.gz",       "archive",    "critical",
     [r"\x1f\x8b"],
     "Dump tarball"),
    ("/data.tar.gz",       "archive",    "critical",
     [r"\x1f\x8b"],
     "Data tarball"),
    ("/backup.tar",        "archive",    "critical",
     [],
     "Uncompressed tar backup"),
    ("/backup.7z",         "archive",    "critical",
     [r"7z\xbc\xaf\x27\x1c"],  # 7-zip magic
     "7-Zip backup"),

    # ── Environment / config leaks with DB credentials ─────────────────────
    ("/.env",              "env_config", "critical",
     [r"(DB_PASSWORD|DB_HOST|DB_NAME|DATABASE_URL|MYSQL_|POSTGRES_|MONGO_URI)",],
     ".env file with DB credentials"),
    ("/.env.local",        "env_config", "critical",
     [r"(DB_PASSWORD|DB_HOST|DATABASE_URL)"],
     ".env.local with DB credentials"),
    ("/.env.production",   "env_config", "critical",
     [r"(DB_PASSWORD|DB_HOST|DATABASE_URL)"],
     "Production .env"),
    ("/.env.backup",       "env_config", "critical",
     [r"(DB_PASSWORD|DB_HOST|DATABASE_URL)"],
     "Backup .env"),
    ("/config/database.yml","env_config","critical",
     [r"(password|username|database|host|adapter)",],
     "Rails database.yml"),
    ("/config/database.yaml","env_config","critical",
     [r"(password|username|database|host)"],
     "Database YAML config"),
    ("/config/db.php",     "env_config", "critical",
     [r"(DB_HOST|DB_USER|DB_PASS|mysqli|PDO|pg_connect)",],
     "PHP database config"),
    ("/application.properties","env_config","critical",
     [r"(spring\.datasource|db\.url|db\.password|jdbc:)"],
     "Spring Boot DB config"),
    ("/application.yml",   "env_config", "critical",
     [r"(datasource|username|password|url.*jdbc)"],
     "Spring Boot YAML config"),
    ("/wp-config.php",     "env_config", "critical",
     [r"(DB_PASSWORD|DB_NAME|DB_HOST|DB_USER)"],
     "WordPress DB config"),
    ("/config.php",        "env_config", "critical",
     [r"(DB_HOST|DB_USER|DB_PASS|mysql_connect|PDO)"],
     "PHP config with DB"),
    ("/includes/config.php","env_config","critical",
     [r"(DB_HOST|DB_USER|DB_PASS|mysql_connect)"],
     "PHP includes config"),
    ("/config/config.php", "env_config", "critical",
     [r"(DB_HOST|DB_USER|DB_PASS|database)"],
     "Nested PHP config"),
    ("/settings.py",       "env_config", "high",
     [r"(DATABASES|ENGINE.*django\.db|PASSWORD|HOST|NAME)",],
     "Django settings with DB"),
    ("/local_settings.py", "env_config", "high",
     [r"(DATABASES|PASSWORD|HOST)"],
     "Django local settings"),

    # ── phpMyAdmin / DB admin interface exposure ───────────────────────────
    ("/phpmyadmin/",       "admin_panel","high",
     [r"(phpMyAdmin|Welcome to phpMyAdmin|pma_)",],
     "phpMyAdmin exposed"),
    ("/pma/",              "admin_panel","high",
     [r"(phpMyAdmin|pma_)"],
     "phpMyAdmin (short path)"),
    ("/phpmyadmin/index.php","admin_panel","high",
     [r"(phpMyAdmin|pma_)"],
     "phpMyAdmin index"),
    ("/adminer.php",       "admin_panel","high",
     [r"(Adminer|adminer)",],
     "Adminer DB panel"),
    ("/adminer/",          "admin_panel","high",
     [r"(Adminer|adminer)"],
     "Adminer directory"),
    ("/db/",               "admin_panel","medium",
     [r"(phpMyAdmin|Adminer|pgAdmin|database)"],
     "Generic /db/ endpoint"),

    # ── Redis / Elasticsearch / NoSQL HTTP APIs ────────────────────────────
    ("/:6379",             "nosql_api",  "critical",
     [r"(PONG|\+PONG|ERR|redis_version)"],
     "Redis port via HTTP path (unusual exposure)"),
    ("/_cat/indices",      "nosql_api",  "critical",
     [r"(health|status|index|green|yellow|red)"],
     "Elasticsearch index list"),
    ("/_nodes",            "nosql_api",  "critical",
     [r"(\"cluster_name\"|\"number_of_nodes\"|\"version\")"],
     "Elasticsearch nodes info"),
    ("/_cluster/health",   "nosql_api",  "high",
     [r"(\"cluster_name\"|\"status\"\s*:\s*\"(green|yellow|red)\")"],
     "Elasticsearch cluster health"),
    ("/_all/_search",      "nosql_api",  "critical",
     [r"(\"hits\"\s*:|\"_index\"\s*:|\"_source\"\s*:)"],
     "Elasticsearch wildcard search"),
    ("/solr/admin/cores",  "nosql_api",  "high",
     [r"(\"status\"\s*:|\"responseHeader\")"],
     "Apache Solr cores exposed"),
    ("/couchdb/_all_dbs",  "nosql_api",  "critical",
     [r"\[\".*\"\]"],
     "CouchDB database list"),

    # ── Log files that may contain queries / credentials ───────────────────
    ("/logs/db.log",       "log_file",   "high",
     [r"(SELECT|INSERT|UPDATE|DELETE|ERROR|password|Exception)"],
     "Database log file"),
    ("/log/db.log",        "log_file",   "high",
     [r"(SELECT|INSERT|UPDATE|DELETE|ERROR)"],
     "DB log (alt path)"),
    ("/logs/error.log",    "log_file",   "high",
     [r"(SQL|mysqli|PDO|ORA-|postgres|mongo|redis)"],
     "Error log with DB traces"),
    ("/storage/logs/laravel.log","log_file","high",
     [r"(SQLSTATE|Illuminate\\Database|PDOException)"],
     "Laravel log with SQL errors"),
    ("/var/log/mysql/",    "log_file",   "high",
     [],
     "MySQL log directory listing"),
]

# ---------------------------------------------------------------------------
# Path mutation engine
# ---------------------------------------------------------------------------

_DATE_VARIANTS = [
    "2023", "2024", "2025",
    "2024-01", "2024-06", "2024-12",
    "20240101", "20241231",
]

_PREFIX_VARIANTS = ["", "old_", "new_", "bak_", "backup_", "old-", "backup-"]
_SUFFIX_VARIANTS = ["", ".bak", ".old", ".1", ".orig", ".save", "~"]

_COMMON_PREFIXES_DIRS = [
    "", "/backup", "/backups", "/bak", "/db", "/database",
    "/data", "/dumps", "/sql", "/files", "/private", "/archive",
    "/old", "/temp", "/tmp",
]


def _generate_mutations(base_targets: List[Tuple]) -> List[Tuple]:
    """
    For every target path, generate common naming mutations:
    date suffixes, backup prefixes, directory variations.
    Returns a deduplicated extended target list with the same tuple shape.
    """
    seen: Set[str] = set()
    expanded: List[Tuple] = []
    
    for path, category, severity, patterns, desc in base_targets:
        if path not in seen:
            seen.add(path)
            expanded.append((path, category, severity, patterns, desc))
            
        stem = Path(path).stem
        suffix = "".join(Path(path).suffixes)
        
        # Date-stamped variants: /backup_2024.sql, /dump_20240101.sql
        for date in _DATE_VARIANTS:
            for sep in ("-", "_", "."):
                for order in [f"{stem}{sep}{date}{suffix}", f"{date}{sep}{stem}{suffix}"]:
                    p = "/" + order.lstrip("/")
                    if p not in seen:
                        seen.add(p)
                        expanded.append((p, category, severity, patterns, f"{desc} (date variant)"))

        # Prefix mutations within the same directory segment
        for pfx in _PREFIX_VARIANTS:
            if pfx:
                p = f"/{pfx}{path.lstrip('/')}"
                if p not in seen:
                    seen.add(p)
                    expanded.append((p, category, severity, patterns, f"{desc} (prefix variant)"))

        # Extension mutations: .bak, .old, .orig
        for sfx in _SUFFIX_VARIANTS:
            if sfx:
                p = f"{path}{sfx}"
                if p not in seen:
                    seen.add(p)
                    expanded.append((p, category, severity, patterns, f"{desc} (ext variant)"))

    return expanded


def _prefix_dir_variants(targets: List[Tuple]) -> Iterator[Tuple]:
    """Yield targets under common backup/data sub-directories."""
    for path, category, severity, patterns, desc in targets:
        for prefix in _COMMON_PREFIXES_DIRS:
            if prefix:
                new_path = prefix.rstrip("/") + "/" + path.lstrip("/")
                yield (new_path, category, severity, patterns, f"{desc} ({prefix})")
            else:
                yield (path, category, severity, patterns, desc)
                
                
# ---------------------------------------------------------------------------
# HTTP session factory
# ---------------------------------------------------------------------------

def _build_session(proxy: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=1, backoff_factor=0.2, status_forcelist=[])
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=25,
        pool_maxsize=50,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "curl/8.7.1",
]


def _ua() -> str:
    return random.choice(_UA_POOL)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DBFileHit:
    url: str
    path: str
    category: str
    severity: str
    description: str
    status: int
    content_length: int
    content_type: Optional[str]
    matched_patterns: List[str]
    snippet: Optional[str]      # first 300 bytes of body, printable chars only
    is_binary: bool
    server: Optional[str]
    accessible: bool            # False when 401/403 (still reported — path disclosed)


# ---------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------

_BINARY_MAGIC: Dict[str, bytes] = {
    "sqlite":  b"SQLite format 3",
    "gzip":    b"\x1f\x8b",
    "zip":     b"PK\x03\x04",
    "7zip":    b"7z\xbc\xaf\x27\x1c",
    "bson":    b"\xd4\x07\x00\x00",   # common first 4 bytes
}


def _detect_binary(content: bytes) -> bool:
    if b"\x00" in content[:512]:
        return True
    try:
        content[:512].decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def _extract_snippet(content: bytes, max_len: int = 300) -> str:
    """Return a printable ASCII snippet from the first *max_len* bytes."""
    sample = content[:max_len]
    return re.sub(r"[^\x20-\x7e\n\r\t]", ".", sample.decode("latin-1"))


def _match_patterns(content: bytes, patterns: List[str]) -> List[str]:
    """Return the subset of patterns that match in *content*."""
    text = content[:8192].decode("latin-1")
    matched: List[str] = []
    for pat in patterns:
        try:
            if re.search(pat, text, re.I):
                matched.append(pat)
        except re.error:
            pass
    return matched


def _check_binary_magic(content: bytes) -> List[str]:
    """Detect known binary DB formats by magic bytes."""
    matched: List[str] = []
    for name, magic in _BINARY_MAGIC.items():
        if content[:len(magic)] == magic:
            matched.append(f"magic:{name}")
    return matched


# ---------------------------------------------------------------------------
# Baseline false-positive filter
# ---------------------------------------------------------------------------

def _fetch_baseline_hash(session: requests.Session,
                          base_url: str, timeout: float) -> Set[str]:
    """
    Probe two random paths and record their body hashes.
    Used to suppress wildcard-200 responses.
    """
    hashes: Set[str] = set()
    canaries = [
        f"{base_url}/artex_db_canary_{hashlib.md5(b'db1').hexdigest()[:8]}.json",
        f"{base_url}/artex_db_canary_{hashlib.md5(b'db2').hexdigest()[:8]}.sql",
    ]
    for url in canaries:
        try:
            resp = session.get(
                url,
                headers={"User-Agent": _ua()},
                timeout=timeout,
                allow_redirects=True,
            )
            if resp.status_code == 200:
                hashes.add(hashlib.md5(resp.content).hexdigest())
        except requests.RequestException:
            pass
    return hashes


# ---------------------------------------------------------------------------
# Core probe worker
# ---------------------------------------------------------------------------

_REPORT_ON_STATUS = {200, 206, 401, 403, 500, 301, 302}


def _probe(
    session: requests.Session,
    base_url: str,
    entry: Tuple[str, str, str, List[str], str],
    timeout: float,
    rate_delay: float,
    wildcard_hashes: Set[str],
) -> Optional[DBFileHit]:
    path, category, severity, patterns, desc = entry

    if rate_delay > 0:
        time.sleep(rate_delay)

    url = base_url.rstrip("/") + path
    try:
        resp = session.get(
            url,
            headers={"User-Agent": _ua()},
            timeout=timeout,
            allow_redirects=True,
            stream=True,          # avoid pulling huge archives into RAM
        )
        # Read up to 64 KB for analysis; avoids OOM on archive downloads
        content = b"".join(itertools.islice(resp.iter_content(1024), 64))
        resp.close()
    except requests.RequestException:
        return None

    if resp.status_code not in _REPORT_ON_STATUS:
        return None

    # Suppress wildcard 200s
    if resp.status_code == 200:
        body_hash = hashlib.md5(content).hexdigest()
        if body_hash in wildcard_hashes:
            return None

    is_bin = _detect_binary(content)
    matched = _match_patterns(content, patterns) if not is_bin else []
    matched += _check_binary_magic(content)

    # For non-binary responses with evidence patterns defined,
    # require at least one match to avoid false positives
    if patterns and not is_bin and not matched and resp.status_code == 200:
        return None

    accessible = resp.status_code not in (401, 403)
    snippet = None if is_bin else _extract_snippet(content)
    ct = resp.headers.get("Content-Type", "").split(";")[0].strip() or None
    server = resp.headers.get("Server") or None

    return DBFileHit(
        url=url,
        path=path,
        category=category,
        severity=severity,
        description=desc,
        status=resp.status_code,
        content_length=int(resp.headers.get("Content-Length", len(content))),
        content_type=ct,
        matched_patterns=matched,
        snippet=snippet,
        is_binary=is_bin,
        server=server,
        accessible=accessible,
    )


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sort_hits(hits: List[DBFileHit]) -> List[DBFileHit]:
    return sorted(hits, key=lambda h: (
        0 if h.accessible else 1,
        _SEV_ORDER.get(h.severity, 9),
        h.url,
    ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class DBFileHunter:
    """
    Database file hunter — scans a web target for exposed database files,
    dumps, configuration files with credentials, and admin panel interfaces.

    Combines a curated target catalogue with a mutation engine that generates
    date-stamped, prefixed, and directory-varied path variants automatically.

    Usage in app.py:
        hunter = DBFileHunter(target_url=f"https://{domain}")
        results = hunter.scan()
        scan_results[scan_id]['db_file_hunter'] = results
    """

    def __init__(
        self,
        target_url: str,
        enable_mutations: bool = True,
        enable_dir_variants: bool = True,
        timeout: float = 7.0,
        max_workers: int = 16,
        rate_delay: float = 0.0,
        proxy: Optional[str] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.enable_mutations = enable_mutations
        self.enable_dir_variants = enable_dir_variants
        self.timeout = timeout
        self.max_workers = max_workers
        self.rate_delay = rate_delay
        self.proxy = proxy

    # ------------------------------------------------------------------
    # Target list construction
    # ------------------------------------------------------------------

    def _build_targets(self) -> List[Tuple]:
        targets = list(_DB_TARGETS)

        if self.enable_mutations:
            targets = _generate_mutations(targets)

        if self.enable_dir_variants:
            targets = list(_prefix_dir_variants(targets))

        # Final dedup on path
        seen: Set[str] = set()
        unique: List[Tuple] = []
        for entry in targets:
            if entry[0] not in seen:
                seen.add(entry[0])
                unique.append(entry)

        return unique

    # ------------------------------------------------------------------
    # Public scan
    # ------------------------------------------------------------------

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = _build_session(self.proxy)
        targets = self._build_targets()

        print(f"[db_hunter] target  : {self.target_url}")
        print(f"[db_hunter] paths   : {len(targets)}")
        print(f"[db_hunter] workers : {self.max_workers}")

        wildcard_hashes = _fetch_baseline_hash(session, self.target_url, self.timeout)
        if wildcard_hashes:
            print(f"[db_hunter] wildcard hashes: {wildcard_hashes}")

        hits: List[DBFileHit] = []
        lock = threading.Lock()
        t0 = time.monotonic()

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures: Dict = {
                ex.submit(
                    _probe,
                    session, self.target_url, entry,
                    self.timeout, self.rate_delay, wildcard_hashes,
                ): entry[0]
                for entry in targets
            }
            for future in as_completed(futures):
                result = future.result()
                if result is None:
                    continue
                with lock:
                    hits.append(result)
                acc = "OPEN" if result.accessible else "AUTH"
                print(
                    f"  [{result.status}][{acc}][{result.severity.upper():<8}] "
                    f"{result.url}"
                    + (f"  match={result.matched_patterns[0][:40]}"
                       if result.matched_patterns else "")
                )

        elapsed = time.monotonic() - t0
        hits = _sort_hits(hits)

        # Category breakdown for summary
        category_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        for h in hits:
            category_counts[h.category] = category_counts.get(h.category, 0) + 1
            severity_counts[h.severity] = severity_counts.get(h.severity, 0) + 1

        accessible_hits = [h for h in hits if h.accessible]
        auth_required = [h for h in hits if not h.accessible]

        return {
            "target": self.target_url,
            "paths_tested": len(targets),
            "total_hits": len(hits),
            "accessible": len(accessible_hits),
            "auth_required": len(auth_required),
            "severity_summary": severity_counts,
            "category_summary": category_counts,
            "elapsed_seconds": round(elapsed, 2),
            "results": [self._serialize(h) for h in hits],
        }

    @staticmethod
    def _serialize(h: DBFileHit) -> Dict:
        return {
            "url": h.url,
            "path": h.path,
            "category": h.category,
            "severity": h.severity,
            "description": h.description,
            "status": h.status,
            "content_length": h.content_length,
            "content_type": h.content_type,
            "matched_patterns": h.matched_patterns,
            "snippet": h.snippet,
            "is_binary": h.is_binary,
            "server": h.server,
            "accessible": h.accessible,
        }