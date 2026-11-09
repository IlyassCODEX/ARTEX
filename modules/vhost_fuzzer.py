# modules/vhost_fuzzer.py

import os
import re
import time
import random
import socket
import hashlib
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Wordlist loader — same convention as dir_bruteforce.py
# ---------------------------------------------------------------------------

_WORDLIST_DIR = Path(__file__).parent.parent / "wordlists"

# Built-in fallback — covers the most common vhost patterns
_BUILTIN_VHOST_WORDS = [
    "admin", "api", "app", "auth", "backend", "beta", "billing",
    "blog", "cdn", "ci", "console", "cp", "dashboard", "db",
    "dev", "devops", "dns", "docs", "download", "email", "erp",
    "exchange", "extranet", "files", "forum", "ftp", "git", "help",
    "hr", "img", "internal", "intranet", "jenkins", "jira", "lab",
    "ldap", "legacy", "log", "logs", "mail", "media", "metrics",
    "mobile", "monitor", "mta", "mx", "mysql", "nagios", "new",
    "noc", "ns1", "ns2", "office", "old", "ops", "panel", "portal",
    "preprod", "prod", "proxy", "qa", "redis", "registry", "relay",
    "remote", "report", "reports", "repo", "owa", "s3", "sandbox",
    "secure", "shop", "smtp", "ssh", "stage", "staging", "static",
    "status", "support", "test", "testing", "tools", "uploads",
    "vault", "vpn", "wiki", "www", "www2", "xml", "zabbix",
]


def _load_vhost_words(directory: Path) -> List[str]:
    """
    Merge every .txt in *directory* into a deduplicated word list.
    Each line is treated as a bare hostname label (no dots).
    Falls back to _BUILTIN_VHOST_WORDS if the folder is absent or empty.
    """
    words: Set[str] = set()

    if directory.is_dir():
        for txt in sorted(directory.glob("*.txt")):
            try:
                with open(txt, "r", encoding="utf-8", errors="ignore") as fh:
                    for raw in fh:
                        word = raw.strip().lstrip("/").split(".")[0]
                        if word and not word.startswith("#"):
                            words.add(word.lower())
                print(f"[vhost] loaded {txt.name} ({len(words)} unique so far)")
            except OSError as exc:
                print(f"[vhost] cannot read {txt}: {exc}")

    if not words:
        words = set(_BUILTIN_VHOST_WORDS)
        print("[vhost] no wordlist files found — using built-in fallback")

    return sorted(words)


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def _build_session(proxy: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=1, backoff_factor=0.2, status_forelist=[])
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connection=30,
        pool_maxsize=60,
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
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]


def _ua() -> str:
    return random.choice(_UA_POOL)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class VHostResult:
    vhost: str                   # full hostname probed  (e.g. "admin.example.com")
    label: str                   # just the prefix word  (e.g. "admin")
    ip: str                      # resolved IP at scan time
    status: int
    content_length: int
    title: Optional[str]
    redirect_to: Optional[str]
    content_type: Optional[str]
    server: Optional[str]
    response_hash: str           # md5 of body — used for dedup
    differential: bool           # True when response differs from baseline
    interesting: bool            # heuristic flag


@dataclass
class BaselineProfile:
    """Fingerprint of the server's response to a non-existent vhost."""
    status: int
    content_length: int
    body_hash: str
    title: Optional[str]
    redirect_target: Optional[str]
    # Lengths seen across multiple canary requests — used for variance filtering
    length_samples: List[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_MAX_TITLE_LEN = 120


def _extract_title(html: str) -> Optional[str]:
    m = _TITLE_RE.search(html)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()[:_MAX_TITLE_LEN]
    return None


def _body_hash(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()


def _probe_raw(session: requests.Session, url: str,
               host_header: str, timeout: float) -> Optional[requests.Response]:
    try:
        return session.get(
            url,
            headers={"Host": host_header, "User-Agent": _ua()},
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None


def _build_baseline(session: requests.Session, target_ip: str,
                    port: int, scheme: str, domain: str,
                    timeout: float) -> BaselineProfile:
    """
    Send three requests with randomised non-existent vhost labels.
    The resulting profile is used to filter wildcard responses.
    """
    canary_labels = [
        f"artex-canary-{hashlib.md5(b'x').hexdigest()[:6]}",
        f"artex-canary-{hashlib.md5(b'y').hexdigest()[:6]}",
        f"artex-canary-{hashlib.md5(b'z').hexdigest()[:6]}",
    ]

    url = f"{scheme}://{target_ip}:{port}"
    profiles: List[dict] = []

    for label in canary_labels:
        host = f"{label}.{domain}"
        resp = _probe_raw(session, url, host, timeout)
        if resp is None:
            continue
        profiles.append({
            "status": resp.status_code,
            "length": len(resp.content),
            "hash": _body_hash(resp.content),
            "title": _extract_title(resp.text),
            "redirect": resp.headers.get("Location"),
        })

    if not profiles:
        # Server didn't respond to canaries — treat everything as potentially valid
        return BaselineProfile(
            status=0, content_length=0, body_hash="",
            title=None, redirect_target=None, length_samples=[],
        )

    # Use the most common status; pick the first profile as representative
    rep = profiles[0]
    return BaselineProfile(
        status=rep["status"],
        content_length=rep["length"],
        body_hash=rep["hash"],
        title=rep["title"],
        redirect_target=rep["redirect"],
        length_samples=[p["length"] for p in profiles],
    )


# ---------------------------------------------------------------------------
# Differential filter
# ---------------------------------------------------------------------------

def _is_differential(resp: requests.Response, baseline: BaselineProfile) -> bool:
    """
    Return True when *resp* is meaningfully different from the baseline profile.
    Uses status code, body hash, and a dynamic length variance band.
    """
    # Different status -> always interesting
    if resp.status_code != baseline.status:
        return True
        
    body = resp.content
    bh = _body_hash(body)
    
    # Same hash -> wildcard response
    if bh == baseline.body_hash:
        return False

    # Length within ±5 % of every sample -> likely wildcard with minor noise
    length = len(body)
    if baseline.length_samples:
        variance_band = max(64, int(min(baseline.length_samples) * 0.05))
        if all(abs(length - s) <= variance_band for s in baseline.length_samples):
            return False
            
    return True
    
    
# ---------------------------------------------------------------------------
# Interest heuristics
# ---------------------------------------------------------------------------

_INTERESTING_LABELS = re.compile(
    r"^(admin|api|app|auth|backend|billing|ci|console|cp|dashboard|"
    r"db|dev|devops|erp|git|hr|internal|intranet|jenkins|jira|ldap|"
    r"legacy|log|logs|mail|monitor|mysql|nagios|noc|ops|panel|portal|"
    r"preprod|prod|redis|registry|sandbox|secure|smtp|ssh|stage|staging|"
    r"support|tools|vault|vpn|wiki|zabbix)$",
    re.I,
)

_INTERESTING_STATUS = {200, 201, 204, 301, 302, 401, 403, 500}

_SENSITIVE_CONTENT_TYPES = {
    "application/json", "application/xml", "text/xml",
    "application/x-www-form-urlencoded",
}


def _flag_interesting(result: VHostResult) -> bool:
    if result.status in _INTERESTING_STATUS:
        return True
    if _INTERESTING_LABELS.match(result.label):
        return True
    ct = (result.content_type or "").split(";")[0].strip()
    if ct in _SENSITIVE_CONTENT_TYPES:
        return True
    return False
    
    
# ---------------------------------------------------------------------------
# DNS resolution helper
# ---------------------------------------------------------------------------

def _resolve_ip(hostname: str, timeout: float = 3.0) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except socket.error:
        return None


# ---------------------------------------------------------------------------
# Core probe worker
# ---------------------------------------------------------------------------

def _probe_vhost(
    session: requests.Session,
    url: str,
    label: str,
    domain: str,
    target_ip: str,
    baseline: BaselineProfile,
    timeout: float,
    rate_delay: float,
) -> Optional[VHostResult]:
    """
    Probe one virtual host by injecting the Host header.
    Returns None when the response matches the baseline (wildcard).
    """
    if rate_delay > 0:
        time.sleep(rate_delay)

    vhost = f"{label}.{domain}"
    resp = _probe_raw(session, url, vhost, timeout)
    if resp is None:
        return None

    if not _is_differential(resp, baseline):
        return None

    length = len(resp.content)
    redirect_to = resp.headers.get("Location") if resp.status_code in (
        301, 302, 303, 307, 308) else None
    ct = resp.headers.get("Content-Type", "").split(";")[0].strip()
    server = resp.headers.get("Server")
    title = _extract_title(resp.text)
    rhash = _body_hash(resp.content)

    # Attempt DNS resolution to check if the vhost also resolves publicly
    resolved_ip = _resolve_ip(vhost)

    result = VHostResult(
        vhost=vhost,
        label=label,
        ip=resolved_ip or target_ip,
        status=resp.status_code,
        content_length=length,
        title=title,
        redirect_to=redirect_to,
        content_type=ct,
        server=server,
        response_hash=rhash,
        differential=True,
        interesting=False,
    )
    result.interesting = _flag_interesting(result)
    return result


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _dedup(results: List[VHostResult]) -> List[VHostResult]:
    """
    Remove results whose body hash matches an already-seen entry.
    Different vhosts may serve identical content — only the first is kept.
    """
    seen_hashes: Set[str] = set()
    unique: List[VHostResult] = []
    for r in results:
        if r.response_hash not in seen_hashes:
            seen_hashes.add(r.response_hash)
            unique.append(r)
    return unique


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class VHostFuzzer:
    """
    Virtual host fuzzer via Host header injection.

    Sends all requests to the server's IP directly and rotates the
    Host header through a wordlist-derived set of candidate vhosts.
    Baseline filtering strips wildcard responses before results are returned.

    Usage in app.py:
        fuzzer = VHostFuzzer(domain=domain, target_ip=resolved_ip)
        results = fuzzer.scan()
        scan_results[scan_id]['vhost_fuzzer'] = results
    """

    def __init__(
        self,
        domain: str,
        target_ip: Optional[str] = None,
        port: int = 443,
        scheme: str = "https",
        wordlist_dir: Optional[str] = None,
        extra_labels: Optional[List[str]] = None,
        timeout: float = 7.0,
        max_workers: int = 20,
        rate_delay: float = 0.0,
        proxy: Optional[str] = None,
    ):
        self.domain = domain
        self.target_ip = target_ip or _resolve_ip(domain) or domain
        self.port = port
        self.scheme = scheme
        self.wordlist_dir = Path(wordlist_dir) if wordlist_dir else _WORDLIST_DIR
        self.extra_labels = extra_labels or []
        self.timeout = timeout
        self.max_workers = max_workers
        self.rate_delay = rate_delay
        self.proxy = proxy

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_label_list(self) -> List[str]:
        words = _load_vhost_words(self.wordlist_dir)
        # Merge wordlist + caller-supplied extras, deduplicate, sort
        combined: Set[str] = set(words) | set(self.extra_labels)
        return sorted(combined)

    # ------------------------------------------------------------------
    # Public scan
    # ------------------------------------------------------------------

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = _build_session(self.proxy)
        labels = self._build_label_list()
        base_url = f"{self.scheme}://{self.target_ip}:{self.port}"

        print(f"[vhost] target  : {self.domain} ({self.target_ip}:{self.port})")
        print(f"[vhost] labels  : {len(labels)}")
        print(f"[vhost] workers : {self.max_workers}")

        # --- Baseline ---
        baseline = _build_baseline(
            session, self.target_ip, self.port,
            self.scheme, self.domain, self.timeout,
        )
        print(
            f"[vhost] baseline: HTTP {baseline.status} | "
            f"{baseline.content_length}B | "
            f"hash={baseline.body_hash[:8]}..."
        )

        # --- Parallel probe ---
        results: List[VHostResult] = []
        lock = threading.Lock()

        t0 = time.monotonic()

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures: Dict = {
                ex.submit(
                    _probe_vhost,
                    session, base_url, label, self.domain,
                    self.target_ip, baseline,
                    self.timeout, self.rate_delay,
                ): label
                for label in labels
            }
            for future in as_completed(futures):
                r = future.result()
                if r is None:
                    continue
                with lock:
                    results.append(r)
                flag = "★" if r.interesting else " "
                print(
                    f"  [{r.status}] {flag} {r.vhost:<50} "
                    f"{r.content_length:>8}B"
                    + (f"  → {r.redirect_to}" if r.redirect_to else "")
                    + (f'  "{r.title}"' if r.title else "")
                )

        elapsed = time.monotonic() - t0

        # --- Post-process ---
        results = _dedup(results)
        results.sort(key=lambda r: (0 if r.interesting else 1, r.status, r.vhost))

        interesting = [r for r in results if r.interesting]
        other = [r for r in results if not r.interesting]

        return {
            "domain": self.domain,
            "target_ip": self.target_ip,
            "port": self.port,
            "scheme": self.scheme,
            "labels_tested": len(labels),
            "baseline": {
                "status": baseline.status,
                "content_length": baseline.content_length,
                "body_hash": baseline.body_hash,
                "title": baseline.title,
            },
            "total_found": len(results),
            "interesting_count": len(interesting),
            "elapsed_seconds": round(elapsed, 2),
            "results": [self._serialize(r) for r in results],
        }

    @staticmethod
    def _serialize(r: VHostResult) -> Dict:
        return {
            "vhost": r.vhost,
            "label": r.label,
            "resolved_ip": r.ip,
            "status": r.status,
            "content_length": r.content_length,
            "title": r.title,
            "redirect_to": r.redirect_to,
            "content_type": r.content_type,
            "server": r.server,
            "interesting": r.interesting,
        }