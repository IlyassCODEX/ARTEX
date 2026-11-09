# modules/clickjacking_checker.py
import re
import time
import random
import hashlib
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Endpoints to check — covers SPAs, admin panels, auth pages
# ---------------------------------------------------------------------------

_PROBE_PATHS: List[Tuple[str, str]] = [
    # (path, label)
    ("/",                    "root"),
    ("/login",               "login"),
    ("/signin",              "signin"),
    ("/admin",               "admin"),
    ("/admin/login",         "admin-login"),
    ("/dashboard",           "dashboard"),
    ("/account",             "account"),
    ("/profile",             "profile"),
    ("/settings",            "settings"),
    ("/password",            "password"),
    ("/password/change",     "password-change"),
    ("/transfer",            "transfer"),
    ("/payment",             "payment"),
    ("/checkout",            "checkout"),
    ("/oauth/authorize",     "oauth-authorize"),
    ("/auth",                "auth"),
    ("/api/v1",              "api-v1"),
    ("/api",                 "api"),
    ("/wp-admin",            "wp-admin"),
    ("/wp-login.php",        "wp-login"),
    ("/phpmyadmin",          "phpmyadmin"),
    ("/panel",               "panel"),
    ("/portal",              "portal"),
    ("/console",             "console"),
    ("/manage",              "manage"),
    ("/user",                "user"),
    ("/register",            "register"),
    ("/delete",              "delete-account"),
    ("/withdraw",            "withdraw"),
    ("/send",                "send"),
    ("/confirm",             "confirm"),
    ("/2fa",                 "2fa"),
    ("/mfa",                 "mfa"),
]

# ---------------------------------------------------------------------------
# XFO / CSP analysis rules
# ---------------------------------------------------------------------------

# XFO values that fully protect against clickjacking
_XFO_SECURE = {"DENY", "SAMEORIGIN"}

# XFO values that are insecure or deprecated
_XFO_INSECURE = {
    "ALLOW-FROM",           # deprecated in modern browsers
    "ALLOWALL",             # non-standard, insecure
    "*",
}

# CSP frame-ancestors patterns
_CSP_FA_RE = re.compile(
    r"frame-ancestors\s+([^;]+?)(?:;|$)", re.I
)

_CSP_FA_SECURE_RE = re.compile(
    r"frame-ancestors\s+(?:'none'|'self')", re.I
)

_CSP_FA_WILDCARD_RE = re.compile(
    r"frame-ancestors\s+(?:\*|http://\*|https://\*)", re.I
)

# Headers that indicate a security-conscious server
_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FrameAnalysis:
    """Analysis of framing protection headers for one HTTP response."""
    url:               str
    path:              str
    label:             str
    status_code:       int
    xfo_header:        Optional[str]       # raw X-Frame-Options value
    xfo_verdict:       str                 # secure / insecure / missing / deprecated
    csp_header:        Optional[str]       # raw Content-Security-Policy
    csp_fa_value:      Optional[str]       # frame-ancestors directive value
    csp_fa_verdict:    str                 # secure / insecure / missing / wildcard
    protected:         bool                # True when effectively protected
    effective_policy:  str                 # which mechanism provides protection
    missing_headers:   List[str]           # other missing security headers
    server:            Optional[str]
    content_type:      Optional[str]
    redirect_to:       Optional[str]


@dataclass
class ClickjackingFinding:
    url:              str
    path:             str
    severity:         str
    attack_type:      str    # missing / deprecated_allow_from / wildcard_csp /
                             # inconsistent / login_unprotected / payment_unprotected
    title:            str
    detail:           str
    evidence:         str
    cwe:              str
    cvss:             float
    poc_html:         Optional[str]        # minimal PoC iframe HTML


@dataclass
class ScanState:
    target_url:  str
    domain:      str
    analyses:    List[FrameAnalysis]
    findings:    List[ClickjackingFinding]
    lock:        threading.Lock = field(default_factory=threading.Lock)


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def _build_session(proxy: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=1, backoff_factor=0.2, status_forcelist=[])
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=20,
        pool_maxsize=40,
    )
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
    })
    return session


def _req(session: requests.Session, url: str,
         timeout: float = 8.0) -> Optional[requests.Response]:
    try:
        return session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None


# ---------------------------------------------------------------------------
# Header analysis
# ---------------------------------------------------------------------------

def _analyse_xfo(value: Optional[str]) -> Tuple[str, bool]:
    """
    Returns (verdict, is_secure).
    Verdicts: 'secure', 'insecure', 'deprecated', 'missing'
    """
    if not value:
        return "missing", False
    upper = value.strip().upper()
    if any(upper.startswith(v) for v in _XFO_SECURE):
        return "secure", True
    if any(upper.startswith(v) for v in _XFO_INSECURE):
        return "deprecated" if "ALLOW-FROM" in upper else "insecure", False
    return "insecure", False


def _analyse_csp_fa(csp_value: Optional[str]) -> Tuple[str, Optional[str], bool]:
    """
    Returns (verdict, fa_value, is_secure).
    Verdicts: 'secure', 'insecure', 'wildcard', 'missing'
    """
    if not csp_value:
        return "missing", None, False

    m = _CSP_FA_RE.search(csp_value)
    if not m:
        return "missing", None, False

    fa_value = m.group(1).strip()

    if _CSP_FA_WILDCARD_RE.search(csp_value):
        return "wildcard", fa_value, False

    if _CSP_FA_SECURE_RE.search(csp_value):
        return "secure", fa_value, True

    # Has frame-ancestors but neither 'none' nor 'self' exclusively
    # Could be "frame-ancestors trusted.com" — treat as partial
    return "partial", fa_value, False


def _effective_protection(
    xfo_verdict: str, xfo_secure: bool,
    csp_verdict: str, csp_secure: bool,
) -> Tuple[bool, str]:
    """
    Determine effective clickjacking protection considering both mechanisms.
    CSP frame-ancestors takes precedence over XFO in modern browsers.
    """
    if csp_secure:
        return True, "CSP frame-ancestors"
    if xfo_secure:
        return True, "X-Frame-Options"
    if csp_verdict == "partial":
        return True, "CSP frame-ancestors (partial)"
    return False, "none"


def _missing_security_headers(headers: Dict[str, str]) -> List[str]:
    missing = []
    hdr_lower = {k.lower(): v for k, v in headers.items()}
    for h in _SECURITY_HEADERS:
        if h.lower() not in hdr_lower:
            missing.append(h)
    return missing


# ---------------------------------------------------------------------------
# Single endpoint analyser
# ---------------------------------------------------------------------------

def _analyse_endpoint(
    session:    requests.Session,
    base_url:   str,
    path:       str,
    label:      str,
    timeout:    float,
    rate_delay: float,
) -> Optional[FrameAnalysis]:
    if rate_delay > 0:
        time.sleep(rate_delay)

    url  = base_url.rstrip("/") + path
    resp = _req(session, url, timeout)
    if not resp or resp.status_code in (404, 410, 400, 429):
        return None

    hdrs        = {k.lower(): v for k, v in resp.headers.items()}
    xfo_raw     = resp.headers.get("X-Frame-Options")
    csp_raw     = resp.headers.get("Content-Security-Policy")
    server      = resp.headers.get("Server")
    ct          = resp.headers.get("Content-Type", "").split(";")[0].strip()
    redirect_to = resp.headers.get("Location") if resp.status_code in (
        301, 302, 303, 307, 308) else None

    xfo_verdict, xfo_secure = _analyse_xfo(xfo_raw)
    csp_verdict, csp_fa, csp_secure = _analyse_csp_fa(csp_raw)
    protected, effective = _effective_protection(
        xfo_verdict, xfo_secure, csp_verdict, csp_secure
    )

    missing = _missing_security_headers(dict(resp.headers))

    return FrameAnalysis(
        url=url,
        path=path,
        label=label,
        status_code=resp.status_code,
        xfo_header=xfo_raw,
        xfo_verdict=xfo_verdict,
        csp_header=csp_raw,
        csp_fa_value=csp_fa,
        csp_fa_verdict=csp_verdict,
        protected=protected,
        effective_policy=effective,
        missing_headers=missing,
        server=server,
        content_type=ct,
        redirect_to=redirect_to,
    )


# ---------------------------------------------------------------------------
# PoC HTML builder
# ---------------------------------------------------------------------------

def _build_poc(target_url: str, path: str) -> str:
    """Generate a minimal clickjacking PoC HTML page."""
    url = target_url.rstrip("/") + path
    return f"""<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title>
<style>
  body {{ margin: 0; }}
  iframe {{
    position: absolute; top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.0001;
    z-index: 2;
  }}
  .decoy {{
    position: absolute; top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    z-index: 1;
    font-size: 24px; cursor: pointer;
    background: #0070f3; color: white;
    padding: 16px 32px; border-radius: 8px;
  }}
</style>
</head>
<body>
  <div class="decoy">Click Here to Win a Prize!</div>
  <iframe src="{url}" scrolling="no" frameborder="0"></iframe>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Finding synthesis
# ---------------------------------------------------------------------------

_HIGH_VALUE_LABELS = {
    "login", "signin", "admin", "admin-login", "dashboard",
    "account", "profile", "settings", "password", "password-change",
    "transfer", "payment", "checkout", "oauth-authorize",
    "2fa", "mfa", "delete-account", "withdraw", "send", "confirm",
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _synthesise_findings(
    analyses: List[FrameAnalysis],
    target_url: str,
) -> List[ClickjackingFinding]:
    findings: List[ClickjackingFinding] = []

    unprotected = [a for a in analyses if not a.protected and a.status_code == 200]
    high_value  = [a for a in unprotected if a.label in _HIGH_VALUE_LABELS]
    other_unprotected = [a for a in unprotected if a.label not in _HIGH_VALUE_LABELS]

    # High-value unprotected pages
    for a in high_value:
        is_auth = a.label in {"login", "signin", "admin", "admin-login",
                              "oauth-authorize", "2fa", "mfa"}
        is_financial = a.label in {"transfer", "payment", "checkout",
                                   "withdraw", "send", "confirm", "delete-account"}
        sev = "critical" if is_financial else "high"
        attack_type = (
            "payment_unprotected" if is_financial else
            "login_unprotected"   if is_auth      else
            "missing"
        )
        findings.append(ClickjackingFinding(
            url=a.url,
            path=a.path,
            severity=sev,
            attack_type=attack_type,
            title=f"Clickjacking on High-Value Page: {a.path}",
            detail=(
                f"The page '{a.path}' ({a.label}) has no effective framing protection. "
                f"X-Frame-Options: {a.xfo_header or 'absent'} | "
                f"CSP frame-ancestors: {a.csp_fa_value or 'absent'}. "
                f"An attacker can embed this page in a transparent iframe "
                f"and trick authenticated users into performing unintended actions."
            ),
            evidence=(
                f"XFO={a.xfo_header!r} CSP-FA={a.csp_fa_value!r} "
                f"status={a.status_code}"
            ),
            cwe="CWE-1021",
            cvss=8.1 if sev == "critical" else 6.5,
            poc_html=_build_poc(target_url, a.path),
        ))

    # Other unprotected pages
    if other_unprotected:
        affected_paths = [a.path for a in other_unprotected[:10]]
        findings.append(ClickjackingFinding(
            url=target_url,
            path="/",
            severity="medium",
            attack_type="missing",
            title=f"Missing Framing Protection on {len(other_unprotected)} Pages",
            detail=(
                f"{len(other_unprotected)} pages lack X-Frame-Options and CSP "
                f"frame-ancestors headers. Affected paths: "
                + ", ".join(affected_paths)
            ),
            evidence=f"{len(other_unprotected)} unprotected endpoints",
            cwe="CWE-1021",
            cvss=4.3,
            poc_html=None,
        ))

    # Deprecated ALLOW-FROM
    allow_from = [
        a for a in analyses
        if a.xfo_verdict == "deprecated"
    ]
    if allow_from:
        findings.append(ClickjackingFinding(
            url=allow_from[0].url,
            path=allow_from[0].path,
            severity="medium",
            attack_type="deprecated_allow_from",
            title="Deprecated X-Frame-Options: ALLOW-FROM",
            detail=(
                "X-Frame-Options: ALLOW-FROM is not supported by modern browsers "
                "(Chrome, Firefox, Edge all ignore it). Use CSP frame-ancestors instead."
            ),
            evidence=f"X-Frame-Options: {allow_from[0].xfo_header}",
            cwe="CWE-1021",
            cvss=4.3,
            poc_html=None,
        ))

    # Wildcard CSP frame-ancestors
    wildcard_csp = [
        a for a in analyses
        if a.csp_fa_verdict == "wildcard"
    ]
    if wildcard_csp:
        findings.append(ClickjackingFinding(
            url=wildcard_csp[0].url,
            path=wildcard_csp[0].path,
            severity="high",
            attack_type="wildcard_csp",
            title="CSP frame-ancestors Uses Wildcard (*)",
            detail=(
                f"Content-Security-Policy frame-ancestors is set to wildcard '*', "
                f"which allows any origin to embed this page. "
                f"This provides no clickjacking protection."
            ),
            evidence=f"frame-ancestors: {wildcard_csp[0].csp_fa_value}",
            cwe="CWE-1021",
            cvss=6.5,
            poc_html=_build_poc(target_url, wildcard_csp[0].path),
        ))

    # Inconsistent protection — XFO but no CSP FA (bypass possible in some browsers)
    xfo_no_csp = [
        a for a in analyses
        if a.xfo_verdict == "secure" and a.csp_fa_verdict == "missing"
        and a.label in _HIGH_VALUE_LABELS
    ]
    if xfo_no_csp:
        findings.append(ClickjackingFinding(
            url=xfo_no_csp[0].url,
            path=xfo_no_csp[0].path,
            severity="low",
            attack_type="inconsistent",
            title="Clickjacking: X-Frame-Options Only (No CSP frame-ancestors)",
            detail=(
                "X-Frame-Options is set but CSP frame-ancestors is absent. "
                "CSP frame-ancestors is the modern standard and takes precedence "
                "over XFO in browsers that support it. Having only XFO leaves "
                "edge cases open in older/non-standard user agents."
            ),
            evidence=f"XFO={xfo_no_csp[0].xfo_header} | CSP FA absent",
            cwe="CWE-1021",
            cvss=2.6,
            poc_html=None,
        ))

    findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 9))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class ClickjackingChecker:
    """
    X-Frame-Options / CSP frame-ancestors clickjacking checker.

    Checks every discovered endpoint for:
      - Missing X-Frame-Options
      - Deprecated ALLOW-FROM (not supported in modern browsers)
      - Missing CSP frame-ancestors
      - Wildcard CSP frame-ancestors (*)
      - Inconsistent protection (XFO only, no CSP FA)

    Generates PoC iframe HTML for all confirmed unprotected high-value pages.

    Usage in app.py:
        checker = ClickjackingChecker(target_url=f"https://{domain}")
        results = checker.scan()
        scan_results[scan_id]['clickjacking'] = results
    """

    def __init__(
        self,
        target_url:  str,
        extra_paths: Optional[List[str]] = None,
        timeout:     float = 7.0,
        max_workers: int   = 15,
        rate_delay:  float = 0.1,
        proxy:       Optional[str] = None,
    ):
        self.target_url  = target_url.rstrip("/")
        self.extra_paths = extra_paths or []
        self.timeout     = timeout
        self.max_workers = max_workers
        self.rate_delay  = rate_delay
        self.proxy       = proxy

        parsed     = urllib.parse.urlparse(self.target_url)
        self.domain = parsed.hostname or self.target_url

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        import time as _time
        t0 = _time.monotonic()

        print(f"[clickjack] target : {self.target_url}")

        session = _build_session(self.proxy)
        state   = ScanState(
            target_url=self.target_url,
            domain=self.domain,
            analyses=[],
            findings=[],
        )

        # Build path list
        all_paths = list(_PROBE_PATHS)
        for ep in self.extra_paths:
            all_paths.append((ep, "extra"))
        # Dedup
        seen_paths: Set[str] = set()
        unique_paths = []
        for path, label in all_paths:
            if path not in seen_paths:
                seen_paths.add(path)
                unique_paths.append((path, label))

        print(f"[clickjack] paths  : {len(unique_paths)}")

        # Parallel analysis
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {
                ex.submit(
                    _analyse_endpoint, session, self.target_url,
                    path, label, self.timeout, self.rate_delay,
                ): (path, label)
                for path, label in unique_paths
            }
            for f in as_completed(futures):
                r = f.result()
                if r:
                    with state.lock:
                        state.analyses.append(r)
                    if not r.protected:
                        print(
                            f"  [clickjack] UNPROTECTED [{r.status_code}] "
                            f"{r.path} XFO={r.xfo_header!r}"
                        )

        # Synthesise findings
        state.findings = _synthesise_findings(state.analyses, self.target_url)

        # Stats
        total      = len(state.analyses)
        protected  = sum(1 for a in state.analyses if a.protected)
        unprotected = total - protected

        sev_counts: Dict[str, int] = {}
        for f in state.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        elapsed = _time.monotonic() - t0
        print(
            f"[clickjack] done | "
            f"checked={total} protected={protected} "
            f"unprotected={unprotected} "
            f"findings={len(state.findings)} "
            f"elapsed={elapsed:.1f}s"
        )

        return {
            "target":           self.target_url,
            "endpoints_checked":total,
            "protected_count":  protected,
            "unprotected_count":unprotected,
            "total_findings":   len(state.findings),
            "severity_summary": sev_counts,
            "elapsed_seconds":  round(elapsed, 2),
            "analyses": [
                {
                    "url":            a.url,
                    "path":           a.path,
                    "label":          a.label,
                    "status_code":    a.status_code,
                    "xfo_header":     a.xfo_header,
                    "xfo_verdict":    a.xfo_verdict,
                    "csp_fa_value":   a.csp_fa_value,
                    "csp_fa_verdict": a.csp_fa_verdict,
                    "protected":      a.protected,
                    "effective_policy":a.effective_policy,
                    "missing_headers":a.missing_headers,
                    "server":         a.server,
                }
                for a in state.analyses
            ],
            "findings": [
                {
                    "url":         f.url,
                    "path":        f.path,
                    "severity":    f.severity,
                    "attack_type": f.attack_type,
                    "title":       f.title,
                    "detail":      f.detail,
                    "evidence":    f.evidence,
                    "cwe":         f.cwe,
                    "cvss":        f.cvss,
                    "poc_html":    f.poc_html,
                }
                for f in state.findings
            ],
        }