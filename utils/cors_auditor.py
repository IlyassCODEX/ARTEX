# utils/cors_auditor.py
import asyncio
import aiohttp
import time
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class CORSIssue(Enum):
    WILDCARD_ORIGIN = "wildcard_origin"
    ARBITRARY_ORIGIN_REFLECTED = "arbitrary_origin_reflected"
    NULL_ORIGIN_ALLOWED = "null_origin_allowed"
    SUBDOMAIN_TRUST = "subdomain_trust"
    HTTP_ORIGIN_TRUSTED = "http_origin_trusted"
    CREDENTIALS_WITH_WILDCARD = "credentials_with_wildcard"
    CREDENTIALS_WITH_REFLECTED = "credentials_with_reflected"
    PARTIAL_MATCH_BYPASS = "partial_match_bypass"
    PREFIX_MATCH_BYPASS = "prefix_match_bypass"
    SUFFIX_MATCH_BYPASS = "suffix_match_bypass"
    SPECIAL_CHAR_BYPASS = "special_char_bypass"
    THIRD_PARTY_TRUSTED = "third_party_trusted"
    VARY_MISSING = "vary_missing"
    EXPOSED_HEADERS_SENSITIVE = "exposed_headers_sensitive"
    PREFLIGHT_METHODS_DANGEROUS = "preflight_methods_dangerous"
    NO_CORS = "no_cors_headers"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


ISSUE_SEVERITY: dict[CORSIssue, Severity] = {
    CORSIssue.CREDENTIALS_WITH_WILDCARD: Severity.CRITICAL,
    CORSIssue.CREDENTIALS_WITH_REFLECTED: Severity.CRITICAL,
    CORSIssue.ARBITRARY_ORIGIN_REFLECTED: Severity.HIGH,
    CORSIssue.NULL_ORIGIN_ALLOWED: Severity.HIGH,
    CORSIssue.HTTP_ORIGIN_TRUSTED: Severity.HIGH,
    CORSIssue.PREFIX_MATCH_BYPASS: Severity.HIGH,
    CORSIssue.SUFFIX_MATCH_BYPASS: Severity.HIGH,
    CORSIssue.PARTIAL_MATCH_BYPASS: Severity.MEDIUM,
    CORSIssue.SPECIAL_CHAR_BYPASS: Severity.MEDIUM,
    CORSIssue.SUBDOMAIN_TRUST: Severity.MEDIUM,
    CORSIssue.WILDCARD_ORIGIN: Severity.MEDIUM,
    CORSIssue.THIRD_PARTY_TRUSTED: Severity.MEDIUM,
    CORSIssue.PREFLIGHT_METHODS_DANGEROUS: Severity.LOW,
    CORSIssue.EXPOSED_HEADERS_SENSITIVE: Severity.LOW,
    CORSIssue.VARY_MISSING: Severity.INFO,
    CORSIssue.NO_CORS: Severity.INFO,
}

SENSITIVE_HEADERS_PATTERN = re.compile(
    r"(authorization|x-auth|x-api-key|x-access-token|cookie|set-cookie|x-csrf|x-session)",
    re.I,
)

DANGEROUS_METHODS = {"DELETE", "PUT", "PATCH", "CONNECT", "TRACE"}

THIRD_PARTY_DOMAINS = [
    "evil.com",
    "attacker.com",
    "burpcollaborator.net",
    "oastify.com",
    "ngrok.io",
    "requestbin.com",
]


@dataclass
class CORSFinding:
    issue: CORSIssue
    severity: Severity
    origin_sent: str
    acao_received: str
    acac_received: str
    method: str
    endpoint: str
    details: str


@dataclass
class PreflightResult:
    origin: str
    request_method: str
    status_code: int
    allowed_methods: str
    allowed_headers: str
    max_age: str
    credentials: str
    acao: str


@dataclass
class CORSAuditReport:
    target_url: str
    baseline_acao: str
    baseline_acac: str
    findings: list[CORSFinding] = field(default_factory=list)
    preflight_results: list[PreflightResult] = field(default_factory=list)
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    duration_seconds: float = 0.0


def _build_origin_probes(target_url: str) -> list[tuple[str, str]]:
    parsed = urlparse(target_url)
    host = parsed.netloc or parsed.hostname or ""
    scheme = parsed.scheme or "https"
    base = f"{scheme}://{host}"

    probes: list[tuple[str, str]] = []

    probes.append(("arbitrary_external", "https://evil.attacker.com"))
    probes.append(("null_origin", "null"))

    probes.append(("http_downgrade", f"http://{host}"))

    probes.append(("prefix_bypass_prepend", f"https://evil.com.{host}"))
    probes.append(("prefix_bypass_subdomain", f"https://{host}.evil.com"))

    parts = host.split(".")
    if len(parts) >= 2:
        parent = ".".join(parts[-2:])
        probes.append(("suffix_match", f"https://evil{parent}"))
        probes.append(("suffix_match_dot", f"https://evil.{parent}"))

    probes.append(("special_char_underscore", f"https://{host}_.evil.com"))
    probes.append(("special_char_backtick", f"https://{host}`evil.com"))
    probes.append(("special_char_space", f"https://{host} .evil.com"))
    probes.append(("url_encoded_dot", f"https://{host}%60evil.com"))

    for i, part in enumerate(parts):
        if i < len(parts) - 1:
            sub = ".".join(parts[i:])
            probes.append((f"subdomain_wildcard_{i}", f"https://xss.{sub}"))
            probes.append((f"subdomain_takeover_candidate_{i}", f"https://nonexistent-xss-test.{sub}"))

    for tp in THIRD_PARTY_DOMAINS:
        probes.append((f"third_party_{tp}", f"https://{tp}"))

    probes.append(("origin_with_port", f"https://{host}:8443"))
    probes.append(("origin_with_path", f"https://{host}/path"))
    probes.append(("origin_no_scheme", f"//{host}"))

    return probes


def _extract_cors_headers(resp_headers: dict) -> tuple[str, str, str, str, str]:
    acao = resp_headers.get("access-control-allow-origin", "")
    acac = resp_headers.get("access-control-allow-credentials", "")
    acam = resp_headers.get("access-control-allow-methods", "")
    acah = resp_headers.get("access-control-allow-headers", "")
    aceh = resp_headers.get("access-control-expose-headers", "")
    return acao, acac, acam, acah, aceh


def _normalize_headers(raw: dict) -> dict:
    return {k.lower(): v for k, v in raw.items()}


def _is_credentials_true(acac: str) -> bool:
    return acac.strip().lower() == "true"


def _analyze_response(
    probe_name: str,
    origin_sent: str,
    resp_headers: dict,
    baseline_acao: str,
    target_url: str,
    method: str = "GET",
) -> list[CORSFinding]:
    findings: list[CORSFinding] = []
    norm = _normalize_headers(resp_headers)
    acao, acac, acam, acah, aceh = _extract_cors_headers(norm)
    with_credentials = _is_credentials_true(acac)

    if not acao:
        return findings

    if acao == "*":
        if with_credentials:
            findings.append(CORSFinding(
                issue=CORSIssue.CREDENTIALS_WITH_WILDCARD,
                severity=ISSUE_SEVERITY[CORSIssue.CREDENTIALS_WITH_WILDCARD],
                origin_sent=origin_sent,
                acao_received=acao,
                acac_received=acac,
                method=method,
                endpoint=target_url,
                details="ACAO: * combined with ACAC: true — browsers block this but misconfigured proxies may not",
            ))
        else:
            findings.append(CORSFinding(
                issue=CORSIssue.WILDCARD_ORIGIN,
                severity=ISSUE_SEVERITY[CORSIssue.WILDCARD_ORIGIN],
                origin_sent=origin_sent,
                acao_received=acao,
                acac_received=acac,
                method=method,
                endpoint=target_url,
                details="Wildcard ACAO without credentials — read-only cross-origin requests allowed from any origin",
            ))
        return findings

    if acao == "null" or (origin_sent == "null" and acao == "null"):
        sev = CORSIssue.NULL_ORIGIN_ALLOWED
        findings.append(CORSFinding(
            issue=sev,
            severity=ISSUE_SEVERITY[sev],
            origin_sent=origin_sent,
            acao_received=acao,
            acac_received=acac,
            method=method,
            endpoint=target_url,
            details="null origin accepted — exploitable via sandboxed iframe or file:// context",
        ))

    if acao == origin_sent and acao != baseline_acao:
        parsed_origin = urlparse(origin_sent)
        parsed_target = urlparse(target_url)

        issue = CORSIssue.ARBITRARY_ORIGIN_REFLECTED
        details = f"Origin '{origin_sent}' fully reflected in ACAO"

        if parsed_origin.scheme == "http" and parsed_target.scheme == "https":
            issue = CORSIssue.HTTP_ORIGIN_TRUSTED
            details = f"HTTP origin '{origin_sent}' trusted by HTTPS endpoint — downgrades transport security"

        elif "evil" in origin_sent or "attacker" in origin_sent or any(tp in origin_sent for tp in THIRD_PARTY_DOMAINS):
            if "prefix_bypass" in probe_name:
                issue = CORSIssue.PREFIX_MATCH_BYPASS
                details = f"Prefix match bypass: '{origin_sent}' accepted — validator checks wrong end of origin"
            elif "suffix_match" in probe_name:
                issue = CORSIssue.SUFFIX_MATCH_BYPASS
                details = f"Suffix match bypass: '{origin_sent}' accepted — attacker registers matching domain"
            elif any(tp in origin_sent for tp in THIRD_PARTY_DOMAINS):
                issue = CORSIssue.THIRD_PARTY_TRUSTED
                details = f"Third-party origin '{origin_sent}' explicitly trusted"
            else:
                issue = CORSIssue.ARBITRARY_ORIGIN_REFLECTED
                details = f"Arbitrary external origin reflected: '{origin_sent}'"

        elif "special_char" in probe_name or any(c in origin_sent for c in ["`", " ", "%60", "_."]):
            issue = CORSIssue.SPECIAL_CHAR_BYPASS
            details = f"Special character bypass: '{origin_sent}' accepted — validator may be using loose regex"

        elif parsed_origin.netloc and parsed_origin.netloc.endswith("." + parsed_target.netloc):
            issue = CORSIssue.SUBDOMAIN_TRUST
            details = f"Subdomain '{origin_sent}' trusted — subdomain XSS leads to full CORS exploit"

        final_issue = issue
        if with_credentials:
            if issue in (CORSIssue.ARBITRARY_ORIGIN_REFLECTED, CORSIssue.PREFIX_MATCH_BYPASS,
                         CORSIssue.SUFFIX_MATCH_BYPASS, CORSIssue.HTTP_ORIGIN_TRUSTED):
                final_issue = CORSIssue.CREDENTIALS_WITH_REFLECTED
                details += " + ACAC: true — full authenticated CORS exploit"

        findings.append(CORSFinding(
            issue=final_issue,
            severity=ISSUE_SEVERITY[final_issue],
            origin_sent=origin_sent,
            acao_received=acao,
            acac_received=acac,
            method=method,
            endpoint=target_url,
            details=details,
        ))

    vary = norm.get("vary", "")
    if acao and "origin" not in vary.lower():
        findings.append(CORSFinding(
            issue=CORSIssue.VARY_MISSING,
            severity=ISSUE_SEVERITY[CORSIssue.VARY_MISSING],
            origin_sent=origin_sent,
            acao_received=acao,
            acac_received=acac,
            method=method,
            endpoint=target_url,
            details="Vary: Origin header missing — CORS response may be cached and served to wrong origin",
        ))

    if aceh and SENSITIVE_HEADERS_PATTERN.search(aceh):
        findings.append(CORSFinding(
            issue=CORSIssue.EXPOSED_HEADERS_SENSITIVE,
            severity=ISSUE_SEVERITY[CORSIssue.EXPOSED_HEADERS_SENSITIVE],
            origin_sent=origin_sent,
            acao_received=acao,
            acac_received=acac,
            method=method,
            endpoint=target_url,
            details=f"Sensitive headers exposed via ACEH: {aceh}",
        ))

    return findings
    
    
async def _send_cors_probe(
    session: aiohttp.ClientSession,
    url: str,
    origin: str,
    method: str,
    base_headers: dict,
    semaphore: asyncio.Semaphore,
    delay: float,
) -> tuple[int, dict, float]:
    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)
        headers = {**base_headers, "Origin": origin}
        t0 = time.monotonic()
        try:
            async with session.request(
                method, url,
                headers=headers,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
            ) as resp:
                await resp.read()
                return resp.status, _normalize_headers(dict(resp.headers)), (time.monotonic() - t0) * 1000
        except Exception:
            return -1, {}, (time.monotonic() - t0) * 1000
            
            
async def _send_preflight(
    session: aiohttp.ClientSession,
    url: str,
    origin: str,
    request_method: str,
    base_headers: dict,
    semaphore: asyncio.Semaphore,
) -> PreflightResult:
    async with semaphore:
        headers = {
            **base_headers,
            "Origin": origin,
            "Access-Control-Request-Method": request_method,
            "Access-Control-Request-Headers": "authorization,x-custom-header,content-type",
        }
        try:
            async with session.options(
                url,
                headers=headers,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
            ) as resp:
                norm = _normalize_headers(dict(resp.headers))
                acao, acac, acam, acah, _ = _extract_cors_headers(norm)
                return PreflightResult(
                    origin=origin,
                    request_method=request_method,
                    status_code=resp.status,
                    allowed_methods=acam,
                    allowed_headers=acah,
                    max_age=norm.get("access-control-max-age", ""),
                    credentials=acac,
                    acao=acao,
                )
        except Exception:
            return PreflightResult(
                origin=origin,
                request_method=request_method,
                status_code=-1,
                allowed_methods="",
                allowed_headers="",
                max_age="",
                credentials="",
                acao="",
            )


class CORSAuditor:
    def __init__(
        self,
        concurrency: int = 10,
        delay: float = 0.1,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        test_methods: Optional[list[str]] = None,
    ):
        self.concurrency = concurrency
        self.delay = delay
        self.test_methods = test_methods or ["GET", "POST"]
        self.base_headers = {
            "User-Agent": user_agent,
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        }

    async def run(self, target_url: str) -> CORSAuditReport:
        t_start = time.monotonic()
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        semaphore = asyncio.Semaphore(self.concurrency)

        async with aiohttp.ClientSession(connector=connector) as session:
            status, baseline_headers, _ = await _send_cors_probe(
                session, target_url, "https://baseline-no-origin.internal",
                "GET", self.base_headers, semaphore, 0
            )
            norm_baseline = _normalize_headers(baseline_headers)
            baseline_acao, baseline_acac, _, _, _ = _extract_cors_headers(norm_baseline)

            origin_probes = _build_origin_probes(target_url)

            all_findings: list[CORSFinding] = []
            seen_fingerprints: set[str] = set()

            for method in self.test_methods:
                tasks = [
                    _send_cors_probe(
                        session, target_url, origin,
                        method, self.base_headers, semaphore, self.delay
                    )
                    for _, origin in origin_probes
                ]
                results = await asyncio.gather(*tasks)

                for (probe_name, origin), (resp_status, resp_headers, _) in zip(origin_probes, results):
                    if resp_status < 0:
                        continue
                    findings = _analyze_response(
                        probe_name, origin, resp_headers,
                        baseline_acao, target_url, method
                    )
                    for f in findings:
                        fp = f"{f.issue.value}:{f.origin_sent}:{f.method}"
                        if fp not in seen_fingerprints:
                            seen_fingerprints.add(fp)
                            all_findings.append(f)

            preflight_tasks = [
                _send_preflight(
                    session, target_url,
                    "https://evil.attacker.com",
                    m, self.base_headers, semaphore
                )
                for m in list(DANGEROUS_METHODS) + ["GET", "POST"]
            ]
            preflight_results = await asyncio.gather(*preflight_tasks)

            for pf in preflight_results:
                if pf.acao and pf.request_method in DANGEROUS_METHODS:
                    if pf.acao not in ("", "*") or _is_credentials_true(pf.credentials):
                        all_findings.append(CORSFinding(
                            issue=CORSIssue.PREFLIGHT_METHODS_DANGEROUS,
                            severity=ISSUE_SEVERITY[CORSIssue.PREFLIGHT_METHODS_DANGEROUS],
                            origin_sent="https://evil.attacker.com",
                            acao_received=pf.acao,
                            acac_received=pf.credentials,
                            method=f"OPTIONS→{pf.request_method}",
                            endpoint=target_url,
                            details=f"Preflight allows dangerous method {pf.request_method} from external origin",
                        ))

            if not all_findings:
                all_findings.append(CORSFinding(
                    issue=CORSIssue.NO_CORS,
                    severity=ISSUE_SEVERITY[CORSIssue.NO_CORS],
                    origin_sent="",
                    acao_received=baseline_acao,
                    acac_received=baseline_acac,
                    method="GET",
                    endpoint=target_url,
                    details="No CORS headers returned for any probe — endpoint may not support CORS",
                ))

        all_findings.sort(key=lambda f: list(Severity).index(f.severity))
        severity_count = {s.value: 0 for s in Severity}
        for f in all_findings:
            severity_count[f.severity.value] += 1

        return CORSAuditReport(
            target_url=target_url,
            baseline_acao=baseline_acao,
            baseline_acac=baseline_acac,
            findings=all_findings,
            preflight_results=list(preflight_results),
            findings_by_severity=severity_count,
            duration_seconds=time.monotonic() - t_start,
        )

    def run_sync(self, target_url: str) -> CORSAuditReport:
        return asyncio.run(self.run(target_url))


def serialize_report(report: CORSAuditReport) -> dict:
    def finding_to_dict(f: CORSFinding) -> dict:
        return {
            "issue": f.issue.value,
            "severity": f.severity.value,
            "origin_sent": f.origin_sent,
            "acao_received": f.acao_received,
            "acac_received": f.acac_received,
            "method": f.method,
            "endpoint": f.endpoint,
            "details": f.details,
        }

    def preflight_to_dict(p: PreflightResult) -> dict:
        return {
            "origin": p.origin,
            "request_method": p.request_method,
            "status": p.status_code,
            "acao": p.acao,
            "allowed_methods": p.allowed_methods,
            "allowed_headers": p.allowed_headers,
            "max_age": p.max_age,
            "credentials": p.credentials,
        }

    return {
        "target": report.target_url,
        "baseline_acao": report.baseline_acao,
        "baseline_acac": report.baseline_acac,
        "duration_seconds": round(report.duration_seconds, 2),
        "total_findings": len(report.findings),
        "findings_by_severity": report.findings_by_severity,
        "findings": [finding_to_dict(f) for f in report.findings],
        "preflight_results": [preflight_to_dict(p) for p in report.preflight_results],
    }


def run_cors_audit(
    target_url: str,
    concurrency: int = 10,
    delay: float = 0.1,
    test_methods: Optional[list[str]] = None,
) -> dict:
    auditor = CORSAuditor(
        concurrency=concurrency,
        delay=delay,
        test_methods=test_methods or ["GET", "POST"],
    )
    report = auditor.run_sync(target_url)
    return serialize_report(report)