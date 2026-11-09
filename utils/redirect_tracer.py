# utils/redirect_tracer.py
import asyncio
import hashlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, urlencode


class RedirectType(Enum):
    HTTP_301 = "301_moved_permanently"
    HTTP_302 = "302_found"
    HTTP_303 = "303_see_other"
    HTTP_307 = "307_temporary_redirect"
    HTTP_308 = "308_permanent_redirect"
    META_REFRESH = "meta_refresh"
    JS_LOCATION = "js_location_assign"
    OPEN_REDIRECT = "open_redirect"
    SSRF_VECTOR = "ssrf_via_redirect"
    HEADER_INJECTION = "header_injection_via_location"
    LOOP = "redirect_loop"
    CHAIN_TOO_LONG = "chain_too_long"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RedirectHop:
    hop_number: int
    from_url: str
    to_url: str
    status_code: int
    redirect_type: RedirectType
    response_headers: dict
    latency_ms: float
    is_cross_domain: bool
    is_external: bool
    location_header_raw: str
    notes: str


@dataclass
class RedirectFinding:
    finding_type: RedirectType
    severity: Severity
    url: str
    detail: str
    evidence: str
    hop_index: int


@dataclass
class RedirectChain:
    seed_url: str
    final_url: str
    hops: list[RedirectHop]
    findings: list[RedirectFinding]
    total_latency_ms: float
    has_loop: bool
    has_open_redirect: bool
    chain_length: int
    crosses_domains: bool
    param_tested: str
    payload_used: str


@dataclass
class RedirectReport:
    target_url: str
    total_chains: int
    chains: list[RedirectChain]
    all_findings: list[RedirectFinding]
    findings_by_severity: dict[str, int]
    unique_domains_touched: list[str]
    open_redirect_params: list[str]
    duration_seconds: float


OPEN_REDIRECT_PAYLOADS = [
    ("external_basic",          "https://evil.com"),
    ("external_path",           "https://evil.com/path?a=1"),
    ("proto_relative",          "//evil.com"),
    ("proto_relative_path",     "//evil.com/x"),
    ("url_encoded_slash",       "https%3A%2F%2Fevil.com"),
    ("double_encoded",          "https%253A%252F%252Fevil.com"),
    ("backslash_bypass",        "https:\\\\evil.com"),
    ("tab_bypass",              "https://evil.com\t"),
    ("newline_bypass",          "https://evil.com\n"),
    ("null_byte",               "https://evil.com\x00"),
    ("at_sign_bypass",          "https://trusted.com@evil.com"),
    ("at_sign_encoded",         "https://trusted.com%40evil.com"),
    ("triple_slash",            "///evil.com"),
    ("scheme_case",             "HTTPS://evil.com"),
    ("whitespace_prefix",       " https://evil.com"),
    ("dot_bypass",              "https://evil.com.trusted.com"),
    ("subdomain_bypass",        "https://trusted.com.evil.com"),
    ("path_traversal",          "/\\evil.com"),
    ("javascript_proto",        "javascript:alert(1)"),
    ("data_uri",                "data:text/html,<script>alert(1)</script>"),
    ("vbscript_proto",          "vbscript:alert(1)"),
    ("crlf_in_location",        "https://evil.com%0d%0aSet-Cookie:injected=1"),
    ("fragment_bypass",         "https://evil.com#trusted.com"),
    ("port_bypass",             "https://evil.com:80"),
    ("ipv6_bypass",             "https://[::1]"),
    ("decimal_ip",              "https://1113982867"),
    ("octal_ip",                "https://0100.0250.0251.0254"),
    ("hex_ip",                  "https://0x425fed6e"),
    ("mixed_encoding",          "https://evil%2ecom"),
    ("unicode_dot",             "https://evil\u3002com"),
]

REDIRECT_PARAM_NAMES = [
    "redirect", "redirect_uri", "redirect_url", "redirectUri", "redirectUrl",
    "return", "return_url", "returnUrl", "return_to", "returnTo",
    "next", "next_url", "nextUrl",
    "url", "uri",
    "dest", "destination",
    "goto", "go",
    "target", "to",
    "callback", "callback_url", "callbackUrl",
    "continue", "cont",
    "forward", "fwd",
    "ref", "referrer",
    "out", "exit",
    "path", "page",
    "link", "site",
    "u", "r", "q",
    "login_success_url", "post_login_redirect",
    "logout_redirect", "success_url", "cancel_url",
    "error_url", "after_login",
]

META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d*;\s*url=([^"\'>\s]+)',
    re.I,
)
META_REFRESH_ALT_RE = re.compile(
    r'<meta[^>]+content=["\']?\d*;\s*url=([^"\'>\s]+)[^>]*http-equiv=["\']?refresh["\']?',
    re.I,
)
JS_LOCATION_RE = re.compile(
    r'(?:window\.location|location\.href|location\.replace|location\.assign)\s*[=\(]\s*["\']([^"\']+)["\']',
    re.I,
)

EXTERNAL_INDICATORS = ["evil.com", "attacker.com", "external-test.com", "oast.me"]

CRLF_IN_LOCATION_RE = re.compile(r'%0[dD]|%0[aA]|\r|\n')
DANGEROUS_SCHEME_RE = re.compile(r'^(javascript|vbscript|data):', re.I)


def _fingerprint(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()[:10]


def _extract_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def _is_external(to_url: str, seed_url: str) -> bool:
    seed_domain = _extract_domain(seed_url)
    to_domain = _extract_domain(to_url)
    if not to_domain:
        return False
    return to_domain != seed_domain and not to_domain.endswith("." + seed_domain)


def _is_cross_domain(from_url: str, to_url: str) -> bool:
    return _extract_domain(from_url) != _extract_domain(to_url)


def _detect_open_redirect(to_url: str, payload: str, seed_url: str) -> bool:
    if not to_url:
        return False
    if any(ind in to_url for ind in EXTERNAL_INDICATORS):
        return True
    parsed_seed = urlparse(seed_url)
    parsed_to = urlparse(to_url)
    if parsed_to.netloc and parsed_to.netloc != parsed_seed.netloc:
        payload_domain = _extract_domain(payload) if payload.startswith("http") else ""
        if payload_domain and payload_domain in to_url:
            return True
    if DANGEROUS_SCHEME_RE.match(to_url):
        return True
    return False


def _detect_header_injection(location: str) -> bool:
    return bool(CRLF_IN_LOCATION_RE.search(location))


def _build_probe_url(base_url: str, param: str, payload: str) -> str:
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_query))


def _extract_soft_redirects(html: str, base_url: str) -> list[tuple[str, RedirectType]]:
    found: list[tuple[str, RedirectType]] = []
    for pat in (META_REFRESH_RE, META_REFRESH_ALT_RE):
        for m in pat.finditer(html):
            raw = m.group(1).strip().strip("'\"")
            full = urljoin(base_url, raw)
            found.append((full, RedirectType.META_REFRESH))
    for m in JS_LOCATION_RE.finditer(html):
        raw = m.group(1).strip()
        if raw.startswith("http") or raw.startswith("//") or raw.startswith("/"):
            full = urljoin(base_url, raw)
            found.append((full, RedirectType.JS_LOCATION))
    return found


def _status_to_redirect_type(status: int) -> RedirectType:
    return {
        301: RedirectType.HTTP_301,
        302: RedirectType.HTTP_302,
        303: RedirectType.HTTP_303,
        307: RedirectType.HTTP_307,
        308: RedirectType.HTTP_308,
    }.get(status, RedirectType.HTTP_302)


async def _follow_chain(
    session,
    seed_url: str,
    param: str,
    payload: str,
    max_hops: int,
    semaphore: asyncio.Semaphore,
    delay: float,
    base_headers: dict,
) -> RedirectChain:
    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)

    hops: list[RedirectHop] = []
    findings: list[RedirectFinding] = []
    visited: set[str] = set()
    current_url = _build_probe_url(seed_url, param, payload)
    total_latency = 0.0

    for hop_num in range(max_hops):
        if current_url in visited:
            findings.append(RedirectFinding(
                finding_type=RedirectType.LOOP,
                severity=Severity.MEDIUM,
                url=current_url,
                detail=f"Redirect loop detected at hop {hop_num}",
                evidence=current_url,
                hop_index=hop_num,
            ))
            break
        if len(hops) >= max_hops:
            findings.append(RedirectFinding(
                finding_type=RedirectType.CHAIN_TOO_LONG,
                severity=Severity.LOW,
                url=current_url,
                detail=f"Chain exceeded {max_hops} hops",
                evidence=current_url,
                hop_index=hop_num,
            ))
            break

        visited.add(current_url)
        t0 = time.monotonic()

        try:
            async with semaphore:
                async with session.get(
                    current_url,
                    headers=base_headers,
                    allow_redirects=False,
                    timeout=asyncio.timeout(10),
                    ssl=False,
                ) as resp:
                    status = resp.status
                    resp_headers = dict(resp.headers)
                    body_bytes = await resp.read()
                    body = body_bytes.decode("utf-8", errors="ignore")
                    latency = (time.monotonic() - t0) * 1000
                    total_latency += latency
        except Exception as e:
            break

        location_raw = resp_headers.get("Location", resp_headers.get("location", ""))

        if status in (301, 302, 303, 307, 308) and location_raw:
            to_url = urljoin(current_url, location_raw)
            rtype = _status_to_redirect_type(status)
            cross = _is_cross_domain(current_url, to_url)
            external = _is_external(to_url, seed_url)

            hop = RedirectHop(
                hop_number=hop_num,
                from_url=current_url,
                to_url=to_url,
                status_code=status,
                redirect_type=rtype,
                response_headers=resp_headers,
                latency_ms=round(latency, 2),
                is_cross_domain=cross,
                is_external=external,
                location_header_raw=location_raw,
                notes="",
            )
            hops.append(hop)

            if _detect_open_redirect(to_url, payload, seed_url):
                findings.append(RedirectFinding(
                    finding_type=RedirectType.OPEN_REDIRECT,
                    severity=Severity.HIGH,
                    url=current_url,
                    detail=f"Open redirect via param '{param}' — redirects to {to_url}",
                    evidence=f"payload={payload!r} → Location: {location_raw!r}",
                    hop_index=hop_num,
                ))

            if _detect_header_injection(location_raw):
                findings.append(RedirectFinding(
                    finding_type=RedirectType.HEADER_INJECTION,
                    severity=Severity.HIGH,
                    url=current_url,
                    detail=f"CRLF/newline in Location header — header injection possible",
                    evidence=f"Location: {location_raw[:200]!r}",
                    hop_index=hop_num,
                ))

            if DANGEROUS_SCHEME_RE.match(to_url):
                findings.append(RedirectFinding(
                    finding_type=RedirectType.OPEN_REDIRECT,
                    severity=Severity.CRITICAL,
                    url=current_url,
                    detail=f"Dangerous scheme in redirect target: {to_url[:100]}",
                    evidence=f"Location: {location_raw[:200]!r}",
                    hop_index=hop_num,
                ))

            current_url = to_url

        else:
            soft_redirects = _extract_soft_redirects(body, current_url)
            for soft_url, soft_type in soft_redirects:
                cross = _is_cross_domain(current_url, soft_url)
                external = _is_external(soft_url, seed_url)
                hop = RedirectHop(
                    hop_number=hop_num,
                    from_url=current_url,
                    to_url=soft_url,
                    status_code=status,
                    redirect_type=soft_type,
                    response_headers=resp_headers,
                    latency_ms=round(latency, 2),
                    is_cross_domain=cross,
                    is_external=external,
                    location_header_raw="",
                    notes=f"soft redirect via {soft_type.value}",
                )
                hops.append(hop)

                if _detect_open_redirect(soft_url, payload, seed_url):
                    findings.append(RedirectFinding(
                        finding_type=RedirectType.OPEN_REDIRECT,
                        severity=Severity.MEDIUM,
                        url=current_url,
                        detail=f"Open redirect via {soft_type.value} — target: {soft_url}",
                        evidence=f"payload={payload!r}",
                        hop_index=hop_num,
                    ))
                current_url = soft_url
                break
            else:
                break

    final_url = hops[-1].to_url if hops else seed_url
    has_loop = any(f.finding_type == RedirectType.LOOP for f in findings)
    has_open_redirect = any(f.finding_type == RedirectType.OPEN_REDIRECT for f in findings)
    crosses_domains = any(h.is_cross_domain for h in hops)

    return RedirectChain(
        seed_url=seed_url,
        final_url=final_url,
        hops=hops,
        findings=findings,
        total_latency_ms=round(total_latency, 2),
        has_loop=has_loop,
        has_open_redirect=has_open_redirect,
        chain_length=len(hops),
        crosses_domains=crosses_domains,
        param_tested=param,
        payload_used=payload,
    )


async def _discover_redirect_params(
    session,
    target_url: str,
    semaphore: asyncio.Semaphore,
    base_headers: dict,
) -> list[str]:
    found: list[str] = []
    try:
        async with semaphore:
            async with session.get(
                target_url,
                headers=base_headers,
                allow_redirects=True,
                timeout=asyncio.timeout(12),
                ssl=False,
            ) as resp:
                body = (await resp.read()).decode("utf-8", errors="ignore")
    except Exception:
        return REDIRECT_PARAM_NAMES[:10]

    parsed = urlparse(target_url)
    qs_params = list(parse_qs(parsed.query).keys())
    for p in qs_params:
        if p not in found:
            found.append(p)

    form_input_re = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.I)
    for m in form_input_re.finditer(body):
        name = m.group(1).strip()
        if name not in found:
            found.append(name)

    for p in REDIRECT_PARAM_NAMES:
        if re.search(rf'["\']({re.escape(p)})["\']', body, re.I) or p in body:
            if p not in found:
                found.append(p)

    if not found:
        found = REDIRECT_PARAM_NAMES[:12]

    return found


class RedirectTracer:
    def __init__(
        self,
        concurrency: int = 10,
        delay: float = 0.1,
        max_hops: int = 15,
        max_params: int = 15,
        max_payloads: int = 10,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        self.concurrency = concurrency
        self.delay = delay
        self.max_hops = max_hops
        self.max_params = max_params
        self.max_payloads = max_payloads
        self.base_headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        }

    async def run(self, target_url: str) -> RedirectReport:
        import aiohttp
        t_start = time.monotonic()
        semaphore = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)

        async with aiohttp.ClientSession(connector=connector) as session:
            params = await _discover_redirect_params(
                session, target_url, semaphore, self.base_headers
            )
            params = params[:self.max_params]

            payloads = OPEN_REDIRECT_PAYLOADS[:self.max_payloads]

            tasks = []
            for param in params:
                for payload_name, payload_val in payloads:
                    tasks.append(_follow_chain(
                        session, target_url, param, payload_val,
                        self.max_hops, semaphore, self.delay, self.base_headers,
                    ))

            chains: list[RedirectChain] = await asyncio.gather(*tasks)

        meaningful = [
            c for c in chains
            if c.chain_length > 0 or c.findings
        ]

        all_findings: list[RedirectFinding] = []
        seen_fps: set[str] = set()
        for chain in meaningful:
            for f in chain.findings:
                fp = _fingerprint(f"{f.finding_type.value}:{f.url}:{f.evidence[:40]}")
                if fp not in seen_fps:
                    seen_fps.add(fp)
                    all_findings.append(f)

        all_findings.sort(key=lambda f: list(Severity).index(f.severity))

        severity_count = {s.value: 0 for s in Severity}
        for f in all_findings:
            severity_count[f.severity.value] += 1

        unique_domains: list[str] = []
        seen_domains: set[str] = set()
        for chain in meaningful:
            for hop in chain.hops:
                d = _extract_domain(hop.to_url)
                if d and d not in seen_domains:
                    seen_domains.add(d)
                    unique_domains.append(d)

        open_redirect_params = list({
            c.param_tested for c in meaningful if c.has_open_redirect
        })

        return RedirectReport(
            target_url=target_url,
            total_chains=len(meaningful),
            chains=meaningful,
            all_findings=all_findings,
            findings_by_severity=severity_count,
            unique_domains_touched=unique_domains,
            open_redirect_params=open_redirect_params,
            duration_seconds=time.monotonic() - t_start,
        )

    def run_sync(self, target_url: str) -> RedirectReport:
        return asyncio.run(self.run(target_url))


def serialize_report(report: RedirectReport) -> dict:
    def hop_to_dict(h: RedirectHop) -> dict:
        return {
            "hop": h.hop_number,
            "from": h.from_url,
            "to": h.to_url,
            "status": h.status_code,
            "type": h.redirect_type.value,
            "latency_ms": h.latency_ms,
            "cross_domain": h.is_cross_domain,
            "external": h.is_external,
            "location_raw": h.location_header_raw[:300] if h.location_header_raw else "",
            "notes": h.notes,
        }

    def finding_to_dict(f: RedirectFinding) -> dict:
        return {
            "type": f.finding_type.value,
            "severity": f.severity.value,
            "url": f.url,
            "detail": f.detail,
            "evidence": f.evidence[:300],
            "hop_index": f.hop_index,
        }

    def chain_to_dict(c: RedirectChain) -> dict:
        return {
            "seed_url": c.seed_url,
            "final_url": c.final_url,
            "param_tested": c.param_tested,
            "payload_used": c.payload_used,
            "chain_length": c.chain_length,
            "total_latency_ms": c.total_latency_ms,
            "has_loop": c.has_loop,
            "has_open_redirect": c.has_open_redirect,
            "crosses_domains": c.crosses_domains,
            "hops": [hop_to_dict(h) for h in c.hops],
            "findings": [finding_to_dict(f) for f in c.findings],
        }

    return {
        "target": report.target_url,
        "total_chains": report.total_chains,
        "total_findings": len(report.all_findings),
        "duration_seconds": round(report.duration_seconds, 2),
        "findings_by_severity": report.findings_by_severity,
        "open_redirect_params": report.open_redirect_params,
        "unique_domains_touched": report.unique_domains_touched,
        "findings": [finding_to_dict(f) for f in report.all_findings],
        "chains": [chain_to_dict(c) for c in report.chains],
    }


def run_redirect_trace(
    target_url: str,
    concurrency: int = 10,
    delay: float = 0.1,
    max_hops: int = 15,
    max_params: int = 15,
    max_payloads: int = 10,
) -> dict:
    tracer = RedirectTracer(
        concurrency=concurrency,
        delay=delay,
        max_hops=max_hops,
        max_params=max_params,
        max_payloads=max_payloads,
    )
    report = tracer.run_sync(target_url)
    return serialize_report(report)