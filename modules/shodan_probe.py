# modules/shodan_probe.py
import os
import re
import time
import hashlib
import logging
import ipaddress
import itertools
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shodan API base
# ---------------------------------------------------------------------------

_SHODAN_BASE = "https://api.shodan.io"

# Rate limits (free tier: 1 req/s, paid: 10 req/s)
# Conservative default — overridden at runtime for paid plans
_FREE_TIER_DELAY   = 1.1   # seconds between requests
_PAID_TIER_DELAY   = 0.12


# ---------------------------------------------------------------------------
# Dork query templates
# ---------------------------------------------------------------------------
#
# Each template is expanded with the caller-supplied domain / org / IP.
# Grouped by what surface they expose.
# ---------------------------------------------------------------------------

_DORK_TEMPLATES: List[Tuple[str, str, str]] = [
    # (template, category, description)

    # ── Core domain / hostname ─────────────────────────────────────────────
    ("hostname:{domain}",                       "domain",     "All Shodan hits for hostname"),
    ("hostname:.{domain}",                      "domain",     "Wildcard subdomain hits"),
    ("ssl.cert.subject.cn:{domain}",            "ssl",        "Cert CN exact match"),
    ("ssl.cert.subject.cn:.{domain}",           "ssl",        "Cert CN wildcard"),
    ("ssl.cert.issuer.cn:{domain}",             "ssl",        "Cert issuer match"),
    ("http.host:{domain}",                      "http",       "HTTP Host header match"),

    # ── Admin / management panels ──────────────────────────────────────────
    ("hostname:{domain} http.title:admin",      "panel",      "Admin panel in title"),
    ("hostname:{domain} http.title:login",      "panel",      "Login panel"),
    ("hostname:{domain} http.title:dashboard",  "panel",      "Dashboard"),
    ("hostname:{domain} http.title:phpmyadmin", "panel",      "phpMyAdmin"),
    ("hostname:{domain} http.title:kibana",     "panel",      "Kibana exposed"),
    ("hostname:{domain} http.title:grafana",    "panel",      "Grafana exposed"),
    ("hostname:{domain} http.title:Jenkins",    "panel",      "Jenkins CI exposed"),
    ("hostname:{domain} http.title:Jira",       "panel",      "Jira exposed"),
    ("hostname:{domain} http.title:GitLab",     "panel",      "GitLab exposed"),
    ("hostname:{domain} http.title:Portainer",  "panel",      "Portainer Docker panel"),
    ("hostname:{domain} http.title:Traefik",    "panel",      "Traefik reverse proxy panel"),

    # ── Databases exposed ──────────────────────────────────────────────────
    ("hostname:{domain} port:3306",             "database",   "MySQL exposed"),
    ("hostname:{domain} port:5432",             "database",   "PostgreSQL exposed"),
    ("hostname:{domain} port:27017",            "database",   "MongoDB exposed"),
    ("hostname:{domain} port:6379",             "database",   "Redis exposed"),
    ("hostname:{domain} port:9200",             "database",   "Elasticsearch exposed"),
    ("hostname:{domain} port:5984",             "database",   "CouchDB exposed"),
    ("hostname:{domain} port:1521",             "database",   "Oracle DB exposed"),
    ("hostname:{domain} port:1433",             "database",   "MSSQL exposed"),
    ("hostname:{domain} port:11211",            "database",   "Memcached exposed"),
    ("hostname:{domain} port:9042",             "database",   "Cassandra CQL exposed"),
    ("hostname:{domain} port:2181",             "database",   "Zookeeper exposed"),
    ("hostname:{domain} port:5601",             "database",   "Kibana port exposed"),

    # ── Remote access / management ─────────────────────────────────────────
    ("hostname:{domain} port:22",               "remote",     "SSH exposed"),
    ("hostname:{domain} port:23",               "remote",     "Telnet exposed"),
    ("hostname:{domain} port:3389",             "remote",     "RDP exposed"),
    ("hostname:{domain} port:5900",             "remote",     "VNC exposed"),
    ("hostname:{domain} port:5901",             "remote",     "VNC-1 exposed"),
    ("hostname:{domain} port:2222",             "remote",     "Alt-SSH exposed"),
    ("hostname:{domain} port:8291",             "remote",     "Winbox (Mikrotik) exposed"),
    ("hostname:{domain} port:10000",            "remote",     "Webmin exposed"),

    # ── API / developer exposure ───────────────────────────────────────────
    ("hostname:{domain} http.title:swagger",    "api",        "Swagger UI exposed"),
    ("hostname:{domain} http.html:swagger-ui",  "api",        "Swagger HTML"),
    ("hostname:{domain} http.html:graphql",     "api",        "GraphQL endpoint"),
    ("hostname:{domain} http.title:api",        "api",        "Generic API title"),
    ('hostname:{domain} http.html:"api_key"',   "api",        "API key in HTML"),
    ('hostname:{domain} http.html:"access_token"', "api",     "Access token in HTML"),

    # ── Cloud / container infrastructure ──────────────────────────────────
    ("hostname:{domain} product:docker",        "infra",      "Docker API exposed"),
    ("hostname:{domain} port:2375",             "infra",      "Docker daemon (unauth)"),
    ("hostname:{domain} port:2376",             "infra",      "Docker TLS daemon"),
    ("hostname:{domain} port:6443",             "infra",      "Kubernetes API server"),
    ("hostname:{domain} port:10250",            "infra",      "Kubernetes Kubelet"),
    ("hostname:{domain} port:8500",             "infra",      "Consul API exposed"),
    ("hostname:{domain} port:4001",             "infra",      "etcd HTTP exposed"),
    ("hostname:{domain} port:2379",             "infra",      "etcd client port"),
    ("hostname:{domain} product:kubernetes",    "infra",      "Kubernetes product tag"),

    # ── Sensitive file / content exposure ──────────────────────────────────
    ('hostname:{domain} http.html:".env"',      "disclosure", ".env in HTML response"),
    ('hostname:{domain} http.html:"DB_PASSWORD"',"disclosure","DB_PASSWORD in HTML"),
    ('hostname:{domain} http.html:"private_key"',"disclosure","Private key in HTML"),
    ('hostname:{domain} http.html:"-----BEGIN"', "disclosure","PEM block in HTML"),
    ('hostname:{domain} http.html:"phpinfo"',   "disclosure", "phpinfo in HTML"),
    ('hostname:{domain} http.html:"Exception"', "disclosure", "Stack trace in HTML"),
    ('hostname:{domain} http.html:"stack trace"',"disclosure","Stack trace string"),
    ('hostname:{domain} http.html:"ERROR:"',    "disclosure", "Error message in HTML"),

    # ── IoT / industrial / embedded ────────────────────────────────────────
    ("hostname:{domain} port:502",              "ics",        "Modbus exposed"),
    ("hostname:{domain} port:102",              "ics",        "Siemens S7 exposed"),
    ("hostname:{domain} port:47808",            "ics",        "BACnet exposed"),
    ("hostname:{domain} port:1911",             "ics",        "Niagara Fox exposed"),
    ("hostname:{domain} product:webcam",        "iot",        "Webcam exposed"),

    # ── Vulnerability surface ──────────────────────────────────────────────
    ("hostname:{domain} vuln:CVE-2021-44228",   "vuln",       "Log4Shell (CVE-2021-44228)"),
    ("hostname:{domain} vuln:CVE-2021-26855",   "vuln",       "ProxyLogon Exchange"),
    ("hostname:{domain} vuln:CVE-2022-26134",   "vuln",       "Confluence RCE"),
    ("hostname:{domain} vuln:CVE-2023-23397",   "vuln",       "Outlook NTLM leak"),
    ("hostname:{domain} vuln:CVE-2023-44487",   "vuln",       "HTTP/2 Rapid Reset"),
    ("hostname:{domain} vuln:CVE-2024-21762",   "vuln",       "Fortinet SSL-VPN RCE"),
    ("hostname:{domain} vuln:CVE-2024-3400",    "vuln",       "PAN-OS cmd injection"),
]

# org-scoped dorks — used when org is known
_ORG_DORK_TEMPLATES: List[Tuple[str, str, str]] = [
    ("org:\"{org}\" port:22",                  "remote",     "SSH across org"),
    ("org:\"{org}\" port:3389",                "remote",     "RDP across org"),
    ("org:\"{org}\" port:3306",                "database",   "MySQL across org"),
    ("org:\"{org}\" port:27017",               "database",   "MongoDB across org"),
    ("org:\"{org}\" port:9200",                "database",   "Elasticsearch across org"),
    ("org:\"{org}\" port:6379",                "database",   "Redis across org"),
    ("org:\"{org}\" http.title:admin",         "panel",      "Admin panels in org"),
    ("org:\"{org}\" http.title:Jenkins",       "panel",      "Jenkins in org"),
    ("org:\"{org}\" product:docker",           "infra",      "Docker daemons in org"),
    ("org:\"{org}\" port:2375",                "infra",      "Unauth Docker in org"),
    ('org:\"{org}\" vuln:CVE-2021-44228',      "vuln",       "Log4Shell in org"),
]


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_CATEGORY_SEVERITY: Dict[str, str] = {
    "vuln":       "critical",
    "database":   "critical",
    "disclosure": "critical",
    "ics":        "critical",
    "remote":     "high",
    "panel":      "high",
    "infra":      "high",
    "api":        "medium",
    "ssl":        "medium",
    "domain":     "info",
    "http":       "info",
    "iot":        "high",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ShodanHost:
    ip: str
    port: int
    transport: str                  # tcp / udp
    product: Optional[str]
    version: Optional[str]
    os: Optional[str]
    banner: Optional[str]           # first 300 chars of raw banner
    http_title: Optional[str]
    http_server: Optional[str]
    ssl_cn: Optional[str]           # cert CN if TLS
    ssl_sans: List[str]
    org: Optional[str]
    isp: Optional[str]
    asn: Optional[str]
    country: Optional[str]
    city: Optional[str]
    hostnames: List[str]
    cves: List[str]
    tags: List[str]
    last_update: Optional[str]
    query: str                       # dork that surfaced this host
    category: str
    severity: str


@dataclass
class ShodanFinding:
    """High-level aggregated finding — one per unique (ip, port) pair."""
    ip: str
    port: int
    severity: str
    category: str
    description: str
    evidence: str
    cves: List[str] = field(default_factory=list)
    product: Optional[str] = None
    version: Optional[str] = None


@dataclass
class ShodanScanState:
    domain: str
    org: Optional[str]
    asn: Optional[str]
    known_ips: Set[str]
    hosts: List[ShodanHost] = field(default_factory=list)
    findings: List[ShodanFinding] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    seen_ip_port: Set[Tuple[str, int]] = field(default_factory=set)
    queries_run: int = 0
    queries_failed: int = 0


# ---------------------------------------------------------------------------
# HTTP client for Shodan API
# ---------------------------------------------------------------------------

def _build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=5, pool_maxsize=10)
    session.mount("https://", adapter)
    return session


def _api_get(
    session: requests.Session,
    endpoint: str,
    params: Dict[str, Any],
    api_key: str,
    delay: float,
) -> Optional[Dict]:
    """
    Perform one authenticated GET against the Shodan REST API.
    Handles rate-limit 429 with exponential back-off on top of Retry.
    """
    params["key"] = api_key
    url = _SHODAN_BASE + endpoint
    for attempt in range(3):
        try:
            resp = session.get(url, params=params, timeout=15.0)
            if resp.status_code == 429:
                wait = delay * (2 ** attempt) * 3
                logger.warning(f"[shodan] 429 rate-limit — sleeping {wait:.1f}s")
                time.sleep(wait)
                continue
            if resp.status_code == 401:
                logger.error("[shodan] API key invalid or plan limit reached")
                return None
            if resp.status_code != 200:
                logger.debug(f"[shodan] HTTP {resp.status_code} for {url}")
                return None
            time.sleep(delay)
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            logger.debug(f"[shodan] request error: {exc}")
            time.sleep(delay)
    return None


# ---------------------------------------------------------------------------
# API info — determines plan tier and remaining credits
# ---------------------------------------------------------------------------

def _fetch_api_info(session: requests.Session, api_key: str) -> Dict:
    data = _api_get(session, "/api-info", {}, api_key, 0)
    return data or {}


def _is_paid_plan(api_info: Dict) -> bool:
    plan = (api_info.get("plan") or "").lower()
    return plan not in ("", "dev", "free", "community")


# ---------------------------------------------------------------------------
# Host record parser
# ---------------------------------------------------------------------------

def _parse_match(match: Dict, query: str, category: str) -> ShodanHost:
    """Parse one Shodan search match dict into a typed ShodanHost."""
    loc = match.get("location") or {}
    ssl = match.get("ssl") or {}
    cert = ssl.get("cert") or {}
    subject = cert.get("subject") or {}
    ext = cert.get("extensions") or []
    sans: List[str] = []
    for e in ext:
        if isinstance(e, dict) and e.get("name") == "subjectAltName":
            # e.g. "DNS:*.example.com, DNS:example.com"
            raw = e.get("data", "")
            sans = [s.strip().lstrip("DNS:") for s in raw.split(",") if "DNS:" in s]

    http = match.get("http") or {}
    banner_raw = match.get("data") or ""

    return ShodanHost(
        ip=match.get("ip_str", ""),
        port=match.get("port", 0),
        transport=match.get("transport", "tcp"),
        product=match.get("product") or None,
        version=match.get("version") or None,
        os=match.get("os") or None,
        banner=banner_raw[:300] if banner_raw else None,
        http_title=(http.get("title") or "")[:120] or None,
        http_server=(http.get("server") or "") or None,
        ssl_cn=subject.get("CN") or None,
        ssl_sans=sans,
        org=match.get("org") or None,
        isp=match.get("isp") or None,
        asn=match.get("asn") or None,
        country=loc.get("country_name") or None,
        city=loc.get("city") or None,
        hostnames=match.get("hostnames") or [],
        cves=list((match.get("vulns") or {}).keys()),
        tags=match.get("tags") or [],
        last_update=match.get("timestamp") or None,
        query=query,
        category=category,
        severity=_CATEGORY_SEVERITY.get(category, "info"),
    )


# ---------------------------------------------------------------------------
# Phase 1 — dork search
# ---------------------------------------------------------------------------

def _run_dork(
    session: requests.Session,
    api_key: str,
    query: str,
    category: str,
    description: str,
    state: ShodanScanState,
    delay: float,
    max_results: int,
) -> None:
    """Execute one dork query and merge results into *state*."""
    params = {
        "query":  query,
        "facets": "org,country,port,os,product",
        "minify": "true",
    }
    data = _api_get(session, "/shodan/host/search", params, api_key, delay)
    with state.lock:
        state.queries_run += 1
    if not data:
        with state.lock:
            state.queries_failed += 1
        return

    matches = data.get("matches") or []
    for match in matches[:max_results]:
        host = _parse_match(match, query, category)
        key = (host.ip, host.port)
        with state.lock:
            if key in state.seen_ip_port:
                continue
            state.seen_ip_port.add(key)
            state.hosts.append(host)

            # Promote org / ASN if not yet known
            if not state.org and host.org:
                state.org = host.org
            if not state.asn and host.asn:
                state.asn = host.asn


# ---------------------------------------------------------------------------
# Phase 2 — per-IP deep lookup
# ---------------------------------------------------------------------------

def _ip_deep_lookup(
    session: requests.Session,
    api_key: str,
    ip: str,
    state: ShodanScanState,
    delay: float,
) -> None:
    """
    Retrieve the full Shodan host record for *ip*.
    Surfaces ports / CVEs not caught by search matches (which are paginated).
    """
    data = _api_get(session, f"/shodan/host/{ip}", {}, api_key, delay)
    if not data or "error" in data:
        return

    # Promote org/ASN
    with state.lock:
        if not state.org:
            state.org = data.get("org")
        if not state.asn:
            state.asn = data.get("asn")

    for port_data in data.get("data") or []:
        host = _parse_match(
            {**port_data, "ip_str": ip,
             "org": data.get("org"), "isp": data.get("isp"),
             "asn": data.get("asn"),
             "location": {"country_name": data.get("country_name"),
                          "city": data.get("city")},
             "hostnames": data.get("hostnames", []),
             "tags": data.get("tags", [])},
            query="ip-deep-lookup",
            category="domain",
        )
        key = (host.ip, host.port)
        with state.lock:
            if key not in state.seen_ip_port:
                state.seen_ip_port.add(key)
                state.hosts.append(host)


# ---------------------------------------------------------------------------
# Phase 3 — SSL cert pivot (find related IPs sharing the same cert)
# ---------------------------------------------------------------------------

def _ssl_cert_pivot(
    session: requests.Session,
    api_key: str,
    domain: str,
    state: ShodanScanState,
    delay: float,
) -> None:
    """
    Search for every IP whose TLS certificate includes *domain* in SAN or CN.
    Often reveals origin IPs hiding behind CDN.
    """
    queries = [
        f'ssl.cert.subject.cn:"{domain}"',
        f'ssl.cert.subject.cn:"*.{domain}"',
        f'ssl:"*.{domain}"',
    ]
    for query in queries:
        params = {"query": query, "minify": "true"}
        data = _api_get(session, "/shodan/host/search", params, api_key, delay)
        if not data:
            continue
        for match in (data.get("matches") or [])[:30]:
            host = _parse_match(match, query, "ssl")
            key = (host.ip, host.port)
            with state.lock:
                if key not in state.seen_ip_port:
                    state.seen_ip_port.add(key)
                    state.hosts.append(host)
                state.queries_run += 1


# ---------------------------------------------------------------------------
# Phase 4 — favicon hash pivot
# ---------------------------------------------------------------------------

def _favicon_hash(icon_bytes: bytes) -> int:
    """
    Compute Shodan-compatible MurmurHash3 of a base64-encoded favicon.
    Shodan indexes http.favicon.hash using this exact algorithm.
    """
    import base64, struct

    b64 = base64.encodebytes(icon_bytes).decode()

    def _mm3_x86_32(data: bytes, seed: int = 0) -> int:
        c1, c2 = 0xcc9e2d51, 0x1b873593
        length = len(data)
        h1 = seed & 0xFFFFFFFF
        chunk_size = 4
        num_chunks = length // chunk_size

        for i in range(num_chunks):
            k1 = struct.unpack("<I", data[i * chunk_size:(i + 1) * chunk_size])[0]
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1
            h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
            h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

        tail = data[num_chunks * chunk_size:]
        k1 = 0
        tail_size = length & 3
        if tail_size >= 3: k1 ^= tail[2] << 16
        if tail_size >= 2: k1 ^= tail[1] << 8
        if tail_size >= 1:
            k1 ^= tail[0]
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1

        h1 ^= length
        h1 ^= h1 >> 16
        h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
        h1 ^= h1 >> 13
        h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
        h1 ^= h1 >> 16

        # Return as signed int32 to match Shodan's encoding
        return h1 if h1 < 0x80000000 else h1 - 0x100000000

    return _mm3_x86_32(b64.encode())


def _favicon_pivot(
    session: requests.Session,
    api_key: str,
    target_url: str,
    state: ShodanScanState,
    delay: float,
) -> Optional[int]:
    """
    Fetch /favicon.ico from *target_url*, compute its Shodan hash,
    then search for every host exposing the same favicon — common
    technique to discover origin IPs behind reverse proxies / CDNs.
    """
    favicon_url = target_url.rstrip("/") + "/favicon.ico"
    try:
        resp = requests.get(favicon_url, timeout=8.0, verify=False,
                            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200 or not resp.content:
            return None
        fav_hash = _favicon_hash(resp.content)
    except requests.RequestException:
        return None

    logger.info(f"[shodan] favicon hash: {fav_hash}")

    query = f"http.favicon.hash:{fav_hash}"
    params = {"query": query, "minify": "true"}
    data = _api_get(session, "/shodan/host/search", params, api_key, delay)
    with state.lock:
        state.queries_run += 1

    if not data:
        return fav_hash

    for match in (data.get("matches") or [])[:30]:
        host = _parse_match(match, query, "domain")
        key = (host.ip, host.port)
        with state.lock:
            if key not in state.seen_ip_port:
                state.seen_ip_port.add(key)
                # Mark explicitly — favicons are a strong origin-IP signal
                host.tags = list(set(host.tags + ["favicon-pivot"]))
                state.hosts.append(host)

    return fav_hash


# ---------------------------------------------------------------------------
# Phase 5 — network range sweep (ASN CIDR)
# ---------------------------------------------------------------------------

def _asn_cidr_sweep(
    session: requests.Session,
    api_key: str,
    asn: str,
    state: ShodanScanState,
    delay: float,
) -> None:
    """
    Pull every host Shodan knows about in the given ASN.
    Useful for org-wide exposure mapping.
    """
    # Strip leading 'AS' if present
    asn_num = asn.lstrip("ASas")
    query = f"asn:AS{asn_num}"
    params = {"query": query, "facets": "port,country,product", "minify": "true"}
    data = _api_get(session, "/shodan/host/search", params, api_key, delay)
    with state.lock:
        state.queries_run += 1
    if not data:
        return

    for match in (data.get("matches") or [])[:50]:
        host = _parse_match(match, query, "domain")
        key = (host.ip, host.port)
        with state.lock:
            if key not in state.seen_ip_port:
                state.seen_ip_port.add(key)
                state.hosts.append(host)


# ---------------------------------------------------------------------------
# Phase 6 — CVE / vulnerability cross-reference
# ---------------------------------------------------------------------------

_HIGH_PRIORITY_CVES = [
    "CVE-2021-44228",   # Log4Shell
    "CVE-2021-26855",   # ProxyLogon
    "CVE-2021-34527",   # PrintNightmare
    "CVE-2022-26134",   # Confluence RCE
    "CVE-2022-22965",   # Spring4Shell
    "CVE-2023-23397",   # Outlook NTLM
    "CVE-2023-44487",   # HTTP/2 Rapid Reset
    "CVE-2024-21762",   # Fortinet SSL-VPN
    "CVE-2024-3400",    # PAN-OS cmdi
]


def _cve_deep_search(
    session: requests.Session,
    api_key: str,
    domain: str,
    state: ShodanScanState,
    delay: float,
) -> None:
    """
    For each high-priority CVE, check whether any host under *domain* is listed.
    Supplements the vuln: dork by being exhaustive against the fixed CVE list.
    """
    for cve in _HIGH_PRIORITY_CVES:
        query = f"hostname:{domain} vuln:{cve}"
        params = {"query": query, "minify": "true"}
        data = _api_get(session, "/shodan/host/search", params, api_key, delay)
        with state.lock:
            state.queries_run += 1
        if not data:
            continue
        for match in (data.get("matches") or [])[:10]:
            host = _parse_match(match, query, "vuln")
            key = (host.ip, host.port)
            with state.lock:
                if key not in state.seen_ip_port:
                    state.seen_ip_port.add(key)
                    state.hosts.append(host)
                # Ensure CVE is recorded even if host was seen via another query
                for existing in state.hosts:
                    if existing.ip == host.ip and existing.port == host.port:
                        if cve not in existing.cves:
                            existing.cves.append(cve)


# ---------------------------------------------------------------------------
# Finding synthesis
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _synthesise_findings(state: ShodanScanState) -> List[ShodanFinding]:
    """
    Collapse collected hosts into actionable ShodanFinding objects.
    One finding per unique (ip, port) — higher-severity category wins
    when a host appears under multiple queries.
    """
    # Build the highest-severity category per (ip, port)
    best: Dict[Tuple[str, int], ShodanHost] = {}
    for host in state.hosts:
        key = (host.ip, host.port)
        if key not in best:
            best[key] = host
        else:
            existing = best[key]
            if _SEV_ORDER.get(host.severity, 9) < _SEV_ORDER.get(existing.severity, 9):
                best[key] = host
            # Merge CVEs
            for cve in host.cves:
                if cve not in existing.cves:
                    existing.cves.append(cve)

    findings: List[ShodanFinding] = []
    for (ip, port), host in best.items():
        evidence_parts = [f"port {port}/{host.transport}"]
        if host.product:
            evidence_parts.append(host.product + (f" {host.version}" if host.version else ""))
        if host.http_title:
            evidence_parts.append(f'title="{host.http_title}"')
        if host.cves:
            evidence_parts.append(f"CVEs: {', '.join(host.cves[:5])}")
        if "favicon-pivot" in host.tags:
            evidence_parts.append("favicon-match (possible origin IP)")

        findings.append(ShodanFinding(
            ip=ip,
            port=port,
            severity=host.severity,
            category=host.category,
            description=_CATEGORY_SEVERITY.get(host.category, host.category),
            evidence=" | ".join(evidence_parts),
            cves=host.cves,
            product=host.product,
            version=host.version,
        ))

    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.ip, f.port))
    return findings


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------

def _build_summary(state: ShodanScanState, findings: List[ShodanFinding]) -> Dict:
    sev_count: Dict[str, int] = {}
    cat_count: Dict[str, int] = {}
    port_count: Dict[int, int] = {}
    country_count: Dict[str, int] = {}
    all_cves: Set[str] = set()

    for host in state.hosts:
        sev_count[host.severity] = sev_count.get(host.severity, 0) + 1
        cat_count[host.category] = cat_count.get(host.category, 0) + 1
        port_count[host.port] = port_count.get(host.port, 0) + 1
        if host.country:
            country_count[host.country] = country_count.get(host.country, 0) + 1
        for cve in host.cves:
            all_cves.add(cve)

    top_ports = sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:10]
    top_countries = sorted(country_count.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "severity_distribution": sev_count,
        "category_distribution": cat_count,
        "top_ports": [{"port": p, "count": c} for p, c in top_ports],
        "top_countries": [{"country": c, "count": n} for c, n in top_countries],
        "unique_ips": len({h.ip for h in state.hosts}),
        "total_cves": sorted(all_cves),
        "critical_cves": [c for c in all_cves if c in _HIGH_PRIORITY_CVES],
        "org": state.org,
        "asn": state.asn,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class ShodanProbe:
    """
    Deep Shodan intelligence probe.

    Runs multi-phase enumeration:
      1. Dork query sweep (domain + org scoped)
      2. Per-IP deep lookup for every discovered / supplied IP
      3. SSL certificate pivot (origin-IP discovery)
      4. Favicon hash pivot (CDN bypass)
      5. ASN CIDR sweep (org-wide exposure)
      6. CVE cross-reference against high-priority vulnerability list

    Usage in app.py:
        probe = ShodanProbe(
            domain=domain,
            api_key=os.getenv('SHODAN_API_KEY'),
            known_ips=discovered_ips,
            target_url=f"https://{domain}",
        )
        results = probe.scan()
        scan_results[scan_id]['shodan_probe'] = results
    """

    def __init__(
        self,
        domain: str,
        api_key: Optional[str] = None,
        known_ips: Optional[Set[str]] = None,
        target_url: Optional[str] = None,
        max_results_per_query: int = 20,
        enable_favicon_pivot: bool = True,
        enable_asn_sweep: bool = True,
        enable_cve_deep: bool = True,
        max_ip_deep_lookups: int = 10,
    ):
        self.domain = domain
        self.api_key = api_key or os.getenv("SHODAN_API_KEY", "")
        self.known_ips: Set[str] = known_ips or set()
        self.target_url = target_url or f"https://{domain}"
        self.max_results_per_query = max_results_per_query
        self.enable_favicon_pivot = enable_favicon_pivot
        self.enable_asn_sweep = enable_asn_sweep
        self.enable_cve_deep = enable_cve_deep
        self.max_ip_deep_lookups = max_ip_deep_lookups

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _expand_dorks(self, org: Optional[str]) -> List[Tuple[str, str, str]]:
        """Substitute {domain} and {org} into all dork templates."""
        expanded: List[Tuple[str, str, str]] = []
        for template, category, desc in _DORK_TEMPLATES:
            expanded.append((
                template.replace("{domain}", self.domain),
                category, desc,
            ))
        if org:
            for template, category, desc in _ORG_DORK_TEMPLATES:
                expanded.append((
                    template.replace("{org}", org),
                    category, desc,
                ))
        return expanded

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if not self.api_key:
            return {
                "error": "SHODAN_API_KEY not set",
                "domain": self.domain,
                "hosts": [],
                "findings": [],
                "summary": {},
            }

        session = _build_session()

        # Determine plan tier → rate-limit delay
        api_info = _fetch_api_info(session, self.api_key)
        paid = _is_paid_plan(api_info)
        delay = _PAID_TIER_DELAY if paid else _FREE_TIER_DELAY
        plan = api_info.get("plan", "unknown")
        credits_remaining = api_info.get("query_credits", "?")

        print(f"[shodan] domain  : {self.domain}")
        print(f"[shodan] plan    : {plan} | credits: {credits_remaining} | delay: {delay}s")

        state = ShodanScanState(
            domain=self.domain,
            org=None,
            asn=None,
            known_ips=set(self.known_ips),
        )

        # ── Phase 1: dork sweep ────────────────────────────────────────────
        dorks = self._expand_dorks(org=None)
        print(f"[shodan] phase 1: {len(dorks)} dork queries")

        # Run dorks sequentially to stay within rate limits
        for query, category, desc in dorks:
            _run_dork(
                session, self.api_key, query, category, desc,
                state, delay, self.max_results_per_query,
            )

        # ── Phase 2: per-IP deep lookup ────────────────────────────────────
        all_ips: Set[str] = {h.ip for h in state.hosts} | state.known_ips
        deep_ips = list(all_ips)[:self.max_ip_deep_lookups]
        print(f"[shodan] phase 2: deep lookup on {len(deep_ips)} IPs")
        for ip in deep_ips:
            _ip_deep_lookup(session, self.api_key, ip, state, delay)

        # Now that org is known, run org-scoped dorks
        if state.org:
            print(f"[shodan] phase 2b: org dorks for '{state.org}'")
            org_dorks = self._expand_dorks(org=state.org)
            # Only the org-specific ones — avoid re-running domain dorks
            new_org_dorks = [(q, c, d) for q, c, d in org_dorks
                             if "{domain}" not in q]
            for query, category, desc in new_org_dorks:
                _run_dork(
                    session, self.api_key, query, category, desc,
                    state, delay, self.max_results_per_query,
                )

        # ── Phase 3: SSL cert pivot ────────────────────────────────────────
        print(f"[shodan] phase 3: SSL cert pivot")
        _ssl_cert_pivot(session, self.api_key, self.domain, state, delay)

        # ── Phase 4: favicon pivot ─────────────────────────────────────────
        favicon_hash: Optional[int] = None
        if self.enable_favicon_pivot:
            print(f"[shodan] phase 4: favicon hash pivot")
            favicon_hash = _favicon_pivot(
                session, self.api_key, self.target_url, state, delay
            )

        # ── Phase 5: ASN CIDR sweep ────────────────────────────────────────
        if self.enable_asn_sweep and state.asn:
            print(f"[shodan] phase 5: ASN sweep ({state.asn})")
            _asn_cidr_sweep(session, self.api_key, state.asn, state, delay)

        # ── Phase 6: CVE cross-reference ───────────────────────────────────
        if self.enable_cve_deep:
            print(f"[shodan] phase 6: CVE deep search")
            _cve_deep_search(session, self.api_key, self.domain, state, delay)

        # ── Synthesis ──────────────────────────────────────────────────────
        findings = _synthesise_findings(state)
        summary  = _build_summary(state, findings)

        print(
            f"[shodan] done | hosts={len(state.hosts)} "
            f"findings={len(findings)} "
            f"queries={state.queries_run} failed={state.queries_failed}"
        )

        return {
            "domain":         self.domain,
            "org":            state.org,
            "asn":            state.asn,
            "plan":           plan,
            "favicon_hash":   favicon_hash,
            "queries_run":    state.queries_run,
            "queries_failed": state.queries_failed,
            "total_hosts":    len(state.hosts),
            "summary":        summary,
            "findings":       [self._ser_finding(f) for f in findings],
            "hosts":          [self._ser_host(h) for h in state.hosts],
        }

    @staticmethod
    def _ser_host(h: ShodanHost) -> Dict:
        return {
            "ip":          h.ip,
            "port":        h.port,
            "transport":   h.transport,
            "product":     h.product,
            "version":     h.version,
            "os":          h.os,
            "banner":      h.banner,
            "http_title":  h.http_title,
            "http_server": h.http_server,
            "ssl_cn":      h.ssl_cn,
            "ssl_sans":    h.ssl_sans,
            "org":         h.org,
            "isp":         h.isp,
            "asn":         h.asn,
            "country":     h.country,
            "city":        h.city,
            "hostnames":   h.hostnames,
            "cves":        h.cves,
            "tags":        h.tags,
            "last_update": h.last_update,
            "query":       h.query,
            "category":    h.category,
            "severity":    h.severity,
        }

    @staticmethod
    def _ser_finding(f: ShodanFinding) -> Dict:
        return {
            "ip":          f.ip,
            "port":        f.port,
            "severity":    f.severity,
            "category":    f.category,
            "description": f.description,
            "evidence":    f.evidence,
            "cves":        f.cves,
            "product":     f.product,
            "version":     f.version,
        }