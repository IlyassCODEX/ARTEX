# modules/network_range_mapper.py
#
# Sources (all free, no API key required):
#   BGP.tools       — ASN info, prefix list, peer list
#   RIPEstat API    — RIPE NCC authoritative prefix data, routing history
#   Hurricane Electric BGP Toolkit — ASN peer / upstream data
#   ARIN RDAP       — North American IP block registration
#   RIPE RDAP       — European / global IP block registration
#   APNIC RDAP      — Asia-Pacific IP block registration
#   Routeviews      — BGP table snapshot (passive)
#   ip-api.com      — Reverse IP→ASN lookup for discovered IPs
#   Shodan FaviconHash / SSL pivot (optional, via SHODAN_API_KEY)
#   WHOIS raw       — TCP port 43 whois as last-resort fallback

import os
import re
import csv
import gzip
import json
import math
import time
import socket
import struct
import hashlib
import logging
import ipaddress
import threading
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import StringIO, BytesIO
from typing import Dict, Iterator, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Source constants
# ---------------------------------------------------------------------------

_BGPTOOLS_BASE    = "https://bgp.tools"
_RIPESTAT_BASE    = "https://stat.ripe.net/data"
_HE_BGP_BASE      = "https://bgp.he.net"
_IPAPI_BASE       = "http://ip-api.com/json"
_RDAP_ARIN        = "https://rdap.arin.net/registry"
_RDAP_RIPE        = "https://rdap.db.ripe.net"
_RDAP_APNIC       = "https://rdap.apnic.net"
_RDAP_LACNIC      = "https://rdap.lacnic.net/rdap"
_RDAP_AFRINIC     = "https://rdap.afrinic.net/rdap"
_CYMRU_WHOIS_HOST = "whois.cymru.com"
_CYMRU_WHOIS_PORT = 43
_ROUTEVIEWS_BASE  = "http://archive.routeviews.org"

# RIR allocation table URLs — updated daily snapshots
_RIR_DELEGATION_URLS: Dict[str, str] = {
    "arin":    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "ripe":    "https://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest",
    "apnic":   "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "lacnic":  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "afrinic": "https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest",
}

# Cloud provider ASN map (supplement to Shodan ASN detection)
_CLOUD_ASN: Dict[str, str] = {
    "AS16509": "Amazon AWS",    "AS14618": "Amazon AWS",
    "AS15169": "Google Cloud",  "AS396982": "Google Cloud",
    "AS8075":  "Microsoft Azure","AS8068": "Microsoft Azure",
    "AS13335": "Cloudflare",    "AS209242": "Cloudflare",
    "AS54113": "Fastly",        "AS20940": "Akamai",
    "AS16276": "OVH",           "AS14061": "DigitalOcean",
    "AS63949": "Linode/Akamai", "AS36351": "IBM SoftLayer",
    "AS19551": "Incapsula",     "AS22822": "Limelight",
    "AS32934": "Facebook/Meta", "AS15133": "Edgecast",
    "AS30675": "Rackspace",     "AS35994": "Neustar",
    "AS26496": "GoDaddy",       "AS46606": "Unified Layer",
    "AS2635":  "Automattic",    "AS7224":  "Amazon CloudFront",
    "AS16625": "Akamai",        "AS23454": "Zscaler",
    "AS55967": "Baidu Cloud",   "AS45090": "Tencent Cloud",
    "AS37963": "Alibaba Cloud",
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ASNRecord:
    asn:          str           # e.g. "AS15169"
    asn_number:   int
    name:         str
    description:  str
    country:      str
    rir:          str           # arin / ripe / apnic / lacnic / afrinic
    prefixes_v4:  List[str]     # list of CIDR strings
    prefixes_v6:  List[str]
    peer_asns:    List[str]
    upstream_asns:List[str]
    cloud_provider: Optional[str]
    total_ipv4:   int           # sum of host addresses across all v4 prefixes
    source:       str           # which source provided this record


@dataclass
class IPBlock:
    cidr:         str
    network:      ipaddress.IPv4Network
    asn:          str
    asn_name:     str
    country:      str
    rir:          str
    allocated:    Optional[str]  # allocation date
    status:       str            # allocated / assigned / reserved / available
    is_cloud:     bool
    cloud_provider: Optional[str]
    host_count:   int


@dataclass
class HostRecord:
    ip:           str
    asn:          str
    asn_name:     str
    cidr:         str
    country:      str
    org:          str
    is_cloud:     bool
    cloud_provider: Optional[str]
    ptr:          Optional[str]  # reverse DNS
    open_ports:   List[int]      # from Shodan if available


@dataclass
class ScanState:
    domain:         str
    seed_ips:       Set[str]
    asn_records:    Dict[str, ASNRecord]   # asn → record
    ip_blocks:      List[IPBlock]
    host_records:   List[HostRecord]
    pivot_asns:     Set[str]
    all_cidrs:      Set[str]
    lock:           threading.Lock = field(default_factory=threading.Lock)


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def _build_session(proxy: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; ARTEX-NetMapper/1.0)"
    })
    return session


def _jget(session: requests.Session, url: str,
          params: Optional[Dict] = None,
          timeout: float = 15.0) -> Optional[Dict]:
    try:
        resp = session.get(url, params=params, timeout=timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.debug(f"[net_mapper] GET {url}: {exc}")
        return None


def _tget(session: requests.Session, url: str,
          params: Optional[Dict] = None,
          timeout: float = 15.0) -> Optional[str]:
    try:
        resp = session.get(url, params=params, timeout=timeout)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as exc:
        logger.debug(f"[net_mapper] GET {url}: {exc}")
        return None


# ---------------------------------------------------------------------------
# IP utilities
# ---------------------------------------------------------------------------

def _asn_normalize(raw: str) -> str:
    """Ensure ASN is in 'AS12345' format."""
    raw = str(raw).strip().upper()
    if raw.startswith("AS"):
        return raw
    if raw.isdigit():
        return f"AS{raw}"
    return raw


def _cidr_host_count(cidr: str) -> int:
    """Return usable host count for a CIDR string."""
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        return max(0, net.num_addresses - 2)
    except ValueError:
        return 0


def _prefix_len_to_cidr(ip: str, prefix_len: int) -> str:
    """Convert base-IP + prefix length to CIDR notation."""
    try:
        net = ipaddress.IPv4Network(f"{ip}/{prefix_len}", strict=False)
        return str(net)
    except ValueError:
        return f"{ip}/{prefix_len}"


def _ip_in_range(ip: str, cidrs: List[str]) -> bool:
    """Return True if *ip* falls within any of the CIDR ranges."""
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in cidrs:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False


def _resolve_ip(hostname: str, timeout: float = 3.0) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except socket.error:
        return None


def _reverse_dns(ip: str, timeout: float = 3.0) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except socket.error:
        return None


# ---------------------------------------------------------------------------
# Source 1 — BGP.tools
# ---------------------------------------------------------------------------

def _bgptools_asn_info(session: requests.Session, asn: str) -> Optional[Dict]:
    """
    Pull ASN summary from BGP.tools /api/asn/<asn>.
    Returns raw dict with name, country, prefixes.
    """
    num = asn.lstrip("ASas")
    data = _jget(session, f"{_BGPTOOLS_BASE}/api/asn/{num}", timeout=10.0)
    return data


def _bgptools_prefixes(session: requests.Session, asn: str) -> List[str]:
    """
    Fetch all IPv4 prefixes announced by *asn* from BGP.tools /api/prefixes.
    """
    num  = asn.lstrip("ASas")
    data = _jget(session, f"{_BGPTOOLS_BASE}/api/prefixes/{num}", timeout=12.0)
    if not data:
        return []
    prefixes: List[str] = []
    for entry in data.get("ipv4Prefixes", []):
        pfx = entry.get("prefix") or entry if isinstance(entry, str) else None
        if pfx:
            prefixes.append(pfx)
    return prefixes


def _bgptools_peers(session: requests.Session, asn: str) -> Tuple[List[str], List[str]]:
    """
    Return (peer_asns, upstream_asns) for *asn* from BGP.tools.
    """
    num  = asn.lstrip("ASas")
    data = _jget(session, f"{_BGPTOOLS_BASE}/api/asn/{num}", timeout=10.0)
    if not data:
        return [], []
    peers    = [_asn_normalize(str(p)) for p in data.get("peers", [])]
    upstream = [_asn_normalize(str(u)) for u in data.get("upstreams", [])]
    return peers, upstream


# ---------------------------------------------------------------------------
# Source 2 — RIPEstat API
# ---------------------------------------------------------------------------

def _ripestat_announced_prefixes(session: requests.Session, asn: str) -> List[str]:
    """
    Query RIPEstat /announced-prefixes for all BGP-announced prefixes.
    More comprehensive than BGP.tools — includes withdrawn/historical.
    """
    url  = f"{_RIPESTAT_BASE}/announced-prefixes/data.json"
    data = _jget(session, url, params={"resource": asn, "min_peers_seeing": "1"}, timeout=15.0)
    if not data:
        return []

    prefixes: List[str] = []
    for entry in (data.get("data", {}).get("prefixes") or []):
        pfx = entry.get("prefix")
        if pfx and ":" not in pfx:   # IPv4 only
            prefixes.append(pfx)
    return prefixes


def _ripestat_routing_history(session: requests.Session, asn: str) -> List[Dict]:
    """
    Pull BGP routing history for *asn* — reveals historically announced
    prefixes that may still host live infrastructure.
    """
    url  = f"{_RIPESTAT_BASE}/routing-history/data.json"
    data = _jget(session, url, params={"resource": asn, "max_rows": "200"}, timeout=15.0)
    if not data:
        return []

    history: List[Dict] = []
    for entry in (data.get("data", {}).get("by_origin") or []):
        for prefix_data in entry.get("prefixes", []):
            pfx = prefix_data.get("prefix")
            if pfx and ":" not in pfx:
                history.append({
                    "prefix":      pfx,
                    "first_seen":  prefix_data.get("timelines", [{}])[0].get("starttime"),
                    "last_seen":   prefix_data.get("timelines", [{}])[-1].get("endtime"),
                    "withdrawn":   not prefix_data.get("timelines", [{}])[-1].get("endtime", "").startswith("2099"),
                })
    return history


def _ripestat_asn_neighbours(session: requests.Session, asn: str) -> Dict[str, List[str]]:
    """
    Return ASN neighbours (peers + upstreams + downstreams) from RIPEstat.
    """
    url  = f"{_RIPESTAT_BASE}/asn-neighbours/data.json"
    data = _jget(session, url, params={"resource": asn}, timeout=12.0)
    if not data:
        return {"peers": [], "upstreams": [], "downstreams": []}

    result: Dict[str, List[str]] = {"peers": [], "upstreams": [], "downstreams": []}
    for nb in (data.get("data", {}).get("neighbours") or []):
        nb_type = nb.get("type", "")
        nb_asn  = _asn_normalize(str(nb.get("asn", "")))
        if nb_type == "left":
            result["upstreams"].append(nb_asn)
        elif nb_type == "right":
            result["downstreams"].append(nb_asn)
        elif nb_type == "uncertain":
            result["peers"].append(nb_asn)
    return result


def _ripestat_ip_overview(session: requests.Session, ip: str) -> Optional[Dict]:
    """
    Reverse lookup: given an IP, find its ASN + allocation info via RIPEstat.
    """
    url  = f"{_RIPESTAT_BASE}/prefix-overview/data.json"
    data = _jget(session, url, params={"resource": ip}, timeout=10.0)
    if not data:
        return None
    d = data.get("data", {})
    return {
        "asns":    [_asn_normalize(str(a.get("asn",""))) for a in d.get("asns", [])],
        "prefix":  d.get("resource"),
        "is_less_specific": d.get("is_less_specific", False),
    }


# ---------------------------------------------------------------------------
# Source 3 — ip-api.com (reverse IP→ASN)
# ---------------------------------------------------------------------------

def _ipapi_lookup(session: requests.Session, ip: str) -> Optional[Dict]:
    url  = f"{_IPAPI_BASE}/{ip}"
    params = {
        "fields": "status,country,regionName,city,isp,org,as,asname,hosting,query"
    }
    data = _jget(session, url, params=params, timeout=8.0)
    if not data or data.get("status") != "success":
        return None
    return data


def _ipapi_batch(session: requests.Session, ips: List[str]) -> List[Dict]:
    """
    Batch lookup up to 100 IPs at once via ip-api.com /batch endpoint.
    Rate limited to 15 requests/minute on the free tier.
    """
    results: List[Dict] = []
    for chunk in [ips[i:i+100] for i in range(0, len(ips), 100)]:
        try:
            resp = session.post(
                "http://ip-api.com/batch",
                json=[{"query": ip, "fields": "status,country,isp,org,as,asname,hosting,query"}
                      for ip in chunk],
                timeout=15.0,
            )
            resp.raise_for_status()
            results.extend(resp.json())
            time.sleep(1.5)   # respect rate limit
        except (requests.RequestException, ValueError):
            pass
    return results


# ---------------------------------------------------------------------------
# Source 4 — Team Cymru WHOIS (TCP port 43)
# ---------------------------------------------------------------------------

def _cymru_whois_lookup(ips: List[str], timeout: float = 8.0) -> Dict[str, Dict]:
    """
    Query Team Cymru IP-to-ASN WHOIS service over TCP port 43.
    Returns {ip: {asn, prefix, country, registry, allocated, name}}.
    Very fast — handles thousands of IPs per session.
    """
    results: Dict[str, Dict] = {}
    if not ips:
        return results

    try:
        sock = socket.create_connection((_CYMRU_WHOIS_HOST, _CYMRU_WHOIS_PORT),
                                         timeout=timeout)
        sock.settimeout(timeout)

        # Begin batch mode
        sock.sendall(b"begin\nverbose\n")
        for ip in ips[:500]:    # hard cap
            sock.sendall(f"{ip}\n".encode())
        sock.sendall(b"end\n")

        raw = b""
        while True:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                raw += chunk
            except socket.timeout:
                break
        sock.close()

        # Parse CSV-like output
        # Format: ASN | IP | Prefix | CC | Registry | Allocated | AS Name
        for line in raw.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("Bulk") or "|" not in line:
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 7:
                continue
            asn_raw, ip_raw, prefix, cc, registry, allocated, name = parts[:7]
            ip_raw = ip_raw.strip()
            if ip_raw in ips:
                results[ip_raw] = {
                    "asn":        _asn_normalize(asn_raw) if asn_raw.isdigit() else asn_raw,
                    "prefix":     prefix,
                    "country":    cc,
                    "registry":   registry.lower(),
                    "allocated":  allocated,
                    "name":       name,
                }

    except (socket.error, OSError) as exc:
        logger.debug(f"[cymru_whois] socket error: {exc}")

    return results


# ---------------------------------------------------------------------------
# Source 5 — RDAP IP block lookup
# ---------------------------------------------------------------------------

_RDAP_REGISTRY_MAP: Dict[str, str] = {
    "arin":    _RDAP_ARIN,
    "ripe":    _RDAP_RIPE,
    "apnic":   _RDAP_APNIC,
    "lacnic":  _RDAP_LACNIC,
    "afrinic": _RDAP_AFRINIC,
}


def _rdap_ip(session: requests.Session, ip: str,
             registry: str = "arin") -> Optional[Dict]:
    """
    RDAP lookup for a single IP address.
    Returns allocation record with CIDR, org, country, dates.
    """
    base = _RDAP_REGISTRY_MAP.get(registry.lower(), _RDAP_ARIN)
    data = _jget(session, f"{base}/ip/{ip}", timeout=10.0)
    if not data:
        # Fallback: try ARIN which often redirects to correct RIR
        data = _jget(session, f"{_RDAP_ARIN}/ip/{ip}", timeout=10.0)
    if not data:
        return None

    # Extract CIDR
    start = data.get("startAddress", "")
    end   = data.get("endAddress", "")
    cidr  = data.get("handle", "")

    # Try to get CIDR from startAddress/prefixLength
    prefix_len = data.get("cidr0_cidrs", [{}])
    if isinstance(prefix_len, list) and prefix_len:
        cidr = f"{prefix_len[0].get('v4prefix','')}/{prefix_len[0].get('length','')}"

    # Org name from entities
    org = None
    for entity in (data.get("entities") or []):
        for role in entity.get("roles", []):
            if role in ("registrant", "administrative"):
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            org = field[3]

    return {
        "cidr":       cidr or f"{start}/32",
        "start":      start,
        "end":        end,
        "org":        org,
        "country":    data.get("country"),
        "type":       data.get("type"),
        "name":       data.get("name"),
        "parent":     data.get("parentHandle"),
    }


# ---------------------------------------------------------------------------
# Source 6 — RIR delegation files (bulk CIDR lookup by ASN)
# ---------------------------------------------------------------------------

def _parse_rir_delegation_line(line: str) -> Optional[Dict]:
    """
    Parse one line from a RIR delegation file.
    Format: registry|cc|type|start|value|date|status[|extensions]
    """
    if line.startswith("#") or not line.strip():
        return None
    parts = line.strip().split("|")
    if len(parts) < 7:
        return None
    registry, cc, rtype, start, value, date, status = parts[:7]
    if rtype not in ("ipv4", "ipv6"):
        return None
    return {
        "registry": registry.lower(),
        "cc":       cc,
        "type":     rtype,
        "start":    start,
        "value":    int(value) if value.isdigit() else 0,
        "date":     date,
        "status":   status,
    }


def _fetch_rir_delegations_for_country(
    session: requests.Session,
    country_code: str,
    rir: str = "ripe",
) -> List[str]:
    """
    Download and parse the RIR delegation file, returning all IPv4 CIDRs
    allocated to *country_code* by *rir*.
    Used when we know the org's country but not the full prefix list.
    """
    url  = _RIR_DELEGATION_URLS.get(rir.lower())
    if not url:
        return []

    text = _tget(session, url, timeout=30.0)
    if not text:
        return []

    cidrs: List[str] = []
    for line in text.splitlines():
        entry = _parse_rir_delegation_line(line)
        if not entry:
            continue
        if entry["cc"].upper() != country_code.upper():
            continue
        if entry["type"] != "ipv4":
            continue
        # Convert start IP + host count to CIDR
        try:
            count    = entry["value"]
            prefix_len = 32 - int(math.log2(count)) if count > 0 else 32
            cidr     = _prefix_len_to_cidr(entry["start"], prefix_len)
            cidrs.append(cidr)
        except (ValueError, TypeError):
            continue

    return cidrs


# ---------------------------------------------------------------------------
# Source 7 — Shodan ASN search (optional)
# ---------------------------------------------------------------------------

def _shodan_asn_prefixes(
    session: requests.Session,
    asn: str,
    api_key: str,
) -> List[str]:
    """
    Query Shodan for the network ranges associated with *asn*.
    Returns CIDR list from Shodan's facet data.
    """
    if not api_key:
        return []
    params = {
        "query":  f"asn:{asn}",
        "facets": "net",
        "key":    api_key,
        "minify": "true",
    }
    data = _jget(session, "https://api.shodan.io/shodan/host/search", params=params, timeout=12.0)
    if not data:
        return []
    prefixes: List[str] = []
    for facet in (data.get("facets", {}).get("net") or []):
        val = facet.get("value", "")
        if "/" in val:
            prefixes.append(val)
    return prefixes


# ---------------------------------------------------------------------------
# ASN record builder
# ---------------------------------------------------------------------------

def _build_asn_record(
    session: requests.Session,
    asn: str,
    shodan_key: Optional[str] = None,
) -> ASNRecord:
    """
    Pull data from BGP.tools + RIPEstat + Cymru and build a typed ASNRecord.
    """
    asn_num = int(asn.lstrip("ASas"))

    # BGP.tools — fast, good prefix list
    bgpt_info = _bgptools_asn_info(session, asn)
    bgpt_pfxs = _bgptools_prefixes(session, asn)
    bgpt_peers, bgpt_upstream = _bgptools_peers(session, asn)

    # RIPEstat — authoritative, may have more prefixes
    ripe_pfxs    = _ripestat_announced_prefixes(session, asn)
    ripe_nb      = _ripestat_asn_neighbours(session, asn)

    # Shodan (optional)
    shodan_pfxs: List[str] = []
    if shodan_key:
        shodan_pfxs = _shodan_asn_prefixes(session, asn, shodan_key)

    # Merge + deduplicate prefixes (v4 only for now)
    all_pfx_v4: Set[str] = set()
    for p in bgpt_pfxs + ripe_pfxs + shodan_pfxs:
        if p and "/" in p and ":" not in p:
            try:
                # Normalise to canonical CIDR
                net = ipaddress.IPv4Network(p, strict=False)
                all_pfx_v4.add(str(net))
            except ValueError:
                pass

    # Merge peers/upstreams
    all_peers    = list(set(bgpt_peers + ripe_nb.get("peers", [])))
    all_upstream = list(set(bgpt_upstream + ripe_nb.get("upstreams", [])))

    # Metadata from BGP.tools or RIPEstat
    name    = (bgpt_info or {}).get("name", "") or ""
    desc    = (bgpt_info or {}).get("description", "") or ""
    country = (bgpt_info or {}).get("country", "") or ""
    rir     = (bgpt_info or {}).get("rir", "").lower() or "unknown"

    prefixes_v4 = sorted(all_pfx_v4, key=lambda p: ipaddress.IPv4Network(p, strict=False))
    total_ipv4  = sum(_cidr_host_count(p) for p in prefixes_v4)
    cloud       = _CLOUD_ASN.get(asn)

    return ASNRecord(
        asn=asn,
        asn_number=asn_num,
        name=name,
        description=desc,
        country=country,
        rir=rir,
        prefixes_v4=prefixes_v4,
        prefixes_v6=[],
        peer_asns=all_peers[:50],
        upstream_asns=all_upstream[:20],
        cloud_provider=cloud,
        total_ipv4=total_ipv4,
        source="bgptools+ripestat" + ("+shodan" if shodan_pfxs else ""),
    )


# ---------------------------------------------------------------------------
# IP block builder
# ---------------------------------------------------------------------------

def _build_ip_blocks(asn_record: ASNRecord) -> List[IPBlock]:
    """Convert an ASNRecord's prefix list into typed IPBlock objects."""
    blocks: List[IPBlock] = []
    for cidr in asn_record.prefixes_v4:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            continue
        is_cloud = asn_record.cloud_provider is not None
        blocks.append(IPBlock(
            cidr=cidr,
            network=net,
            asn=asn_record.asn,
            asn_name=asn_record.name,
            country=asn_record.country,
            rir=asn_record.rir,
            allocated=None,
            status="allocated",
            is_cloud=is_cloud,
            cloud_provider=asn_record.cloud_provider,
            host_count=net.num_addresses - 2,
        ))
    return blocks


# ---------------------------------------------------------------------------
# Host enumeration within CIDRs
# ---------------------------------------------------------------------------

def _enumerate_live_hosts(
    cidrs: List[str],
    max_hosts: int = 256,
    timeout: float = 1.0,
    max_workers: int = 50,
) -> List[str]:
    """
    Passively enumerate a sample of IPs within each CIDR using reverse DNS.
    Does NOT do TCP connect scans — only PTR record lookups.
    Caps at *max_hosts* total to avoid runaway.
    """
    candidates: List[str] = []
    for cidr in cidrs:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            # For large blocks, sample at beginning/middle/end
            if net.num_addresses > 256:
                hosts = list(itertools.islice(net.hosts(), 10))          # first 10
                mid   = net.num_addresses // 2
                hosts += [net.network_address + mid + i for i in range(5)]
                hosts += list(reversed(list(net.hosts())))[:5]            # last 5
            else:
                hosts = list(net.hosts())
            candidates.extend([str(h) for h in hosts])
            if len(candidates) >= max_hosts:
                break
        except ValueError:
            continue

    candidates = list(dict.fromkeys(candidates))[:max_hosts]

    def _ptr(ip: str) -> Optional[Tuple[str, str]]:
        ptr = _reverse_dns(ip, timeout=timeout)
        if ptr:
            return (ip, ptr)
        return None

    live: List[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_ptr, ip): ip for ip in candidates}
        for f in as_completed(futures):
            r = f.result()
            if r:
                live.append(r[0])

    return live


# ---------------------------------------------------------------------------
# ASN pivot — find related ASNs from seed data
# ---------------------------------------------------------------------------

def _pivot_asns(
    seed_asns: Set[str],
    asn_records: Dict[str, ASNRecord],
    max_pivot_depth: int = 1,
) -> Set[str]:
    """
    Discover additional ASNs by pivoting through peer/upstream relationships.
    Limited to *max_pivot_depth* hops to avoid runaway expansion.
    Returns set of new ASN strings to investigate.
    """
    seen:  Set[str] = set(seed_asns)
    queue: Set[str] = set(seed_asns)

    for _ in range(max_pivot_depth):
        next_hop: Set[str] = set()
        for asn in queue:
            rec = asn_records.get(asn)
            if not rec:
                continue
            # Only pivot to upstream ASNs (more targeted than peers)
            for nb in rec.upstream_asns[:5]:
                if nb not in seen and not _CLOUD_ASN.get(nb):
                    next_hop.add(nb)
        seen.update(next_hop)
        queue = next_hop

    return seen - set(seed_asns)


# ---------------------------------------------------------------------------
# Routing history analysis
# ---------------------------------------------------------------------------

def _analyse_routing_history(
    session: requests.Session,
    asn_records: Dict[str, ASNRecord],
) -> List[Dict]:
    """
    For each known ASN, fetch BGP routing history to surface prefixes
    that were previously announced but are now withdrawn.
    These are interesting because:
    - They may indicate old infrastructure the org still controls
    - They may be re-announced later and not in current prefix lists
    """
    historical: List[Dict] = []
    seen_prefixes: Set[str] = set()

    # Collect currently active prefixes
    for rec in asn_records.values():
        for pfx in rec.prefixes_v4:
            seen_prefixes.add(pfx)

    for asn, rec in list(asn_records.items())[:5]:   # cap to avoid rate limits
        history = _ripestat_routing_history(session, asn)
        for entry in history:
            pfx = entry.get("prefix", "")
            if pfx and pfx not in seen_prefixes and ":" not in pfx:
                historical.append({
                    "asn":        asn,
                    "prefix":     pfx,
                    "first_seen": entry.get("first_seen"),
                    "last_seen":  entry.get("last_seen"),
                    "withdrawn":  entry.get("withdrawn", True),
                })
        time.sleep(0.5)   # rate limit RIPEstat

    return historical


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------

def _build_summary(state: ScanState, historical: List[Dict]) -> Dict:
    total_v4   = sum(len(r.prefixes_v4) for r in state.asn_records.values())
    total_hosts = sum(b.host_count for b in state.ip_blocks)
    countries   = list(dict.fromkeys(
        b.country for b in state.ip_blocks if b.country
    ))
    rirs        = list(dict.fromkeys(
        b.rir for b in state.ip_blocks if b.rir
    ))
    cloud_blocks = [b for b in state.ip_blocks if b.is_cloud]

    # Prefix size distribution
    size_buckets: Dict[str, int] = {
        "/8–/16":  0, "/17–/20": 0,
        "/21–/24": 0, "/25–/32": 0,
    }
    for block in state.ip_blocks:
        plen = block.network.prefixlen
        if plen <= 16:
            size_buckets["/8–/16"] += 1
        elif plen <= 20:
            size_buckets["/17–/20"] += 1
        elif plen <= 24:
            size_buckets["/21–/24"] += 1
        else:
            size_buckets["/25–/32"] += 1

    return {
        "asns_mapped":          len(state.asn_records),
        "total_prefixes_v4":    total_v4,
        "total_host_addresses": total_hosts,
        "total_cidrs":          len(state.all_cidrs),
        "countries":            countries,
        "rirs":                 rirs,
        "cloud_blocks":         len(cloud_blocks),
        "cloud_providers":      list(dict.fromkeys(
            b.cloud_provider for b in cloud_blocks if b.cloud_provider
        )),
        "historical_prefixes":  len(historical),
        "withdrawn_prefixes":   len([h for h in historical if h["withdrawn"]]),
        "prefix_size_distribution": size_buckets,
        "host_records":         len(state.host_records),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class NetworkRangeMapper:
    """
    ASN → CIDR mapping and IP range enumeration engine.

    Maps the full network footprint of a target organisation by:

      Phase 1 — Seed ASN discovery
                Resolve seed IPs (from previous scan modules) to ASNs
                via Team Cymru WHOIS + RIPEstat reverse lookup.

      Phase 2 — ASN → prefix expansion
                For each ASN, pull announced IPv4 prefixes from
                BGP.tools + RIPEstat (+ Shodan optional).
                Builds typed ASNRecord + IPBlock objects.

      Phase 3 — ASN pivot
                Walk upstream relationships one hop to discover related
                ASNs (subsidiaries, transit providers used exclusively
                by this org) and expand their prefix lists.

      Phase 4 — Routing history analysis
                Identify historically announced but withdrawn prefixes
                via RIPEstat — surfaces old infrastructure.

      Phase 5 — Host enumeration
                Passive PTR-record sampling across discovered CIDRs
                to identify live hosts without active port scanning.

      Phase 6 — RDAP enrichment
                RDAP lookup on a sample of discovered blocks for
                allocation dates, org name, and registration status.

    Usage in app.py:
        mapper = NetworkRangeMapper(
            domain=domain,
            seed_ips=discovered_ips,
        )
        results = mapper.scan()
        scan_results[scan_id]['network_range_mapper'] = results
    """

    def __init__(
        self,
        domain: str,
        seed_ips: Optional[Set[str]] = None,
        seed_asns: Optional[Set[str]] = None,
        shodan_api_key: Optional[str] = None,
        proxy: Optional[str] = None,
        max_pivot_depth: int = 1,
        enumerate_hosts: bool = True,
        max_host_sample: int = 128,
        fetch_history: bool = True,
        timeout: float = 15.0,
        max_workers: int = 8,
    ):
        self.domain          = domain
        self.seed_ips        = seed_ips or set()
        self.seed_asns       = seed_asns or set()
        self.shodan_key      = shodan_api_key or os.getenv("SHODAN_API_KEY", "")
        self.proxy           = proxy
        self.max_pivot_depth = max_pivot_depth
        self.enumerate_hosts = enumerate_hosts
        self.max_host_sample = max_host_sample
        self.fetch_history   = fetch_history
        self.timeout         = timeout
        self.max_workers     = max_workers

    # ------------------------------------------------------------------
    # Public scan
    # ------------------------------------------------------------------

    def scan(self) -> Dict:
        import urllib3
        import itertools as _itertools
        global itertools
        itertools = _itertools
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = _build_session(self.proxy)
        t0      = time.monotonic()

        print(f"[net_mapper] domain   : {self.domain}")
        print(f"[net_mapper] seed IPs : {len(self.seed_ips)}")
        print(f"[net_mapper] seed ASNs: {len(self.seed_asns)}")

        state = ScanState(
            domain=self.domain,
            seed_ips=set(self.seed_ips),
            asn_records={},
            ip_blocks=[],
            host_records=[],
            pivot_asns=set(),
            all_cidrs=set(),
        )

        # ── Phase 1: seed ASN discovery ───────────────────────────────────
        print(f"[net_mapper] phase 1: seed ASN discovery")
        all_seed_ips = list(self.seed_ips)

        # Resolve domain if no IPs provided
        if not all_seed_ips:
            ip = _resolve_ip(self.domain)
            if ip:
                all_seed_ips.append(ip)
                print(f"[net_mapper]   resolved {self.domain} → {ip}")

        # Team Cymru bulk lookup
        discovered_asns: Set[str] = set(self.seed_asns)
        if all_seed_ips:
            cymru_results = _cymru_whois_lookup(all_seed_ips, timeout=self.timeout)
            for ip, info in cymru_results.items():
                asn = info.get("asn", "")
                if asn and asn.startswith("AS"):
                    discovered_asns.add(asn)
                    print(f"[net_mapper]   {ip} → {asn} ({info.get('name','')})")

        # RIPEstat fallback for any IPs Cymru didn't resolve
        unresolved = [ip for ip in all_seed_ips if ip not in
                      {k: v for k, v in cymru_results.items() if cymru_results.get(k,{}).get("asn")}.keys()]
        for ip in unresolved[:5]:
            overview = _ripestat_ip_overview(session, ip)
            if overview:
                for asn in overview.get("asns", []):
                    if asn.startswith("AS"):
                        discovered_asns.add(asn)
            time.sleep(0.5)

        print(f"[net_mapper] phase 1: {len(discovered_asns)} ASNs identified")

        if not discovered_asns:
            return {
                "domain":   self.domain,
                "error":    "no ASNs discovered from seed IPs",
                "asns":     [],
                "cidrs":    [],
                "summary":  {},
            }

        # ── Phase 2: ASN → prefix expansion ──────────────────────────────
        print(f"[net_mapper] phase 2: prefix expansion for {len(discovered_asns)} ASNs")

        def _expand_asn(asn: str) -> Tuple[str, ASNRecord]:
            rec = _build_asn_record(session, asn, self.shodan_key or None)
            return asn, rec

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(_expand_asn, asn): asn for asn in discovered_asns}
            for f in as_completed(futures):
                asn, rec = f.result()
                with state.lock:
                    state.asn_records[asn] = rec
                    blocks = _build_ip_blocks(rec)
                    state.ip_blocks.extend(blocks)
                    for b in blocks:
                        state.all_cidrs.add(b.cidr)
                print(
                    f"  {asn} ({rec.name[:30]:<30}) "
                    f"prefixes={len(rec.prefixes_v4)} "
                    f"hosts≈{rec.total_ipv4:,}"
                )

        # ── Phase 3: ASN pivot ────────────────────────────────────────────
        if self.max_pivot_depth > 0:
            print(f"[net_mapper] phase 3: ASN pivot (depth={self.max_pivot_depth})")
            pivot = _pivot_asns(
                discovered_asns, state.asn_records, self.max_pivot_depth
            )
            # Filter out cloud providers — not part of the org's infra
            pivot = {a for a in pivot if not _CLOUD_ASN.get(a)}
            state.pivot_asns = pivot
            print(f"[net_mapper]   {len(pivot)} pivot ASNs found")

            for asn in list(pivot)[:8]:    # cap pivot expansion
                asn, rec = _expand_asn(asn)
                with state.lock:
                    state.asn_records[asn] = rec
                    blocks = _build_ip_blocks(rec)
                    state.ip_blocks.extend(blocks)
                    for b in blocks:
                        state.all_cidrs.add(b.cidr)
                print(f"  [pivot] {asn} ({rec.name[:30]}) prefixes={len(rec.prefixes_v4)}")

        # ── Phase 4: routing history ──────────────────────────────────────
        historical: List[Dict] = []
        if self.fetch_history:
            print(f"[net_mapper] phase 4: routing history analysis")
            historical = _analyse_routing_history(session, state.asn_records)
            print(f"[net_mapper]   {len(historical)} historical prefixes found")

        # ── Phase 5: host enumeration ─────────────────────────────────────
        if self.enumerate_hosts:
            print(f"[net_mapper] phase 5: passive host enumeration")
            # Only enumerate non-cloud blocks
            target_cidrs = [
                b.cidr for b in state.ip_blocks
                if not b.is_cloud
            ][:20]   # cap
            live_ips = _enumerate_live_hosts(
                target_cidrs,
                max_hosts=self.max_host_sample,
                timeout=2.0,
                max_workers=40,
            )
            print(f"[net_mapper]   {len(live_ips)} live hosts found via PTR")

            # Enrich live IPs with ip-api batch
            if live_ips:
                enriched = _ipapi_batch(session, live_ips[:100])
                for entry in enriched:
                    if entry.get("status") != "success":
                        continue
                    asn_str  = entry.get("as", "")
                    asn_id   = _asn_normalize(asn_str.split(" ", 1)[0]) if asn_str else ""
                    state.host_records.append(HostRecord(
                        ip=            entry.get("query", ""),
                        asn=           asn_id,
                        asn_name=      entry.get("asname", ""),
                        cidr=          "",
                        country=       entry.get("country", ""),
                        org=           entry.get("org", "") or entry.get("isp", ""),
                        is_cloud=      entry.get("hosting", False),
                        cloud_provider=_CLOUD_ASN.get(asn_id),
                        ptr=           None,
                        open_ports=    [],
                    ))

        # ── Phase 6: RDAP enrichment (sample) ────────────────────────────
        print(f"[net_mapper] phase 6: RDAP block enrichment")
        for block in state.ip_blocks[:10]:
            if block.allocated:
                continue
            reg = block.rir or "arin"
            rdap = _rdap_ip(session, str(block.network.network_address), registry=reg)
            if rdap:
                block.allocated = rdap.get("date")
                if not block.asn_name and rdap.get("org"):
                    block.asn_name = rdap["org"]
            time.sleep(0.3)

        # ── Summary ───────────────────────────────────────────────────────
        summary  = _build_summary(state, historical)
        elapsed  = time.monotonic() - t0

        print(
            f"[net_mapper] done | "
            f"asns={len(state.asn_records)} "
            f"cidrs={len(state.all_cidrs)} "
            f"hosts≈{summary['total_host_addresses']:,} "
            f"elapsed={elapsed:.1f}s"
        )

        return {
            "domain":            self.domain,
            "seed_ips":          list(self.seed_ips),
            "elapsed_seconds":   round(elapsed, 2),
            "summary":           summary,
            "asn_records": [
                {
                    "asn":           r.asn,
                    "name":          r.name,
                    "description":   r.description,
                    "country":       r.country,
                    "rir":           r.rir,
                    "prefixes_v4":   r.prefixes_v4,
                    "total_ipv4":    r.total_ipv4,
                    "peer_asns":     r.peer_asns[:20],
                    "upstream_asns": r.upstream_asns,
                    "cloud_provider":r.cloud_provider,
                    "source":        r.source,
                }
                for r in state.asn_records.values()
            ],
            "ip_blocks": [
                {
                    "cidr":           b.cidr,
                    "asn":            b.asn,
                    "asn_name":       b.asn_name,
                    "country":        b.country,
                    "rir":            b.rir,
                    "host_count":     b.host_count,
                    "is_cloud":       b.is_cloud,
                    "cloud_provider": b.cloud_provider,
                    "allocated":      b.allocated,
                    "status":         b.status,
                }
                for b in state.ip_blocks
            ],
            "historical_prefixes": historical,
            "host_records": [
                {
                    "ip":             h.ip,
                    "asn":            h.asn,
                    "asn_name":       h.asn_name,
                    "country":        h.country,
                    "org":            h.org,
                    "is_cloud":       h.is_cloud,
                    "cloud_provider": h.cloud_provider,
                }
                for h in state.host_records
            ],
            "all_cidrs": sorted(state.all_cidrs),
            "pivot_asns": sorted(state.pivot_asns),
        }