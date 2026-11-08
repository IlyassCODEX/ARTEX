# modules/reverse_whois.py
# Sources: RDAP (IANA bootstrap), ViewDNS.info, WhoisXML API (optional),
#          SecurityTrails (optional), crt.sh registrant pivot,
#          DomainTools-style permutation cross-check (passive).

import os
import re
import time
import json
import socket
import hashlib
import logging
import threading
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode, quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"

# RDAP fallback servers per TLD when bootstrap lookup fails
_RDAP_FALLBACK: Dict[str, str] = {
    "com":  "https://rdap.verisign.com/com/v1/",
    "net":  "https://rdap.verisign.com/net/v1/",
    "org":  "https://rdap.publicinterestregistry.org/rdap/",
    "io":   "https://rdap.nic.io/",
    "co":   "https://rdap.nic.co/",
    "info": "https://rdap.afilias.info/rdap/info/",
    "biz":  "https://rdap.nic.biz/",
    "us":   "https://rdap.nic.us/",
    "uk":   "https://rdap.nominet.uk/",
    "de":   "https://rdap.denic.de/",
    "fr":   "https://rdap.nic.fr/",
    "nl":   "https://rdap.sidn.nl/",
    "au":   "https://rdap.auda.org.au/",
    "ca":   "https://rdap.ca.fury.ca/",
    "eu":   "https://rdap.eu/",
    "ai":   "https://rdap.nic.ai/",
    "app":  "https://rdap.nic.google/",
    "dev":  "https://rdap.nic.google/",
    "xyz":  "https://rdap.nic.xyz/",
    "tech": "https://rdap.nic.tech/",
    "online": "https://rdap.nic.online/",
}

# ViewDNS.info — free, no API key, rate-limited
_VIEWDNS_BASE       = "https://api.viewdns.info"
_VIEWDNS_DELAY      = 2.0   # seconds between requests (free tier)

# WhoisXML API — optional, requires WHOISXML_API_KEY
_WHOISXML_BASE      = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
_WHOISXML_REVERSE   = "https://reverse-whois-api.whoisxmlapi.com/api/v2"

# SecurityTrails — optional, requires SECURITYTRAILS_API_KEY
_SECTRAILS_BASE     = "https://api.securitytrails.com/v1"

# crt.sh — free, used for registrant email pivot via cert org field
_CRTSH_BASE         = "https://crt.sh"

# DomainTools-style permutations (passive only, no API)
_PERMUTATION_AFFIXES = [
    "mail", "email", "smtp", "mx", "ns", "dns", "ftp", "ssh",
    "vpn", "remote", "access", "portal", "login", "admin",
    "api", "dev", "staging", "test", "prod", "app", "web",
    "cdn", "static", "img", "media", "files", "upload",
    "shop", "store", "pay", "billing", "invoice", "crm",
    "support", "help", "docs", "wiki", "blog", "forum",
    "monitor", "metrics", "logs", "analytics", "tracking",
    "auth", "oauth", "sso", "id", "identity",
    "backup", "db", "database", "sql", "data",
    "git", "ci", "build", "jenkins", "jira", "confluence",
    "intranet", "internal", "corp", "office", "hr",
    "mobile", "m", "wap", "ios", "android",
    "old", "new", "v2", "v3", "beta", "alpha",
    "aws", "cloud", "azure", "gcp", "k8s",
]

_PRIVACY_INDICATORS = re.compile(
    r"(privacy|redacted|whoisguard|perfect privacy|proxy|protection|"
    r"domains by proxy|withheld|not disclosed|data protected|"
    r"contactprivacy|privacyguardian|registrant proxy)",
    re.I,
)

_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b"
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class RegistrantProfile:
    """Normalised registrant identity extracted from WHOIS / RDAP."""
    name: Optional[str]
    org: Optional[str]
    email: Optional[str]
    email_hash: Optional[str]        # SHA-1 of lowercase email (matches RDAP abuse contact)
    phone: Optional[str]
    address: Optional[str]
    country: Optional[str]
    privacy_protected: bool
    raw_source: str                   # which source provided this


@dataclass
class DomainRecord:
    """One domain found via reverse pivot."""
    domain: str
    registrar: Optional[str]
    registrant_name: Optional[str]
    registrant_email: Optional[str]
    registrant_org: Optional[str]
    created: Optional[str]
    expires: Optional[str]
    updated: Optional[str]
    name_servers: List[str]
    status: List[str]
    pivot_source: str               # which pivot method found this
    pivot_key: str                  # the value used as pivot (email/org/name)
    confidence: str                 # confirmed / likely / possible


@dataclass
class RdapRecord:
    """Raw parsed RDAP response."""
    domain: str
    registrar: Optional[str]
    registrant: RegistrantProfile
    admin: Optional[RegistrantProfile]
    tech: Optional[RegistrantProfile]
    created: Optional[str]
    expires: Optional[str]
    updated: Optional[str]
    name_servers: List[str]
    status: List[str]
    events: List[Dict]
    notices: List[str]


@dataclass
class ScanState:
    domain: str
    tld: str
    sld: str                          # second-level domain (e.g. "example" from "example.com")
    target_rdap: Optional[RdapRecord]
    registrant: Optional[RegistrantProfile]
    pivot_domains: List[DomainRecord] = field(default_factory=list)
    pivot_emails: Set[str]            = field(default_factory=set)
    pivot_orgs: Set[str]              = field(default_factory=set)
    pivot_name_servers: Set[str]      = field(default_factory=set)
    permutation_hits: List[str]       = field(default_factory=list)
    crt_org_domains: List[str]        = field(default_factory=list)
    historical_registrants: List[Dict] = field(default_factory=list)
    sources_used: List[str]           = field(default_factory=list)
    lock: threading.Lock              = field(default_factory=threading.Lock)


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
    session.mount("http://", adapter)
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; ARTEX-Scanner/1.0; +https://github.com)"
    })
    return session


def _get_json(session: requests.Session, url: str,
              params: Optional[Dict] = None,
              headers: Optional[Dict] = None,
              timeout: float = 12.0) -> Optional[Dict]:
    try:
        resp = session.get(url, params=params, headers=headers or {}, timeout=timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.debug(f"[reverse_whois] GET {url} → {exc}")
        return None


def _get_text(session: requests.Session, url: str,
              params: Optional[Dict] = None,
              timeout: float = 12.0) -> Optional[str]:
    try:
        resp = session.get(url, params=params, timeout=timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as exc:
        logger.debug(f"[reverse_whois] GET {url} → {exc}")
        return None


# ---------------------------------------------------------------------------
# Domain / TLD utilities
# ---------------------------------------------------------------------------

def _split_domain(domain: str) -> Tuple[str, str]:
    """Return (sld, tld) for 'example.co.uk' → ('example', 'co.uk')."""
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) >= 3 and len(parts[-2]) <= 3:
        # Likely a ccSLD: co.uk, com.au, net.br
        return parts[-3], ".".join(parts[-2:])
    return parts[-2], parts[-1]


def _extract_emails(text: str) -> List[str]:
    return list({m.lower() for m in _EMAIL_RE.findall(text)})


def _extract_domains(text: str, exclude: str) -> List[str]:
    found = {d.lower() for d in _DOMAIN_RE.findall(text)}
    found.discard(exclude)
    # Drop obvious false positives — single-label or known infra domains
    return [d for d in found
            if "." in d and not d.endswith((".png", ".jpg", ".css", ".js"))]


def _sha1_email(email: str) -> str:
    return hashlib.sha1(email.strip().lower().encode()).hexdigest()


# ---------------------------------------------------------------------------
# Phase 1 — RDAP lookup (target domain)
# ---------------------------------------------------------------------------

def _rdap_server_for_tld(session: requests.Session, tld: str) -> Optional[str]:
    """
    Consult the IANA RDAP bootstrap registry to find the authoritative
    RDAP server for *tld*.  Falls back to _RDAP_FALLBACK.
    """
    if tld in _RDAP_FALLBACK:
        return _RDAP_FALLBACK[tld]
    data = _get_json(session, _RDAP_BOOTSTRAP, timeout=10.0)
    if not data:
        return None
    for service in data.get("services", []):
        tlds, urls = service[0], service[1]
        if tld in tlds or f".{tld}" in tlds:
            return urls[0].rstrip("/") + "/"
    return None


def _parse_vcard(vcard: List) -> Dict[str, str]:
    """Parse a jCard (RFC 7095) array into a flat dict of contact fields."""
    result: Dict[str, str] = {}
    for entry in vcard:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        field_name = entry[0].lower()
        value = entry[3]
        if isinstance(value, list):
            value = " ".join(str(v) for v in value if v)
        result[field_name] = str(value).strip()
    return result


def _parse_rdap_entity(entity: Dict, role_filter: Optional[str] = None) -> Optional[RegistrantProfile]:
    """
    Extract a RegistrantProfile from one RDAP entity object.
    If *role_filter* is set, only process entities whose roles include it.
    """
    roles = [r.lower() for r in (entity.get("roles") or [])]
    if role_filter and role_filter not in roles:
        return None

    vcard_array = entity.get("vcardArray") or []
    contact: Dict[str, str] = {}
    if len(vcard_array) > 1:
        contact = _parse_vcard(vcard_array[1])

    name  = contact.get("fn") or entity.get("handle")
    org   = contact.get("org")
    email = contact.get("email")
    phone = contact.get("tel")
    adr   = contact.get("adr") or contact.get("label")
    country = None

    # Try structured address
    adr_raw = contact.get("adr", "")
    if isinstance(adr_raw, str):
        country_m = re.search(r"\b([A-Z]{2})\s*$", adr_raw.strip())
        if country_m:
            country = country_m.group(1)

    privacy = bool(
        _PRIVACY_INDICATORS.search(str(name) + str(org) + str(email))
        if (name or org or email) else False
    )

    email_hash = _sha1_email(email) if email and not privacy else None

    return RegistrantProfile(
        name=name,
        org=org,
        email=email if not privacy else None,
        email_hash=email_hash,
        phone=phone if not privacy else None,
        address=adr if not privacy else None,
        country=country,
        privacy_protected=privacy,
        raw_source="rdap",
    )


def _rdap_lookup(session: requests.Session, domain: str) -> Optional[RdapRecord]:
    """
    Perform a full RDAP lookup for *domain* using the IANA bootstrap.
    Returns a typed RdapRecord or None.
    """
    sld, tld = _split_domain(domain)
    server = _rdap_server_for_tld(session, tld)
    if not server:
        logger.warning(f"[rdap] no server found for TLD '{tld}'")
        return None

    url = f"{server}domain/{domain}"
    data = _get_json(session, url, timeout=12.0)
    if not data:
        return None

    # Name servers
    ns_list: List[str] = []
    for ns_obj in data.get("nameservers") or []:
        ns = (ns_obj.get("ldhName") or "").lower()
        if ns:
            ns_list.append(ns)

    # Status
    status = [s for s in (data.get("status") or []) if isinstance(s, str)]

    # Events
    events: List[Dict] = []
    created = expires = updated = None
    for ev in data.get("events") or []:
        action = ev.get("eventAction", "")
        date   = ev.get("eventDate", "")
        events.append({"action": action, "date": date})
        if action == "registration":
            created = date
        elif action == "expiration":
            expires = date
        elif action == "last changed":
            updated = date

    # Registrar
    registrar: Optional[str] = None
    registrant: Optional[RegistrantProfile] = None
    admin: Optional[RegistrantProfile] = None
    tech: Optional[RegistrantProfile] = None

    for entity in data.get("entities") or []:
        roles = [r.lower() for r in (entity.get("roles") or [])]
        if "registrar" in roles:
            vc = entity.get("vcardArray") or []
            if len(vc) > 1:
                fc = _parse_vcard(vc[1])
                registrar = fc.get("fn") or fc.get("org")
        if "registrant" in roles:
            registrant = _parse_rdap_entity(entity, "registrant")
        if "administrative" in roles:
            admin = _parse_rdap_entity(entity, "administrative")
        if "technical" in roles:
            tech = _parse_rdap_entity(entity, "technical")

        # Some registries nest contacts one level deeper
        for sub in entity.get("entities") or []:
            sub_roles = [r.lower() for r in (sub.get("roles") or [])]
            if "registrant" in sub_roles and not registrant:
                registrant = _parse_rdap_entity(sub, "registrant")
            if "administrative" in sub_roles and not admin:
                admin = _parse_rdap_entity(sub, "administrative")

    # Notices (legal / TOS lines)
    notices = [
        n.get("title", "") for n in (data.get("notices") or [])
        if isinstance(n, dict)
    ]

    return RdapRecord(
        domain=domain,
        registrar=registrar,
        registrant=registrant or RegistrantProfile(
            name=None, org=None, email=None, email_hash=None,
            phone=None, address=None, country=None,
            privacy_protected=True, raw_source="rdap",
        ),
        admin=admin,
        tech=tech,
        created=created,
        expires=expires,
        updated=updated,
        name_servers=ns_list,
        status=status,
        events=events,
        notices=notices,
    )


# ---------------------------------------------------------------------------
# Phase 2 — ViewDNS reverse WHOIS (free, no API key)
# ---------------------------------------------------------------------------

def _viewdns_reverse_whois(
    session: requests.Session,
    query: str,
    query_type: str,     # "email" | "name"
) -> List[DomainRecord]:
    """
    Query ViewDNS.info reverse WHOIS endpoint.
    Returns up to 500 domains matching *query*.
    Free tier — no API key but rate-limited.
    """
    url = f"{_VIEWDNS_BASE}/reversewhois/"
    params = {
        "q":      query,
        "apikey": os.getenv("VIEWDNS_API_KEY", ""),   # optional — raises limit
        "output": "json",
    }
    data = _get_json(session, url, params=params, timeout=15.0)
    if not data:
        return []

    records: List[DomainRecord] = []
    for entry in (data.get("result", {}).get("matches") or []):
        domain  = (entry.get("domain") or "").lower().strip()
        created = entry.get("created_date") or entry.get("registrar_created")
        if not domain:
            continue
        records.append(DomainRecord(
            domain=domain,
            registrar=entry.get("registrar"),
            registrant_name=entry.get("registrant_name"),
            registrant_email=query if query_type == "email" else None,
            registrant_org=None,
            created=created,
            expires=None,
            updated=None,
            name_servers=[],
            status=[],
            pivot_source="viewdns_reverse_whois",
            pivot_key=query,
            confidence="likely",
        ))

    time.sleep(_VIEWDNS_DELAY)
    return records


# ---------------------------------------------------------------------------
# Phase 3 — WhoisXML API reverse WHOIS (optional)
# ---------------------------------------------------------------------------

def _whoisxml_reverse_whois(
    session: requests.Session,
    api_key: str,
    terms: List[Dict[str, str]],    # [{"field": "RegistrantEmail", "value": "..."}]
    max_results: int = 100,
) -> List[DomainRecord]:
    """
    WhoisXML Reverse WHOIS API v2.
    Supports pivoting on: RegistrantEmail, RegistrantOrganization,
    RegistrantName, AdminEmail, TechEmail, RegistrantPhone, Registrar.
    """
    if not api_key:
        return []

    payload = {
        "apiKey":        api_key,
        "searchType":    "current",
        "mode":          "purchase",
        "basicSearchTerms": {"include": terms},
    }
    try:
        resp = session.post(
            _WHOISXML_REVERSE,
            json=payload,
            timeout=20.0,
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.debug(f"[whoisxml] reverse WHOIS error: {exc}")
        return []

    records: List[DomainRecord] = []
    for entry in (data.get("domainsList") or [])[:max_results]:
        domain = (entry if isinstance(entry, str) else entry.get("domainName", "")).lower()
        if not domain:
            continue
        records.append(DomainRecord(
            domain=domain,
            registrar=None,
            registrant_name=None,
            registrant_email=None,
            registrant_org=None,
            created=None,
            expires=None,
            updated=None,
            name_servers=[],
            status=[],
            pivot_source="whoisxml_reverse_whois",
            pivot_key=str(terms),
            confidence="confirmed",
        ))
    return records


# ---------------------------------------------------------------------------
# Phase 4 — SecurityTrails associated domains (optional)
# ---------------------------------------------------------------------------

def _sectrails_associated(
    session: requests.Session,
    api_key: str,
    domain: str,
) -> List[str]:
    """
    Pull domains associated with the same registrant from SecurityTrails.
    Returns a list of domain strings.
    """
    if not api_key:
        return []

    headers = {"APIKEY": api_key}
    # /v1/domain/{domain}/associated — returns domains sharing registrant email/org
    url = f"{_SECTRAILS_BASE}/domain/{domain}/associated"
    data = _get_json(session, url, headers=headers, timeout=12.0)
    if not data:
        return []

    result: List[str] = []
    for rec in (data.get("records") or []):
        name = (rec.get("hostname") or "").lower().strip()
        if name and name != domain:
            result.append(name)

    time.sleep(1.0)
    return result


def _sectrails_whois_history(
    session: requests.Session,
    api_key: str,
    domain: str,
) -> List[Dict]:
    """
    Pull historical WHOIS records from SecurityTrails.
    Returns a list of historical registrant dicts.
    """
    if not api_key:
        return []

    headers = {"APIKEY": api_key}
    url = f"{_SECTRAILS_BASE}/domain/{domain}/whois/history"
    data = _get_json(session, url, headers=headers, timeout=12.0)
    if not data:
        return []

    history: List[Dict] = []
    for rec in (data.get("result") or {}).get("items") or []:
        entry: Dict = {
            "date": rec.get("date"),
            "registrar": rec.get("registrar"),
            "registrant_name": None,
            "registrant_email": None,
            "registrant_org": None,
        }
        contacts = rec.get("contacts") or {}
        registrant = contacts.get("registrant") or {}
        entry["registrant_name"]  = registrant.get("name")
        entry["registrant_email"] = registrant.get("email")
        entry["registrant_org"]   = registrant.get("organization")
        history.append(entry)

    time.sleep(1.0)
    return history


# ---------------------------------------------------------------------------
# Phase 5 — crt.sh organisation pivot
# ---------------------------------------------------------------------------

def _crtsh_org_pivot(
    session: requests.Session,
    org: str,
) -> List[str]:
    """
    Search crt.sh for certificates issued to *org*.
    Extracts unique common names → domain names.
    """
    # crt.sh JSON API: ?o=<org>&output=json
    url = f"{_CRTSH_BASE}/"
    params = {"o": org, "output": "json"}
    data = _get_json(session, url, params=params, timeout=15.0)
    if not data or not isinstance(data, list):
        return []

    domains: Set[str] = set()
    for cert in data:
        cn = (cert.get("common_name") or "").lower().strip()
        # crt.sh also returns name_value which may contain SANs
        name_value = (cert.get("name_value") or "").lower()
        for candidate in [cn] + name_value.split("\n"):
            candidate = candidate.strip().lstrip("*.")
            if candidate and "." in candidate:
                domains.add(candidate)

    time.sleep(1.0)
    return sorted(domains)


# ---------------------------------------------------------------------------
# Phase 6 — Name server pivot
# ---------------------------------------------------------------------------

def _ns_pivot(
    session: requests.Session,
    name_servers: List[str],
    state: ScanState,
) -> List[DomainRecord]:
    """
    For each authoritative name server, query HackerTarget's
    reverse NS lookup to find co-hosted domains.
    Free, no API key required.
    """
    records: List[DomainRecord] = []
    seen: Set[str] = set()

    for ns in name_servers[:5]:    # cap to avoid excessive requests
        # Strip trailing dot
        ns_clean = ns.rstrip(".")
        url = "https://api.hackertarget.com/reversens/"
        text = _get_text(session, url, params={"q": ns_clean}, timeout=10.0)
        if not text or "error" in text.lower():
            time.sleep(1.0)
            continue

        for line in text.strip().splitlines():
            # Format: "ns1.example.com,victim.com"
            parts = line.split(",")
            if len(parts) >= 2:
                domain = parts[-1].strip().lower()
            else:
                domain = line.strip().lower()

            if not domain or domain == state.domain or domain in seen:
                continue
            seen.add(domain)
            records.append(DomainRecord(
                domain=domain,
                registrar=None,
                registrant_name=None,
                registrant_email=None,
                registrant_org=None,
                created=None,
                expires=None,
                updated=None,
                name_servers=[ns_clean],
                status=[],
                pivot_source="nameserver_pivot",
                pivot_key=ns_clean,
                confidence="possible",
            ))

        time.sleep(1.5)

    return records


# ---------------------------------------------------------------------------
# Phase 7 — Passive permutation DNS check
# ---------------------------------------------------------------------------

def _resolve_domain(domain: str, timeout: float = 2.0) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(domain)
    except socket.error:
        return None


def _permutation_check(
    sld: str,
    tld: str,
    extra_tlds: Optional[List[str]] = None,
) -> List[str]:
    """
    Generate and passively resolve permuted domain names derived from the
    target SLD.  Only returns names that actually resolve in DNS.
    No HTTP requests — purely passive DNS.
    """
    tlds_to_check = list({tld, "com", "net", "org", "io", "co"})
    if extra_tlds:
        tlds_to_check += extra_tlds

    candidates: List[str] = []

    # Affix permutations
    for affix in _PERMUTATION_AFFIXES:
        for t in tlds_to_check:
            candidates.append(f"{sld}-{affix}.{t}")
            candidates.append(f"{affix}-{sld}.{t}")
            candidates.append(f"{affix}.{sld}.{t}")

    # Typosquatting — common patterns
    for t in tlds_to_check:
        # Double-letter omission: "googgle" → "gogle"
        for i in range(len(sld)):
            typo = sld[:i] + sld[i+1:]
            if len(typo) >= 3:
                candidates.append(f"{typo}.{t}")
        # Character transposition
        for i in range(len(sld) - 1):
            swapped = sld[:i] + sld[i+1] + sld[i] + sld[i+2:]
            candidates.append(f"{swapped}.{t}")
        # Homoglyph substitutions
        for original, replacement in [("o", "0"), ("i", "1"), ("l", "1"), ("a", "@")]:
            if original in sld:
                candidates.append(f"{sld.replace(original, replacement)}.{t}")

    # Deduplicate
    candidates = list(dict.fromkeys(candidates))

    # Passive DNS resolution — parallel, capped
    resolved: List[str] = []
    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(_resolve_domain, c): c for c in candidates[:300]}
        for f in as_completed(futures):
            if f.result() is not None:
                resolved.append(futures[f])

    return sorted(resolved)


# ---------------------------------------------------------------------------
# Phase 8 — RDAP batch lookup on pivot results
# ---------------------------------------------------------------------------

def _enrich_pivot_domain(
    session: requests.Session,
    record: DomainRecord,
) -> DomainRecord:
    """
    Perform RDAP lookup on a pivot-found domain to fill in
    registrant / dates / name servers where missing.
    """
    rdap = _rdap_lookup(session, record.domain)
    if not rdap:
        return record

    reg = rdap.registrant
    record.registrar         = record.registrar or rdap.registrar
    record.registrant_name   = record.registrant_name or (reg.name if reg else None)
    record.registrant_email  = record.registrant_email or (reg.email if reg else None)
    record.registrant_org    = record.registrant_org or (reg.org if reg else None)
    record.created           = record.created or rdap.created
    record.expires           = record.expires or rdap.expires
    record.updated           = record.updated or rdap.updated
    record.name_servers      = record.name_servers or rdap.name_servers
    record.status            = record.status or rdap.status

    return record


# ---------------------------------------------------------------------------
# Deduplication and scoring
# ---------------------------------------------------------------------------

def _dedup_pivot_domains(records: List[DomainRecord]) -> List[DomainRecord]:
    """
    Deduplicate by domain name.  When the same domain appears from multiple
    sources, merge them into the highest-confidence entry.
    """
    _CONF_ORDER = {"confirmed": 0, "likely": 1, "possible": 2}
    best: Dict[str, DomainRecord] = {}
    for r in records:
        domain = r.domain.lower().strip()
        if not domain:
            continue
        if domain not in best:
            best[domain] = r
        else:
            existing = best[domain]
            # Upgrade confidence
            if _CONF_ORDER.get(r.confidence, 9) < _CONF_ORDER.get(existing.confidence, 9):
                best[domain] = r
            # Merge source tag
            if r.pivot_source not in existing.pivot_source:
                existing.pivot_source += f",{r.pivot_source}"
            # Fill blanks
            existing.registrant_name  = existing.registrant_name  or r.registrant_name
            existing.registrant_email = existing.registrant_email or r.registrant_email
            existing.registrant_org   = existing.registrant_org   or r.registrant_org
            existing.created          = existing.created           or r.created
            existing.name_servers     = existing.name_servers      or r.name_servers

    return sorted(best.values(), key=lambda r: r.domain)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class ReverseWhois:
    """
    Passive reverse WHOIS / registrant pivot scanner.

    Chains eight passive data sources without requiring any paid API keys:
      Phase 1 — RDAP lookup on the target domain (IANA bootstrap)
      Phase 2 — ViewDNS.info reverse WHOIS (email + name pivot)
      Phase 3 — WhoisXML API reverse WHOIS (optional, WHOISXML_API_KEY)
      Phase 4 — SecurityTrails associated domains + WHOIS history (optional)
      Phase 5 — crt.sh certificate organisation pivot
      Phase 6 — Name server reverse pivot (HackerTarget)
      Phase 7 — Passive permutation DNS resolution
      Phase 8 — RDAP enrichment on discovered domains (sampled)

    Usage in app.py:
        rw = ReverseWhois(domain=domain)
        results = rw.scan()
        scan_results[scan_id]['reverse_whois'] = results
    """

    def __init__(
        self,
        domain: str,
        whoisxml_api_key: Optional[str] = None,
        sectrails_api_key: Optional[str] = None,
        proxy: Optional[str] = None,
        enrich_sample: int = 10,       # how many pivot domains to RDAP-enrich
        max_permutations: int = 300,   # candidate cap for permutation check
        enable_permutations: bool = True,
        enable_ns_pivot: bool = True,
        enable_crtsh: bool = True,
        timeout: float = 12.0,
    ):
        self.domain           = domain.lower().strip()
        self.whoisxml_key     = whoisxml_api_key or os.getenv("WHOISXML_API_KEY", "")
        self.sectrails_key    = sectrails_api_key or os.getenv("SECURITYTRAILS_API_KEY", "")
        self.proxy            = proxy
        self.enrich_sample    = enrich_sample
        self.max_permutations = max_permutations
        self.enable_perms     = enable_permutations
        self.enable_ns_pivot  = enable_ns_pivot
        self.enable_crtsh     = enable_crtsh
        self.timeout          = timeout

    # ------------------------------------------------------------------
    # Public scan
    # ------------------------------------------------------------------

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = _build_session(self.proxy)
        sld, tld = _split_domain(self.domain)

        state = ScanState(
            domain=self.domain,
            tld=tld,
            sld=sld,
            target_rdap=None,
            registrant=None,
        )

        # ── Phase 1: RDAP on target ────────────────────────────────────────
        print(f"[reverse_whois] phase 1: RDAP lookup — {self.domain}")
        rdap = _rdap_lookup(session, self.domain)
        state.target_rdap = rdap
        if rdap:
            state.registrant = rdap.registrant
            state.sources_used.append("rdap")
            if rdap.name_servers:
                state.pivot_name_servers.update(rdap.name_servers)
            reg = rdap.registrant
            if reg:
                if reg.email:
                    state.pivot_emails.add(reg.email)
                if reg.org:
                    state.pivot_orgs.add(reg.org)
            # Admin / tech may carry different emails
            for contact in [rdap.admin, rdap.tech]:
                if contact and contact.email:
                    state.pivot_emails.add(contact.email)

        print(
            f"[reverse_whois]   registrant: "
            f"{'PRIVACY' if (rdap and rdap.registrant.privacy_protected) else 'exposed'} | "
            f"emails={len(state.pivot_emails)} | orgs={len(state.pivot_orgs)} | "
            f"NS={len(state.pivot_name_servers)}"
        )

        # ── Phase 2: ViewDNS reverse WHOIS ────────────────────────────────
        print(f"[reverse_whois] phase 2: ViewDNS pivot")
        for email in list(state.pivot_emails)[:3]:
            recs = _viewdns_reverse_whois(session, email, "email")
            state.pivot_domains.extend(recs)
            print(f"[reverse_whois]   email '{email}' → {len(recs)} domains")
        for org in list(state.pivot_orgs)[:2]:
            recs = _viewdns_reverse_whois(session, org, "name")
            state.pivot_domains.extend(recs)
            print(f"[reverse_whois]   org '{org}' → {len(recs)} domains")
        if state.pivot_emails or state.pivot_orgs:
            state.sources_used.append("viewdns_reverse_whois")

        # ── Phase 3: WhoisXML reverse WHOIS ───────────────────────────────
        if self.whoisxml_key:
            print(f"[reverse_whois] phase 3: WhoisXML pivot")
            terms: List[Dict[str, str]] = []
            for email in list(state.pivot_emails)[:2]:
                terms.append({"field": "RegistrantEmail", "value": email})
            for org in list(state.pivot_orgs)[:2]:
                terms.append({"field": "RegistrantOrganization", "value": org})
            if terms:
                recs = _whoisxml_reverse_whois(session, self.whoisxml_key, terms)
                state.pivot_domains.extend(recs)
                state.sources_used.append("whoisxml_reverse_whois")
                print(f"[reverse_whois]   WhoisXML → {len(recs)} domains")
        else:
            print(f"[reverse_whois] phase 3: skipped (no WHOISXML_API_KEY)")

        # ── Phase 4: SecurityTrails ────────────────────────────────────────
        if self.sectrails_key:
            print(f"[reverse_whois] phase 4: SecurityTrails")
            assoc = _sectrails_associated(session, self.sectrails_key, self.domain)
            for d in assoc:
                state.pivot_domains.append(DomainRecord(
                    domain=d, registrar=None, registrant_name=None,
                    registrant_email=None, registrant_org=None,
                    created=None, expires=None, updated=None,
                    name_servers=[], status=[],
                    pivot_source="sectrails_associated",
                    pivot_key=self.domain, confidence="likely",
                ))
            history = _sectrails_whois_history(session, self.sectrails_key, self.domain)
            state.historical_registrants = history
            # Extract historical emails for extra pivots
            for entry in history:
                if entry.get("registrant_email"):
                    state.pivot_emails.add(entry["registrant_email"])
            state.sources_used.append("securitytrails")
            print(f"[reverse_whois]   associated={len(assoc)} history={len(history)}")
        else:
            print(f"[reverse_whois] phase 4: skipped (no SECURITYTRAILS_API_KEY)")

        # ── Phase 5: crt.sh org pivot ──────────────────────────────────────
        if self.enable_crtsh:
            print(f"[reverse_whois] phase 5: crt.sh org pivot")
            for org in list(state.pivot_orgs)[:2]:
                crt_domains = _crtsh_org_pivot(session, org)
                state.crt_org_domains.extend(crt_domains)
                for d in crt_domains:
                    if d != self.domain:
                        state.pivot_domains.append(DomainRecord(
                            domain=d, registrar=None, registrant_name=None,
                            registrant_email=None, registrant_org=org,
                            created=None, expires=None, updated=None,
                            name_servers=[], status=[],
                            pivot_source="crtsh_org_pivot",
                            pivot_key=org, confidence="likely",
                        ))
                print(f"[reverse_whois]   org '{org}' → {len(crt_domains)} cert domains")
            if state.pivot_orgs:
                state.sources_used.append("crtsh_org_pivot")

        # ── Phase 6: Name server pivot ─────────────────────────────────────
        if self.enable_ns_pivot and state.pivot_name_servers:
            print(f"[reverse_whois] phase 6: NS pivot ({len(state.pivot_name_servers)} servers)")
            ns_recs = _ns_pivot(session, list(state.pivot_name_servers), state)
            state.pivot_domains.extend(ns_recs)
            if ns_recs:
                state.sources_used.append("nameserver_pivot")
            print(f"[reverse_whois]   NS pivot → {len(ns_recs)} domains")

        # ── Phase 7: Permutation DNS ───────────────────────────────────────
        if self.enable_perms:
            print(f"[reverse_whois] phase 7: permutation DNS check")
            hits = _permutation_check(sld, tld)
            state.permutation_hits = hits
            if hits:
                state.sources_used.append("permutation_dns")
            print(f"[reverse_whois]   {len(hits)} permutations resolved")

        # ── Phase 8: RDAP enrichment on sample ────────────────────────────
        # Deduplicate first so we don't enrich duplicates
        state.pivot_domains = _dedup_pivot_domains(state.pivot_domains)
        if self.enrich_sample > 0:
            print(f"[reverse_whois] phase 8: RDAP enrich (sample={self.enrich_sample})")
            to_enrich = [
                r for r in state.pivot_domains
                if not r.registrant_email and not r.created
            ][:self.enrich_sample]
            for rec in to_enrich:
                _enrich_pivot_domain(session, rec)
                time.sleep(0.5)
            if to_enrich:
                state.sources_used.append("rdap_enrichment")

        # ── Serialise ──────────────────────────────────────────────────────
        summary = self._build_summary(state)
        print(
            f"[reverse_whois] done | "
            f"pivot_domains={len(state.pivot_domains)} | "
            f"permutations={len(state.permutation_hits)} | "
            f"sources={state.sources_used}"
        )

        return {
            "domain":                self.domain,
            "registrant":            self._ser_profile(state.registrant),
            "rdap": self._ser_rdap(state.target_rdap) if state.target_rdap else None,
            "pivot_emails":          sorted(state.pivot_emails),
            "pivot_orgs":            sorted(state.pivot_orgs),
            "pivot_name_servers":    sorted(state.pivot_name_servers),
            "pivot_domains":         [self._ser_domain(r) for r in state.pivot_domains],
            "permutation_hits":      state.permutation_hits,
            "crt_org_domains":       state.crt_org_domains,
            "historical_registrants":state.historical_registrants,
            "sources_used":          list(dict.fromkeys(state.sources_used)),
            "summary":               summary,
        }

    # ------------------------------------------------------------------
    # Serialisers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(state: ScanState) -> Dict:
        source_counts: Dict[str, int] = {}
        for r in state.pivot_domains:
            for src in r.pivot_source.split(","):
                source_counts[src.strip()] = source_counts.get(src.strip(), 0) + 1

        confidence_counts: Dict[str, int] = {}
        for r in state.pivot_domains:
            confidence_counts[r.confidence] = confidence_counts.get(r.confidence, 0) + 1

        # Count registrars
        registrar_counts: Dict[str, int] = {}
        for r in state.pivot_domains:
            if r.registrar:
                registrar_counts[r.registrar] = registrar_counts.get(r.registrar, 0) + 1
        top_registrars = sorted(registrar_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "total_pivot_domains":   len(state.pivot_domains),
            "total_permutations":    len(state.permutation_hits),
            "pivot_emails_found":    len(state.pivot_emails),
            "pivot_orgs_found":      len(state.pivot_orgs),
            "privacy_protected":     (
                state.registrant.privacy_protected
                if state.registrant else None
            ),
            "source_breakdown":      source_counts,
            "confidence_breakdown":  confidence_counts,
            "top_registrars":        [{"registrar": r, "count": c} for r, c in top_registrars],
            "has_historical_whois":  bool(state.historical_registrants),
        }

    @staticmethod
    def _ser_profile(p: Optional[RegistrantProfile]) -> Optional[Dict]:
        if not p:
            return None
        return {
            "name":              p.name,
            "org":               p.org,
            "email":             p.email,
            "email_hash":        p.email_hash,
            "phone":             p.phone,
            "address":           p.address,
            "country":           p.country,
            "privacy_protected": p.privacy_protected,
            "source":            p.raw_source,
        }

    @staticmethod
    def _ser_rdap(r: RdapRecord) -> Dict:
        return {
            "domain":      r.domain,
            "registrar":   r.registrar,
            "created":     r.created,
            "expires":     r.expires,
            "updated":     r.updated,
            "name_servers":r.name_servers,
            "status":      r.status,
        }

    @staticmethod
    def _ser_domain(r: DomainRecord) -> Dict:
        return {
            "domain":            r.domain,
            "registrar":         r.registrar,
            "registrant_name":   r.registrant_name,
            "registrant_email":  r.registrant_email,
            "registrant_org":    r.registrant_org,
            "created":           r.created,
            "expires":           r.expires,
            "name_servers":      r.name_servers,
            "pivot_source":      r.pivot_source,
            "pivot_key":         r.pivot_key,
            "confidence":        r.confidence,
        }