# AI_cve_mapper.py
#
# Problem this module solves:
#   tech_detector uses Wappalyzer -> version=None (always)
#   port_scanner uses socket -> version='' (always)
#   Neither module queries CVE databases.
#   This module bridges that gap by:
#     1. ACTIVE version extraction — HTTP headers, meta tags, error pages,
#        JS library patterns, banner grabbing via TCP socket (non-destructive)
#     2. CPE string construction from extracted version + vendor + product
#     3. Multi-source CVE search:
#          NVD API v2.0  -> https://services.nvd.nist.gov/rest/json/cves/2.0
#          OSV.dev API   -> https://api.osv.dev/v1/query
#          EPSS API      -> https://api.first.org/data/v1/epss
#     4. EPSS score enrichment per CVE (exploitation probability 0.0–1.0)
#     5. CPE-aware deduplication and version range matching
#     6. Groq AI ranking by exploitability + business impact
#
# reads from confirmed scan_results keys:
#   tech_detection -> {url: {technologies:[{name, version, category, sources}]}}
#   port_scan      -> [{target, ports:[{port,service,state,risk}],
#                       risky_ports:[{port,service,version,risk}]}]
#   subdomains     -> [{subdomain, ip, http_status, https_status}]
# depends: requests, packaging (version comparison), groq (via HTTP)

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlparse

import requests as req_lib

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
NVD_API_KEY  = os.getenv("NVD_API_KEY", "")    # optional — boosts rate limit 5→50 req/30s

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NVD_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_BASE    = "https://api.osv.dev/v1"
EPSS_BASE   = "https://api.first.org/data/v1/epss"
CVEDB_BASE  = "https://cvedb.shodan.io/cve"       # Shodan CVE DB — no key needed

# Rate limits (requests / window in seconds)
_NVD_RATE_NO_KEY  = (5,  30)   # 5 req / 30s without API key
_NVD_RATE_WITH_KEY = (50, 30)  # 50 req / 30s with API key
_OSV_RATE         = (25, 10)
_EPSS_BATCH_MAX   = 100         # EPSS API accepts up to 100 CVE IDs per request

# Version string patterns — extracted from HTTP responses
_VERSION_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    # (product_hint, pattern, group_name)
    # HTTP headers
    ("apache",    re.compile(r"Apache[/\s]([\d.]+)", re.I),                 "version"),
    ("nginx",     re.compile(r"nginx[/\s]([\d.]+)", re.I),                  "version"),
    ("iis",       re.compile(r"Microsoft-IIS[/\s]([\d.]+)", re.I),          "version"),
    ("php",       re.compile(r"PHP[/\s]([\d.]+)", re.I),                    "version"),
    ("openssl",   re.compile(r"OpenSSL[/\s]([\d.a-z]+)", re.I),             "version"),
    ("node",      re.compile(r"Node\.js[/\s]([\d.]+)", re.I),               "version"),
    ("express",   re.compile(r"Express[/\s]([\d.]+)", re.I),                "version"),
    ("tomcat",    re.compile(r"Apache-Coyote[/\s]([\d.]+)", re.I),          "version"),
    ("tomcat",    re.compile(r"Tomcat[/\s]([\d.]+)", re.I),                 "version"),
    ("django",    re.compile(r"Django[/\s]([\d.]+)", re.I),                 "version"),
    ("rails",     re.compile(r"Rails[/\s]([\d.]+)", re.I),                  "version"),
    ("wordpress", re.compile(r"WordPress[/\s]([\d.]+)", re.I),              "version"),
    ("drupal",    re.compile(r"Drupal[/\s]([\d.]+)", re.I),                 "version"),
    ("joomla",    re.compile(r"Joomla[!/\s]([\d.]+)", re.I),               "version"),
    # HTML/JS body patterns
    ("wordpress", re.compile(r'<meta name="generator" content="WordPress ([\d.]+)"', re.I), "version"),
    ("drupal",    re.compile(r'<meta name="Generator" content="Drupal ([\d.]+)', re.I),     "version"),
    ("joomla",    re.compile(r'<meta name="generator" content="Joomla!\s*([\d.]+)', re.I), "version"),
    ("jquery",    re.compile(r'jquery[.-]([\d.]+)(?:\.min)?\.js', re.I),    "version"),
    ("bootstrap", re.compile(r'bootstrap[.-]([\d.]+)(?:\.min)?\.(?:js|css)', re.I), "version"),
    ("react",     re.compile(r'react(?:dom)?[.-]([\d.]+)\.js', re.I),       "version"),
    ("angular",   re.compile(r'angular[.-]([\d.]+)\.js', re.I),             "version"),
    ("vue",       re.compile(r'vue[.-]([\d.]+)\.js', re.I),                 "version"),
    # Error page version leaks
    ("tomcat",    re.compile(r'Apache Tomcat/([\d.]+)', re.I),              "version"),
    ("spring",    re.compile(r'Spring Framework[\s/]([\d.]+)', re.I),       "version"),
    ("struts",    re.compile(r'Struts[\s/]([\d.]+)', re.I),                 "version"),
    ("log4j",     re.compile(r'log4j[-:\s]([\d.]+)', re.I),                 "version"),
    # X-Generator header
    ("generic",   re.compile(r'X-Generator:\s*(\S+)[/\s]([\d.]+)', re.I),  "both"),
]

# Service name → CPE vendor:product mapping
# Sourced from NVD CPE dictionary common entries
_SERVICE_CPE_MAP: Dict[str, Tuple[str, str]] = {
    "ssh":           ("openbsd", "openssh"),
    "openssh":       ("openbsd", "openssh"),
    "ftp":           ("vsftpd", "vsftpd"),
    "vsftpd":        ("vsftpd", "vsftpd"),
    "proftpd":       ("proftpd_project", "proftpd"),
    "mysql":         ("mysql", "mysql"),
    "mariadb":       ("mariadb", "mariadb"),
    "postgresql":    ("postgresql", "postgresql"),
    "mssql":         ("microsoft", "sql_server"),
    "oracle":        ("oracle", "database_server"),
    "mongodb":       ("mongodb", "mongodb"),
    "redis":         ("redislabs", "redis"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "memcached":     ("memcached", "memcached"),
    "apache":        ("apache", "http_server"),
    "nginx":         ("f5", "nginx"),
    "iis":           ("microsoft", "internet_information_services"),
    "tomcat":        ("apache", "tomcat"),
    "php":           ("php", "php"),
    "openssl":       ("openssl", "openssl"),
    "wordpress":     ("wordpress", "wordpress"),
    "drupal":        ("drupal", "drupal"),
    "joomla":        ("joomla", "joomla\\!"),
    "jquery":        ("jquery", "jquery"),
    "django":        ("djangoproject", "django"),
    "rails":         ("rubyonrails", "rails"),
    "spring":        ("pivotal_software", "spring_framework"),
    "struts":        ("apache", "struts"),
    "log4j":         ("apache", "log4j"),
    "node":          ("nodejs", "node.js"),
    "express":       ("expressjs", "express"),
    "react":         ("facebook", "react"),
    "angular":       ("google", "angular"),
    "vue":           ("vuejs", "vue.js"),
    "bootstrap":     ("getbootstrap", "bootstrap"),
    "smb":           ("microsoft", "windows"),
    "rdp":           ("microsoft", "remote_desktop_protocol"),
    "vnc":           ("realvnc", "vnc"),
    "telnet":        ("gnu", "inetutils"),
}

# TCP banner grab port → expected banner patterns
_BANNER_PORTS: Dict[int, str] = {
    21:    "ftp",
    22:    "ssh",
    25:    "smtp",
    80:    "http",
    110:   "pop3",
    143:   "imap",
    443:   "https",
    3306:  "mysql",
    5432:  "postgresql",
    6379:  "redis",
    27017: "mongodb",
    9200:  "elasticsearch",
    11211: "memcached",
}

# CVSS severity → numeric for ranking
_SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


# ---------------------------------------------------------------------------
# Version string extractor
# ---------------------------------------------------------------------------

class VersionExtractor:
    """
    Extracts version strings from live HTTP responses and TCP banners.
    Does NOT rely on Wappalyzer — performs its own active probing.
    """

    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self._session = req_lib.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; ARTEX-Scanner/2.0)",
        })

    def extract_from_url(self, url: str) -> List[Dict]:
        """
        Fetch URL and extract all version strings.
        Returns [{product, version, source, url}]
        """
        results: List[Dict] = []
        try:
            resp = self._session.get(
                url, timeout=self.timeout, verify=False,
                allow_redirects=True,
            )
            # Combine headers + body for scanning
            header_text = "\n".join(
                f"{k}: {v}" for k, v in resp.headers.items()
            )
            body_text = resp.text[:8000]
            combined  = header_text + "\n" + body_text

            for product, pattern, group_mode in _VERSION_PATTERNS:
                for match in pattern.finditer(combined):
                    if group_mode == "version":
                        version = match.group(1)
                    elif group_mode == "both":
                        # X-Generator pattern captures product + version
                        product = match.group(1).lower()
                        version = match.group(2)
                    else:
                        version = match.group(1)

                    version = version.strip()
                    if not version or not re.match(r"\d", version):
                        continue

                    # Determine source (header vs body)
                    pos   = match.start()
                    src   = "http_header" if pos < len(header_text) else "http_body"

                    results.append({
                        "product": product,
                        "version": version,
                        "source":  src,
                        "url":     url,
                        "raw_match": match.group(0)[:80],
                    })

            # Also check X-Powered-By, Server headers explicitly
            for hdr in ("Server", "X-Powered-By", "X-Generator",
                        "X-AspNet-Version", "X-AspNetMvc-Version"):
                val = resp.headers.get(hdr, "")
                if val:
                    # Try to extract product:version from header value
                    m = re.match(r"^([\w.\-]+)[/\s]([\d.]+)", val)
                    if m:
                        results.append({
                            "product": m.group(1).lower(),
                            "version": m.group(2),
                            "source":  f"header:{hdr}",
                            "url":     url,
                            "raw_match": val[:80],
                        })

        except Exception:
            pass

        return self._deduplicate(results)

    def extract_from_banner(self, host: str, port: int) -> List[Dict]:
        """
        TCP banner grab — read first 2KB from port.
        Non-destructive: connects, reads, closes.
        """
        results: List[Dict] = []
        service = _BANNER_PORTS.get(port, "")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # Wrap in SSL for HTTPS-like ports
            if port in (443, 8443, 465, 993, 995):
                ctx  = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))

            # Send minimal trigger for banner-emitting protocols
            triggers = {
                21:    b"",          # FTP sends banner immediately
                22:    b"",          # SSH sends banner immediately
                25:    b"",          # SMTP sends banner immediately
                3306:  b"",          # MySQL sends greeting packet
                6379:  b"INFO\r\n",  # Redis INFO command
                27017: b"",          # MongoDB sends ismaster response
                9200:  b"GET / HTTP/1.0\r\n\r\n",   # Elasticsearch
                11211: b"version\r\n",               # Memcached
            }
            if port in triggers and triggers[port]:
                sock.sendall(triggers[port])

            banner = sock.recv(2048).decode("utf-8", errors="replace")
            sock.close()

            # Apply version patterns to banner
            for product, pattern, group_mode in _VERSION_PATTERNS:
                for match in pattern.finditer(banner):
                    version = match.group(1)
                    version = version.strip()
                    if not version or not re.match(r"\d", version):
                        continue
                    results.append({
                        "product": product,
                        "version": version,
                        "source":  f"tcp_banner:{port}",
                        "url":     f"{host}:{port}",
                        "raw_match": match.group(0)[:80],
                    })

            # Service-specific banner parsing
            if service == "ssh" and banner.startswith("SSH-"):
                # SSH-2.0-OpenSSH_8.9p1
                m = re.match(r"SSH-\S+-OpenSSH_([\d.p]+)", banner)
                if m:
                    results.append({
                        "product": "openssh",
                        "version": m.group(1),
                        "source":  "ssh_banner",
                        "url":     f"{host}:{port}",
                        "raw_match": banner[:60],
                    })

            if service == "mysql":
                # MySQL greeting packet contains version at offset 5
                # Banner starts with handshake — look for version string
                m = re.search(r"(\d+\.\d+\.\d+[\w-]*)", banner)
                if m:
                    results.append({
                        "product": "mysql",
                        "version": m.group(1),
                        "source":  "mysql_handshake",
                        "url":     f"{host}:{port}",
                        "raw_match": m.group(0),
                    })

            if service == "redis":
                # INFO output: redis_version:7.0.5
                m = re.search(r"redis_version:([\d.]+)", banner)
                if m:
                    results.append({
                        "product": "redis",
                        "version": m.group(1),
                        "source":  "redis_info",
                        "url":     f"{host}:{port}",
                        "raw_match": m.group(0),
                    })

            if service == "postgresql":
                # PostgreSQL greeting contains version
                m = re.search(r"PostgreSQL ([\d.]+)", banner, re.I)
                if m:
                    results.append({
                        "product": "postgresql",
                        "version": m.group(1),
                        "source":  "pgsql_banner",
                        "url":     f"{host}:{port}",
                        "raw_match": m.group(0),
                    })

        except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError):
            pass
        except Exception:
            pass

        return self._deduplicate(results)

    @staticmethod
    def _deduplicate(results: List[Dict]) -> List[Dict]:
        seen:   Set[str]  = set()
        output: List[Dict] = []
        for r in results:
            key = f"{r['product']}:{r['version']}"
            if key not in seen:
                seen.add(key)
                output.append(r)
        return output


# ---------------------------------------------------------------------------
# CPE builder
# ---------------------------------------------------------------------------

class CPEBuilder:
    """
    Constructs CPE 2.3 strings from product + version.
    CPE format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    """

    def build(self, product: str, version: str) -> Optional[str]:
        p_lower = product.lower().strip()
        # Lookup vendor:product from service map
        cpe_tuple = _SERVICE_CPE_MAP.get(p_lower)
        if not cpe_tuple:
            # Try partial match
            for key, val in _SERVICE_CPE_MAP.items():
                if key in p_lower or p_lower in key:
                    cpe_tuple = val
                    break
        if not cpe_tuple:
            return None

        vendor, prod = cpe_tuple
        # Sanitise version for CPE
        version_cpe = re.sub(r"[^a-zA-Z0-9._\-]", "", version)
        if not version_cpe:
            return None

        return f"cpe:2.3:a:{vendor}:{prod}:{version_cpe}:*:*:*:*:*:*:*"

    def build_keyword(self, product: str, version: str) -> str:
        """Build a plain-text search query for NVD keywordSearch."""
        p_lower = product.lower().strip()
        cpe_tuple = _SERVICE_CPE_MAP.get(p_lower)
        if cpe_tuple:
            _, prod = cpe_tuple
            # Clean up product name for search
            prod_clean = prod.replace("_", " ").replace("\\!", "!")
            return f"{prod_clean} {version}"
        return f"{product} {version}"


# ---------------------------------------------------------------------------
# NVD API v2.0 client
# ---------------------------------------------------------------------------

class NVDClient:
    """
    Queries NVD API v2.0 for CVEs by CPE string or keyword.
    Handles rate limiting, pagination, and result normalisation.
    """

    def __init__(self, api_key: str = NVD_API_KEY, timeout: int = 20):
        self.api_key  = api_key
        self.timeout  = timeout
        self._last_req = 0.0
        self._rate_window, self._rate_max = (
            _NVD_RATE_WITH_KEY if api_key else _NVD_RATE_NO_KEY
        )
        self._req_count_in_window = 0
        self._window_start = time.time()
        self.logger = logging.getLogger(__name__ + ".NVD")

    def _wait_rate_limit(self) -> None:
        now = time.time()
        if now - self._window_start > self._rate_window:
            self._req_count_in_window = 0
            self._window_start = now
        if self._req_count_in_window >= self._rate_max:
            wait = self._rate_window - (now - self._window_start) + 0.5
            self.logger.debug(f"NVD rate limit — sleeping {wait:.1f}s")
            time.sleep(max(0.1, wait))
            self._req_count_in_window = 0
            self._window_start = time.time()
        # Minimum gap between requests
        gap = time.time() - self._last_req
        min_gap = 0.6 if self.api_key else 6.5
        if gap < min_gap:
            time.sleep(min_gap - gap)

    def search_by_cpe(self, cpe_name: str, results_per_page: int = 20) -> List[Dict]:
        self._wait_rate_limit()
        params: Dict[str, Any] = {
            "cpeName":        cpe_name,
            "resultsPerPage": results_per_page,
        }
        return self._fetch(params)

    def search_by_keyword(self, keyword: str, results_per_page: int = 15) -> List[Dict]:
        self._wait_rate_limit()
        params: Dict[str, Any] = {
            "keywordSearch":  keyword,
            "keywordExactMatch": False,
            "resultsPerPage": results_per_page,
        }
        return self._fetch(params)

    def search_by_cve_id(self, cve_id: str) -> Optional[Dict]:
        self._wait_rate_limit()
        params = {"cveId": cve_id}
        results = self._fetch(params)
        return results[0] if results else None

    def _fetch(self, params: Dict) -> List[Dict]:
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            resp = req_lib.get(
                NVD_BASE, params=params, headers=headers,
                timeout=self.timeout,
            )
            self._last_req = time.time()
            self._req_count_in_window += 1

            if resp.status_code == 403:
                self.logger.warning("NVD API rate limited (403)")
                time.sleep(35)
                return []
            if resp.status_code != 200:
                self.logger.warning(f"NVD returned {resp.status_code}")
                return []

            data = resp.json()
            return [self._normalise(v) for v in data.get("vulnerabilities", [])]

        except req_lib.exceptions.Timeout:
            self.logger.warning("NVD timeout")
            return []
        except Exception as e:
            self.logger.warning(f"NVD error: {e}")
            return []

    @staticmethod
    def _normalise(vuln_entry: Dict) -> Dict:
        cve   = vuln_entry.get("cve", {})
        cve_id = cve.get("id", "")

        # CVSS — prefer v3.1, fall back to v3.0, then v2.0
        cvss_data  = cve.get("metrics", {})
        cvss_score = None
        cvss_vector = None
        cvss_ver    = None

        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cvss_data.get(metric_key, [])
            if metrics:
                m = metrics[0].get("cvssData", {})
                cvss_score  = m.get("baseScore")
                cvss_vector = m.get("vectorString")
                cvss_ver    = metric_key
                break

        # Severity
        severity = "unknown"
        if cvss_score is not None:
            if cvss_score >= 9.0:   severity = "critical"
            elif cvss_score >= 7.0: severity = "high"
            elif cvss_score >= 4.0: severity = "medium"
            elif cvss_score > 0.0:  severity = "low"
            else:                   severity = "none"

        # Description (English)
        descriptions = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        # Affected CPEs
        cpes: List[str] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        cpes.append(cpe_match.get("criteria", ""))
                        break

        # Published / modified dates
        published = cve.get("published", "")
        modified  = cve.get("lastModified", "")

        # References
        refs = [
            r.get("url", "") for r in cve.get("references", [])[:5]
        ]

        return {
            "cve_id":       cve_id,
            "source":       "nvd",
            "severity":     severity,
            "cvss_score":   cvss_score,
            "cvss_vector":  cvss_vector,
            "cvss_version": cvss_ver,
            "description":  desc[:400],
            "cpes":         cpes[:10],
            "published":    published[:10],
            "modified":     modified[:10],
            "references":   refs,
            "epss_score":   None,     # filled later
            "epss_percentile": None,
            "exploit_available": False,
            "kev_listed":   False,
        }


# ---------------------------------------------------------------------------
# OSV.dev API client
# ---------------------------------------------------------------------------

class OSVClient:
    """
    Queries OSV.dev for vulnerabilities by package name + version.
    OSV covers npm, PyPI, Maven, Go, RubyGems, crates.io, etc.
    """

    _ECOSYSTEM_MAP: Dict[str, str] = {
        "node":      "npm",
        "nodejs":    "npm",
        "express":   "npm",
        "react":     "npm",
        "angular":   "npm",
        "vue":       "npm",
        "jquery":    "npm",
        "django":    "PyPI",
        "flask":     "PyPI",
        "pillow":    "PyPI",
        "requests":  "PyPI",
        "rails":     "RubyGems",
        "sinatra":   "RubyGems",
        "spring":    "Maven",
        "struts":    "Maven",
        "log4j":     "Maven",
        "wordpress":  "npm",    # For JS aspects
        "bootstrap":  "npm",
        "php":        "Packagist",
        "composer":   "Packagist",
        "symfony":    "Packagist",
        "laravel":    "Packagist",
    }

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self._last_req = 0.0

    def query_package(
        self, product: str, version: str
    ) -> List[Dict]:
        ecosystem = self._ECOSYSTEM_MAP.get(product.lower())
        if not ecosystem:
            return []

        # OSV uses package name, not CPE
        pkg_name = self._get_package_name(product)
        if not pkg_name:
            return []

        payload = {
            "version": version,
            "package": {
                "name":      pkg_name,
                "ecosystem": ecosystem,
            },
        }

        return self._post(f"{OSV_BASE}/query", payload)

    def _get_package_name(self, product: str) -> Optional[str]:
        # Map generic names to actual package names
        pkg_map = {
            "node":     "nodejs",
            "express":  "express",
            "react":    "react",
            "angular":  "@angular/core",
            "vue":      "vue",
            "jquery":   "jquery",
            "django":   "django",
            "flask":    "flask",
            "rails":    "rails",
            "log4j":    "log4j",
            "spring":   "spring-framework",
            "struts":   "struts2-core",
            "bootstrap": "bootstrap",
            "symfony":  "symfony/symfony",
            "laravel":  "laravel/framework",
        }
        return pkg_map.get(product.lower(), product.lower())

    def _post(self, url: str, payload: Dict) -> List[Dict]:
        # OSV rate limit: be polite
        gap = time.time() - self._last_req
        if gap < 0.5:
            time.sleep(0.5 - gap)

        try:
            resp = req_lib.post(
                url, json=payload, timeout=self.timeout,
            )
            self._last_req = time.time()

            if resp.status_code != 200:
                return []

            data  = resp.json()
            vulns = data.get("vulns", [])
            return [self._normalise_osv(v) for v in vulns]

        except Exception:
            return []

    @staticmethod
    def _normalise_osv(vuln: Dict) -> Dict:
        aliases    = vuln.get("aliases", [])
        cve_id     = next((a for a in aliases if a.startswith("CVE-")), "")
        summary    = vuln.get("summary", "")
        details    = vuln.get("details", "")[:300]
        modified   = vuln.get("modified", "")[:10]
        published  = vuln.get("published", "")[:10]

        # Severity from database_specific or cvss
        severity  = "unknown"
        cvss_score = None
        for sev_entry in vuln.get("severity", []):
            st = sev_entry.get("type", "")
            sc = sev_entry.get("score", "")
            if "CVSS" in st and sc:
                # Extract base score from vector
                m = re.search(r"(\d+\.\d+)$", sc)
                if m:
                    cvss_score = float(m.group(1))
                    if cvss_score >= 9.0:   severity = "critical"
                    elif cvss_score >= 7.0: severity = "high"
                    elif cvss_score >= 4.0: severity = "medium"
                    elif cvss_score > 0:    severity = "low"
                break

        # Affected ranges
        affected: List[str] = []
        for a_entry in vuln.get("affected", []):
            for r in a_entry.get("ranges", []):
                for ev in r.get("events", []):
                    introduced = ev.get("introduced")
                    fixed      = ev.get("fixed")
                    if introduced:
                        affected.append(f"introduced: {introduced}")
                    if fixed:
                        affected.append(f"fixed: {fixed}")

        return {
            "cve_id":       cve_id or vuln.get("id", ""),
            "osv_id":       vuln.get("id", ""),
            "source":       "osv",
            "severity":     severity,
            "cvss_score":   cvss_score,
            "cvss_vector":  None,
            "description":  (summary or details)[:400],
            "affected_ranges": affected[:6],
            "published":    published,
            "modified":     modified,
            "references":   [r.get("url","") for r in vuln.get("references",[])[:5]],
            "epss_score":   None,
            "epss_percentile": None,
            "exploit_available": False,
            "kev_listed":   False,
        }


# ---------------------------------------------------------------------------
# EPSS API client
# ---------------------------------------------------------------------------

class EPSSClient:
    """
    Fetches Exploit Prediction Scoring System (EPSS) scores from FIRST.org.
    EPSS score = probability of exploitation in the wild within 30 days (0.0–1.0).
    Accepts batch of up to 100 CVE IDs per request.
    """

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    def enrich(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Returns {cve_id: {epss_score: float, percentile: float}}.
        CVEs not found return score=0.0.
        """
        result: Dict[str, Dict] = {}
        if not cve_ids:
            return result

        # Deduplicate and filter to valid CVE-YYYY-NNNNN format
        valid_ids = list({
            cid for cid in cve_ids
            if re.match(r"CVE-\d{4}-\d{4,}", cid, re.I)
        })

        # Batch into groups of _EPSS_BATCH_MAX
        for i in range(0, len(valid_ids), _EPSS_BATCH_MAX):
            batch = valid_ids[i:i + _EPSS_BATCH_MAX]
            batch_result = self._fetch_batch(batch)
            result.update(batch_result)
            if i + _EPSS_BATCH_MAX < len(valid_ids):
                time.sleep(0.5)

        return result

    def _fetch_batch(self, cve_ids: List[str]) -> Dict[str, Dict]:
        result: Dict[str, Dict] = {}
        try:
            # EPSS API accepts cve= as repeated query param
            params = [("cve", cid) for cid in cve_ids]
            resp   = req_lib.get(
                EPSS_BASE, params=params, timeout=self.timeout,
            )
            if resp.status_code != 200:
                return result

            data = resp.json()
            for entry in data.get("data", []):
                cve_id     = entry.get("cve", "")
                epss_score = float(entry.get("epss", 0.0))
                percentile = float(entry.get("percentile", 0.0)) * 100  # → 0–100

                result[cve_id] = {
                    "epss_score":        round(epss_score, 4),
                    "epss_percentile":   round(percentile, 1),
                    "epss_label": (
                        "critical" if epss_score >= 0.70
                        else "high"    if epss_score >= 0.30
                        else "medium"  if epss_score >= 0.05
                        else "low"
                    ),
                }

        except Exception:
            pass

        return result


# ---------------------------------------------------------------------------
# CISA KEV checker
# ---------------------------------------------------------------------------

class KEVChecker:
    """
    Checks CISA Known Exploited Vulnerabilities catalog.
    Downloads once per session and caches in memory.
    """
    _CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    _cache:       Optional[Set[str]] = None
    _cache_time:  float              = 0.0
    _CACHE_TTL    = 86400            # 24 hours

    def is_in_kev(self, cve_id: str) -> bool:
        kev_set = self._get_kev_set()
        return cve_id.upper() in kev_set

    def _get_kev_set(self) -> Set[str]:
        now = time.time()
        if KEVChecker._cache and (now - KEVChecker._cache_time) < KEVChecker._CACHE_TTL:
            return KEVChecker._cache

        try:
            resp = req_lib.get(
                self._CATALOG_URL, timeout=20
            )
            if resp.status_code == 200:
                data = resp.json()
                KEVChecker._cache = {
                    v.get("cveID", "").upper()
                    for v in data.get("vulnerabilities", [])
                }
                KEVChecker._cache_time = now
                return KEVChecker._cache
        except Exception:
            pass

        return KEVChecker._cache or set()


# ---------------------------------------------------------------------------
# Version range matcher — does detected version fall in CVE's affected range?
# ---------------------------------------------------------------------------

class VersionMatcher:
    """
    Checks if a detected version string falls within a CVE's affected version range.
    Uses simple tuple comparison — avoids packaging library dependency.
    """

    @staticmethod
    def parse_version(version_str: str) -> Tuple[int, ...]:
        """Convert '7.4.3' → (7, 4, 3). Strips non-numeric suffixes."""
        clean = re.match(r"(\d[\d.]*)", version_str.strip())
        if not clean:
            return (0,)
        parts = clean.group(1).rstrip(".").split(".")
        try:
            return tuple(int(p) for p in parts[:5])
        except ValueError:
            return (0,)

    @staticmethod
    def compare(v1: str, v2: str) -> int:
        """Returns -1, 0, or 1."""
        t1 = VersionMatcher.parse_version(v1)
        t2 = VersionMatcher.parse_version(v2)
        # Pad to same length
        max_len = max(len(t1), len(t2))
        t1 = t1 + (0,) * (max_len - len(t1))
        t2 = t2 + (0,) * (max_len - len(t2))
        if t1 < t2:   return -1
        if t1 > t2:   return  1
        return 0

    def version_in_cpe(self, detected_version: str, cpe_string: str) -> bool:
        """
        Does a CPE string's version component match the detected version?
        cpe:2.3:a:vendor:product:7.4.3:*:... → matches if detected == 7.4.3
        Also handles 'up_to_including' ranges in NVD cpeMatch.
        """
        m = re.match(
            r"cpe:2\.3:a:[^:]+:[^:]+:([^:]+):", cpe_string
        )
        if not m:
            return False
        cpe_version = m.group(1)
        if cpe_version in ("*", "-"):
            return True  # wildcard — assume match
        return self.compare(detected_version, cpe_version) == 0

    def version_in_range(
        self,
        detected: str,
        introduced: Optional[str],
        fixed: Optional[str],
    ) -> bool:
        """
        Returns True if introduced <= detected < fixed.
        None introduced means "from the beginning".
        None fixed means "not yet fixed".
        """
        if introduced and self.compare(detected, introduced) < 0:
            return False
        if fixed and self.compare(detected, fixed) >= 0:
            return False
        return True


# ---------------------------------------------------------------------------
# Main CVE mapper
# ---------------------------------------------------------------------------

class AICVEMapper:
    """
    Active CVE discovery engine for ARTEX.

    Workflow per component:
        1. Extract version strings (HTTP headers, body, TCP banner)
        2. Build CPE strings from product + version
        3. Query NVD by CPE + keyword
        4. Query OSV by package + version (for supported ecosystems)
        5. Enrich all discovered CVEs with EPSS scores (batch)
        6. Check CISA KEV for each CVE
        7. Version range filter — keep only CVEs where detected version
           falls within the vulnerable range
        8. Deduplicate across NVD + OSV results
        9. Groq AI ranking by exploitability × business impact × EPSS

    Slot in run_scan() after tech_detection + port_scan:
        mapper = AICVEMapper(groq_api_key=GROQ_API_KEY)
        scan_results[scan_id]['cve_map'] = mapper.map(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    def __init__(
        self,
        groq_api_key:  str = GROQ_API_KEY,
        nvd_api_key:   str = NVD_API_KEY,
        timeout:       int = 15,
        max_components: int = 20,
        max_workers:   int = 4,
    ):
        self.groq_api_key    = groq_api_key
        self.max_components  = max_components
        self.max_workers     = max_workers

        self._extractor  = VersionExtractor(timeout=timeout)
        self._cpe_builder = CPEBuilder()
        self._nvd         = NVDClient(api_key=nvd_api_key, timeout=timeout)
        self._osv         = OSVClient(timeout=timeout)
        self._epss        = EPSSClient(timeout=timeout)
        self._kev         = KEVChecker()
        self._ver_matcher  = VersionMatcher()

        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] AICVEMapper — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def map(self, domain: str, scan_results: Dict) -> Dict:
        """
        Args:
            domain:       Primary target domain.
            scan_results: Full ARTEX scan_results dict.

        Returns:
            {
                components:      [{product, version, source, cpe, urls}]
                cve_findings:    [{cve_id, product, version, severity,
                                    cvss_score, epss_score, epss_percentile,
                                    kev_listed, description, ...}]
                kev_findings:    [cve_findings entries where kev_listed=True]
                high_epss:       [cve_findings entries where epss_score>=0.3]
                severity_counts: {critical, high, medium, low}
                ai_analysis:     Groq ranking + narrative
                scan_metadata
            }
        """
        self.logger.info(f"CVE mapping starting — domain: {domain}")
        start = time.time()

        # ── Step 1: Collect component targets ────────────────────────
        components = self._collect_components(domain, scan_results)
        self.logger.info(f"Components to map: {len(components)}")

        # ── Step 2: Extract version strings from live targets ─────────
        components = self._enrich_versions(components)
        versioned = [c for c in components if c.get("version")]
        self.logger.info(f"Components with versions: {len(versioned)}")

        # ── Step 3: CVE search per component ─────────────────────────
        all_cves: List[Dict] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._search_cves_for_component, c): c
                for c in versioned[:self.max_components]
            }
            for future in as_completed(futures):
                component = futures[future]
                try:
                    cves = future.result()
                    for cve in cves:
                        cve["component_product"] = component["product"]
                        cve["component_version"] = component["version"]
                        cve["component_url"]     = component.get("urls", [component.get("url","")])
                        all_cves.append(cve)
                    self.logger.info(
                        f"  {component['product']} {component['version']}: "
                        f"{len(cves)} CVEs"
                    )
                except Exception as e:
                    self.logger.warning(
                        f"CVE search failed for {component.get('product','?')}: {e}"
                    )

        # ── Step 4: Deduplicate across sources ────────────────────────
        all_cves = self._deduplicate_cves(all_cves)
        self.logger.info(f"Total unique CVEs after dedup: {len(all_cves)}")

        # ── Step 5: EPSS enrichment (batch) ──────────────────────────
        cve_ids = [
            c["cve_id"] for c in all_cves
            if re.match(r"CVE-\d{4}-\d+", c.get("cve_id", ""))
        ]
        if cve_ids:
            epss_map = self._epss.enrich(cve_ids)
            for cve in all_cves:
                epss = epss_map.get(cve["cve_id"], {})
                cve["epss_score"]       = epss.get("epss_score", 0.0)
                cve["epss_percentile"]  = epss.get("epss_percentile", 0.0)
                cve["epss_label"]       = epss.get("epss_label", "unknown")
            self.logger.info(f"EPSS enrichment complete — {len(epss_map)} scores")

        # ── Step 6: CISA KEV check ────────────────────────────────────
        for cve in all_cves:
            cve["kev_listed"] = self._kev.is_in_kev(cve.get("cve_id", ""))

        # ── Step 7: Scoring and sorting ───────────────────────────────
        all_cves = self._score_and_sort(all_cves)

        # ── Step 8: Build output subsets ─────────────────────────────
        kev_findings  = [c for c in all_cves if c["kev_listed"]]
        high_epss     = [c for c in all_cves if (c.get("epss_score") or 0) >= 0.3]
        sev_counts    = defaultdict(int)
        for cve in all_cves:
            sev_counts[cve.get("severity", "unknown")] += 1

        # ── Step 9: AI ranking ────────────────────────────────────────
        ai_result = None
        if self.groq_api_key and all_cves:
            ai_result = self._ai_analysis(domain, all_cves[:25], kev_findings, high_epss)

        duration = round(time.time() - start, 2)
        self.logger.info(
            f"CVE mapping complete — {len(all_cves)} CVEs, "
            f"{len(kev_findings)} KEV, {len(high_epss)} high-EPSS in {duration}s"
        )

        return {
            "components":      versioned,
            "cve_findings":    all_cves,
            "kev_findings":    kev_findings,
            "high_epss":       high_epss,
            "severity_counts": dict(sev_counts),
            "ai_analysis":     ai_result,
            "scan_metadata": {
                "domain":                domain,
                "scan_duration_seconds": duration,
                "timestamp":             datetime.now().isoformat(),
                "ai_model":              "Groq Llama3-70B" if ai_result else "Rule-based only",
                "components_scanned":    len(versioned),
                "total_cves":            len(all_cves),
                "kev_count":             len(kev_findings),
                "high_epss_count":       len(high_epss),
            },
        }

    # ------------------------------------------------------------------
    # Component collection from scan_results
    # ------------------------------------------------------------------

    def _collect_components(self, domain: str, sr: Dict) -> List[Dict]:
        """
        Build component list from tech_detection names and port_scan services.
        Each component: {product, version (may be empty), source, url, host, port}
        """
        components: List[Dict] = []
        seen: Set[str] = set()

        def _add(product: str, version: str, source: str,
                 url: str = "", host: str = "", port: int = 0) -> None:
            p_lower = product.lower().strip()
            if not p_lower or p_lower in ("unknown", "generic", ""):
                return
            # Map to canonical CPE-friendly name
            canonical = p_lower
            for key in _SERVICE_CPE_MAP:
                if key in p_lower:
                    canonical = key
                    break
            sig = f"{canonical}:{version}"
            if sig in seen:
                return
            seen.add(sig)
            components.append({
                "product":   canonical,
                "version":   version,
                "source":    source,
                "url":       url,
                "host":      host,
                "port":      port,
                "cpe":       None,    # filled in _enrich_versions
                "urls":      [url] if url else [],
            })

        # ── From tech_detection ───────────────────────────────────────
        for url, tech_data in sr.get("tech_detection", {}).items():
            if not isinstance(tech_data, dict):
                continue
            for tech in tech_data.get("technologies", []):
                if not isinstance(tech, dict):
                    continue
                name    = tech.get("name", "")
                version = tech.get("version") or ""   # Wappalyzer returns None
                _add(name, version, "tech_detection", url=url)

        # ── From port_scan ────────────────────────────────────────────
        for host_data in sr.get("port_scan", []):
            if not isinstance(host_data, dict):
                continue
            target = host_data.get("target", domain)

            for port_info in host_data.get("ports", []):
                if not isinstance(port_info, dict):
                    continue
                service = port_info.get("service", "")
                version = port_info.get("version", "")
                port    = port_info.get("port", 0)
                if service:
                    _add(service, version, "port_scan",
                         host=target, port=port)

            for rp in host_data.get("risky_ports", []):
                if not isinstance(rp, dict):
                    continue
                service = rp.get("service", "")
                version = rp.get("version", "")
                port    = rp.get("port", 0)
                if service:
                    _add(service, version, "port_scan_risky",
                         host=target, port=port)

        # ── From active subdomains (HTTP probe targets) ───────────────
        subdomains = sr.get("subdomains", [])
        active = [
            s for s in subdomains
            if (s.get("http_status") == 200 or s.get("https_status") == 200)
        ]
        # We'll extract versions from these in _enrich_versions
        # Add placeholder entries for each active subdomain
        for sub in active[:8]:
            name = sub.get("subdomain", "")
            scheme = "https" if sub.get("https_status") == 200 else "http"
            url = f"{scheme}://{name}/"
            if url not in seen:
                seen.add(url)
                components.append({
                    "product":   "_probe_target",
                    "version":   "",
                    "source":    "subdomain",
                    "url":       url,
                    "host":      name,
                    "port":      443 if scheme == "https" else 80,
                    "cpe":       None,
                    "urls":      [url],
                    "_is_probe_target": True,
                })

        return components

    # ------------------------------------------------------------------
    # Version enrichment — active probing
    # ------------------------------------------------------------------

    def _enrich_versions(self, components: List[Dict]) -> List[Dict]:
        """
        For components without version strings, do active probing:
        - HTTP header/body version extraction for URL-based components
        - TCP banner grab for port-based components
        - Merge new version findings back into components
        """
        # Collect URLs to probe (avoid duplicates)
        urls_to_probe: List[str] = []
        seen_probe_urls: Set[str] = set()

        # Banner targets: (host, port)
        banner_targets: List[Tuple[str, int]] = []
        seen_banner: Set[str] = set()

        for c in components:
            if c.get("_is_probe_target") or not c.get("version"):
                url = c.get("url", "")
                if url and url not in seen_probe_urls:
                    seen_probe_urls.add(url)
                    urls_to_probe.append(url)
            if c.get("host") and c.get("port") and c.get("port") in _BANNER_PORTS:
                sig = f"{c['host']}:{c['port']}"
                if sig not in seen_banner:
                    seen_banner.add(sig)
                    banner_targets.append((c["host"], c["port"]))

        # HTTP extraction in parallel
        url_results: Dict[str, List[Dict]] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._extractor.extract_from_url, url): url
                for url in urls_to_probe[:12]
            }
            for future in as_completed(futures):
                url = futures[future]
                try:
                    findings = future.result()
                    if findings:
                        url_results[url] = findings
                except Exception:
                    pass

        # TCP banner extraction in parallel
        banner_results: Dict[str, List[Dict]] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._extractor.extract_from_banner, host, port): f"{host}:{port}"
                for host, port in banner_targets[:10]
            }
            for future in as_completed(futures):
                sig = futures[future]
                try:
                    findings = future.result()
                    if findings:
                        banner_results[sig] = findings
                except Exception:
                    pass

        # Merge newly discovered version strings into components
        # Also create new components for versions found in HTTP probing
        new_components: List[Dict] = []
        existing_sigs: Set[str] = {
            f"{c['product']}:{c['version']}" for c in components
        }

        for url, findings in url_results.items():
            for f in findings:
                sig = f"{f['product']}:{f['version']}"
                if sig not in existing_sigs:
                    existing_sigs.add(sig)
                    new_components.append({
                        "product": f["product"],
                        "version": f["version"],
                        "source":  f["source"],
                        "url":     url,
                        "host":    urlparse(url).netloc,
                        "port":    0,
                        "cpe":     None,
                        "urls":    [url],
                    })
                # Update existing component if it has no version
                for c in components:
                    if (c["product"] == f["product"] and not c["version"]
                            and c.get("url") == url):
                        c["version"] = f["version"]
                        break

        for sig_key, findings in banner_results.items():
            host, port_str = sig_key.rsplit(":", 1)
            port = int(port_str)
            for f in findings:
                sig = f"{f['product']}:{f['version']}"
                if sig not in existing_sigs:
                    existing_sigs.add(sig)
                    new_components.append({
                        "product": f["product"],
                        "version": f["version"],
                        "source":  f["source"],
                        "url":     f"{host}:{port}",
                        "host":    host,
                        "port":    port,
                        "cpe":     None,
                        "urls":    [f"{host}:{port}"],
                    })

        # Remove probe-target placeholders and versionless entries
        all_components = [
            c for c in components + new_components
            if not c.get("_is_probe_target") and c.get("version")
        ]

        # Build CPE strings
        for c in all_components:
            c["cpe"] = self._cpe_builder.build(c["product"], c["version"])

        return all_components

    # ------------------------------------------------------------------
    # CVE search per component
    # ------------------------------------------------------------------

    def _search_cves_for_component(self, component: Dict) -> List[Dict]:
        """
        Multi-source CVE search for one component.
        Applies version range filtering to reduce false positives.
        """
        product = component["product"]
        version = component["version"]
        cpe     = component.get("cpe")

        all_cves: List[Dict] = []
        seen_cve_ids: Set[str] = set()

        # ── NVD: CPE-based search ─────────────────────────────────────
        if cpe:
            nvd_cpes = self._nvd.search_by_cpe(cpe, results_per_page=20)
            for cve in nvd_cpes:
                cid = cve.get("cve_id", "")
                if cid and cid not in seen_cve_ids:
                    # Version range filter
                    if self._passes_version_filter(cve, version):
                        seen_cve_ids.add(cid)
                        all_cves.append(cve)

        # ── NVD: keyword-based search ─────────────────────────────────
        keyword = self._cpe_builder.build_keyword(product, version)
        nvd_kw  = self._nvd.search_by_keyword(keyword, results_per_page=10)
        for cve in nvd_kw:
            cid = cve.get("cve_id", "")
            if cid and cid not in seen_cve_ids:
                if self._passes_version_filter(cve, version):
                    seen_cve_ids.add(cid)
                    all_cves.append(cve)

        # ── OSV: package-based search ─────────────────────────────────
        osv_results = self._osv.query_package(product, version)
        for cve in osv_results:
            cid = cve.get("cve_id", "") or cve.get("osv_id", "")
            if cid and cid not in seen_cve_ids:
                # OSV already applies version filtering
                seen_cve_ids.add(cid)
                all_cves.append(cve)

        return all_cves

    def _passes_version_filter(self, cve: Dict, detected_version: str) -> bool:
        """
        Returns True if the detected version plausibly falls within
        the CVE's affected range.
        Conservative: if no range data available, include the CVE.
        """
        if not detected_version:
            return True

        # Try to match against CPE version components
        for cpe_str in cve.get("cpes", []):
            if self._ver_matcher.version_in_cpe(detected_version, cpe_str):
                return True

        # Try OSV-style ranges
        affected = cve.get("affected_ranges", [])
        if affected:
            introduced = None
            fixed      = None
            for entry in affected:
                if entry.startswith("introduced:"):
                    introduced = entry.replace("introduced:", "").strip()
                if entry.startswith("fixed:"):
                    fixed = entry.replace("fixed:", "").strip()
            if introduced or fixed:
                return self._ver_matcher.version_in_range(
                    detected_version, introduced, fixed
                )

        # No range data — include (conservative)
        return True

    # ------------------------------------------------------------------
    # Deduplication across NVD + OSV
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate_cves(cves: List[Dict]) -> List[Dict]:
        """
        Merge duplicate CVE IDs from different sources.
        NVD takes precedence over OSV (better CVSS data).
        """
        by_cve_id: Dict[str, Dict] = {}

        for cve in cves:
            cid = cve.get("cve_id", "") or cve.get("osv_id", "")
            if not cid:
                continue
            if cid not in by_cve_id:
                by_cve_id[cid] = cve
            else:
                existing = by_cve_id[cid]
                # Merge: prefer NVD source, keep higher CVSS
                if cve.get("source") == "nvd" and existing.get("source") != "nvd":
                    # NVD version wins
                    cve["component_product"] = existing.get("component_product", cve.get("component_product"))
                    cve["component_version"] = existing.get("component_version", cve.get("component_version"))
                    by_cve_id[cid] = cve
                else:
                    # Keep existing but merge CVSS if better
                    if (cve.get("cvss_score") or 0) > (existing.get("cvss_score") or 0):
                        existing["cvss_score"]  = cve["cvss_score"]
                        existing["cvss_vector"] = cve.get("cvss_vector")

        return list(by_cve_id.values())

    # ------------------------------------------------------------------
    # Scoring and sorting
    # ------------------------------------------------------------------

    def _score_and_sort(self, cves: List[Dict]) -> List[Dict]:
        """
        Compute composite exploitability score for each CVE:
            (cvss_score * 0.5) + (epss_score * 100 * 0.3) + (kev_bonus * 0.2)
        Sort descending by composite score.
        """
        for cve in cves:
            cvss   = float(cve.get("cvss_score") or 0)
            epss   = float(cve.get("epss_score") or 0) * 100  # 0–100
            kev    = 25.0 if cve.get("kev_listed") else 0.0

            composite = (cvss * 10 * 0.5) + (epss * 0.3) + (kev * 0.2)
            cve["composite_score"] = round(composite, 2)

        cves.sort(key=lambda x: x["composite_score"], reverse=True)
        return cves

    # ------------------------------------------------------------------
    # Pass 2 — Groq AI analysis
    # ------------------------------------------------------------------

    def _ai_analysis(
        self,
        domain:        str,
        all_cves:      List[Dict],
        kev_findings:  List[Dict],
        high_epss:     List[Dict],
    ) -> Optional[Dict]:
        try:
            prompt = self._build_prompt(domain, all_cves, kev_findings, high_epss)
            text   = self._call_groq(prompt)
            if not text:
                return None
            return self._parse_ai_response(text)
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return None

    def _build_prompt(
        self,
        domain:       str,
        all_cves:     List[Dict],
        kev_findings: List[Dict],
        high_epss:    List[Dict],
    ) -> str:
        condensed = []
        for cve in all_cves[:20]:
            condensed.append({
                "cve_id":        cve.get("cve_id", ""),
                "product":       cve.get("component_product", ""),
                "version":       cve.get("component_version", ""),
                "severity":      cve.get("severity", "?"),
                "cvss":          cve.get("cvss_score"),
                "epss":          cve.get("epss_score"),
                "epss_pct":      cve.get("epss_percentile"),
                "kev":           cve.get("kev_listed", False),
                "composite":     cve.get("composite_score", 0),
                "description":   cve.get("description", "")[:100],
            })

        return f"""You are a senior vulnerability analyst and red team engineer.
Rank and analyse these CVEs discovered on {domain} and return ONLY valid JSON.

Total CVEs found: {len(all_cves)}
CISA KEV listed: {len(kev_findings)}
High EPSS (>=30%): {len(high_epss)}

Top CVEs (sorted by composite score = CVSS*0.5 + EPSS*0.3 + KEV*0.2):
{json.dumps(condensed, indent=2)}

Return a JSON object with EXACTLY these keys:
- "exploitation_ranking": array of objects ordered by real-world threat priority (not just CVSS), each with:
    "rank" (int 1-10), "cve_id" (string), "product_version" (string),
    "why_this_rank" (string — specific reasoning using EPSS/KEV/CVSS/exploit-availability),
    "exploit_scenario" (string — 2 sentences: how an attacker would use this CVE against {domain}),
    "immediate_action" (string — what to do RIGHT NOW).
- "kev_critical_note": string — 2 sentences on the urgency of KEV-listed CVEs if any exist.
    If none, write "No CISA KEV entries found — monitor EPSS scores for changes."
- "epss_insights": string — 2 sentences interpreting the EPSS distribution.
    High EPSS = actively being exploited in wild. What does the distribution tell us?
- "attack_chain_potential": string — 2-3 sentences: could any of these CVEs be chained
    for escalated impact? E.g. RCE via CVE-X → then lateral movement via CVE-Y.
- "patch_priority_matrix": array of objects, each with:
    "priority" (critical|high|medium|low), "cve_ids" (array of strings),
    "rationale" (string — why this group has this priority),
    "patch_window" (string — e.g. "24 hours", "7 days", "next maintenance window").
- "overall_cve_risk": one of [critical, high, medium, low, info].

Return ONLY valid JSON. No markdown fences, no preamble."""

    def _call_groq(self, prompt: str) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type":  "application/json",
        }
        payload = {
            "model":       "llama3-70b-8192",
            "messages":    [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens":  2000,
        }
        for attempt in range(3):
            try:
                self.logger.info(f"Groq API call attempt {attempt + 1}")
                resp = req_lib.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=headers, json=payload, timeout=50,
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
                if resp.status_code == 429:
                    time.sleep(15 * (attempt + 1))
                    continue
                break
            except req_lib.exceptions.Timeout:
                if attempt < 2:
                    time.sleep(2 ** attempt)
            except Exception as e:
                self.logger.error(f"Groq error: {e}")
                break
        return None

    def _parse_ai_response(self, text: str) -> Optional[Dict]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("```")[1]
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
        cleaned = cleaned.strip()
        try:
            parsed = json.loads(cleaned)
            parsed["ai_model"]     = "Groq Llama3-70B"
            parsed["generated_at"] = datetime.now().isoformat()
            return parsed
        except json.JSONDecodeError:
            start = cleaned.find("{")
            end   = cleaned.rfind("}") + 1
            if start != -1 and end > start:
                try:
                    parsed = json.loads(cleaned[start:end])
                    parsed["ai_model"]     = "Groq Llama3-70B"
                    parsed["generated_at"] = datetime.now().isoformat()
                    return parsed
                except json.JSONDecodeError:
                    pass
            self.logger.error("Could not parse Groq JSON response")
            return None