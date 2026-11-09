# core/cve_matcher.py
from __future__ import annotations

import logging
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class CvssRating(Enum):
    CRITICAL  = "CRITICAL"   # 9.0-10.0
    HIGH      = "HIGH"       # 7.0-8.9
    MEDIUM    = "MEDIUM"     # 4.0-6.9
    LOW       = "LOW"        # 0.1-3.9
    NONE      = "NONE"       # 0.0

    @staticmethod
    def from_score(score: float) -> "CvssRating":
        if score >= 9.0:  return CvssRating.CRITICAL
        if score >= 7.0:  return CvssRating.HIGH
        if score >= 4.0:  return CvssRating.MEDIUM
        if score > 0.0:   return CvssRating.LOW
        return CvssRating.NONE


class MatchConfidence(Enum):
    CONFIRMED   = "confirmed"    # version exactly in affected range
    LIKELY      = "likely"       # tech name matched, version absent
    POSSIBLE    = "possible"     # tech family matched, version unclear
    CONTEXTUAL  = "contextual"   # port/ssl signal matches known CVE surface


# ─────────────────────────────────────────────────────────────────────────────
# Static CVE knowledge base
# Each entry is the ground truth from NVD / vendor advisories, baked in so
# the module has zero external dependencies.
# Fields: cve_id, description, cvss_v3, cvss_v2, cpe_prefix, affected_versions,
#         vector_string, exploit_available, patch_available, references, tags
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CveEntry:
    cve_id:             str
    description:        str
    cvss_v3:            float
    cvss_v2:            float
    cpe_prefix:         str          # matched against detected tech name
    affected_versions:  Tuple[str, ...] = ()   # empty = all known versions
    affected_range:     Optional[Tuple[Optional[str], Optional[str]]] = None  # (min, max) semver
    vector_string:      str = ""
    exploit_available:  bool = False
    patch_available:    bool = True
    references:         Tuple[str, ...] = ()
    tags:               Tuple[str, ...] = ()

    @property
    def rating(self) -> CvssRating:
        return CvssRating.from_score(self.cvss_v3)


# ─────────────────────────────────────────────────────────────────────────────
# CVE database — sourced from NVD, curated for web-facing technologies
# Format: tech keyword (lowercase) → list of CveEntry
# ─────────────────────────────────────────────────────────────────────────────

_CVE_DB: Dict[str, List[CveEntry]] = {

    # ── Apache HTTP Server ───────────────────────────────────────────────────
    "apache": [
        CveEntry(
            cve_id="CVE-2021-41773",
            description="Path traversal and RCE in Apache HTTP Server 2.4.49 — "
                        "insufficient input normalisation allows unauthenticated "
                        "traversal outside document root; when mod_cgi enabled, RCE.",
            cvss_v3=9.8, cvss_v2=7.5,
            cpe_prefix="apache",
            affected_versions=("2.4.49",),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://httpd.apache.org/security/vulnerabilities_24.html",),
            tags=("rce", "path_traversal", "actively_exploited"),
        ),
        CveEntry(
            cve_id="CVE-2021-42013",
            description="Path traversal bypass in Apache 2.4.49-2.4.50 via double URL encoding.",
            cvss_v3=9.8, cvss_v2=7.5,
            cpe_prefix="apache",
            affected_versions=("2.4.49", "2.4.50"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://httpd.apache.org/security/vulnerabilities_24.html",),
            tags=("rce", "path_traversal", "bypass"),
        ),
        CveEntry(
            cve_id="CVE-2017-7679",
            description="Apache mod_mime buffer overread — remote code execution via "
                        "malformed Content-Type response header.",
            cvss_v3=9.8, cvss_v2=7.5,
            cpe_prefix="apache",
            affected_range=(None, "2.4.25"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://httpd.apache.org/security/vulnerabilities_24.html",),
            tags=("rce", "buffer_overflow"),
        ),
        CveEntry(
            cve_id="CVE-2022-22721",
            description="Apache HTTP Server 2.4.52 and earlier — LimitXMLRequestBody "
                        "integer overflow leads to heap buffer overflow.",
            cvss_v3=9.1, cvss_v2=6.4,
            cpe_prefix="apache",
            affected_range=(None, "2.4.52"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
            exploit_available=False, patch_available=True,
            references=("https://httpd.apache.org/security/vulnerabilities_24.html",),
            tags=("buffer_overflow"),
        ),
        CveEntry(
            cve_id="CVE-2007-6750",
            description="Apache mod_status server-side request smuggling and slow HTTP DoS "
                        "(Slowloris) — no connection timeout enforcement.",
            cvss_v3=5.3, cvss_v2=5.0,
            cpe_prefix="apache",
            affected_range=(None, "2.2.17"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            exploit_available=True, patch_available=True,
            tags=("dos", "http_request_smuggling"),
        ),
    ],

    # ── nginx ────────────────────────────────────────────────────────────────
    "nginx": [
        CveEntry(
            cve_id="CVE-2021-23017",
            description="nginx DNS resolver off-by-one heap write — specially crafted "
                        "DNS response allows remote heap corruption.",
            cvss_v3=7.7, cvss_v2=6.8,
            cpe_prefix="nginx",
            affected_range=(None, "1.20.0"),
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=False, patch_available=True,
            references=("https://nginx.org/en/security_advisories.html",),
            tags=("heap_overflow", "dns"),
        ),
        CveEntry(
            cve_id="CVE-2017-7529",
            description="nginx integer overflow in mp4 module — allows reading of "
                        "potentially sensitive process memory (information disclosure).",
            cvss_v3=7.5, cvss_v2=5.0,
            cpe_prefix="nginx",
            affected_range=(None, "1.13.2"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            exploit_available=True, patch_available=True,
            references=("https://nginx.org/en/security_advisories.html",),
            tags=("info_disclosure", "integer_overflow"),
        ),
        CveEntry(
            cve_id="CVE-2019-20372",
            description="nginx HTTP request smuggling via invalid Transfer-Encoding "
                        "in HTTP/1.1 requests.",
            cvss_v3=5.3, cvss_v2=4.3,
            cpe_prefix="nginx",
            affected_range=(None, "1.17.7"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            exploit_available=True, patch_available=True,
            tags=("http_request_smuggling"),
        ),
    ],

    # ── PHP ──────────────────────────────────────────────────────────────────
    "php": [
        CveEntry(
            cve_id="CVE-2024-4577",
            description="PHP CGI argument injection on Windows — Windows encoding "
                        "quirk allows unauthenticated RCE via crafted URL in XAMPP "
                        "and similar CGI configurations.",
            cvss_v3=9.8, cvss_v2=10.0,
            cpe_prefix="php",
            affected_range=("8.0.0", "8.3.8"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://www.php.net/ChangeLog-8.php",),
            tags=("rce", "argument_injection", "actively_exploited"),
        ),
        CveEntry(
            cve_id="CVE-2022-31625",
            description="PHP Postgres extension use-after-free leads to remote "
                        "code execution via pg_query_params().",
            cvss_v3=8.1, cvss_v2=6.8,
            cpe_prefix="php",
            affected_range=(None, "8.1.7"),
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=False, patch_available=True,
            tags=("rce", "use_after_free"),
        ),
        CveEntry(
            cve_id="CVE-2021-21703",
            description="PHP-FPM master process privilege escalation via out-of-bounds "
                        "write in fpm_log.c.",
            cvss_v3=7.0, cvss_v2=6.9,
            cpe_prefix="php",
            affected_range=(None, "8.0.11"),
            vector_string="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            tags=("privesc", "local"),
        ),
        CveEntry(
            cve_id="CVE-2019-11043",
            description="PHP-FPM path_info buffer underflow — crafted nginx config "
                        "allows remote code execution via URL.",
            cvss_v3=9.8, cvss_v2=7.5,
            cpe_prefix="php",
            affected_range=(None, "7.3.10"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://bugs.php.net/bug.php?id=78599",),
            tags=("rce", "buffer_underflow", "actively_exploited"),
        ),
    ],

    # ── WordPress ────────────────────────────────────────────────────────────
    "wordpress": [
        CveEntry(
            cve_id="CVE-2023-2745",
            description="WordPress Core directory traversal via the wp_theme_json_resolver "
                        "class allows reading arbitrary files (< 6.2.1).",
            cvss_v3=6.4, cvss_v2=5.5,
            cpe_prefix="wordpress",
            affected_range=(None, "6.2.1"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            exploit_available=True, patch_available=True,
            tags=("lfi", "path_traversal"),
        ),
        CveEntry(
            cve_id="CVE-2022-21661",
            description="WordPress SQLi via WP_Query — authenticated (subscriber+) SQL "
                        "injection through the posts query.",
            cvss_v3=8.8, cvss_v2=6.5,
            cpe_prefix="wordpress",
            affected_range=(None, "5.8.3"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            tags=("sqli", "authenticated"),
        ),
        CveEntry(
            cve_id="CVE-2022-21663",
            description="WordPress object injection via untrusted deserialization of "
                        "multisite meta values.",
            cvss_v3=7.2, cvss_v2=6.5,
            cpe_prefix="wordpress",
            affected_range=(None, "5.8.3"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=False, patch_available=True,
            tags=("deserialization", "object_injection"),
        ),
        CveEntry(
            cve_id="CVE-2020-36326",
            description="WordPress PHP object injection via phpmailer internal deserialization.",
            cvss_v3=9.8, cvss_v2=7.5,
            cpe_prefix="wordpress",
            affected_range=(None, "5.4.1"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            tags=("rce", "deserialization"),
        ),
    ],

    # ── Drupal ───────────────────────────────────────────────────────────────
    "drupal": [
        CveEntry(
            cve_id="CVE-2018-7600",
            description="Drupalgeddon2 — remote code execution via form API "
                        "AJAX requests without authentication (Drupal 6/7/8).",
            cvss_v3=9.8, cvss_v2=10.0,
            cpe_prefix="drupal",
            affected_range=(None, "8.5.1"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://www.drupal.org/sa-core-2018-002",),
            tags=("rce", "actively_exploited", "unauthenticated"),
        ),
        CveEntry(
            cve_id="CVE-2018-7602",
            description="Drupalgeddon3 — remote code execution via request "
                        "cancellation in node deletion flow (authenticated).",
            cvss_v3=8.1, cvss_v2=6.0,
            cpe_prefix="drupal",
            affected_range=(None, "8.5.2"),
            vector_string="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://www.drupal.org/sa-core-2018-004",),
            tags=("rce", "authenticated"),
        ),
        CveEntry(
            cve_id="CVE-2019-6340",
            description="Drupal REST API remote code execution — non-form data "
                        "endpoints deserialise PHP objects.",
            cvss_v3=8.1, cvss_v2=6.8,
            cpe_prefix="drupal",
            affected_range=(None, "8.6.10"),
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            tags=("rce", "deserialization"),
        ),
    ],

    # ── Spring Framework ─────────────────────────────────────────────────────
    "spring": [
        CveEntry(
            cve_id="CVE-2022-22965",
            description="Spring4Shell — Spring Framework RCE via data binding on JDK9+. "
                        "Unauthenticated code execution via ClassLoader manipulation.",
            cvss_v3=9.8, cvss_v2=7.5,
            cpe_prefix="spring",
            affected_range=(None, "5.3.18"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://spring.io/security/cve-2022-22965",),
            tags=("rce", "actively_exploited", "unauthenticated"),
        ),
        CveEntry(
            cve_id="CVE-2022-22963",
            description="Spring Cloud Function SpEL injection — SPEL expression in "
                        "routing function header leads to unauthenticated RCE.",
            cvss_v3=9.8, cvss_v2=7.5,
            cpe_prefix="spring",
            affected_versions=("3.1.6", "3.2.2"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://spring.io/security/cve-2022-22963",),
            tags=("rce", "spel_injection", "actively_exploited"),
        ),
        CveEntry(
            cve_id="CVE-2023-20860",
            description="Spring Security AuthorizationFilter double wildcard pattern "
                        "bypass allows unauthenticated access to protected endpoints.",
            cvss_v3=7.5, cvss_v2=5.0,
            cpe_prefix="spring",
            affected_range=(None, "6.0.2"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            exploit_available=True, patch_available=True,
            tags=("auth_bypass", "pattern_bypass"),
        ),
    ],

    # ── Log4j / Log4Shell ────────────────────────────────────────────────────
    "log4j": [
        CveEntry(
            cve_id="CVE-2021-44228",
            description="Log4Shell — Apache Log4j2 JNDI injection via user-controlled "
                        "log input enables unauthenticated RCE on any JVM application "
                        "logging untrusted data.",
            cvss_v3=10.0, cvss_v2=9.3,
            cpe_prefix="log4j",
            affected_range=("2.0-beta9", "2.14.1"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://logging.apache.org/log4j/2.x/security.html",),
            tags=("rce", "jndi_injection", "actively_exploited", "critical_internet_exposure"),
        ),
        CveEntry(
            cve_id="CVE-2021-45046",
            description="Log4j2 context lookup bypass — partial fix in 2.15.0 still "
                        "allows RCE via crafted input strings.",
            cvss_v3=9.0, cvss_v2=5.1,
            cpe_prefix="log4j",
            affected_versions=("2.15.0",),
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            tags=("rce", "jndi_injection", "bypass"),
        ),
    ],

    # ── Node.js ──────────────────────────────────────────────────────────────
    "node.js": [
        CveEntry(
            cve_id="CVE-2022-32213",
            description="Node.js HTTP request smuggling — improper handling of "
                        "OBS-fold in HTTP headers allows cache poisoning / bypass.",
            cvss_v3=6.5, cvss_v2=5.8,
            cpe_prefix="node.js",
            affected_range=(None, "18.5.0"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            exploit_available=False, patch_available=True,
            tags=("http_request_smuggling"),
        ),
        CveEntry(
            cve_id="CVE-2023-30581",
            description="Node.js mainModule proto pollution leads to privilege escalation "
                        "via __proto__ injection in child_process.",
            cvss_v3=7.5, cvss_v2=5.0,
            cpe_prefix="node.js",
            affected_range=(None, "20.3.1"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
            exploit_available=False, patch_available=True,
            tags=("prototype_pollution", "privesc"),
        ),
    ],

    # ── OpenSSL ──────────────────────────────────────────────────────────────
    "openssl": [
        CveEntry(
            cve_id="CVE-2022-0778",
            description="OpenSSL BN_mod_sqrt infinite loop — crafted certificate with "
                        "invalid elliptic curve parameter causes denial of service.",
            cvss_v3=7.5, cvss_v2=5.0,
            cpe_prefix="openssl",
            affected_range=(None, "3.0.2"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            exploit_available=False, patch_available=True,
            references=("https://www.openssl.org/news/secadv/20220315.txt",),
            tags=("dos", "cert_parsing"),
        ),
        CveEntry(
            cve_id="CVE-2022-3602",
            description="OpenSSL X.509 email address punycode buffer overflow — "
                        "4-byte overflow in name constraint checking (High, not Critical).",
            cvss_v3=7.5, cvss_v2=6.8,
            cpe_prefix="openssl",
            affected_range=("3.0.0", "3.0.6"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            exploit_available=False, patch_available=True,
            references=("https://www.openssl.org/news/secadv/20221101.txt",),
            tags=("buffer_overflow", "dos"),
        ),
        CveEntry(
            cve_id="CVE-2014-0160",
            description="Heartbleed — OpenSSL TLS heartbeat extension read overrun "
                        "leaks up to 64KB of server process memory per request.",
            cvss_v3=7.5, cvss_v2=5.0,
            cpe_prefix="openssl",
            affected_range=("1.0.1", "1.0.1f"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            exploit_available=True, patch_available=True,
            references=("https://heartbleed.com/",),
            tags=("info_disclosure", "heartbleed", "actively_exploited"),
        ),
    ],

    # ── Microsoft IIS ────────────────────────────────────────────────────────
    "iis": [
        CveEntry(
            cve_id="CVE-2017-7269",
            description="IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow — "
                        "unauthenticated remote code execution via crafted IF header.",
            cvss_v3=9.8, cvss_v2=10.0,
            cpe_prefix="iis",
            affected_versions=("6.0",),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=False,
            references=("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7269",),
            tags=("rce", "webdav", "buffer_overflow", "eol"),
        ),
        CveEntry(
            cve_id="CVE-2022-21907",
            description="IIS HTTP Protocol Stack RCE — wormable unauthenticated remote "
                        "code execution via HTTP trailer support.",
            cvss_v3=9.8, cvss_v2=10.0,
            cpe_prefix="iis",
            affected_range=(None, "10.0.19041.1466"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21907",),
            tags=("rce", "wormable", "unauthenticated"),
        ),
    ],

    # ── OpenSSH ─────────────────────────────────────────────────────────────
    "ssh": [
        CveEntry(
            cve_id="CVE-2023-38408",
            description="OpenSSH ssh-agent PKCS#11 provider RCE — malicious PKCS#11 "
                        "provider can be loaded by a forwarded agent, leading to RCE.",
            cvss_v3=9.8, cvss_v2=10.0,
            cpe_prefix="ssh",
            affected_range=(None, "9.3p2"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://www.openssh.com/security.html",),
            tags=("rce", "ssh_agent"),
        ),
        CveEntry(
            cve_id="CVE-2024-6387",
            description="regreSSHion — OpenSSH server race condition in signal handler "
                        "allows unauthenticated RCE as root on glibc-based Linux.",
            cvss_v3=8.1, cvss_v2=7.6,
            cpe_prefix="ssh",
            affected_range=("8.5p1", "9.8p1"),
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt",),
            tags=("rce", "race_condition", "unauthenticated", "actively_exploited"),
        ),
        CveEntry(
            cve_id="CVE-2016-0777",
            description="OpenSSH roaming feature information leak — client-side memory "
                        "disclosure of private keys via UseRoaming.",
            cvss_v3=6.5, cvss_v2=4.0,
            cpe_prefix="ssh",
            affected_range=(None, "7.1p2"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            exploit_available=False, patch_available=True,
            tags=("info_disclosure", "key_leak"),
        ),
    ],

    # ── Redis ────────────────────────────────────────────────────────────────
    "redis": [
        CveEntry(
            cve_id="CVE-2022-0543",
            description="Redis Lua sandbox escape — Debian/Ubuntu packaging flaw "
                        "leaks package library into Lua environment, enabling RCE.",
            cvss_v3=10.0, cvss_v2=10.0,
            cpe_prefix="redis",
            affected_range=(None, "6.0.16"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0543",),
            tags=("rce", "sandbox_escape", "actively_exploited"),
        ),
        CveEntry(
            cve_id="CVE-2023-28856",
            description="Redis SINTERCARD integer overflow causes assertion and crash "
                        "via specifically crafted command.",
            cvss_v3=6.5, cvss_v2=4.0,
            cpe_prefix="redis",
            affected_range=(None, "7.0.11"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
            exploit_available=False, patch_available=True,
            tags=("dos", "integer_overflow"),
        ),
    ],

    # ── MongoDB ──────────────────────────────────────────────────────────────
    "mongodb": [
        CveEntry(
            cve_id="CVE-2021-20328",
            description="MongoDB client-side field level encryption bypass — "
                        "improper validation allows server to read plaintext.",
            cvss_v3=6.8, cvss_v2=4.0,
            cpe_prefix="mongodb",
            affected_range=(None, "4.4.4"),
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            exploit_available=False, patch_available=True,
            tags=("crypto_bypass", "info_disclosure"),
        ),
    ],

    # ── SMB (port 445) ───────────────────────────────────────────────────────
    "smb": [
        CveEntry(
            cve_id="CVE-2017-0144",
            description="EternalBlue — Windows SMBv1 buffer overflow in "
                        "transaction handling allows unauthenticated remote code execution.",
            cvss_v3=8.1, cvss_v2=9.3,
            cpe_prefix="smb",
            affected_versions=("SMBv1",),
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",),
            tags=("rce", "wormable", "actively_exploited", "nsa_exploit"),
        ),
        CveEntry(
            cve_id="CVE-2020-0796",
            description="SMBGhost — Windows SMBv3 compression buffer overflow "
                        "allows unauthenticated RCE / local privilege escalation.",
            cvss_v3=10.0, cvss_v2=10.0,
            cpe_prefix="smb",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796",),
            tags=("rce", "wormable", "actively_exploited"),
        ),
    ],

    # ── RDP ─────────────────────────────────────────────────────────────────
    "rdp": [
        CveEntry(
            cve_id="CVE-2019-0708",
            description="BlueKeep — Windows Remote Desktop Services pre-auth use-after-free "
                        "allows unauthenticated wormable RCE.",
            cvss_v3=9.8, cvss_v2=10.0,
            cpe_prefix="rdp",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708",),
            tags=("rce", "wormable", "unauthenticated", "actively_exploited"),
        ),
        CveEntry(
            cve_id="CVE-2019-1181",
            description="DejaBlue — RDP pre-authentication buffer overflow "
                        "in Windows Remote Desktop Services (wormable).",
            cvss_v3=9.8, cvss_v2=10.0,
            cpe_prefix="rdp",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            tags=("rce", "wormable", "unauthenticated"),
        ),
    ],

    # ── Elasticsearch ────────────────────────────────────────────────────────
    "elasticsearch": [
        CveEntry(
            cve_id="CVE-2021-22145",
            description="Elasticsearch information disclosure via sensitive data "
                        "in logs when memory allocation errors occur.",
            cvss_v3=6.5, cvss_v2=4.0,
            cpe_prefix="elasticsearch",
            affected_range=(None, "7.13.4"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            exploit_available=False, patch_available=True,
            tags=("info_disclosure"),
        ),
        CveEntry(
            cve_id="CVE-2014-3120",
            description="Elasticsearch dynamic scripting RCE — default Groovy/MVEL "
                        "script execution without auth allows arbitrary OS commands.",
            cvss_v3=9.8, cvss_v2=7.5,
            cpe_prefix="elasticsearch",
            affected_range=(None, "1.6.0"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            tags=("rce", "default_config", "unauthenticated"),
        ),
    ],

    # ── FTP (port 21) ────────────────────────────────────────────────────────
    "ftp": [
        CveEntry(
            cve_id="CVE-2011-2523",
            description="vsftpd 2.3.4 backdoor — trojanized source tarball installs "
                        "a bindshell on TCP/6200 triggered by :) in username.",
            cvss_v3=9.8, cvss_v2=10.0,
            cpe_prefix="ftp",
            affected_versions=("2.3.4",),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            references=("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523",),
            tags=("rce", "backdoor"),
        ),
    ],

    # ── MySQL ────────────────────────────────────────────────────────────────
    "mysql": [
        CveEntry(
            cve_id="CVE-2016-6662",
            description="MySQL 5.x remote root exploit — mysql config injection via "
                        "SELECT INTO OUTFILE allows privilege escalation to root.",
            cvss_v3=9.8, cvss_v2=10.0,
            cpe_prefix="mysql",
            affected_range=(None, "5.7.15"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            tags=("rce", "privesc", "sqli_chained"),
        ),
        CveEntry(
            cve_id="CVE-2023-21980",
            description="MySQL Server vulnerability in the Client programs component — "
                        "allows unauthenticated remote attacker to compromise MySQL Server.",
            cvss_v3=7.6, cvss_v2=4.9,
            cpe_prefix="mysql",
            affected_range=(None, "8.0.33"),
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
            exploit_available=False, patch_available=True,
            tags=("rce"),
        ),
    ],

    # ── Joomla ───────────────────────────────────────────────────────────────
    "joomla": [
        CveEntry(
            cve_id="CVE-2023-23752",
            description="Joomla improper access check allows unauthenticated read of "
                        "web service endpoints exposing config including DB credentials.",
            cvss_v3=7.5, cvss_v2=5.0,
            cpe_prefix="joomla",
            affected_range=("4.0.0", "4.2.7"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            exploit_available=True, patch_available=True,
            references=("https://developer.joomla.org/security-centre/894-20230201-core-improper-access-check.html",),
            tags=("info_disclosure", "config_leak", "actively_exploited"),
        ),
        CveEntry(
            cve_id="CVE-2015-8562",
            description="Joomla PHP object injection via HTTP User-Agent / X-Forwarded-For "
                        "header — unauthenticated RCE.",
            cvss_v3=9.8, cvss_v2=7.5,
            cpe_prefix="joomla",
            affected_range=(None, "3.4.6"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            tags=("rce", "deserialization", "unauthenticated"),
        ),
    ],

    # ── Magento ──────────────────────────────────────────────────────────────
    "magento": [
        CveEntry(
            cve_id="CVE-2022-24086",
            description="Adobe Commerce / Magento SQL injection via improper input "
                        "validation in checkout allows unauthenticated RCE.",
            cvss_v3=9.8, cvss_v2=7.5,
            cpe_prefix="magento",
            affected_range=(None, "2.4.3-p2"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True, patch_available=True,
            tags=("rce", "sqli", "unauthenticated", "actively_exploited"),
        ),
    ],

    # ── SSL/TLS surface CVEs (matched via ssl_scan vulnerabilities keys) ─────
    "heartbleed": [
        CveEntry(
            cve_id="CVE-2014-0160",
            description="Heartbleed — OpenSSL TLS heartbeat extension read overrun "
                        "leaks up to 64KB of server process memory per request.",
            cvss_v3=7.5, cvss_v2=5.0,
            cpe_prefix="openssl",
            affected_range=("1.0.1", "1.0.1f"),
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            exploit_available=True, patch_available=True,
            tags=("info_disclosure", "heartbleed"),
        ),
    ],
    "poodle": [
        CveEntry(
            cve_id="CVE-2014-3566",
            description="POODLE — SSLv3 CBC padding oracle allows MITM attacker to "
                        "decrypt HTTPS cookies with ~256 requests per byte.",
            cvss_v3=3.4, cvss_v2=4.3,
            cpe_prefix="openssl",
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N",
            exploit_available=True, patch_available=True,
            tags=("crypto_attack", "mitm"),
        ),
    ],
    "beast": [
        CveEntry(
            cve_id="CVE-2011-3389",
            description="BEAST — TLS 1.0 CBC chosen-plaintext attack allows MITM "
                        "to decrypt session cookies via predictable IV.",
            cvss_v3=5.9, cvss_v2=4.3,
            cpe_prefix="openssl",
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
            exploit_available=True, patch_available=True,
            tags=("crypto_attack", "mitm"),
        ),
    ],
    "sweet32": [
        CveEntry(
            cve_id="CVE-2016-2183",
            description="SWEET32 — 64-bit block cipher birthday attack (3DES/Blowfish) "
                        "allows MITM to recover plaintext after ~785GB of traffic.",
            cvss_v3=7.5, cvss_v2=5.0,
            cpe_prefix="openssl",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            exploit_available=False, patch_available=True,
            tags=("crypto_attack", "mitm"),
        ),
    ],
    "logjam": [
        CveEntry(
            cve_id="CVE-2015-4000",
            description="Logjam — TLS DHE key exchange downgrade to 512-bit export "
                        "allows MITM decryption (FREAK/Logjam).",
            cvss_v3=3.7, cvss_v2=4.3,
            cpe_prefix="openssl",
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            exploit_available=True, patch_available=True,
            tags=("crypto_attack", "mitm", "downgrade"),
        ),
    ],
    "freak": [
        CveEntry(
            cve_id="CVE-2015-0204",
            description="FREAK — OpenSSL accepts EXPORT_RSA cipher suites allowing "
                        "MITM to force downgrade and factor the weak key.",
            cvss_v3=3.7, cvss_v2=4.3,
            cpe_prefix="openssl",
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            exploit_available=True, patch_available=True,
            tags=("crypto_attack", "mitm", "downgrade"),
        ),
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Version comparison helpers
# ─────────────────────────────────────────────────────────────────────────────

class _VersionParser:
    """
    Parses dotted semver strings into comparable integer tuples.
    Handles: "1.2.3", "2.4.49", "8.0-beta9", "3.4.6", "10.0.19041.1466"
    Returns (0,) on unparseable input so comparisons degrade gracefully.
    """

    _CLEAN = re.compile(r'[^0-9.]')

    @classmethod
    def parse(cls, v: str) -> Tuple[int, ...]:
        if not v:
            return (0,)
        cleaned = cls._CLEAN.sub("", v.split("-")[0].split("p")[0])
        try:
            return tuple(int(x) for x in cleaned.split(".") if x)
        except ValueError:
            return (0,)

    @classmethod
    def in_range(
        cls,
        version: str,
        lo: Optional[str],
        hi: Optional[str],
    ) -> bool:
        """Return True if lo <= version <= hi (None = unbounded)."""
        v   = cls.parse(version)
        if lo:
            if v < cls.parse(lo):
                return False
        if hi:
            if v > cls.parse(hi):
                return False
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Match result data structure
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CveMatch:
    match_id:       str
    cve_id:         str
    description:    str
    cvss_v3:        float
    cvss_v2:        float
    rating:         str
    confidence:     MatchConfidence
    matched_tech:   str
    detected_version: Optional[str]
    affected_versions: List[str]
    affected_range: Optional[Tuple[Optional[str], Optional[str]]]
    vector_string:  str
    exploit_available: bool
    patch_available:   bool
    references:     List[str]
    tags:           List[str]
    source:         str       # "tech_detection" | "port_scan" | "ssl_scan"
    target_url:     str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "match_id":          self.match_id,
            "cve_id":            self.cve_id,
            "description":       self.description,
            "cvss_v3":           self.cvss_v3,
            "cvss_v2":           self.cvss_v2,
            "rating":            self.rating,
            "confidence":        self.confidence.value,
            "matched_tech":      self.matched_tech,
            "detected_version":  self.detected_version,
            "affected_versions": self.affected_versions,
            "affected_range":    list(self.affected_range) if self.affected_range else None,
            "vector_string":     self.vector_string,
            "exploit_available": self.exploit_available,
            "patch_available":   self.patch_available,
            "references":        self.references,
            "tags":              self.tags,
            "source":            self.source,
            "target_url":        self.target_url,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Source readers — extract (tech_name, version, url) tuples from scan_results
# ─────────────────────────────────────────────────────────────────────────────

class _TechReader:
    """
    Reads scan_results['tech_detection'] — Wappalyzer output from tech_detector.py.
    Schema: {url: {'technologies': [{'name', 'version', 'category', ...}]}}
    """

    def read(self, scan_results: Dict[str, Any]) -> List[Tuple[str, Optional[str], str]]:
        out: List[Tuple[str, Optional[str], str]] = []
        for url, data in scan_results.get("tech_detection", {}).items():
            for tech in data.get("technologies", []):
                name    = (tech.get("name") or "").lower().strip()
                version = tech.get("version") or None
                if name:
                    out.append((name, version, url))
        return out


class _PortReader:
    """
    Reads scan_results['port_scan'] — PortScanner.batch_scan() output.
    Schema: [{'target', 'ports': [{'port', 'service', 'version', ...}]}]
    Maps service name → CVE DB key and port number → well-known keys.
    """

    # port → canonical key in _CVE_DB
    _PORT_KEY: Dict[int, str] = {
        21:    "ftp",
        22:    "ssh",
        25:    "smtp",
        80:    "apache",   # fallback — overridden by service name if present
        443:   "openssl",
        445:   "smb",
        3306:  "mysql",
        3389:  "rdp",
        5432:  "postgresql",
        6379:  "redis",
        8080:  "apache",
        9200:  "elasticsearch",
        27017: "mongodb",
    }

    # service string → CVE DB key
    _SVC_KEY: Dict[str, str] = {
        "ssh":           "ssh",
        "ftp":           "ftp",
        "sftp":          "ftp",
        "smtp":          "smtp",
        "smb":           "smb",
        "microsoft-ds":  "smb",
        "netbios-ssn":   "smb",
        "mysql":         "mysql",
        "rdp":           "rdp",
        "ms-rdp":        "rdp",
        "redis":         "redis",
        "elasticsearch": "elasticsearch",
        "mongodb":       "mongodb",
        "postgresql":    "postgresql",
        "http":          "apache",
        "https":         "openssl",
        "http-alt":      "apache",
        "ms-sql-s":      "mssql",
    }

    def read(self, scan_results: Dict[str, Any]) -> List[Tuple[str, Optional[str], str]]:
        out: List[Tuple[str, Optional[str], str]] = []
        for host_result in scan_results.get("port_scan", []):
            target = host_result.get("target", "")
            for p in host_result.get("ports", []):
                port    = p.get("port", 0)
                service = (p.get("service") or "").lower().strip()
                version = p.get("version") or None

                key: Optional[str] = None
                if service and service in self._SVC_KEY:
                    key = self._SVC_KEY[service]
                elif port in self._PORT_KEY:
                    key = self._PORT_KEY[port]

                if key:
                    out.append((key, version, f"{target}:{port}"))

        return out


class _SslReader:
    """
    Reads scan_results['ssl_scan'] — SSLScanner output.
    Maps _check_vulnerabilities() bool flags → CVE DB SSL keys.
    Also pulls OpenSSL version from TLS fingerprint where present.
    """

    # ssl vuln key → CVE DB key (all defined in _CVE_DB above)
    _SSL_VULN_KEY: Dict[str, str] = {
        "heartbleed": "heartbleed",
        "poodle":     "poodle",
        "beast":      "beast",
        "sweet32":    "sweet32",
        "logjam":     "logjam",
        "freak":      "freak",
    }

    def read(self, scan_results: Dict[str, Any]) -> List[Tuple[str, Optional[str], str]]:
        out: List[Tuple[str, Optional[str], str]] = []
        for host, ssl_data in scan_results.get("ssl_scan", {}).items():
            if not isinstance(ssl_data, dict):
                continue
            vulns = ssl_data.get("vulnerabilities", {})
            for vuln_key, cve_key in self._SSL_VULN_KEY.items():
                if vulns.get(vuln_key):
                    out.append((cve_key, None, host))

            # OpenSSL version from TLS fingerprint
            fp = ssl_data.get("tls_fingerprint", {})
            openssl_ver = fp.get("openssl_version") or None
            if openssl_ver:
                out.append(("openssl", openssl_ver, host))

        return out


# ─────────────────────────────────────────────────────────────────────────────
# Matcher — tech tuples → CveMatch list
# ─────────────────────────────────────────────────────────────────────────────

class _CveMatcher:
    """
    For each (tech_key, version, url) tuple, walks _CVE_DB:
    1. Exact tech name match (or substring)
    2. Version check:
       - If version present + affected_versions list: exact match → CONFIRMED
       - If version present + affected_range: range check → CONFIRMED
       - If version present but not in range → skip
       - If no version: → LIKELY (name match only)
    3. SSL/context matches → CONTEXTUAL
    """

    def match(
        self,
        tech_tuples: List[Tuple[str, Optional[str], str]],
        source: str,
    ) -> List[CveMatch]:
        matches: List[CveMatch] = []
        seen_pairs: Set[Tuple[str, str]] = set()   # (cve_id, url) dedup

        for tech_key, version, url in tech_tuples:
            for db_key, entries in _CVE_DB.items():
                if not self._key_matches(tech_key, db_key):
                    continue
                for entry in entries:
                    dedup_key = (entry.cve_id, url)
                    if dedup_key in seen_pairs:
                        continue
                    conf = self._confidence(version, entry)
                    if conf is None:
                        continue   # version present + definitively not affected
                    seen_pairs.add(dedup_key)
                    matches.append(CveMatch(
                        match_id          = str(uuid.uuid4()),
                        cve_id            = entry.cve_id,
                        description       = entry.description,
                        cvss_v3           = entry.cvss_v3,
                        cvss_v2           = entry.cvss_v2,
                        rating            = entry.rating.value,
                        confidence        = conf,
                        matched_tech      = tech_key,
                        detected_version  = version,
                        affected_versions = list(entry.affected_versions),
                        affected_range    = entry.affected_range,
                        vector_string     = entry.vector_string,
                        exploit_available = entry.exploit_available,
                        patch_available   = entry.patch_available,
                        references        = list(entry.references),
                        tags              = list(entry.tags),
                        source            = source,
                        target_url        = url,
                    ))

        return matches

    @staticmethod
    def _key_matches(tech_key: str, db_key: str) -> bool:
        return tech_key == db_key or db_key in tech_key or tech_key in db_key

    @staticmethod
    def _confidence(
        version: Optional[str],
        entry:   CveEntry,
    ) -> Optional[MatchConfidence]:
        """
        Returns:
          CONFIRMED  — version exactly within affected scope
          LIKELY     — no version info available
          POSSIBLE   — tech matched, version present but outside known affected range
          None       — version present and definitively not affected
        """
        if version is None:
            return MatchConfidence.LIKELY

        # exact version list check
        if entry.affected_versions:
            if version in entry.affected_versions:
                return MatchConfidence.CONFIRMED
            # version info present, not in explicit list — not affected
            return None

        # range check
        if entry.affected_range:
            lo, hi = entry.affected_range
            if _VersionParser.in_range(version, lo, hi):
                return MatchConfidence.CONFIRMED
            return None   # definitively out of range

        # CVE has no version constraints — always LIKELY with version present
        return MatchConfidence.LIKELY


# ─────────────────────────────────────────────────────────────────────────────
# CVSS scorer
# ─────────────────────────────────────────────────────────────────────────────

class _CvssScorer:
    """
    Aggregates a list of CveMatch into a single risk score (0-100) and label.
    Weights: CONFIRMED > LIKELY > POSSIBLE > CONTEXTUAL.
    Exploit-available bonus applied.
    """

    _CONF_WEIGHT: Dict[MatchConfidence, float] = {
        MatchConfidence.CONFIRMED:   1.00,
        MatchConfidence.LIKELY:      0.70,
        MatchConfidence.POSSIBLE:    0.45,
        MatchConfidence.CONTEXTUAL:  0.30,
    }

    def score(self, matches: List[CveMatch]) -> Tuple[float, str]:
        if not matches:
            return 0.0, "NONE"

        # weighted sum of CVSS scores
        total = 0.0
        for m in matches:
            w = self._CONF_WEIGHT.get(m.confidence, 0.5)
            bonus = 0.5 if m.exploit_available else 0.0
            total += (m.cvss_v3 + bonus) * w

        # normalise against a theoretical worst-case ceiling
        max_possible = len(matches) * (10.0 + 0.5) * 1.0
        score = min(100.0, (total / max_possible) * 100)

        label = (
            "CRITICAL" if score >= 80 else
            "HIGH"     if score >= 60 else
            "MEDIUM"   if score >= 40 else
            "LOW"      if score >= 20 else
            "INFO"
        )
        return round(score, 2), label


# ─────────────────────────────────────────────────────────────────────────────
# Recommendation builder
# ─────────────────────────────────────────────────────────────────────────────

class _RecommendationBuilder:
    """Maps tags on matched CVEs to prioritised patch/mitigate strings."""

    _TAG_RECS: Dict[str, str] = {
        "rce":                  "PATCH IMMEDIATELY — remote code execution confirmed on surface.",
        "actively_exploited":   "Exploit code is public and actively used in the wild.",
        "wormable":             "Vulnerability is wormable — isolate host from network.",
        "unauthenticated":      "No credentials required for exploitation — highest priority.",
        "sqli":                 "Parameterise all DB queries; audit ORM usage.",
        "lfi":                  "Canonicalise file paths; block traversal sequences.",
        "deserialization":      "Disable untrusted deserialisation; use allowlist for class loading.",
        "http_request_smuggling": "Normalise Transfer-Encoding; enforce strict HTTP parsing.",
        "info_disclosure":      "Redact version banners and error detail from responses.",
        "dos":                  "Rate-limit and resource-limit the affected endpoint.",
        "crypto_attack":        "Disable weak cipher suites and legacy TLS versions (≤1.1).",
        "mitm":                 "Enforce HSTS preload; disable SSLv3/TLS1.0/1.1.",
        "buffer_overflow":      "Update to patched version; enable memory-safe compiler flags.",
        "auth_bypass":          "Audit access control rules; test with role-escalation payloads.",
        "key_leak":             "Rotate all SSH keys and session tokens immediately.",
        "default_config":       "Harden default configuration before internet exposure.",
        "eol":                  "Software is end-of-life — migrate to supported version.",
        "privesc":              "Apply vendor patch; audit sudoers and SUID binaries.",
        "backdoor":             "Check for vsftpd 2.3.4 trojanised binary — verify checksum.",
    }

    def build(self, matches: List[CveMatch]) -> List[str]:
        seen_tags: Set[str] = set()
        recs: List[str] = []

        # Priority: CRITICAL first, then CONFIRMED, then exploit_available
        sorted_matches = sorted(
            matches,
            key=lambda m: (
                -CvssRating[m.rating].value,
                m.confidence != MatchConfidence.CONFIRMED,
                not m.exploit_available,
            ),
        )

        for m in sorted_matches:
            for tag in m.tags:
                if tag not in seen_tags and tag in self._TAG_RECS:
                    seen_tags.add(tag)
                    recs.append(
                        f"[{m.rating}][{m.cve_id}] {self._TAG_RECS[tag]}"
                    )

        return recs


# ─────────────────────────────────────────────────────────────────────────────
# Result container
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CveMatchResult:
    run_id:          str
    domain:          str
    total_matches:   int
    confirmed:       int
    likely:          int
    possible:        int
    critical_count:  int
    high_count:      int
    exploit_count:   int
    score:           float
    risk_level:      str
    matches:         List[Dict[str, Any]]
    recommendations: List[str]
    started_at:      datetime
    finished_at:     datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id":          self.run_id,
            "domain":          self.domain,
            "total_matches":   self.total_matches,
            "confirmed":       self.confirmed,
            "likely":          self.likely,
            "possible":        self.possible,
            "critical_count":  self.critical_count,
            "high_count":      self.high_count,
            "exploit_count":   self.exploit_count,
            "score":           self.score,
            "risk_level":      self.risk_level,
            "matches":         self.matches,
            "recommendations": self.recommendations,
            "started_at":      self.started_at.isoformat(),
            "finished_at":     self.finished_at.isoformat(),
            "duration_s":      round(
                (self.finished_at - self.started_at).total_seconds(), 3
            ),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Public API — drop-in ARTEX module
# ─────────────────────────────────────────────────────────────────────────────

class CveMatcher:
    """
    Drop-in ARTEX module.

    Usage in app.py (run_scan), after tech_detection + ssl_scan + port_scan:

        from core.cve_matcher import CveMatcher

        cvm = CveMatcher()
        scan_results[scan_id]['cve_matches'] = cvm.run(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    def __init__(self) -> None:
        self._tech_reader = _TechReader()
        self._port_reader = _PortReader()
        self._ssl_reader  = _SslReader()
        self._matcher     = _CveMatcher()
        self._scorer      = _CvssScorer()
        self._rec_builder = _RecommendationBuilder()

    # ── entry point ───────────────────────────────────────────────────────

    def run(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        run_id     = str(uuid.uuid4())
        started_at = datetime.now()
        logger.info("CveMatcher %s starting for %s", run_id, domain)

        # collect tech tuples from all three sources in parallel
        all_matches: List[CveMatch] = []
        lock = threading.Lock()

        def collect(reader_fn, source_label: str) -> None:
            tuples  = reader_fn(scan_results)
            matches = self._matcher.match(tuples, source_label)
            with lock:
                all_matches.extend(matches)

        threads = [
            threading.Thread(
                target=collect,
                args=(self._tech_reader.read, "tech_detection"),
            ),
            threading.Thread(
                target=collect,
                args=(self._port_reader.read, "port_scan"),
            ),
            threading.Thread(
                target=collect,
                args=(self._ssl_reader.read, "ssl_scan"),
            ),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # global dedup across sources — same CVE + URL should appear once
        all_matches = self._dedup(all_matches)

        # sort: CRITICAL first, CONFIRMED first within same severity
        all_matches.sort(key=lambda m: (
            -CvssRating[m.rating].value,
            m.confidence != MatchConfidence.CONFIRMED,
            not m.exploit_available,
        ))

        score, risk_level = self._scorer.score(all_matches)
        recs              = self._rec_builder.build(all_matches)

        finished_at = datetime.now()

        result = CveMatchResult(
            run_id          = run_id,
            domain          = domain,
            total_matches   = len(all_matches),
            confirmed       = sum(1 for m in all_matches if m.confidence == MatchConfidence.CONFIRMED),
            likely          = sum(1 for m in all_matches if m.confidence == MatchConfidence.LIKELY),
            possible        = sum(1 for m in all_matches if m.confidence == MatchConfidence.POSSIBLE),
            critical_count  = sum(1 for m in all_matches if m.rating == CvssRating.CRITICAL.value),
            high_count      = sum(1 for m in all_matches if m.rating == CvssRating.HIGH.value),
            exploit_count   = sum(1 for m in all_matches if m.exploit_available),
            score           = score,
            risk_level      = risk_level,
            matches         = [m.to_dict() for m in all_matches],
            recommendations = recs,
            started_at      = started_at,
            finished_at     = finished_at,
        )

        logger.info(
            "CveMatcher %s done — score=%.1f risk=%s matches=%d confirmed=%d exploit=%d",
            run_id, score, risk_level,
            result.total_matches, result.confirmed, result.exploit_count,
        )

        return result.to_dict()

    # ── dedup ─────────────────────────────────────────────────────────────

    @staticmethod
    def _dedup(matches: List[CveMatch]) -> List[CveMatch]:
        """
        For the same (cve_id, url) keep the highest-confidence match.
        Preference: CONFIRMED > LIKELY > POSSIBLE > CONTEXTUAL.
        """
        _CONF_ORDER = {
            MatchConfidence.CONFIRMED:  0,
            MatchConfidence.LIKELY:     1,
            MatchConfidence.POSSIBLE:   2,
            MatchConfidence.CONTEXTUAL: 3,
        }
        best: Dict[Tuple[str, str], CveMatch] = {}
        for m in matches:
            key = (m.cve_id, m.target_url)
            existing = best.get(key)
            if existing is None or _CONF_ORDER[m.confidence] < _CONF_ORDER[existing.confidence]:
                best[key] = m
        return list(best.values())

    # ── query helpers (optional, for template / reporting use) ────────────

    def by_rating(
        self,
        result:  Dict[str, Any],
        rating:  str,
    ) -> List[Dict[str, Any]]:
        return [m for m in result.get("matches", []) if m["rating"] == rating]

    def exploitable(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [m for m in result.get("matches", []) if m["exploit_available"]]

    def by_tag(
        self,
        result: Dict[str, Any],
        tag:    str,
    ) -> List[Dict[str, Any]]:
        return [m for m in result.get("matches", []) if tag in m.get("tags", [])]