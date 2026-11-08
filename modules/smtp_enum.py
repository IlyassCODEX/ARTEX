# modules/smtp_enum.py
import re
import os
import ssl
import time
import socket
import random
import string
import threading
import ipaddress
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Username wordlist
# ---------------------------------------------------------------------------

_USERNAMES: List[str] = [
    # Admin / system
    "admin", "administrator", "root", "postmaster", "hostmaster",
    "webmaster", "sysadmin", "netadmin", "noreply", "no-reply",
    "bounce", "mailer-daemon", "mailerdaemon", "daemon", "nobody",

    # Common personal
    "info", "contact", "support", "help", "helpdesk", "service",
    "sales", "marketing", "billing", "accounts", "finance", "legal",
    "hr", "recruitment", "jobs", "careers", "press", "media",
    "pr", "partnerships", "feedback", "complaints", "returns",

    # Technical
    "abuse", "security", "privacy", "dpo", "gdpr", "compliance",
    "devops", "dev", "developer", "api", "monitoring", "alerts",
    "notifications", "noc", "ops", "it", "tech",

    # First names (common)
    "john", "jane", "mike", "michael", "david", "james", "robert",
    "william", "richard", "charles", "joseph", "thomas", "daniel",
    "paul", "mark", "donald", "george", "kenneth", "steven",
    "edward", "brian", "ronald", "anthony", "kevin", "jason",
    "matthew", "gary", "timothy", "jose", "larry", "jeffrey",
    "frank", "scott", "eric", "stephen", "andrew", "raymond",
    "gregory", "joshua", "jerry", "dennis", "walter", "patrick",
    "peter", "harold", "douglas", "henry", "carl", "arthur",
    "ryan", "roger", "joe", "juan", "jack", "albert", "jonathan",
    "justin", "terry", "gerald", "keith", "samuel", "willie",
    "ralph", "lawrence", "nicholas", "roy", "benjamin", "bruce",
    "brandon", "adam", "harry", "fred", "wayne", "billy",
    "mary", "patricia", "linda", "barbara", "elizabeth", "jennifer",
    "maria", "susan", "margaret", "dorothy", "lisa", "nancy",
    "karen", "betty", "helen", "sandra", "donna", "carol",
    "ruth", "sharon", "michelle", "laura", "sarah", "kimberly",
    "deborah", "jessica", "shirley", "cynthia", "angela", "melissa",
    "brenda", "amy", "anna", "rebecca", "virginia", "kathleen",
    "pamela", "martha", "debra", "amanda", "stephanie", "carolyn",
    "christine", "marie", "janet", "catherine", "frances", "ann",
    "joyce", "diane", "alice", "julie", "heather", "teresa",

    # Pattern-based (firstname.lastname style)
    "j.smith", "j.doe", "john.doe", "john.smith",
    "m.johnson", "d.williams", "j.brown", "j.jones",

    # Short handles
    "jdoe", "jsmith", "mjohnson", "dwilliams",

    # Test / dummy
    "test", "test1", "test2", "demo", "user", "user1", "guest",
    "anonymous", "example",
]

# Common role-based additions per domain
_ROLE_ACCOUNTS = [
    "admin@{domain}", "postmaster@{domain}", "abuse@{domain}",
    "info@{domain}", "support@{domain}", "security@{domain}",
    "noreply@{domain}", "no-reply@{domain}", "webmaster@{domain}",
]

# ---------------------------------------------------------------------------
# SMTP response codes
# ---------------------------------------------------------------------------

# 2xx — positive completion
_SUCCESS_CODES = {
    200, 211, 214, 220, 221, 250, 251, 252,
}

# Codes that confirm user EXISTS
_USER_EXISTS_CODES = {250, 251, 252}

# Codes that confirm user DOES NOT EXIST
_USER_MISSING_CODES = {550, 551, 552, 553, 554, 555}

# Codes that mean the command is not implemented / access denied
_NOT_IMPLEMENTED = {500, 501, 502, 503, 504, 550, 553}

# Temporary failures — retry-able
_TEMP_FAIL_CODES = {421, 450, 451, 452}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SMTPBanner:
    raw:          str
    hostname:     Optional[str]
    software:     Optional[str]
    version:      Optional[str]
    extensions:   List[str]
    tls_available:bool
    auth_methods: List[str]
    vrfy_enabled: bool
    expn_enabled: bool
    size_limit:   Optional[int]


@dataclass
class SMTPUserResult:
    username:     str
    email:        str
    method:       str           # VRFY / EXPN / RCPT / MAIL
    exists:       bool
    response_code:int
    response_text:str
    confidence:   str           # confirmed / likely / possible / unknown


@dataclass
class SMTPFinding:
    host:         str
    port:         int
    severity:     str
    category:     str           # open_relay / vrfy_enabled / expn_enabled /
                                # user_enum / banner_disclosure / auth_plain /
                                # starttls_missing / catch_all
    title:        str
    detail:       str
    evidence:     str
    cwe:          str
    cvss:         float


@dataclass
class SMTPTarget:
    host:         str
    port:         int
    tls:          bool          # True = implicit TLS (SMTPS port 465)
    starttls:     bool          # True = STARTTLS upgrade on port 25/587


@dataclass
class ScanState:
    domain:       str
    targets:      List[SMTPTarget]
    banners:      Dict[str, SMTPBanner]       # "host:port" → banner
    user_results: List[SMTPUserResult]
    findings:     List[SMTPFinding]
    lock:         threading.Lock = field(default_factory=threading.Lock)


# ---------------------------------------------------------------------------
# Raw SMTP connection
# ---------------------------------------------------------------------------

class _SMTPConn:
    """
    Minimal synchronous SMTP client over raw socket / TLS.
    Handles EHLO, STARTTLS, VRFY, EXPN, MAIL FROM, RCPT TO, RSET.
    """

    def __init__(self, host: str, port: int,
                 tls: bool = False, timeout: float = 10.0):
        self._host    = host
        self._port    = port
        self._tls     = tls          # implicit TLS
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._buf     = b""
        self.connected = False

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> Tuple[int, str]:
        """Open connection and return (code, banner)."""
        raw = socket.create_connection(
            (self._host, self._port), timeout=self._timeout
        )
        if self._tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=self._host)
        raw.settimeout(self._timeout)
        self._sock    = raw
        self.connected = True
        return self._read_response()

    def starttls(self) -> Tuple[int, str]:
        """Upgrade an existing cleartext connection to TLS."""
        code, text = self.cmd("STARTTLS")
        if code == 220 and self._sock:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            self._sock = ctx.wrap_socket(
                self._sock, server_hostname=self._host
            )
            self._tls = True
        return code, text

    def close(self) -> None:
        if self._sock:
            try:
                self.cmd("QUIT")
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock    = None
            self.connected = False

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def _read_response(self) -> Tuple[int, str]:
        """
        Read one SMTP response (possibly multi-line).
        Returns (numeric_code, full_text).
        """
        if not self._sock:
            return 0, ""
        lines: List[str] = []
        try:
            while True:
                while b"\n" not in self._buf:
                    chunk = self._sock.recv(4096)
                    if not chunk:
                        break
                    self._buf += chunk
                if not self._buf:
                    break
                idx      = self._buf.find(b"\n")
                raw_line = self._buf[:idx + 1]
                self._buf = self._buf[idx + 1:]
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                lines.append(line)
                # Last line of response has "NNN " (space after code)
                # Continuation lines have "NNN-" (dash after code)
                if len(line) >= 4 and line[3] == " ":
                    break
        except socket.timeout:
            pass
        except OSError:
            pass

        if not lines:
            return 0, ""
        try:
            code = int(lines[0][:3])
        except (ValueError, IndexError):
            code = 0
        text = "\n".join(lines)
        return code, text

    def cmd(self, command: str) -> Tuple[int, str]:
        """Send one SMTP command and read the response."""
        if not self._sock:
            return 0, "not connected"
        try:
            self._sock.sendall((command + "\r\n").encode())
        except OSError:
            return 0, "send error"
        return self._read_response()

    # ------------------------------------------------------------------
    # SMTP protocol methods
    # ------------------------------------------------------------------

    def ehlo(self, domain: str = "artex.local") -> Tuple[int, str]:
        return self.cmd(f"EHLO {domain}")

    def helo(self, domain: str = "artex.local") -> Tuple[int, str]:
        return self.cmd(f"HELO {domain}")

    def vrfy(self, user: str) -> Tuple[int, str]:
        return self.cmd(f"VRFY {user}")

    def expn(self, list_name: str) -> Tuple[int, str]:
        return self.cmd(f"EXPN {list_name}")

    def mail_from(self, addr: str) -> Tuple[int, str]:
        return self.cmd(f"MAIL FROM:<{addr}>")

    def rcpt_to(self, addr: str) -> Tuple[int, str]:
        return self.cmd(f"RCPT TO:<{addr}>")

    def rset(self) -> Tuple[int, str]:
        return self.cmd("RSET")

    def noop(self) -> Tuple[int, str]:
        return self.cmd("NOOP")


# ---------------------------------------------------------------------------
# Banner parsing
# ---------------------------------------------------------------------------

_SW_PATTERNS: List[Tuple[str, str]] = [
    (r"Postfix",         "Postfix"),
    (r"Sendmail",        "Sendmail"),
    (r"Exim",            "Exim"),
    (r"Microsoft.*SMTP", "Microsoft Exchange"),
    (r"MailEnable",      "MailEnable"),
    (r"qmail",           "qmail"),
    (r"OpenSMTPD",       "OpenSMTPD"),
    (r"Haraka",          "Haraka"),
    (r"hMailServer",     "hMailServer"),
    (r"MailHog",         "MailHog"),
    (r"Zimbra",          "Zimbra"),
    (r"MDaemon",         "MDaemon"),
]

_VERSION_RE = re.compile(r"(\d+\.\d+[\.\d]*)")
_SIZE_RE    = re.compile(r"SIZE\s+(\d+)", re.I)


def _parse_banner(banner_text: str, ehlo_text: str) -> SMTPBanner:
    """Parse the SMTP greeting + EHLO response into typed SMTPBanner."""
    combined = banner_text + "\n" + ehlo_text

    # Hostname — first token after "220"
    hostname: Optional[str] = None
    m = re.search(r"^220\s+(\S+)", banner_text, re.M)
    if m:
        hostname = m.group(1)

    # Software + version
    software: Optional[str] = None
    version:  Optional[str] = None
    for pattern, name in _SW_PATTERNS:
        if re.search(pattern, combined, re.I):
            software = name
            vm = _VERSION_RE.search(combined)
            if vm:
                version = vm.group(1)
            break

    # Extensions from EHLO response
    extensions: List[str] = []
    for line in ehlo_text.splitlines():
        line = line.strip()
        if re.match(r"250[- ]", line):
            ext = line[4:].strip().upper()
            if ext:
                extensions.append(ext)

    # TLS / STARTTLS
    tls_available = any("STARTTLS" in e for e in extensions)

    # AUTH methods
    auth_methods: List[str] = []
    for ext in extensions:
        if ext.startswith("AUTH"):
            auth_methods = ext.replace("AUTH", "").strip().split()

    # Size limit
    size_limit: Optional[int] = None
    sm = _SIZE_RE.search(ehlo_text)
    if sm:
        size_limit = int(sm.group(1))

    # VRFY / EXPN — determined later after probing
    return SMTPBanner(
        raw=banner_text[:500],
        hostname=hostname,
        software=software,
        version=version,
        extensions=extensions,
        tls_available=tls_available,
        auth_methods=auth_methods,
        vrfy_enabled=False,
        expn_enabled=False,
        size_limit=size_limit,
    )


# ---------------------------------------------------------------------------
# SMTP target discovery
# ---------------------------------------------------------------------------

_SMTP_PORTS: List[Tuple[int, bool, bool]] = [
    # (port, implicit_tls, try_starttls)
    (25,   False, True),
    (587,  False, True),
    (465,  True,  False),
    (2525, False, True),
]


def _discover_smtp_targets(
    domain: str,
    timeout: float = 5.0,
) -> List[SMTPTarget]:
    """
    Discover SMTP servers for *domain* via MX DNS lookup
    and direct port probing on the domain itself.
    Returns list of reachable SMTPTarget objects.
    """
    targets: List[SMTPTarget] = []
    seen:    Set[str]         = set()

    # MX lookup via Google DNS-over-HTTPS (no dnspython dependency)
    mx_hosts: List[str] = []
    try:
        resp = requests.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": "MX"},
            timeout=8.0,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            for rec in (data.get("Answer") or []):
                if rec.get("type") == 15:   # MX record type
                    # Format: "10 mail.example.com."
                    parts = str(rec.get("data", "")).split()
                    if len(parts) >= 2:
                        mx_hosts.append(parts[1].rstrip("."))
    except Exception:
        pass

    # Also try the domain itself and common mail subdomains
    candidates = list(dict.fromkeys(
        mx_hosts + [
            domain,
            f"mail.{domain}",
            f"smtp.{domain}",
            f"mx.{domain}",
            f"mx1.{domain}",
            f"mx2.{domain}",
        ]
    ))

    def _probe_host_port(host: str, port: int,
                         tls: bool, starttls: bool) -> Optional[SMTPTarget]:
        key = f"{host}:{port}"
        if key in seen:
            return None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return SMTPTarget(host=host, port=port, tls=tls, starttls=starttls)
        except (socket.error, OSError):
            return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {
            ex.submit(_probe_host_port, host, port, tls, starttls): f"{host}:{port}"
            for host in candidates
            for port, tls, starttls in _SMTP_PORTS
        }
        for f in as_completed(futures):
            r = f.result()
            if r:
                key = f"{r.host}:{r.port}"
                if key not in seen:
                    seen.add(key)
                    targets.append(r)
                    print(f"  [smtp] found : {r.host}:{r.port} "
                          f"({'TLS' if r.tls else 'STARTTLS' if r.starttls else 'plain'})")

    return targets


# ---------------------------------------------------------------------------
# SMTP banner grab + capability probe
# ---------------------------------------------------------------------------

def _grab_banner(target: SMTPTarget, timeout: float) -> Optional[SMTPBanner]:
    """
    Connect, read banner, send EHLO, check VRFY/EXPN, return SMTPBanner.
    """
    conn = _SMTPConn(target.host, target.port, target.tls, timeout)
    try:
        code, banner_text = conn.connect()
        if code not in (220, 200):
            return None

        # EHLO
        ehlo_code, ehlo_text = conn.ehlo()
        if ehlo_code != 250:
            # Fallback to HELO
            conn.helo()
            ehlo_text = ""

        # Upgrade to STARTTLS if available
        if target.starttls and not target.tls and "STARTTLS" in ehlo_text.upper():
            st_code, _ = conn.starttls()
            if st_code == 220:
                ehlo_code, ehlo_text = conn.ehlo()

        banner = _parse_banner(banner_text, ehlo_text)

        # Test VRFY
        v_code, _ = conn.vrfy("postmaster")
        banner.vrfy_enabled = v_code not in _NOT_IMPLEMENTED and v_code not in {500, 502}

        # Test EXPN
        e_code, _ = conn.expn("postmaster")
        banner.expn_enabled = e_code not in _NOT_IMPLEMENTED and e_code not in {500, 502}

        return banner

    except Exception as exc:
        logger_debug(f"[smtp] banner grab {target.host}:{target.port}: {exc}")
        return None
    finally:
        conn.close()


def logger_debug(msg: str) -> None:
    import logging
    logging.getLogger(__name__).debug(msg)


# ---------------------------------------------------------------------------
# User enumeration methods
# ---------------------------------------------------------------------------

def _enum_vrfy(
    target: SMTPTarget,
    username: str,
    domain: str,
    timeout: float,
    rate_delay: float,
) -> Optional[SMTPUserResult]:
    """VRFY <username> — most direct method but often disabled."""
    if rate_delay > 0:
        time.sleep(rate_delay)

    email = f"{username}@{domain}"
    conn  = _SMTPConn(target.host, target.port, target.tls, timeout)
    try:
        code, _ = conn.connect()
        if code not in (220, 200):
            return None
        conn.ehlo()
        # Try both username and full email
        for probe in [username, email]:
            v_code, v_text = conn.vrfy(probe)
            if v_code in _USER_EXISTS_CODES:
                return SMTPUserResult(
                    username=username, email=email,
                    method="VRFY", exists=True,
                    response_code=v_code, response_text=v_text[:120],
                    confidence="confirmed",
                )
            if v_code in _USER_MISSING_CODES:
                return SMTPUserResult(
                    username=username, email=email,
                    method="VRFY", exists=False,
                    response_code=v_code, response_text=v_text[:120],
                    confidence="confirmed",
                )
    except Exception:
        pass
    finally:
        conn.close()

    return None


def _enum_expn(
    target: SMTPTarget,
    username: str,
    domain: str,
    timeout: float,
    rate_delay: float,
) -> Optional[SMTPUserResult]:
    """EXPN <listname> — reveals mailing list membership."""
    if rate_delay > 0:
        time.sleep(rate_delay)

    conn = _SMTPConn(target.host, target.port, target.tls, timeout)
    try:
        code, _ = conn.connect()
        if code not in (220, 200):
            return None
        conn.ehlo()
        e_code, e_text = conn.expn(username)
        exists = e_code in _USER_EXISTS_CODES
        if e_code in _USER_EXISTS_CODES | _USER_MISSING_CODES:
            return SMTPUserResult(
                username=username,
                email=f"{username}@{domain}",
                method="EXPN",
                exists=exists,
                response_code=e_code,
                response_text=e_text[:120],
                confidence="confirmed" if exists else "likely",
            )
    except Exception:
        pass
    finally:
        conn.close()

    return None


def _enum_rcpt(
    target: SMTPTarget,
    usernames: List[str],
    domain: str,
    sender: str,
    timeout: float,
    rate_delay: float,
) -> List[SMTPUserResult]:
    """
    MAIL FROM + RCPT TO batch — most reliable method, works even when VRFY
    is disabled. Sends multiple RCPT TO commands per connection to minimise
    connection overhead.
    """
    results: List[SMTPUserResult] = []
    if not usernames:
        return results

    conn = _SMTPConn(target.host, target.port, target.tls, timeout)
    try:
        code, _ = conn.connect()
        if code not in (220, 200):
            return results

        conn.ehlo()

        # Upgrade to STARTTLS if available
        if target.starttls and not target.tls:
            conn.starttls()
            conn.ehlo()

        # Open envelope
        mf_code, mf_text = conn.mail_from(sender)
        if mf_code not in {250, 251}:
            return results

        for username in usernames:
            if rate_delay > 0:
                time.sleep(rate_delay)

            email     = f"{username}@{domain}"
            rc_code, rc_text = conn.rcpt_to(email)

            exists     = rc_code in _USER_EXISTS_CODES
            not_exists = rc_code in _USER_MISSING_CODES

            if exists or not_exists:
                confidence = "confirmed" if rc_code in (250, 550) else "likely"
                results.append(SMTPUserResult(
                    username=username,
                    email=email,
                    method="RCPT",
                    exists=exists,
                    response_code=rc_code,
                    response_text=rc_text[:120],
                    confidence=confidence,
                ))

            # Reset envelope every 5 recipients to avoid greylisting
            if len(results) > 0 and len(results) % 5 == 0:
                conn.rset()
                mf_code, _ = conn.mail_from(sender)
                if mf_code not in {250, 251}:
                    break

    except Exception as exc:
        logger_debug(f"[smtp] RCPT enum {target.host}: {exc}")
    finally:
        conn.close()

    return results


def _enum_mail_from(
    target: SMTPTarget,
    username: str,
    domain: str,
    timeout: float,
    rate_delay: float,
) -> Optional[SMTPUserResult]:
    """
    Use MAIL FROM + RCPT TO with the probe address as sender.
    Some servers leak whether the sender address is valid via
    different response codes.
    """
    if rate_delay > 0:
        time.sleep(rate_delay)

    email = f"{username}@{domain}"
    conn  = _SMTPConn(target.host, target.port, target.tls, timeout)
    try:
        code, _ = conn.connect()
        if code not in (220, 200):
            return None
        conn.ehlo()
        mf_code, mf_text = conn.mail_from(email)
        if mf_code in _USER_EXISTS_CODES:
            return SMTPUserResult(
                username=username, email=email,
                method="MAIL",
                exists=True,
                response_code=mf_code,
                response_text=mf_text[:120],
                confidence="likely",
            )
        if mf_code in _USER_MISSING_CODES:
            return SMTPUserResult(
                username=username, email=email,
                method="MAIL",
                exists=False,
                response_code=mf_code,
                response_text=mf_text[:120],
                confidence="likely",
            )
    except Exception:
        pass
    finally:
        conn.close()

    return None


# ---------------------------------------------------------------------------
# Catch-all detection
# ---------------------------------------------------------------------------

def _detect_catch_all(
    target: SMTPTarget,
    domain: str,
    sender: str,
    timeout: float,
) -> bool:
    """
    Send RCPT TO with a guaranteed non-existent address.
    If the server accepts it, it has a catch-all configured —
    RCPT-based enumeration results are unreliable.
    """
    canary = f"artex_canary_{''.join(random.choices(string.ascii_lowercase, k=12))}"
    email  = f"{canary}@{domain}"
    conn   = _SMTPConn(target.host, target.port, target.tls, timeout)
    try:
        code, _ = conn.connect()
        if code not in (220, 200):
            return False
        conn.ehlo()
        mf_code, _ = conn.mail_from(sender)
        if mf_code not in {250, 251}:
            return False
        rc_code, _ = conn.rcpt_to(email)
        return rc_code in _USER_EXISTS_CODES
    except Exception:
        return False
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Open relay test
# ---------------------------------------------------------------------------

def _test_open_relay(
    target: SMTPTarget,
    domain: str,
    timeout: float,
) -> bool:
    """
    Attempt to relay a message from an external sender to an external recipient.
    A properly configured server should reject this with 5xx.
    """
    external_sender    = "test@example.com"
    external_recipient = "test@example.org"

    conn = _SMTPConn(target.host, target.port, target.tls, timeout)
    try:
        code, _ = conn.connect()
        if code not in (220, 200):
            return False
        conn.ehlo()
        mf_code, _ = conn.mail_from(external_sender)
        if mf_code not in {250, 251}:
            return False
        rc_code, _ = conn.rcpt_to(external_recipient)
        return rc_code in _USER_EXISTS_CODES
    except Exception:
        return False
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Finding synthesis
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _synthesise_findings(
    target: SMTPTarget,
    banner: Optional[SMTPBanner],
    user_results: List[SMTPUserResult],
    is_catch_all: bool,
    is_open_relay: bool,
) -> List[SMTPFinding]:
    findings: List[SMTPFinding] = []
    host_port = f"{target.host}:{target.port}"

    # Open relay — highest severity
    if is_open_relay:
        findings.append(SMTPFinding(
            host=target.host, port=target.port,
            severity="critical",
            category="open_relay",
            title="SMTP Open Relay Detected",
            detail=(
                f"{host_port} accepted relaying from external sender "
                f"'test@example.com' to external recipient 'test@example.org'. "
                f"The server can be used to send spam / phishing on behalf of anyone."
            ),
            evidence="RCPT TO:<test@example.org> returned 2xx with external MAIL FROM",
            cwe="CWE-359",
            cvss=9.8,
        ))

    if banner:
        # VRFY enabled
        if banner.vrfy_enabled:
            findings.append(SMTPFinding(
                host=target.host, port=target.port,
                severity="medium",
                category="vrfy_enabled",
                title="SMTP VRFY Command Enabled",
                detail=(
                    f"{host_port} responds to VRFY, allowing direct username "
                    f"enumeration without initiating a mail transaction."
                ),
                evidence="VRFY postmaster returned 2xx (not 502/500)",
                cwe="CWE-200",
                cvss=5.3,
            ))

        # EXPN enabled
        if banner.expn_enabled:
            findings.append(SMTPFinding(
                host=target.host, port=target.port,
                severity="medium",
                category="expn_enabled",
                title="SMTP EXPN Command Enabled",
                detail=(
                    f"{host_port} responds to EXPN, potentially revealing "
                    f"mailing list membership and hidden addresses."
                ),
                evidence="EXPN postmaster returned 2xx (not 502/500)",
                cwe="CWE-200",
                cvss=5.3,
            ))

        # Banner software disclosure
        if banner.software:
            findings.append(SMTPFinding(
                host=target.host, port=target.port,
                severity="info",
                category="banner_disclosure",
                title=f"SMTP Banner Discloses Software: {banner.software}",
                detail=(
                    f"The SMTP greeting reveals '{banner.software} {banner.version or ''}'. "
                    f"Version disclosure aids targeted exploit selection."
                ),
                evidence=f"220 banner: {banner.raw[:80]}",
                cwe="CWE-200",
                cvss=2.6,
            ))

        # Plaintext AUTH without TLS
        if banner.auth_methods and not banner.tls_available and not target.tls:
            plain_methods = [m for m in banner.auth_methods
                             if m in ("PLAIN", "LOGIN")]
            if plain_methods:
                findings.append(SMTPFinding(
                    host=target.host, port=target.port,
                    severity="high",
                    category="auth_plain",
                    title=f"SMTP Accepts Plaintext AUTH ({', '.join(plain_methods)}) Without TLS",
                    detail=(
                        f"{host_port} advertises AUTH {' '.join(plain_methods)} without STARTTLS. "
                        f"Credentials sent with these methods are transmitted in cleartext."
                    ),
                    evidence=f"AUTH methods: {banner.auth_methods} | STARTTLS: False",
                    cwe="CWE-319",
                    cvss=7.5,
                ))

        # STARTTLS not available on port 25/587
        if not banner.tls_available and not target.tls and target.port in (25, 587):
            findings.append(SMTPFinding(
                host=target.host, port=target.port,
                severity="medium",
                category="starttls_missing",
                title="SMTP STARTTLS Not Available",
                detail=(
                    f"{host_port} does not offer STARTTLS. "
                    f"All SMTP traffic is transmitted in cleartext, "
                    f"including credentials and message content."
                ),
                evidence="STARTTLS absent from EHLO extensions",
                cwe="CWE-319",
                cvss=5.9,
            ))

    # Catch-all configured
    if is_catch_all:
        findings.append(SMTPFinding(
            host=target.host, port=target.port,
            severity="info",
            category="catch_all",
            title="SMTP Catch-All Configured — RCPT Enumeration Unreliable",
            detail=(
                f"{host_port} accepted delivery for a randomly-generated address. "
                f"A catch-all is configured; RCPT TO user enumeration results "
                f"cannot be trusted for this target."
            ),
            evidence="RCPT TO:<artex_canary_*> returned 2xx",
            cwe="CWE-200",
            cvss=0.0,
        ))

    # Confirmed existing users
    confirmed = [r for r in user_results if r.exists and r.confidence == "confirmed"]
    if confirmed:
        email_list = ", ".join(r.email for r in confirmed[:10])
        findings.append(SMTPFinding(
            host=target.host, port=target.port,
            severity="high",
            category="user_enum",
            title=f"SMTP User Enumeration: {len(confirmed)} Confirmed Accounts",
            detail=(
                f"{len(confirmed)} valid email addresses confirmed on {host_port} "
                f"via {confirmed[0].method if confirmed else 'N/A'} enumeration. "
                f"These accounts can be targeted for password spray / phishing."
            ),
            evidence=f"Confirmed: {email_list}" + (" ..." if len(confirmed) > 10 else ""),
            cwe="CWE-200",
            cvss=5.3,
        ))

    findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 9))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SMTPEnumerator:
    """
    SMTP user enumeration and security analysis module.

    Five probing techniques per discovered SMTP server:
      VRFY    — direct username validation (RFC 821)
      EXPN    — mailing list expansion
      RCPT TO — envelope-based user validation (most reliable)
      MAIL FROM — sender address validation (supplementary)
      Catch-all — detects wildcard acceptance (invalidates RCPT results)

    Security checks performed:
      - Open relay detection
      - VRFY / EXPN enabled
      - Banner software / version disclosure
      - Plaintext AUTH without TLS
      - Missing STARTTLS on submission ports

    Usage in app.py:
        enum = SMTPEnumerator(domain=domain)
        results = enum.scan()
        scan_results[scan_id]['smtp_enum'] = results
    """

    def __init__(
        self,
        domain: str,
        usernames: Optional[List[str]] = None,
        sender_domain: str = "artex-scanner.local",
        timeout: float = 10.0,
        max_workers: int = 15,
        rate_delay: float = 0.1,
        proxy: Optional[str] = None,
        skip_rcpt: bool = False,
        skip_vrfy: bool = False,
        skip_relay_test: bool = False,
    ):
        self.domain          = domain
        self.usernames       = usernames or _USERNAMES
        self.sender_domain   = sender_domain
        self.sender          = f"probe@{sender_domain}"
        self.timeout         = timeout
        self.max_workers     = max_workers
        self.rate_delay      = rate_delay
        self.proxy           = proxy
        self.skip_rcpt       = skip_rcpt
        self.skip_vrfy       = skip_vrfy
        self.skip_relay_test = skip_relay_test

    # ------------------------------------------------------------------
    # Public scan
    # ------------------------------------------------------------------

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        import time as _time
        t0 = _time.monotonic()

        print(f"[smtp] domain    : {self.domain}")
        print(f"[smtp] usernames : {len(self.usernames)}")

        state = ScanState(
            domain=self.domain,
            targets=[],
            banners={},
            user_results=[],
            findings=[],
        )

        # ── Target discovery ───────────────────────────────────────────────
        print(f"[smtp] phase 1: target discovery")
        state.targets = _discover_smtp_targets(self.domain, self.timeout)
        if not state.targets:
            print(f"[smtp] no SMTP servers found for {self.domain}")
            return {
                "domain":         self.domain,
                "servers_found":  0,
                "users_confirmed":0,
                "total_findings": 0,
                "findings":       [],
                "users":          [],
                "elapsed_seconds":round(_time.monotonic() - t0, 2),
            }
        print(f"[smtp] found {len(state.targets)} SMTP target(s)")

        for target in state.targets:
            host_port = f"{target.host}:{target.port}"
            print(f"[smtp] probing : {host_port}")

            # ── Banner grab ────────────────────────────────────────────────
            banner = _grab_banner(target, self.timeout)
            if banner:
                state.banners[host_port] = banner
                print(
                    f"  [smtp] software={banner.software or '?'} "
                    f"tls={banner.tls_available} "
                    f"vrfy={banner.vrfy_enabled} "
                    f"expn={banner.expn_enabled} "
                    f"auth={banner.auth_methods}"
                )

            # ── Catch-all detection ────────────────────────────────────────
            is_catch_all = _detect_catch_all(
                target, self.domain, self.sender, self.timeout
            )
            if is_catch_all:
                print(f"  [smtp] catch-all DETECTED — RCPT results unreliable")

            # ── Open relay test ────────────────────────────────────────────
            is_open_relay = False
            if not self.skip_relay_test:
                is_open_relay = _test_open_relay(target, self.domain, self.timeout)
                if is_open_relay:
                    print(f"  [smtp] OPEN RELAY DETECTED")

            # ── User enumeration ───────────────────────────────────────────
            target_results: List[SMTPUserResult] = []

            # VRFY
            if not self.skip_vrfy and banner and banner.vrfy_enabled:
                print(f"  [smtp] VRFY enumeration ({len(self.usernames)} users)")
                with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                    futures = {
                        ex.submit(
                            _enum_vrfy, target, u, self.domain,
                            self.timeout, self.rate_delay
                        ): u
                        for u in self.usernames
                    }
                    for f in as_completed(futures):
                        r = f.result()
                        if r and r.exists:
                            target_results.append(r)
                            print(f"    [smtp] VRFY [{r.response_code}] {r.email}")

            # EXPN
            if banner and banner.expn_enabled:
                print(f"  [smtp] EXPN enumeration")
                with ThreadPoolExecutor(max_workers=5) as ex:
                    futures = {
                        ex.submit(
                            _enum_expn, target, u, self.domain,
                            self.timeout, self.rate_delay
                        ): u
                        for u in self.usernames[:30]  # EXPN is slow — limit
                    }
                    for f in as_completed(futures):
                        r = f.result()
                        if r and r.exists:
                            target_results.append(r)
                            print(f"    [smtp] EXPN [{r.response_code}] {r.email}")

            # RCPT TO (batch per connection)
            if not self.skip_rcpt and not is_catch_all:
                print(f"  [smtp] RCPT TO enumeration ({len(self.usernames)} users)")
                # Split into batches of 10 (one TCP connection per batch)
                batch_size = 10
                batches = [
                    self.usernames[i:i+batch_size]
                    for i in range(0, len(self.usernames), batch_size)
                ]
                with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                    futures = [
                        ex.submit(
                            _enum_rcpt, target, batch, self.domain,
                            self.sender, self.timeout, self.rate_delay
                        )
                        for batch in batches
                    ]
                    for f in as_completed(futures):
                        batch_results = f.result()
                        for r in batch_results:
                            if r.exists:
                                target_results.append(r)
                                print(f"    [smtp] RCPT [{r.response_code}] {r.email}")

            # Deduplicate results by email
            seen_emails: Set[str] = set()
            unique_results: List[SMTPUserResult] = []
            for r in target_results:
                if r.email not in seen_emails:
                    seen_emails.add(r.email)
                    unique_results.append(r)

            state.user_results.extend(unique_results)

            # ── Finding synthesis ──────────────────────────────────────────
            target_findings = _synthesise_findings(
                target, banner, unique_results,
                is_catch_all, is_open_relay,
            )
            state.findings.extend(target_findings)
            for f in target_findings:
                if _SEV_ORDER.get(f.severity, 9) <= 1:
                    print(f"  [smtp] [{f.severity.upper()}] {f.title}")

        # ── Summary ────────────────────────────────────────────────────────
        confirmed    = [r for r in state.user_results if r.exists and r.confidence == "confirmed"]
        sev_counts: Dict[str, int] = {}
        for f in state.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        elapsed = _time.monotonic() - t0
        print(
            f"[smtp] done | "
            f"servers={len(state.targets)} "
            f"users_confirmed={len(confirmed)} "
            f"findings={len(state.findings)} "
            f"elapsed={elapsed:.1f}s"
        )

        return {
            "domain":           self.domain,
            "servers_found":    len(state.targets),
            "users_tested":     len(self.usernames),
            "users_confirmed":  len(confirmed),
            "severity_summary": sev_counts,
            "total_findings":   len(state.findings),
            "elapsed_seconds":  round(elapsed, 2),
            "servers": [
                {
                    "host":          t.host,
                    "port":          t.port,
                    "tls":           t.tls,
                    "starttls":      t.starttls,
                    "software":      state.banners.get(f"{t.host}:{t.port}", SMTPBanner(
                        raw="", hostname=None, software=None, version=None,
                        extensions=[], tls_available=False, auth_methods=[],
                        vrfy_enabled=False, expn_enabled=False, size_limit=None,
                    )).software,
                    "version":       state.banners.get(f"{t.host}:{t.port}", SMTPBanner(
                        raw="", hostname=None, software=None, version=None,
                        extensions=[], tls_available=False, auth_methods=[],
                        vrfy_enabled=False, expn_enabled=False, size_limit=None,
                    )).version,
                    "vrfy_enabled":  state.banners.get(f"{t.host}:{t.port}", SMTPBanner(
                        raw="", hostname=None, software=None, version=None,
                        extensions=[], tls_available=False, auth_methods=[],
                        vrfy_enabled=False, expn_enabled=False, size_limit=None,
                    )).vrfy_enabled,
                    "expn_enabled":  state.banners.get(f"{t.host}:{t.port}", SMTPBanner(
                        raw="", hostname=None, software=None, version=None,
                        extensions=[], tls_available=False, auth_methods=[],
                        vrfy_enabled=False, expn_enabled=False, size_limit=None,
                    )).expn_enabled,
                    "auth_methods":  state.banners.get(f"{t.host}:{t.port}", SMTPBanner(
                        raw="", hostname=None, software=None, version=None,
                        extensions=[], tls_available=False, auth_methods=[],
                        vrfy_enabled=False, expn_enabled=False, size_limit=None,
                    )).auth_methods,
                }
                for t in state.targets
            ],
            "users": [
                {
                    "username":     r.username,
                    "email":        r.email,
                    "method":       r.method,
                    "exists":       r.exists,
                    "response_code":r.response_code,
                    "confidence":   r.confidence,
                }
                for r in state.user_results
                if r.exists
            ],
            "findings": [
                {
                    "host":     f.host,
                    "port":     f.port,
                    "severity": f.severity,
                    "category": f.category,
                    "title":    f.title,
                    "detail":   f.detail,
                    "evidence": f.evidence,
                    "cwe":      f.cwe,
                    "cvss":     f.cvss,
                }
                for f in state.findings
            ],
        }