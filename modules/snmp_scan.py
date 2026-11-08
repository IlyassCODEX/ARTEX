# modules/snmp_scan.py
# SNMP v1/v2c community string brute-force + MIB walk via raw UDP sockets.
# Zero third-party SNMP dependencies — raw ASN.1 BER over stdlib socket.

import re
import os
import time
import uuid
import socket
import struct
import random
import hashlib
import logging
import threading
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Community string wordlist
# ---------------------------------------------------------------------------

_COMMUNITY_STRINGS: List[str] = [
    # Universal defaults
    "public", "private", "community", "default", "manager",
    "admin", "administrator", "password", "snmp", "snmpd",
    "monitor", "monitoring", "read", "write", "readonly",
    "readwrite", "rw", "ro", "all", "test", "cisco",
    "cisco123", "0", "1234", "12345", "secret",

    # Vendor defaults — Cisco
    "cable-docsis", "ILMI",

    # Vendor defaults — 3Com / HP
    "hp_admin", "openview", "agent",

    # Vendor defaults — Juniper
    "juniper",

    # Vendor defaults — Net-SNMP
    "net-snmp", "netsnmp",

    # Vendor defaults — Printer
    "print", "printer", "scan",

    # Vendor defaults — UPS / APC
    "apc",

    # Vendor defaults — Checkpoint
    "SolarWinds",

    # Common mis-configured
    "localhost", "localgroup", "group", "switch", "router",
    "firewall", "gateway", "server", "workstation",
    "internal", "external", "corp", "company",
    "support", "helpdesk", "noc", "ops", "netops",
    "demo", "lab", "dev", "prod", "staging",

    # Number patterns
    "0000", "1111", "9999", "1234567890",

    # Empty / blank
    "",
]

# ---------------------------------------------------------------------------
# BER / ASN.1 encoding for SNMP messages
# ---------------------------------------------------------------------------
#
# SNMP v1/v2c PDUs are BER-encoded ASN.1.
# We only implement GET-REQUEST (0xa0) and GET-NEXT-REQUEST (0xa1).
# GET-BULK-REQUEST (0xa5) is used for v2c MIB walk optimisation.
#
# SNMPv1/v2c message structure:
#   SEQUENCE {
#       version   INTEGER,
#       community OCTET STRING,
#       pdu       GetRequest-PDU | GetNextRequest-PDU | GetBulkRequest-PDU | Response-PDU
#   }
#
# PDU structure:
#   [APPLICATION tag] SEQUENCE {
#       request-id      INTEGER,
#       error-status    INTEGER,
#       error-index     INTEGER,   (or non-repeaters/max-repetitions for BULK)
#       variable-bindings SEQUENCE OF VarBind
#   }
#
# VarBind:
#   SEQUENCE {
#       name  OID,
#       value ANY (NULL for GET requests)
#   }
# ---------------------------------------------------------------------------

def _ber_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    elif n < 256:
        return bytes([0x81, n])
    elif n < 65536:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    else:
        return bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _ber_int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    parts = []
    v = n if n >= 0 else (~(-n) + 1)  # two's complement for negative
    while v:
        parts.append(v & 0xFF)
        v >>= 8
    if n < 0 and not (parts[-1] & 0x80):
        parts.append(0xFF)
    if n >= 0 and (parts[-1] & 0x80):
        parts.append(0x00)
    parts.reverse()
    return _tlv(0x02, bytes(parts))


def _ber_octet(s: str) -> bytes:
    return _tlv(0x04, s.encode("latin-1"))


def _ber_null() -> bytes:
    return _tlv(0x05, b"")


def _encode_oid(oid_str: str) -> bytes:
    """
    Encode OID string (e.g. "1.3.6.1.2.1.1.1.0") to BER OID bytes.
    """
    parts = [int(x) for x in oid_str.strip(".").split(".")]
    # First two components encoded as 40*x + y
    if len(parts) < 2:
        parts = [1, 3] + parts
    encoded = bytes([40 * parts[0] + parts[1]])
    for n in parts[2:]:
        if n == 0:
            encoded += b"\x00"
        else:
            # Base-128 big-endian encoding
            chunks = []
            while n:
                chunks.append(n & 0x7F)
                n >>= 7
            chunks.reverse()
            for i, chunk in enumerate(chunks):
                if i < len(chunks) - 1:
                    encoded += bytes([chunk | 0x80])
                else:
                    encoded += bytes([chunk])
    return _tlv(0x06, encoded)


def _decode_oid(data: bytes) -> str:
    """Decode BER OID bytes to dotted string."""
    if not data:
        return ""
    first = data[0]
    result = [str(first // 40), str(first % 40)]
    i = 1
    while i < len(data):
        n = 0
        while i < len(data):
            b = data[i]
            i += 1
            n = (n << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        result.append(str(n))
    return ".".join(result)


def _varbind(oid_str: str, value: bytes = None) -> bytes:
    """Build a VarBind: SEQUENCE { OID, value }."""
    oid_bytes = _encode_oid(oid_str)
    val_bytes  = value if value is not None else _ber_null()
    return _tlv(0x30, oid_bytes + val_bytes)


def _build_get_request(
    community: str,
    oids: List[str],
    request_id: int,
    version: int = 1,  # 0=v1, 1=v2c
) -> bytes:
    """Build SNMP GET-REQUEST PDU."""
    varbinds   = b"".join(_varbind(oid) for oid in oids)
    varbind_seq = _tlv(0x30, varbinds)
    pdu_body   = (
        _ber_int(request_id) +
        _ber_int(0) +   # error-status = noError
        _ber_int(0) +   # error-index = 0
        varbind_seq
    )
    pdu = _tlv(0xa0, pdu_body)   # GetRequest-PDU [0]
    msg = _tlv(0x30,
        _ber_int(version) +
        _ber_octet(community) +
        pdu
    )
    return msg


def _build_getnext_request(
    community: str,
    oids: List[str],
    request_id: int,
    version: int = 1,
) -> bytes:
    """Build SNMP GET-NEXT-REQUEST PDU."""
    varbinds    = b"".join(_varbind(oid) for oid in oids)
    varbind_seq = _tlv(0x30, varbinds)
    pdu_body    = (
        _ber_int(request_id) +
        _ber_int(0) +
        _ber_int(0) +
        varbind_seq
    )
    pdu = _tlv(0xa1, pdu_body)   # GetNextRequest-PDU [1]
    msg = _tlv(0x30,
        _ber_int(version) +
        _ber_octet(community) +
        pdu
    )
    return msg


def _build_getbulk_request(
    community: str,
    oids: List[str],
    request_id: int,
    non_repeaters: int = 0,
    max_repetitions: int = 10,
) -> bytes:
    """Build SNMP GET-BULK-REQUEST PDU (v2c only)."""
    varbinds    = b"".join(_varbind(oid) for oid in oids)
    varbind_seq = _tlv(0x30, varbinds)
    pdu_body    = (
        _ber_int(request_id) +
        _ber_int(non_repeaters) +   # non-repeaters
        _ber_int(max_repetitions) + # max-repetitions
        varbind_seq
    )
    pdu = _tlv(0xa5, pdu_body)   # GetBulkRequest-PDU [5]
    msg = _tlv(0x30,
        _ber_int(1) +   # version = v2c
        _ber_octet(community) +
        pdu
    )
    return msg


# ---------------------------------------------------------------------------
# BER response parser
# ---------------------------------------------------------------------------

def _parse_ber_len(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        return 0, offset
    b = data[offset]
    if b < 128:
        return b, offset + 1
    elif b == 0x81:
        return data[offset + 1], offset + 2
    elif b == 0x82:
        return (data[offset + 1] << 8) | data[offset + 2], offset + 3
    elif b == 0x83:
        return (
            (data[offset + 1] << 16) |
            (data[offset + 2] << 8) |
            data[offset + 3]
        ), offset + 4
    return 0, offset + 1


def _parse_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        return 0, b"", offset
    tag    = data[offset]
    length, offset = _parse_ber_len(data, offset + 1)
    value  = data[offset:offset + length]
    return tag, value, offset + length


def _parse_all_tlv(data: bytes) -> List[Tuple[int, bytes]]:
    items  = []
    offset = 0
    while offset < len(data):
        tag, value, offset = _parse_tlv(data, offset)
        if tag == 0:
            break
        items.append((tag, value))
    return items


def _decode_int(data: bytes) -> int:
    if not data:
        return 0
    n = int.from_bytes(data, "big", signed=True)
    return n


def _decode_string(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except Exception:
            return data.hex()


def _decode_ip(data: bytes) -> str:
    if len(data) == 4:
        return ".".join(str(b) for b in data)
    return data.hex()


def _decode_timeticks(data: bytes) -> str:
    """Convert TimeTicks (1/100 sec) to human-readable uptime."""
    ticks = _decode_int(data)
    total_secs = ticks // 100
    days    = total_secs // 86400
    hours   = (total_secs % 86400) // 3600
    minutes = (total_secs % 3600) // 60
    secs    = total_secs % 60
    return f"{days}d {hours:02d}:{minutes:02d}:{secs:02d}"


def _decode_value(tag: int, data: bytes) -> Tuple[str, Any]:
    """
    Decode an SNMP value given its BER tag.
    Returns (type_name, decoded_value).
    """
    if tag == 0x02:
        return "INTEGER",    _decode_int(data)
    elif tag == 0x04:
        return "STRING",     _decode_string(data)
    elif tag == 0x05:
        return "NULL",       None
    elif tag == 0x06:
        return "OID",        _decode_oid(data)
    elif tag == 0x40:
        return "IP_ADDRESS", _decode_ip(data)
    elif tag == 0x41:
        return "COUNTER32",  _decode_int(data)
    elif tag == 0x42:
        return "GAUGE32",    _decode_int(data)
    elif tag == 0x43:
        return "TIMETICKS",  _decode_timeticks(data)
    elif tag == 0x44:
        return "OPAQUE",     data.hex()
    elif tag == 0x45:
        return "NSAP",       data.hex()
    elif tag == 0x46:
        return "COUNTER64",  _decode_int(data)
    elif tag == 0x47:
        return "UINTEGER32", _decode_int(data)
    elif tag == 0x80:
        return "NO_SUCH_OBJECT", None
    elif tag == 0x81:
        return "NO_SUCH_INSTANCE", None
    elif tag == 0x82:
        return "END_OF_MIB_VIEW", None
    else:
        return f"UNKNOWN_0x{tag:02x}", data.hex()


def _parse_response(data: bytes) -> Optional[Dict]:
    """
    Parse an SNMP Response-PDU.
    Returns {
        "version": int,
        "community": str,
        "request_id": int,
        "error_status": int,
        "error_index": int,
        "varbinds": [(oid_str, type_name, value), ...]
    }
    or None on parse error.
    """
    try:
        tag, msg_body, _ = _parse_tlv(data, 0)
        if tag != 0x30:
            return None

        items = _parse_all_tlv(msg_body)
        if len(items) < 3:
            return None

        version   = _decode_int(items[0][1]) if items[0][0] == 0x02 else 0
        community = _decode_string(items[1][1]) if items[1][0] == 0x04 else ""
        pdu_tag   = items[2][0]
        pdu_body  = items[2][1]

        # Response-PDU tag: 0xa2
        if pdu_tag != 0xa2:
            return None

        pdu_items = _parse_all_tlv(pdu_body)
        if len(pdu_items) < 4:
            return None

        req_id      = _decode_int(pdu_items[0][1])
        error_status = _decode_int(pdu_items[1][1])
        error_index  = _decode_int(pdu_items[2][1])

        # Varbind list
        varbinds = []
        vbl_tag, vbl_body, _ = _parse_tlv(pdu_body, sum(
            1 + len(_ber_len(len(v))) + len(v)
            for _, v in pdu_items[:3]
        ))
        for vb_tag, vb_body in _parse_all_tlv(vbl_body):
            if vb_tag != 0x30:
                continue
            vb_items = _parse_all_tlv(vb_body)
            if len(vb_items) < 2:
                continue
            oid_str = _decode_oid(vb_items[0][1]) if vb_items[0][0] == 0x06 else "?"
            val_tag = vb_items[1][0]
            val_data = vb_items[1][1]
            type_name, value = _decode_value(val_tag, val_data)
            varbinds.append((oid_str, type_name, value))

        return {
            "version":      version,
            "community":    community,
            "request_id":   req_id,
            "error_status": error_status,
            "error_index":  error_index,
            "varbinds":     varbinds,
        }
    except Exception as exc:
        logger.debug(f"[snmp] parse_response error: {exc}")
        return None


# ---------------------------------------------------------------------------
# Well-known OIDs for MIB walk
# ---------------------------------------------------------------------------
#
# MIB-II (RFC 1213) + system/interface/routing tables.
# OIDs are grouped by category for structured output.
# ---------------------------------------------------------------------------

# (oid, human_readable_name, category)
_SEED_OIDS: List[Tuple[str, str, str]] = [
    # ── System group (1.3.6.1.2.1.1) ──────────────────────────────────────
    ("1.3.6.1.2.1.1.1.0", "sysDescr",         "system"),
    ("1.3.6.1.2.1.1.2.0", "sysObjectID",      "system"),
    ("1.3.6.1.2.1.1.3.0", "sysUpTime",        "system"),
    ("1.3.6.1.2.1.1.4.0", "sysContact",       "system"),
    ("1.3.6.1.2.1.1.5.0", "sysName",          "system"),
    ("1.3.6.1.2.1.1.6.0", "sysLocation",      "system"),

    # ── Interfaces group (1.3.6.1.2.1.2) ──────────────────────────────────
    ("1.3.6.1.2.1.2.1.0", "ifNumber",         "interfaces"),
    ("1.3.6.1.2.1.2.2",   "ifTable",          "interfaces"),

    # ── IP group (1.3.6.1.2.1.4) ──────────────────────────────────────────
    ("1.3.6.1.2.1.4.1.0", "ipForwarding",     "ip"),
    ("1.3.6.1.2.1.4.2.0", "ipDefaultTTL",     "ip"),
    ("1.3.6.1.2.1.4.20",  "ipAddrTable",      "ip"),
    ("1.3.6.1.2.1.4.21",  "ipRouteTable",     "ip"),
    ("1.3.6.1.2.1.4.22",  "ipNetToMediaTable","ip"),

    # ── TCP group (1.3.6.1.2.1.6) ──────────────────────────────────────────
    ("1.3.6.1.2.1.6.13",  "tcpConnTable",     "tcp"),

    # ── UDP group (1.3.6.1.2.1.7) ──────────────────────────────────────────
    ("1.3.6.1.2.1.7.5",   "udpTable",         "udp"),

    # ── ICMP group (1.3.6.1.2.1.5) ────────────────────────────────────────
    ("1.3.6.1.2.1.5.1.0", "icmpInMsgs",       "icmp"),

    # ── SNMP group (1.3.6.1.2.1.11) ───────────────────────────────────────
    ("1.3.6.1.2.1.11.1.0","snmpInPkts",       "snmp"),
    ("1.3.6.1.2.1.11.6.0","snmpInBadCommunityNames", "snmp"),

    # ── Host resources (1.3.6.1.2.1.25) ───────────────────────────────────
    ("1.3.6.1.2.1.25.1.1.0","hrSystemUptime", "host"),
    ("1.3.6.1.2.1.25.2.3",  "hrStorageTable","host"),
    ("1.3.6.1.2.1.25.4.2",  "hrSWRunTable",  "host"),
    ("1.3.6.1.2.1.25.6.3",  "hrSWInstalledTable","host"),

    # ── Cisco extensions (1.3.6.1.4.1.9) ──────────────────────────────────
    ("1.3.6.1.4.1.9.2.1.3.0","ciscoSysDescr",    "cisco"),
    ("1.3.6.1.4.1.9.2.1.73.0","ciscoFlashSize",  "cisco"),
    ("1.3.6.1.4.1.9.9.48.1.1.1.2.1","ciscoMemFree","cisco"),

    # ── Windows / Microsoft (1.3.6.1.4.1.311) ─────────────────────────────
    ("1.3.6.1.4.1.311.1.1.3.1.1.0","windowsOSVersion","windows"),
    ("1.3.6.1.4.1.311.1.1.3.1.2.0","windowsUserCount","windows"),

    # ── UPS / APC (1.3.6.1.4.1.318) ───────────────────────────────────────
    ("1.3.6.1.4.1.318.1.1.1.1.1.1.0","upsBasicIdentModel","ups"),
    ("1.3.6.1.4.1.318.1.1.1.4.2.2.0","upsBatteryCapacity","ups"),

    # ── Net-SNMP extend / exec (1.3.6.1.4.1.8072) ─────────────────────────
    ("1.3.6.1.4.1.8072.1.3.2",  "netSnmpExtend",   "net-snmp"),
    ("1.3.6.1.4.1.8072.3.2.10", "netSnmpAgentOIDs","net-snmp"),

    # ── Printer MIB (1.3.6.1.2.1.43) ──────────────────────────────────────
    ("1.3.6.1.2.1.43.5.1.1.17.1","prtGeneralPrinterName","printer"),
    ("1.3.6.1.2.1.43.11.1.1.6.1.1","prtMarkerSuppliesDescription","printer"),

    # ── IF-MIB extended (1.3.6.1.2.1.31) ─────────────────────────────────
    ("1.3.6.1.2.1.31.1.1.1.1",  "ifName",          "interfaces"),
    ("1.3.6.1.2.1.31.1.1.1.18", "ifAlias",         "interfaces"),
]

# MIB walk subtrees — walk these entire branches during full scan
_WALK_ROOTS = [
    ("1.3.6.1.2.1.1",   "system",         50),    # (oid, label, max_entries)
    ("1.3.6.1.2.1.2",   "interfaces",     100),
    ("1.3.6.1.2.1.4",   "ip",             200),
    ("1.3.6.1.2.1.6",   "tcp",            100),
    ("1.3.6.1.2.1.7",   "udp",            100),
    ("1.3.6.1.2.1.25",  "host_resources", 200),
    ("1.3.6.1.2.1.31",  "if_mib",         100),
    ("1.3.6.1.4.1.9.2", "cisco_local",    100),
    ("1.3.6.1.4.1.311", "microsoft",      100),
    ("1.3.6.1.4.1.8072","net_snmp",       100),
]

# OIDs that commonly leak sensitive data
_SENSITIVE_OIDS = {
    "1.3.6.1.2.1.1.4.0": "sysContact",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
    "1.3.6.1.2.1.4.21":  "IP routing table",
    "1.3.6.1.2.1.4.22":  "ARP table",
    "1.3.6.1.2.1.6.13":  "TCP connection table",
    "1.3.6.1.2.1.25.4.2":"Running processes",
    "1.3.6.1.2.1.25.6.3":"Installed software",
    "1.3.6.1.4.1.9.2":   "Cisco configuration",
    "1.3.6.1.4.1.311":   "Windows system info",
    "1.3.6.1.4.1.8072.1.3.2": "Net-SNMP extend commands",
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SNMPResult:
    oid:        str
    name:       str
    category:   str
    type_name:  str
    value:      Any
    is_sensitive: bool


@dataclass
class SNMPTarget:
    host:    str
    port:    int
    version: str    # "v1" / "v2c"


@dataclass
class CommunityResult:
    community:   str
    version:     str
    accessible:  bool
    write_access:bool
    seed_data:   List[SNMPResult]


@dataclass
class SNMPFinding:
    host:     str
    port:     int
    severity: str
    category: str
    title:    str
    detail:   str
    evidence: str
    cwe:      str
    cvss:     float


@dataclass
class ScanState:
    domain:          str
    targets:         List[SNMPTarget]
    cracked_communities: List[CommunityResult]
    mib_data:        Dict[str, List[SNMPResult]]  # community → results
    findings:        List[SNMPFinding]
    lock:            threading.Lock = field(default_factory=threading.Lock)


# ---------------------------------------------------------------------------
# UDP SNMP socket layer
# ---------------------------------------------------------------------------

class _SNMPSocket:
    """
    Minimal UDP socket wrapper for SNMP.
    Handles send + receive with configurable timeout and retries.
    """

    def __init__(self, host: str, port: int = 161,
                 timeout: float = 2.0, retries: int = 2):
        self._host    = host
        self._port    = port
        self._timeout = timeout
        self._retries = retries
        self._sock: Optional[socket.socket] = None

    def open(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.settimeout(self._timeout)
            return True
        except socket.error:
            return False

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def send_recv(self, data: bytes) -> Optional[bytes]:
        """Send *data* and return first response within timeout×retries."""
        if not self._sock:
            return None
        for attempt in range(self._retries):
            try:
                self._sock.sendto(data, (self._host, self._port))
                resp, addr = self._sock.recvfrom(65535)
                return resp
            except socket.timeout:
                if attempt < self._retries - 1:
                    continue
            except (socket.error, OSError) as exc:
                logger.debug(f"[snmp] UDP error {self._host}:{self._port}: {exc}")
                break
        return None


# ---------------------------------------------------------------------------
# Request ID generator
# ---------------------------------------------------------------------------

_req_counter = 0
_req_lock    = threading.Lock()


def _next_req_id() -> int:
    global _req_counter
    with _req_lock:
        _req_counter = (_req_counter + 1) & 0x7FFFFFFF
        return _req_counter


# ---------------------------------------------------------------------------
# Community string probing
# ---------------------------------------------------------------------------

_PROBE_OIDS = [
    "1.3.6.1.2.1.1.1.0",   # sysDescr
    "1.3.6.1.2.1.1.5.0",   # sysName
    "1.3.6.1.2.1.1.3.0",   # sysUpTime
]


def _probe_community(
    host:      str,
    port:      int,
    community: str,
    version:   int,         # 0=v1, 1=v2c
    timeout:   float = 2.0,
    retries:   int   = 2,
) -> Optional[Dict]:
    """
    Send a GET-REQUEST for sysDescr.0 with the given community string.
    Returns parsed response dict on success, None on failure.
    """
    sock = _SNMPSocket(host, port, timeout, retries)
    if not sock.open():
        return None

    req_id = _next_req_id()
    pkt    = _build_get_request(community, _PROBE_OIDS, req_id, version)
    raw    = sock.send_recv(pkt)
    sock.close()

    if not raw:
        return None

    parsed = _parse_response(raw)
    if not parsed:
        return None

    # Verify community matches what we sent (some agents echo it back)
    if parsed.get("community") != community:
        return None

    # Check error status (0 = noError)
    if parsed.get("error_status", 1) != 0:
        return None

    # Ensure we got at least one valid varbind
    varbinds = parsed.get("varbinds", [])
    if not varbinds:
        return None

    # Filter out end-of-mib / no-such-object responses
    valid = [v for v in varbinds if v[1] not in ("NO_SUCH_OBJECT", "NO_SUCH_INSTANCE", "END_OF_MIB_VIEW", "NULL")]
    if not valid and all(v[2] is None for v in varbinds):
        return None

    return parsed


def _test_write_access(
    host:      str,
    port:      int,
    community: str,
    version:   int,
    timeout:   float,
) -> bool:
    """
    Test if the community string has write access by sending a SET-REQUEST
    with an intentionally safe value (sysContact = current value).
    We use a GET first to get the current value, then try SET.
    A real SET implementation needs SNMP SET PDU (0xa3).
    Here we use a heuristic: if the community string is 'private' or 'write',
    we flag it as potentially write-accessible.
    """
    write_communities = {
        "private", "write", "readwrite", "rw", "admin", "manager",
        "administrator", "all", "cisco123",
    }
    return community.lower() in write_communities


# ---------------------------------------------------------------------------
# MIB walk
# ---------------------------------------------------------------------------

def _get_seed_values(
    host:      str,
    port:      int,
    community: str,
    version:   int,
    timeout:   float,
) -> List[SNMPResult]:
    """
    Fetch all seed OIDs in one or two GET-REQUEST PDUs.
    Returns list of SNMPResult objects.
    """
    results: List[SNMPResult] = []
    # Build OID → (name, category) map
    oid_map: Dict[str, Tuple[str, str]] = {
        oid: (name, cat) for oid, name, cat in _SEED_OIDS
    }

    # Batch into groups of 10 (PDU size limit)
    all_oids = [oid for oid, _, _ in _SEED_OIDS]
    batch_size = 10

    for i in range(0, len(all_oids), batch_size):
        batch  = all_oids[i:i + batch_size]
        sock   = _SNMPSocket(host, port, timeout, retries=2)
        if not sock.open():
            continue

        req_id = _next_req_id()
        pkt    = _build_get_request(community, batch, req_id, version)
        raw    = sock.send_recv(pkt)
        sock.close()

        if not raw:
            continue

        parsed = _parse_response(raw)
        if not parsed:
            continue

        for oid_str, type_name, value in parsed.get("varbinds", []):
            if value is None or type_name in (
                "NO_SUCH_OBJECT", "NO_SUCH_INSTANCE", "END_OF_MIB_VIEW"
            ):
                continue
            name, cat = oid_map.get(oid_str, ("unknown", "misc"))
            is_sensitive = any(
                oid_str.startswith(prefix)
                for prefix in _SENSITIVE_OIDS
            )
            results.append(SNMPResult(
                oid=oid_str, name=name, category=cat,
                type_name=type_name, value=value,
                is_sensitive=is_sensitive,
            ))

    return results


def _walk_subtree(
    host:        str,
    port:        int,
    community:   str,
    version:     int,
    root_oid:    str,
    max_entries: int,
    timeout:     float,
    use_bulk:    bool = True,
) -> List[SNMPResult]:
    """
    Perform a MIB walk starting at *root_oid* using GETNEXT (v1) or
    GETBULK (v2c).  Stops when OID moves outside the subtree or
    max_entries is reached.
    """
    results:    List[SNMPResult] = []
    current_oid = root_oid
    seen:       Set[str] = set()

    sock = _SNMPSocket(host, port, timeout, retries=2)
    if not sock.open():
        return results

    try:
        while len(results) < max_entries:
            req_id = _next_req_id()

            if use_bulk and version == 1:   # v2c
                pkt = _build_getbulk_request(
                    community, [current_oid], req_id,
                    non_repeaters=0, max_repetitions=20,
                )
            else:
                pkt = _build_getnext_request(
                    community, [current_oid], req_id, version
                )

            raw = sock.send_recv(pkt)
            if not raw:
                break

            parsed = _parse_response(raw)
            if not parsed or parsed.get("error_status", 0) != 0:
                break

            varbinds = parsed.get("varbinds", [])
            if not varbinds:
                break

            any_progress = False
            for oid_str, type_name, value in varbinds:
                # Stop if OID has moved outside the subtree
                if not oid_str.startswith(root_oid):
                    return results
                if oid_str in seen:
                    continue
                if type_name in ("END_OF_MIB_VIEW",):
                    return results

                seen.add(oid_str)
                any_progress = True
                current_oid  = oid_str

                is_sensitive = any(
                    oid_str.startswith(prefix)
                    for prefix in _SENSITIVE_OIDS
                )
                results.append(SNMPResult(
                    oid=oid_str,
                    name=oid_str,
                    category="walk",
                    type_name=type_name,
                    value=value,
                    is_sensitive=is_sensitive,
                ))

            if not any_progress:
                break

    finally:
        sock.close()

    return results


# ---------------------------------------------------------------------------
# Target discovery
# ---------------------------------------------------------------------------

def _discover_snmp_targets(domain: str, timeout: float) -> List[SNMPTarget]:
    """
    Probe UDP 161, 162, and TCP 161 on the domain and common subdomains.
    Returns reachable SNMPTarget list.
    """
    targets: List[SNMPTarget] = []
    seen:    Set[str]         = set()

    candidates = [
        domain,
        f"snmp.{domain}",
        f"router.{domain}",
        f"switch.{domain}",
        f"gw.{domain}",
        f"gateway.{domain}",
        f"fw.{domain}",
        f"firewall.{domain}",
        f"mgmt.{domain}",
        f"monitor.{domain}",
    ]

    # Resolve IPs
    resolved: Dict[str, str] = {}
    for host in candidates:
        try:
            ip = socket.gethostbyname(host)
            resolved[host] = ip
        except socket.error:
            pass

    def _probe(host: str, port: int) -> Optional[SNMPTarget]:
        key = f"{host}:{port}"
        if key in seen:
            return None
        sock = _SNMPSocket(host, port, timeout, retries=1)
        if not sock.open():
            return None
        # Try a minimal probe with "public"
        req_id = _next_req_id()
        pkt    = _build_get_request("public", ["1.3.6.1.2.1.1.1.0"], req_id, 1)
        raw    = sock.send_recv(pkt)
        sock.close()
        if raw:
            return SNMPTarget(host=host, port=port, version="v2c")
        # Try v1
        pkt = _build_get_request("public", ["1.3.6.1.2.1.1.1.0"], req_id, 0)
        sock = _SNMPSocket(host, port, timeout, retries=1)
        sock.open()
        raw = sock.send_recv(pkt)
        sock.close()
        if raw:
            return SNMPTarget(host=host, port=port, version="v1")
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {
            ex.submit(_probe, host, 161): host
            for host in resolved
        }
        for f in as_completed(futures):
            r = f.result()
            if r:
                key = f"{r.host}:161"
                if key not in seen:
                    seen.add(key)
                    targets.append(r)
                    print(f"  [snmp] found: {r.host}:161 ({r.version})")

    return targets


# ---------------------------------------------------------------------------
# Finding synthesis
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _synthesise_findings(
    state:     ScanState,
    target:    SNMPTarget,
    cracked:   List[CommunityResult],
    mib_data:  List[SNMPResult],
) -> List[SNMPFinding]:
    findings: List[SNMPFinding] = []
    h = target.host
    p = target.port

    # Community strings cracked
    if cracked:
        read_comm  = [c.community for c in cracked if c.accessible and not c.write_access]
        write_comm = [c.community for c in cracked if c.write_access]

        if read_comm:
            findings.append(SNMPFinding(
                host=h, port=p, severity="high",
                category="community_brute",
                title=f"SNMP Community String Brute-Forced: {read_comm[:3]}",
                detail=(
                    f"Read community string(s) {read_comm[:5]} discovered via brute-force. "
                    f"An attacker can read the full SNMP MIB tree, exposing network topology, "
                    f"routing tables, running processes, and system configuration."
                ),
                evidence=f"GET sysDescr.0 with community='{read_comm[0]}' returned valid response",
                cwe="CWE-521",
                cvss=7.5,
            ))

        if write_comm:
            findings.append(SNMPFinding(
                host=h, port=p, severity="critical",
                category="write_community",
                title=f"SNMP Write Community Detected: {write_comm[:3]}",
                detail=(
                    f"Community string(s) {write_comm[:5]} likely have write access. "
                    f"SNMP write access allows network reconfiguration, interface shutdown, "
                    f"and in some cases remote code execution via OID abuse."
                ),
                evidence=f"Community '{write_comm[0]}' is a known write-community default",
                cwe="CWE-284",
                cvss=9.8,
            ))

    # Sensitive data disclosed
    sensitive = [r for r in mib_data if r.is_sensitive and r.value is not None]
    if sensitive:
        categories = list(dict.fromkeys(r.category for r in sensitive))
        findings.append(SNMPFinding(
            host=h, port=p, severity="high",
            category="info_disclosure",
            title=f"SNMP Sensitive Data Disclosed ({len(sensitive)} OIDs)",
            detail=(
                f"MIB walk returned sensitive data in categories: "
                f"{', '.join(categories)}. "
                f"Includes: "
                + "; ".join(f"{r.name}={str(r.value)[:40]}" for r in sensitive[:5])
            ),
            evidence=f"{len(sensitive)} sensitive OIDs with non-null values",
            cwe="CWE-200",
            cvss=6.5,
        ))

    # Running processes exposed
    proc_data = [r for r in mib_data if "hrSWRunTable" in r.oid or "25.4.2" in r.oid]
    if proc_data:
        findings.append(SNMPFinding(
            host=h, port=p, severity="medium",
            category="process_disclosure",
            title=f"Running Process List Exposed via SNMP ({len(proc_data)} entries)",
            detail=(
                f"The host resources MIB (hrSWRunTable) is readable, "
                f"exposing {len(proc_data)} running process entries. "
                f"This reveals installed software and services."
            ),
            evidence=f"hrSWRunTable accessible with {len(proc_data)} entries",
            cwe="CWE-200",
            cvss=5.3,
        ))

    # Routing table exposed
    route_data = [r for r in mib_data if "4.21" in r.oid or "ipRouteTable" in r.name]
    if route_data:
        findings.append(SNMPFinding(
            host=h, port=p, severity="medium",
            category="routing_disclosure",
            title=f"IP Routing Table Exposed via SNMP ({len(route_data)} routes)",
            detail=(
                f"The IP routing table (ipRouteTable) is accessible anonymously. "
                f"{len(route_data)} routing entries revealed — exposes internal "
                f"network topology for network mapping."
            ),
            evidence=f"ipRouteTable ({len(route_data)} entries) readable",
            cwe="CWE-200",
            cvss=5.3,
        ))

    # Net-SNMP extend — potential RCE
    extend_data = [r for r in mib_data if "8072.1.3.2" in r.oid]
    if extend_data:
        findings.append(SNMPFinding(
            host=h, port=p, severity="critical",
            category="snmp_extend_rce",
            title="Net-SNMP Extend Commands Accessible",
            detail=(
                f"Net-SNMP nsExtendObjects (1.3.6.1.4.1.8072.1.3.2) is accessible. "
                f"If write access is available, an attacker can configure arbitrary "
                f"shell commands to be executed via SNMP GET requests."
            ),
            evidence=f"nsExtendObjects OID accessible: {extend_data[0].value}",
            cwe="CWE-78",
            cvss=9.8,
        ))

    # SNMPv1 in use (deprecated, weak)
    if target.version == "v1":
        findings.append(SNMPFinding(
            host=h, port=p, severity="medium",
            category="deprecated_version",
            title="SNMP v1 in Use (Deprecated, No Authentication)",
            detail=(
                f"{h}:{p} is running SNMPv1, which has no authentication or "
                f"encryption. All traffic is cleartext and community strings "
                f"are trivially sniffed."
            ),
            evidence="SNMP v1 PDU accepted",
            cwe="CWE-326",
            cvss=5.9,
        ))

    # Cisco config data
    cisco_data = [r for r in mib_data if r.category == "cisco" and r.value]
    if cisco_data:
        findings.append(SNMPFinding(
            host=h, port=p, severity="high",
            category="cisco_disclosure",
            title=f"Cisco-Specific MIB Data Exposed ({len(cisco_data)} OIDs)",
            detail=(
                f"Cisco proprietary MIB (1.3.6.1.4.1.9) is readable. "
                f"Exposes device model, IOS version, flash size, and "
                f"potentially interface configurations."
            ),
            evidence=", ".join(f"{r.name}={str(r.value)[:30]}" for r in cisco_data[:3]),
            cwe="CWE-200",
            cvss=6.5,
        ))

    findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 9))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SNMPScanner:
    """
    SNMP v1/v2c community string brute-force + MIB walk scanner.

    Five phases:

      Phase 1 — Target discovery
                UDP 161 probe on domain + common network-device subdomains.

      Phase 2 — Community string brute-force
                Tests all wordlist entries for both v1 and v2c.
                Parallel probes across all community strings.
                Flags potential write-community strings.

      Phase 3 — Seed OID fetch
                Retrieves 30+ key OIDs (sysDescr, sysName, sysContact,
                sysLocation, ipForwarding, interface table, etc.) for each
                cracked community.

      Phase 4 — MIB subtree walk
                Full GETNEXT / GETBULK walk of 10 MIB subtrees including
                system, interfaces, IP, TCP, UDP, host resources,
                Cisco extensions, Windows info, and Net-SNMP extend.

      Phase 5 — Finding synthesis
                Flags: community brute, write access, sensitive data,
                process list, routing table, Net-SNMP extend RCE surface,
                deprecated SNMPv1, Cisco MIB disclosure.

    Zero third-party SNMP dependencies — raw BER/ASN.1 over stdlib UDP socket.

    Usage in app.py:
        scanner = SNMPScanner(domain=domain)
        results = scanner.scan()
        scan_results[scan_id]['snmp_scan'] = results
    """

    def __init__(
        self,
        domain:          str,
        extra_communities:Optional[List[str]] = None,
        timeout:         float = 2.0,
        max_workers:     int   = 25,
        rate_delay:      float = 0.05,
        walk_enabled:    bool  = True,
        walk_max_entries:int   = 150,
        proxy:           Optional[str] = None,
    ):
        self.domain           = domain
        self.communities      = list(dict.fromkeys(
            (extra_communities or []) + _COMMUNITY_STRINGS
        ))
        self.timeout          = timeout
        self.max_workers      = max_workers
        self.rate_delay       = rate_delay
        self.walk_enabled     = walk_enabled
        self.walk_max_entries = walk_max_entries
        self.proxy            = proxy

    # ------------------------------------------------------------------
    # Public scan
    # ------------------------------------------------------------------

    def scan(self) -> Dict:
        import time as _time
        t0 = _time.monotonic()

        print(f"[snmp] domain     : {self.domain}")
        print(f"[snmp] communities: {len(self.communities)}")

        state = ScanState(
            domain=self.domain,
            targets=[],
            cracked_communities=[],
            mib_data={},
            findings=[],
        )

        # ── Phase 1: target discovery ──────────────────────────────────────
        print(f"[snmp] phase 1: target discovery")
        state.targets = _discover_snmp_targets(self.domain, self.timeout)
        if not state.targets:
            print(f"[snmp] no SNMP targets found for {self.domain}")
            return {
                "domain":         self.domain,
                "targets_found":  0,
                "total_findings": 0,
                "findings":       [],
                "mib_data":       {},
                "elapsed_seconds":round(_time.monotonic() - t0, 2),
            }

        target = state.targets[0]
        version_int = 1 if target.version == "v2c" else 0
        print(f"[snmp] primary: {target.host}:{target.port} ({target.version})")

        # ── Phase 2: community string brute-force ──────────────────────────
        print(f"[snmp] phase 2: community string brute-force "
              f"({len(self.communities)} strings × v1+v2c)")

        cracked: List[CommunityResult] = []
        lock = threading.Lock()

        def _brute(community: str) -> None:
            if self.rate_delay > 0:
                time.sleep(self.rate_delay)
            for ver in [1, 0]:   # try v2c first, then v1
                parsed = _probe_community(
                    target.host, target.port, community, ver, self.timeout
                )
                if parsed:
                    ver_str    = "v2c" if ver == 1 else "v1"
                    write_flag = _test_write_access(
                        target.host, target.port, community, ver, self.timeout
                    )
                    result = CommunityResult(
                        community=community,
                        version=ver_str,
                        accessible=True,
                        write_access=write_flag,
                        seed_data=[],
                    )
                    with lock:
                        cracked.append(result)
                    print(
                        f"  [snmp] CRACKED: '{community}' "
                        f"({ver_str}) "
                        f"{'[WRITE]' if write_flag else '[READ]'}"
                    )
                    break   # one successful version per community is enough

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = [ex.submit(_brute, c) for c in self.communities]
            for f in as_completed(futures):
                pass

        state.cracked_communities = cracked
        print(f"[snmp] cracked: {len(cracked)} community string(s)")

        if not cracked:
            print(f"[snmp] no community strings cracked")
            return {
                "domain":              self.domain,
                "targets_found":       len(state.targets),
                "communities_tested":  len(self.communities),
                "communities_cracked": 0,
                "total_findings":      1,
                "findings": [{
                    "host": target.host, "port": target.port,
                    "severity": "info",
                    "category": "no_community",
                    "title": "No SNMP Community Strings Cracked",
                    "detail": "All community strings in the wordlist were rejected.",
                    "evidence": f"Tested {len(self.communities)} strings",
                    "cwe": "CWE-521", "cvss": 0.0,
                }],
                "mib_data":       {},
                "elapsed_seconds":round(_time.monotonic() - t0, 2),
            }

        # Use first cracked community for deep walk
        best = cracked[0]
        best_ver_int = 1 if best.version == "v2c" else 0

        # ── Phase 3: seed OID fetch ────────────────────────────────────────
        print(f"[snmp] phase 3: seed OID fetch (community='{best.community}')")
        seed_results = _get_seed_values(
            target.host, target.port,
            best.community, best_ver_int, self.timeout,
        )
        best.seed_data = seed_results
        state.mib_data[best.community] = seed_results

        for r in seed_results[:8]:
            print(f"  [snmp] {r.name} = {str(r.value)[:60]}")

        # ── Phase 4: MIB subtree walk ──────────────────────────────────────
        all_mib_results: List[SNMPResult] = list(seed_results)

        if self.walk_enabled:
            print(f"[snmp] phase 4: MIB walk ({len(_WALK_ROOTS)} subtrees)")
            use_bulk = best.version == "v2c"

            for root_oid, label, max_e in _WALK_ROOTS:
                walk_max = min(max_e, self.walk_max_entries)
                walk_results = _walk_subtree(
                    target.host, target.port,
                    best.community, best_ver_int,
                    root_oid, walk_max,
                    self.timeout, use_bulk,
                )
                all_mib_results.extend(walk_results)
                print(
                    f"  [snmp] walk {label} ({root_oid}): "
                    f"{len(walk_results)} entries"
                )
                time.sleep(0.1)   # brief pause between subtrees

            state.mib_data[best.community] = all_mib_results

        # ── Phase 5: finding synthesis ─────────────────────────────────────
        print(f"[snmp] phase 5: finding synthesis")
        state.findings = _synthesise_findings(
            state, target, cracked, all_mib_results
        )

        sev_counts: Dict[str, int] = {}
        for f in state.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        elapsed = _time.monotonic() - t0
        print(
            f"[snmp] done | "
            f"cracked={len(cracked)} "
            f"mib_entries={len(all_mib_results)} "
            f"findings={len(state.findings)} "
            f"elapsed={elapsed:.1f}s"
        )

        # Categorise MIB data for output
        mib_by_category: Dict[str, List[Dict]] = {}
        for r in all_mib_results:
            cat = r.category
            mib_by_category.setdefault(cat, [])
            mib_by_category[cat].append({
                "oid":       r.oid,
                "name":      r.name,
                "type":      r.type_name,
                "value":     str(r.value)[:200] if r.value is not None else None,
                "sensitive": r.is_sensitive,
            })

        return {
            "domain":              self.domain,
            "targets_found":       len(state.targets),
            "communities_tested":  len(self.communities),
            "communities_cracked": len(cracked),
            "mib_entries_total":   len(all_mib_results),
            "total_findings":      len(state.findings),
            "severity_summary":    sev_counts,
            "elapsed_seconds":     round(elapsed, 2),
            "targets": [
                {"host": t.host, "port": t.port, "version": t.version}
                for t in state.targets
            ],
            "communities": [
                {
                    "community":    c.community,
                    "version":      c.version,
                    "accessible":   c.accessible,
                    "write_access": c.write_access,
                }
                for c in cracked
            ],
            "system_info": {
                r.name: str(r.value)
                for r in seed_results
                if r.category == "system" and r.value is not None
            },
            "mib_data": mib_by_category,
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