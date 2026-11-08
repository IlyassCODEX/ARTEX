# modules/websocket_scanner.py
import re
import os
import ssl
import json
import time
import uuid
import base64
import hashlib
import socket
import struct
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# WebSocket endpoint discovery catalogue
# ---------------------------------------------------------------------------
#
# Common WebSocket paths across frameworks, real-time libs, and protocols.
# Each entry: (path, label, framework_hint)
# ---------------------------------------------------------------------------

_WS_PATHS: List[Tuple[str, str, str]] = [
    # ── Generic ────────────────────────────────────────────────────────────
    ("/ws",                     "generic-ws",           "generic"),
    ("/websocket",              "generic-websocket",    "generic"),
    ("/socket",                 "generic-socket",       "generic"),
    ("/ws/",                    "generic-ws-trail",     "generic"),
    ("/wss",                    "generic-wss",          "generic"),
    ("/connect",                "generic-connect",      "generic"),
    ("/live",                   "generic-live",         "generic"),
    ("/realtime",               "generic-realtime",     "generic"),
    ("/stream",                 "generic-stream",       "generic"),
    ("/feed",                   "generic-feed",         "generic"),
    ("/push",                   "generic-push",         "generic"),
    ("/events",                 "generic-events",       "generic"),
    ("/updates",                "generic-updates",      "generic"),
    ("/channel",                "generic-channel",      "generic"),
    ("/hub",                    "generic-hub",          "generic"),
    ("/sub",                    "generic-sub",          "generic"),
    ("/pub",                    "generic-pub",          "generic"),
    ("/notify",                 "generic-notify",       "generic"),

    # ── Socket.IO ──────────────────────────────────────────────────────────
    ("/socket.io/",             "socketio-root",        "socket.io"),
    ("/socket.io/?EIO=4&transport=websocket",
                                "socketio-eio4",        "socket.io"),
    ("/socket.io/?EIO=3&transport=websocket",
                                "socketio-eio3",        "socket.io"),
    ("/socket.io/1/websocket",  "socketio-v1",          "socket.io"),

    # ── SockJS ────────────────────────────────────────────────────────────
    ("/sockjs/websocket",       "sockjs-ws",            "sockjs"),
    ("/sockjs/info",            "sockjs-info",          "sockjs"),
    ("/sockjs-node/websocket",  "sockjs-node",          "sockjs"),

    # ── GraphQL subscriptions ─────────────────────────────────────────────
    ("/graphql",                "graphql-ws",           "graphql"),
    ("/graphql/subscriptions",  "graphql-subs",         "graphql"),
    ("/subscriptions",          "graphql-subs-alt",     "graphql"),
    ("/graphql-ws",             "graphql-ws-path",      "graphql"),

    # ── SignalR ────────────────────────────────────────────────────────────
    ("/signalr/connect",        "signalr-connect",      "signalr"),
    ("/signalr/negotiate",      "signalr-negotiate",    "signalr"),
    ("/hubs",                   "signalr-hubs",         "signalr"),
    ("/chatHub",                "signalr-chathub",      "signalr"),

    # ── Action Cable (Rails) ───────────────────────────────────────────────
    ("/cable",                  "actioncable",          "rails"),
    ("/ws/cable",               "actioncable-ws",       "rails"),

    # ── Django Channels ───────────────────────────────────────────────────
    ("/ws/chat/",               "dj-channels-chat",     "django"),
    ("/ws/notifications/",      "dj-channels-notify",   "django"),

    # ── Phoenix / Elixir ─────────────────────────────────────────────────
    ("/socket/websocket",       "phoenix-socket",       "phoenix"),
    ("/socket/websocket?vsn=2.0.0",
                                "phoenix-vsn2",         "phoenix"),

    # ── Meteor ────────────────────────────────────────────────────────────
    ("/sockjs/0/websocket",     "meteor-sockjs",        "meteor"),
    ("/websocket/0/websocket",  "meteor-ws",            "meteor"),

    # ── Centrifugo ────────────────────────────────────────────────────────
    ("/connection/websocket",   "centrifugo",           "centrifugo"),

    # ── WAMP / Autobahn ───────────────────────────────────────────────────
    ("/wamp",                   "wamp",                 "autobahn"),
    ("/ws/wamp",                "wamp-ws",              "autobahn"),

    # ── Admin / internal ──────────────────────────────────────────────────
    ("/admin/ws",               "admin-ws",             "generic"),
    ("/internal/ws",            "internal-ws",          "generic"),
    ("/debug/ws",               "debug-ws",             "generic"),
    ("/metrics/ws",             "metrics-ws",           "generic"),
    ("/console/ws",             "console-ws",           "generic"),
    ("/terminal",               "terminal-ws",          "generic"),
    ("/shell",                  "shell-ws",             "generic"),
    ("/exec",                   "exec-ws",              "generic"),

    # ── API / versioned ───────────────────────────────────────────────────
    ("/api/ws",                 "api-ws",               "generic"),
    ("/api/v1/ws",              "api-v1-ws",            "generic"),
    ("/api/v2/ws",              "api-v2-ws",            "generic"),
    ("/api/websocket",          "api-websocket",        "generic"),
    ("/v1/ws",                  "v1-ws",                "generic"),
    ("/v2/ws",                  "v2-ws",                "generic"),

    # ── IoT / device ──────────────────────────────────────────────────────
    ("/mqtt",                   "mqtt-over-ws",         "iot"),
    ("/ws/device",              "device-ws",            "iot"),
    ("/ws/sensor",              "sensor-ws",            "iot"),
]

# Subprotocols to advertise in Upgrade handshake
_SUBPROTOCOLS = [
    "graphql-transport-ws",
    "graphql-ws",
    "chat",
    "binary",
    "json",
    "wamp.2.json",
    "wamp.2.msgpack",
    "actioncable-v1-json",
    "actioncable-v1-msgpack",
    "v10.stomp",
    "v11.stomp",
    "v12.stomp",
]

# ---------------------------------------------------------------------------
# Injection payload catalogue
# ---------------------------------------------------------------------------
#
# Payloads are sent as text frames after a successful handshake.
# Each entry: (payload_bytes, label, family, evidence_patterns)
# ---------------------------------------------------------------------------

_INJECTION_PAYLOADS: List[Tuple[str, str, str, List[str]]] = [

    # ── XSS via message reflection ─────────────────────────────────────────
    ('<script>alert("ARTEX_XSS")</script>',
     "xss-script-tag",   "xss",
     [r"<script>alert", r"ARTEX_XSS"]),

    ('"><img src=x onerror=alert(1)>',
     "xss-img-onerror",  "xss",
     [r"onerror=alert", r"img src=x"]),

    # ── SQL injection ─────────────────────────────────────────────────────
    ("' OR '1'='1",
     "sqli-or",          "sqli",
     [r"(syntax error|sql|mysql|sqlite|postgres|ora-\d)", ]),

    ("1; DROP TABLE users--",
     "sqli-drop",        "sqli",
     [r"(syntax error|sql|mysql|error)"]),

    # ── OS command injection ───────────────────────────────────────────────
    ("; id #",
     "cmdi-id",          "cmdi",
     [r"uid=\d+\(", r"root"]),

    ("$(id)",
     "cmdi-subshell",    "cmdi",
     [r"uid=\d+\("]),

    # ── Path traversal ────────────────────────────────────────────────────
    ("../../../etc/passwd",
     "path-traversal",   "lfi",
     [r"root:x:0:0", r"daemon:"]),

    # ── SSTI ──────────────────────────────────────────────────────────────
    ("{{7*7}}",
     "ssti-jinja",       "ssti",
     [r"\b49\b"]),

    ("${7*7}",
     "ssti-freemarker",  "ssti",
     [r"\b49\b"]),

    # ── JSON injection ────────────────────────────────────────────────────
    ('{"type":"ping","data":"ARTEX_PROBE"}',
     "json-probe",       "protocol",
     [r"(pong|ARTEX_PROBE|type.*ping)"]),

    ('{"action":"subscribe","channel":"ARTEX_CHANNEL"}',
     "subscribe-probe",  "protocol",
     [r"(ARTEX_CHANNEL|subscribe|confirm)"]),

    ('{"cmd":"info"}',
     "cmd-info",         "protocol",
     [r"(version|info|server|status)"]),

    ('{"op":"status"}',
     "op-status",        "protocol",
     [r"(status|ok|success|version)"]),

    # ── Prototype pollution ───────────────────────────────────────────────
    ('{"__proto__":{"polluted":"ARTEX_PROTO"}}',
     "proto-pollution",  "prototype",
     [r"(ARTEX_PROTO|polluted)"]),

    ('{"constructor":{"prototype":{"x":"ARTEX_CTOR"}}}',
     "ctor-pollution",   "prototype",
     [r"(ARTEX_CTOR)"]),

    # ── CRLF / header injection ───────────────────────────────────────────
    ("ARTEX_CRLF\r\nX-Injected: true",
     "crlf-inject",      "crlf",
     [r"X-Injected"]),

    # ── GraphQL introspection ─────────────────────────────────────────────
    ('{"type":"connection_init","payload":{}}',
     "graphql-init",     "graphql",
     [r"(connection_ack|ka|type)"]),

    ('{"id":"1","type":"start","payload":{"query":"{__schema{types{name}}}"}}',
     "graphql-introspect","graphql",
     [r"(__schema|__type|types)"]),

    # ── Oversized / DoS probes ────────────────────────────────────────────
    ("A" * 65536,
     "oversized-frame",  "dos",
     [r"(error|close|disconnect|limit)"]),

    # ── Binary frame probe ────────────────────────────────────────────────
    # Sent as binary — handled separately in _send_binary_probe
]

# Origin values for CORS testing
_ORIGINS_TO_TEST = [
    "https://evil.com",
    "null",
    "https://{target_host}.evil.com",
    "https://evil.{target_host}",
    "http://localhost",
    "http://127.0.0.1",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class WsEndpoint:
    url: str                    # full ws:// or wss:// URL
    http_url: str               # corresponding https:// URL used for probe
    path: str
    label: str
    framework: str
    status_code: int            # HTTP upgrade response code
    upgrade_headers: Dict[str, str]
    subprotocol: Optional[str]
    server_banner: Optional[str]
    tls: bool
    open: bool                  # handshake completed
    detection_method: str       # "upgrade-101" / "upgrade-denied" / "header-hint"


@dataclass
class WsInjectionResult:
    endpoint_url: str
    payload_label: str
    payload_family: str
    payload_sent: str
    response_received: Optional[str]
    matched_patterns: List[str]
    reflected: bool
    close_code: Optional[int]
    close_reason: Optional[str]
    latency_ms: float
    vulnerable: bool
    evidence: str


@dataclass
class WsCorsResult:
    endpoint_url: str
    origin_tested: str
    upgrade_allowed: bool
    acao_header: Optional[str]
    reflected_origin: bool
    vulnerable: bool


@dataclass
class WsScanState:
    target_url: str
    target_host: str
    target_port: int
    tls: bool
    endpoints: List[WsEndpoint] = field(default_factory=list)
    injection_results: List[WsInjectionResult] = field(default_factory=list)
    cors_results: List[WsCorsResult] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


# ---------------------------------------------------------------------------
# RFC 6455 raw WebSocket client (stdlib only)
# ---------------------------------------------------------------------------

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_accept_key(nonce: str) -> str:
    """Compute the expected Sec-WebSocket-Accept value."""
    combined = (nonce + _WS_GUID).encode("utf-8")
    return base64.b64encode(hashlib.sha1(combined).digest()).decode()


def _make_nonce() -> str:
    return base64.b64encode(os.urandom(16)).decode()


def _build_handshake(
    host: str,
    path: str,
    port: int,
    nonce: str,
    origin: Optional[str] = None,
    subprotocol: Optional[str] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> bytes:
    """Build the HTTP/1.1 Upgrade request bytes for a WebSocket handshake."""
    hdrs = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {nonce}",
        "Sec-WebSocket-Version: 13",
        "User-Agent: Mozilla/5.0 (compatible; ARTEX-WS/1.0)",
    ]
    if origin:
        hdrs.append(f"Origin: {origin}")
    if subprotocol:
        hdrs.append(f"Sec-WebSocket-Protocol: {subprotocol}")
    if extra_headers:
        for k, v in extra_headers.items():
            hdrs.append(f"{k}: {v}")
    hdrs.append("\r\n")
    return "\r\n".join(hdrs).encode("utf-8")


def _parse_http_response(data: bytes) -> Tuple[int, Dict[str, str], bytes]:
    """Split raw HTTP response into (status_code, headers_dict, body_remainder)."""
    sep = b"\r\n\r\n"
    idx = data.find(sep)
    if idx == -1:
        return 0, {}, data
    head = data[:idx].decode("utf-8", errors="replace")
    body = data[idx + len(sep):]
    lines = head.split("\r\n")
    status = 0
    try:
        status = int(lines[0].split(" ", 2)[1])
    except (IndexError, ValueError):
        pass
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


def _make_ws_frame(payload: bytes, opcode: int = 0x1) -> bytes:
    """
    Build a masked WebSocket frame (client → server).
    opcode 0x1 = text, 0x2 = binary, 0x8 = close, 0x9 = ping, 0xA = pong.
    """
    mask_key = os.urandom(4)
    masked   = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    plen     = len(payload)

    if plen <= 125:
        header = bytes([0x80 | opcode, 0x80 | plen]) + mask_key
    elif plen <= 65535:
        header = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack(">H", plen) + mask_key
    else:
        header = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack(">Q", plen) + mask_key

    return header + masked


def _unmask_frame(data: bytes) -> Tuple[int, bytes, int]:
    """
    Parse first WebSocket frame from *data*.
    Returns (opcode, payload_bytes, bytes_consumed).
    Returns (0, b"", 0) if data is too short.
    """
    if len(data) < 2:
        return 0, b"", 0
    opcode  = data[0] & 0x0F
    masked  = bool(data[1] & 0x80)
    plen    = data[1] & 0x7F
    offset  = 2

    if plen == 126:
        if len(data) < 4:
            return 0, b"", 0
        plen    = struct.unpack(">H", data[2:4])[0]
        offset  = 4
    elif plen == 127:
        if len(data) < 10:
            return 0, b"", 0
        plen    = struct.unpack(">Q", data[2:10])[0]
        offset  = 10

    mask_key = b""
    if masked:
        if len(data) < offset + 4:
            return 0, b"", 0
        mask_key = data[offset:offset + 4]
        offset  += 4

    if len(data) < offset + plen:
        return 0, b"", 0

    payload = data[offset:offset + plen]
    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    return opcode, payload, offset + plen


class _RawWsConn:
    """
    Minimal synchronous WebSocket connection over raw socket / TLS.
    Supports text send, text/binary receive, ping, and close.
    """

    def __init__(
        self,
        host: str,
        port: int,
        tls: bool,
        timeout: float = 6.0,
    ):
        self._host    = host
        self._port    = port
        self._tls     = tls
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._buf     = b""
        self.connected = False

    def connect(
        self,
        path: str,
        origin: Optional[str] = None,
        subprotocol: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, str]]:
        """
        Perform RFC 6455 handshake.
        Returns (status_code, response_headers).
        """
        raw = socket.create_connection((self._host, self._port), timeout=self._timeout)
        if self._tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=self._host)
        raw.settimeout(self._timeout)
        self._sock = raw

        nonce = _make_nonce()
        hs    = _build_handshake(
            self._host, path, self._port,
            nonce, origin, subprotocol, extra_headers,
        )
        self._sock.sendall(hs)

        # Read until we have the full HTTP response header
        resp_data = b""
        while b"\r\n\r\n" not in resp_data:
            chunk = self._sock.recv(4096)
            if not chunk:
                break
            resp_data += chunk

        status, headers, leftover = _parse_http_response(resp_data)
        self._buf = leftover

        # Verify Sec-WebSocket-Accept
        expected = _ws_accept_key(nonce)
        actual   = headers.get("sec-websocket-accept", "")
        if status == 101 and actual == expected:
            self.connected = True

        return status, headers

    def send_text(self, text: str) -> None:
        if not self._sock:
            raise RuntimeError("not connected")
        self._sock.sendall(_make_ws_frame(text.encode("utf-8"), opcode=0x1))

    def send_binary(self, data: bytes) -> None:
        if not self._sock:
            raise RuntimeError("not connected")
        self._sock.sendall(_make_ws_frame(data, opcode=0x2))

    def send_ping(self, payload: bytes = b"ping") -> None:
        if not self._sock:
            return
        self._sock.sendall(_make_ws_frame(payload, opcode=0x9))

    def recv(self, timeout: Optional[float] = None) -> Tuple[int, bytes]:
        """
        Receive one WebSocket frame.
        Returns (opcode, payload).
        opcode 0x8 = close, 0x9 = ping, 0xA = pong, 0x1 = text, 0x2 = binary.
        """
        if not self._sock:
            return 0, b""
        if timeout is not None:
            self._sock.settimeout(timeout)
        try:
            while True:
                opcode, payload, consumed = _unmask_frame(self._buf)
                if consumed > 0:
                    self._buf = self._buf[consumed:]
                    return opcode, payload
                chunk = self._sock.recv(8192)
                if not chunk:
                    return 0x8, b""   # treat EOF as close
                self._buf += chunk
        except socket.timeout:
            return 0, b""
        except OSError:
            return 0x8, b""

    def close(self) -> None:
        if self._sock:
            try:
                # Send close frame
                self._sock.sendall(_make_ws_frame(
                    struct.pack(">H", 1000) + b"done", opcode=0x8
                ))
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock    = None
            self.connected = False


# ---------------------------------------------------------------------------
# HTTP session (for endpoint discovery phase)
# ---------------------------------------------------------------------------

def _build_http_session(proxy: Optional[str] = None) -> requests.Session:
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
    return session


_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"


# ---------------------------------------------------------------------------
# Phase 1 — WebSocket endpoint discovery
# ---------------------------------------------------------------------------

def _http_to_ws_url(http_url: str) -> str:
    """Convert https://host/path → wss://host/path."""
    return http_url.replace("https://", "wss://").replace("http://", "ws://")


def _probe_upgrade(
    session: requests.Session,
    base_url: str,
    path: str,
    label: str,
    framework: str,
    timeout: float,
) -> Optional[WsEndpoint]:
    """
    Send an HTTP Upgrade request using requests (which will NOT follow the
    upgrade but will capture the response code and headers).
    101 → confirmed WebSocket.
    400/426 with Upgrade header → endpoint exists but rejected our handshake.
    403/401 → protected WebSocket endpoint.
    """
    url = base_url.rstrip("/") + path
    try:
        resp = session.get(
            url,
            headers={
                "User-Agent":             _UA,
                "Upgrade":                "websocket",
                "Connection":             "Upgrade",
                "Sec-WebSocket-Key":      base64.b64encode(os.urandom(16)).decode(),
                "Sec-WebSocket-Version":  "13",
            },
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        resp.close()
    except requests.RequestException:
        return None

    code = resp.status_code
    hdrs = dict(resp.headers)

    # Determine if this is a real WebSocket endpoint
    upgrade_val = hdrs.get("Upgrade", "").lower()
    is_ws = (
        code == 101 or
        (code in (400, 426, 403, 401) and "websocket" in upgrade_val) or
        (code == 200 and "websocket" in upgrade_val) or
        "sec-websocket-accept" in {k.lower() for k in hdrs}
    )

    if not is_ws:
        # Check for framework-specific hints in response body
        # (socket.io returns JSON on plain GET)
        if framework in ("socket.io", "sockjs") and code == 200:
            is_ws = True
        else:
            return None

    parsed = urllib.parse.urlparse(base_url)
    tls    = parsed.scheme == "https"
    ws_url = _http_to_ws_url(url)

    detection = (
        "upgrade-101"   if code == 101 else
        "upgrade-denied" if code in (400, 426) else
        "header-hint"
    )

    return WsEndpoint(
        url=ws_url,
        http_url=url,
        path=path,
        label=label,
        framework=framework,
        status_code=code,
        upgrade_headers={k.lower(): v for k, v in hdrs.items()},
        subprotocol=hdrs.get("Sec-WebSocket-Protocol"),
        server_banner=hdrs.get("Server"),
        tls=tls,
        open=(code == 101),
        detection_method=detection,
    )


def _discover_endpoints(
    session: requests.Session,
    base_url: str,
    timeout: float,
    max_workers: int,
) -> List[WsEndpoint]:
    """Parallel probe of all _WS_PATHS entries."""
    endpoints: List[WsEndpoint] = []
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(_probe_upgrade, session, base_url, path, label, fw, timeout):
            (path, label)
            for path, label, fw in _WS_PATHS
        }
        for f in as_completed(futures):
            r = f.result()
            if r:
                with lock:
                    endpoints.append(r)
                print(
                    f"  [WS][{r.status_code}][{r.detection_method}] "
                    f"{r.url}  ({r.framework})"
                )

    return endpoints


# ---------------------------------------------------------------------------
# Phase 2 — Raw handshake + injection probes
# ---------------------------------------------------------------------------

def _match_patterns(text: str, patterns: List[str]) -> List[str]:
    matched: List[str] = []
    for pat in patterns:
        try:
            if re.search(pat, text, re.I | re.S):
                matched.append(pat)
        except re.error:
            pass
    return matched


def _probe_injection(
    endpoint: WsEndpoint,
    host: str,
    port: int,
    payload_text: str,
    payload_label: str,
    payload_family: str,
    evidence_patterns: List[str],
    timeout: float,
    rate_delay: float,
) -> Optional[WsInjectionResult]:
    """
    Open a raw WebSocket connection, send one injection payload,
    collect any response frames, then close.
    """
    if rate_delay > 0:
        time.sleep(rate_delay)

    conn = _RawWsConn(host, port, endpoint.tls, timeout=timeout)
    t0   = time.monotonic()

    try:
        status, _ = conn.connect(
            endpoint.path,
            origin=f"https://{host}",
            subprotocol=endpoint.subprotocol,
        )
        if status not in (101, 200):
            return None

        # For GraphQL / Socket.IO — send init frame first
        if endpoint.framework in ("graphql", "socket.io"):
            conn.send_text('{"type":"connection_init","payload":{}}')
            conn.recv(timeout=1.5)

        conn.send_text(payload_text)

        # Collect response frames for up to timeout seconds
        response_parts: List[str] = []
        close_code: Optional[int] = None
        close_reason: Optional[str] = None
        deadline = time.monotonic() + min(timeout, 4.0)

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            opcode, payload_bytes = conn.recv(timeout=max(0.5, remaining))
            if opcode == 0x8:   # close
                if len(payload_bytes) >= 2:
                    close_code   = struct.unpack(">H", payload_bytes[:2])[0]
                    close_reason = payload_bytes[2:].decode("utf-8", errors="replace")
                break
            if opcode in (0x1, 0x2) and payload_bytes:
                response_parts.append(payload_bytes.decode("utf-8", errors="replace"))
            if opcode == 0:     # timeout / no data
                break

    except Exception:
        return None
    finally:
        elapsed_ms = (time.monotonic() - t0) * 1000
        conn.close()

    response_text = "\n".join(response_parts)
    matched       = _match_patterns(response_text, evidence_patterns)
    reflected     = payload_text[:30] in response_text
    vulnerable    = bool(matched) or reflected

    return WsInjectionResult(
        endpoint_url=endpoint.url,
        payload_label=payload_label,
        payload_family=payload_family,
        payload_sent=payload_text[:120],
        response_received=response_text[:500] if response_text else None,
        matched_patterns=matched,
        reflected=reflected,
        close_code=close_code,
        close_reason=close_reason,
        latency_ms=round(elapsed_ms, 1),
        vulnerable=vulnerable,
        evidence=(
            f"matched: {matched[0][:60]}" if matched else
            f"reflected payload" if reflected else
            f"close {close_code}: {close_reason}" if close_code else
            "no evidence"
        ),
    )


def _run_injection_suite(
    endpoint: WsEndpoint,
    host: str,
    port: int,
    timeout: float,
    rate_delay: float,
    max_workers: int,
) -> List[WsInjectionResult]:
    """Run all injection payloads against one endpoint in parallel."""
    results: List[WsInjectionResult] = []
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(
                _probe_injection,
                endpoint, host, port,
                payload, label, family, patterns,
                timeout, rate_delay,
            ): label
            for payload, label, family, patterns in _INJECTION_PAYLOADS
        }
        for f in as_completed(futures):
            r = f.result()
            if r:
                with lock:
                    results.append(r)
                if r.vulnerable:
                    print(
                        f"    [VULN][{r.payload_family.upper():<8}] "
                        f"{r.payload_label} @ {r.endpoint_url} | {r.evidence}"
                    )

    return results


# ---------------------------------------------------------------------------
# Phase 3 — CORS / origin validation probe
# ---------------------------------------------------------------------------

def _probe_ws_cors(
    endpoint: WsEndpoint,
    host: str,
    port: int,
    timeout: float,
    rate_delay: float,
) -> List[WsCorsResult]:
    """
    Test whether the WebSocket server validates the Origin header.
    A server that accepts connections from arbitrary origins is vulnerable
    to cross-site WebSocket hijacking (CSWSH).
    """
    results: List[WsCorsResult] = []

    for origin_template in _ORIGINS_TO_TEST:
        origin = origin_template.replace("{target_host}", host)

        if rate_delay > 0:
            time.sleep(rate_delay)

        conn = _RawWsConn(host, port, endpoint.tls, timeout=timeout)
        try:
            status, headers = conn.connect(endpoint.path, origin=origin)
        except Exception:
            continue
        finally:
            conn.close()

        upgrade_allowed = (status == 101)
        acao = headers.get("access-control-allow-origin", "")
        reflected_origin = (acao == origin or acao == "*")

        # Vulnerable if arbitrary origin is accepted with upgrade
        vulnerable = upgrade_allowed and origin not in (
            f"https://{host}", f"http://{host}",
        )

        results.append(WsCorsResult(
            endpoint_url=endpoint.url,
            origin_tested=origin,
            upgrade_allowed=upgrade_allowed,
            acao_header=acao or None,
            reflected_origin=reflected_origin,
            vulnerable=vulnerable,
        ))

        if vulnerable:
            print(
                f"    [CSWSH] origin '{origin}' accepted at {endpoint.url}"
            )

    return results


# ---------------------------------------------------------------------------
# Phase 4 — Protocol-specific deep probes
# ---------------------------------------------------------------------------

def _probe_socketio(
    endpoint: WsEndpoint,
    host: str,
    port: int,
    timeout: float,
) -> List[Dict]:
    """
    Socket.IO specific: enumerate namespaces, check auth bypass,
    probe event name injection.
    """
    findings: List[Dict] = []

    conn = _RawWsConn(host, port, endpoint.tls, timeout=timeout)
    try:
        status, _ = conn.connect(endpoint.path)
        if status != 101:
            return findings

        # Socket.IO engine opens with text "0{...}" (EIO open packet)
        opcode, payload = conn.recv(timeout=2.0)
        if opcode != 0x1:
            return findings

        try:
            # Strip EIO packet type prefix
            raw = payload.decode("utf-8", errors="replace").lstrip("0123456789")
            eio_data = json.loads(raw)
            findings.append({
                "type":     "socketio-open-packet",
                "severity": "info",
                "evidence": f"sid={eio_data.get('sid','?')} "
                            f"upgrades={eio_data.get('upgrades',[])}",
            })
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # Probe namespace enumeration: send "40/admin," connect packet
        conn.send_text("40/admin,")
        opcode, payload = conn.recv(timeout=2.0)
        if opcode == 0x1:
            resp = payload.decode("utf-8", errors="replace")
            if resp.startswith("40/admin"):
                findings.append({
                    "type":     "socketio-namespace-admin",
                    "severity": "high",
                    "evidence": f"/admin namespace accepted: {resp[:80]}",
                })

    except Exception:
        pass
    finally:
        conn.close()

    return findings


def _probe_graphql_ws(
    endpoint: WsEndpoint,
    host: str,
    port: int,
    timeout: float,
) -> List[Dict]:
    """
    GraphQL-over-WebSocket: attempt introspection + subscription injection.
    """
    findings: List[Dict] = []

    for subproto in ("graphql-transport-ws", "graphql-ws"):
        conn = _RawWsConn(host, port, endpoint.tls, timeout=timeout)
        try:
            status, _ = conn.connect(endpoint.path, subprotocol=subproto)
            if status != 101:
                continue

            conn.send_text(json.dumps({"type": "connection_init", "payload": {}}))
            opcode, payload = conn.recv(timeout=2.0)
            if opcode != 0x1:
                continue

            resp = payload.decode("utf-8", errors="replace")
            if "connection_ack" in resp:
                findings.append({
                    "type":     "graphql-ws-open",
                    "severity": "info",
                    "evidence": f"subprotocol={subproto} ack received",
                })

                # Introspection query
                conn.send_text(json.dumps({
                    "id": "1", "type": "subscribe",
                    "payload": {"query": "{__schema{queryType{name}}}"},
                }))
                opcode, payload = conn.recv(timeout=3.0)
                if opcode == 0x1:
                    body = payload.decode("utf-8", errors="replace")
                    if "__schema" in body or "queryType" in body:
                        findings.append({
                            "type":     "graphql-introspection-enabled",
                            "severity": "medium",
                            "evidence": body[:200],
                        })
                break
        except Exception:
            pass
        finally:
            conn.close()

    return findings


# ---------------------------------------------------------------------------
# Phase 5 — Binary frame / ping flood detection
# ---------------------------------------------------------------------------

def _probe_binary_and_ping(
    endpoint: WsEndpoint,
    host: str,
    port: int,
    timeout: float,
) -> List[Dict]:
    findings: List[Dict] = []

    conn = _RawWsConn(host, port, endpoint.tls, timeout=timeout)
    try:
        status, _ = conn.connect(endpoint.path)
        if status != 101:
            return findings

        # Send ping — RFC 6455 compliant server MUST reply with pong
        conn.send_ping(b"ARTEX_PING")
        opcode, payload = conn.recv(timeout=2.0)
        if opcode == 0xA:  # pong
            findings.append({
                "type":     "ping-pong-ok",
                "severity": "info",
                "evidence": f"pong received: {payload.decode('utf-8', errors='replace')[:40]}",
            })

        # Send binary frame with 1 KB of random data
        conn.send_binary(os.urandom(1024))
        opcode, payload = conn.recv(timeout=2.0)
        if opcode == 0x2:
            findings.append({
                "type":     "binary-frame-reflected",
                "severity": "low",
                "evidence": f"{len(payload)}B binary frame echoed back",
            })
        elif opcode == 0x8:
            code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 0
            findings.append({
                "type":     "binary-frame-closed",
                "severity": "info",
                "evidence": f"server closed on binary frame with code {code}",
            })

    except Exception:
        pass
    finally:
        conn.close()

    return findings


# ---------------------------------------------------------------------------
# Deduplication and severity summary
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _dedup_injection(results: List[WsInjectionResult]) -> List[WsInjectionResult]:
    seen: Set[Tuple] = set()
    unique: List[WsInjectionResult] = []
    for r in results:
        key = (r.endpoint_url, r.payload_family, r.vulnerable)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    unique.sort(key=lambda r: (
        0 if r.vulnerable else 1,
        r.payload_family,
    ))
    return unique


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class WebSocketScanner:
    """
    WebSocket endpoint detection + injection probe.

    Five scan phases:
      1. Endpoint discovery — HTTP Upgrade probe across 60+ common WS paths
      2. Injection suite   — 20 payload families per open endpoint
                             (XSS, SQLi, CMDi, SSTI, prototype pollution,
                              GraphQL introspection, oversized frame)
      3. CORS / CSWSH probe — Origin header validation testing
      4. Protocol deep probe — Socket.IO namespace enum, GraphQL introspection
      5. Binary / ping probe — RFC compliance + echo detection

    Zero third-party WebSocket dependencies — raw RFC 6455 over stdlib ssl/socket.

    Usage in app.py:
        scanner = WebSocketScanner(target_url=f"https://{domain}")
        results = scanner.scan()
        scan_results[scan_id]['websocket_scanner'] = results
    """

    def __init__(
        self,
        target_url: str,
        timeout: float = 7.0,
        max_workers: int = 10,
        rate_delay: float = 0.2,
        proxy: Optional[str] = None,
        skip_injection: bool = False,
        skip_cors: bool = False,
    ):
        self.target_url     = target_url.rstrip("/")
        self.timeout        = timeout
        self.max_workers    = max_workers
        self.rate_delay     = rate_delay
        self.proxy          = proxy
        self.skip_injection = skip_injection
        self.skip_cors      = skip_cors

        parsed           = urllib.parse.urlparse(self.target_url)
        self.target_host = parsed.hostname or self.target_url
        self.tls         = parsed.scheme == "https"
        default_port     = 443 if self.tls else 80
        self.target_port = parsed.port or default_port

    # ------------------------------------------------------------------
    # Public scan
    # ------------------------------------------------------------------

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = _build_http_session(self.proxy)

        print(f"[ws_scanner] target  : {self.target_url}")
        print(f"[ws_scanner] paths   : {len(_WS_PATHS)}")

        t0 = time.monotonic()

        # ── Phase 1: discovery ─────────────────────────────────────────────
        endpoints = _discover_endpoints(
            session, self.target_url, self.timeout, self.max_workers
        )
        print(f"[ws_scanner] found   : {len(endpoints)} WebSocket endpoints")

        all_injection: List[WsInjectionResult] = []
        all_cors:      List[WsCorsResult]      = []
        all_proto:     List[Dict]              = []

        for ep in endpoints:
            print(f"[ws_scanner] probing : {ep.url}")

            # ── Phase 2: injection ─────────────────────────────────────────
            if not self.skip_injection:
                inj = _run_injection_suite(
                    ep, self.target_host, self.target_port,
                    self.timeout, self.rate_delay, self.max_workers,
                )
                all_injection.extend(inj)

            # ── Phase 3: CORS ──────────────────────────────────────────────
            if not self.skip_cors:
                cors = _probe_ws_cors(
                    ep, self.target_host, self.target_port,
                    self.timeout, self.rate_delay,
                )
                all_cors.extend(cors)

            # ── Phase 4: protocol-specific deep probes ─────────────────────
            if ep.framework == "socket.io":
                all_proto.extend(_probe_socketio(
                    ep, self.target_host, self.target_port, self.timeout,
                ))
            if ep.framework == "graphql" or "graphql" in ep.path:
                all_proto.extend(_probe_graphql_ws(
                    ep, self.target_host, self.target_port, self.timeout,
                ))

            # ── Phase 5: binary / ping ─────────────────────────────────────
            all_proto.extend(_probe_binary_and_ping(
                ep, self.target_host, self.target_port, self.timeout,
            ))

        elapsed = time.monotonic() - t0

        # ── Post-process ───────────────────────────────────────────────────
        all_injection = _dedup_injection(all_injection)

        vulns     = [r for r in all_injection if r.vulnerable]
        cors_hits = [r for r in all_cors      if r.vulnerable]

        family_counts: Dict[str, int] = {}
        for r in vulns:
            family_counts[r.payload_family] = family_counts.get(r.payload_family, 0) + 1

        print(
            f"[ws_scanner] done | "
            f"endpoints={len(endpoints)} "
            f"vulns={len(vulns)} "
            f"cswsh={len(cors_hits)} "
            f"elapsed={elapsed:.1f}s"
        )

        return {
            "target":               self.target_url,
            "endpoints_found":      len(endpoints),
            "vulnerable_findings":  len(vulns),
            "cswsh_findings":       len(cors_hits),
            "elapsed_seconds":      round(elapsed, 2),
            "vulnerability_families": family_counts,
            "endpoints":            [self._ser_endpoint(e)   for e in endpoints],
            "injection_results":    [self._ser_injection(r)  for r in all_injection],
            "cors_results":         [self._ser_cors(r)        for r in all_cors],
            "protocol_findings":    all_proto,
        }

    # ------------------------------------------------------------------
    # Serialisers
    # ------------------------------------------------------------------

    @staticmethod
    def _ser_endpoint(e: WsEndpoint) -> Dict:
        return {
            "url":              e.url,
            "path":             e.path,
            "label":            e.label,
            "framework":        e.framework,
            "status_code":      e.status_code,
            "open":             e.open,
            "detection_method": e.detection_method,
            "subprotocol":      e.subprotocol,
            "server_banner":    e.server_banner,
            "tls":              e.tls,
        }

    @staticmethod
    def _ser_injection(r: WsInjectionResult) -> Dict:
        return {
            "endpoint_url":       r.endpoint_url,
            "payload_label":      r.payload_label,
            "payload_family":     r.payload_family,
            "payload_sent":       r.payload_sent,
            "response_received":  r.response_received,
            "matched_patterns":   r.matched_patterns,
            "reflected":          r.reflected,
            "close_code":         r.close_code,
            "close_reason":       r.close_reason,
            "latency_ms":         r.latency_ms,
            "vulnerable":         r.vulnerable,
            "evidence":           r.evidence,
        }

    @staticmethod
    def _ser_cors(r: WsCorsResult) -> Dict:
        return {
            "endpoint_url":    r.endpoint_url,
            "origin_tested":   r.origin_tested,
            "upgrade_allowed": r.upgrade_allowed,
            "acao_header":     r.acao_header,
            "reflected_origin":r.reflected_origin,
            "vulnerable":      r.vulnerable,
        }