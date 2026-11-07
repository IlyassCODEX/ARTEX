# DISTINCT FROM: _RateLimitProbe in auth_bypass.py (login-form burst only)
# THIS FILE: full rate-limit fingerprinting, algorithm detection, multi-layer
# bypass strategy engine, timing attack logic, state machine analysis,
# distributed request coordination, and bypass confirmation chain.

from __future__ import annotations

import hashlib
import itertools
import logging
import math
import random
import re
import statistics
import string
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Deque, Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import urlencode, urljoin, urlparse, urlunparse, parse_qs, quote

import requests
from requests import Response
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class RlAlgorithm(Enum):
    """Rate-limit algorithm detected on the target."""
    FIXED_WINDOW      = "fixed_window"
    SLIDING_WINDOW    = "sliding_window"
    TOKEN_BUCKET      = "token_bucket"
    LEAKY_BUCKET      = "leaky_bucket"
    CONCURRENCY_LIMIT = "concurrency_limit"
    NONE_DETECTED     = "none_detected"
    UNKNOWN           = "unknown"


class BypassTechnique(Enum):
    # IP-layer bypass
    IP_SPOOF_X_FORWARDED    = "ip_spoof_x_forwarded_for"
    IP_SPOOF_TRUE_CLIENT    = "ip_spoof_true_client_ip"
    IP_SPOOF_X_REAL_IP      = "ip_spoof_x_real_ip"
    IP_SPOOF_FORWARDED      = "ip_spoof_forwarded_rfc7239"
    IP_SPOOF_CLUSTER        = "ip_spoof_x_cluster_client_ip"
    IP_SPOOF_CF             = "ip_spoof_cf_connecting_ip"
    IP_SPOOF_FASTLY         = "ip_spoof_fastly_client_ip"
    IP_SPOOF_AKAMAI         = "ip_spoof_akamai_origin_hop"
    IP_SPOOF_COMBINATION    = "ip_spoof_header_combination"

    # Header rotation
    HDR_UA_ROTATE           = "header_rotate_user_agent"
    HDR_ACCEPT_ROTATE       = "header_rotate_accept"
    HDR_CONTENT_TYPE        = "header_rotate_content_type"
    HDR_CASE_VARIATION      = "header_name_case_variation"
    HDR_NULL_BYTE           = "header_null_byte_injection"
    HDR_DUPLICATE           = "header_duplicate_key"
    HDR_ENCODING_VARIANT    = "header_encoding_variation"

    # Request mutation
    REQ_PARAM_POLLUTION     = "request_param_pollution"
    REQ_PATH_VARIATION      = "request_path_variation"
    REQ_VERB_TUNNEL         = "request_method_tunneling"
    REQ_CACHE_KEY_POISON    = "request_cache_key_bypass"
    REQ_CHUNKED_BODY        = "request_chunked_transfer"
    REQ_MULTIPART_WRAP      = "request_multipart_wrapping"
    REQ_JSON_INFLATE        = "request_json_body_inflation"
    REQ_PARAM_CASE          = "request_param_case_variation"
    REQ_PATH_APPEND         = "request_path_append_bypass"
    REQ_FRAGMENT_APPEND     = "request_fragment_bypass"

    # Timing-based
    TIMING_WINDOW_BOUNDARY  = "timing_fixed_window_boundary"
    TIMING_BURST_RESET      = "timing_burst_after_reset"
    TIMING_JITTER_SPREAD    = "timing_jitter_spread_requests"
    TIMING_SLOW_DRIP        = "timing_slow_drip_under_threshold"

    # Algorithm-specific
    ALGO_TOKEN_BUCKET_DRAIN  = "algo_token_bucket_drain_refill"
    ALGO_SLIDING_WINDOW_EDGE = "algo_sliding_window_edge_exploit"
    ALGO_CONCURRENCY_FLOOD   = "algo_concurrency_slot_exhaustion"


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
class RlFingerprint:
    """Everything detected about an endpoint's rate-limiting behaviour."""
    url:              str
    algorithm:        RlAlgorithm
    limit:            Optional[int]       # max requests
    window_s:         Optional[float]     # window size in seconds
    refill_rate:      Optional[float]     # tokens/s for token bucket
    limit_header:     Optional[str]       # X-RateLimit-Limit header name
    remaining_header: Optional[str]       # X-RateLimit-Remaining
    reset_header:     Optional[str]       # X-RateLimit-Reset / Retry-After
    keyed_by:         List[str]           # ["ip", "user", "api_key", "session"]
    block_code:       int                 # 429 / 503 / 200(soft) / etc.
    block_body_sig:   Optional[str]       # fragment in block response body
    recovers_after_s: Optional[float]     # measured recovery window
    soft_block:       bool                # 200 OK with error body (soft block)
    response_times:   List[float]         # baseline response time samples
    headers_seen:     Dict[str, str]      # raw RL headers from responses

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url":              self.url,
            "algorithm":        self.algorithm.value,
            "limit":            self.limit,
            "window_s":         self.window_s,
            "refill_rate":      self.refill_rate,
            "limit_header":     self.limit_header,
            "remaining_header": self.remaining_header,
            "reset_header":     self.reset_header,
            "keyed_by":         self.keyed_by,
            "block_code":       self.block_code,
            "block_body_sig":   self.block_body_sig,
            "recovers_after_s": self.recovers_after_s,
            "soft_block":       self.soft_block,
            "avg_response_ms":  round(statistics.mean(self.response_times) * 1000, 1)
                                 if self.response_times else None,
            "headers_seen":     self.headers_seen,
        }


@dataclass
class BypassResult:
    """Result of a single bypass attempt."""
    technique:      BypassTechnique
    endpoint_url:   str
    succeeded:      bool
    requests_sent:  int
    blocked_at:     Optional[int]      # request number when block hit
    breakthrough:   Optional[int]      # requests sent past the limit without block
    evidence:       Dict[str, Any]
    timings:        List[float]        # per-request response times
    status_codes:   List[int]


@dataclass
class RlFinding:
    finding_id:    str
    technique:     BypassTechnique
    severity:      FindingSeverity
    status:        FindingStatus
    target_url:    str
    evidence:      Dict[str, Any]
    bypass_detail: BypassResult
    attack_steps:  List[str]
    exploitation:  Dict[str, Any]
    notes:         str
    timestamp:     datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id":   self.finding_id,
            "technique":    self.technique.value,
            "severity":     self.severity.name,
            "status":       self.status.name,
            "target_url":   self.target_url,
            "evidence":     self.evidence,
            "bypass_detail": {
                "succeeded":     self.bypass_detail.succeeded,
                "requests_sent": self.bypass_detail.requests_sent,
                "blocked_at":    self.bypass_detail.blocked_at,
                "breakthrough":  self.bypass_detail.breakthrough,
                "status_codes":  self.bypass_detail.status_codes[:20],
                "timings_ms":    [round(t * 1000, 1) for t in self.bypass_detail.timings[:20]],
            },
            "attack_steps": self.attack_steps,
            "exploitation": self.exploitation,
            "notes":        self.notes,
            "timestamp":    self.timestamp.isoformat(),
        }


@dataclass
class RlBypassResult:
    run_id:              str
    domain:              str
    endpoints_tested:    int
    fingerprints:        List[Dict[str, Any]]
    findings:            List[Dict[str, Any]]
    bypasses_confirmed:  int
    score:               float
    risk_level:          str
    techniques_tested:   List[str]
    recommendations:     List[str]
    started_at:          datetime
    finished_at:         datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id":              self.run_id,
            "domain":              self.domain,
            "endpoints_tested":    self.endpoints_tested,
            "fingerprints":        self.fingerprints,
            "findings":            self.findings,
            "bypasses_confirmed":  self.bypasses_confirmed,
            "score":               round(self.score, 2),
            "risk_level":          self.risk_level,
            "techniques_tested":   self.techniques_tested,
            "recommendations":     self.recommendations,
            "started_at":          self.started_at.isoformat(),
            "finished_at":         self.finished_at.isoformat(),
            "duration_s":          round(
                (self.finished_at - self.started_at).total_seconds(), 3
            ),
        }


# ─────────────────────────────────────────────────────────────────────────────
# HTTP pool — optimised for high-frequency probing
# ─────────────────────────────────────────────────────────────────────────────

class _HttpPool:
    """
    Multi-session pool.  Each logical 'identity' (IP spoof value) gets its
    own requests.Session so cookies and connection state don't bleed across
    identities.  Session count is capped to avoid fd exhaustion.
    """

    _MAX_SESSIONS = 64

    _USER_AGENTS: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        "curl/8.7.1",
        "python-requests/2.31.0",
        "Go-http-client/2.0",
        "okhttp/4.12.0",
        "axios/1.6.8",
        "node-fetch/3.3.2",
    ]

    _ACCEPT_VARIANTS: List[str] = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "application/json, text/plain, */*",
        "*/*",
        "text/html, application/json;q=0.9",
        "application/json",
        "text/plain",
    ]

    _CONTENT_TYPES: List[str] = [
        "application/json",
        "application/json; charset=utf-8",
        "application/x-www-form-urlencoded",
        "application/x-www-form-urlencoded; charset=UTF-8",
        "text/json",
        "application/json;charset=UTF-8",
    ]

    def __init__(self, timeout: float = 8.0, verify_tls: bool = False):
        self._timeout  = timeout
        self._verify   = verify_tls
        self._sessions: Dict[str, requests.Session] = {}
        self._lock     = threading.Lock()
        self._ua_cycle = itertools.cycle(self._USER_AGENTS)

    def session(self, identity: str = "default") -> requests.Session:
        with self._lock:
            if identity not in self._sessions:
                if len(self._sessions) >= self._MAX_SESSIONS:
                    oldest = next(iter(self._sessions))
                    self._sessions[oldest].close()
                    del self._sessions[oldest]
                s = requests.Session()
                s.headers["User-Agent"] = next(self._ua_cycle)
                s.verify       = self._verify
                s.max_redirects = 3
                self._sessions[identity] = s
            return self._sessions[identity]

    def send(
        self,
        url:          str,
        method:       str             = "GET",
        headers:      Optional[Dict[str, str]] = None,
        params:       Optional[Dict[str, str]] = None,
        data:         Optional[Any]   = None,
        json_body:    Optional[Any]   = None,
        identity:     str             = "default",
        allow_redirects: bool         = True,
    ) -> Optional[Tuple[Response, float]]:
        """Returns (Response, elapsed_seconds) or None."""
        sess = self.session(identity)
        t0   = time.perf_counter()
        try:
            resp = sess.request(
                method     = method.upper(),
                url        = url,
                headers    = headers or {},
                params     = params,
                data       = data,
                json       = json_body,
                timeout    = self._timeout,
                allow_redirects = allow_redirects,
                verify     = self._verify,
            )
            return resp, time.perf_counter() - t0
        except RequestException as e:
            logger.debug("send %s: %s", url, e)
            return None

    def rotate_ua(self, identity: str) -> None:
        """Replace the User-Agent on a session with the next UA in cycle."""
        with self._lock:
            s = self._sessions.get(identity)
            if s:
                s.headers["User-Agent"] = next(self._ua_cycle)

    def close_all(self) -> None:
        with self._lock:
            for s in self._sessions.values():
                s.close()
            self._sessions.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Rate-limit header parser
# ─────────────────────────────────────────────────────────────────────────────

class _RlHeaderParser:
    """
    Parses rate-limit signal headers from HTTP responses.
    Handles: standard (RFC 6585), Cloudflare, AWS API GW, Nginx limit_req,
    Kong, NGINX Plus, Traefik, custom non-standard variants.
    """

    # Ordered search — first match wins per category
    _LIMIT_HEADERS: List[str] = [
        "X-RateLimit-Limit",
        "X-Rate-Limit-Limit",
        "RateLimit-Limit",
        "Rate-Limit-Limit",
        "X-Request-Limit",
        "X-API-Limit",
        "Throttle-Limit",
        "X-Throttle-Limit",
        "X-WP-Nonce",         # WordPress REST
        "Ratelimit",          # FastAPI / Starlette
    ]

    _REMAINING_HEADERS: List[str] = [
        "X-RateLimit-Remaining",
        "X-Rate-Limit-Remaining",
        "RateLimit-Remaining",
        "Rate-Limit-Remaining",
        "X-Request-Remaining",
        "X-API-Remaining",
        "Throttle-Remaining",
        "X-Throttle-Remaining",
    ]

    _RESET_HEADERS: List[str] = [
        "X-RateLimit-Reset",
        "X-Rate-Limit-Reset",
        "RateLimit-Reset",
        "Retry-After",
        "X-Retry-After",
        "X-RateLimit-Retry-After",
        "X-Request-Reset",
        "Throttle-Wait",
    ]

    _WINDOW_HEADERS: List[str] = [
        "X-RateLimit-Window",
        "X-Rate-Limit-Window",
        "RateLimit-Window",
        "X-Request-Window",
    ]

    _POLICY_HEADERS: List[str] = [
        "RateLimit-Policy",        # RFC draft
        "X-RateLimit-Policy",
    ]

    @classmethod
    def parse(cls, resp: Response) -> Dict[str, Any]:
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        result: Dict[str, Any] = {
            "limit":     None,
            "remaining": None,
            "reset":     None,
            "window":    None,
            "policy":    None,
            "raw":       {},
        }

        for hdr in cls._LIMIT_HEADERS:
            v = hdrs.get(hdr.lower())
            if v is not None:
                result["limit"]          = cls._parse_int(v)
                result["raw"]["limit"]   = (hdr, v)
                break

        for hdr in cls._REMAINING_HEADERS:
            v = hdrs.get(hdr.lower())
            if v is not None:
                result["remaining"]          = cls._parse_int(v)
                result["raw"]["remaining"]   = (hdr, v)
                break

        for hdr in cls._RESET_HEADERS:
            v = hdrs.get(hdr.lower())
            if v is not None:
                result["reset"]          = cls._parse_reset(v)
                result["raw"]["reset"]   = (hdr, v)
                break

        for hdr in cls._WINDOW_HEADERS:
            v = hdrs.get(hdr.lower())
            if v is not None:
                result["window"]         = cls._parse_int(v)
                result["raw"]["window"]  = (hdr, v)
                break

        for hdr in cls._POLICY_HEADERS:
            v = hdrs.get(hdr.lower())
            if v is not None:
                result["policy"]         = v
                result["raw"]["policy"]  = (hdr, v)
                break

        return result

    @staticmethod
    def _parse_int(v: str) -> Optional[int]:
        try:
            return int(v.split(";")[0].strip())
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _parse_reset(v: str) -> Optional[float]:
        """Return seconds until reset (epoch or delta)."""
        try:
            val = float(v.strip())
            if val > 1_000_000:          # looks like a Unix timestamp
                return max(0.0, val - time.time())
            return val                   # already a delta
        except ValueError:
            return None


# ─────────────────────────────────────────────────────────────────────────────
# Rate-limit algorithm fingerprinter
# ─────────────────────────────────────────────────────────────────────────────

class _AlgorithmFingerprinter:
    """
    Sends a calibrated sequence of requests and interprets the pattern of
    remaining counts + timing to identify the underlying algorithm.

    Identification matrix:
    ┌─────────────────┬────────────────────────────────────────────────────┐
    │ Fixed window    │ Remaining decrements 1-per-req; resets all at once │
    │                 │ at a fixed clock boundary                          │
    ├─────────────────┼────────────────────────────────────────────────────┤
    │ Sliding window  │ Remaining decrements 1-per-req; resets gradually   │
    │                 │ as old requests age out of the window              │
    ├─────────────────┼────────────────────────────────────────────────────┤
    │ Token bucket    │ Remaining may jump up between requests as tokens   │
    │                 │ refill; response time constant (no queuing)        │
    ├─────────────────┼────────────────────────────────────────────────────┤
    │ Leaky bucket    │ Response time increases under load (queuing delay) │
    │                 │ No remaining header; 429 only when queue full      │
    ├─────────────────┼────────────────────────────────────────────────────┤
    │ Concurrency     │ 429 only with parallel requests; sequential OK     │
    └─────────────────┴────────────────────────────────────────────────────┘
    """

    _PROBE_COUNT    = 12   # requests in fingerprint burst
    _PROBE_INTERVAL = 0.08 # 80ms between probes

    def fingerprint(
        self,
        http: _HttpPool,
        url:  str,
        base_headers: Optional[Dict[str, str]] = None,
    ) -> RlFingerprint:
        parser   = _RlHeaderParser()
        samples: List[Dict[str, Any]] = []
        timings:  List[float]         = []
        block_code = 0
        block_body = None
        soft_block = False
        headers_seen: Dict[str, str]  = {}

        # --- Send probe burst ---
        for i in range(self._PROBE_COUNT):
            result = http.send(url, headers=base_headers or {})
            if not result:
                time.sleep(self._PROBE_INTERVAL)
                continue
            resp, elapsed = result
            timings.append(elapsed)

            parsed = parser.parse(resp)
            samples.append({
                "i":         i,
                "status":    resp.status_code,
                "elapsed":   elapsed,
                "limit":     parsed["limit"],
                "remaining": parsed["remaining"],
                "reset":     parsed["reset"],
                "window":    parsed["window"],
            })
            # collect raw RL headers
            for cat, pair in parsed.get("raw", {}).items():
                if pair:
                    headers_seen[pair[0]] = pair[1]

            # Detect block
            if resp.status_code in (429, 503):
                block_code = resp.status_code
                block_body = resp.text[:200] if resp.text else None
                break
            # Soft block: 200 but body says rate limited
            if resp.status_code == 200 and resp.text:
                body_low = resp.text.lower()
                if any(kw in body_low for kw in
                       ("rate limit", "too many requests", "slow down",
                        "throttled", "retry after")):
                    soft_block = True
                    block_body = resp.text[:200]
                    block_code = 200

            time.sleep(self._PROBE_INTERVAL)

        # --- Extract RL parameters ---
        limit     = next((s["limit"]     for s in samples if s["limit"]     is not None), None)
        window_s  = next((s["window"]    for s in samples if s["window"]    is not None), None)
        reset_val = next((s["reset"]     for s in samples if s["reset"]     is not None), None)

        limit_hdr     = headers_seen.get(next(iter(
            [k for k in headers_seen if "limit" in k.lower() and "remaining" not in k.lower()
             and "reset" not in k.lower()]), ""), None) and next(
            (k for k in headers_seen if "limit" in k.lower() and "remaining" not in k.lower()
             and "reset" not in k.lower()), None
        )
        remaining_hdr = next(
            (k for k in headers_seen if "remaining" in k.lower()), None
        )
        reset_hdr = next(
            (k for k in headers_seen if "reset" in k.lower() or "retry" in k.lower()), None
        )

        algo      = self._identify_algorithm(samples, timings, block_code, soft_block)
        refill    = self._estimate_refill(algo, limit, window_s)
        keyed_by  = self._infer_keying(samples, headers_seen)

        # Measure recovery window
        recovery = None
        if block_code in (429, 503) and reset_val:
            recovery = reset_val
        elif block_code in (429, 503) and window_s:
            recovery = window_s

        return RlFingerprint(
            url              = url,
            algorithm        = algo,
            limit            = limit,
            window_s         = window_s or (recovery if recovery else None),
            refill_rate      = refill,
            limit_header     = limit_hdr,
            remaining_header = remaining_hdr,
            reset_header     = reset_hdr,
            keyed_by         = keyed_by,
            block_code       = block_code,
            block_body_sig   = block_body,
            recovers_after_s = recovery,
            soft_block       = soft_block,
            response_times   = timings,
            headers_seen     = headers_seen,
        )

    # ── algorithm identification ──────────────────────────────────────────────

    def _identify_algorithm(
        self,
        samples:    List[Dict[str, Any]],
        timings:    List[float],
        block_code: int,
        soft_block: bool,
    ) -> RlAlgorithm:
        if not samples:
            return RlAlgorithm.UNKNOWN

        remainders = [s["remaining"] for s in samples if s["remaining"] is not None]

        # No RL signals at all
        if not remainders and block_code == 0 and not soft_block:
            return RlAlgorithm.NONE_DETECTED

        # Token bucket: remaining sometimes jumps UP between requests
        if len(remainders) >= 3:
            jumps_up = sum(
                1 for i in range(1, len(remainders))
                if remainders[i] > remainders[i - 1]
            )
            if jumps_up >= 2:
                return RlAlgorithm.TOKEN_BUCKET

        # Leaky bucket: response time increases under load (queuing delay)
        if len(timings) >= 6:
            first_half = statistics.mean(timings[:len(timings)//2])
            sec_half   = statistics.mean(timings[len(timings)//2:])
            if sec_half > first_half * 1.5:
                return RlAlgorithm.LEAKY_BUCKET

        # Fixed window: remaining monotonically decreases; reset is discrete
        if len(remainders) >= 4:
            always_decreasing = all(
                remainders[i] >= remainders[i + 1]
                for i in range(len(remainders) - 1)
            )
            resets            = [s["reset"] for s in samples if s["reset"] is not None]
            if always_decreasing and resets:
                # If reset values cluster near a fixed interval → fixed window
                if len(resets) >= 2:
                    gaps = [abs(resets[i] - resets[i-1]) for i in range(1, len(resets))]
                    if gaps and max(gaps) < 2.0:
                        return RlAlgorithm.FIXED_WINDOW

        # Sliding window: remaining changes gradually with time
        if remainders and block_code in (429, 503):
            return RlAlgorithm.SLIDING_WINDOW

        return RlAlgorithm.UNKNOWN

    @staticmethod
    def _estimate_refill(
        algo:     RlAlgorithm,
        limit:    Optional[int],
        window_s: Optional[float],
    ) -> Optional[float]:
        if algo == RlAlgorithm.TOKEN_BUCKET and limit and window_s:
            return limit / window_s
        return None

    @staticmethod
    def _infer_keying(
        samples:      List[Dict[str, Any]],
        headers_seen: Dict[str, str],
    ) -> List[str]:
        """Guess what the rate limit key is based on header presence."""
        keys: List[str] = []
        hdr_low = {k.lower() for k in headers_seen}
        if any("user" in h or "account" in h for h in hdr_low):
            keys.append("user")
        if any("api" in h and "key" in h for h in hdr_low):
            keys.append("api_key")
        # Default assumption: IP-based
        if not keys:
            keys.append("ip")
        return keys


# ─────────────────────────────────────────────────────────────────────────────
# IP spoof header generator
# ─────────────────────────────────────────────────────────────────────────────

class _IpSpoofGenerator:
    """
    Generates sets of IP-spoofing headers for each bypass attempt.
    Covers every proxy/CDN header that edge servers forward to the
    origin as the 'real' client IP.
    """

    # Headers that many origins trust as the real client IP
    _IP_HEADERS: List[str] = [
        "X-Forwarded-For",
        "X-Real-IP",
        "True-Client-IP",
        "X-Cluster-Client-IP",
        "CF-Connecting-IP",
        "Fastly-Client-IP",
        "X-Client-IP",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-ProxyUser-Ip",
        "X-Original-Forwarded-For",
        "Forwarded-For",
        "Client-IP",
        "X-Custom-IP-Authorization",
        "X-Azure-ClientIP",
        "Akamai-Origin-Hop",
        "INCAP_SES_",
    ]

    @staticmethod
    def _random_ip(
        rng: Optional[random.Random] = None,
        private: bool = False,
    ) -> str:
        r = rng or random
        if private:
            octets = [10, r.randint(0, 255), r.randint(0, 255), r.randint(1, 254)]
        else:
            # RFC 5737 test ranges: 198.51.100.0/24 and 203.0.113.0/24
            prefix = r.choice([[198, 51, 100], [203, 0, 113]])
            octets = prefix + [r.randint(1, 254)]
        return ".".join(str(o) for o in octets)

    @staticmethod
    def _sequential_ip(seq: int) -> str:
        """Return 10.0.{seq//256}.{seq%256}."""
        return f"10.0.{seq // 256 % 256}.{seq % 256 or 1}"

    def generate_single(
        self,
        header: str,
        seq:    int,
        rng:    Optional[random.Random] = None,
    ) -> Dict[str, str]:
        """One header set for a specific IP-spoofing header."""
        ip = self._sequential_ip(seq)
        return {header: ip}

    def generate_combination(
        self, seq: int
    ) -> Dict[str, str]:
        """Full combination — set many IP headers at once."""
        ip = self._sequential_ip(seq)
        hdrs: Dict[str, str] = {}
        for hdr in self._IP_HEADERS[:8]:
            hdrs[hdr] = ip
        # Also add X-Forwarded-For with chain
        hdrs["X-Forwarded-For"] = f"{ip}, 10.0.0.1, 192.168.1.1"
        # RFC 7239 Forwarded
        hdrs["Forwarded"] = f"for={ip};by=127.0.0.1;proto=https"
        return hdrs

    def generate_pool(self, count: int) -> List[Tuple[str, Dict[str, str]]]:
        """
        Returns list of (identity_key, header_dict) for `count` distinct identities.
        Each identity uses a different header + IP combination.
        """
        pool: List[Tuple[str, Dict[str, str]]] = []
        for i in range(count):
            hdr = self._IP_HEADERS[i % len(self._IP_HEADERS)]
            ip  = self._sequential_ip(i + 1)
            pool.append((f"ip_spoof_{i}", {hdr: ip}))
        return pool


# ─────────────────────────────────────────────────────────────────────────────
# Request mutator — varies request shape to avoid per-request fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

class _RequestMutator:
    """
    Generates mutated versions of a request that look different to cache/RL
    keying functions while targeting the same logical resource.
    """

    @staticmethod
    def path_variations(url: str) -> List[Tuple[str, str]]:
        """Returns [(variation_label, mutated_url)]."""
        parsed = urlparse(url)
        path   = parsed.path.rstrip("/")
        base   = f"{parsed.scheme}://{parsed.netloc}"
        qs     = parsed.query

        variants: List[Tuple[str, str]] = []

        # Trailing slash
        variants.append(("path_trailing_slash",
                         urlunparse(parsed._replace(path=path + "/"))))
        # Double slash
        variants.append(("path_double_slash",
                         urlunparse(parsed._replace(path=path + "//"))))
        # Uppercase path
        variants.append(("path_uppercase",
                         urlunparse(parsed._replace(path=path.upper()))))
        # Mixed case
        mixed = "".join(c.upper() if i % 2 == 0 else c for i, c in enumerate(path))
        variants.append(("path_mixed_case",
                         urlunparse(parsed._replace(path=mixed))))
        # Dot-segment
        variants.append(("path_dot_segment",
                         urlunparse(parsed._replace(path=path + "/."))))
        # URL-encoded slash in path
        enc_path = path[:-1] + "%2F" + path[-1] if len(path) > 1 else path
        variants.append(("path_encoded_slash",
                         urlunparse(parsed._replace(path=enc_path))))
        # Fragment append (may not be sent to server but sometimes leaks through)
        variants.append(("path_fragment",
                         url + "#bypass_" + uuid.uuid4().hex[:6]))

        return variants

    @staticmethod
    def param_pollution(url: str, param: str = "v") -> List[Tuple[str, str]]:
        """
        HTTP Parameter Pollution — add an extra throwaway param to change
        the cache key without affecting backend logic.
        """
        variants: List[Tuple[str, str]] = []
        for i in range(8):
            noise  = uuid.uuid4().hex[:8]
            sep    = "&" if "?" in url else "?"
            variants.append((
                f"param_pollution_{i}",
                f"{url}{sep}{param}={noise}",
            ))
        return variants

    @staticmethod
    def header_case_variants(headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Return header dicts with varied key casing."""
        def _vary(k: str) -> List[str]:
            return [
                k,
                k.upper(),
                k.lower(),
                k.title(),
                k.swapcase(),
                k[:1].upper() + k[1:].lower(),
            ]

        variants: List[Dict[str, str]] = [{}]
        for k, v in headers.items():
            new_variants: List[Dict[str, str]] = []
            for existing in variants:
                for case_k in _vary(k)[:4]:
                    new_variants.append({**existing, case_k: v})
            variants = new_variants
        return variants[:6]

    @staticmethod
    def method_tunnel(url: str, method: str = "POST") -> List[Tuple[str, Dict[str, str], str]]:
        """
        HTTP method tunneling: send POST with X-HTTP-Method-Override=GET.
        Returns [(label, extra_headers, actual_method)].
        """
        return [
            ("method_override_header",
             {"X-HTTP-Method-Override": "GET",
              "X-Method-Override": "GET",
              "X-Override": "GET"},
             "POST"),
            ("method_query_param",
             {},
             "GET"),   # caller should append ?_method=GET
        ]

    @staticmethod
    def cache_key_bypass(url: str) -> List[Tuple[str, str, Dict[str, str]]]:
        """
        Cache-busting techniques that may force the RL middleware to see
        a different cache key while the CDN serves the same cached response.
        Returns [(label, mutated_url, extra_headers)].
        """
        return [
            ("cache_control_no_cache", url,
             {"Cache-Control": "no-cache", "Pragma": "no-cache"}),
            ("cache_control_no_store", url,
             {"Cache-Control": "no-store"}),
            ("cache_bust_param", url + ("&" if "?" in url else "?") + "_=" + str(int(time.time())),
             {}),
            ("cache_accept_encoding", url,
             {"Accept-Encoding": "identity"}),
            ("cache_vary_accept", url,
             {"Accept": "application/json;q=0.9,*/*;q=0.8"}),
            ("cache_x_forwarded_proto", url,
             {"X-Forwarded-Proto": "https"}),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Timing attack engine — fixed-window boundary exploit + slow-drip
# ─────────────────────────────────────────────────────────────────────────────

class _TimingEngine:
    """
    Three timing-based bypass strategies:

    1. Fixed-window boundary: send N-1 requests in window W1, observe
       the reset timestamp, then fire a burst immediately at the W1→W2
       boundary before the CDN/proxy refreshes its count.

    2. Slow drip: send one request every (window_s / limit - epsilon)
       seconds — stays just under the threshold forever.

    3. Jitter spread: randomise inter-request intervals within [0, 2/limit * window]
       to avoid detection by systems that bucket by fixed time slots.
    """

    def boundary_burst(
        self,
        http:         _HttpPool,
        url:          str,
        fp:           RlFingerprint,
        burst_extra:  int = 10,
        base_headers: Optional[Dict[str, str]] = None,
    ) -> BypassResult:
        """
        Drain to N-1 requests, wait for window reset, then fire burst_extra+1
        at the boundary to straddle the reset and get extra requests in.
        """
        if not fp.limit or not fp.window_s:
            return self._empty_result(BypassTechnique.TIMING_WINDOW_BOUNDARY, url)

        statuses: List[int]  = []
        timings:  List[float] = []
        req_n = 0

        # Phase 1: drain to limit-2 (safe margin)
        drain_count = max(1, fp.limit - 2)
        for _ in range(drain_count):
            r = http.send(url, headers=base_headers or {})
            if not r:
                continue
            resp, t = r
            statuses.append(resp.status_code)
            timings.append(t)
            req_n += 1
            if resp.status_code in (429, 503):
                # Already blocked — abort drain
                break
            # Parse reset from response
            parsed = _RlHeaderParser.parse(resp)
            if parsed["reset"]:
                fp = RlFingerprint(**{**fp.__dict__,
                                      "recovers_after_s": parsed["reset"]})

        # Phase 2: sleep until window boundary
        wait = (fp.recovers_after_s or fp.window_s or 60.0) + 0.05
        logger.debug("Boundary burst: waiting %.2fs for window reset", wait)
        time.sleep(wait)

        # Phase 3: burst at reset boundary
        blocked_at   = None
        breakthrough = 0
        for i in range(burst_extra + fp.limit + 2):
            r = http.send(url, headers=base_headers or {})
            if not r:
                continue
            resp, t = r
            statuses.append(resp.status_code)
            timings.append(t)
            req_n += 1
            if resp.status_code in (429, 503):
                if blocked_at is None:
                    blocked_at = req_n
            else:
                if blocked_at:
                    breakthrough += 1

        succeeded = breakthrough > 0 and blocked_at and blocked_at > fp.limit

        return BypassResult(
            technique     = BypassTechnique.TIMING_WINDOW_BOUNDARY,
            endpoint_url  = url,
            succeeded     = succeeded,
            requests_sent = req_n,
            blocked_at    = blocked_at,
            breakthrough  = breakthrough,
            evidence      = {
                "drain_count":   drain_count,
                "wait_s":        wait,
                "burst_extra":   burst_extra,
                "blocked_at":    blocked_at,
                "extra_through": breakthrough,
            },
            timings      = timings,
            status_codes = statuses,
        )

    def slow_drip(
        self,
        http:         _HttpPool,
        url:          str,
        fp:           RlFingerprint,
        duration_s:   float = 30.0,
        base_headers: Optional[Dict[str, str]] = None,
    ) -> BypassResult:
        """
        Send requests at a rate just below the limit:
        interval = window_s / limit - epsilon.
        """
        if not fp.limit or not fp.window_s:
            return self._empty_result(BypassTechnique.TIMING_SLOW_DRIP, url)

        epsilon  = 0.05
        interval = max(0.01, fp.window_s / fp.limit - epsilon)
        statuses: List[int]  = []
        timings:  List[float] = []
        req_n    = 0
        blocked  = 0
        start    = time.monotonic()

        while time.monotonic() - start < duration_s:
            r = http.send(url, headers=base_headers or {})
            if r:
                resp, t = r
                statuses.append(resp.status_code)
                timings.append(t)
                req_n += 1
                if resp.status_code in (429, 503):
                    blocked += 1
            time.sleep(interval)

        succeeded = req_n > 0 and blocked == 0

        return BypassResult(
            technique     = BypassTechnique.TIMING_SLOW_DRIP,
            endpoint_url  = url,
            succeeded     = succeeded,
            requests_sent = req_n,
            blocked_at    = None,
            breakthrough  = req_n if succeeded else None,
            evidence      = {
                "interval_s": round(interval, 4),
                "duration_s": duration_s,
                "total_sent": req_n,
                "blocked":    blocked,
            },
            timings      = timings,
            status_codes = statuses,
        )

    def jitter_spread(
        self,
        http:         _HttpPool,
        url:          str,
        fp:           RlFingerprint,
        count:        int = 30,
        base_headers: Optional[Dict[str, str]] = None,
    ) -> BypassResult:
        """
        Randomise inter-request delays within a window so no fixed-slot
        bucket ever sees too many requests.
        """
        if not fp.limit or not fp.window_s:
            return self._empty_result(BypassTechnique.TIMING_JITTER_SPREAD, url)

        rng      = random.Random(uuid.uuid4().int)
        # jitter range: 0 to 2×(window/limit) seconds
        jitter_max = 2.0 * fp.window_s / fp.limit
        statuses: List[int]  = []
        timings:  List[float] = []
        req_n    = 0
        blocked  = 0

        for _ in range(count):
            r = http.send(url, headers=base_headers or {})
            if r:
                resp, t = r
                statuses.append(resp.status_code)
                timings.append(t)
                req_n += 1
                if resp.status_code in (429, 503):
                    blocked += 1
            time.sleep(rng.uniform(0, jitter_max))

        succeeded = blocked == 0 and req_n > 0

        return BypassResult(
            technique     = BypassTechnique.TIMING_JITTER_SPREAD,
            endpoint_url  = url,
            succeeded     = succeeded,
            requests_sent = req_n,
            blocked_at    = None,
            breakthrough  = req_n if succeeded else None,
            evidence      = {
                "jitter_max_s":  round(jitter_max, 4),
                "count":         count,
                "blocked":       blocked,
            },
            timings      = timings,
            status_codes = statuses,
        )

    # ── token bucket drain+refill ─────────────────────────────────────────────

    def token_bucket_exploit(
        self,
        http:         _HttpPool,
        url:          str,
        fp:           RlFingerprint,
        burst_size:   int = 5,
        base_headers: Optional[Dict[str, str]] = None,
    ) -> BypassResult:
        """
        Token bucket exploit: drain tokens in a fast burst, wait for
        exactly one refill cycle, burst again.  Repeat to get more
        requests than a naive token-bucket would intend.
        """
        if fp.algorithm != RlAlgorithm.TOKEN_BUCKET or not fp.refill_rate:
            return self._empty_result(BypassTechnique.ALGO_TOKEN_BUCKET_DRAIN, url)

        refill_wait = burst_size / fp.refill_rate
        statuses: List[int]  = []
        timings:  List[float] = []
        req_n    = 0
        total_blocked = 0

        for cycle in range(5):
            # Burst: send burst_size requests as fast as possible
            for _ in range(burst_size):
                r = http.send(url, headers=base_headers or {})
                if r:
                    resp, t = r
                    statuses.append(resp.status_code)
                    timings.append(t)
                    req_n += 1
                    if resp.status_code in (429, 503):
                        total_blocked += 1
            # Wait for tokens to refill
            time.sleep(refill_wait)

        succeeded = total_blocked < req_n * 0.1  # less than 10% blocked

        return BypassResult(
            technique     = BypassTechnique.ALGO_TOKEN_BUCKET_DRAIN,
            endpoint_url  = url,
            succeeded     = succeeded,
            requests_sent = req_n,
            blocked_at    = None,
            breakthrough  = req_n - total_blocked if succeeded else None,
            evidence      = {
                "cycles":      5,
                "burst_size":  burst_size,
                "refill_wait": round(refill_wait, 3),
                "total_blocked": total_blocked,
            },
            timings      = timings,
            status_codes = statuses,
        )

    def sliding_window_edge(
        self,
        http:         _HttpPool,
        url:          str,
        fp:           RlFingerprint,
        base_headers: Optional[Dict[str, str]] = None,
    ) -> BypassResult:
        """
        Sliding window edge attack: send limit-1 requests at the very end of
        a window, then limit-1 more at the very start of the next window.
        In a sliding window this would see only 1 request in-window at any
        point; in a fixed window it would see limit-1 at each boundary.
        """
        if not fp.limit or not fp.window_s:
            return self._empty_result(BypassTechnique.ALGO_SLIDING_WINDOW_EDGE, url)

        burst    = fp.limit - 1
        statuses: List[int]  = []
        timings:  List[float] = []
        req_n    = 0
        blocked  = 0

        # Burst 1: end of window
        for _ in range(burst):
            r = http.send(url, headers=base_headers or {})
            if r:
                resp, t = r
                statuses.append(resp.status_code)
                timings.append(t)
                req_n += 1
                if resp.status_code in (429, 503):
                    blocked += 1
            time.sleep(0.02)

        # Sleep to window boundary
        time.sleep(fp.window_s)

        # Burst 2: start of new window
        for _ in range(burst):
            r = http.send(url, headers=base_headers or {})
            if r:
                resp, t = r
                statuses.append(resp.status_code)
                timings.append(t)
                req_n += 1
                if resp.status_code in (429, 503):
                    blocked += 1
            time.sleep(0.02)

        succeeded = blocked == 0 and req_n >= burst * 2

        return BypassResult(
            technique     = BypassTechnique.ALGO_SLIDING_WINDOW_EDGE,
            endpoint_url  = url,
            succeeded     = succeeded,
            requests_sent = req_n,
            blocked_at    = None,
            breakthrough  = req_n if succeeded else None,
            evidence      = {
                "burst_per_edge": burst,
                "window_s":       fp.window_s,
                "blocked":        blocked,
            },
            timings      = timings,
            status_codes = statuses,
        )

    @staticmethod
    def _empty_result(technique: BypassTechnique, url: str) -> BypassResult:
        return BypassResult(
            technique     = technique,
            endpoint_url  = url,
            succeeded     = False,
            requests_sent = 0,
            blocked_at    = None,
            breakthrough  = None,
            evidence      = {"reason": "insufficient fingerprint data"},
            timings       = [],
            status_codes  = [],
        )


# ─────────────────────────────────────────────────────────────────────────────
# Concurrency flood prober
# ─────────────────────────────────────────────────────────────────────────────

class _ConcurrencyProbe:
    """
    Tests concurrency-based rate limits by firing N requests simultaneously
    via threads.  Some systems limit by concurrent connections rather than
    request/window counts — sequential probing never triggers them.
    """

    def probe(
        self,
        http:        _HttpPool,
        url:         str,
        concurrency: int = 20,
        rounds:      int = 3,
        base_headers: Optional[Dict[str, str]] = None,
    ) -> BypassResult:
        all_statuses: List[int]   = []
        all_timings:  List[float] = []
        req_n = 0

        for round_i in range(rounds):
            results: List[Optional[Tuple[Response, float]]] = [None] * concurrency
            lock    = threading.Lock()
            threads: List[threading.Thread] = []

            def _send(idx: int) -> None:
                r = http.send(url, identity=f"concurrent_{round_i}_{idx}",
                              headers=base_headers or {})
                with lock:
                    results[idx] = r

            for i in range(concurrency):
                t = threading.Thread(target=_send, args=(i,))
                threads.append(t)
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15)

            for r in results:
                if r:
                    resp, elapsed = r
                    all_statuses.append(resp.status_code)
                    all_timings.append(elapsed)
                    req_n += 1

            time.sleep(1.0)   # brief pause between rounds

        blocked   = sum(1 for s in all_statuses if s in (429, 503))
        succeeded = blocked == 0 and req_n >= concurrency

        return BypassResult(
            technique     = BypassTechnique.ALGO_CONCURRENCY_FLOOD,
            endpoint_url  = url,
            succeeded     = succeeded,
            requests_sent = req_n,
            blocked_at    = None,
            breakthrough  = req_n if succeeded else None,
            evidence      = {
                "concurrency": concurrency,
                "rounds":      rounds,
                "blocked":     blocked,
            },
            timings      = all_timings,
            status_codes = all_statuses,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Bypass executor — runs all techniques against one endpoint
# ─────────────────────────────────────────────────────────────────────────────

class _BypassExecutor:
    """
    Coordinates the full bypass test sequence for one fingerprinted endpoint.
    Returns a list of (BypassResult, finding severity, notes) tuples.
    """

    def __init__(
        self,
        http:       _HttpPool,
        fp:         RlFingerprint,
        ip_gen:     _IpSpoofGenerator,
        mutator:    _RequestMutator,
        timing_eng: _TimingEngine,
        concurrency: _ConcurrencyProbe,
    ):
        self._http         = http
        self._fp           = fp
        self._ip_gen       = ip_gen
        self._mutator      = mutator
        self._timing       = timing_eng
        self._concurrency  = concurrency

    def execute(self) -> List[Tuple[BypassResult, FindingSeverity, str]]:
        url      = self._fp.url
        fp       = self._fp
        results: List[Tuple[BypassResult, FindingSeverity, str]] = []

        # ── 1. IP spoof: individual headers ───────────────────────────────────
        pool = self._ip_gen.generate_pool(len(_IpSpoofGenerator._IP_HEADERS))
        for identity, spoof_hdrs in pool:
            br = self._run_burst(url, spoof_hdrs, identity, count=20)
            if br.succeeded:
                hdr_name  = next(iter(spoof_hdrs))
                technique = self._classify_ip_spoof(hdr_name)
                results.append((br, FindingSeverity.CRITICAL,
                                 f"IP spoof via {hdr_name} bypassed rate limit"))

        # ── 2. IP spoof combination ────────────────────────────────────────────
        for i in range(5):
            combo_hdrs = self._ip_gen.generate_combination(i + 100)
            br         = self._run_burst(url, combo_hdrs, f"combo_{i}", count=20)
            if br.succeeded:
                results.append((br, FindingSeverity.CRITICAL,
                                 "IP spoof header combination bypassed rate limit"))

        # ── 3. User-Agent rotation ─────────────────────────────────────────────
        ua_results: List[int] = []
        for ua in _HttpPool._USER_AGENTS:
            r = self._http.send(url, headers={"User-Agent": ua})
            if r:
                ua_results.append(r[0].status_code)
        if ua_results:
            ua_br = BypassResult(
                technique     = BypassTechnique.HDR_UA_ROTATE,
                endpoint_url  = url,
                succeeded     = all(s not in (429, 503) for s in ua_results),
                requests_sent = len(ua_results),
                blocked_at    = None,
                breakthrough  = len(ua_results),
                evidence      = {"ua_count": len(ua_results),
                                 "blocked": sum(1 for s in ua_results
                                                if s in (429, 503))},
                timings       = [],
                status_codes  = ua_results,
            )
            if ua_br.succeeded:
                results.append((ua_br, FindingSeverity.HIGH,
                                 "User-Agent rotation bypassed rate limit"))

        # ── 4. Accept / Content-Type header rotation ──────────────────────────
        for hdr_name, variants in [
            ("Accept",        _HttpPool._ACCEPT_VARIANTS),
            ("Content-Type",  _HttpPool._CONTENT_TYPES),
        ]:
            variant_results: List[int] = []
            for v in variants:
                r = self._http.send(url, headers={hdr_name: v})
                if r:
                    variant_results.append(r[0].status_code)
            if all(s not in (429, 503) for s in variant_results) and variant_results:
                br = BypassResult(
                    technique     = (BypassTechnique.HDR_ACCEPT_ROTATE
                                     if hdr_name == "Accept"
                                     else BypassTechnique.HDR_CONTENT_TYPE),
                    endpoint_url  = url,
                    succeeded     = True,
                    requests_sent = len(variant_results),
                    blocked_at    = None,
                    breakthrough  = len(variant_results),
                    evidence      = {"header": hdr_name,
                                     "variants_tested": len(variants)},
                    timings       = [],
                    status_codes  = variant_results,
                )
                results.append((br, FindingSeverity.HIGH,
                                 f"{hdr_name} rotation bypassed rate limit"))

        # ── 5. Path variations ─────────────────────────────────────────────────
        path_vars = self._mutator.path_variations(url)
        path_ok: List[Tuple[str, int]] = []
        for label, mutated_url in path_vars:
            # First confirm base is blocked
            base_resp = self._http.send(url)
            if base_resp and base_resp[0].status_code in (429, 503):
                r = self._http.send(mutated_url)
                if r and r[0].status_code not in (429, 503):
                    path_ok.append((label, r[0].status_code))
        if path_ok:
            br = BypassResult(
                technique     = BypassTechnique.REQ_PATH_VARIATION,
                endpoint_url  = url,
                succeeded     = True,
                requests_sent = len(path_vars),
                blocked_at    = None,
                breakthrough  = len(path_ok),
                evidence      = {"bypassed_via": path_ok[:3]},
                timings       = [],
                status_codes  = [p[1] for p in path_ok],
            )
            results.append((br, FindingSeverity.HIGH,
                             f"Path variation bypass: {path_ok[0][0]}"))

        # ── 6. Parameter pollution ─────────────────────────────────────────────
        pp_ok = 0
        for label, polluted_url in self._mutator.param_pollution(url)[:6]:
            r = self._http.send(polluted_url)
            if r and r[0].status_code not in (429, 503, 404):
                pp_ok += 1
        if pp_ok >= 3:
            br = BypassResult(
                technique     = BypassTechnique.REQ_PARAM_POLLUTION,
                endpoint_url  = url,
                succeeded     = True,
                requests_sent = 6,
                blocked_at    = None,
                breakthrough  = pp_ok,
                evidence      = {"successful_variations": pp_ok},
                timings       = [],
                status_codes  = [],
            )
            results.append((br, FindingSeverity.HIGH,
                             "Parameter pollution changes cache/RL key"))

        # ── 7. Cache-key bypass ────────────────────────────────────────────────
        for label, cb_url, cb_hdrs in self._mutator.cache_key_bypass(url):
            r = self._http.send(cb_url, headers=cb_hdrs)
            if r and r[0].status_code not in (429, 503):
                br = BypassResult(
                    technique     = BypassTechnique.REQ_CACHE_KEY_POISON,
                    endpoint_url  = url,
                    succeeded     = True,
                    requests_sent = 1,
                    blocked_at    = None,
                    breakthrough  = 1,
                    evidence      = {"technique": label, "headers": cb_hdrs},
                    timings       = [],
                    status_codes  = [r[0].status_code],
                )
                results.append((br, FindingSeverity.MEDIUM,
                                 f"Cache-key bypass via {label}"))
                break

        # ── 8. Timing-based techniques ─────────────────────────────────────────
        if fp.algorithm == RlAlgorithm.FIXED_WINDOW and fp.limit and fp.window_s:
            br = self._timing.boundary_burst(self._http, url, fp)
            if br.succeeded:
                results.append((br, FindingSeverity.HIGH,
                                 "Fixed-window boundary burst exceeded limit"))

        if fp.limit and fp.window_s:
            br = self._timing.slow_drip(self._http, url, fp, duration_s=20.0)
            if br.succeeded:
                results.append((br, FindingSeverity.MEDIUM,
                                 f"Slow drip: {br.requests_sent} requests under radar"))

            br = self._timing.jitter_spread(self._http, url, fp, count=25)
            if br.succeeded:
                results.append((br, FindingSeverity.MEDIUM,
                                 "Jitter spread evaded rate-limit detection"))

        if fp.algorithm == RlAlgorithm.TOKEN_BUCKET and fp.refill_rate:
            br = self._timing.token_bucket_exploit(self._http, url, fp)
            if br.succeeded:
                results.append((br, FindingSeverity.HIGH,
                                 "Token bucket drain+refill cycle exceeded effective limit"))

        if fp.algorithm in (RlAlgorithm.SLIDING_WINDOW, RlAlgorithm.FIXED_WINDOW):
            br = self._timing.sliding_window_edge(self._http, url, fp)
            if br.succeeded:
                results.append((br, FindingSeverity.HIGH,
                                 "Sliding-window edge attack doubled effective request budget"))

        # ── 9. Concurrency flood ───────────────────────────────────────────────
        if fp.algorithm != RlAlgorithm.CONCURRENCY_LIMIT:
            br = self._concurrency.probe(self._http, url, concurrency=15, rounds=2)
            if br.succeeded:
                results.append((br, FindingSeverity.HIGH,
                                 "Concurrent burst: no rate limit on parallel requests"))

        # ── 10. Header case variation ──────────────────────────────────────────
        base_spoof = {"X-Forwarded-For": "10.0.0.99"}
        for case_variant in self._mutator.header_case_variants(base_spoof)[:4]:
            r = self._http.send(url, headers=case_variant)
            if r and r[0].status_code not in (429, 503):
                br = BypassResult(
                    technique     = BypassTechnique.HDR_CASE_VARIATION,
                    endpoint_url  = url,
                    succeeded     = True,
                    requests_sent = 1,
                    blocked_at    = None,
                    breakthrough  = 1,
                    evidence      = {"header_variant": case_variant},
                    timings       = [r[1]],
                    status_codes  = [r[0].status_code],
                )
                results.append((br, FindingSeverity.HIGH,
                                 f"Header case variation bypassed RL: {case_variant}"))
                break

        return results

    # ── helpers ───────────────────────────────────────────────────────────────

    def _run_burst(
        self,
        url:          str,
        extra_headers: Dict[str, str],
        identity:     str,
        count:        int = 20,
    ) -> BypassResult:
        """Send `count` rapid requests with given headers and identity."""
        statuses: List[int]  = []
        timings:  List[float] = []
        blocked_at = None

        for i in range(count):
            r = self._http.send(url, headers=extra_headers, identity=identity)
            if not r:
                continue
            resp, elapsed = r
            statuses.append(resp.status_code)
            timings.append(elapsed)
            if resp.status_code in (429, 503) and blocked_at is None:
                blocked_at = i + 1

        # Also check for soft blocks in body
        blocked = sum(1 for s in statuses if s in (429, 503))
        succeeded = blocked == 0 and len(statuses) >= count * 0.8

        return BypassResult(
            technique     = BypassTechnique.IP_SPOOF_X_FORWARDED,
            endpoint_url  = url,
            succeeded     = succeeded,
            requests_sent = len(statuses),
            blocked_at    = blocked_at,
            breakthrough  = len(statuses) - blocked if succeeded else None,
            evidence      = {"headers": extra_headers, "blocked": blocked},
            timings       = timings,
            status_codes  = statuses,
        )

    @staticmethod
    def _classify_ip_spoof(hdr: str) -> BypassTechnique:
        mapping = {
            "X-Forwarded-For":    BypassTechnique.IP_SPOOF_X_FORWARDED,
            "True-Client-IP":     BypassTechnique.IP_SPOOF_TRUE_CLIENT,
            "X-Real-IP":          BypassTechnique.IP_SPOOF_X_REAL_IP,
            "Forwarded":          BypassTechnique.IP_SPOOF_FORWARDED,
            "X-Cluster-Client-IP":BypassTechnique.IP_SPOOF_CLUSTER,
            "CF-Connecting-IP":   BypassTechnique.IP_SPOOF_CF,
            "Fastly-Client-IP":   BypassTechnique.IP_SPOOF_FASTLY,
        }
        return mapping.get(hdr, BypassTechnique.IP_SPOOF_COMBINATION)


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint discoverer
# ─────────────────────────────────────────────────────────────────────────────

class _EndpointDiscoverer:
    """
    Builds the list of rate-limited endpoints to probe.
    Priority: login/auth/register/api/payment endpoints.
    """

    _HIGH_VALUE_PATHS: List[str] = [
        "/login", "/signin", "/auth/login", "/api/auth/login",
        "/api/v1/auth/login", "/api/v2/auth/login",
        "/register", "/signup", "/api/register",
        "/password/reset", "/forgot-password", "/api/password/reset",
        "/api/token", "/oauth/token", "/api/v1/token",
        "/api/v1/users", "/api/v2/users", "/api/users",
        "/api/v1/search", "/api/search",
        "/api/v1/pay", "/api/payment", "/checkout",
        "/api/v1/verify", "/verify", "/api/verify",
        "/api/v1/otp", "/api/otp", "/api/mfa",
        "/graphql", "/api/graphql",
        "/admin/login", "/admin/api",
    ]

    def discover(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> List[str]:
        endpoints: Set[str] = set()

        # 1. email_enumeration login pages
        for page in scan_results.get("email_enumeration", {}).get("login_pages", []):
            url = page.get("url", "")
            if url:
                endpoints.add(url)

        # 2. payload_analysis injection points with high-value paths
        for ip in scan_results.get("payload_analysis", {}).get("injection_points", []):
            url = ip.get("url", "")
            if url:
                for path in self._HIGH_VALUE_PATHS:
                    if path.rstrip("/") in url:
                        endpoints.add(url)
                        break

        # 3. tech_detection + high-value path guesses
        base_seen: Set[str] = set()
        for t_url in scan_results.get("tech_detection", {}):
            parsed = urlparse(t_url)
            base   = f"{parsed.scheme}://{parsed.netloc}"
            if base not in base_seen:
                base_seen.add(base)
                for path in self._HIGH_VALUE_PATHS:
                    endpoints.add(base + path)

        # 4. subdomains that look like API hosts
        for sub in scan_results.get("subdomains", []):
            if not (sub.get("http_status") or sub.get("https_status")):
                continue
            hostname = sub["subdomain"]
            if not any(kw in hostname for kw in
                       ("api", "auth", "login", "account", "admin",
                        "pay", "gateway", "gate")):
                continue
            scheme = "https" if sub.get("https_status") else "http"
            base   = f"{scheme}://{hostname}"
            for path in self._HIGH_VALUE_PATHS[:8]:
                endpoints.add(base + path)

        return list(endpoints)[:40]   # cap to avoid runaway


# ─────────────────────────────────────────────────────────────────────────────
# Finding builder
# ─────────────────────────────────────────────────────────────────────────────

class _FindingBuilder:
    _EXPLOITATIONS: Dict[BypassTechnique, Dict[str, Any]] = {
        BypassTechnique.IP_SPOOF_X_FORWARDED: {
            "script": "for i in range(10000):\n"
                      "    r = requests.post(url, headers={'X-Forwarded-For': f'10.0.0.{i%254+1}'})\n"
                      "    if r.status_code == 200: process(r)",
            "impact": "Unlimited login attempts → credential stuffing / account takeover",
        },
        BypassTechnique.IP_SPOOF_COMBINATION: {
            "script": "Rotate all 18 IP-spoofing headers simultaneously per request",
            "impact": "Full rate-limit bypass regardless of which header the server trusts",
        },
        BypassTechnique.HDR_UA_ROTATE: {
            "script": "Cycle through 12 known User-Agent strings",
            "impact": "Bypass UA-keyed rate limits",
        },
        BypassTechnique.REQ_PATH_VARIATION: {
            "script": "Rotate: /login -> /login/ -> /LOGIN -> /login/. -> /login%2F",
            "impact": "Each path variant counts as a different endpoint in cache/RL",
        },
        BypassTechnique.REQ_PARAM_POLLUTION: {
            "script": "Append unique noise param: /api?v=<uuid> per request",
            "impact": "Cache key changes per request — RL sees distinct resources",
        },
        BypassTechnique.TIMING_WINDOW_BOUNDARY: {
            "script": "Drain to N-1 -> sleep to window reset -> burst N+extra",
            "impact": "2× effective request budget at window boundary",
        },
        BypassTechnique.TIMING_SLOW_DRIP: {
            "script": "interval = window_s / limit - epsilon; loop forever",
            "impact": "Unlimited throughput at just-below-limit rate — no blocking ever",
        },
        BypassTechnique.ALGO_TOKEN_BUCKET_DRAIN: {
            "script": "Burst burst_size -> sleep refill_wait -> repeat",
            "impact": "Doubles effective token budget via drain+refill cycle timing",
        },
        BypassTechnique.ALGO_SLIDING_WINDOW_EDGE: {
            "script": "limit-1 at t=window_end → sleep(window_s) → limit-1 at t=0",
            "impact": "2×(limit-1) requests in one window using edge exploitation",
        },
        BypassTechnique.ALGO_CONCURRENCY_FLOOD: {
            "script": "15 threads all send simultaneously",
            "impact": "Concurrency-unaware RL passes all parallel requests",
        },
    }

    _REMEDIATIONS: Dict[BypassTechnique, str] = {
        BypassTechnique.IP_SPOOF_X_FORWARDED:
            "Never trust X-Forwarded-For from untrusted network layers. "
            "Configure proxy to only set trusted IP header from verified upstream. "
            "Use CGNAT/edge-enforced limits keyed by authenticated session, not IP.",
        BypassTechnique.IP_SPOOF_TRUE_CLIENT:
            "Only accept True-Client-IP from your own CDN edge. "
            "Reject the header if it arrives at the origin directly.",
        BypassTechnique.IP_SPOOF_CF:
            "Restrict CF-Connecting-IP to Cloudflare IP ranges only. "
            "Block the header from non-Cloudflare sources at origin.",
        BypassTechnique.IP_SPOOF_COMBINATION:
            "Allowlist the specific IP header your infrastructure uses. "
            "Strip all others at the reverse proxy before reaching the RL middleware.",
        BypassTechnique.HDR_UA_ROTATE:
            "Do not key rate limits by User-Agent alone — it is trivially rotatable. "
            "Key by session token, authenticated user, or verified client fingerprint.",
        BypassTechnique.REQ_PATH_VARIATION:
            "Normalise request paths (lowercase, resolve ./, strip trailing /, "
            "decode %2F) before applying rate-limit key. "
            "Use canonical form in both RL logic and cache keys.",
        BypassTechnique.REQ_PARAM_POLLUTION:
            "Exclude noise query parameters from RL key. "
            "Normalise and sort query string before hashing.",
        BypassTechnique.REQ_CACHE_KEY_POISON:
            "Cache and RL keys must not vary on Cache-Control / Pragma headers. "
            "Strip attacker-controllable cache-busting params server-side.",
        BypassTechnique.TIMING_WINDOW_BOUNDARY:
            "Replace fixed-window with sliding-window or token-bucket algorithm. "
            "Sliding windows eliminate the boundary burst vulnerability.",
        BypassTechnique.TIMING_SLOW_DRIP:
            "Add a minimum floor to effective rate — even at interval = window/limit "
            "a slow-drip attack sends unlimited requests. "
            "Layer with brute-force detection (N failed attempts → account lockout).",
        BypassTechnique.TIMING_JITTER_SPREAD:
            "Sliding window naturally handles jitter. "
            "Complement with velocity checking across longer time horizons (1h, 24h).",
        BypassTechnique.ALGO_TOKEN_BUCKET_DRAIN:
            "Cap burst depth of token bucket (max_burst < limit). "
            "Add minimum refill interval to prevent drain+refill gaming.",
        BypassTechnique.ALGO_SLIDING_WINDOW_EDGE:
            "Ensure sliding window implementation has sub-second granularity. "
            "Consider adding a request-velocity cap in addition to windowed count.",
        BypassTechnique.ALGO_CONCURRENCY_FLOOD:
            "Add a concurrent-connection limit per session/IP at the load balancer. "
            "NGINX: limit_conn; HAProxy: maxconn per server.",
        BypassTechnique.HDR_CASE_VARIATION:
            "Normalise header names to lowercase before RL key computation.",
    }
    
    def build(
        self,
        br:        BypassResult,
        severity:  FindingSeverity,
        notes:     str,
        fp:        RlFingerprint,
    ) -> RlFinding:
        exploit = self._EXPLOITATIONS.get(br.technique, {
            "script": "Rotate bypass payload per request",
            "impact":  "Rate-limit bypass — unlimited request throughput",
        })
        remediaton = self._REMEDIATIONS.get(
            br.technique,
            "Harden rate-limit key to use authenticated session identity. "
            "Layer multiple RL strategies (IP + session + account).",
        )

        blocked_pct = (
            sum(1 for s in br.status_codes if s in (429, 503)) / len(br.status_codes) * 100
            if br.status_codes else 0.0
        )

        return RlFinding(
            finding_id    = str(uuid.uuid4()),
            technique     = br.technique,
            severity      = severity,
            status        = (FindingStatus.CONFIRMED if br.succeeded
                             else FindingStatus.LIKELY),
            target_url    = br.endpoint_url,
            evidence      = {
                **br.evidence,
                "requests_sent":  br.requests_sent,
                "blocked_pct":    round(blocked_pct, 1),
                "algorithm":      fp.algorithm.value,
                "limit":          fp.limit,
                "window_s":       fp.window_s,
                "keyed_by":       fp.keyed_by,
                "headers_seen":   fp.headers_seen,
            },
            bypass_detail = br,
            attack_steps  = [
                f"Algorithm: {fp.algorithm.value}  Limit: {fp.limit}  Window: {fp.window_s}s",
                f"Bypass technique: {br.technique.value}",
                f"Sent {br.requests_sent} requests — blocked: {blocked_pct:.0f}%",
                exploit.get("script", ""),
                f"Impact: {exploit.get('impact', '')}",
            ],
            exploitation  = exploit,
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

    def score(self, findings: List[RlFinding]) -> Tuple[float, str]:
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
    def build(self, findings: List[RlFinding],
              fps: List[RlFingerprint]) -> List[str]:
        recs:  List[str] = []
        seen:  Set[BypassTechnique] = set()
        builder = _FindingBuilder()

        # Algorithm-level recommendations
        for fp in fps:
            if fp.algorithm == RlAlgorithm.FIXED_WINDOW:
                recs.append(
                    "[ARCH] Migrate from fixed-window to sliding-window or token-bucket "
                    "algorithm — fixed windows are fundamentally vulnerable at boundaries."
                )
            if not fp.keyed_by or fp.keyed_by == ["ip"]:
                recs.append(
                    "[ARCH] Rate-limit key is IP-only — trivially bypassed via IP-spoof headers. "
                    "Key by authenticated session or user identity."
                )
            if fp.algorithm == RlAlgorithm.NONE_DETECTED:
                recs.append(
                    f"[CRITICAL] No rate limit detected on {fp.url} — "
                    "implement rate limiting immediately on this endpoint."
                )

        # Finding-level
        for f in sorted(findings, key=lambda x: (-x.severity.value,
                                                   x.status != FindingStatus.CONFIRMED)):
            if f.technique not in seen:
                seen.add(f.technique)
                recs.append(
                    f"[{f.severity.name}][{f.technique.value}] "
                    f"{builder._REMEDIATIONS.get(f.technique, 'Harden rate-limit configuration.')}"
                )
        return recs


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

class RateLimitBypass:
    """
    Drop-in ARTEX module — final file for core/.

    Usage in app.py (run_scan), after header_analysis + tech_detection:

        from core.ratelimit_bypass import RateLimitBypass

        rl = RateLimitBypass()
        scan_results[scan_id]['ratelimit_bypass'] = rl.run(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    def __init__(
        self,
        timeout:    float = 8.0,
        on_finding: Optional[Callable[[RlFinding], None]] = None,
    ):
        self._timeout    = timeout
        self._on_finding = on_finding

    def run(
        self,
        domain:       str,
        scan_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        run_id     = str(uuid.uuid4())
        started_at = datetime.now()
        logger.info("RateLimitBypass %s starting for %s", run_id, domain)

        http         = _HttpPool(timeout=self._timeout)
        ip_gen       = _IpSpoofGenerator()
        mutator      = _RequestMutator()
        timing_eng   = _TimingEngine()
        concurrency  = _ConcurrencyProbe()
        fp_engine    = _AlgorithmFingerprinter()
        finder       = _FindingBuilder()
        discoverer   = _EndpointDiscoverer()
        scorer       = _Scorer()

        # 1. discover endpoints
        endpoints = discoverer.discover(domain, scan_results)
        logger.info("RateLimitBypass endpoints: %d", len(endpoints))

        all_findings:   List[RlFinding]      = []
        all_fps:        List[RlFingerprint]  = []
        lock = threading.Lock()

        def probe_one(url: str) -> None:
            try:
                # 2. fingerprint
                fp = fp_engine.fingerprint(http, url)

                with lock:
                    all_fps.append(fp)

                # 3. skip if no RL present and no block detected
                if fp.algorithm == RlAlgorithm.NONE_DETECTED and fp.block_code == 0:
                    return

                # 4. execute bypass strategies
                executor = _BypassExecutor(
                    http, fp, ip_gen, mutator, timing_eng, concurrency
                )
                results = executor.execute()

                for br, severity, notes in results:
                    if br.succeeded or br.requests_sent > 0:
                        f = finder.build(br, severity, notes, fp)
                        with lock:
                            all_findings.append(f)
                            if self._on_finding:
                                try:
                                    self._on_finding(f)
                                except Exception:
                                    pass

            except Exception as exc:
                logger.debug("RateLimitBypass probe %s failed: %s", url, exc)

        threads = [threading.Thread(target=probe_one, args=(url,))
                   for url in endpoints]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        http.close_all()

        # 5. aggregate
        all_findings.sort(
            key=lambda f: (-f.severity.value, f.status != FindingStatus.CONFIRMED)
        )
        confirmed = sum(1 for f in all_findings if f.status == FindingStatus.CONFIRMED)
        score, risk_level = scorer.score(all_findings)
        recs   = _RecBuilder().build(all_findings, all_fps)

        finished_at = datetime.now()
        result = RlBypassResult(
            run_id              = run_id,
            domain              = domain,
            endpoints_tested    = len(endpoints),
            fingerprints        = [fp.to_dict() for fp in all_fps],
            findings            = [f.to_dict() for f in all_findings],
            bypasses_confirmed  = confirmed,
            score               = score,
            risk_level          = risk_level,
            techniques_tested   = sorted({f.technique.value for f in all_findings}),
            recommendations     = recs,
            started_at          = started_at,
            finished_at         = finished_at,
        )

        logger.info(
            "RateLimitBypass %s done — score=%.1f risk=%s findings=%d confirmed=%d",
            run_id, score, risk_level, len(all_findings), confirmed,
        )
        return result.to_dict()