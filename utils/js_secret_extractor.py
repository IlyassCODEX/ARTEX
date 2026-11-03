# utils/js_secret_extractor.py

import asyncio
import aiohttp
import re
import time
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse, urljoin


class SecretType(Enum):
    AWS_ACCESS_KEY = "AWS Access Key"
    AWS_SECRET_KEY = "AWS Secret Key"
    AWS_SESSION_TOKEN = "AWS Session Token"
    GCP_API_KEY = "GCP API Key"
    GCP_SERVICE_ACCOUNT = "GCP Service Account JSON"
    AZURE_CLIENT_SECRET = "Azure Client Secret"
    AZURE_CONNECTION_STRING = "Azure Connection String"
    GITHUB_TOKEN = "GitHub Token"
    GITHUB_OAUTH = "GitHub OAuth Token"
    GITLAB_TOKEN = "GitLab Token"
    STRIPE_KEY_LIVE = "Stripe Live Key"
    STRIPE_KEY_TEST = "Stripe Test Key"
    STRIPE_WEBHOOK = "Stripe Webhook Secret"
    SENDGRID_KEY = "SendGrid API Key"
    TWILIO_ACCOUNT = "Twilio Account SID"
    TWILIO_AUTH = "Twilio Auth Token"
    SLACK_TOKEN = "Slack Token"
    SLACK_WEBHOOK = "Slack Webhook URL"
    DISCORD_TOKEN = "Discord Bot Token"
    DISCORD_WEBHOOK = "Discord Webhook URL"
    TELEGRAM_BOT = "Telegram Bot Token"
    FIREBASE_KEY = "Firebase API Key"
    FIREBASE_URL = "Firebase Database URL"
    JWT_TOKEN = "JWT Token"
    PRIVATE_KEY_RSA = "RSA Private Key"
    PRIVATE_KEY_EC = "EC Private Key"
    PRIVATE_KEY_PGP = "PGP Private Key"
    GENERIC_API_KEY = "Generic API Key"
    GENERIC_SECRET = "Generic Secret"
    GENERIC_TOKEN = "Generic Token"
    BASIC_AUTH = "Basic Auth Credential"
    BEARER_TOKEN = "Bearer Token"
    PASSWORD_IN_URL = "Password in URL"
    DATABASE_URL = "Database Connection URL"
    INTERNAL_IP = "Internal IP Address"
    INTERNAL_URL = "Internal URL / Endpoint"
    S3_BUCKET = "S3 Bucket Reference"
    GRAPHQL_ENDPOINT = "GraphQL Endpoint"
    HARDCODED_USERNAME = "Hardcoded Username"
    HARDCODED_PASSWORD = "Hardcoded Password"
    ENV_VARIABLE = "Environment Variable Leak"
    DEBUG_FLAG = "Debug / Verbose Flag Enabled"
    SOURCEMAP = "Source Map Reference"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SECRET_SEVERITY: dict[SecretType, Severity] = {
    SecretType.AWS_ACCESS_KEY: Severity.CRITICAL,
    SecretType.AWS_SECRET_KEY: Severity.CRITICAL,
    SecretType.AWS_SESSION_TOKEN: Severity.CRITICAL,
    SecretType.GCP_SERVICE_ACCOUNT: Severity.CRITICAL,
    SecretType.AZURE_CONNECTION_STRING: Severity.CRITICAL,
    SecretType.STRIPE_KEY_LIVE: Severity.CRITICAL,
    SecretType.PRIVATE_KEY_RSA: Severity.CRITICAL,
    SecretType.PRIVATE_KEY_EC: Severity.CRITICAL,
    SecretType.PRIVATE_KEY_PGP: Severity.CRITICAL,
    SecretType.DATABASE_URL: Severity.CRITICAL,
    SecretType.GCP_API_KEY: Severity.HIGH,
    SecretType.AZURE_CLIENT_SECRET: Severity.HIGH,
    SecretType.GITHUB_TOKEN: Severity.HIGH,
    SecretType.GITHUB_OAUTH: Severity.HIGH,
    SecretType.GITLAB_TOKEN: Severity.HIGH,
    SecretType.SENDGRID_KEY: Severity.HIGH,
    SecretType.TWILIO_AUTH: Severity.HIGH,
    SecretType.SLACK_TOKEN: Severity.HIGH,
    SecretType.DISCORD_TOKEN: Severity.HIGH,
    SecretType.TELEGRAM_BOT: Severity.HIGH,
    SecretType.FIREBASE_KEY: Severity.HIGH,
    SecretType.JWT_TOKEN: Severity.HIGH,
    SecretType.BEARER_TOKEN: Severity.HIGH,
    SecretType.STRIPE_KEY_TEST: Severity.MEDIUM,
    SecretType.STRIPE_WEBHOOK: Severity.MEDIUM,
    SecretType.TWILIO_ACCOUNT: Severity.MEDIUM,
    SecretType.SLACK_WEBHOOK: Severity.MEDIUM,
    SecretType.DISCORD_WEBHOOK: Severity.MEDIUM,
    SecretType.BASIC_AUTH: Severity.MEDIUM,
    SecretType.PASSWORD_IN_URL: Severity.MEDIUM,
    SecretType.HARDCODED_PASSWORD: Severity.MEDIUM,
    SecretType.FIREBASE_URL: Severity.MEDIUM,
    SecretType.S3_BUCKET: Severity.MEDIUM,
    SecretType.INTERNAL_URL: Severity.MEDIUM,
    SecretType.GRAPHQL_ENDPOINT: Severity.MEDIUM,
    SecretType.GENERIC_API_KEY: Severity.MEDIUM,
    SecretType.GENERIC_SECRET: Severity.MEDIUM,
    SecretType.GENERIC_TOKEN: Severity.LOW,
    SecretType.INTERNAL_IP: Severity.LOW,
    SecretType.HARDCODED_USERNAME: Severity.LOW,
    SecretType.ENV_VARIABLE: Severity.LOW,
    SecretType.DEBUG_FLAG: Severity.LOW,
    SecretType.SOURCEMAP: Severity.INFO,
}

SECRET_PATTERNS: list[tuple[SecretType, re.Pattern]] = [
    (SecretType.AWS_ACCESS_KEY,     re.compile(r"(?<![A-Z0-9])(AKIA|ASIA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")),
    (SecretType.AWS_SECRET_KEY,     re.compile(r"(?i)aws.{0,30}secret.{0,10}['\"]([A-Za-z0-9/+=]{40})['\"]")),
    (SecretType.AWS_SESSION_TOKEN,  re.compile(r"(?i)aws.session.token.{0,10}['\"]([A-Za-z0-9/+=]{100,})['\"]")),
    (SecretType.GCP_API_KEY,        re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    (SecretType.GCP_SERVICE_ACCOUNT, re.compile(r'"type"\s*:\s*"service_account"')),
    (SecretType.AZURE_CLIENT_SECRET, re.compile(r"(?i)azure.{0,30}(client.secret|client_secret|clientsecret).{0,10}['\"]([A-Za-z0-9~._\-]{30,})['\"]")),
    (SecretType.AZURE_CONNECTION_STRING, re.compile(r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}")),
    (SecretType.GITHUB_TOKEN,       re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}")),
    (SecretType.GITHUB_OAUTH,       re.compile(r"github.{0,30}['\"]([a-f0-9]{40})['\"]")),
    (SecretType.GITLAB_TOKEN,       re.compile(r"glpat-[A-Za-z0-9\-_]{20}")),
    (SecretType.STRIPE_KEY_LIVE,    re.compile(r"sk_live_[0-9A-Za-z]{24,}")),
    (SecretType.STRIPE_KEY_TEST,    re.compile(r"sk_test_[0-9A-Za-z]{24,}")),
    (SecretType.STRIPE_WEBHOOK,     re.compile(r"whsec_[A-Za-z0-9]+")),
    (SecretType.SENDGRID_KEY,       re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}")),
    (SecretType.TWILIO_ACCOUNT,     re.compile(r"AC[a-z0-9]{32}")),
    (SecretType.TWILIO_AUTH,        re.compile(r"(?i)twilio.{0,30}['\"]([a-z0-9]{32})['\"]")),
    (SecretType.SLACK_TOKEN,        re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    (SecretType.SLACK_WEBHOOK,      re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    (SecretType.DISCORD_TOKEN,      re.compile(r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}")),
    (SecretType.DISCORD_WEBHOOK,    re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+")),
    (SecretType.TELEGRAM_BOT,       re.compile(r"[0-9]{8,10}:[A-Za-z0-9\-_]{35}")),
    (SecretType.FIREBASE_KEY,       re.compile(r"(?i)firebase.{0,30}['\"]([A-Za-z0-9\-_]{39})['\"]")),
    (SecretType.FIREBASE_URL,       re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")),
    (SecretType.JWT_TOKEN,          re.compile(r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*")),
    (SecretType.PRIVATE_KEY_RSA,    re.compile(r"-----BEGIN RSA PRIVATE KEY-----")),
    (SecretType.PRIVATE_KEY_EC,     re.compile(r"-----BEGIN EC PRIVATE KEY-----")),
    (SecretType.PRIVATE_KEY_PGP,    re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----")),
    (SecretType.BASIC_AUTH,         re.compile(r"(?i)(Authorization|auth)\s*[:=]\s*['\"]?Basic\s+[A-Za-z0-9+/=]{8,}['\"]?")),
    (SecretType.BEARER_TOKEN,       re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.~+/=]{20,}")),
    (SecretType.PASSWORD_IN_URL,    re.compile(r"[a-zA-Z]+://[^:@\s]+:[^@\s]{4,}@[^\s'\"]+")),
    (SecretType.DATABASE_URL,       re.compile(r"(?i)(mongodb(\+srv)?|postgres|postgresql|mysql|redis|mssql|sqlserver|oracle|jdbc)://[^\s'\"]+")),
    (SecretType.S3_BUCKET,          re.compile(r"(?i)(s3\.amazonaws\.com/[a-z0-9\-_.]+|[a-z0-9\-_.]+\.s3\.amazonaws\.com)")),
    (SecretType.GRAPHQL_ENDPOINT,   re.compile(r"(?i)['\"/]graphql['\"/]")),
    (SecretType.INTERNAL_IP,        re.compile(r"(?<!\d)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)")),
    (SecretType.INTERNAL_URL,       re.compile(r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|internal|intranet|corp|staging|dev|test)[^\s'\",]*")),
    (SecretType.GENERIC_API_KEY,    re.compile(r"(?i)(api[_\-\s]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9\-_]{16,64})['\"]")),
    (SecretType.GENERIC_SECRET,     re.compile(r"(?i)(secret|secret[_\-]?key)\s*[:=]\s*['\"]([A-Za-z0-9\-_/+=]{8,64})['\"]")),
    (SecretType.GENERIC_TOKEN,      re.compile(r"(?i)(token|access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['\"]([A-Za-z0-9\-_./+=]{16,128})['\"]")),
    (SecretType.HARDCODED_USERNAME,  re.compile(r"(?i)(username|user|login)\s*[:=]\s*['\"]([a-zA-Z0-9_\-@.]{3,32})['\"]")),
    (SecretType.HARDCODED_PASSWORD,  re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^\s'\"]{4,64})['\"]")),
    (SecretType.ENV_VARIABLE,       re.compile(r"process\.env\.[A-Z_][A-Z0-9_]{2,}")),
    (SecretType.DEBUG_FLAG,         re.compile(r"(?i)(debug|verbose|isDev|devMode|development)\s*[:=]\s*(true|1|\"true\"|'true')")),
    (SecretType.SOURCEMAP,          re.compile(r"//[#@]\s*sourceMappingURL=(.+\.map)")),
]

FALSE_POSITIVE_PATTERNS = [
    re.compile(r"^(example|test|placeholder|your|my|sample|dummy|fake|xxx+|000+)$", re.I),
    re.compile(r"^[a-z]{1,4}$", re.I),
    re.compile(r"^\*+$"),
    re.compile(r"^<[^>]+>$"),
    re.compile(r"^\$\{[^}]+\}$"),
    re.compile(r"^__[A-Z_]+__$"),
]

JS_URL_PATTERNS = [
    re.compile(r"""<script[^>]+src=['"]([^'"]+\.js(?:\?[^'"]*)?)['"]\s*""", re.I),
    re.compile(r"""(?:import|require)\s*\(?['"]([^'"]+\.js(?:\?[^'"]*)?)['"]"""),
    re.compile(r"""['"]([^'"]+\.js(?:\?[^'"]*)?)['"]"""),
]

INLINE_SCRIPT_PATTERN = re.compile(
    r"<script(?:\s[^>]*)?>(.+?)</script>", re.DOTALL | re.IGNORECASE
)

SOURCEMAP_URL_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL=(.+\.map)")


@dataclass
class SecretFinding:
    secret_type: SecretType
    severity: Severity
    raw_match: str
    context: str
    source_url: str
    line_number: int
    column: int
    fingerprint: str


@dataclass
class JSFile:
    url: str
    content: str
    size_bytes: int
    status_code: int
    sourcemap_url: Optional[str]
    fetch_error: Optional[str] = None


@dataclass
class ExtractionReport:
    target_url: str
    js_files_found: int
    js_files_fetched: int
    total_findings: int
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings: list[SecretFinding] = field(default_factory=list)
    js_files: list[JSFile] = field(default_factory=list)
    sourcemaps_found: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


def _make_fingerprint(secret_type: SecretType, raw_match: str) -> str:
    return hashlib.sha256(f"{secret_type.value}:{raw_match}".encode()).hexdigest()[:16]


def _get_context(content: str, pos: int, window: int = 80) -> str:
    start = max(0, pos - window)
    end = min(len(content), pos + window)
    snippet = content[start:end].replace("\n", " ").replace("\r", "")
    return snippet.strip()


def _get_line_col(content: str, pos: int) -> tuple[int, int]:
    before = content[:pos]
    line = before.count("\n") + 1
    col = pos - before.rfind("\n") - 1
    return line, col


def _is_false_positive(value: str) -> bool:
    v = value.strip()
    for pattern in FALSE_POSITIVE_PATTERNS:
        if pattern.match(v):
            return True
    if len(set(v)) <= 2 and len(v) > 4:
        return True
    return False
    
    
def _scan_content(content: str, source_url: str) -> list[SecretFinding]:
    findings: list[SecretFindings] = []
    seen: set[str] = set()
    
    for secret_type, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(content):
            raw = m.group(0)
            matched_groups = m.groups()
            representative = matched_groups[-1] if matched_groups else raw
            
            if _is_false_positive(representative):
                continue
                
            fp = _make_fingerprint(secret_type, raw)
            if fp in seen:
                continue
            seen.add(fp)
            
            line, col = _get_line_col(content, m.start())
            context = _get_context(content, m.start())
            severity = SECRET_SEVERITY.get(secret_type, Severity.INFO)
            
            findings.append(SecretFinding(
                secret_type=secret_type,
                severity=severity,
                raw_match=raw[:200],
                context=context,
                source_url=source_url,
                line_number=line,
                column=col,
                fingerprint=fp,
            ))
            
    return findings
    
    
def _extract_js_urls(html: str, base_url: str) -> list[str]:
    urls: set[str] = set()
    parsed_base = urlparse(base_url)
    
    for m in JS_URL_PATTERNS[0].finditer(html):
        raw = m.group(1).strip()
        if raw and not raw.startswith("data:"):
            urls.add(urljoin(base_url, raw))
            
    for m in INLINE_SCRIPT_PATTERN.finditer(html):
        inner = m.group(1)
        for pattern in JS_URL_PATTERNS[1:]:
            for m2 in pattern.finditer(inner):
                raw = m2.group(1).strip()
                if raw and not raw.startswith("data:") and not raw.startswith("//"):
                    candidate = urljoin(base_url, raw)
                    c_parsed = urlparse(candidate)
                    if c_parsed.netloc == parsed_base.netloc:
                        urls.add(candidate)
                
    filtered = set()
    for u in urls:
        p = urlparse(u)
        if p.netloc == parsed_base.netloc and p.path.endswith(".js"):
            filtered.add(u)
        elif p.scheme in ("http", "https") and ".js" in p.path:
            filtered.add(u)
            
    return list(filtered)
    
    
def _extract_sourcemap_url(content: str, js_url: str) -> Optional[str]:
    m = SOURCEMAP_URL_PATTERN.search(content[-2000:])
    if not m:
        return None
    raw = m.group(1).strip()
    if raw.startswith("data:"):
        return None
    return urljoin(js_url, raw)
    
    
async def _fetch_url(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict,
    semaphore: asyncio.Semaphore,
    max_size: int = 5 * 1024 * 1024,
) -> tuple[int, str, Optional[str]]:
    async with semaphore:
        try:
            async with session.get(
                url,
                headers=headers,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False,
            ) as resp:
                status = resp.status
                if status != 200:
                    return status, "", None
                raw = await resp.read()
                if len(raw) > max_size:
                    raw = raw[:max_size]
                try:
                    content = raw.decode("utf-8", errors="ignore")
                except Exception:
                    content = ""
                return status, content, None
        except asyncio.TimeoutError:
            return 0, "", "timeout"
        except Exception as e:
            return -1, "", str(e)[:120]
            
            
async def _fetch_js_file(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict,
    semaphore: asyncio.Semaphore,
) -> JSFile:
    status, content, error = await _fetch_url(session, url, headers, semaphore)
    sourcemap_url = None
    if content:
        sourcemap_url = _extract_sourcemap_url(content, url)
    return JSFile(
        url=url,
        content=content,
        size_bytes=len(content.encode("utf-8", errors="ignore")),
        status_code=status,
        sourcemap_url=sourcemap_url,
        fetch_error=error,
    )


async def _fetch_sourcemap(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict,
    semaphore: asyncio.Semaphore,
) -> Optional[str]:
    status, content, _ = await _fetch_url(session, url, headers, semaphore, max_size=10 * 1024 * 1024)
    if status == 200 and content:
        return content
    return None


def _extract_js_from_sourcemap(sourcemap_content: str, sourcemap_url: str) -> list[tuple[str, str]]:
    import json
    results: list[tuple[str, str]] = []
    try:
        data = json.loads(sourcemap_content)
        sources = data.get("sources", [])
        sources_content = data.get("sourcesContent", [])
        for i, src in enumerate(sources):
            src_content = sources_content[i] if i < len(sources_content) else None
            if src_content:
                full_url = urljoin(sourcemap_url, src)
                results.append((full_url, src_content))
    except Exception:
        pass
    return results


class JSSecretExtractor:
    def __init__(
        self,
        concurrency: int = 10,
        max_js_files: int = 100,
        follow_sourcemaps: bool = True,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        self.concurrency = concurrency
        self.max_js_files = max_js_files
        self.follow_sourcemaps = follow_sourcemaps
        self.base_headers = {
            "User-Agent": user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        }

    async def run(self, target_url: str) -> ExtractionReport:
        t_start = time.monotonic()
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        semaphore = asyncio.Semaphore(self.concurrency)