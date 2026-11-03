import os
import re
import time
import hashlib
import itertools
import threading
import urllib.parse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


_WORDLIST_DIR = Path(__file__).parent.parent / "wordlists"


def _load_wordlists(directory: Path) -> List[str]:
    """
    Read every .txt file in *directory*, merge lines, deduplicate,
    strip comments (#) and blank lines.  Returns a sorted word list.
    Falls back to a minimal built-in set if the folder is missing or empty.
    """
    words: Set[str] = set()
    
    if directory.is_dir():
        txt_files = sorted(directory.glob("*.txt"))
        for txt in txt_files:
            try:
                with open(txt, "r", encoding="utf-8", errors="ignore") as fh:
                    for raw in fh:
                        word = raw.strip()
                        if word and not word.startswith("#"):
                            words.add(word.lstrip("/"))
                print(f"[wordlist] loaded {txt.name} ({len(words)} unique so far)")
            except OSError as exc:
                print(f"[wordlist] could not read {txt}: {exc}")
                
    if not words:
        # Minimal fallback — keeps the scanner functional without wordlists on disk
        words = {
            "admin", "login", "api", "api/v1", "api/v2", "backup",
            "config", "console", "dashboard", "debug", "dev", "docs",
            "env", "health", "hidden", "images", "includes", "index",
            "info", "js", "lib", "logs", "old", "panel", "phpmyadmin",
            "private", "scripts", "secret", "server-status", "setup",
            "sql", "static", "swagger", "temp", "test", "tmp", "upload",
            "uploads", "user", "users", "v1", "v2", "wp-admin", "xmlrpc.php",
        }
        print("[wordlist] directory missing or empty — using built-in fallback")

    return sorted(words)
    
    
# ---------------------------------------------------------------------------
# HTTP session factory
# ---------------------------------------------------------------------------

def _build_session(proxy: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=1, backoff_factor=0.2, status_forcelist=[])
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=30,
        pool_maxsize=60,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "curl/8.7.1",
]


def _ua() -> str:
    import random
    return random.choice(_UA_POOL)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BruteResult:
    url: str
    word: str
    status: int
    content_length: int
    redirect_to: Optional[str]
    content_type: Optional[str]
    interesting: bool           # heuristic flag
    extensions_tried: List[str] = field(default_factory=list)


@dataclass
class ScanProfile:
    """Encapsulates all scan-time settings so nothing is passed around as kwargs."""
    base_url: str
    extensions: List[str]
    exclude_codes: Set[int]
    exclude_lengths: Set[int]
    timeout: float
    follow_redirects: bool
    recursive: bool
    recursion_depth: int
    interesting_codes: Set[int]
    rate_delay: float           # seconds between requests per worker (0 = off)


# ---------------------------------------------------------------------------
# Baseline & false-positive filtering
# ---------------------------------------------------------------------------

def _fetch_baseline(session: requests.Session, base_url: str,
                    timeout: float) -> Tuple[int, Set[int]]:
    """
    Request two guaranteed-random paths to establish the 'not found' fingerprint.
    Returns (typical_404_length, set_of_wildcard_lengths).
    """
    wildcard_lengths: Set[int] = set()
    canaries = [
        f"{base_url}/artex_canary_{hashlib.md5(b'a').hexdigest()[:8]}",
        f"{base_url}/artex_canary_{hashlib.md5(b'b').hexdigest()[:8]}/",
    ]
    for url in canaries:
        try:
            r = session.get(url, headers={"User-Agent": _ua()},
                            timeout=timeout, allow_redirects=True)
            wildcard_lengths.add(len(r.content))
        except requests.RequestException:
            pass

    typical = min(wildcard_lengths) if wildcard_lengths else 0
    return typical, wildcard_lengths


def _is_false_positive(length: int, status: int,
                        wildcard_lengths: Set[int],
                        exclude_lengths: Set[int]) -> bool:
    """
    True when the response almost certainly represents a wildcard 404-catchall
    or an explicitly excluded length.
    """
    if length in exclude_lengths:
        return True
    # Allow ±32-byte variance around each wildcard length
    for wl in wildcard_lengths:
        if abs(length - wl) <= 32:
            return True
    return False


# ---------------------------------------------------------------------------
# Request worker
# ---------------------------------------------------------------------------

def _probe(session: requests.Session, url: str, profile: ScanProfile,
           wildcard_lengths: Set[int]) -> Optional[BruteResult]:
    """
    Send a single GET request and decide whether the response is interesting.
    Returns None if the response should be discarded.
    """
    if profile.rate_delay > 0:
        time.sleep(profile.rate_delay)

    try:
        resp = session.get(
            url,
            headers={"User-Agent": _ua()},
            timeout=profile.timeout,
            allow_redirects=profile.follow_redirects,
        )
    except requests.RequestException:
        return None

    if resp.status_code in profile.exclude_codes:
        return None

    cl = len(resp.content)
    if _is_false_positive(cl, resp.status_code, wildcard_lengths, profile.exclude_lengths):
        return None

    redirect_to = None
    if resp.status_code in (301, 302, 303, 307, 308):
        redirect_to = resp.headers.get("Location")

    ct = resp.headers.get("Content-Type", "").split(";")[0].strip()
    interesting = resp.status_code in profile.interesting_codes

    return BruteResult(
        url=url,
        word=url.split("/")[-1] or url.split("/")[-2],
        status=resp.status_code,
        content_length=cl,
        redirect_to=redirect_to,
        content_type=ct,
        interesting=interesting,
    )


# ---------------------------------------------------------------------------
# URL generator
# ---------------------------------------------------------------------------

def _url_stream(base: str, words: List[str],
                extensions: List[str]) -> Iterator[Tuple[str, str]]:
    """
    Yield (url, bare_word) pairs for every word × extension combination.
    An empty string in *extensions* represents the bare path (no extension).
    """
    base = base.rstrip("/")
    for word in words:
        word = word.strip("/")
        for ext in extensions:
            path = word if not ext else f"{word}.{ext}"
            yield f"{base}/{path}", word

        # Always probe the directory form regardless of extensions
        yield f"{base}/{word}/", word


# ---------------------------------------------------------------------------
# Recursive engine
# ---------------------------------------------------------------------------

def _scan_layer(session: requests.Session,
                base_url: str,
                words: List[str],
                profile: ScanProfile,
                wildcard_lengths: Set[int],
                depth: int,
                found: List[BruteResult],
                lock: threading.Lock,
                max_workers: int) -> None:
    """
    Brute-force one URL layer in parallel.  If *profile.recursive* is True,
    successful directory hits are fed back into a new layer up to
    *profile.recursion_depth*.
    """
    urls = list(_url_stream(base_url, words, profile.extensions))
    next_dirs: List[str] = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures: Dict = {
            ex.submit(_probe, session, url, profile, wildcard_lengths): (url, word)
            for url, word in urls
        }
        for future in as_completed(futures):
            result = future.result()
            if result is None:
                continue
            url, word = futures[future]

            with lock:
                found.append(result)

            print(
                f"  [{result.status}] {result.url:<60} "
                f"{result.content_length:>8} bytes"
                + (f"  → {result.redirect_to}" if result.redirect_to else "")
            )

            # Queue directory hits for next recursion layer
            if (profile.recursive
                    and depth < profile.recursion_depth
                    and result.status in (200, 301, 302, 403)
                    and (url.endswith("/") or result.redirect_to and result.redirect_to.endswith("/"))):
                next_dirs.append(url.rstrip("/") + "/")

    # Recurse into discovered directories
    for next_base in dict.fromkeys(next_dirs):  # deduplicate, preserve order
        # Re-baseline for the sub-path (it may have different wildcard behaviour)
        _, sub_wildcards = _fetch_baseline(session, next_base.rstrip("/"), profile.timeout)
        _scan_layer(
            session, next_base.rstrip("/"), words, profile,
            sub_wildcards, depth + 1, found, lock, max_workers,
        )


# ---------------------------------------------------------------------------
# Content-type & interesting-path heuristics
# ---------------------------------------------------------------------------

_INTERESTING_CONTENT_TYPES = {
    "application/json", "application/xml", "text/xml",
    "application/x-www-form-urlencoded", "application/octet-stream",
}

_SENSITIVE_WORD_PATTERN = re.compile(
    r"(backup|config|secret|password|passwd|credential|token|"
    r"private|admin|shadow|dump|sql|env|key|\.git|\.env|"
    r"swagger|openapi|phpinfo|server-status)",
    re.I,
)


def _annotate_interesting(results: List[BruteResult]) -> None:
    """Post-pass: mark additional results as interesting based on content-type
    and path keywords, so the caller can surface them first."""
    for r in results:
        if r.content_type in _INTERESTING_CONTENT_TYPES:
            r.interesting = True
        if _SENSITIVE_WORD_PATTERN.search(r.url):
            r.interesting = True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class DirectoryBruteforcer:
    """
    Wordlist-driven directory and file brute-forcer.

    Usage in app.py:
        brute = DirectoryBruteforcer(target_url=f"https://{domain}")
        results = brute.scan()
        scan_results[scan_id]['dir_bruteforce'] = results
    """

    DEFAULT_EXTENSIONS = ["php", "html", "js", "json", "txt", "bak", "zip", "xml", ""]
    DEFAULT_EXCLUDE_CODES = {404, 429}
    DEFAULT_INTERESTING_CODES = {200, 201, 204, 301, 302, 401, 403, 500}

    def __init__(
        self,
        target_url: str,
        wordlist_dir: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        exclude_codes: Optional[Set[int]] = None,
        exclude_lengths: Optional[Set[int]] = None,
        timeout: float = 6.0,
        follow_redirects: bool = True,
        recursive: bool = False,
        recursion_depth: int = 2,
        max_workers: int = 20,
        rate_delay: float = 0.0,
        proxy: Optional[str] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.wordlist_dir = Path(wordlist_dir) if wordlist_dir else _WORDLIST_DIR
        self.max_workers = max_workers
        self.proxy = proxy

        self.profile = ScanProfile(
            base_url=self.target_url,
            extensions=extensions if extensions is not None else self.DEFAULT_EXTENSIONS,
            exclude_codes=exclude_codes if exclude_codes is not None else self.DEFAULT_EXCLUDE_CODES,
            exclude_lengths=exclude_lengths or set(),
            timeout=timeout,
            follow_redirects=follow_redirects,
            recursive=recursive,
            recursion_depth=recursion_depth,
            interesting_codes=self.DEFAULT_INTERESTING_CODES,
            rate_delay=rate_delay,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_words(self) -> List[str]:
        return _load_wordlists(self.wordlist_dir)

    # ------------------------------------------------------------------
    # Public scan entry point
    # ------------------------------------------------------------------

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = _build_session(self.proxy)
        words = self._load_words()

        print(f"[dir_bruteforce] target  : {self.target_url}")
        print(f"[dir_bruteforce] words   : {len(words)}")
        print(f"[dir_bruteforce] exts    : {self.profile.extensions}")
        print(f"[dir_bruteforce] workers : {self.max_workers}")

        # Baseline — used for false-positive filtering throughout
        typical_len, wildcard_lengths = _fetch_baseline(
            session, self.target_url, self.profile.timeout
        )
        # Add baseline lengths to the explicit exclude set so callers
        # can also pass extra sizes they want suppressed
        self.profile.exclude_lengths.update(wildcard_lengths)

        found: List[BruteResult] = []
        lock = threading.Lock()

        t0 = time.monotonic()
        _scan_layer(
            session=session,
            base_url=self.target_url,
            words=words,
            profile=self.profile,
            wildcard_lengths=wildcard_lengths,
            depth=0,
            found=found,
            lock=lock,
            max_workers=self.max_workers,
        )
        elapsed = time.monotonic() - t0

        _annotate_interesting(found)

        # Split output into tiers
        interesting = [r for r in found if r.interesting]
        other = [r for r in found if not r.interesting]

        # Sort each tier: interesting first, then by status code
        interesting.sort(key=lambda r: (r.status, r.url))
        other.sort(key=lambda r: (r.status, r.url))
        ordered = interesting + other

        return {
            "target": self.target_url,
            "words_tested": len(words),
            "extensions": self.profile.extensions,
            "total_found": len(ordered),
            "interesting_count": len(interesting),
            "elapsed_seconds": round(elapsed, 2),
            "results": [self._serialize(r) for r in ordered],
        }

    @staticmethod
    def _serialize(r: BruteResult) -> Dict:
        return {
            "url": r.url,
            "status": r.status,
            "content_length": r.content_length,
            "content_type": r.content_type,
            "redirect_to": r.redirect_to,
            "interesting": r.interesting,
        }