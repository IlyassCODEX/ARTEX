# utils/ai_vuln_scorer.py
import hashlib
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class VulnClass(Enum):
    CORS_MISCONFIGURATION   = "cors_misconfiguration"
    OPEN_REDIRECT           = "open_redirect"
    HEADER_INJECTION        = "header_injection"
    SSRF                    = "ssrf"
    JS_SECRET_EXPOSURE      = "js_secret_exposure"
    WAF_BYPASS              = "waf_bypass"
    CREDENTIAL_EXPOSURE     = "credential_exposure"
    REDIRECT_CHAIN          = "redirect_chain"
    PAYLOAD_BYPASS          = "payload_bypass"
    AUTH_BYPASS             = "auth_bypass"
    SESSION_THEFT           = "session_theft"
    INFORMATION_DISCLOSURE  = "information_disclosure"
    TIMING_ORACLE           = "timing_oracle"
    CRLF_INJECTION          = "crlf_injection"
    BLIND_SSRF              = "blind_ssrf"
    CLOUD_METADATA          = "cloud_metadata"
    INTERNAL_SERVICE        = "internal_service"
    XSS_REFLECTED           = "xss_reflected"
    SQLI_ERROR              = "sqli_error"
    SSTI                    = "ssti"
    PATH_TRAVERSAL          = "path_traversal"
    CMD_INJECTION           = "cmd_injection"


class CVSSVector(Enum):
    AV_NETWORK   = "AV:N"
    AV_ADJACENT  = "AV:A"
    AV_LOCAL     = "AV:L"
    AC_LOW       = "AC:L"
    AC_HIGH      = "AC:H"
    PR_NONE      = "PR:N"
    PR_LOW       = "PR:L"
    PR_HIGH      = "PR:H"
    UI_NONE      = "UI:N"
    UI_REQUIRED  = "UI:R"
    S_CHANGED    = "S:C"
    S_UNCHANGED  = "S:U"
    C_HIGH       = "C:H"
    C_LOW        = "C:L"
    C_NONE       = "C:N"
    I_HIGH       = "I:H"
    I_LOW        = "I:L"
    I_NONE       = "I:N"
    A_HIGH       = "A:H"
    A_LOW        = "A:L"
    A_NONE       = "A:N"


class ExploitMaturity(Enum):
    CONFIRMED       = "confirmed"
    PROOF_OF_CONCEPT = "proof_of_concept"
    THEORETICAL     = "theoretical"
    UNPROVEN        = "unproven"


class AttackComplexity(Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"


class ImpactDomain(Enum):
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY       = "integrity"
    AVAILABILITY    = "availability"
    AUTH            = "authentication"
    LATERAL         = "lateral_movement"
    EXFILTRATION    = "data_exfiltration"


@dataclass
class CVSSScore:
    base_score: float
    vector_string: str
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality: str
    integrity: str
    availability: str


@dataclass
class ChainLink:
    source_vuln_id: str
    target_vuln_id: str
    chain_type: str
    amplification: float
    description: str


@dataclass
class ScoredVuln:
    vuln_id: str
    vuln_class: VulnClass
    source_module: str
    title: str
    description: str
    raw_severity: str
    cvss: CVSSScore
    exploit_maturity: ExploitMaturity
    attack_complexity: AttackComplexity
    impact_domains: list[ImpactDomain]
    weighted_score: float
    chaining_potential: float
    composite_score: float
    evidence: list[str]
    affected_param: str
    affected_url: str
    remediation: str
    mitre_techniques: list[str]
    chain_links: list[ChainLink] = field(default_factory=list)


@dataclass
class AttackPath:
    path_id: str
    steps: list[ScoredVuln]
    total_score: float
    entry_point: str
    impact_summary: list[ImpactDomain]
    narrative: str
    exploitability_rating: str


@dataclass
class ScorerReport:
    target_url: str
    total_vulns: int
    scored_vulns: list[ScoredVuln]
    attack_paths: list[AttackPath]
    top_findings: list[ScoredVuln]
    impact_coverage: dict[str, int]
    severity_distribution: dict[str, int]
    module_coverage: list[str]
    red_team_narrative: str
    overall_risk_score: float
    duration_seconds: float


CVSS_PROFILES: dict[VulnClass, CVSSScore] = {
    VulnClass.SSRF: CVSSScore(
        base_score=9.8, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="CHANGED",
        confidentiality="HIGH", integrity="HIGH", availability="HIGH",
    ),
    VulnClass.CLOUD_METADATA: CVSSScore(
        base_score=10.0, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="CHANGED",
        confidentiality="HIGH", integrity="HIGH", availability="HIGH",
    ),
    VulnClass.BLIND_SSRF: CVSSScore(
        base_score=7.5, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="UNCHANGED",
        confidentiality="HIGH", integrity="NONE", availability="NONE",
    ),
    VulnClass.CORS_MISCONFIGURATION: CVSSScore(
        base_score=8.1, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="REQUIRED", scope="CHANGED",
        confidentiality="HIGH", integrity="LOW", availability="NONE",
    ),
    VulnClass.OPEN_REDIRECT: CVSSScore(
        base_score=6.1, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="REQUIRED", scope="CHANGED",
        confidentiality="LOW", integrity="LOW", availability="NONE",
    ),
    VulnClass.HEADER_INJECTION: CVSSScore(
        base_score=7.2, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="CHANGED",
        confidentiality="LOW", integrity="HIGH", availability="NONE",
    ),
    VulnClass.CRLF_INJECTION: CVSSScore(
        base_score=7.2, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="CHANGED",
        confidentiality="LOW", integrity="HIGH", availability="NONE",
    ),
    VulnClass.JS_SECRET_EXPOSURE: CVSSScore(
        base_score=7.5, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="UNCHANGED",
        confidentiality="HIGH", integrity="NONE", availability="NONE",
    ),
    VulnClass.CREDENTIAL_EXPOSURE: CVSSScore(
        base_score=9.1, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="CHANGED",
        confidentiality="HIGH", integrity="HIGH", availability="NONE",
    ),
    VulnClass.AUTH_BYPASS: CVSSScore(
        base_score=9.8, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="CHANGED",
        confidentiality="HIGH", integrity="HIGH", availability="HIGH",
    ),
    VulnClass.WAF_BYPASS: CVSSScore(
        base_score=5.3, vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        attack_vector="NETWORK", attack_complexity="HIGH", privileges_required="NONE",
        user_interaction="NONE", scope="UNCHANGED",
        confidentiality="LOW", integrity="LOW", availability="NONE",
    ),
    VulnClass.PAYLOAD_BYPASS: CVSSScore(
        base_score=6.5, vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N",
        attack_vector="NETWORK", attack_complexity="HIGH", privileges_required="NONE",
        user_interaction="NONE", scope="CHANGED",
        confidentiality="LOW", integrity="HIGH", availability="NONE",
    ),
    VulnClass.XSS_REFLECTED: CVSSScore(
        base_score=6.1, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="REQUIRED", scope="CHANGED",
        confidentiality="LOW", integrity="LOW", availability="NONE",
    ),
    VulnClass.SQLI_ERROR: CVSSScore(
        base_score=8.8, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="UNCHANGED",
        confidentiality="HIGH", integrity="HIGH", availability="HIGH",
    ),
    VulnClass.SSTI: CVSSScore(
        base_score=9.8, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="CHANGED",
        confidentiality="HIGH", integrity="HIGH", availability="HIGH",
    ),
    VulnClass.PATH_TRAVERSAL: CVSSScore(
        base_score=7.5, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="UNCHANGED",
        confidentiality="HIGH", integrity="NONE", availability="NONE",
    ),
    VulnClass.CMD_INJECTION: CVSSScore(
        base_score=10.0, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="CHANGED",
        confidentiality="HIGH", integrity="HIGH", availability="HIGH",
    ),
    VulnClass.INFORMATION_DISCLOSURE: CVSSScore(
        base_score=5.3, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="UNCHANGED",
        confidentiality="LOW", integrity="NONE", availability="NONE",
    ),
    VulnClass.TIMING_ORACLE: CVSSScore(
        base_score=5.9, vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        attack_vector="NETWORK", attack_complexity="HIGH", privileges_required="NONE",
        user_interaction="NONE", scope="UNCHANGED",
        confidentiality="HIGH", integrity="NONE", availability="NONE",
    ),
    VulnClass.SESSION_THEFT: CVSSScore(
        base_score=8.8, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="REQUIRED", scope="CHANGED",
        confidentiality="HIGH", integrity="HIGH", availability="NONE",
    ),
    VulnClass.INTERNAL_SERVICE: CVSSScore(
        base_score=8.6, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="NONE", scope="CHANGED",
        confidentiality="HIGH", integrity="LOW", availability="NONE",
    ),
    VulnClass.REDIRECT_CHAIN: CVSSScore(
        base_score=5.4, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE",
        user_interaction="REQUIRED", scope="UNCHANGED",
        confidentiality="LOW", integrity="LOW", availability="NONE",
    ),
}

IMPACT_MAP: dict[VulnClass, list[ImpactDomain]] = {
    VulnClass.SSRF:                 [ImpactDomain.CONFIDENTIALITY, ImpactDomain.LATERAL, ImpactDomain.EXFILTRATION],
    VulnClass.CLOUD_METADATA:       [ImpactDomain.CONFIDENTIALITY, ImpactDomain.LATERAL, ImpactDomain.EXFILTRATION, ImpactDomain.AUTH],
    VulnClass.BLIND_SSRF:           [ImpactDomain.CONFIDENTIALITY, ImpactDomain.LATERAL],
    VulnClass.CORS_MISCONFIGURATION:[ImpactDomain.CONFIDENTIALITY, ImpactDomain.AUTH, ImpactDomain.EXFILTRATION],
    VulnClass.OPEN_REDIRECT:        [ImpactDomain.AUTH, ImpactDomain.INTEGRITY],
    VulnClass.HEADER_INJECTION:     [ImpactDomain.INTEGRITY, ImpactDomain.LATERAL],
    VulnClass.CRLF_INJECTION:       [ImpactDomain.INTEGRITY, ImpactDomain.AUTH],
    VulnClass.JS_SECRET_EXPOSURE:   [ImpactDomain.CONFIDENTIALITY, ImpactDomain.AUTH, ImpactDomain.EXFILTRATION],
    VulnClass.CREDENTIAL_EXPOSURE:  [ImpactDomain.AUTH, ImpactDomain.CONFIDENTIALITY, ImpactDomain.LATERAL],
    VulnClass.AUTH_BYPASS:          [ImpactDomain.AUTH, ImpactDomain.LATERAL, ImpactDomain.CONFIDENTIALITY],
    VulnClass.WAF_BYPASS:           [ImpactDomain.INTEGRITY],
    VulnClass.PAYLOAD_BYPASS:       [ImpactDomain.INTEGRITY, ImpactDomain.CONFIDENTIALITY],
    VulnClass.XSS_REFLECTED:        [ImpactDomain.AUTH, ImpactDomain.CONFIDENTIALITY],
    VulnClass.SQLI_ERROR:           [ImpactDomain.CONFIDENTIALITY, ImpactDomain.INTEGRITY, ImpactDomain.EXFILTRATION],
    VulnClass.SSTI:                 [ImpactDomain.CONFIDENTIALITY, ImpactDomain.INTEGRITY, ImpactDomain.LATERAL],
    VulnClass.PATH_TRAVERSAL:       [ImpactDomain.CONFIDENTIALITY, ImpactDomain.EXFILTRATION],
    VulnClass.CMD_INJECTION:        [ImpactDomain.CONFIDENTIALITY, ImpactDomain.INTEGRITY, ImpactDomain.LATERAL, ImpactDomain.EXFILTRATION],
    VulnClass.INFORMATION_DISCLOSURE:[ImpactDomain.CONFIDENTIALITY],
    VulnClass.TIMING_ORACLE:        [ImpactDomain.CONFIDENTIALITY],
    VulnClass.SESSION_THEFT:        [ImpactDomain.AUTH, ImpactDomain.CONFIDENTIALITY],
    VulnClass.INTERNAL_SERVICE:     [ImpactDomain.LATERAL, ImpactDomain.CONFIDENTIALITY],
    VulnClass.REDIRECT_CHAIN:       [ImpactDomain.AUTH, ImpactDomain.INTEGRITY],
}

MITRE_MAP: dict[VulnClass, list[str]] = {
    VulnClass.SSRF:                 ["T1090.002", "T1210", "T1083"],
    VulnClass.CLOUD_METADATA:       ["T1552.005", "T1078.004", "T1530"],
    VulnClass.BLIND_SSRF:           ["T1090.002", "T1046"],
    VulnClass.CORS_MISCONFIGURATION:["T1539", "T1185"],
    VulnClass.OPEN_REDIRECT:        ["T1192", "T1566.002"],
    VulnClass.HEADER_INJECTION:     ["T1565.002", "T1557"],
    VulnClass.CRLF_INJECTION:       ["T1565.002", "T1557.001"],
    VulnClass.JS_SECRET_EXPOSURE:   ["T1552.001", "T1083"],
    VulnClass.CREDENTIAL_EXPOSURE:  ["T1552", "T1078"],
    VulnClass.AUTH_BYPASS:          ["T1078", "T1110"],
    VulnClass.WAF_BYPASS:           ["T1562.001", "T1027"],
    VulnClass.PAYLOAD_BYPASS:       ["T1562.001", "T1027.002"],
    VulnClass.XSS_REFLECTED:        ["T1185", "T1059.007"],
    VulnClass.SQLI_ERROR:           ["T1190", "T1552.001"],
    VulnClass.SSTI:                 ["T1059", "T1190"],
    VulnClass.PATH_TRAVERSAL:       ["T1083", "T1552.001"],
    VulnClass.CMD_INJECTION:        ["T1059", "T1203"],
    VulnClass.INFORMATION_DISCLOSURE:["T1083", "T1213"],
    VulnClass.TIMING_ORACLE:        ["T1110.004", "T1522"],
    VulnClass.SESSION_THEFT:        ["T1539", "T1185"],
    VulnClass.INTERNAL_SERVICE:     ["T1046", "T1210"],
    VulnClass.REDIRECT_CHAIN:       ["T1192"],
}

REMEDIATION_MAP: dict[VulnClass, str] = {
    VulnClass.SSRF:                 "Implement allowlist-based URL validation server-side. Block access to RFC1918 ranges and metadata endpoints at the network layer. Use SSRF-safe HTTP client libraries.",
    VulnClass.CLOUD_METADATA:       "Block outbound requests to 169.254.169.254 and metadata.google.internal at the network layer. Use IMDSv2 token-required mode on AWS. Rotate all IAM credentials immediately.",
    VulnClass.BLIND_SSRF:           "Block outbound DNS and HTTP to internal ranges. Enable egress filtering. Monitor for unexpected outbound connections.",
    VulnClass.CORS_MISCONFIGURATION:"Set Access-Control-Allow-Origin to an explicit allowlist. Never reflect the Origin header dynamically without validation. Remove wildcard + credentials combination.",
    VulnClass.OPEN_REDIRECT:        "Validate redirect targets against an allowlist of approved domains. Use relative paths for internal redirects. Add SSRF protection to any server-side URL fetch triggered by redirect params.",
    VulnClass.HEADER_INJECTION:     "Sanitize all user-supplied values used in response headers. Reject input containing CRLF characters. Use framework-level header-setting APIs that escape newlines.",
    VulnClass.CRLF_INJECTION:       "Strip \\r\\n from all user input before inserting into HTTP headers. Encode header values at the response layer.",
    VulnClass.JS_SECRET_EXPOSURE:   "Remove all secrets from client-side JS. Use server-side token exchange. Rotate all exposed credentials immediately. Audit build pipeline for secret leakage.",
    VulnClass.CREDENTIAL_EXPOSURE:  "Rotate exposed credentials immediately. Audit all authentication logs for unauthorized use. Enforce credential scanning in CI/CD.",
    VulnClass.AUTH_BYPASS:          "Review all authentication checks for logic flaws. Add server-side session validation. Remove client-controlled authentication state.",
    VulnClass.WAF_BYPASS:           "Tune WAF ruleset with vendor-specific bypass patterns. Enable anomaly scoring mode. Add application-layer input validation independent of WAF.",
    VulnClass.PAYLOAD_BYPASS:       "Implement defense-in-depth: WAF + application-level input validation + output encoding. Do not rely on WAF as sole control.",
    VulnClass.XSS_REFLECTED:        "HTML-encode all reflected user input. Implement Content-Security-Policy with nonce. Use framework-level auto-escaping.",
    VulnClass.SQLI_ERROR:           "Use parameterized queries / prepared statements exclusively. Suppress database error messages in production responses.",
    VulnClass.SSTI:                 "Never pass user input directly to template engines. Use sandboxed template environments. Upgrade to template engine versions with restricted execution.",
    VulnClass.PATH_TRAVERSAL:       "Canonicalize file paths before use. Validate that resolved path starts within the allowed base directory. Use chroot jails for file serving.",
    VulnClass.CMD_INJECTION:        "Never pass user input to shell commands. Use language-native APIs. If shell is unavoidable, use allowlist-based argument validation.",
    VulnClass.INFORMATION_DISCLOSURE:"Suppress stack traces and error details in production. Implement generic error pages. Audit response bodies for internal paths and version strings.",
    VulnClass.TIMING_ORACLE:        "Use constant-time comparison for secret validation. Add jitter to authentication responses to prevent timing measurement.",
    VulnClass.SESSION_THEFT:        "Set HttpOnly and Secure flags on session cookies. Implement SameSite=Strict. Rotate session tokens after privilege change.",
    VulnClass.INTERNAL_SERVICE:     "Enforce network segmentation. Block access to internal services from application tier. Use service mesh with mutual TLS.",
    VulnClass.REDIRECT_CHAIN:       "Limit redirect chain depth server-side. Log redirect chains. Validate final destination before following.",
}

CHAINING_PAIRS: dict[tuple[VulnClass, VulnClass], tuple[float, str]] = {
    (VulnClass.OPEN_REDIRECT,         VulnClass.SSRF):                 (0.95, "Open redirect used as SSRF pivot — attacker controls server-side fetch destination via trusted redirect parameter"),
    (VulnClass.OPEN_REDIRECT,         VulnClass.CORS_MISCONFIGURATION):(0.80, "Open redirect + CORS allows cross-origin credential theft via trusted-domain redirect chain"),
    (VulnClass.HEADER_INJECTION,      VulnClass.SSRF):                 (0.90, "Host/X-Forwarded-Host injection triggers internal SSRF on backend reverse proxy"),
    (VulnClass.HEADER_INJECTION,      VulnClass.CORS_MISCONFIGURATION):(0.75, "Injected Origin header poisons CORS response — cache poisoning attack on shared reverse proxy"),
    (VulnClass.CRLF_INJECTION,        VulnClass.SESSION_THEFT):        (0.85, "CRLF injection injects Set-Cookie into response — session fixation on victim's browser"),
    (VulnClass.JS_SECRET_EXPOSURE,    VulnClass.AUTH_BYPASS):          (0.92, "Hardcoded API key or JWT secret found in JS — directly used to forge auth tokens"),
    (VulnClass.JS_SECRET_EXPOSURE,    VulnClass.SSRF):                 (0.85, "Extracted internal endpoint from JS used as SSRF target — internal service URL confirmed"),
    (VulnClass.CORS_MISCONFIGURATION, VulnClass.JS_SECRET_EXPOSURE):   (0.78, "CORS misconfiguration allows attacker origin to read JS responses containing embedded secrets"),
    (VulnClass.CORS_MISCONFIGURATION, VulnClass.SESSION_THEFT):        (0.88, "CORS wildcard + credentials flag allows cross-origin read of authenticated API responses"),
    (VulnClass.SSRF,                  VulnClass.CLOUD_METADATA):       (0.98, "SSRF reaches cloud metadata endpoint — IAM credential extraction enables full cloud environment compromise"),
    (VulnClass.SSRF,                  VulnClass.INTERNAL_SERVICE):     (0.90, "SSRF reaches internal service (Redis/Elasticsearch/K8s API) — lateral movement within private network"),
    (VulnClass.CLOUD_METADATA,        VulnClass.CREDENTIAL_EXPOSURE):  (0.99, "Cloud metadata SSRF yields IAM role credentials — AWS/GCP account takeover path confirmed"),
    (VulnClass.AUTH_BYPASS,           VulnClass.SSRF):                 (0.95, "Post-auth SSRF with valid session bypasses IP-based access controls on internal endpoints"),
    (VulnClass.AUTH_BYPASS,           VulnClass.EXFILTRATION := VulnClass.JS_SECRET_EXPOSURE): (0.88, "Authenticated session enables access to admin API returning sensitive configuration"),
    (VulnClass.CREDENTIAL_EXPOSURE,   VulnClass.AUTH_BYPASS):          (0.97, "Valid credentials found — direct authentication bypass without exploit needed"),
    (VulnClass.WAF_BYPASS,            VulnClass.SQLI_ERROR):           (0.90, "WAF bypass unlocks SQLi vector — database error disclosure confirms injectable parameter"),
    (VulnClass.WAF_BYPASS,            VulnClass.SSTI):                 (0.88, "WAF bypass allows SSTI payload delivery — template engine RCE path confirmed"),
    (VulnClass.WAF_BYPASS,            VulnClass.XSS_REFLECTED):        (0.82, "WAF bypass enables XSS reflection — CSP absent, session theft via script injection"),
    (VulnClass.PAYLOAD_BYPASS,        VulnClass.CMD_INJECTION):        (0.92, "Payload mutation bypasses WAF and application filter — OS command injection confirmed"),
    (VulnClass.OPEN_REDIRECT,         VulnClass.AUTH_BYPASS):          (0.72, "Open redirect in OAuth callback flow — authorization code theft via redirect_uri manipulation"),
    (VulnClass.PATH_TRAVERSAL,        VulnClass.JS_SECRET_EXPOSURE):   (0.80, "Path traversal reads .env or config files — secrets exposed server-side"),
    (VulnClass.XSS_REFLECTED,         VulnClass.SESSION_THEFT):        (0.86, "Reflected XSS steals session cookie — account takeover without credential knowledge"),
    (VulnClass.TIMING_ORACLE,         VulnClass.AUTH_BYPASS):          (0.70, "Timing oracle on authentication endpoint reveals valid usernames for targeted attack"),
    (VulnClass.INFORMATION_DISCLOSURE,VulnClass.SSRF):                 (0.72, "Error disclosure reveals internal service URLs — SSRF targets confirmed without brute force"),
    (VulnClass.REDIRECT_CHAIN,        VulnClass.OPEN_REDIRECT):        (0.82, "Multi-hop redirect chain obscures final destination — open redirect detection bypassed by intermediary"),
}

SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 1.0,
    "high":     0.75,
    "medium":   0.45,
    "low":      0.20,
    "info":     0.05,
}

EXPLOITABILITY_WEIGHT: dict[ExploitMaturity, float] = {
    ExploitMaturity.CONFIRMED:          1.0,
    ExploitMaturity.PROOF_OF_CONCEPT:   0.75,
    ExploitMaturity.THEORETICAL:        0.40,
    ExploitMaturity.UNPROVEN:           0.20,
}

COMPLEXITY_WEIGHT: dict[AttackComplexity, float] = {
    AttackComplexity.LOW:    1.0,
    AttackComplexity.MEDIUM: 0.65,
    AttackComplexity.HIGH:   0.35,
}


def _vid(vuln_class: VulnClass, source: str, idx: int) -> str:
    raw = f"{vuln_class.value}:{source}:{idx}"
    return "V-" + hashlib.md5(raw.encode()).hexdigest()[:8].upper()


def _map_severity_to_maturity(severity: str, evidence_count: int) -> ExploitMaturity:
    if severity == "critical" and evidence_count >= 1:
        return ExploitMaturity.CONFIRMED
    if severity in ("critical", "high") and evidence_count >= 1:
        return ExploitMaturity.PROOF_OF_CONCEPT
    if severity == "medium":
        return ExploitMaturity.THEORETICAL
    return ExploitMaturity.UNPROVEN


def _map_severity_to_complexity(severity: str, vuln_class: VulnClass) -> AttackComplexity:
    high_complexity = {VulnClass.TIMING_ORACLE, VulnClass.WAF_BYPASS, VulnClass.BLIND_SSRF}
    if vuln_class in high_complexity:
        return AttackComplexity.HIGH
    if severity in ("critical", "high"):
        return AttackComplexity.LOW
    if severity == "medium":
        return AttackComplexity.MEDIUM
    return AttackComplexity.HIGH


def _compute_weighted_score(
    cvss_base: float,
    severity: str,
    maturity: ExploitMaturity,
    complexity: AttackComplexity,
    impact_count: int,
) -> float:
    sev_w = SEVERITY_WEIGHT.get(severity, 0.1)
    mat_w = EXPLOITABILITY_WEIGHT[maturity]
    cmp_w = COMPLEXITY_WEIGHT[complexity]
    impact_bonus = min(0.2, impact_count * 0.04)
    base = (cvss_base / 10.0) * 0.5 + sev_w * 0.3 + mat_w * 0.15 + cmp_w * 0.05
    return round(min(1.0, base + impact_bonus), 4)


def _extract_from_waf(result: dict, idx_counter: list) -> list[ScoredVuln]:
    vulns: list[ScoredVuln] = []
    if not result or result.get("error"):
        return vulns
    vendor = result.get("vendor", "")
    evasion_hits = result.get("evasion_hits", 0)
    if evasion_hits > 0:
        vc = VulnClass.WAF_BYPASS
        cvss = CVSS_PROFILES[vc]
        severity = "medium"
        maturity = ExploitMaturity.PROOF_OF_CONCEPT
        complexity = AttackComplexity.HIGH
        impacts = IMPACT_MAP[vc]
        ws = _compute_weighted_score(cvss.base_score, severity, maturity, complexity, len(impacts))
        idx_counter[0] += 1
        vulns.append(ScoredVuln(
            vuln_id=_vid(vc, "waf_fingerprint", idx_counter[0]),
            vuln_class=vc,
            source_module="waf_fingerprint",
            title=f"WAF Evasion Vector Identified ({vendor})",
            description=f"{evasion_hits} evasion probe(s) returned non-blocked responses against {vendor} WAF",
            raw_severity=severity,
            cvss=cvss,
            exploit_maturity=maturity,
            attack_complexity=complexity,
            impact_domains=impacts,
            weighted_score=ws,
            chaining_potential=0.0,
            composite_score=0.0,
            evidence=[f"vendor={vendor}", f"evasion_hits={evasion_hits}"],
            affected_param="",
            affected_url=result.get("target", ""),
            remediation=REMEDIATION_MAP[vc],
            mitre_techniques=MITRE_MAP[vc],
        ))
    return vulns


def _extract_from_headers(result: dict, idx_counter: list) -> list[ScoredVuln]:
    vulns: list[ScoredVuln] = []
    if not result or result.get("error"):
        return vulns
    for finding in result.get("findings", []):
        severity = finding.get("severity", "info")
        if severity == "info":
            continue
        evidence_text = finding.get("evidence", "")
        is_crlf = "crlf" in evidence_text.lower() or "\\r\\n" in evidence_text or "0d0a" in evidence_text.lower()
        vc = VulnClass.CRLF_INJECTION if is_crlf else VulnClass.HEADER_INJECTION
        cvss = CVSS_PROFILES[vc]
        maturity = _map_severity_to_maturity(severity, 1)
        complexity = _map_severity_to_complexity(severity, vc)
        impacts = IMPACT_MAP[vc]
        ws = _compute_weighted_score(cvss.base_score, severity, maturity, complexity, len(impacts))
        idx_counter[0] += 1
        vulns.append(ScoredVuln(
            vuln_id=_vid(vc, "header_injection", idx_counter[0]),
            vuln_class=vc,
            source_module="header_injection",
            title=finding.get("header", "Header Injection") + " — " + vc.value.replace("_", " ").title(),
            description=finding.get("detail", ""),
            raw_severity=severity,
            cvss=cvss,
            exploit_maturity=maturity,
            attack_complexity=complexity,
            impact_domains=impacts,
            weighted_score=ws,
            chaining_potential=0.0,
            composite_score=0.0,
            evidence=[evidence_text[:300]],
            affected_param=finding.get("header", ""),
            affected_url=result.get("target", ""),
            remediation=REMEDIATION_MAP[vc],
            mitre_techniques=MITRE_MAP[vc],
        ))
    return vulns


def _extract_from_cors(result: dict, idx_counter: list) -> list[ScoredVuln]:
    vulns: list[ScoredVuln] = []
    if not result or result.get("error"):
        return vulns
    for finding in result.get("findings", []):
        severity = finding.get("severity", "info")
        if severity == "info":
            continue
        vc = VulnClass.CORS_MISCONFIGURATION
        cvss = CVSS_PROFILES[vc]
        maturity = _map_severity_to_maturity(severity, 1)
        complexity = _map_severity_to_complexity(severity, vc)
        impacts = IMPACT_MAP[vc]
        ws = _compute_weighted_score(cvss.base_score, severity, maturity, complexity, len(impacts))
        idx_counter[0] += 1
        vulns.append(ScoredVuln(
            vuln_id=_vid(vc, "cors_audit", idx_counter[0]),
            vuln_class=vc,
            source_module="cors_audit",
            title="CORS Misconfiguration — " + finding.get("issue_type", ""),
            description=finding.get("detail", ""),
            raw_severity=severity,
            cvss=cvss,
            exploit_maturity=maturity,
            attack_complexity=complexity,
            impact_domains=impacts,
            weighted_score=ws,
            chaining_potential=0.0,
            composite_score=0.0,
            evidence=[finding.get("evidence", "")[:300]],
            affected_param="Origin",
            affected_url=finding.get("url", result.get("target", "")),
            remediation=REMEDIATION_MAP[vc],
            mitre_techniques=MITRE_MAP[vc],
        ))
    return vulns


def _extract_from_js_secrets(result: dict, idx_counter: list) -> list[ScoredVuln]:
    vulns: list[ScoredVuln] = []
    if not result or result.get("error"):
        return vulns
    for secret in result.get("secrets", []):
        severity = secret.get("severity", "medium")
        secret_type = secret.get("secret_type", "unknown")
        is_cred = any(k in secret_type.lower() for k in ("password", "credential", "token", "key", "secret"))
        vc = VulnClass.CREDENTIAL_EXPOSURE if is_cred else VulnClass.JS_SECRET_EXPOSURE
        cvss = CVSS_PROFILES[vc]
        maturity = ExploitMaturity.CONFIRMED
        complexity = AttackComplexity.LOW
        impacts = IMPACT_MAP[vc]
        ws = _compute_weighted_score(cvss.base_score, severity, maturity, complexity, len(impacts))
        idx_counter[0] += 1
        vulns.append(ScoredVuln(
            vuln_id=_vid(vc, "js_secrets", idx_counter[0]),
            vuln_class=vc,
            source_module="js_secrets",
            title=f"Secret Exposure in JS — {secret_type}",
            description=f"Secret of type '{secret_type}' found in client-side JavaScript",
            raw_severity=severity,
            cvss=cvss,
            exploit_maturity=maturity,
            attack_complexity=complexity,
            impact_domains=impacts,
            weighted_score=ws,
            chaining_potential=0.0,
            composite_score=0.0,
            evidence=[secret.get("js_file", ""), secret.get("match_preview", "")[:200]],
            affected_param=secret.get("variable_name", ""),
            affected_url=secret.get("js_file", result.get("target", "")),
            remediation=REMEDIATION_MAP[vc],
            mitre_techniques=MITRE_MAP[vc],
        ))
    return vulns


def _extract_from_ssrf(result: dict, idx_counter: list) -> list[ScoredVuln]:
    vulns: list[ScoredVuln] = []
    if not result or result.get("error"):
        return vulns
    for finding in result.get("findings", []):
        severity = finding.get("severity", "info")
        if severity == "info":
            continue
        evidence_text = finding.get("details", "")
        payload_target = finding.get("payload_target", "")
        is_cloud = any(k in payload_target for k in ("169.254.", "metadata.google", "metadata/instance"))
        is_internal = any(k in payload_target for k in ("localhost", "127.", "10.", "172.", "192.168.", "kubernetes", "docker"))
        is_blind = finding.get("evidence") == "blind_no_evidence"
        if is_cloud:
            vc = VulnClass.CLOUD_METADATA
        elif is_internal:
            vc = VulnClass.INTERNAL_SERVICE
        elif is_blind:
            vc = VulnClass.BLIND_SSRF
        else:
            vc = VulnClass.SSRF
        cvss = CVSS_PROFILES[vc]
        maturity = _map_severity_to_maturity(severity, 1)
        complexity = _map_severity_to_complexity(severity, vc)
        impacts = IMPACT_MAP[vc]
        ws = _compute_weighted_score(cvss.base_score, severity, maturity, complexity, len(impacts))
        idx_counter[0] += 1
        vulns.append(ScoredVuln(
            vuln_id=_vid(vc, "ssrf_probe", idx_counter[0]),
            vuln_class=vc,
            source_module="ssrf_probe",
            title=f"SSRF — {vc.value.replace('_',' ').title()} via {finding.get('vector','param')}",
            description=evidence_text,
            raw_severity=severity,
            cvss=cvss,
            exploit_maturity=maturity,
            attack_complexity=complexity,
            impact_domains=impacts,
            weighted_score=ws,
            chaining_potential=0.0,
            composite_score=0.0,
            evidence=[finding.get("snippet", "")[:300], payload_target],
            affected_param=finding.get("param", ""),
            affected_url=finding.get("endpoint", result.get("target", "")),
            remediation=REMEDIATION_MAP[vc],
            mitre_techniques=MITRE_MAP[vc],
        ))
    return vulns


def _extract_from_redirect(result: dict, idx_counter: list) -> list[ScoredVuln]:
    vulns: list[ScoredVuln] = []
    if not result or result.get("error"):
        return vulns
    for finding in result.get("findings", []):
        severity = finding.get("severity", "info")
        ftype = finding.get("type", "")
        is_open = "open_redirect" in ftype
        is_crlf = "header_injection" in ftype
        vc = VulnClass.CRLF_INJECTION if is_crlf else (VulnClass.OPEN_REDIRECT if is_open else VulnClass.REDIRECT_CHAIN)
        cvss = CVSS_PROFILES[vc]
        maturity = _map_severity_to_maturity(severity, 1)
        complexity = _map_severity_to_complexity(severity, vc)
        impacts = IMPACT_MAP[vc]
        ws = _compute_weighted_score(cvss.base_score, severity, maturity, complexity, len(impacts))
        idx_counter[0] += 1
        vulns.append(ScoredVuln(
            vuln_id=_vid(vc, "redirect_trace", idx_counter[0]),
            vuln_class=vc,
            source_module="redirect_trace",
            title=f"{vc.value.replace('_',' ').title()} — {finding.get('url','')[:60]}",
            description=finding.get("detail", ""),
            raw_severity=severity,
            cvss=cvss,
            exploit_maturity=maturity,
            attack_complexity=complexity,
            impact_domains=impacts,
            weighted_score=ws,
            chaining_potential=0.0,
            composite_score=0.0,
            evidence=[finding.get("evidence", "")[:300]],
            affected_param=finding.get("param", ""),
            affected_url=finding.get("url", result.get("target", "")),
            remediation=REMEDIATION_MAP[vc],
            mitre_techniques=MITRE_MAP[vc],
        ))
    return vulns


def _extract_from_spray(result: dict, idx_counter: list) -> list[ScoredVuln]:
    vulns: list[ScoredVuln] = []
    if not result or result.get("error"):
        return vulns
    summary = result.get("summary", {})
    if summary.get("successful_logins", 0) > 0:
        vc = VulnClass.CREDENTIAL_EXPOSURE
        cvss = CVSS_PROFILES[vc]
        maturity = ExploitMaturity.CONFIRMED
        complexity = AttackComplexity.LOW
        impacts = IMPACT_MAP[vc]
        ws = _compute_weighted_score(cvss.base_score, "critical", maturity, complexity, len(impacts))
        idx_counter[0] += 1
        successes = result.get("successful_logins", [])
        evidence = [f"login_success: {s.get('username','?')}:{s.get('password','?')}" for s in successes[:5]]
        vulns.append(ScoredVuln(
            vuln_id=_vid(vc, "credential_spray", idx_counter[0]),
            vuln_class=vc,
            source_module="credential_spray",
            title="Valid Credentials Discovered via Spray",
            description=f"{summary['successful_logins']} valid credential pair(s) confirmed via authentication spray",
            raw_severity="critical",
            cvss=cvss,
            exploit_maturity=maturity,
            attack_complexity=complexity,
            impact_domains=impacts,
            weighted_score=ws,
            chaining_potential=0.0,
            composite_score=0.0,
            evidence=evidence,
            affected_param="username/password",
            affected_url=result.get("target", ""),
            remediation=REMEDIATION_MAP[vc],
            mitre_techniques=MITRE_MAP[VulnClass.AUTH_BYPASS],
        ))
    return vulns


def _extract_from_mutator(result: dict, idx_counter: list) -> list[ScoredVuln]:
    vulns: list[ScoredVuln] = []
    if not result or result.get("error"):
        return vulns
    best = result.get("best_payload")
    if not best or best.get("fitness_score", 0) < 0.3:
        return vulns
    signals = best.get("signals", [])
    category_str = result.get("category", "xss")
    signal_to_vc = {
        "error_disclosure": VulnClass.SQLI_ERROR,
        "reflection":       VulnClass.XSS_REFLECTED,
        "waf_bypass":       VulnClass.WAF_BYPASS,
        "blind_timing":     VulnClass.TIMING_ORACLE,
    }
    vc = VulnClass.PAYLOAD_BYPASS
    for sig in signals:
        if sig in signal_to_vc:
            vc = signal_to_vc[sig]
            break
    cvss = CVSS_PROFILES.get(vc, CVSS_PROFILES[VulnClass.PAYLOAD_BYPASS])
    fitness = best.get("fitness_score", 0.3)
    severity = "critical" if fitness > 0.8 else "high" if fitness > 0.5 else "medium"
    maturity = ExploitMaturity.PROOF_OF_CONCEPT
    complexity = AttackComplexity.MEDIUM
    impacts = IMPACT_MAP.get(vc, [ImpactDomain.INTEGRITY])
    ws = _compute_weighted_score(cvss.base_score, severity, maturity, complexity, len(impacts))
    idx_counter[0] += 1
    vulns.append(ScoredVuln(
        vuln_id=_vid(vc, "payload_mutator", idx_counter[0]),
        vuln_class=vc,
        source_module="payload_mutator",
        title=f"Evolved Payload Bypass — {vc.value.replace('_',' ').title()} (fitness={fitness:.2f})",
        description=f"Genetic mutation produced payload with fitness {fitness:.2f} after {result.get('total_generations',0)} generations",
        raw_severity=severity,
        cvss=cvss,
        exploit_maturity=maturity,
        attack_complexity=complexity,
        impact_domains=impacts,
        weighted_score=ws,
        chaining_potential=0.0,
        composite_score=0.0,
        evidence=[
            f"payload={best.get('value','')[:200]}",
            f"mutations={','.join(best.get('mutations',[]))}",
            f"signals={signals}",
        ],
        affected_param=result.get("param", ""),
        affected_url=result.get("target", ""),
        remediation=REMEDIATION_MAP.get(vc, ""),
        mitre_techniques=MITRE_MAP.get(vc, []),
    ))
    return vulns


def _extract_from_mouse(result: dict, idx_counter: list) -> list[ScoredVuln]:
    vulns: list[ScoredVuln] = []
    if not result or result.get("error"):
        return vulns
    findings = result.get("findings", {})
    if findings.get("result") == "success":
        vc = VulnClass.AUTH_BYPASS
        cvss = CVSS_PROFILES[vc]
        maturity = ExploitMaturity.CONFIRMED
        complexity = AttackComplexity.LOW
        impacts = IMPACT_MAP[vc]
        ws = _compute_weighted_score(cvss.base_score, "critical", maturity, complexity, len(impacts))
        idx_counter[0] += 1
        vulns.append(ScoredVuln(
            vuln_id=_vid(vc, "ai_mouse_agent", idx_counter[0]),
            vuln_class=vc,
            source_module="ai_mouse_agent",
            title="Authentication Bypass via Browser Automation",
            description="AI mouse agent successfully authenticated — credentials valid or auth flow bypassable",
            raw_severity="critical",
            cvss=cvss,
            exploit_maturity=maturity,
            attack_complexity=complexity,
            impact_domains=impacts,
            weighted_score=ws,
            chaining_potential=0.0,
            composite_score=0.0,
            evidence=[
                f"cookies_captured={list(result.get('cookies',{}).keys())}",
                f"session_id={findings.get('session_id','')}",
            ],
            affected_param="login_form",
            affected_url=result.get("target_url", ""),
            remediation=REMEDIATION_MAP[vc],
            mitre_techniques=MITRE_MAP[vc],
        ))
    return vulns


MODULE_EXTRACTORS = {
    "waf_fingerprint":   _extract_from_waf,
    "header_injection":  _extract_from_headers,
    "cors_audit":        _extract_from_cors,
    "js_secrets":        _extract_from_js_secrets,
    "ssrf_probe":        _extract_from_ssrf,
    "redirect_trace":    _extract_from_redirect,
    "credential_spray":  _extract_from_spray,
    "payload_mutator":   _extract_from_mutator,
    "ai_mouse_agent":    _extract_from_mouse,
}


def _build_chain_links(vulns: list[ScoredVuln]) -> list[ChainLink]:
    links: list[ChainLink] = []
    vc_to_vulns: dict[VulnClass, list[ScoredVuln]] = {}
    for v in vulns:
        vc_to_vulns.setdefault(v.vuln_class, []).append(v)

    for (src_vc, dst_vc), (amp, desc) in CHAINING_PAIRS.items():
        if src_vc in vc_to_vulns and dst_vc in vc_to_vulns:
            src = vc_to_vulns[src_vc][0]
            dst = vc_to_vulns[dst_vc][0]
            links.append(ChainLink(
                source_vuln_id=src.vuln_id,
                target_vuln_id=dst.vuln_id,
                chain_type=f"{src_vc.value}→{dst_vc.value}",
                amplification=amp,
                description=desc,
            ))
            src.chain_links.append(links[-1])
            src.chaining_potential = max(src.chaining_potential, amp)
            dst.chaining_potential = max(dst.chaining_potential, amp * 0.8)
    return links


def _compute_composite(vuln: ScoredVuln) -> float:
    return round(
        vuln.weighted_score * 0.55
        + vuln.chaining_potential * 0.30
        + (len(vuln.impact_domains) / 6) * 0.15,
        4
    )


def _build_attack_paths(vulns: list[ScoredVuln]) -> list[AttackPath]:
    paths: list[AttackPath] = []
    chained: list[ScoredVuln] = [v for v in vulns if v.chaining_potential > 0]
    if not chained:
        return paths

    chained.sort(key=lambda v: -v.composite_score)
    seen_combos: set[str] = set()

    for src in chained:
        for link in src.chain_links:
            dst = next((v for v in vulns if v.vuln_id == link.target_vuln_id), None)
            if not dst:
                continue
            combo = f"{src.vuln_id}:{dst.vuln_id}"
            if combo in seen_combos:
                continue
            seen_combos.add(combo)

            path_score = round(
                (src.composite_score + dst.composite_score) / 2 * link.amplification,
                4
            )
            all_impacts = list({i for v in (src, dst) for i in v.impact_domains})
            rating = (
                "CRITICAL" if path_score > 0.75
                else "HIGH" if path_score > 0.55
                else "MEDIUM" if path_score > 0.35
                else "LOW"
            )
            paths.append(AttackPath(
                path_id=hashlib.md5(combo.encode()).hexdigest()[:8].upper(),
                steps=[src, dst],
                total_score=path_score,
                entry_point=src.affected_url or src.source_module,
                impact_summary=all_impacts,
                narrative=link.description,
                exploitability_rating=rating,
            ))

    paths.sort(key=lambda p: -p.total_score)
    return paths[:15]


def _build_red_team_narrative(
    vulns: list[ScoredVuln],
    paths: list[AttackPath],
    target_url: str,
) -> str:
    if not vulns:
        return f"No actionable findings against {target_url}."

    crits = [v for v in vulns if v.raw_severity == "critical"]
    highs = [v for v in vulns if v.raw_severity == "high"]
    top = vulns[0]

    lines: list[str] = []
    lines.append(f"Target: {target_url}")
    lines.append(
        f"Assessment surface: {len(vulns)} findings ({len(crits)} critical, {len(highs)} high). "
        f"Highest-scored: {top.title} (composite={top.composite_score:.3f})."
    )

    if paths:
        best = paths[0]
        lines.append(
            f"Top attack chain [{best.exploitability_rating}, score={best.total_score:.3f}]: "
            f"{best.narrative}"
        )
        if len(paths) > 1:
            lines.append(
                f"Secondary chains: {', '.join(p.path_id for p in paths[1:4])} "
                f"(scores: {', '.join(str(p.total_score) for p in paths[1:4])})."
            )

    cloud_hit = any(v.vuln_class == VulnClass.CLOUD_METADATA for v in vulns)
    cred_hit = any(v.vuln_class in (VulnClass.CREDENTIAL_EXPOSURE, VulnClass.AUTH_BYPASS) for v in vulns)
    if cloud_hit:
        lines.append("PRIORITY: Cloud metadata SSRF confirmed — immediate IAM credential rotation required.")
    if cred_hit:
        lines.append("PRIORITY: Valid credentials or auth bypass confirmed — assume full application compromise.")

    all_mitre = list({t for v in vulns for t in v.mitre_techniques})
    if all_mitre:
        lines.append(f"MITRE ATT&CK coverage: {', '.join(all_mitre[:8])}.")

    return " | ".join(lines)


class VulnScorer:
    def run(self, scan_results: dict, target_url: str) -> ScorerReport:
        t0 = time.monotonic()
        idx_counter = [0]
        all_vulns: list[ScoredVuln] = []

        for module_key, extractor in MODULE_EXTRACTORS.items():
            module_data = scan_results.get(module_key, {})
            if not module_data:
                continue
            extracted = extractor(module_data, idx_counter)
            all_vulns.extend(extracted)

        if "orchestrator" in scan_results:
            orch = scan_results["orchestrator"]
            for mod_key, mod_result in orch.get("module_results", {}).items():
                if mod_result.get("status") == "complete" and mod_key not in scan_results:
                    extractor = MODULE_EXTRACTORS.get(mod_key)
                    if extractor:
                        extracted = extractor(mod_result.get("output", {}), idx_counter)
                        all_vulns.extend(extracted)

        chain_links = _build_chain_links(all_vulns)

        for v in all_vulns:
            v.composite_score = _compute_composite(v)

        all_vulns.sort(key=lambda v: -v.composite_score)

        attack_paths = _build_attack_paths(all_vulns)
        narrative = _build_red_team_narrative(all_vulns, attack_paths, target_url)

        impact_coverage: dict[str, int] = {d.value: 0 for d in ImpactDomain}
        for v in all_vulns:
            for d in v.impact_domains:
                impact_coverage[d.value] += 1

        severity_dist: dict[str, int] = {s: 0 for s in SEVERITY_WEIGHT}
        for v in all_vulns:
            severity_dist[v.raw_severity] = severity_dist.get(v.raw_severity, 0) + 1

        module_coverage = list({v.source_module for v in all_vulns})

        overall_risk = 0.0
        if all_vulns:
            top_scores = [v.composite_score for v in all_vulns[:5]]
            overall_risk = round(
                sum(s * (0.5 ** i) for i, s in enumerate(top_scores))
                / sum(0.5 ** i for i in range(len(top_scores))),
                4
            )

        return ScorerReport(
            target_url=target_url,
            total_vulns=len(all_vulns),
            scored_vulns=all_vulns,
            attack_paths=attack_paths,
            top_findings=all_vulns[:10],
            impact_coverage=impact_coverage,
            severity_distribution=severity_dist,
            module_coverage=module_coverage,
            red_team_narrative=narrative,
            overall_risk_score=overall_risk,
            duration_seconds=round(time.monotonic() - t0, 2),
        )


def serialize_report(report: ScorerReport) -> dict:
    def cvss_to_dict(c: CVSSScore) -> dict:
        return {
            "base_score": c.base_score,
            "vector_string": c.vector_string,
            "attack_vector": c.attack_vector,
            "attack_complexity": c.attack_complexity,
            "privileges_required": c.privileges_required,
            "user_interaction": c.user_interaction,
            "scope": c.scope,
            "confidentiality": c.confidentiality,
            "integrity": c.integrity,
            "availability": c.availability,
        }

    def chain_to_dict(c: ChainLink) -> dict:
        return {
            "source": c.source_vuln_id,
            "target": c.target_vuln_id,
            "chain_type": c.chain_type,
            "amplification": c.amplification,
            "description": c.description,
        }

    def vuln_to_dict(v: ScoredVuln) -> dict:
        return {
            "vuln_id": v.vuln_id,
            "vuln_class": v.vuln_class.value,
            "source_module": v.source_module,
            "title": v.title,
            "description": v.description,
            "raw_severity": v.raw_severity,
            "cvss": cvss_to_dict(v.cvss),
            "exploit_maturity": v.exploit_maturity.value,
            "attack_complexity": v.attack_complexity.value,
            "impact_domains": [d.value for d in v.impact_domains],
            "weighted_score": v.weighted_score,
            "chaining_potential": v.chaining_potential,
            "composite_score": v.composite_score,
            "evidence": v.evidence,
            "affected_param": v.affected_param,
            "affected_url": v.affected_url,
            "remediation": v.remediation,
            "mitre_techniques": v.mitre_techniques,
            "chain_links": [chain_to_dict(c) for c in v.chain_links],
        }

    def path_to_dict(p: AttackPath) -> dict:
        return {
            "path_id": p.path_id,
            "total_score": p.total_score,
            "exploitability_rating": p.exploitability_rating,
            "entry_point": p.entry_point,
            "impact_summary": [d.value for d in p.impact_summary],
            "narrative": p.narrative,
            "steps": [v.vuln_id for v in p.steps],
            "step_titles": [v.title for v in p.steps],
        }

    return {
        "target": report.target_url,
        "total_vulns": report.total_vulns,
        "overall_risk_score": report.overall_risk_score,
        "duration_seconds": report.duration_seconds,
        "severity_distribution": report.severity_distribution,
        "impact_coverage": report.impact_coverage,
        "module_coverage": report.module_coverage,
        "red_team_narrative": report.red_team_narrative,
        "top_findings": [vuln_to_dict(v) for v in report.top_findings],
        "attack_paths": [path_to_dict(p) for p in report.attack_paths],
        "all_findings": [vuln_to_dict(v) for v in report.scored_vulns],
    }


def run_vuln_scorer(
    scan_results: dict,
    target_url: str,
) -> dict:
    scorer = VulnScorer()
    report = scorer.run(scan_results, target_url)
    return serialize_report(report)