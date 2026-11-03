# AI_vuln_prioritizer.py
# lang: Python 3.8+, file: modules/AI_vuln_prioritizer.py
# target: ARTEX v2.0 — slot as final step before ai_analysis in run_scan()
# reads from scan_results keys (all confirmed from source):
#   port_scan          → host_data['risky_ports'], host_data['vulnerabilities'], host_data['ports']
#   ssl_scan           → per-domain dict with 'vulnerabilities' (heartbleed/poodle/etc), 'grade', 'protocols'
#   security_analysis  → FastSecurityAnalyst output: 'risk_assessment', 'high_value_targets', 'attack_surface'
#   header_analysis    → AIHeaderAnalyzer output: 'targets'[url]['findings'] with severity field
#   takeover_analysis  → AISubdomainTakeoverAnalyzer output: 'vulnerable', 'dangling_dns'
#   payload_analysis   → AIPayloadGenerator output: 'vuln_classes', 'waf_detected', 'tech_profile'
#   osint_correlation  → AIOSINTCorrelator output: 'credential_leaks', 'reputation', 'dns_intelligence'
#   subdomains         → list of subdomain dicts with http_status/https_status/ip
#   tech_detection     → {url: {technologies: [{name, version, category}]}}
#   dns_records        → {A:[], MX:[], SPF:[], TXT:[], NS:[]}
# depends: requests (Groq call only)

import json
import time
import logging
import requests
import math
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict


# ---------------------------------------------------------------------------
# CVSS-inspired scoring constants
# ---------------------------------------------------------------------------

# Attack Vector weight — how accessible is the vulnerable component
AV_WEIGHT = {
    "network":   1.0,   # reachable over internet
    "adjacent":  0.85,  # same network segment
    "local":     0.55,  # requires local access
    "physical":  0.20,  # requires physical presence
}

# Attack Complexity — how difficult is exploitation
AC_WEIGHT = {
    "low":    1.0,   # no special conditions
    "medium": 0.77,
    "high":   0.44,  # specific race condition, special config
}

# Privileges Required — what level attacker needs before exploiting
PR_WEIGHT = {
    "none":  1.0,
    "low":   0.68,
    "high":  0.50,
}

# User Interaction
UI_WEIGHT = {
    "none":     1.0,
    "required": 0.85,
}

# Impact weights per CIA triad component (0.0–1.0)
IMPACT_WEIGHT = {
    "none":     0.0,
    "low":      0.22,
    "high":     0.56,
    "complete": 1.0,
}

# Business impact multipliers — applied on top of technical score
BUSINESS_IMPACT = {
    # Data sensitivity
    "pii_exposure":          1.4,
    "credential_theft":      1.5,
    "financial_data":        1.6,
    "intellectual_property": 1.3,
    # Operational impact
    "service_disruption":    1.2,
    "reputational":          1.1,
    "regulatory":            1.35,   # PDPA / GDPR / PCI-DSS violation
    # Attack chain value
    "initial_access":        1.0,
    "lateral_movement":      1.25,
    "persistence":           1.3,
    "data_exfiltration":     1.45,
    "full_compromise":       1.6,
}

# Severity thresholds (final 0–100 score → label)
SEVERITY_THRESHOLDS = [
    (90, "critical"),
    (70, "high"),
    (40, "medium"),
    (10, "low"),
    (0,  "info"),
]

# Source trust multiplier — how reliable is the detection method
SOURCE_TRUST = {
    "nmap_vuln_script":    1.0,
    "ssl_protocol":        0.95,
    "ssl_cve":             1.0,
    "header_missing":      0.80,
    "header_weak":         0.75,
    "subdomain_takeover":  1.0,
    "cname_dangling":      0.85,
    "credential_leak":     1.0,
    "shodan_cve":          0.90,
    "port_exposure":       0.70,
    "tech_version":        0.65,
    "dns_weakness":        0.80,
    "fast_analyst":        0.60,   # rule-based heuristic — lower trust
    "payload_class":       0.55,   # inferred from tech stack
}

# Port → base exploitability profile
PORT_PROFILES: Dict[int, Dict] = {
    21:    {"name": "FTP",           "av": "network", "ac": "low",  "pr": "none", "ui": "none",
            "c": "high",  "i": "high",  "a": "low",   "business": ["credential_theft", "data_exfiltration"]},
    22:    {"name": "SSH",           "av": "network", "ac": "low",  "pr": "none", "ui": "none",
            "c": "high",  "i": "high",  "a": "high",  "business": ["full_compromise", "lateral_movement"]},
    23:    {"name": "Telnet",        "av": "network", "ac": "low",  "pr": "none", "ui": "none",
            "c": "complete", "i": "complete", "a": "complete", "business": ["full_compromise", "credential_theft"]},
    25:    {"name": "SMTP",          "av": "network", "ac": "low",  "pr": "none", "ui": "none",
            "c": "low",  "i": "low",  "a": "low",    "business": ["reputational"]},
    445:   {"name": "SMB",           "av": "network", "ac": "low",  "pr": "none", "ui": "none",
            "c": "complete", "i": "complete", "a": "complete", "business": ["full_compromise", "lateral_movement", "persistence"]},
    1433:  {"name": "MSSQL",         "av": "network", "ac": "low",  "pr": "none", "ui": "none",
            "c": "complete", "i": "complete", "a": "high",  "business": ["data_exfiltration", "full_compromise"]},
    3306:  {"name": "MySQL",         "av": "network", "ac": "low",  "pr": "none", "ui": "none",
            "c": "high",  "i": "high",  "a": "low",   "business": ["data_exfiltration", "credential_theft"]},
    3389:  {"name": "RDP",           "av": "network", "ac": "low",  "pr": "none", "ui": "none",
            "c": "complete", "i": "complete", "a": "complete", "business": ["full_compromise", "lateral_movement"]},
    5432:  {"name": "PostgreSQL",    "av": "network", "ac": "low",  "pr": "none", "ui": "none",
            "c": "high",  "i": "high",  "a": "low",   "business": ["data_exfiltration"]},
    5900:  {"name": "VNC",           "av": "network", "ac": "low",  "pr": "none", "ui": "none",
            "c": "complete", "i": "complete", "a": "complete", "business": ["full_compromise"]},
    6379:  {"name": "Redis",         "av": "network", "ac": "low",  "pr": "none", "ui": "none",
            "c": "high",  "i": "high",  "a": "high",  "business": ["data_exfiltration", "full_compromise"]},
    9200:  {"name": "Elasticsearch", "av": "network", "ac": "low",  "pr": "none", "ui": "none",
            "c": "complete", "i": "low",  "a": "low",  "business": ["data_exfiltration", "pii_exposure"]},
    27017: {"name": "MongoDB",       "av": "network", "ac": "low",  "pr": "none", "ui": "none",
            "c": "complete", "i": "high",  "a": "low",  "business": ["data_exfiltration", "pii_exposure"]},
}

# SSL/TLS CVE profiles — keyed to ssl_scan['vulnerabilities'] dict keys
SSL_CVE_PROFILES: Dict[str, Dict] = {
    "heartbleed": {
        "cve": "CVE-2014-0160", "cvss_base": 7.5,
        "description": "OpenSSL Heartbleed — read up to 64KB of server memory per request, leaking private keys and session data.",
        "av": "network", "ac": "low", "pr": "none", "ui": "none",
        "c": "complete", "i": "none", "a": "none",
        "business": ["credential_theft", "data_exfiltration"],
    },
    "poodle": {
        "cve": "CVE-2014-3566", "cvss_base": 3.4,
        "description": "POODLE — SSLv3 CBC padding oracle, allows MITM to decrypt session cookies.",
        "av": "network", "ac": "medium", "pr": "none", "ui": "required",
        "c": "low", "i": "none", "a": "none",
        "business": ["credential_theft"],
    },
    "freak": {
        "cve": "CVE-2015-0204", "cvss_base": 7.4,
        "description": "FREAK — forces export-grade RSA keys (512-bit), enabling factoring and MITM decryption.",
        "av": "network", "ac": "medium", "pr": "none", "ui": "none",
        "c": "high", "i": "high", "a": "none",
        "business": ["credential_theft", "data_exfiltration"],
    },
    "beast": {
        "cve": "CVE-2011-3389", "cvss_base": 3.4,
        "description": "BEAST — TLS 1.0 CBC IV prediction, block-wise chosen-plaintext attack on HTTPS sessions.",
        "av": "network", "ac": "medium", "pr": "none", "ui": "required",
        "c": "low", "i": "none", "a": "none",
        "business": ["credential_theft"],
    },
    "lucky13": {
        "cve": "CVE-2013-0169", "cvss_base": 3.4,
        "description": "Lucky Thirteen — timing side-channel in TLS CBC record MAC verification.",
        "av": "network", "ac": "high", "pr": "none", "ui": "none",
        "c": "low", "i": "none", "a": "none",
        "business": ["credential_theft"],
    },
    "crime": {
        "cve": "CVE-2012-4929", "cvss_base": 5.9,
        "description": "CRIME — TLS compression side-channel enables session cookie extraction.",
        "av": "network", "ac": "medium", "pr": "none", "ui": "required",
        "c": "high", "i": "none", "a": "none",
        "business": ["credential_theft"],
    },
    "breach": {
        "cve": "CVE-2013-3587", "cvss_base": 5.9,
        "description": "BREACH — HTTP compression oracle attack against secret tokens in HTTPS responses.",
        "av": "network", "ac": "medium", "pr": "none", "ui": "required",
        "c": "high", "i": "none", "a": "none",
        "business": ["credential_theft"],
    },
    "logjam": {
        "cve": "CVE-2015-4000", "cvss_base": 3.7,
        "description": "Logjam — DHE export downgrade; precomputed 512-bit DH fields allow MITM.",
        "av": "network", "ac": "medium", "pr": "none", "ui": "none",
        "c": "low", "i": "low", "a": "none",
        "business": ["credential_theft"],
    },
    "drown": {
        "cve": "CVE-2016-0800", "cvss_base": 5.9,
        "description": "DROWN — SSLv2 cross-protocol attack decrypts RSA-encrypted TLS sessions.",
        "av": "network", "ac": "medium", "pr": "none", "ui": "none",
        "c": "high", "i": "none", "a": "none",
        "business": ["credential_theft", "data_exfiltration"],
    },
    "sweet32": {
        "cve": "CVE-2016-2183", "cvss_base": 3.7,
        "description": "SWEET32 — birthday attack on 64-bit ciphers (3DES/Blowfish) in long-lived sessions.",
        "av": "network", "ac": "medium", "pr": "none", "ui": "none",
        "c": "low", "i": "none", "a": "none",
        "business": ["credential_theft"],
    },
    "ccs_injection": {
        "cve": "CVE-2014-0224", "cvss_base": 7.4,
        "description": "OpenSSL CCS Injection — MitM can force weak keying material in handshake.",
        "av": "network", "ac": "medium", "pr": "none", "ui": "none",
        "c": "high", "i": "high", "a": "none",
        "business": ["credential_theft", "data_exfiltration"],
    },
}

# Header severity → score contribution (from AIHeaderAnalyzer output)
HEADER_SEVERITY_SCORE = {
    "critical": 85,
    "high":     65,
    "medium":   40,
    "low":      20,
    "info":     5,
}

# Subdomain takeover confidence → score
TAKEOVER_CONFIDENCE_SCORE = {
    "high":   95,
    "medium": 75,
    "low":    55,
}

# DNS weakness scoring
DNS_WEAKNESS_SCORES = {
    "no_dmarc":        {"score": 72, "business": ["reputational", "credential_theft"]},
    "dmarc_none":      {"score": 55, "business": ["reputational"]},
    "no_spf":          {"score": 68, "business": ["reputational"]},
    "spf_plus_all":    {"score": 60, "business": ["reputational"]},
    "open_resolver":   {"score": 50, "business": ["service_disruption"]},
    "no_dnssec":       {"score": 25, "business": ["credential_theft"]},
}


# ---------------------------------------------------------------------------
# Data classes (plain dicts — no dataclass dependency for Python 3.7 compat)
# ---------------------------------------------------------------------------

def _vuln(
    vuln_id: str,
    title: str,
    source: str,
    source_trust: float,
    technical_score: float,
    business_score: float,
    severity: str,
    affected_asset: str,
    description: str,
    evidence: Dict,
    remediation: str,
    attack_vector: str,
    cve: Optional[str] = None,
    cvss_base: Optional[float] = None,
    business_tags: Optional[List[str]] = None,
    exploit_complexity: str = "low",
    privileges_required: str = "none",
    user_interaction: str = "none",
) -> Dict:
    return {
        "vuln_id":           vuln_id,
        "title":             title,
        "source":            source,
        "source_trust":      round(source_trust, 3),
        "technical_score":   round(technical_score, 2),
        "business_score":    round(business_score, 2),
        "final_score":       round((technical_score * 0.55 + business_score * 0.45), 2),
        "severity":          severity,
        "affected_asset":    affected_asset,
        "description":       description,
        "evidence":          evidence,
        "remediation":       remediation,
        "attack_vector":     attack_vector,
        "cve":               cve,
        "cvss_base":         cvss_base,
        "business_tags":     business_tags or [],
        "exploit_complexity":    exploit_complexity,
        "privileges_required":   privileges_required,
        "user_interaction":      user_interaction,
        "created_at":        datetime.now().isoformat(),
    }


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

def _cvss_like_score(
    av: str, ac: str, pr: str, ui: str,
    c: str, i: str, a: str,
    source_trust: float = 1.0,
) -> float:
    """
    Compute a 0–100 exploitability+impact score inspired by CVSS v3.
    Not a strict CVSS implementation — tuned for ranking, not NVD submission.
    """
    exploitability = (
        AV_WEIGHT.get(av, 0.85) *
        AC_WEIGHT.get(ac, 0.77) *
        PR_WEIGHT.get(pr, 1.0) *
        UI_WEIGHT.get(ui, 1.0)
    )

    c_val = IMPACT_WEIGHT.get(c, 0.56)
    i_val = IMPACT_WEIGHT.get(i, 0.56)
    a_val = IMPACT_WEIGHT.get(a, 0.56)

    # Scope: if any high/complete impact → multiplicative bonus
    impact_subscore = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))
    impact = impact_subscore * 10.0

    base = min(10.0, (exploitability * 2.5) + (impact * 0.6))
    score = (base / 10.0) * 100 * source_trust
    return min(100.0, round(score, 2))


def _business_score(base_technical: float, tags: List[str]) -> float:
    """Apply business impact multipliers to technical score."""
    multiplier = 1.0
    for tag in tags:
        m = BUSINESS_IMPACT.get(tag, 1.0)
        # Additive stacking — but cap total multiplier at 2.5
        multiplier = min(2.5, multiplier + (m - 1.0))
    return min(100.0, round(base_technical * multiplier, 2))


def _score_to_severity(score: float) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "info"


def _make_id(prefix: str, counter: List[int]) -> str:
    counter[0] += 1
    return f"{prefix}-{counter[0]:04d}"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class AIVulnPrioritizer:
    """
    Unified vulnerability ingestion, scoring, and AI-prioritisation engine.

    Reads every ARTEX scan_results key that carries vulnerability or risk data,
    normalises findings into a common schema, scores each finding with a
    CVSS-inspired engine (technical × business impact), and sends a condensed
    prioritised list to Groq for analyst-grade narrative + remediation roadmap.

    Slot in run_scan() after all scan modules, before ai_analyst:

        prioritizer = AIVulnPrioritizer(groq_api_key=GROQ_API_KEY)
        scan_results[scan_id]['vuln_prioritization'] = prioritizer.prioritize(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    def __init__(
        self,
        groq_api_key: Optional[str] = None,
        timeout: int = 12,
    ):
        self.groq_api_key = groq_api_key
        self.timeout      = timeout
        self.logger       = logging.getLogger(__name__)

        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def prioritize(
        self,
        domain: str,
        scan_results: Dict,
    ) -> Dict:
        """
        Args:
            domain:       Primary target domain.
            scan_results: Full ARTEX scan_results dict for this scan_id.

        Returns dict with keys:
            findings          — all normalised + scored vuln dicts, sorted by final_score desc
            prioritized       — top 20, same schema
            severity_counts   — {critical, high, medium, low, info}
            asset_risk_map    — per-asset risk summary
            attack_chains     — inferred multi-step chains from finding combinations
            overall_risk      — {score, level, rationale}
            coverage_map      — which sources contributed findings
            ai_analysis       — Groq enrichment or None
            scan_metadata
        """
        self.logger.info(f"Vuln prioritization starting — domain: {domain}")
        start       = time.time()
        id_counter  = [0]   # mutable for _make_id closure

        all_findings: List[Dict] = []

        # ── Ingest every source ──────────────────────────────────────────
        all_findings += self._ingest_port_scan(scan_results, id_counter)
        all_findings += self._ingest_ssl_scan(scan_results, id_counter)
        all_findings += self._ingest_header_analysis(scan_results, id_counter)
        all_findings += self._ingest_takeover_analysis(scan_results, id_counter)
        all_findings += self._ingest_osint_correlation(scan_results, id_counter)
        all_findings += self._ingest_security_analysis(scan_results, id_counter)
        all_findings += self._ingest_payload_classes(scan_results, id_counter)
        all_findings += self._ingest_dns_records(scan_results, id_counter)

        # ── Deduplicate overlapping findings from multiple sources ───────
        all_findings = self._deduplicate(all_findings)

        # ── Sort descending by final_score ───────────────────────────────
        all_findings.sort(key=lambda x: x["final_score"], reverse=True)

        # ── Severity counts ──────────────────────────────────────────────
        severity_counts: Dict[str, int] = defaultdict(int)
        for f in all_findings:
            severity_counts[f["severity"]] += 1

        # ── Per-asset risk map ───────────────────────────────────────────
        asset_risk_map = self._build_asset_risk_map(all_findings)

        # ── Attack chain inference ───────────────────────────────────────
        attack_chains = self._infer_attack_chains(all_findings, domain)

        # ── Overall risk ─────────────────────────────────────────────────
        overall_risk = self._calculate_overall_risk(all_findings, severity_counts)

        # ── Coverage map ─────────────────────────────────────────────────
        coverage_map = self._build_coverage_map(all_findings)

        # ── AI enrichment ────────────────────────────────────────────────
        ai_result = None
        if self.groq_api_key and all_findings:
            ai_result = self._ai_analysis(domain, all_findings[:20], overall_risk, attack_chains)

        duration = round(time.time() - start, 2)
        self.logger.info(
            f"Prioritization complete — {len(all_findings)} findings, "
            f"overall: {overall_risk['level']} in {duration}s"
        )

        return {
            "findings":        all_findings,
            "prioritized":     all_findings[:20],
            "severity_counts": dict(severity_counts),
            "asset_risk_map":  asset_risk_map,
            "attack_chains":   attack_chains,
            "overall_risk":    overall_risk,
            "coverage_map":    coverage_map,
            "ai_analysis":     ai_result,
            "scan_metadata": {
                "domain":                  domain,
                "total_findings":          len(all_findings),
                "scan_duration_seconds":   duration,
                "timestamp":               datetime.now().isoformat(),
                "ai_model":                "Groq Llama3-70B" if ai_result else "Rule-based only",
            },
        }

    # ------------------------------------------------------------------
    # Ingest: port_scan
    # scan_results['port_scan'] = [
    #   { 'target': str, 'ports': [{port, protocol, state, service, version, risk}],
    #     'risky_ports': [...], 'vulnerabilities': [...], 'os_guess': str }
    # ]
    # ------------------------------------------------------------------

    def _ingest_port_scan(self, scan_results: Dict, counter: List[int]) -> List[Dict]:
        findings: List[Dict] = []
        port_scan = scan_results.get("port_scan", [])

        for host_data in port_scan:
            if not isinstance(host_data, dict):
                continue
            target = host_data.get("target", "unknown")

            # ── risky_ports ───────────────────────────────────────────
            for rp in host_data.get("risky_ports", []):
                port    = rp.get("port")
                profile = PORT_PROFILES.get(port)
                if not profile:
                    # Generic risky port — use port_scanner's own risk field
                    risk_obj = rp.get("risk", {})
                    risk_lvl = risk_obj.get("level", "medium") if isinstance(risk_obj, dict) else str(risk_obj)
                    service  = rp.get("service", f"port/{port}")
                    t_score  = {"critical": 85, "high": 65, "medium": 40, "low": 20}.get(risk_lvl, 40)
                    b_score  = t_score
                    sev      = _score_to_severity(t_score)
                    findings.append(_vuln(
                        vuln_id         = _make_id("PORT", counter),
                        title           = f"Exposed service: {service} on port {port}",
                        source          = "port_exposure",
                        source_trust    = SOURCE_TRUST["port_exposure"],
                        technical_score = t_score * SOURCE_TRUST["port_exposure"],
                        business_score  = b_score,
                        severity        = sev,
                        affected_asset  = f"{target}:{port}",
                        description     = (
                            f"{service} exposed on port {port}/{rp.get('protocol','tcp')} "
                            f"(state: {rp.get('state','open')}). "
                            f"Version: {rp.get('version','unknown')}."
                        ),
                        evidence        = {"host": target, "port": port,
                                           "service": service, "version": rp.get("version","")},
                        remediation     = f"Firewall port {port} from public internet. "
                                          f"If service is required, enforce authentication and patch to latest version.",
                        attack_vector   = "network",
                        business_tags   = ["initial_access"],
                    ))
                    continue

                t_score = _cvss_like_score(
                    av=profile["av"], ac=profile["ac"],
                    pr=profile["pr"], ui=profile["ui"],
                    c=profile["c"],  i=profile["i"], a=profile["a"],
                    source_trust=SOURCE_TRUST["port_exposure"],
                )
                b_tags  = profile["business"]
                b_score = _business_score(t_score, b_tags)
                sev     = _score_to_severity(max(t_score, b_score))

                findings.append(_vuln(
                    vuln_id          = _make_id("PORT", counter),
                    title            = f"Exposed {profile['name']} on port {port} ({target})",
                    source           = "port_exposure",
                    source_trust     = SOURCE_TRUST["port_exposure"],
                    technical_score  = t_score,
                    business_score   = b_score,
                    severity         = sev,
                    affected_asset   = f"{target}:{port}",
                    description      = (
                        f"{profile['name']} (port {port}) is directly reachable from the internet. "
                        f"Version: {rp.get('version','unknown')}. "
                        f"OS: {host_data.get('os_guess','unknown')}."
                    ),
                    evidence         = {
                        "host":    target,
                        "port":    port,
                        "service": profile["name"],
                        "version": rp.get("version", ""),
                        "os":      host_data.get("os_guess", ""),
                    },
                    remediation      = (
                        f"Block port {port} at the network perimeter. "
                        f"If {profile['name']} must be internet-facing, enforce key-based auth "
                        f"(SSH), firewall to known IPs, and monitor for brute-force attempts."
                    ),
                    attack_vector    = "network",
                    business_tags    = b_tags,
                    exploit_complexity   = profile["ac"],
                    privileges_required  = profile["pr"],
                ))

            # ── nmap vuln scripts ─────────────────────────────────────
            for vuln in host_data.get("vulnerabilities", []):
                if not isinstance(vuln, dict):
                    continue
                cve_id  = vuln.get("cve") or vuln.get("id", "")
                risk    = vuln.get("risk", "high").lower()
                t_score = {"critical": 90, "high": 70, "medium": 45, "low": 20}.get(risk, 70)
                t_score *= SOURCE_TRUST["nmap_vuln_script"]
                b_score  = _business_score(t_score, ["data_exfiltration", "full_compromise"])
                sev      = _score_to_severity(max(t_score, b_score))

                findings.append(_vuln(
                    vuln_id          = _make_id("NVULN", counter),
                    title            = vuln.get("title", f"nmap vuln: {cve_id or 'unknown'}"),
                    source           = "nmap_vuln_script",
                    source_trust     = SOURCE_TRUST["nmap_vuln_script"],
                    technical_score  = t_score,
                    business_score   = b_score,
                    severity         = sev,
                    affected_asset   = target,
                    description      = vuln.get("description", "nmap vuln script detection."),
                    evidence         = vuln,
                    remediation      = vuln.get("solution", "Apply vendor patch immediately."),
                    attack_vector    = "network",
                    cve              = cve_id or None,
                    business_tags    = ["data_exfiltration", "full_compromise"],
                ))

        return findings

    # ------------------------------------------------------------------
    # Ingest: ssl_scan
    # scan_results['ssl_scan'] = {
    #   'main_domain': { 'vulnerabilities': {heartbleed: bool, ...},
    #                    'grade': str, 'protocols': {...} },
    #   '<subdomain>': { ... }
    # }
    # ------------------------------------------------------------------

    def _ingest_ssl_scan(self, scan_results: Dict, counter: List[int]) -> List[Dict]:
        findings: List[Dict] = []
        ssl_scan = scan_results.get("ssl_scan", {})
        if not isinstance(ssl_scan, dict):
            return findings

        for host, ssl_data in ssl_scan.items():
            if not isinstance(ssl_data, dict):
                continue

            vulns = ssl_data.get("vulnerabilities", {})
            if not isinstance(vulns, dict):
                continue

            for vuln_key, is_vulnerable in vulns.items():
                if not is_vulnerable:
                    continue
                profile = SSL_CVE_PROFILES.get(vuln_key)
                if not profile:
                    continue

                t_score = _cvss_like_score(
                    av=profile["av"], ac=profile["ac"],
                    pr=profile["pr"], ui=profile["ui"],
                    c=profile["c"],  i=profile["i"], a=profile["a"],
                    source_trust=SOURCE_TRUST["ssl_cve"],
                )
                b_tags  = profile["business"]
                b_score = _business_score(t_score, b_tags)
                sev     = _score_to_severity(max(t_score, b_score))

                findings.append(_vuln(
                    vuln_id          = _make_id("SSL", counter),
                    title            = f"{vuln_key.upper()} ({profile['cve']}) on {host}",
                    source           = "ssl_cve",
                    source_trust     = SOURCE_TRUST["ssl_cve"],
                    technical_score  = t_score,
                    business_score   = b_score,
                    severity         = sev,
                    affected_asset   = host,
                    description      = profile["description"],
                    evidence         = {
                        "host":      host,
                        "cve":       profile["cve"],
                        "ssl_grade": ssl_data.get("grade", "?"),
                        "protocols": ssl_data.get("protocols", {}),
                    },
                    remediation      = (
                        f"Disable {vuln_key.upper()}-affected protocol/feature. "
                        f"Upgrade OpenSSL / TLS stack. Grade currently: {ssl_data.get('grade','?')}."
                    ),
                    attack_vector    = "network",
                    cve              = profile["cve"],
                    cvss_base        = profile["cvss_base"],
                    business_tags    = b_tags,
                    exploit_complexity   = profile["ac"],
                    privileges_required  = profile["pr"],
                    user_interaction     = profile["ui"],
                ))

            # ── Deprecated protocol still enabled (SSLv2 / SSLv3 / TLS1.0) ─
            protocols = ssl_data.get("protocols", {})
            deprecated = {
                "SSLv2":  ("critical", "SSLv2 — completely broken, enables DROWN."),
                "SSLv3":  ("high",     "SSLv3 — vulnerable to POODLE, should be disabled."),
                "TLSv1":  ("medium",   "TLS 1.0 — deprecated by PCI-DSS 3.2+, vulnerable to BEAST."),
                "TLSv1.1": ("low",     "TLS 1.1 — deprecated, prefer TLS 1.2 / 1.3."),
            }
            for proto, (sev_label, desc) in deprecated.items():
                if protocols.get(proto, False):
                    t_score = HEADER_SEVERITY_SCORE.get(sev_label, 40) * SOURCE_TRUST["ssl_protocol"]
                    b_score = _business_score(t_score, ["credential_theft"])
                    findings.append(_vuln(
                        vuln_id          = _make_id("PROTO", counter),
                        title            = f"Deprecated protocol {proto} enabled on {host}",
                        source           = "ssl_protocol",
                        source_trust     = SOURCE_TRUST["ssl_protocol"],
                        technical_score  = t_score,
                        business_score   = b_score,
                        severity         = sev_label,
                        affected_asset   = host,
                        description      = desc,
                        evidence         = {"host": host, "protocol": proto, "enabled": True},
                        remediation      = f"Disable {proto} in server TLS configuration. Enforce TLS 1.2 minimum.",
                        attack_vector    = "network",
                        business_tags    = ["credential_theft"],
                    ))

        return findings

    # ------------------------------------------------------------------
    # Ingest: header_analysis (AIHeaderAnalyzer output)
    # scan_results['header_analysis']['targets'][url] = {
    #   'findings': [{ type, header, severity, description, attack_class,
    #                  recommendation, exposed_value? }]
    # }
    # ------------------------------------------------------------------

    def _ingest_header_analysis(self, scan_results: Dict, counter: List[int]) -> List[Dict]:
        findings: List[Dict] = []
        ha = scan_results.get("header_analysis", {})
        if not isinstance(ha, dict):
            return findings

        for url, target_data in ha.get("targets", {}).items():
            if not isinstance(target_data, dict) or not target_data.get("reachable", True):
                continue

            for f in target_data.get("findings", []):
                if not isinstance(f, dict):
                    continue

                sev     = f.get("severity", "low")
                t_score = HEADER_SEVERITY_SCORE.get(sev, 20) * SOURCE_TRUST["header_missing"]
                b_tags  = self._header_to_business_tags(f)
                b_score = _business_score(t_score, b_tags)
                sev_out = _score_to_severity(max(t_score, b_score))

                source_key = (
                    "header_weak"    if f.get("type", "").startswith("weak")
                    else "header_missing"
                )

                findings.append(_vuln(
                    vuln_id          = _make_id("HDR", counter),
                    title            = f"{f.get('type','header_issue').replace('_',' ').title()}: {f.get('header','')} on {url}",
                    source           = source_key,
                    source_trust     = SOURCE_TRUST[source_key],
                    technical_score  = t_score,
                    business_score   = b_score,
                    severity         = sev_out,
                    affected_asset   = url,
                    description      = f.get("description", ""),
                    evidence         = {
                        "url":            url,
                        "header":         f.get("header"),
                        "type":           f.get("type"),
                        "exposed_value":  f.get("exposed_value", ""),
                        "attack_class":   f.get("attack_class", []),
                    },
                    remediation      = f.get("recommendation", "Consult OWASP Secure Headers Project."),
                    attack_vector    = "network",
                    business_tags    = b_tags,
                ))

        return findings

    def _header_to_business_tags(self, finding: Dict) -> List[str]:
        attack_classes = [a.lower() for a in finding.get("attack_class", [])]
        tags: List[str] = []
        if any("xss" in a or "injection" in a for a in attack_classes):
            tags += ["credential_theft", "data_exfiltration"]
        if any("clickjack" in a or "ui redress" in a for a in attack_classes):
            tags += ["credential_theft"]
        if any("mitm" in a or "ssl" in a or "downgrade" in a for a in attack_classes):
            tags += ["credential_theft", "data_exfiltration"]
        if any("information" in a or "disclosure" in a or "fingerprint" in a for a in attack_classes):
            tags += ["initial_access"]
        if any("cors" in a or "csrf" in a for a in attack_classes):
            tags += ["credential_theft", "data_exfiltration"]
        if not tags:
            tags = ["initial_access"]
        return list(set(tags))

    # ------------------------------------------------------------------
    # Ingest: takeover_analysis (AISubdomainTakeoverAnalyzer output)
    # scan_results['takeover_analysis'] = {
    #   'vulnerable': [{ subdomain, service, confidence_level, cname_chain,
    #                    takeover_method, http_evidence, difficulty }],
    #   'dangling_dns': [{ subdomain, dangling_reason, cname_chain }]
    # }
    # ------------------------------------------------------------------

    def _ingest_takeover_analysis(self, scan_results: Dict, counter: List[int]) -> List[Dict]:
        findings: List[Dict] = []
        ta = scan_results.get("takeover_analysis", {})
        if not isinstance(ta, dict):
            return findings

        for entry in ta.get("vulnerable", []):
            if not isinstance(entry, dict):
                continue
            confidence = entry.get("confidence_level", "medium")
            t_score    = TAKEOVER_CONFIDENCE_SCORE.get(confidence, 75) * SOURCE_TRUST["subdomain_takeover"]
            b_tags     = ["credential_theft", "reputational", "data_exfiltration"]
            b_score    = _business_score(t_score, b_tags)
            sev        = _score_to_severity(max(t_score, b_score))

            confirmed  = entry.get("http_evidence", {}).get("confirmed", False)
            title_sfx  = "CONFIRMED" if confirmed else "probable"

            findings.append(_vuln(
                vuln_id          = _make_id("TKOVER", counter),
                title            = f"Subdomain takeover ({title_sfx}): {entry.get('subdomain','')} → {entry.get('service','')}",
                source           = "subdomain_takeover",
                source_trust     = SOURCE_TRUST["subdomain_takeover"],
                technical_score  = t_score,
                business_score   = b_score,
                severity         = sev,
                affected_asset   = entry.get("subdomain", ""),
                description      = (
                    f"Dangling CNAME points to unclaimed {entry.get('service','')} resource. "
                    f"An attacker can register the resource and serve malicious content "
                    f"on {entry.get('subdomain','')} under the target's trusted domain."
                ),
                evidence         = {
                    "subdomain":        entry.get("subdomain"),
                    "service":          entry.get("service"),
                    "cname_chain":      entry.get("cname_chain", []),
                    "confidence":       confidence,
                    "http_confirmed":   confirmed,
                    "matched_pattern":  entry.get("http_evidence", {}).get("matched_body_pattern"),
                    "status_code":      entry.get("http_evidence", {}).get("status_code"),
                },
                remediation      = (
                    f"Remove or update the CNAME record for {entry.get('subdomain','')}. "
                    f"If the {entry.get('service','')} resource is intentional, claim it immediately. "
                    f"Takeover method: {entry.get('takeover_method','See can-i-take-over-xyz project.')}."
                ),
                attack_vector    = "network",
                business_tags    = b_tags,
                exploit_complexity   = "low" if entry.get("difficulty","medium") == "easy" else "medium",
            ))

        for entry in ta.get("dangling_dns", []):
            if not isinstance(entry, dict):
                continue
            t_score = 55 * SOURCE_TRUST["cname_dangling"]
            b_score = _business_score(t_score, ["reputational", "credential_theft"])
            sev     = _score_to_severity(max(t_score, b_score))

            findings.append(_vuln(
                vuln_id          = _make_id("DANGLE", counter),
                title            = f"Dangling DNS: {entry.get('subdomain','')}",
                source           = "cname_dangling",
                source_trust     = SOURCE_TRUST["cname_dangling"],
                technical_score  = t_score,
                business_score   = b_score,
                severity         = sev,
                affected_asset   = entry.get("subdomain", ""),
                description      = entry.get("dangling_reason", "CNAME target resolves to NXDOMAIN."),
                evidence         = {
                    "subdomain":    entry.get("subdomain"),
                    "cname_chain":  entry.get("cname_chain", []),
                    "reason":       entry.get("dangling_reason"),
                },
                remediation      = (
                    "Remove the stale CNAME record from DNS immediately. "
                    "If the target service is required, re-create the resource and update the CNAME."
                ),
                attack_vector    = "network",
                business_tags    = ["reputational", "credential_theft"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Ingest: osint_correlation
    # Reads: credential_leaks, reputation (malware), dns_intelligence
    # ------------------------------------------------------------------

    def _ingest_osint_correlation(self, scan_results: Dict, counter: List[int]) -> List[Dict]:
        findings: List[Dict] = []
        osint = scan_results.get("osint_correlation", {})
        if not isinstance(osint, dict):
            return findings

        # ── GitHub credential leaks ───────────────────────────────────
        cred_leaks = osint.get("credential_leaks", {})
        for hit in cred_leaks.get("github_hits", []):
            if not isinstance(hit, dict):
                continue
            secrets = hit.get("secrets_found", [])
            if not secrets:
                continue

            t_score = 88 * SOURCE_TRUST["credential_leak"]
            b_score = _business_score(t_score, ["credential_theft", "data_exfiltration", "full_compromise"])
            sev     = _score_to_severity(max(t_score, b_score))

            findings.append(_vuln(
                vuln_id          = _make_id("CRED", counter),
                title            = f"Credential/secret leak in GitHub repo: {hit.get('repo','')}",
                source           = "credential_leak",
                source_trust     = SOURCE_TRUST["credential_leak"],
                technical_score  = t_score,
                business_score   = b_score,
                severity         = sev,
                affected_asset   = hit.get("repo", "github"),
                description      = (
                    f"Repository {hit.get('repo','')} contains potential secrets "
                    f"({', '.join(s['type'] for s in secrets[:3])}). "
                    f"File: {hit.get('path','')}."
                ),
                evidence         = {
                    "repo":    hit.get("repo"),
                    "file":    hit.get("file"),
                    "path":    hit.get("path"),
                    "url":     hit.get("url"),
                    "secrets": secrets[:5],
                    "private": hit.get("private", False),
                },
                remediation      = (
                    "Rotate all exposed credentials immediately. "
                    "Remove secrets from repository history with git-filter-repo. "
                    "Add pre-commit hooks (gitleaks, trufflehog) to prevent future leaks."
                ),
                attack_vector    = "network",
                business_tags    = ["credential_theft", "data_exfiltration", "full_compromise"],
                exploit_complexity = "low",
            ))

        # ── Malware / blacklist flags from VirusTotal / AlienVault ────
        reputation = osint.get("reputation", {})
        malware_samples = reputation.get("malware_samples", [])
        vt_stats        = reputation.get("virustotal", {}) or {}
        malicious_count = vt_stats.get("malicious", 0) if isinstance(vt_stats, dict) else 0

        if malware_samples or malicious_count > 0:
            t_score = min(90, 50 + (malicious_count * 3) + len(malware_samples) * 5)
            t_score *= SOURCE_TRUST["shodan_cve"]
            b_score = _business_score(t_score, ["reputational", "data_exfiltration"])
            sev     = _score_to_severity(max(t_score, b_score))

            findings.append(_vuln(
                vuln_id          = _make_id("REP", counter),
                title            = f"Domain flagged malicious — {malicious_count} VT detections, {len(malware_samples)} malware samples",
                source           = "shodan_cve",
                source_trust     = SOURCE_TRUST["shodan_cve"],
                technical_score  = t_score,
                business_score   = b_score,
                severity         = sev,
                affected_asset   = scan_results.get("domain", ""),
                description      = (
                    f"Domain has {malicious_count} VirusTotal malicious detections "
                    f"and {len(malware_samples)} associated malware samples in AlienVault OTX. "
                    "May indicate prior compromise, phishing abuse, or C2 infrastructure."
                ),
                evidence         = {
                    "vt_stats":       vt_stats,
                    "malware_count":  len(malware_samples),
                    "sample_hashes":  [s.get("hash","") for s in malware_samples[:5]],
                },
                remediation      = (
                    "Investigate server for active compromise. "
                    "Request VT / Google / Cloudflare reputation re-review after cleanup. "
                    "Review access logs for C2 patterns."
                ),
                attack_vector    = "network",
                business_tags    = ["reputational", "data_exfiltration"],
            ))

        # ── DNS intelligence weaknesses (from AIOSINTCorrelator) ─────
        dns_intel = osint.get("dns_intelligence", {})
        if isinstance(dns_intel, dict):
            # DMARC
            dmarc = dns_intel.get("dmarc_analysis", {}) or {}
            if not dmarc.get("present", True):
                cfg = DNS_WEAKNESS_SCORES["no_dmarc"]
                t   = cfg["score"] * SOURCE_TRUST["dns_weakness"]
                b   = _business_score(t, cfg["business"])
                findings.append(_vuln(
                    vuln_id          = _make_id("DNS", counter),
                    title            = "No DMARC record — domain spoofable in email From header",
                    source           = "dns_weakness",
                    source_trust     = SOURCE_TRUST["dns_weakness"],
                    technical_score  = t,
                    business_score   = b,
                    severity         = _score_to_severity(max(t, b)),
                    affected_asset   = scan_results.get("domain", ""),
                    description      = "Absence of DMARC allows anyone to send email impersonating this domain. No policy enforcement on spoofed mail.",
                    evidence         = {"dmarc": dmarc},
                    remediation      = "Add _dmarc TXT record. Start with p=none for monitoring, graduate to p=quarantine then p=reject.",
                    attack_vector    = "network",
                    business_tags    = cfg["business"],
                ))
            elif dmarc.get("policy") == "none":
                cfg = DNS_WEAKNESS_SCORES["dmarc_none"]
                t   = cfg["score"] * SOURCE_TRUST["dns_weakness"]
                b   = _business_score(t, cfg["business"])
                findings.append(_vuln(
                    vuln_id          = _make_id("DNS", counter),
                    title            = "DMARC policy=none — monitoring only, spoofing not blocked",
                    source           = "dns_weakness",
                    source_trust     = SOURCE_TRUST["dns_weakness"],
                    technical_score  = t,
                    business_score   = b,
                    severity         = _score_to_severity(max(t, b)),
                    affected_asset   = scan_results.get("domain", ""),
                    description      = "DMARC policy is set to none — receives reports but does not reject or quarantine spoofed mail.",
                    evidence         = {"dmarc": dmarc},
                    remediation      = "Upgrade DMARC policy from p=none to p=quarantine, then p=reject after reviewing aggregate reports.",
                    attack_vector    = "network",
                    business_tags    = cfg["business"],
                ))

            # SPF
            spf = dns_intel.get("spf_analysis", {}) or {}
            if not spf.get("present", True):
                cfg = DNS_WEAKNESS_SCORES["no_spf"]
                t   = cfg["score"] * SOURCE_TRUST["dns_weakness"]
                b   = _business_score(t, cfg["business"])
                findings.append(_vuln(
                    vuln_id          = _make_id("DNS", counter),
                    title            = "No SPF record — any server can send as this domain",
                    source           = "dns_weakness",
                    source_trust     = SOURCE_TRUST["dns_weakness"],
                    technical_score  = t,
                    business_score   = b,
                    severity         = _score_to_severity(max(t, b)),
                    affected_asset   = scan_results.get("domain", ""),
                    description      = "No SPF TXT record found. Any mail server can claim to be this domain.",
                    evidence         = {"spf": spf},
                    remediation      = "Add SPF TXT record: 'v=spf1 include:<mailprovider> -all'. Use -all (hardfail).",
                    attack_vector    = "network",
                    business_tags    = cfg["business"],
                ))
            elif spf.get("risk") == "high":
                cfg = DNS_WEAKNESS_SCORES["spf_plus_all"]
                t   = cfg["score"] * SOURCE_TRUST["dns_weakness"]
                b   = _business_score(t, cfg["business"])
                findings.append(_vuln(
                    vuln_id          = _make_id("DNS", counter),
                    title            = "Weak SPF — +all or no fail mode allows spoofing",
                    source           = "dns_weakness",
                    source_trust     = SOURCE_TRUST["dns_weakness"],
                    technical_score  = t,
                    business_score   = b,
                    severity         = _score_to_severity(max(t, b)),
                    affected_asset   = scan_results.get("domain", ""),
                    description      = f"SPF fail mode is '{spf.get('fail_mode','?')}' — insufficient to block spoofing.",
                    evidence         = {"spf": spf},
                    remediation      = "Change SPF to end with -all (hardfail) to reject unauthenticated senders.",
                    attack_vector    = "network",
                    business_tags    = cfg["business"],
                ))

            # Open resolver
            if dns_intel.get("open_resolver", False):
                cfg = DNS_WEAKNESS_SCORES["open_resolver"]
                t   = cfg["score"] * SOURCE_TRUST["dns_weakness"]
                b   = _business_score(t, cfg["business"])
                findings.append(_vuln(
                    vuln_id          = _make_id("DNS", counter),
                    title            = "Open DNS resolver — amplification / cache poisoning risk",
                    source           = "dns_weakness",
                    source_trust     = SOURCE_TRUST["dns_weakness"],
                    technical_score  = t,
                    business_score   = b,
                    severity         = _score_to_severity(max(t, b)),
                    affected_asset   = scan_results.get("domain", ""),
                    description      = "Nameserver accepts recursive queries from arbitrary IPs. Usable for DNS amplification DDoS and potential cache poisoning.",
                    evidence         = {"open_resolver": True},
                    remediation      = "Restrict recursive resolution to authorised clients only. Disable recursion on authoritative nameservers.",
                    attack_vector    = "network",
                    business_tags    = cfg["business"],
                ))

        return findings

    # ------------------------------------------------------------------
    # Ingest: security_analysis (FastSecurityAnalyst output)
    # Reads: risk_assessment, high_value_targets, attack_surface
    # ------------------------------------------------------------------

    def _ingest_security_analysis(self, scan_results: Dict, counter: List[int]) -> List[Dict]:
        findings: List[Dict] = []
        sa = scan_results.get("security_analysis", {})
        if not isinstance(sa, dict):
            return findings

        # ── high_value_targets from FastSecurityAnalyst ──────────────
        for target in sa.get("high_value_targets", []):
            if not isinstance(target, dict):
                continue
            score     = target.get("security_score", 0)
            risk_lvl  = target.get("risk_level", "low").lower()
            if risk_lvl not in ("critical", "high"):
                continue   # only escalate critical/high from heuristic source

            t_score   = min(score * 0.7, 65) * SOURCE_TRUST["fast_analyst"]
            b_score   = _business_score(t_score, ["initial_access"])
            sev       = _score_to_severity(max(t_score, b_score))
            reasons   = target.get("reasons", [])
            subdomain = target.get("subdomain", "")

            findings.append(_vuln(
                vuln_id          = _make_id("HSUB", counter),
                title            = f"High-value subdomain: {subdomain} ({', '.join(reasons[:2])})",
                source           = "fast_analyst",
                source_trust     = SOURCE_TRUST["fast_analyst"],
                technical_score  = t_score,
                business_score   = b_score,
                severity         = sev,
                affected_asset   = subdomain,
                description      = (
                    f"Subdomain '{subdomain}' classified {risk_lvl} risk by heuristic analysis. "
                    f"Indicators: {', '.join(reasons)}. "
                    f"HTTP: {target.get('http_status','?')} / HTTPS: {target.get('https_status','?')}."
                ),
                evidence         = {
                    "subdomain":    subdomain,
                    "risk_level":   risk_lvl,
                    "score":        score,
                    "reasons":      reasons,
                    "http_status":  target.get("http_status"),
                    "https_status": target.get("https_status"),
                    "ip":           target.get("ip"),
                },
                remediation      = (
                    "Perform targeted manual penetration test on this subdomain. "
                    "Verify authentication controls, check for default credentials, "
                    "and ensure access is restricted to authorised users."
                ),
                attack_vector    = "network",
                business_tags    = ["initial_access"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Ingest: payload_analysis (AIPayloadGenerator output)
    # Reads: vuln_classes, tech_profile
    # Note: vuln classes are inferences — lowest source trust
    # ------------------------------------------------------------------

    def _ingest_payload_classes(self, scan_results: Dict, counter: List[int]) -> List[Dict]:
        findings: List[Dict] = []
        pa = scan_results.get("payload_analysis", {})
        if not isinstance(pa, dict):
            return findings

        vuln_classes = pa.get("vuln_classes", [])
        tech_profile = pa.get("tech_profile", {})
        waf          = pa.get("waf_detected", {})

        # Map vuln class → base score and business tags
        CLASS_PROFILES: Dict[str, Tuple[int, List[str]]] = {
            "sqli":               (80, ["data_exfiltration", "credential_theft", "full_compromise"]),
            "sqli_mysql":         (80, ["data_exfiltration", "credential_theft"]),
            "sqli_mssql":         (85, ["data_exfiltration", "full_compromise"]),
            "sqli_postgres":      (78, ["data_exfiltration"]),
            "sqli_oracle":        (78, ["data_exfiltration"]),
            "xss":                (60, ["credential_theft", "data_exfiltration"]),
            "ssti":               (85, ["full_compromise", "data_exfiltration"]),
            "ssrf":               (75, ["data_exfiltration", "lateral_movement"]),
            "xxe":                (72, ["data_exfiltration", "ssrf"]),
            "cmdi":               (90, ["full_compromise", "persistence"]),
            "nosql":              (70, ["data_exfiltration", "credential_theft"]),
            "path_traversal":     (65, ["data_exfiltration"]),
            "jwt_attacks":        (75, ["credential_theft", "data_exfiltration"]),
            "graphql":            (55, ["data_exfiltration", "initial_access"]),
            "http_request_smuggling": (70, ["credential_theft", "data_exfiltration"]),
            "cors_misconfiguration":  (68, ["credential_theft", "data_exfiltration"]),
            "open_redirect":      (40, ["credential_theft", "reputational"]),
            "csrf":               (45, ["credential_theft"]),
            "idor":               (60, ["data_exfiltration", "pii_exposure"]),
            "wordpress_enum":     (50, ["initial_access"]),
        }

        for vc in vuln_classes:
            if vc not in CLASS_PROFILES:
                continue
            base, b_tags = CLASS_PROFILES[vc]
            t_score = base * SOURCE_TRUST["payload_class"]
            b_score = _business_score(t_score, b_tags)
            sev     = _score_to_severity(max(t_score, b_score))

            # Bump score slightly if confirmed tech stack makes the class likely
            stack_note = ""
            db = tech_profile.get("database", "")
            lang = tech_profile.get("language", "")
            fw   = tech_profile.get("framework", "")
            if "sqli" in vc and db:
                t_score = min(100, t_score * 1.15)
                stack_note = f" Detected DB: {db}."
            if "ssti" in vc and fw:
                t_score = min(100, t_score * 1.2)
                stack_note = f" Detected framework: {fw}."

            waf_note = ""
            if waf.get("detected"):
                waf_note = f" WAF detected: {waf.get('name')} — bypass required."
                t_score *= 0.85  # harder to exploit through WAF

            findings.append(_vuln(
                vuln_id          = _make_id("VCLS", counter),
                title            = f"Potential {vc.replace('_',' ').upper()} — inferred from stack ({tech_profile.get('language','?')}/{tech_profile.get('framework','?')})",
                source           = "payload_class",
                source_trust     = SOURCE_TRUST["payload_class"],
                technical_score  = round(t_score, 2),
                business_score   = round(b_score, 2),
                severity         = sev,
                affected_asset   = scan_results.get("domain", ""),
                description      = (
                    f"Stack analysis indicates potential {vc} attack surface.{stack_note}{waf_note} "
                    f"Manual verification required — this is an inference, not a confirmed finding."
                ),
                evidence         = {
                    "vuln_class":  vc,
                    "tech_stack":  {
                        "language":  lang,
                        "framework": fw,
                        "database":  db,
                        "cms":       tech_profile.get("cms"),
                    },
                    "waf":         waf,
                },
                remediation      = f"Perform targeted {vc} testing using ARTEX payload_analysis payloads. Confirm before reporting.",
                attack_vector    = "network",
                business_tags    = b_tags,
            ))

        return findings

    # ------------------------------------------------------------------
    # Ingest: dns_records (direct from dns_scan module)
    # scan_results['dns_records'] = {A:[], MX:[], SPF:[], TXT:[], NS:[]}
    # Only adds findings not already covered by osint_correlation
    # ------------------------------------------------------------------

    def _ingest_dns_records(self, scan_results: Dict, counter: List[int]) -> List[Dict]:
        findings: List[Dict] = []
        dns = scan_results.get("dns_records", {})
        if not isinstance(dns, dict):
            return findings

        # If osint_correlation already ran DNS intelligence, skip to avoid duplication
        if scan_results.get("osint_correlation", {}).get("dns_intelligence"):
            return findings

        # SPF check from raw TXT records
        txt_records = dns.get("TXT", []) + dns.get("SPF", [])
        has_spf = any("v=spf1" in str(r) for r in txt_records)
        has_dmarc_record = any("v=DMARC1" in str(r) for r in txt_records)

        if not has_spf:
            cfg = DNS_WEAKNESS_SCORES["no_spf"]
            t   = cfg["score"] * SOURCE_TRUST["dns_weakness"]
            b   = _business_score(t, cfg["business"])
            findings.append(_vuln(
                vuln_id          = _make_id("DNS2", counter),
                title            = "No SPF record found",
                source           = "dns_weakness",
                source_trust     = SOURCE_TRUST["dns_weakness"],
                technical_score  = t,
                business_score   = b,
                severity         = _score_to_severity(max(t, b)),
                affected_asset   = scan_results.get("domain", ""),
                description      = "No SPF record in DNS TXT records. Email spoofing not restricted.",
                evidence         = {"txt_records": [str(r)[:100] for r in txt_records[:5]]},
                remediation      = "Add SPF TXT record ending with -all.",
                attack_vector    = "network",
                business_tags    = cfg["business"],
            ))

        if not has_dmarc_record:
            cfg = DNS_WEAKNESS_SCORES["no_dmarc"]
            t   = cfg["score"] * SOURCE_TRUST["dns_weakness"]
            b   = _business_score(t, cfg["business"])
            findings.append(_vuln(
                vuln_id          = _make_id("DNS2", counter),
                title            = "No DMARC record found",
                source           = "dns_weakness",
                source_trust     = SOURCE_TRUST["dns_weakness"],
                technical_score  = t,
                business_score   = b,
                severity         = _score_to_severity(max(t, b)),
                affected_asset   = scan_results.get("domain", ""),
                description      = "No DMARC record. Domain identity not protected against email spoofing.",
                evidence         = {"txt_sample": [str(r)[:80] for r in txt_records[:3]]},
                remediation      = "Add _dmarc TXT: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com'",
                attack_vector    = "network",
                business_tags    = cfg["business"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Deduplication — merge findings with same title+asset from different sources
    # Keep the one with higher final_score, enrich evidence
    # ------------------------------------------------------------------

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        seen: Dict[str, Dict] = {}

        for f in findings:
            # Key: normalised title + asset
            key = f"{f['title'].lower()[:60]}|{f['affected_asset'].lower()[:40]}"
            if key not in seen:
                seen[key] = f
            else:
                existing = seen[key]
                if f["final_score"] > existing["final_score"]:
                    # Merge evidence from lower-scoring duplicate into winner
                    f["evidence"]["_also_detected_by"] = existing["source"]
                    seen[key] = f
                else:
                    existing["evidence"]["_also_detected_by"] = f["source"]

        return list(seen.values())

    # ------------------------------------------------------------------
    # Asset risk map — group findings by affected_asset
    # ------------------------------------------------------------------

    def _build_asset_risk_map(self, findings: List[Dict]) -> Dict[str, Dict]:
        asset_map: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            asset_map[f["affected_asset"]].append(f)

        result: Dict[str, Dict] = {}
        for asset, asset_findings in asset_map.items():
            scores  = [f["final_score"] for f in asset_findings]
            sevs    = [f["severity"] for f in asset_findings]
            worst   = max(sevs, key=lambda s: ["info","low","medium","high","critical"].index(s))
            top3    = sorted(asset_findings, key=lambda x: x["final_score"], reverse=True)[:3]

            result[asset] = {
                "asset":           asset,
                "finding_count":   len(asset_findings),
                "max_score":       max(scores),
                "avg_score":       round(sum(scores) / len(scores), 2),
                "worst_severity":  worst,
                "top_findings":    [
                    {"vuln_id": f["vuln_id"], "title": f["title"], "score": f["final_score"]}
                    for f in top3
                ],
                "severity_breakdown": {
                    s: sum(1 for f in asset_findings if f["severity"] == s)
                    for s in ["critical", "high", "medium", "low", "info"]
                },
            }

        return result

    # ------------------------------------------------------------------
    # Attack chain inference — look for exploitable finding combinations
    # ------------------------------------------------------------------

    def _infer_attack_chains(self, findings: List[Dict], domain: str) -> List[Dict]:
        chains: List[Dict] = []

        sources   = {f["source"] for f in findings}
        sev_set   = {f["severity"] for f in findings}
        vuln_ids  = {f["vuln_id"] for f in findings}
        b_tags    = {tag for f in findings for tag in f.get("business_tags", [])}

        has = lambda src: src in sources
        any_sev = lambda *s: any(x in sev_set for x in s)

        # ── Chain 1: Credential reuse → SSH / DB pivot ────────────────
        if has("credential_leak") and (
            any(f["source"] == "port_exposure" and "SSH" in f["title"] for f in findings) or
            any(f["source"] == "port_exposure" and any(d in f["title"] for d in ["MySQL","Redis","MongoDB","PostgreSQL"]) for f in findings)
        ):
            chains.append({
                "chain_name":  "Credential Leak → Service Pivot",
                "severity":    "critical",
                "steps": [
                    "1. Extract credentials/API keys from GitHub leak findings.",
                    "2. Attempt authentication against exposed SSH / database port.",
                    "3. Establish foothold; enumerate internal services.",
                    "4. Lateral movement or data exfiltration.",
                ],
                "finding_sources": ["credential_leak", "port_exposure"],
                "impact": "Full compromise — persistent access to production infrastructure.",
            })

        # ── Chain 2: Subdomain takeover → phishing ────────────────────
        if has("subdomain_takeover") and has("dns_weakness"):
            chains.append({
                "chain_name": "Subdomain Takeover → Phishing Campaign",
                "severity":   "high",
                "steps": [
                    "1. Claim dangling CNAME resource (vulnerable subdomain).",
                    "2. Host convincing login page on the trusted subdomain.",
                    "3. Send phishing emails — DMARC/SPF weakness means no enforcement.",
                    "4. Harvest credentials or deploy malware via trusted domain.",
                ],
                "finding_sources": ["subdomain_takeover", "dns_weakness"],
                "impact": "Phishing at scale using trusted domain — high success rate.",
            })

        # ── Chain 3: SQLi → data exfil ────────────────────────────────
        if any("SQLI" in f["vuln_id"] or "sqli" in f.get("evidence", {}).get("vuln_class", "") for f in findings):
            chains.append({
                "chain_name": "SQL Injection → Data Exfiltration",
                "severity":   "critical",
                "steps": [
                    "1. Identify injectable parameter via error or time-based probing.",
                    "2. Enumerate database schema (tables, columns).",
                    "3. Dump sensitive tables (users, credentials, PII).",
                    "4. Optionally: escalate to OS command execution (MSSQL xp_cmdshell / MySQL FILE).",
                ],
                "finding_sources": ["payload_class", "port_exposure"],
                "impact": "Mass data breach — PII, credentials, intellectual property.",
            })

        # ── Chain 4: SSRF → Cloud metadata → credential exfil ─────────
        if any("ssrf" in f.get("evidence", {}).get("vuln_class", "") for f in findings):
            if any("AWS" in str(f) or "Azure" in str(f) or "GCP" in str(f) for f in findings):
                chains.append({
                    "chain_name": "SSRF → Cloud Metadata → IAM Credential Theft",
                    "severity":   "critical",
                    "steps": [
                        "1. Trigger SSRF with http://169.254.169.254/latest/meta-data/ payload.",
                        "2. Read IAM security credentials from metadata endpoint.",
                        "3. Use stolen AWS/Azure/GCP credentials to access cloud resources.",
                        "4. Escalate to full cloud account takeover.",
                    ],
                    "finding_sources": ["payload_class", "ip_enrichment"],
                    "impact": "Cloud account compromise — data exfiltration, infrastructure destruction.",
                })

        # ── Chain 5: Exposed RDP/SSH + no MFA → ransomware ───────────
        if any(
            f["source"] == "port_exposure" and f.get("evidence", {}).get("port") in (3389, 22)
            for f in findings
        ):
            chains.append({
                "chain_name": "Exposed RDP/SSH → Ransomware Deployment",
                "severity":   "critical",
                "steps": [
                    "1. Brute-force or credential-stuff RDP/SSH using leaked or common passwords.",
                    "2. Establish interactive session on target host.",
                    "3. Disable AV, escalate privileges.",
                    "4. Deploy ransomware payload; exfiltrate data before encryption.",
                ],
                "finding_sources": ["port_exposure", "credential_leak"],
                "impact": "Full host compromise — ransomware, data exfil, operational disruption.",
            })

        # ── Chain 6: SSTI → RCE ───────────────────────────────────────
        if any("ssti" in f.get("evidence", {}).get("vuln_class", "") for f in findings):
            chains.append({
                "chain_name": "SSTI → Remote Code Execution → Persistence",
                "severity":   "critical",
                "steps": [
                    "1. Confirm SSTI via {{7*7}} or ${7*7} polyglot payload.",
                    "2. Identify template engine from framework fingerprint.",
                    "3. Execute OS commands via engine-specific payload (Jinja2 __subclasses__, Twig filter, etc.).",
                    "4. Deploy web shell or reverse shell; establish persistence.",
                ],
                "finding_sources": ["payload_class"],
                "impact": "Full server RCE — equivalent to OS-level compromise.",
            })

        return chains

    # ------------------------------------------------------------------
    # Overall risk score
    # ------------------------------------------------------------------

    def _calculate_overall_risk(
        self,
        findings: List[Dict],
        severity_counts: Dict[str, int],
    ) -> Dict:
        if not findings:
            return {"score": 0, "level": "info", "rationale": "No findings collected."}

        # Weighted sum — critical findings dominate
        weights = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 1}
        weighted_sum = sum(
            weights.get(sev, 1) * count
            for sev, count in severity_counts.items()
        )

        # Also factor in the top-5 average final_score
        top5_avg = sum(f["final_score"] for f in findings[:5]) / min(5, len(findings))

        raw = (weighted_sum * 0.4) + (top5_avg * 0.6)
        score = min(100, round(raw, 1))

        level = (
            "critical" if score >= 80
            else "high"   if score >= 55
            else "medium" if score >= 30
            else "low"    if score >= 10
            else "info"
        )

        # Build rationale
        crit_count = severity_counts.get("critical", 0)
        high_count = severity_counts.get("high", 0)
        chains_note = ""
        rationale = (
            f"{crit_count} critical and {high_count} high severity findings detected. "
            f"Top finding score: {findings[0]['final_score']:.1f}/100 ({findings[0]['title'][:60]}). "
            f"Total findings across all sources: {len(findings)}."
        )

        return {"score": score, "level": level, "rationale": rationale}

    # ------------------------------------------------------------------
    # Coverage map
    # ------------------------------------------------------------------

    def _build_coverage_map(self, findings: List[Dict]) -> Dict[str, int]:
        coverage: Dict[str, int] = defaultdict(int)
        for f in findings:
            coverage[f["source"]] += 1
        return dict(coverage)

    # ------------------------------------------------------------------
    # Pass 2 — Groq AI enrichment
    # ------------------------------------------------------------------

    def _ai_analysis(
        self,
        domain: str,
        top_findings: List[Dict],
        overall_risk: Dict,
        attack_chains: List[Dict],
    ) -> Optional[Dict]:
        try:
            prompt = self._build_prompt(domain, top_findings, overall_risk, attack_chains)
            text   = self._call_groq(prompt)
            if not text:
                return None
            return self._parse_ai_response(text)
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return None

    def _build_prompt(
        self,
        domain: str,
        top_findings: List[Dict],
        overall_risk: Dict,
        attack_chains: List[Dict],
    ) -> str:
        condensed_findings = [
            {
                "vuln_id":       f["vuln_id"],
                "title":         f["title"],
                "severity":      f["severity"],
                "final_score":   f["final_score"],
                "technical":     f["technical_score"],
                "business":      f["business_score"],
                "source":        f["source"],
                "affected_asset": f["affected_asset"],
                "cve":           f.get("cve"),
                "business_tags": f.get("business_tags", []),
                "attack_vector": f.get("attack_vector"),
            }
            for f in top_findings[:15]
        ]

        condensed_chains = [
            {
                "name":     c["chain_name"],
                "severity": c["severity"],
                "impact":   c["impact"],
            }
            for c in attack_chains[:4]
        ]

        return f"""You are a lead penetration tester and CISO-level security advisor.
Analyze the following prioritized vulnerability findings for {domain} and return ONLY valid JSON.

Overall Risk: {json.dumps(overall_risk, indent=2)}

Top Findings (scored 0–100, 55% technical / 45% business impact):
{json.dumps(condensed_findings, indent=2)}

Inferred Attack Chains:
{json.dumps(condensed_chains, indent=2)}

Return a JSON object with EXACTLY these keys:
- "executive_summary": string — 3–5 sentences suitable for a CISO briefing. No jargon without explanation.
- "top5_critical_actions": array of objects, each with:
    "rank" (int 1–5), "action" (string — specific, concrete, not generic),
    "addresses_findings" (array of vuln_id strings),
    "effort" (quick-win / short-term / long-term),
    "expected_risk_reduction" (string — e.g. "eliminates 3 critical, 2 high").
- "scoring_rationale": object with:
    "methodology" (string — brief explanation of technical × business scoring),
    "top_finding_justification" (string — why the #1 finding scored highest),
    "business_impact_analysis" (string — which findings have highest regulatory/financial exposure).
- "remediation_roadmap": array of objects ordered by urgency, each with:
    "phase" (string — Immediate/30-day/90-day),
    "items" (array of strings — specific tasks).
- "false_positive_warnings": array of strings — which finding sources have lower confidence
    and should be manually verified before reporting to stakeholders.
- "hunter_vs_defender_split": object with:
    "hunter_priorities" (array of strings — top 3 for bug bounty / red team),
    "defender_priorities" (array of strings — top 3 for the blue team).

Return ONLY valid JSON. No markdown fences, no preamble, no trailing text."""

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
                resp = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=50,
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
                if resp.status_code == 429:
                    wait = 15 * (attempt + 1)
                    self.logger.warning(f"Rate limited — waiting {wait}s")
                    time.sleep(wait)
                    continue
                self.logger.error(f"Groq {resp.status_code}: {resp.text[:200]}")
                break
            except requests.exceptions.Timeout:
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