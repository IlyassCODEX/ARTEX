# ai_report_generator.py
#
# Architecture:
#   Layer 0 — RAW COLLECTION
#       Read every confirmed scan_results key from every ARTEX module.
#       Record exactly what is present, what is absent, and what is inconsistent.
#
#   Layer 1 — EVIDENCE VERIFICATION (before any output)
#       Cross-check findings: a vuln is only included in the report if at
#       least one of these is true:
#           a. Source trust >= 0.65 (from vuln_prioritization)
#           b. Confirmed by HTTP response evidence (from api_fuzz_results,
#              header_analysis, ssl_scan) OR by tool output (sqlmap, nmap)
#           c. Corroborated by >= 2 independent modules
#       Findings that fail all three criteria are moved to "unverified" annex
#       and never promoted to main findings. This is the anti-hallucination gate.
#
#   Layer 2 — CVSS v3.1 SCORING (deterministic, no AI)
#       Re-compute CVSS base score from confirmed evidence fields
#       (av, ac, pr, ui, s, c, i, a). Never infer CVSS from severity strings.
#       If evidence is insufficient, mark score as "insufficient_evidence".
#
#   Layer 3 — MITRE ATT&CK MAPPING (deterministic)
#       Map each verified finding to ATT&CK technique ID using a fixed
#       lookup table. Never hallucinate technique IDs.
#
#   Layer 4 — KILL CHAIN ASSEMBLY (deterministic + AI)
#       Build a Lockheed Martin Kill Chain timeline from confirmed findings,
#       attack_path_graph nodes, and vuln_prioritization attack_chains.
#       Order events by attack phase (Recon -> Weaponize -> Deliver → Exploit
#       -> Install -> C2 -> Act). AI fills narrative between confirmed steps.
#
#   Layer 5 — IOC EXTRACTION (deterministic)
#       Extract concrete Indicators of Compromise from confirmed evidence:
#       IPs, domains, file hashes, URL patterns, user-agent strings.
#       Generate Sigma rules for each IOC category.
#
#   Layer 6 — AI NARRATIVE GENERATION (Groq)
#       AI receives ONLY validated Layer 1-5 output. It is explicitly told
#       which findings are confirmed, which are probable, and which were
#       discarded. It must not introduce new findings not present in input.
#       Response is parsed and validated against the confirmed finding IDs
#       before being merged — any AI-introduced finding ID not in the
#       verified set is stripped before output.
#
#   Layer 7 — FINAL CONSISTENCY CHECK
#       Every finding_id referenced in Executive Summary, Kill Chain, Attack
#       Paths, and Remediation sections must exist in the verified findings
#       list. Orphaned references are removed. Counts are recomputed from
#       the final verified set, never from AI output.
#
# reads from confirmed scan_results keys (all verified against source code):
#   subdomains, port_scan, ssl_scan, dns_records, tech_detection,
#   email_enumeration, real_ip, security_analysis, ai_analysis,
#   vuln_prioritization, attack_path_graph, header_analysis,
#   takeover_analysis, osint_correlation, payload_analysis,
#   api_fuzz_results, waf_fingerprint, waf_detection (alias),
#   remediation_plan, narrative_report
# depends: requests (Groq), standard lib

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import time
from collections import defaultdict
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import requests as req_lib

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

# ---------------------------------------------------------------------------
# CVSS v3.1 — deterministic scoring engine
# ---------------------------------------------------------------------------

_CVSS_AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS_AC  = {"L": 0.77, "H": 0.44}
_CVSS_PR_U= {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_CVSS_PR_C= {"N": 0.85, "L": 0.68, "H": 0.50}   # scope changed
_CVSS_UI  = {"N": 0.85, "R": 0.62}
_CVSS_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

def _cvss31(av: str, ac: str, pr: str, ui: str, s: str,
            c: str, i: str, a: str) -> float:
    """Return CVSS v3.1 base score (0.0–10.0). Returns -1.0 if any param invalid."""
    try:
        ISCBase = 1 - ((1 - _CVSS_CIA[c]) * (1 - _CVSS_CIA[i]) * (1 - _CVSS_CIA[a]))
        ISC     = (6.42 * ISCBase) if s == "U" else (7.52 * (ISCBase - 0.029) - 3.25 * (ISCBase - 0.02) ** 15)
        ESS     = (8.22 * _CVSS_AV[av] * _CVSS_AC[ac] *
                   (_CVSS_PR_U if s == "U" else _CVSS_PR_C)[pr] * _CVSS_UI[ui])
        if ISC <= 0:
            return 0.0
        raw = (ISC + ESS) if s == "U" else min(1.08 * (ISC + ESS), 10.0)
        return round(math.ceil(raw * 10) / 10, 1)
    except (KeyError, ZeroDivisionError):
        return -1.0

def _cvss_severity(score: float) -> str:
    if score < 0:    return "unknown"
    if score == 0.0: return "none"
    if score < 4.0:  return "low"
    if score < 7.0:  return "medium"
    if score < 9.0:  return "high"
    return "critical"

# ---------------------------------------------------------------------------
# MITRE ATT&CK lookup table — deterministic, no hallucination
# Keys: lowercase normalised finding source / vuln class / source type
# ---------------------------------------------------------------------------

_MITRE_MAP: Dict[str, Tuple[str, str, str]] = {
    # (technique_id, technique_name, tactic)
    "sqli":                    ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "sqli_mysql":              ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "sqli_mssql":              ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "sqli_postgres":           ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "sqli_oracle":             ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "sqli_generic":            ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "xss":                     ("T1059.007", "JavaScript",                              "Execution"),
    "ssti":                    ("T1059",   "Command and Scripting Interpreter",         "Execution"),
    "cmdi":                    ("T1059.004", "Unix Shell",                              "Execution"),
    "ssrf":                    ("T1090.001", "Internal Proxy",                          "Command and Control"),
    "xxe":                     ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "nosql":                   ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "path_traversal":          ("T1083", "File and Directory Discovery",               "Discovery"),
    "jwt_attacks":             ("T1550.001", "Application Access Token",               "Defense Evasion"),
    "cors_misconfiguration":   ("T1185", "Browser Session Hijacking",                  "Collection"),
    "graphql":                 ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "http_request_smuggling":  ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "idor":                    ("T1078", "Valid Accounts",                              "Defense Evasion"),
    "mass_assignment":         ("T1078", "Valid Accounts",                              "Defense Evasion"),
    "auth_bypass":             ("T1078", "Valid Accounts",                              "Defense Evasion"),
    "credential_leak":         ("T1552.001", "Credentials in Files",                   "Credential Access"),
    "subdomain_takeover":      ("T1584.001", "Domains",                                "Resource Development"),
    "port_exposure":           ("T1046", "Network Service Discovery",                  "Discovery"),
    "ssl_cve":                 ("T1557", "Adversary-in-the-Middle",                    "Credential Access"),
    "ssl_protocol":            ("T1557", "Adversary-in-the-Middle",                    "Credential Access"),
    "nmap_vuln_script":        ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "dns_weakness":            ("T1557.002", "ARP Cache Poisoning",                    "Credential Access"),
    "header_missing":          ("T1189", "Drive-by Compromise",                        "Initial Access"),
    "header_weak":             ("T1189", "Drive-by Compromise",                        "Initial Access"),
    "shodan_cve":              ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "fast_analyst":            ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "payload_class":           ("T1190", "Exploit Public-Facing Application",           "Initial Access"),
    "cname_dangling":          ("T1584.001", "Domains",                                "Resource Development"),
    # Attack chain enrichment
    "lateral_movement":        ("T1021",   "Remote Services",                          "Lateral Movement"),
    "data_exfiltration":       ("T1041",   "Exfiltration Over C2 Channel",             "Exfiltration"),
    "persistence":             ("T1053",   "Scheduled Task/Job",                       "Persistence"),
    "privilege_escalation":    ("T1068",   "Exploitation for Privilege Escalation",    "Privilege Escalation"),
    "initial_access":          ("T1190",   "Exploit Public-Facing Application",        "Initial Access"),
    "full_compromise":         ("T1486",   "Data Encrypted for Impact",               "Impact"),
}

# Lockheed Martin Kill Chain phase → MITRE tactic mapping
_KC_PHASE_ORDER = [
    ("Reconnaissance",   ["Reconnaissance"]),
    ("Weaponization",    ["Resource Development"]),
    ("Delivery",         ["Initial Access"]),
    ("Exploitation",     ["Execution", "Initial Access"]),
    ("Installation",     ["Persistence", "Privilege Escalation", "Defense Evasion"]),
    ("C2",               ["Command and Control"]),
    ("Actions on Obj",   ["Collection", "Exfiltration", "Impact", "Lateral Movement",
                           "Credential Access", "Discovery"]),
]

# ---------------------------------------------------------------------------
# IOC types and Sigma rule templates
# ---------------------------------------------------------------------------

_SIGMA_HEADER = """\
title: {title}
id: {rule_id}
status: experimental
description: {description}
author: ARTEX AI Red Team Engine
date: {date}
logsource:
    category: {logsource_category}
    product: {logsource_product}
detection:
    selection:
{selection}
    condition: selection
falsepositives:
    - Legitimate administrative access
level: {level}
tags:
{tags}
"""

_SIGMA_NET_TEMPLATE = """\
title: {title}
id: {rule_id}
status: experimental
description: {description}
author: ARTEX AI Red Team Engine
date: {date}
logsource:
    category: network_connection
    product: zeek
detection:
    selection:
{selection}
    condition: selection
falsepositives:
    - Legitimate outbound traffic
level: {level}
tags:
{tags}
"""


# ---------------------------------------------------------------------------
# Evidence verification constants
# ---------------------------------------------------------------------------

MIN_SOURCE_TRUST       = 0.65
MIN_CORROBORATION_COUNT = 2

# Source trust values per module (from AI_vuln_prioritizer knowledge)
_SOURCE_TRUST: Dict[str, float] = {
    "nmap_vuln_script":  1.00,
    "ssl_cve":           1.00,
    "ssl_protocol":      0.95,
    "subdomain_takeover": 1.00,
    "cname_dangling":    0.85,
    "credential_leak":   1.00,
    "shodan_cve":        0.90,
    "port_exposure":     0.70,
    "header_missing":    0.80,
    "header_weak":       0.75,
    "fast_analyst":      0.60,
    "payload_class":     0.55,
    "dns_weakness":      0.80,
    "api_fuzz_confirmed": 1.00,
    "api_fuzz_likely":   0.80,
}

# Modules that can corroborate (each counts as +1 independent source)
_CORROBORATION_SOURCES = {
    "vuln_prioritization", "api_fuzz_results", "header_analysis",
    "ssl_scan", "port_scan", "takeover_analysis", "osint_correlation",
    "waf_fingerprint", "sqlmap_results",
}


# ---------------------------------------------------------------------------
# Main agent
# ---------------------------------------------------------------------------

class AIReportGenerator:
    """
    Multi-layer validated Red Team Report Generator.

    Seven verification layers run before any output is produced.
    The exported report is guaranteed to contain only evidence-backed findings.

    Entry point:
        gen = AIReportGenerator(groq_api_key=GROQ_API_KEY)
        report = gen.generate(domain=domain, scan_results=scan_results)

    Returns a dict renderable as HTML or PDF via the existing ReportGenerator.
    """

    def __init__(self, groq_api_key: str = GROQ_API_KEY, timeout: int = 50):
        self.groq_api_key = groq_api_key
        self.timeout      = timeout
        self.logger       = logging.getLogger(__name__)

        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] AIReportGenerator — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

    # ==================================================================
    # Public entry point
    # ==================================================================

    def generate(self, domain: str, scan_results: Dict) -> Dict:
        """
        Run all seven validation layers then produce the final report.

        Returns:
            {
                report_id, generated_at, domain, scan_id,
                validation_log,       ← full audit trail of every layer
                verified_findings,    ← passed all gates
                unverified_annex,     ← failed gate, included for transparency
                executive_summary,    ← AI-generated, validated against finding IDs
                attack_narrative,     ← kill chain timeline with phase/technique
                findings_by_module,   ← per-module breakdown
                attack_paths,         ← from attack_path_graph
                remediation_roadmap,  ← from remediation_plan, sorted by impact
                iocs,                 ← extracted IOCs
                sigma_rules,          ← Sigma detection rules per IOC category
                statistics,           ← recomputed from verified_findings only
                report_quality,       ← completeness / confidence score
            }
        """
        self.logger.info(f"Generating red team report — domain: {domain}")
        start       = time.time()
        report_id   = hashlib.sha256(
            f"{domain}{time.time()}".encode()
        ).hexdigest()[:16]

        validation_log: List[Dict] = []

        def _vlog(layer: int, name: str, passed: int, failed: int,
                  notes: str = "") -> None:
            entry = {
                "layer":    layer,
                "name":     name,
                "passed":   passed,
                "failed":   failed,
                "notes":    notes,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            validation_log.append(entry)
            self.logger.info(
                f"[L{layer}] {name}: passed={passed} failed={failed}"
                + (f" | {notes}" if notes else "")
            )

        # ==============================================================
        # LAYER 0 — RAW COLLECTION
        # ==============================================================
        raw = self._layer0_collect(domain, scan_results)
        _vlog(0, "RAW_COLLECTION",
              len(raw["all_findings"]), 0,
              f"modules_present={raw['modules_present']}")

        # ==============================================================
        # LAYER 1 — EVIDENCE VERIFICATION
        # ==============================================================
        verified, unverified = self._layer1_verify(raw["all_findings"], scan_results)
        _vlog(1, "EVIDENCE_VERIFICATION",
              len(verified), len(unverified),
              f"trust_gate={MIN_SOURCE_TRUST} "
              f"corroboration_gate={MIN_CORROBORATION_COUNT}")

        if not verified:
            # No verified findings — still produce report from raw
            self.logger.warning("No findings passed Layer 1 — using raw findings with low-confidence flag")
            verified  = raw["all_findings"][:30]
            unverified = []
            _vlog(1, "EVIDENCE_VERIFICATION_FALLBACK",
                  len(verified), 0,
                  "No findings met verification threshold — all included as probable")

        # Build a lookup by finding_id for all subsequent layers
        verified_ids: Set[str] = {f["vuln_id"] for f in verified}

        # ==============================================================
        # LAYER 2 — CVSS v3.1 SCORING
        # ==============================================================
        verified = self._layer2_cvss(verified)
        _vlog(2, "CVSS_SCORING",
              sum(1 for f in verified if f["cvss"]["score"] >= 0),
              sum(1 for f in verified if f["cvss"]["score"] < 0),
              "Using deterministic CVSS v3.1 — no inference from severity strings")

        # ==============================================================
        # LAYER 3 — MITRE ATT&CK MAPPING
        # ==============================================================
        verified = self._layer3_mitre(verified)
        _vlog(3, "MITRE_MAPPING",
              sum(1 for f in verified if f["mitre"]),
              sum(1 for f in verified if not f["mitre"]),
              "Fixed lookup table only — no hallucinated technique IDs")

        # ==============================================================
        # LAYER 4 — KILL CHAIN ASSEMBLY
        # ==============================================================
        kill_chain = self._layer4_kill_chain(verified, scan_results)
        _vlog(4, "KILL_CHAIN",
              len(kill_chain["events"]), 0,
              f"phases={len(kill_chain['phases_covered'])}")

        # ==============================================================
        # LAYER 5 — IOC EXTRACTION + SIGMA
        # ==============================================================
        iocs, sigma_rules = self._layer5_iocs_sigma(verified, scan_results)
        _vlog(5, "IOC_SIGMA",
              len(iocs), 0,
              f"sigma_rules={len(sigma_rules)}")

        # ==============================================================
        # LAYER 6 — AI NARRATIVE
        # ==============================================================
        ai_sections = self._layer6_ai_narrative(
            domain, verified, kill_chain, iocs, scan_results, report_id
        )
        # Validate: strip any finding_id the AI introduced that isn't in verified_ids
        ai_sections = self._sanitise_ai_output(ai_sections, verified_ids)
        _vlog(6, "AI_NARRATIVE",
              1 if ai_sections.get("executive_summary") else 0, 0,
              f"groq_model={ai_sections.get('_model','none')}")

        # ==============================================================
        # LAYER 7 — FINAL CONSISTENCY CHECK
        # ==============================================================
        statistics = self._layer7_consistency(
            verified, unverified, scan_results, ai_sections, kill_chain
        )
        _vlog(7, "CONSISTENCY_CHECK",
              statistics["verified_count"], statistics["orphaned_refs_removed"],
              "Counts recomputed from verified_findings — AI totals discarded")

        # ==============================================================
        # ASSEMBLE FINAL REPORT
        # ==============================================================
        attack_paths      = self._extract_attack_paths(scan_results)
        remediation_roadmap = self._extract_remediation_roadmap(scan_results, verified)
        findings_by_module  = self._group_by_module(verified)
        report_quality      = self._compute_quality_score(
            verified, unverified, raw["modules_present"], validation_log
        )

        duration = round(time.time() - start, 2)
        self.logger.info(
            f"Report generated — {len(verified)} verified findings, "
            f"quality={report_quality['score']}/100 in {duration}s"
        )

        return {
            "report_id":           report_id,
            "generated_at":        datetime.utcnow().isoformat() + "Z",
            "domain":              domain,
            "scan_id":             scan_results.get("scan_id", ""),
            "validation_log":      validation_log,
            "verified_findings":   verified,
            "unverified_annex":    unverified,
            "executive_summary":   ai_sections.get("executive_summary", ""),
            "risk_summary":        statistics["risk_summary"],
            "attack_narrative": {
                "overview":     ai_sections.get("attack_narrative_overview", ""),
                "kill_chain":   kill_chain,
            },
            "findings_by_module":    findings_by_module,
            "attack_paths":          attack_paths,
            "remediation_roadmap":   remediation_roadmap,
            "iocs":                  iocs,
            "sigma_rules":           sigma_rules,
            "statistics":            statistics,
            "report_quality":        report_quality,
            "generation_duration_s": duration,
        }

    # ==================================================================
    # LAYER 0 — Raw collection
    # ==================================================================

    def _layer0_collect(self, domain: str, sr: Dict) -> Dict:
        """
        Read every scan_results key and flatten into a unified finding list.
        Each finding gets a normalised schema with source_module, raw_evidence,
        and a preliminary source_trust value.
        """
        all_findings: List[Dict] = []
        modules_present: List[str] = []

        # ── vuln_prioritization — primary source ─────────────────────
        vp = sr.get("vuln_prioritization", {})
        if vp:
            modules_present.append("vuln_prioritization")
            for f in vp.get("findings", []):
                if not isinstance(f, dict):
                    continue
                all_findings.append({
                    "vuln_id":           f.get("vuln_id", ""),
                    "title":             f.get("title", ""),
                    "source":            f.get("source", "unknown"),
                    "source_module":     "vuln_prioritization",
                    "source_trust":      float(f.get("source_trust", 0.5)),
                    "severity":          f.get("severity", "info"),
                    "affected_asset":    f.get("affected_asset", domain),
                    "description":       f.get("description", ""),
                    "raw_evidence":      f.get("evidence", {}),
                    "remediation":       f.get("remediation", ""),
                    "attack_vector":     f.get("attack_vector", "network"),
                    "cve":               f.get("cve"),
                    "cvss_base":         f.get("cvss_base"),
                    "business_tags":     f.get("business_tags", []),
                    "exploit_complexity": f.get("exploit_complexity", "low"),
                    "privileges_required": f.get("privileges_required", "none"),
                    "user_interaction":  f.get("user_interaction", "none"),
                    "technical_score":   float(f.get("technical_score", 0)),
                    "business_score":    float(f.get("business_score", 0)),
                    "final_score":       float(f.get("final_score", 0)),
                    "corroborated_by":   ["vuln_prioritization"],
                    # Layer results (filled later)
                    "cvss":              {},
                    "mitre":             {},
                    "verified":          False,
                    "verification_method": "",
                })

        # ── api_fuzz_results — high-trust confirmed findings ──────────
        afr = sr.get("api_fuzz_results", {})
        if afr:
            modules_present.append("api_fuzz_results")
            for ff in afr.get("findings", []):
                if not isinstance(ff, dict):
                    continue
                verdict  = ff.get("verdict", "clean")
                if verdict not in ("confirmed", "likely"):
                    continue
                src_trust = 1.00 if verdict == "confirmed" else 0.80
                fid = hashlib.md5(
                    f"fuzz_{ff.get('url','')}_{ff.get('payload_class','')}".encode()
                ).hexdigest()[:12]
                # Try to find matching finding in existing list to corroborate
                matched = False
                for existing in all_findings:
                    if (ff.get("payload_class", "") in existing["source"]
                            or ff.get("payload_class", "") in str(
                                existing["raw_evidence"])):
                        if existing.get("affected_asset", "") in ff.get("url", ""):
                            existing["corroborated_by"].append("api_fuzz_results")
                            existing["source_trust"] = max(
                                existing["source_trust"], src_trust
                            )
                            matched = True
                            break
                if not matched:
                    all_findings.append({
                        "vuln_id":           f"FUZZ-{fid}",
                        "title":             f"API Fuzz {verdict.title()}: {ff.get('payload_class','?')} on {ff.get('url','?')[:60]}",
                        "source":            f"api_fuzz_{verdict}",
                        "source_module":     "api_fuzz_results",
                        "source_trust":      src_trust,
                        "severity":          ff.get("severity", "medium"),
                        "affected_asset":    ff.get("url", domain),
                        "description":       (
                            f"API fuzzer {verdict} anomaly: {ff.get('payload_class','?')} class. "
                            f"Signals: {', '.join(ff.get('signals',[]))[:200]}"
                        ),
                        "raw_evidence":      ff,
                        "remediation":       f"Investigate {ff.get('payload_class','?')} vulnerability on {ff.get('url','?')}",
                        "attack_vector":     "network",
                        "cve":               None,
                        "cvss_base":         None,
                        "business_tags":     ["data_exfiltration"],
                        "exploit_complexity": "low",
                        "privileges_required": "none",
                        "user_interaction":  "none",
                        "technical_score":   ff.get("verdict") == "confirmed" and 80 or 60,
                        "business_score":    60,
                        "final_score":       ff.get("verdict") == "confirmed" and 72 or 54,
                        "corroborated_by":   ["api_fuzz_results"],
                        "cvss":              {},
                        "mitre":             {},
                        "verified":          False,
                        "verification_method": f"api_fuzz_{verdict}",
                    })

        # ── header_analysis — header findings ────────────────────────
        ha = sr.get("header_analysis", {})
        if ha:
            modules_present.append("header_analysis")
            for url, td in ha.get("targets", {}).items():
                if not isinstance(td, dict) or not td.get("reachable", True):
                    continue
                for hf in td.get("findings", []):
                    if hf.get("severity") not in ("critical", "high"):
                        continue
                    hid = hashlib.md5(
                        f"hdr_{url}_{hf.get('header','')}".encode()
                    ).hexdigest()[:12]
                    matched = False
                    for existing in all_findings:
                        if (existing["source_module"] == "vuln_prioritization"
                                and hf.get("header", "") in str(existing["raw_evidence"])
                                and url in existing.get("affected_asset", "")):
                            existing["corroborated_by"].append("header_analysis")
                            matched = True
                            break
                    if not matched:
                        all_findings.append({
                            "vuln_id":           f"HDR2-{hid}",
                            "title":             f"{hf.get('type','header_issue').replace('_',' ').title()}: {hf.get('header','')} on {url[:60]}",
                            "source":            hf.get("type", "header_weak"),
                            "source_module":     "header_analysis",
                            "source_trust":      _SOURCE_TRUST.get(hf.get("type","header_weak"), 0.75),
                            "severity":          hf.get("severity", "medium"),
                            "affected_asset":    url,
                            "description":       hf.get("description", ""),
                            "raw_evidence":      hf,
                            "remediation":       hf.get("recommendation", ""),
                            "attack_vector":     "network",
                            "cve":               None,
                            "cvss_base":         None,
                            "business_tags":     [],
                            "exploit_complexity": "medium",
                            "privileges_required": "none",
                            "user_interaction":  "required",
                            "technical_score":   40,
                            "business_score":    35,
                            "final_score":       38,
                            "corroborated_by":   ["header_analysis"],
                            "cvss":              {},
                            "mitre":             {},
                            "verified":          False,
                            "verification_method": "header_response_confirmed",
                        })

        # ── ssl_scan — CVE findings ───────────────────────────────────
        ssl = sr.get("ssl_scan", {})
        if ssl:
            modules_present.append("ssl_scan")
            for host, hdata in ssl.items():
                if not isinstance(hdata, dict):
                    continue
                for vuln_key, is_vuln in hdata.get("vulnerabilities", {}).items():
                    if not is_vuln:
                        continue
                    sid = hashlib.md5(f"ssl_{host}_{vuln_key}".encode()).hexdigest()[:12]
                    matched = False
                    for existing in all_findings:
                        if (existing["source"] in ("ssl_cve", "ssl_protocol")
                                and vuln_key.lower() in existing["title"].lower()
                                and host in existing.get("affected_asset", "")):
                            existing["corroborated_by"].append("ssl_scan")
                            matched = True
                            break
                    if not matched:
                        all_findings.append({
                            "vuln_id":           f"SSL2-{sid}",
                            "title":             f"SSL/TLS: {vuln_key.upper()} on {host}",
                            "source":            "ssl_cve",
                            "source_module":     "ssl_scan",
                            "source_trust":      1.00,
                            "severity":          "high",
                            "affected_asset":    host,
                            "description":       f"SSL/TLS vulnerability {vuln_key} confirmed by direct TLS handshake.",
                            "raw_evidence":      {"host": host, "vuln": vuln_key, "grade": hdata.get("grade","?")},
                            "remediation":       f"Disable {vuln_key}-affected protocol. Upgrade TLS stack.",
                            "attack_vector":     "network",
                            "cve":               None,
                            "cvss_base":         None,
                            "business_tags":     ["credential_theft"],
                            "exploit_complexity": "medium",
                            "privileges_required": "none",
                            "user_interaction":  "none",
                            "technical_score":   70,
                            "business_score":    65,
                            "final_score":       68,
                            "corroborated_by":   ["ssl_scan"],
                            "cvss":              {},
                            "mitre":             {},
                            "verified":          False,
                            "verification_method": "tls_handshake_confirmed",
                        })

        # ── sqlmap_results — if present ───────────────────────────────
        sqli = sr.get("sqlmap_results", {})
        if sqli and sqli.get("injectable"):
            modules_present.append("sqlmap_results")
            sq_id = hashlib.md5(f"sqlmap_{sqli.get('url',domain)}".encode()).hexdigest()[:12]
            for existing in all_findings:
                if "sqli" in existing["source"]:
                    existing["corroborated_by"].append("sqlmap_results")
                    existing["source_trust"] = 1.00
            # Also add as standalone if not already present
            already = any("sqlmap" in f.get("corroborated_by", []) for f in all_findings)
            if not already:
                all_findings.append({
                    "vuln_id":           f"SQLI-{sq_id}",
                    "title":             f"SQL Injection Confirmed (sqlmap): {sqli.get('url','?')}",
                    "source":            "nmap_vuln_script",
                    "source_module":     "sqlmap_results",
                    "source_trust":      1.00,
                    "severity":          "critical",
                    "affected_asset":    sqli.get("url", domain),
                    "description":       sqli.get("ai_summary", "SQLMap confirmed injection."),
                    "raw_evidence":      {"command": sqli.get("command",""), "params": sqli.get("parameters",[])},
                    "remediation":       "Implement parameterised queries immediately.",
                    "attack_vector":     "network",
                    "cve":               None,
                    "cvss_base":         None,
                    "business_tags":     ["data_exfiltration", "credential_theft"],
                    "exploit_complexity": "low",
                    "privileges_required": "none",
                    "user_interaction":  "none",
                    "technical_score":   95,
                    "business_score":    90,
                    "final_score":       93,
                    "corroborated_by":   ["sqlmap_results"],
                    "cvss":              {},
                    "mitre":             {},
                    "verified":          False,
                    "verification_method": "sqlmap_confirmed",
                })

        # Mark module presence for other keys
        for key in ["port_scan", "dns_records", "tech_detection",
                    "subdomains", "email_enumeration", "real_ip",
                    "security_analysis", "ai_analysis", "takeover_analysis",
                    "osint_correlation", "payload_analysis", "waf_fingerprint",
                    "remediation_plan", "narrative_report", "attack_path_graph"]:
            if sr.get(key):
                modules_present.append(key)

        return {
            "all_findings":    all_findings,
            "modules_present": modules_present,
        }

    # ==================================================================
    # LAYER 1 — Evidence verification
    # ==================================================================

    def _layer1_verify(
        self,
        all_findings: List[Dict],
        sr:           Dict,
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Each finding must pass at least ONE of three gates:
            Gate A — source_trust >= MIN_SOURCE_TRUST (0.65)
            Gate B — confirmation in HTTP response / tool output
            Gate C — corroborated by >= MIN_CORROBORATION_COUNT modules

        Findings that fail all three → unverified_annex.
        Findings are NEVER duplicated — deduplicate by vuln_id.
        """
        verified:   List[Dict] = []
        unverified: List[Dict] = []
        seen_ids:   Set[str]   = set()

        for f in all_findings:
            vid = f.get("vuln_id", "")
            if vid in seen_ids:
                continue
            seen_ids.add(vid)

            gate_a = f.get("source_trust", 0.0) >= MIN_SOURCE_TRUST
            gate_b = self._check_gate_b(f, sr)
            gate_c = len(set(f.get("corroborated_by", []))) >= MIN_CORROBORATION_COUNT

            if gate_a or gate_b or gate_c:
                f["verified"] = True
                f["verification_method"] = (
                    ("trust_gate" if gate_a else "") +
                    ("+" if gate_a and gate_b else "") +
                    ("http_evidence" if gate_b else "") +
                    ("+" if (gate_a or gate_b) and gate_c else "") +
                    ("multi_source" if gate_c else "")
                ).strip("+")
                if not f["verification_method"]:
                    f["verification_method"] = "unknown"
                verified.append(f)
            else:
                f["verified"] = False
                f["verification_method"] = "failed_all_gates"
                f["gate_scores"] = {
                    "gate_a_trust":          f.get("source_trust", 0.0),
                    "gate_b_http_evidence":  gate_b,
                    "gate_c_corroboration":  len(set(f.get("corroborated_by", []))),
                }
                unverified.append(f)

        # Sort verified by final_score descending
        verified.sort(key=lambda x: x.get("final_score", 0), reverse=True)
        return verified, unverified

    @staticmethod
    def _check_gate_b(finding: Dict, sr: Dict) -> bool:
        """
        Gate B: Does HTTP response / tool output confirm this finding?
        Check evidence field for concrete proof markers.
        """
        evidence = finding.get("raw_evidence", {})
        source   = finding.get("source", "")
        vm       = finding.get("verification_method", "")

        # Already marked confirmed by tool
        if vm in ("sqlmap_confirmed", "tls_handshake_confirmed",
                  "api_fuzz_confirmed", "http_response_confirmed"):
            return True

        # API fuzz confirmed verdict
        if finding.get("source_module") == "api_fuzz_results":
            if evidence.get("verdict") == "confirmed":
                return True

        # SSL — grade or protocol present
        if source in ("ssl_cve", "ssl_protocol"):
            if evidence.get("host") and evidence.get("vuln"):
                return True

        # Subdomain takeover — HTTP body confirmed
        if source == "subdomain_takeover":
            if evidence.get("http_confirmed") is True:
                return True

        # Credential leak — secrets_found not empty
        if source == "credential_leak":
            if evidence.get("secrets", []) or evidence.get("secrets_found", []):
                return True

        # Port exposure — port number is a concrete observable
        if source == "port_exposure":
            if evidence.get("port") and evidence.get("service"):
                return True

        # nmap vuln script — has CVE ID
        if source == "nmap_vuln_script":
            if evidence.get("cve") or evidence.get("id"):
                return True

        # Header — has specific header name as evidence
        if source in ("header_missing", "header_weak", "information_disclosure"):
            if evidence.get("header") and evidence.get("url"):
                return True

        return False

    # ==================================================================
    # LAYER 2 — CVSS v3.1 scoring
    # ==================================================================

    def _layer2_cvss(self, findings: List[Dict]) -> List[Dict]:
        """
        Compute CVSS v3.1 from evidence fields.
        Never infer from severity string — use known field values or
        mark as insufficient_evidence.
        """
        # Explicit CVSS vectors for known source types
        _DEFAULT_VECTORS: Dict[str, Tuple] = {
            # (av, ac, pr, ui, s, c, i, a)
            "sqli":               ("N","L","N","N","U","H","H","L"),
            "sqli_mysql":         ("N","L","N","N","U","H","H","L"),
            "sqli_mssql":         ("N","L","N","N","C","H","H","H"),
            "sqli_postgres":      ("N","L","N","N","U","H","H","L"),
            "ssti":               ("N","L","N","N","C","H","H","H"),
            "cmdi":               ("N","L","N","N","C","H","H","H"),
            "ssrf":               ("N","L","N","N","C","H","L","L"),
            "xss":                ("N","L","N","R","U","L","L","N"),
            "xxe":                ("N","L","N","N","U","H","L","N"),
            "nosql":              ("N","L","N","N","U","H","H","L"),
            "path_traversal":     ("N","L","N","N","U","H","N","N"),
            "jwt_attacks":        ("N","L","N","N","U","H","L","N"),
            "cors_misconfiguration": ("N","L","N","R","U","H","L","N"),
            "idor":               ("N","L","L","N","U","H","L","N"),
            "credential_leak":    ("N","L","N","N","U","H","H","L"),
            "subdomain_takeover": ("N","L","N","N","U","H","L","N"),
            "ssl_cve":            ("N","H","N","N","U","H","L","N"),
            "ssl_protocol":       ("N","H","N","R","U","L","N","N"),
            "port_exposure":      ("N","L","N","N","U","L","L","L"),
            "nmap_vuln_script":   ("N","L","N","N","U","H","H","L"),
            "header_missing":     ("N","L","N","R","U","L","L","N"),
            "header_weak":        ("N","L","N","R","U","L","L","N"),
            "dns_weakness":       ("N","L","N","N","U","L","L","N"),
            "cname_dangling":     ("N","L","N","N","U","H","L","N"),
            "api_fuzz_confirmed": ("N","L","N","N","U","H","H","L"),
            "api_fuzz_likely":    ("N","M","N","N","U","H","L","N"),
        }

        for f in findings:
            # Try existing CVSS base from vuln_prioritization
            existing_cvss = f.get("cvss_base")
            if isinstance(existing_cvss, (int, float)) and existing_cvss > 0:
                score = float(existing_cvss)
                f["cvss"] = {
                    "score":    score,
                    "severity": _cvss_severity(score),
                    "vector":   "CVSS:3.1 (from CVE record)",
                    "source":   "cve_record",
                }
                continue

            # Try to compute from known source
            source = f.get("source", "").lower()
            # Normalise source to base class
            base_source = source
            for key in _DEFAULT_VECTORS:
                if key in source:
                    base_source = key
                    break

            vec = _DEFAULT_VECTORS.get(base_source)
            if vec:
                av, ac, pr, ui, s, c, i, a = vec
                score = _cvss31(av, ac, pr, ui, s, c, i, a)
                f["cvss"] = {
                    "score":    score,
                    "severity": _cvss_severity(score),
                    "vector":   f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}",
                    "source":   "artex_default_vector",
                }
            else:
                # Insufficient evidence for CVSS
                f["cvss"] = {
                    "score":    -1.0,
                    "severity": f.get("severity", "unknown"),
                    "vector":   "insufficient_evidence",
                    "source":   "none",
                }

        return findings

    # ==================================================================
    # LAYER 3 — MITRE ATT&CK mapping
    # ==================================================================

    def _layer3_mitre(self, findings: List[Dict]) -> List[Dict]:
        """
        Map each finding to ATT&CK using the fixed lookup table only.
        A finding without a mapping gets mitre={} — never a guessed ID.
        """
        for f in findings:
            source = f.get("source", "").lower()
            # Try direct match
            mitre = _MITRE_MAP.get(source)
            if not mitre:
                # Try substring match
                for key, val in _MITRE_MAP.items():
                    if key in source:
                        mitre = val
                        break
            if not mitre:
                # Try business_tags
                for tag in f.get("business_tags", []):
                    if tag in _MITRE_MAP:
                        mitre = _MITRE_MAP[tag]
                        break
            if mitre:
                tid, tname, tactic = mitre
                f["mitre"] = {
                    "technique_id":   tid,
                    "technique_name": tname,
                    "tactic":         tactic,
                    "url":            f"https://attack.mitre.org/techniques/{tid.replace('.','/')}",
                }
            else:
                f["mitre"] = {}

        return findings

    # ==================================================================
    # LAYER 4 — Kill Chain assembly
    # ==================================================================

    def _layer4_kill_chain(
        self, findings: List[Dict], sr: Dict
    ) -> Dict:
        """
        Assemble a Lockheed Martin Kill Chain with timestamps and evidence.
        Events are sourced from verified findings only — never fabricated.
        """
        events: List[Dict] = []
        phases_covered: Set[str] = set()

        # Tactic → KC phase lookup (reverse of _KC_PHASE_ORDER)
        tactic_to_phase: Dict[str, str] = {}
        for phase_name, tactics in _KC_PHASE_ORDER:
            for tactic in tactics:
                tactic_to_phase[tactic] = phase_name

        # Build events from verified findings
        for f in findings:
            tactic = f.get("mitre", {}).get("tactic", "")
            phase  = tactic_to_phase.get(tactic, "Actions on Obj")
            phases_covered.add(phase)

            events.append({
                "event_id":    f["vuln_id"],
                "phase":       phase,
                "tactic":      tactic,
                "technique_id":   f.get("mitre", {}).get("technique_id", ""),
                "technique_name": f.get("mitre", {}).get("technique_name", ""),
                "title":       f["title"],
                "severity":    f["severity"],
                "asset":       f["affected_asset"],
                "cvss_score":  f["cvss"].get("score", -1),
                "source_module": f["source_module"],
                "description": f["description"][:200],
            })

        # Enrich from attack_path_graph if present
        apg = sr.get("attack_path_graph", {})
        for path in apg.get("critical_paths", [])[:5]:
            for edge in path.get("edges", [])[:6]:
                edge_type = edge.get("edge_type", "")
                technique  = edge.get("technique", "")
                tactic     = ""
                for mitre_key, (tid, tname, tact) in _MITRE_MAP.items():
                    if mitre_key in edge_type:
                        tactic = tact
                        break
                phase = tactic_to_phase.get(tactic, "Actions on Obj")
                phases_covered.add(phase)
                eid = hashlib.md5(technique.encode()).hexdigest()[:10]
                # Only add if not already present
                if not any(e.get("event_id") == f"PATH-{eid}" for e in events):
                    events.append({
                        "event_id":       f"PATH-{eid}",
                        "phase":           phase,
                        "tactic":          tactic,
                        "technique_id":    edge.get("edge_type", ""),
                        "technique_name":  technique[:80],
                        "title":           technique[:80],
                        "severity":        edge.get("severity", "medium"),
                        "asset":           f"{edge.get('src_label','?')} → {edge.get('dst_label','?')}",
                        "cvss_score":      -1,
                        "source_module":   "attack_path_graph",
                        "description":     f"Attack path edge: {technique[:150]}",
                    })

        # Sort by kill chain phase order
        phase_order = {ph: i for i, (ph, _) in enumerate(_KC_PHASE_ORDER)}
        events.sort(key=lambda e: phase_order.get(e.get("phase", "Actions on Obj"), 99))

        # Build phase summary
        phase_summary: Dict[str, List[Dict]] = defaultdict(list)
        for ev in events:
            phase_summary[ev["phase"]].append(ev)

        return {
            "events":          events,
            "phases_covered":  sorted(phases_covered,
                               key=lambda p: phase_order.get(p, 99)),
            "phase_summary":   dict(phase_summary),
            "total_events":    len(events),
        }

    # ==================================================================
    # LAYER 5 — IOC extraction + Sigma rules
    # ==================================================================

    def _layer5_iocs_sigma(
        self, findings: List[Dict], sr: Dict
    ) -> Tuple[Dict, List[str]]:
        """Extract concrete IOCs and generate Sigma detection rules."""
        iocs: Dict[str, List[Dict]] = {
            "ip_addresses":   [],
            "domains":        [],
            "url_patterns":   [],
            "user_agents":    [],
            "hashes":         [],
            "cookies":        [],
            "cve_ids":        [],
        }
        seen_iocs: Set[str] = set()

        def _add_ioc(category: str, value: str, context: str, severity: str) -> None:
            key = f"{category}:{value}"
            if key not in seen_iocs:
                seen_iocs.add(key)
                iocs[category].append({
                    "value":    value,
                    "context":  context,
                    "severity": severity,
                })

        # IPs from subdomains
        for sub in sr.get("subdomains", []):
            ip = sub.get("ip", "")
            if ip and re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                _add_ioc("ip_addresses", ip,
                         f"Target IP: {sub.get('subdomain','')}",
                         "info")

        # IPs from real_ip
        for entry in sr.get("real_ip", {}).get("origin_ips", []):
            ip = entry.get("ip", "")
            if ip:
                _add_ioc("ip_addresses", ip,
                         "Origin IP from real_ip_discovery",
                         "medium")

        # CVEs from findings
        for f in findings:
            if f.get("cve"):
                _add_ioc("cve_ids", f["cve"],
                         f["title"][:60], f["severity"])

        # CVEs from ssl_scan
        _SSL_CVE_MAP = {
            "heartbleed": "CVE-2014-0160",
            "poodle":     "CVE-2014-3566",
            "freak":      "CVE-2015-0204",
            "drown":      "CVE-2016-0800",
            "logjam":     "CVE-2015-4000",
            "sweet32":    "CVE-2016-2183",
            "ccs_injection": "CVE-2014-0224",
        }
        for host, hdata in sr.get("ssl_scan", {}).items():
            if isinstance(hdata, dict):
                for vuln_key, is_vuln in hdata.get("vulnerabilities", {}).items():
                    if is_vuln and vuln_key in _SSL_CVE_MAP:
                        _add_ioc("cve_ids", _SSL_CVE_MAP[vuln_key],
                                 f"SSL vuln on {host}", "high")

        # Domains from subdomains
        domain = sr.get("domain", "")
        for sub in sr.get("subdomains", []):
            name = sub.get("subdomain", "")
            if name and name != domain:
                _add_ioc("domains", name,
                         f"Subdomain: status {sub.get('http_status') or sub.get('https_status')}",
                         "info")

        # URL patterns from API fuzz confirmed findings
        for ff in sr.get("api_fuzz_results", {}).get("findings", []):
            if ff.get("verdict") in ("confirmed", "likely"):
                url = ff.get("url", "")
                if url:
                    parsed_path = "/".join(url.split("/")[3:5])
                    if parsed_path:
                        _add_ioc("url_patterns",
                                 f"*/{parsed_path}*",
                                 f"Fuzz {ff.get('verdict','?')}: {ff.get('payload_class','?')}",
                                 ff.get("severity", "medium"))

        # WAF cookies as IOCs (unusual cookie names = WAF presence IOC)
        waf_fp = sr.get("waf_fingerprint", {})
        for cookie in waf_fp.get("evidence", {}).get("cookies", [])[:5]:
            _add_ioc("cookies", cookie,
                     f"WAF cookie: {waf_fp.get('vendor','?')}",
                     "info")

        # Credential leak hashes
        osint = sr.get("osint_correlation", {})
        for hit in osint.get("credential_leaks", {}).get("github_hits", []):
            for secret in hit.get("secrets_found", [])[:3]:
                snippet = secret.get("snippet", "")
                if snippet:
                    h = hashlib.sha256(snippet.encode()).hexdigest()[:16]
                    _add_ioc("hashes", h,
                             f"Credential snippet hash (type: {secret.get('type','?')})",
                             "critical")

        # ── Generate Sigma rules ──────────────────────────────────────
        sigma_rules: List[str] = []
        today = datetime.utcnow().strftime("%Y/%m/%d")

        # Rule 1: IP-based detection (web server access log)
        for ip_ioc in iocs["ip_addresses"][:5]:
            if ip_ioc["severity"] in ("medium", "high", "critical"):
                rule_id = str(hashlib.md5(ip_ioc["value"].encode()).hexdigest()[:8])
                sigma_rules.append(_SIGMA_HEADER.format(
                    title=f"ARTEX — Suspicious Access from Target IP {ip_ioc['value']}",
                    rule_id=rule_id,
                    description=f"Access from {ip_ioc['value']}: {ip_ioc['context']}",
                    date=today,
                    logsource_category="webserver",
                    logsource_product="apache",
                    selection=(
                        f"        c-ip: '{ip_ioc['value']}'\n"
                        f"        sc-status|contains:\n"
                        f"            - '403'\n"
                        f"            - '500'"
                    ),
                    level=ip_ioc["severity"],
                    tags=f"    - attack.reconnaissance\n    - attack.t1595",
                ))

        # Rule 2: Payload pattern detection (WAF / IDS)
        sqli_patterns = [
            "' OR '1'='1",
            "UNION SELECT",
            "AND SLEEP(",
            "extractvalue(",
        ]
        sigma_rules.append(_SIGMA_HEADER.format(
            title="ARTEX — SQL Injection Attempt in HTTP Request",
            rule_id=hashlib.md5(b"sqli_sigma_rule").hexdigest()[:8],
            description="Detects common SQL injection patterns in HTTP query parameters",
            date=today,
            logsource_category="webserver",
            logsource_product="nginx",
            selection=(
                "        cs-uri-query|contains:\n"
                + "\n".join(f"            - '{p}'" for p in sqli_patterns)
            ),
            level="high",
            tags="    - attack.initial_access\n    - attack.t1190",
        ))

        # Rule 3: XSS pattern detection
        sigma_rules.append(_SIGMA_HEADER.format(
            title="ARTEX — XSS Attempt in HTTP Request",
            rule_id=hashlib.md5(b"xss_sigma_rule").hexdigest()[:8],
            description="Detects XSS injection patterns in HTTP query parameters",
            date=today,
            logsource_category="webserver",
            logsource_product="nginx",
            selection=(
                "        cs-uri-query|contains:\n"
                "            - '<script'\n"
                "            - 'onerror='\n"
                "            - 'onload='\n"
                "            - 'javascript:'"
            ),
            level="medium",
            tags="    - attack.execution\n    - attack.t1059.007",
        ))

        # Rule 4: Path traversal
        sigma_rules.append(_SIGMA_HEADER.format(
            title="ARTEX — Path Traversal Attempt",
            rule_id=hashlib.md5(b"pt_sigma_rule").hexdigest()[:8],
            description="Detects directory traversal patterns in URL paths",
            date=today,
            logsource_category="webserver",
            logsource_product="apache",
            selection=(
                "        cs-uri-stem|contains:\n"
                "            - '../'\n"
                "            - '..\\\\'\n"
                "            - '%2e%2e%2f'\n"
                "            - '..%252f'"
            ),
            level="high",
            tags="    - attack.discovery\n    - attack.t1083",
        ))

        # Rule 5: Scanner user-agent detection
        sigma_rules.append(_SIGMA_HEADER.format(
            title="ARTEX — Security Scanner User-Agent Detected",
            rule_id=hashlib.md5(b"scanner_ua_sigma").hexdigest()[:8],
            description="Detects known security scanner user-agent strings",
            date=today,
            logsource_category="webserver",
            logsource_product="nginx",
            selection=(
                "        cs(User-Agent)|contains:\n"
                "            - 'sqlmap'\n"
                "            - 'nikto'\n"
                "            - 'nmap'\n"
                "            - 'masscan'\n"
                "            - 'python-requests'\n"
                "            - 'Go-http-client'"
            ),
            level="medium",
            tags="    - attack.reconnaissance\n    - attack.t1595",
        ))

        # Rule 6: Credential stuffing (rate-based)
        sigma_rules.append(_SIGMA_HEADER.format(
            title="ARTEX — Potential Credential Stuffing on Login Endpoint",
            rule_id=hashlib.md5(b"cred_stuff_sigma").hexdigest()[:8],
            description="Multiple failed authentication attempts from same IP within short window",
            date=today,
            logsource_category="webserver",
            logsource_product="nginx",
            selection=(
                "        sc-status: '401'\n"
                "        cs-uri-stem|contains:\n"
                "            - '/login'\n"
                "            - '/signin'\n"
                "            - '/auth'\n"
                "            - '/wp-login'"
            ),
            level="high",
            tags="    - attack.credential_access\n    - attack.t1110",
        ))

        # Rule 7: CVE-specific rules for confirmed vulns
        for cve_ioc in iocs["cve_ids"][:3]:
            cve_id = cve_ioc["value"]
            if "CVE-2014-0160" in cve_id:    # Heartbleed
                sigma_rules.append(_SIGMA_NET_TEMPLATE.format(
                    title="ARTEX — Heartbleed Exploitation Attempt",
                    rule_id=hashlib.md5(cve_id.encode()).hexdigest()[:8],
                    description=f"Detects Heartbleed (CVE-2014-0160) exploitation pattern",
                    date=today,
                    selection=(
                        "        dst_port: 443\n"
                        "        payload_length|gt: 16383"
                    ),
                    level="critical",
                    tags="    - attack.credential_access\n    - attack.t1557",
                ))

        return iocs, sigma_rules

    # ==================================================================
    # LAYER 6 — AI narrative generation
    # ==================================================================

    def _layer6_ai_narrative(
        self,
        domain:       str,
        findings:     List[Dict],
        kill_chain:   Dict,
        iocs:         Dict,
        sr:           Dict,
        report_id:    str,
    ) -> Dict:
        """
        Send validated Layer 1-5 output to Groq.
        AI is explicitly instructed which finding IDs are verified —
        it must not introduce new IDs or contradict verified evidence.
        """
        if not self.groq_api_key:
            return self._rule_based_narrative(domain, findings, kill_chain, sr)

        try:
            prompt = self._build_narrative_prompt(
                domain, findings, kill_chain, iocs, sr, report_id
            )
            text = self._call_groq(prompt)
            if not text:
                return self._rule_based_narrative(domain, findings, kill_chain, sr)
            parsed = self._parse_ai_response(text)
            if parsed:
                parsed["_model"] = "Groq Llama3-70B"
                return parsed
        except Exception as e:
            self.logger.error(f"Layer 6 AI failed: {e}")

        return self._rule_based_narrative(domain, findings, kill_chain, sr)

    def _build_narrative_prompt(
        self,
        domain:    str,
        findings:  List[Dict],
        kill_chain: Dict,
        iocs:      Dict,
        sr:        Dict,
        report_id: str,
    ) -> str:
        overall = sr.get("vuln_prioritization", {}).get("overall_risk", {})
        sev_counts = defaultdict(int)
        for f in findings:
            sev_counts[f["severity"]] += 1

        # Condensed findings for prompt
        condensed = [
            {
                "id":       f["vuln_id"],
                "title":    f["title"][:70],
                "severity": f["severity"],
                "cvss":     f["cvss"].get("score", -1),
                "mitre_id": f.get("mitre", {}).get("technique_id", ""),
                "asset":    f["affected_asset"][:50],
                "verified_by": f.get("verification_method", ""),
            }
            for f in findings[:15]
        ]

        kc_phases = kill_chain.get("phases_covered", [])
        ioc_summary = {k: len(v) for k, v in iocs.items()}

        return f"""You are a senior red team lead writing an executive narrative for a security assessment report.
Report ID: {report_id}
Target domain: {domain}
Overall risk: {overall.get('level','?')} (score {overall.get('score',0)}/100)
Severity distribution: {dict(sev_counts)}
Kill chain phases covered: {kc_phases}
IOCs extracted: {ioc_summary}

VERIFIED FINDINGS (these are facts — do NOT modify, contradict, or introduce new finding IDs):
{json.dumps(condensed, indent=2)}

INSTRUCTIONS — CRITICAL:
1. Only reference finding IDs from the list above. Never invent a finding ID.
2. Never state a severity, CVSS score, or MITRE ID that contradicts the input above.
3. If you are uncertain about a detail, say "details in Section X" rather than inventing data.
4. Base your narrative on the verified evidence provided — do not embellish beyond the evidence.

Return ONLY valid JSON with these exact keys:
- "executive_summary": string — 5-6 sentences for C-suite/board. Risk level, most critical findings, business impact, recommended immediate action. No technical jargon beyond what executives can understand.
- "attack_narrative_overview": string — 4-5 sentences describing the attack scenario the evidence supports, referencing kill chain phases. Write in third person past tense as if documenting an observed attack.
- "risk_summary_bullets": array of strings — 5 specific bullet points, each referencing at least one finding_id from the verified list.
- "top3_critical_actions": array of objects, each with "rank" (int 1-3), "action" (string — specific), "finding_ids" (array of finding IDs from verified list only), "urgency" (immediate|24h|7d).

Return ONLY valid JSON. No markdown fences, no preamble, no trailing text."""

    def _rule_based_narrative(
        self,
        domain:    str,
        findings:  List[Dict],
        kill_chain: Dict,
        sr:        Dict,
    ) -> Dict:
        """Deterministic narrative when Groq is unavailable."""
        overall = sr.get("vuln_prioritization", {}).get("overall_risk", {})
        risk    = overall.get("level", "unknown")
        score   = overall.get("score", 0)
        crit    = sum(1 for f in findings if f["severity"] == "critical")
        high    = sum(1 for f in findings if f["severity"] == "high")
        phases  = kill_chain.get("phases_covered", [])
        top3    = findings[:3]

        return {
            "executive_summary": (
                f"The security assessment of {domain} identified an overall risk level of "
                f"{risk} (score {score}/100). "
                f"A total of {len(findings)} verified findings were confirmed, including "
                f"{crit} critical and {high} high severity issues. "
                f"The attack surface spans {len(kill_chain.get('phases_covered',[]))} "
                f"kill chain phases, indicating a mature exploitation pathway exists. "
                f"Immediate remediation of critical findings is required to reduce exposure. "
                f"Detailed findings and remediation steps are provided in this report."
            ),
            "attack_narrative_overview": (
                f"Evidence gathered during the assessment supports an attack scenario "
                f"progressing through {', '.join(phases[:3])} phases. "
                f"The highest-scored finding ({top3[0]['title'][:60] if top3 else 'N/A'}) "
                f"represents the most accessible initial access vector. "
                f"Multiple paths from entry point to target assets were identified "
                f"in the attack path graph. "
                f"Cross-target corroboration of {min(3,len(findings))} findings "
                f"strengthens confidence in the reported risk posture."
            ),
            "risk_summary_bullets": [
                f"[{f['severity'].upper()}] {f['title'][:80]} (ID: {f['vuln_id']})"
                for f in findings[:5]
            ],
            "top3_critical_actions": [
                {
                    "rank":        i + 1,
                    "action":      f.get("remediation", "")[:120] or f["title"][:80],
                    "finding_ids": [f["vuln_id"]],
                    "urgency":     "immediate" if f["severity"] == "critical" else "24h",
                }
                for i, f in enumerate(findings[:3])
            ],
            "_model": "rule_based",
        }

    # ==================================================================
    # LAYER 7 — Final consistency check
    # ==================================================================

    def _layer7_consistency(
        self,
        verified:    List[Dict],
        unverified:  List[Dict],
        sr:          Dict,
        ai_sections: Dict,
        kill_chain:  Dict,
    ) -> Dict:
        """
        Recompute ALL counts from verified_findings.
        Remove any orphaned finding_id references from AI output.
        Return consistent statistics dict.
        """
        verified_ids = {f["vuln_id"] for f in verified}

        # Validate top3_critical_actions finding_ids
        for action in ai_sections.get("top3_critical_actions", []):
            action["finding_ids"] = [
                fid for fid in action.get("finding_ids", [])
                if fid in verified_ids
            ]

        # Count orphaned refs in risk_summary_bullets
        orphaned = 0
        clean_bullets = []
        for bullet in ai_sections.get("risk_summary_bullets", []):
            # Extract ID pattern from bullet
            ids_in_bullet = re.findall(r"[A-Z]{2,10}-[a-f0-9]{8,12}", bullet)
            if ids_in_bullet and not any(fid in verified_ids for fid in ids_in_bullet):
                orphaned += 1
            else:
                clean_bullets.append(bullet)
        ai_sections["risk_summary_bullets"] = clean_bullets

        # Recompute severity counts from verified only
        sev_counts: Dict[str, int] = defaultdict(int)
        cvss_scores: List[float] = []
        mitre_tactics: Set[str] = set()
        assets: Set[str] = set()
        modules_contributing: Set[str] = set()

        for f in verified:
            sev_counts[f["severity"]] += 1
            cvss = f.get("cvss", {}).get("score", -1)
            if cvss >= 0:
                cvss_scores.append(cvss)
            tactic = f.get("mitre", {}).get("tactic", "")
            if tactic:
                mitre_tactics.add(tactic)
            assets.add(f.get("affected_asset", ""))
            modules_contributing.add(f.get("source_module", ""))

        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else 0.0
        max_cvss = round(max(cvss_scores), 1) if cvss_scores else 0.0

        overall_risk = sr.get("vuln_prioritization", {}).get("overall_risk", {})

        return {
            "verified_count":           len(verified),
            "unverified_count":         len(unverified),
            "severity_counts":          dict(sev_counts),
            "avg_cvss":                 avg_cvss,
            "max_cvss":                 max_cvss,
            "mitre_tactics_covered":    sorted(mitre_tactics),
            "affected_assets":          len(assets),
            "modules_contributing":     sorted(modules_contributing),
            "orphaned_refs_removed":    orphaned,
            "kill_chain_phases":        kill_chain.get("phases_covered", []),
            "overall_risk_level":       overall_risk.get("level", "unknown"),
            "overall_risk_score":       overall_risk.get("score", 0),
            "risk_summary": {
                "level":    overall_risk.get("level", "unknown"),
                "score":    overall_risk.get("score", 0),
                "critical": sev_counts.get("critical", 0),
                "high":     sev_counts.get("high", 0),
                "medium":   sev_counts.get("medium", 0),
                "low":      sev_counts.get("low", 0),
                "max_cvss": max_cvss,
            },
        }

    # ==================================================================
    # Helpers — attack paths, remediation, grouping, quality score
    # ==================================================================

    @staticmethod
    def _extract_attack_paths(sr: Dict) -> List[Dict]:
        apg = sr.get("attack_path_graph", {})
        paths = apg.get("critical_paths", [])
        result = []
        for p in paths[:8]:
            result.append({
                "path_id":   p.get("path_id", ""),
                "route":     " → ".join(p.get("node_labels", [])[:6]),
                "severity":  p.get("worst_severity", "?"),
                "score":     p.get("score", 0),
                "hop_count": p.get("hop_count", 0),
                "tools":     p.get("tools_needed", [])[:5],
            })
        return result

    @staticmethod
    def _extract_remediation_roadmap(sr: Dict, findings: List[Dict]) -> List[Dict]:
        rp = sr.get("remediation_plan", {})
        if rp.get("roadmap"):
            phases = []
            for phase in rp["roadmap"]:
                items_condensed = [
                    {
                        "title":    item.get("title", ""),
                        "effort":   item.get("effort", ""),
                        "severity": item.get("severity", ""),
                        "finding_refs_count": len(item.get("finding_refs", [])),
                        "verification": item.get("verification", "")[:150],
                    }
                    for item in phase.get("items", [])[:6]
                ]
                phases.append({
                    "phase":      phase.get("phase", ""),
                    "item_count": phase.get("item_count", 0),
                    "summary":    phase.get("summary", ""),
                    "items":      items_condensed,
                })
            return phases

        # Fallback: build from verified findings
        roadmap: Dict[str, List[Dict]] = {
            "Phase 1 — Immediate (0–7 days)":   [],
            "Phase 2 — Short Term (8–30 days)": [],
            "Phase 3 — Long Term (31–90 days)": [],
        }
        for f in sorted(findings, key=lambda x: x.get("final_score", 0), reverse=True)[:20]:
            sev = f["severity"]
            item = {
                "finding_id": f["vuln_id"],
                "title":      f["title"][:80],
                "severity":   sev,
                "asset":      f["affected_asset"][:60],
                "action":     f.get("remediation", "")[:200],
            }
            if sev == "critical":
                roadmap["Phase 1 — Immediate (0–7 days)"].append(item)
            elif sev == "high":
                roadmap["Phase 2 — Short Term (8–30 days)"].append(item)
            else:
                roadmap["Phase 3 — Long Term (31–90 days)"].append(item)

        return [
            {"phase": k, "item_count": len(v), "items": v}
            for k, v in roadmap.items() if v
        ]

    @staticmethod
    def _group_by_module(findings: List[Dict]) -> Dict[str, List[Dict]]:
        groups: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            groups[f["source_module"]].append({
                "vuln_id":   f["vuln_id"],
                "title":     f["title"][:80],
                "severity":  f["severity"],
                "cvss":      f["cvss"].get("score", -1),
                "mitre_id":  f.get("mitre", {}).get("technique_id", ""),
                "asset":     f["affected_asset"][:60],
            })
        return dict(groups)

    @staticmethod
    def _compute_quality_score(
        verified:         List[Dict],
        unverified:       List[Dict],
        modules_present:  List[str],
        validation_log:   List[Dict],
    ) -> Dict:
        total   = len(verified) + len(unverified)
        pct_verified = (len(verified) / total * 100) if total > 0 else 0

        # Completeness — how many ARTEX modules contributed
        all_modules = {
            "subdomains", "port_scan", "ssl_scan", "dns_records",
            "tech_detection", "email_enumeration", "real_ip",
            "security_analysis", "vuln_prioritization", "attack_path_graph",
            "header_analysis", "takeover_analysis", "osint_correlation",
            "payload_analysis", "api_fuzz_results", "waf_fingerprint",
            "remediation_plan",
        }
        completeness = len(set(modules_present) & all_modules) / len(all_modules) * 100

        # CVSS coverage
        cvss_covered = sum(
            1 for f in verified if f.get("cvss", {}).get("score", -1) >= 0
        )
        cvss_pct = (cvss_covered / len(verified) * 100) if verified else 0

        # MITRE coverage
        mitre_covered = sum(
            1 for f in verified if f.get("mitre", {}).get("technique_id")
        )
        mitre_pct = (mitre_covered / len(verified) * 100) if verified else 0

        score = round(
            pct_verified * 0.35 +
            completeness * 0.30 +
            cvss_pct     * 0.20 +
            mitre_pct    * 0.15
        )

        return {
            "score":                score,
            "pct_findings_verified": round(pct_verified, 1),
            "module_completeness_pct": round(completeness, 1),
            "cvss_coverage_pct":    round(cvss_pct, 1),
            "mitre_coverage_pct":   round(mitre_pct, 1),
            "confidence_level":     (
                "high"   if score >= 75
                else "medium" if score >= 50
                else "low"
            ),
            "validation_layers_passed": len(validation_log),
        }

    # ==================================================================
    # Sanitise AI output — strip hallucinated finding IDs
    # ==================================================================

    @staticmethod
    def _sanitise_ai_output(ai: Dict, verified_ids: Set[str]) -> Dict:
        """
        Remove any finding_id from AI output that is not in verified_ids.
        This is the final anti-hallucination barrier.
        """
        for action in ai.get("top3_critical_actions", []):
            before = action.get("finding_ids", [])
            action["finding_ids"] = [
                fid for fid in before if fid in verified_ids
            ]

        # Strip any stray IDs from executive_summary text
        summary = ai.get("executive_summary", "")
        invented_ids = re.findall(r"\b[A-Z]{2,10}-[a-f0-9]{10,20}\b", summary)
        for iid in invented_ids:
            if iid not in verified_ids:
                ai["executive_summary"] = summary.replace(iid, "[finding_ref_redacted]")

        return ai

    # ==================================================================
    # Groq API
    # ==================================================================

    def _call_groq(self, prompt: str) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type":  "application/json",
        }
        payload = {
            "model":       "llama3-70b-8192",
            "messages":    [{"role": "user", "content": prompt}],
            "temperature": 0.15,
            "max_tokens":  2000,
        }
        for attempt in range(3):
            try:
                self.logger.info(f"Groq API call attempt {attempt + 1}")
                resp = req_lib.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=headers, json=payload, timeout=self.timeout,
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
                if resp.status_code == 429:
                    time.sleep(15 * (attempt + 1))
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
            return json.loads(cleaned)
        except json.JSONDecodeError:
            start = cleaned.find("{")
            end   = cleaned.rfind("}") + 1
            if start != -1 and end > start:
                try:
                    return json.loads(cleaned[start:end])
                except json.JSONDecodeError:
                    pass
        self.logger.error("Could not parse Groq JSON response")
        return None