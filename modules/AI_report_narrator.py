# AI_report_narrator.py
import json
import hashlib
import logging
import time
import requests
import os
from datetime import datetime
from io import BytesIO
from typing import Dict, List, Optional, Any

# ── ReportLab — already installed per existing reporting.py ─────────
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Preformatted, KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

# ── Existing ARTEX utilities ─────────────────────────────────────────
from utils.helpers import format_timestamp
from utils.reporting import ReportGenerator   # reuse styles

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")


# ---------------------------------------------------------------------------
# Evidence record — every AI action becomes a signed evidence entry
# ---------------------------------------------------------------------------

class EvidenceRecord:
    """
    Immutable evidence record representing one AI-initiated action.
    SHA-256 chained so the log cannot be silently tampered.
    """
    __slots__ = (
        "evidence_id", "sequence", "timestamp",
        "agent", "action", "tool_or_function",
        "arguments", "raw_output", "result_summary",
        "exit_code", "duration_s", "sha256",
        "previous_hash",
    )

    def __init__(
        self,
        sequence:          int,
        agent:             str,
        action:            str,
        tool_or_function:  str,
        arguments:         Dict,
        raw_output:        str,
        result_summary:    str,
        exit_code:         int      = 0,
        duration_s:        float    = 0.0,
        previous_hash:     str      = "GENESIS",
    ):
        self.sequence          = sequence
        self.timestamp         = datetime.now().isoformat()
        self.agent             = agent
        self.action            = action
        self.tool_or_function  = tool_or_function
        self.arguments         = arguments
        self.raw_output        = raw_output[:4000]   # cap per record
        self.result_summary    = result_summary
        self.exit_code         = exit_code
        self.duration_s        = round(duration_s, 3)
        self.previous_hash     = previous_hash

        # Deterministic ID
        raw_id = f"{sequence}|{agent}|{action}|{tool_or_function}|{self.timestamp}"
        self.evidence_id = hashlib.sha256(raw_id.encode()).hexdigest()[:16]

        # Chain hash — covers content + previous hash
        chain_input = json.dumps({
            "evidence_id":     self.evidence_id,
            "sequence":        self.sequence,
            "agent":           self.agent,
            "action":          self.action,
            "tool":            self.tool_or_function,
            "arguments":       self.arguments,
            "result_summary":  self.result_summary,
            "exit_code":       self.exit_code,
            "previous_hash":   self.previous_hash,
        }, sort_keys=True, default=str)
        self.sha256 = hashlib.sha256(chain_input.encode()).hexdigest()

    def to_dict(self) -> Dict:
        return {k: getattr(self, k) for k in self.__slots__}


class EvidenceChain:
    """Append-only, hash-chained list of EvidenceRecord objects."""

    def __init__(self, batch_id: str, target: str):
        self.batch_id  = batch_id
        self.target    = target
        self._records: List[EvidenceRecord] = []
        self._counter  = 0

    def add(
        self,
        agent:            str,
        action:           str,
        tool_or_function: str,
        arguments:        Dict,
        raw_output:       str,
        result_summary:   str,
        exit_code:        int   = 0,
        duration_s:       float = 0.0,
    ) -> EvidenceRecord:
        prev_hash = self._records[-1].sha256 if self._records else "GENESIS"
        self._counter += 1
        rec = EvidenceRecord(
            sequence          = self._counter,
            agent             = agent,
            action            = action,
            tool_or_function  = tool_or_function,
            arguments         = arguments,
            raw_output        = raw_output,
            result_summary    = result_summary,
            exit_code         = exit_code,
            duration_s        = duration_s,
            previous_hash     = prev_hash,
        )
        self._records.append(rec)
        return rec

    def all_records(self) -> List[EvidenceRecord]:
        return list(self._records)

    def verify_integrity(self) -> bool:
        """Walk the chain, recompute each hash, return False if tampered."""
        prev_hash = "GENESIS"
        for rec in self._records:
            chain_input = json.dumps({
                "evidence_id":     rec.evidence_id,
                "sequence":        rec.sequence,
                "agent":           rec.agent,
                "action":          rec.action,
                "tool":            rec.tool_or_function,
                "arguments":       rec.arguments,
                "result_summary":  rec.result_summary,
                "exit_code":       rec.exit_code,
                "previous_hash":   prev_hash,
            }, sort_keys=True, default=str)
            expected = hashlib.sha256(chain_input.encode()).hexdigest()
            if expected != rec.sha256:
                return False
            prev_hash = rec.sha256
        return True

    def to_dict(self) -> Dict:
        return {
            "batch_id":    self.batch_id,
            "target":      self.target,
            "total_steps": self._counter,
            "integrity_ok": self.verify_integrity(),
            "records":     [r.to_dict() for r in self._records],
        }


# ---------------------------------------------------------------------------
# Narrative sections — structured output from Groq
# ---------------------------------------------------------------------------

PERSPECTIVE_OWNER  = "owner"
PERSPECTIVE_HUNTER = "hunter"


# ---------------------------------------------------------------------------
# Main narrator class
# ---------------------------------------------------------------------------

class AIReportNarrator:
    """
    Generates an executive narrative security report from all ARTEX scan_results.

    Three output modes:
        generate_pdf()   — full reportlab PDF (extends existing ReportGenerator style)
        generate_json()  — structured JSON for API consumers
        generate_txt()   — plain-text version for terminals and email

    Three report sections:
        1. Owner Perspective   — defensive, board-level, remediation roadmap
        2. Hunter Perspective  — offensive, TTPs, exploitation priority
        3. AI Operation Log    — every AI action with arguments, outputs,
                                 durations, and SHA-256 hash chain (evidence)

    Slot in run_scan() / AI_batch_orchestrator after all other modules:
        narrator = AIReportNarrator(groq_api_key=GROQ_API_KEY)
        scan_results['narrative_report'] = narrator.narrate(
            domain=domain,
            scan_results=scan_results,
            batch_id=batch_id,         # optional — omit for single-target
        )
    """

    # ── ARTEX colour palette from existing ReportGenerator ───────────
    _C_PRIMARY   = colors.HexColor("#4a6baf")
    _C_SECONDARY = colors.HexColor("#2c3e50")
    _C_ACCENT    = colors.HexColor("#e74c3c")
    _C_BG        = colors.HexColor("#f0f0f0")
    _C_BLACK     = colors.HexColor("#000000")
    _C_WHITE     = colors.white
    _C_EVIDENCE  = colors.HexColor("#1a1a2e")   # dark navy for evidence section
    _C_CHAIN_OK  = colors.HexColor("#27ae60")
    _C_CHAIN_ERR = colors.HexColor("#e74c3c")

    _RISK_COLORS = {
        "critical": colors.HexColor("#ff0000"),
        "high":     colors.HexColor("#ff6600"),
        "medium":   colors.HexColor("#0066ff"),
        "low":      colors.HexColor("#00aa00"),
        "info":     colors.HexColor("#666666"),
    }

    def __init__(self, groq_api_key: str = GROQ_API_KEY, timeout: int = 45):
        self.groq_api_key = groq_api_key
        self.timeout      = timeout
        self.logger       = logging.getLogger(__name__)

        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] AIReportNarrator — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

        self._styles = self._build_styles()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def narrate(
        self,
        domain:      str,
        scan_results: Dict,
        batch_id:    str = "single",
    ) -> Dict:
        """
        Build complete narrative report from all available scan_results keys.

        Returns:
            {
                owner_narrative:    { executive_summary, risk_posture, findings,
                                      remediation_roadmap, compliance_notes }
                hunter_narrative:   { threat_model, attack_paths, exploitation_priority,
                                      ttp_mapping, detection_gaps }
                ai_operation_log:   { batch_id, target, total_steps,
                                      integrity_ok, records:[...] }
                report_metadata:    { generated_at, domain, modules_read,
                                      groq_model_used, generation_duration_s }
            }
        """
        self.logger.info(f"Narrating report for domain: {domain}")
        start = time.time()

        # ── Build evidence chain — log every read + AI call ──────────
        chain = EvidenceChain(batch_id=batch_id, target=domain)

        # ── Collect data from all available scan_results keys ─────────
        data_profile = self._collect_data_profile(domain, scan_results, chain)

        # ── Generate owner narrative ──────────────────────────────────
        owner_narrative = self._generate_owner_narrative(domain, data_profile, chain)

        # ── Generate hunter narrative ─────────────────────────────────
        hunter_narrative = self._generate_hunter_narrative(domain, data_profile, chain)

        duration = round(time.time() - start, 2)

        return {
            "owner_narrative":   owner_narrative,
            "hunter_narrative":  hunter_narrative,
            "ai_operation_log":  chain.to_dict(),
            "report_metadata": {
                "generated_at":          datetime.now().isoformat(),
                "domain":                domain,
                "batch_id":              batch_id,
                "modules_read":          data_profile["modules_present"],
                "groq_model_used":       "llama3-70b-8192" if self.groq_api_key else "rule-based",
                "generation_duration_s": duration,
                "evidence_integrity":    chain.verify_integrity(),
                "total_evidence_records": len(chain.all_records()),
            },
        }

    # ------------------------------------------------------------------
    # PDF output
    # ------------------------------------------------------------------

    def generate_pdf(
        self,
        domain:      str,
        scan_results: Dict,
        batch_id:    str = "single",
    ) -> bytes:
        """
        Generate full PDF narrative report.
        Extends existing ReportGenerator retro style.
        """
        narrative = self.narrate(domain, scan_results, batch_id)
        buffer    = BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize    = A4,
            rightMargin = 36,
            leftMargin  = 36,
            topMargin   = 36,
            bottomMargin = 36,
            title       = f"AI Red Team Report — {domain}",
            author      = "ARTEX AI Report Narrator",
        )

        story: List = []
        story += self._pdf_cover(domain, narrative)
        story += self._pdf_toc()
        story += self._pdf_owner_section(narrative["owner_narrative"])
        story += self._pdf_hunter_section(narrative["hunter_narrative"])
        story += self._pdf_evidence_section(narrative["ai_operation_log"])
        story += self._pdf_metadata_section(narrative["report_metadata"])

        doc.build(story)
        return buffer.getvalue()

    # ------------------------------------------------------------------
    # JSON / TXT helpers
    # ------------------------------------------------------------------

    def generate_json(
        self,
        domain:      str,
        scan_results: Dict,
        batch_id:    str = "single",
    ) -> str:
        return json.dumps(
            self.narrate(domain, scan_results, batch_id),
            indent=2, default=str,
        )

    def generate_txt(
        self,
        domain:      str,
        scan_results: Dict,
        batch_id:    str = "single",
    ) -> str:
        n   = self.narrate(domain, scan_results, batch_id)
        own = n["owner_narrative"]
        hun = n["hunter_narrative"]
        log = n["ai_operation_log"]
        meta = n["report_metadata"]

        lines = [
            "=" * 70,
            f"  ARTEX AI RED TEAM REPORT — {domain.upper()}",
            f"  Generated: {meta['generated_at']}",
            f"  Batch ID:  {batch_id}",
            "=" * 70,
            "",
            "━" * 70,
            "  SECTION 1 — OWNER PERSPECTIVE (DEFENSIVE)",
            "━" * 70,
            "",
            f"Executive Summary:",
            own.get("executive_summary", "N/A"),
            "",
            f"Risk Posture: {own.get('risk_posture', {}).get('level','?')} "
            f"(score {own.get('risk_posture', {}).get('score','?')}/100)",
            own.get("risk_posture", {}).get("rationale", ""),
            "",
            "Top Findings:",
        ]
        for f in own.get("top_findings", [])[:5]:
            lines.append(f"  [{f.get('severity','?').upper():8}] {f.get('title','')}")
            lines.append(f"            Asset: {f.get('asset','')}")

        lines += [
            "",
            "Remediation Roadmap:",
        ]
        for phase in own.get("remediation_roadmap", []):
            lines.append(f"  Phase — {phase.get('phase','?')}")
            for item in phase.get("items", [])[:4]:
                lines.append(f"    • {item}")

        lines += [
            "",
            "━" * 70,
            "  SECTION 2 — HUNTER PERSPECTIVE (OFFENSIVE)",
            "━" * 70,
            "",
            f"Threat Model:",
            hun.get("threat_model", "N/A"),
            "",
            "Critical Attack Paths:",
        ]
        for path in hun.get("critical_attack_paths", [])[:3]:
            lines.append(f"  PATH: {path.get('path_name','?')}")
            lines.append(f"  Severity: {path.get('severity','?')} | Effort: {path.get('effort','?')}")
            for step in path.get("steps", [])[:4]:
                lines.append(f"    {step}")
            lines.append("")

        lines += [
            "Exploitation Priority:",
        ]
        for item in hun.get("exploitation_priority", [])[:5]:
            lines.append(f"  [{item.get('rank','?')}] {item.get('target','')} — {item.get('technique','')}")

        lines += [
            "",
            "MITRE ATT&CK TTPs:",
        ]
        for ttp in hun.get("ttp_mapping", [])[:8]:
            lines.append(f"  {ttp.get('technique_id','?')} — {ttp.get('technique_name','?')}")
            lines.append(f"    Evidence: {ttp.get('evidence','')}")

        lines += [
            "",
            "━" * 70,
            "  SECTION 3 — AI OPERATION LOG (EVIDENCE CHAIN)",
            "━" * 70,
            "",
            f"Batch ID:    {log.get('batch_id','?')}",
            f"Target:      {log.get('target','?')}",
            f"Total Steps: {log.get('total_steps','?')}",
            f"Integrity:   {'✓ VERIFIED' if log.get('integrity_ok') else '✗ CHAIN BROKEN'}",
            "",
        ]
        for rec in log.get("records", []):
            lines += [
                f"  ┌─ [{rec['sequence']:03d}] {rec['timestamp']}",
                f"  │  Agent:    {rec['agent']}",
                f"  │  Action:   {rec['action']}",
                f"  │  Tool:     {rec['tool_or_function']}",
                f"  │  Args:     {json.dumps(rec['arguments'], default=str)[:120]}",
                f"  │  Duration: {rec['duration_s']}s | Exit: {rec['exit_code']}",
                f"  │  Result:   {rec['result_summary'][:200]}",
                f"  └─ SHA-256:  {rec['sha256'][:32]}...",
                "",
            ]

        lines += [
            "━" * 70,
            "  REPORT METADATA",
            "━" * 70,
            f"  Modules read:    {', '.join(meta.get('modules_read', []))}",
            f"  AI model:        {meta.get('groq_model_used','?')}",
            f"  Build time:      {meta.get('generation_duration_s','?')}s",
            f"  Evidence records: {meta.get('total_evidence_records','?')}",
            f"  Chain integrity: {'OK' if meta.get('evidence_integrity') else 'BROKEN'}",
            "=" * 70,
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Data collection from all scan_results keys
    # ------------------------------------------------------------------

    def _collect_data_profile(
        self,
        domain:      str,
        sr:          Dict,
        chain:       EvidenceChain,
    ) -> Dict:
        """
        Read every available scan_results key, log each read as evidence,
        return a condensed data_profile dict for Groq prompts.
        """
        t0 = time.time()
        profile: Dict = {
            "domain":          domain,
            "modules_present": [],
        }

        # ── Helper to read a key and log it ──────────────────────────
        def _read(key: str, description: str) -> Any:
            val = sr.get(key)
            if val is not None:
                profile["modules_present"].append(key)
                summary = self._summarise_key(key, val)
                chain.add(
                    agent            = "AIReportNarrator._collect_data_profile",
                    action           = f"READ_SCAN_RESULTS[{key}]",
                    tool_or_function = f"scan_results.get('{key}')",
                    arguments        = {"key": key},
                    raw_output       = json.dumps(val, default=str)[:800],
                    result_summary   = summary,
                    exit_code        = 0,
                    duration_s       = 0.001,
                )
            return val

        # ── Core recon keys ──────────────────────────────────────────
        subdomains = _read("subdomains", "Subdomain enumeration results")
        profile["subdomains"] = subdomains or []
        active = [s for s in profile["subdomains"]
                  if s.get("http_status") or s.get("https_status")]
        profile["active_subdomain_count"] = len(active)
        profile["total_subdomain_count"]  = len(profile["subdomains"])

        dns_records = _read("dns_records", "DNS records")
        profile["dns_records"] = dns_records or {}
        profile["has_spf"]     = any("v=spf1" in str(r) for r in
                                     (dns_records or {}).get("TXT", []))
        profile["has_dmarc"]   = False   # will be updated from osint below

        port_scan = _read("port_scan", "Port scan results")
        profile["port_scan"]    = port_scan or []
        profile["open_ports"]   = []
        profile["risky_ports"]  = []
        for host_data in profile["port_scan"]:
            if isinstance(host_data, dict):
                profile["open_ports"]  += host_data.get("ports", [])
                profile["risky_ports"] += host_data.get("risky_ports", [])
        profile["open_port_count"]  = len(profile["open_ports"])
        profile["risky_port_count"] = len(profile["risky_ports"])

        ssl_scan = _read("ssl_scan", "SSL/TLS scan results")
        profile["ssl_scan"] = ssl_scan or {}
        ssl_vulns = []
        for host, hdata in profile["ssl_scan"].items():
            if isinstance(hdata, dict):
                for vuln, hit in hdata.get("vulnerabilities", {}).items():
                    if hit:
                        ssl_vulns.append({"host": host, "vuln": vuln})
        profile["ssl_vulns"] = ssl_vulns

        tech_detection = _read("tech_detection", "Technology detection results")
        profile["tech_detection"] = tech_detection or {}
        all_techs: List[str] = []
        for url, tdata in profile["tech_detection"].items():
            if isinstance(tdata, dict):
                for t in tdata.get("technologies", []):
                    if isinstance(t, dict) and t.get("name"):
                        all_techs.append(t["name"])
        profile["all_technologies"] = list(set(all_techs))

        email_enum = _read("email_enumeration", "Email enumeration results")
        profile["email_enumeration"] = email_enum or {}
        profile["email_count"]       = len((email_enum or {}).get("found_emails", []))
        profile["login_pages"]       = (email_enum or {}).get("login_pages", [])

        real_ip = _read("real_ip", "Real IP discovery")
        profile["real_ip"] = real_ip or {}

        # ── Security + AI analysis keys ──────────────────────────────
        security_analysis = _read("security_analysis", "FastSecurityAnalyst output")
        profile["security_analysis"] = security_analysis or {}
        profile["risk_level"]  = (security_analysis or {}).get(
            "risk_assessment", {}).get("level", "unknown")
        profile["risk_score"]  = (security_analysis or {}).get(
            "risk_assessment", {}).get("score", 0)
        profile["high_value_targets"] = (security_analysis or {}).get(
            "high_value_targets", [])

        ai_analysis = _read("ai_analysis", "AIAnalyst output")
        profile["ai_analysis"] = ai_analysis or {}

        # ── New AI module outputs ─────────────────────────────────────
        vuln_prio = _read("vuln_prioritization", "AI Vuln Prioritizer output")
        profile["vuln_prioritization"] = vuln_prio or {}
        profile["vuln_findings"]        = (vuln_prio or {}).get("findings", [])
        profile["vuln_severity_counts"] = (vuln_prio or {}).get("severity_counts", {})
        profile["vuln_overall_risk"]    = (vuln_prio or {}).get("overall_risk", {})
        profile["vuln_attack_chains"]   = (vuln_prio or {}).get("attack_chains", [])

        attack_path = _read("attack_path_graph", "AI Attack Path Planner output")
        profile["attack_path_graph"]  = attack_path or {}
        profile["critical_paths"]     = (attack_path or {}).get("critical_paths", [])
        profile["graph_stats"]        = (attack_path or {}).get("graph_stats", {})
        profile["path_summary"]       = (attack_path or {}).get("path_summary", {})

        header_analysis = _read("header_analysis", "AI Header Analyzer output")
        profile["header_analysis"] = header_analysis or {}
        profile["header_findings"]  = []
        for url, tdata in (header_analysis or {}).get("targets", {}).items():
            if isinstance(tdata, dict):
                for f in tdata.get("findings", []):
                    if f.get("severity") in ("critical", "high"):
                        profile["header_findings"].append(f)

        takeover = _read("takeover_analysis", "AI Subdomain Takeover Analyzer output")
        profile["takeover_analysis"] = takeover or {}
        profile["takeover_vulnerable"] = (takeover or {}).get("vulnerable", [])

        osint = _read("osint_correlation", "AI OSINT Correlator output")
        profile["osint_correlation"] = osint or {}
        profile["credential_leaks"]  = (osint or {}).get("credential_leaks", {})
        dns_intel = (osint or {}).get("dns_intelligence", {})
        if dns_intel:
            profile["has_dmarc"] = (dns_intel.get("dmarc_analysis") or {}).get("present", False)
            profile["dmarc_policy"] = (dns_intel.get("dmarc_analysis") or {}).get("policy")
            profile["spf_risk"]     = (dns_intel.get("spf_analysis") or {}).get("risk")

        payload_analysis = _read("payload_analysis", "AI Payload Generator output")
        profile["payload_analysis"] = payload_analysis or {}
        profile["vuln_classes"]      = (payload_analysis or {}).get("vuln_classes", [])
        profile["waf_detected"]      = (payload_analysis or {}).get("waf_detected", {})

        # ── Batch execution log (from AI_batch_orchestrator) ─────────
        exec_log = sr.get("_execution_log", [])
        if exec_log:
            profile["modules_present"].append("_execution_log")
            profile["execution_log"] = exec_log
            for entry in exec_log:
                chain.add(
                    agent            = entry.get("agent", "batch_orchestrator"),
                    action           = f"TOOL_INVOCATION: {entry.get('tool', '?')}",
                    tool_or_function = entry.get("tool", "unknown"),
                    arguments        = {
                        "operation": entry.get("operation", ""),
                        "args":      entry.get("args", {}),
                    },
                    raw_output       = entry.get("stdout", "")[:600],
                    result_summary   = (
                        f"exit={entry.get('exit_code','?')}, "
                        f"status={entry.get('status','?')}, "
                        f"duration={entry.get('duration_s','?')}s"
                    ),
                    exit_code  = entry.get("exit_code", 0),
                    duration_s = entry.get("duration_s", 0.0),
                )
        else:
            profile["execution_log"] = []

        chain.add(
            agent            = "AIReportNarrator._collect_data_profile",
            action           = "DATA_PROFILE_COMPLETE",
            tool_or_function = "internal aggregation",
            arguments        = {"modules_read": len(profile["modules_present"])},
            raw_output       = "",
            result_summary   = (
                f"Profile built from {len(profile['modules_present'])} modules. "
                f"Active subdomains: {profile['active_subdomain_count']}, "
                f"Vulns: {sum(profile['vuln_severity_counts'].values())}, "
                f"Risk: {profile.get('risk_level','?')}"
            ),
            duration_s = round(time.time() - t0, 3),
        )

        return profile

    # ------------------------------------------------------------------
    # Owner narrative generation
    # ------------------------------------------------------------------

    def _generate_owner_narrative(
        self,
        domain:  str,
        profile: Dict,
        chain:   EvidenceChain,
    ) -> Dict:
        t0 = time.time()
        chain.add(
            agent            = "AIReportNarrator.owner_perspective",
            action           = "GROQ_NARRATIVE_REQUEST",
            tool_or_function = "POST https://api.groq.com/openai/v1/chat/completions",
            arguments        = {
                "model":       "llama3-70b-8192",
                "perspective": "owner",
                "domain":      domain,
                "input_keys":  profile["modules_present"],
            },
            raw_output   = "",
            result_summary = "Sending owner-perspective prompt to Groq",
            duration_s   = 0.0,
        )

        if self.groq_api_key:
            result = self._groq_owner(domain, profile)
        else:
            result = self._rule_based_owner(domain, profile)

        duration = round(time.time() - t0, 3)
        chain.add(
            agent            = "AIReportNarrator.owner_perspective",
            action           = "OWNER_NARRATIVE_COMPLETE",
            tool_or_function = "POST https://api.groq.com/openai/v1/chat/completions",
            arguments        = {"domain": domain, "perspective": "owner"},
            raw_output       = json.dumps(result, default=str)[:1000],
            result_summary   = (
                f"Owner narrative generated. "
                f"Risk level: {result.get('risk_posture', {}).get('level', '?')}. "
                f"Top findings: {len(result.get('top_findings', []))}. "
                f"Remediation phases: {len(result.get('remediation_roadmap', []))}."
            ),
            exit_code  = 0,
            duration_s = duration,
        )
        return result

    def _groq_owner(self, domain: str, p: Dict) -> Dict:
        prompt = f"""You are a lead security consultant preparing an executive report for the CISO and board.
Domain assessed: {domain}

Assessment data:
- Risk level: {p.get('risk_level','unknown')} (score {p.get('risk_score',0)}/100)
- Active subdomains: {p.get('active_subdomain_count',0)}
- Risky open ports: {p.get('risky_port_count',0)}
- SSL vulnerabilities: {len(p.get('ssl_vulns',[]))}
- Subdomain takeover candidates: {len(p.get('takeover_vulnerable',[]))}
- Credential leaks (GitHub): {len(p.get('credential_leaks',{}).get('github_hits',[]))}
- Header findings (high/critical): {len(p.get('header_findings',[]))}
- Vulnerability findings: {json.dumps(p.get('vuln_severity_counts',{}),indent=2)}
- Technologies: {p.get('all_technologies',[])[:12]}
- Overall risk rationale: {p.get('vuln_overall_risk',{}).get('rationale','')}
- WAF detected: {p.get('waf_detected',{}).get('name','none')}
- DMARC policy: {p.get('dmarc_policy','absent')} | SPF risk: {p.get('spf_risk','?')}
- Attack chains: {[c.get('chain_name','') for c in p.get('vuln_attack_chains',[])[:4]]}
- Vuln classes (inferred): {p.get('vuln_classes',[])[:10]}

Return ONLY valid JSON with these exact keys:
- "executive_summary": string — 4-5 sentences suitable for a board briefing. Explain the security posture, most critical risk, and business impact in plain English.
- "risk_posture": object with "level" (critical/high/medium/low), "score" (int 0-100), "rationale" (string — 2 sentences).
- "top_findings": array of objects (max 10) ordered by severity, each with "title" (string), "severity" (string), "asset" (string), "business_impact" (string — one sentence), "evidence_ref" (string — which scan module confirmed this).
- "remediation_roadmap": array of objects each with "phase" (Immediate/30-day/90-day/Strategic), "items" (array of strings — specific actionable tasks, not generic advice).
- "compliance_notes": array of strings — potential regulatory implications (PDPA, ISO 27001, PCI-DSS, GDPR) based on findings.
- "positive_controls": array of strings — security controls already in place that were observed.

Return ONLY valid JSON. No markdown, no preamble."""

        return self._call_groq(prompt) or self._rule_based_owner(domain, p)

    def _rule_based_owner(self, domain: str, p: Dict) -> Dict:
        sev = p.get("vuln_severity_counts", {})
        crit = sev.get("critical", 0)
        high = sev.get("high", 0)
        risk = p.get("risk_level", "unknown")

        findings = []
        for f in p.get("vuln_findings", [])[:10]:
            findings.append({
                "title":          f.get("title", "")[:80],
                "severity":       f.get("severity", "?"),
                "asset":          f.get("affected_asset", "?"),
                "business_impact": f.get("description", "")[:120],
                "evidence_ref":   f.get("source", "?"),
            })

        return {
            "executive_summary": (
                f"Security assessment of {domain} identified {crit} critical and {high} high severity "
                f"vulnerabilities across {p.get('active_subdomain_count',0)} active subdomains. "
                f"Overall risk level is {risk}. "
                f"Key concerns include {p.get('risky_port_count',0)} exposed risky ports, "
                f"{len(p.get('takeover_vulnerable',[]))} subdomain takeover candidates, "
                f"and {len(p.get('credential_leaks',{}).get('github_hits',[]))} credential leak hits. "
                f"Immediate remediation is required for critical findings to prevent potential data breach."
            ),
            "risk_posture": {
                "level":    risk,
                "score":    p.get("risk_score", 0),
                "rationale": (
                    f"{crit} critical findings require immediate action. "
                    f"Attack surface spans {p.get('total_subdomain_count',0)} subdomains."
                ),
            },
            "top_findings":       findings,
            "remediation_roadmap": [
                {"phase": "Immediate", "items": [
                    "Patch or firewall all risky open ports",
                    "Rotate any leaked credentials found in GitHub",
                    "Claim or remove dangling DNS records (subdomain takeover)",
                ]},
                {"phase": "30-day", "items": [
                    "Implement DMARC p=quarantine and strict SPF",
                    "Add security headers: CSP, HSTS, X-Frame-Options",
                    "Patch SSL/TLS vulnerabilities",
                ]},
                {"phase": "90-day", "items": [
                    "Penetration test all identified injection point surfaces",
                    "Implement WAF tuned to detected tech stack",
                    "Conduct credential hygiene audit",
                ]},
            ],
            "compliance_notes":  ["Review PDPA obligations for any PII exposure"],
            "positive_controls": ["WAF detected" if p.get("waf_detected", {}).get("detected") else "No WAF observed"],
        }

    # ------------------------------------------------------------------
    # Hunter narrative generation
    # ------------------------------------------------------------------

    def _generate_hunter_narrative(
        self,
        domain:  str,
        profile: Dict,
        chain:   EvidenceChain,
    ) -> Dict:
        t0 = time.time()
        chain.add(
            agent            = "AIReportNarrator.hunter_perspective",
            action           = "GROQ_NARRATIVE_REQUEST",
            tool_or_function = "POST https://api.groq.com/openai/v1/chat/completions",
            arguments        = {
                "model":       "llama3-70b-8192",
                "perspective": "hunter",
                "domain":      domain,
            },
            raw_output   = "",
            result_summary = "Sending hunter-perspective prompt to Groq",
            duration_s   = 0.0,
        )

        if self.groq_api_key:
            result = self._groq_hunter(domain, profile)
        else:
            result = self._rule_based_hunter(domain, profile)

        duration = round(time.time() - t0, 3)
        chain.add(
            agent            = "AIReportNarrator.hunter_perspective",
            action           = "HUNTER_NARRATIVE_COMPLETE",
            tool_or_function = "POST https://api.groq.com/openai/v1/chat/completions",
            arguments        = {"domain": domain, "perspective": "hunter"},
            raw_output       = json.dumps(result, default=str)[:1000],
            result_summary   = (
                f"Hunter narrative generated. "
                f"Attack paths: {len(result.get('critical_attack_paths',[]))}. "
                f"TTPs mapped: {len(result.get('ttp_mapping',[]))}."
            ),
            exit_code  = 0,
            duration_s = duration,
        )
        return result

    def _groq_hunter(self, domain: str, p: Dict) -> Dict:
        # Condense critical paths for prompt
        paths_condensed = []
        for path in p.get("critical_paths", [])[:5]:
            paths_condensed.append({
                "route":     " → ".join(path.get("node_labels", [])[:6]),
                "severity":  path.get("worst_severity","?"),
                "score":     path.get("score", 0),
                "techniques": [e.get("technique","")[:60] for e in path.get("edges",[])[:4]],
            })

        prompt = f"""You are a senior red team operator writing the offensive section of a pentest report.
Domain assessed: {domain}

Technical profile:
- Technologies detected: {p.get('all_technologies',[])[:12]}
- Vuln classes (confirmed by stack): {p.get('vuln_classes',[])[:12]}
- Risky ports: {[r.get('port') for r in p.get('risky_ports',[])[:8]]}
- SSL vulns: {[v.get('vuln') for v in p.get('ssl_vulns',[])[:5]]}
- Subdomain takeover candidates: {len(p.get('takeover_vulnerable',[]))}
- Credential leaks: {len(p.get('credential_leaks',{}).get('github_hits',[]))} GitHub hits
- Login pages: {len(p.get('login_pages',[]))}
- WAF: {p.get('waf_detected',{}).get('name','none')} (bypass: {p.get('waf_detected',{}).get('bypass_strategy','n/a')})
- Attack chains: {[c.get('chain_name','') for c in p.get('vuln_attack_chains',[])[:5]]}
- Critical paths (graph): {json.dumps(paths_condensed, indent=2)[:1200]}

Return ONLY valid JSON with these exact keys:
- "threat_model": string — 3-4 sentences describing the most realistic threat scenario an attacker would pursue.
- "critical_attack_paths": array of objects (max 5), each with "path_name" (string), "severity" (string), "effort" (easy/medium/hard), "steps" (array of strings — concrete attacker actions in order), "impact" (string).
- "exploitation_priority": array of objects ordered by ease×impact, each with "rank" (int 1-10), "target" (string — specific URL or service), "technique" (string), "tool" (string — actual tool name), "estimated_time" (string — realistic estimate).
- "ttp_mapping": array of objects, each with "technique_id" (ATT&CK ID like T1190), "technique_name" (string), "tactic" (string), "evidence" (string — what finding maps to this TTP).
- "detection_gaps": array of strings — 3-5 specific defensive blind spots revealed by the attack paths.
- "quick_wins": array of strings — 3-5 attack vectors most likely to yield results with minimal effort.
- "waf_evasion_guide": string — if WAF detected, specific bypass approach for this stack. Otherwise "No WAF detected."

Return ONLY valid JSON. No markdown, no preamble."""

        return self._call_groq(prompt) or self._rule_based_hunter(domain, p)

    def _rule_based_hunter(self, domain: str, p: Dict) -> Dict:
        paths = []
        for path in p.get("critical_paths", [])[:3]:
            paths.append({
                "path_name":  " → ".join(path.get("node_labels", [])[:4]),
                "severity":   path.get("worst_severity", "?"),
                "effort":     "medium",
                "steps":      [e.get("technique","?")[:80] for e in path.get("edges",[])[:4]],
                "impact":     "Data exfiltration or infrastructure access",
            })

        ttp_base = []
        for vc in p.get("vuln_classes", [])[:8]:
            ttp_map = {
                "sqli":     ("T1190", "Exploit Public-Facing Application", "Initial Access"),
                "xss":      ("T1059.007", "JavaScript", "Execution"),
                "ssti":     ("T1059", "Command and Scripting Interpreter", "Execution"),
                "ssrf":     ("T1090", "Proxy", "Command and Control"),
                "cmdi":     ("T1059.004", "Unix Shell", "Execution"),
                "path_traversal": ("T1083", "File and Directory Discovery", "Discovery"),
            }
            if vc in ttp_map:
                tid, tname, tactic = ttp_map[vc]
                ttp_base.append({
                    "technique_id":   tid,
                    "technique_name": tname,
                    "tactic":         tactic,
                    "evidence":       f"Vuln class {vc} inferred from tech stack",
                })

        return {
            "threat_model": (
                f"The primary attack scenario against {domain} involves chaining exposed "
                f"services ({p.get('risky_port_count',0)} risky ports) with identified "
                f"web application vulnerabilities ({', '.join(p.get('vuln_classes',[])[:4])}). "
                f"Credential leak hits ({len(p.get('credential_leaks',{}).get('github_hits',[]))}) "
                f"provide a high-probability initial access vector."
            ),
            "critical_attack_paths":  paths,
            "exploitation_priority":  [
                {"rank": 1, "target": t.get("subdomain","?"),
                 "technique": "Direct web exploitation",
                 "tool": "Burp Suite",
                 "estimated_time": "1-4 hours"}
                for t in p.get("high_value_targets", [])[:3]
            ],
            "ttp_mapping":     ttp_base,
            "detection_gaps":  [
                "No DMARC enforcement — phishing undetected",
                "Open ports not monitored for auth failures",
            ],
            "quick_wins": [
                f"Credential reuse from {len(p.get('credential_leaks',{}).get('github_hits',[]))} GitHub leak hits",
                f"Subdomain takeover — {len(p.get('takeover_vulnerable',[]))} candidates",
                "Login page bruteforce — no lockout observed",
            ],
            "waf_evasion_guide": (
                p.get("waf_detected", {}).get("bypass_strategy", "No WAF detected.")
                if p.get("waf_detected", {}).get("detected")
                else "No WAF detected."
            ),
        }

    # ------------------------------------------------------------------
    # Groq API caller
    # ------------------------------------------------------------------

    def _call_groq(self, prompt: str) -> Optional[Dict]:
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
                resp = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers = headers,
                    json    = payload,
                    timeout = self.timeout,
                )
                if resp.status_code == 200:
                    text = resp.json()["choices"][0]["message"]["content"].strip()
                    if text.startswith("```"):
                        text = text.split("```")[1]
                        if text.startswith("json"):
                            text = text[4:]
                    parsed = json.loads(text.strip())
                    return parsed
                if resp.status_code == 429:
                    time.sleep(12 * (attempt + 1))
                    continue
                break
            except (json.JSONDecodeError, KeyError):
                break
            except Exception:
                if attempt < 2:
                    time.sleep(2 ** attempt)
        return None

    # ------------------------------------------------------------------
    # PDF section builders
    # ------------------------------------------------------------------

    def _pdf_cover(self, domain: str, narrative: Dict) -> List:
        s    = self._styles
        risk = narrative["owner_narrative"].get("risk_posture", {})
        elements = [
            Spacer(1, 0.5 * inch),
            Paragraph("ARTEX AI RED TEAM REPORT", s["title"]),
            Spacer(1, 0.3 * inch),
            Paragraph(f"Target: {domain}", s["subtitle"]),
            Spacer(1, 0.2 * inch),
            Paragraph(
                f"Generated: {narrative['report_metadata']['generated_at'][:19]}",
                s["meta"],
            ),
            Spacer(1, 0.4 * inch),
        ]

        risk_level = risk.get("level", "unknown").lower()
        risk_color = self._RISK_COLORS.get(risk_level, self._C_BLACK)

        cover_data = [
            [Paragraph("Risk Level",  s["th"]), Paragraph("Risk Score", s["th"]),
             Paragraph("Modules Read", s["th"]), Paragraph("Evidence Records", s["th"])],
            [
                Paragraph(risk.get("level","?").upper(), ParagraphStyle(
                    "RiskBadge", parent=s["td"],
                    textColor=risk_color, fontName="Courier-Bold",
                )),
                Paragraph(f"{risk.get('score',0)}/100", s["td"]),
                Paragraph(str(len(narrative["report_metadata"]["modules_read"])), s["td"]),
                Paragraph(str(narrative["report_metadata"]["total_evidence_records"]), s["td"]),
            ],
        ]
        t = Table(cover_data, colWidths=[1.5*inch]*4)
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), self._C_PRIMARY),
            ("TEXTCOLOR",   (0,0), (-1,0), self._C_WHITE),
            ("GRID",        (0,0), (-1,-1), 1, self._C_BLACK),
            ("BOX",         (0,0), (-1,-1), 2, self._C_BLACK),
            ("BACKGROUND",  (0,1), (-1,-1), self._C_BG),
            ("ALIGN",       (0,0), (-1,-1), "CENTER"),
            ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
            ("FONTSIZE",    (0,0), (-1,-1), 10),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph(
            "CONFIDENTIAL — Authorised Red Team Assessment. "
            "This document contains sensitive operational findings and evidence.",
            s["notice"],
        ))
        elements.append(PageBreak())
        return elements

    def _pdf_toc(self) -> List:
        s = self._styles
        toc_items = [
            ("1. Owner Perspective — Executive Findings",    "3"),
            ("2. Hunter Perspective — Offensive Analysis",   "5"),
            ("3. AI Operation Log — Evidence Chain",         "7"),
            ("4. Report Metadata",                           "10"),
        ]
        toc_data = [[Paragraph("Section", s["th"]), Paragraph("Page", s["th"])]]
        for label, pg in toc_items:
            toc_data.append([Paragraph(label, s["td"]), Paragraph(pg, s["td"])])

        t = Table(toc_data, colWidths=[4.5*inch, 0.5*inch])
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), self._C_PRIMARY),
            ("TEXTCOLOR",   (0,0), (-1,0), self._C_WHITE),
            ("GRID",        (0,0), (-1,-1), 1, self._C_BLACK),
            ("BOX",         (0,0), (-1,-1), 2, self._C_BLACK),
            ("BACKGROUND",  (0,1), (-1,-1), self._C_BG),
            ("FONTSIZE",    (0,0), (-1,-1), 10),
        ]))
        return [
            Paragraph("Table of Contents", self._styles["h1"]),
            Spacer(1, 0.2*inch),
            t,
            PageBreak(),
        ]

    def _pdf_owner_section(self, own: Dict) -> List:
        s = self._styles
        elements = [
            Paragraph("1. Owner Perspective — Executive Findings", s["h1"]),
            HRFlowable(width="100%", thickness=2, color=self._C_PRIMARY),
            Spacer(1, 0.2*inch),
            Paragraph("Executive Summary", s["h2"]),
            Paragraph(own.get("executive_summary", "N/A"), s["body"]),
            Spacer(1, 0.3*inch),
        ]

        # Risk posture
        risk = own.get("risk_posture", {})
        elements += [
            Paragraph("Risk Posture", s["h2"]),
            Paragraph(f"Level: {risk.get('level','?').upper()} | Score: {risk.get('score',0)}/100", s["body"]),
            Paragraph(risk.get("rationale",""), s["body"]),
            Spacer(1, 0.2*inch),
        ]

        # Top findings table
        findings = own.get("top_findings", [])
        if findings:
            elements.append(Paragraph("Top Findings", s["h2"]))
            tbl_data = [[
                Paragraph("Severity", s["th"]),
                Paragraph("Finding", s["th"]),
                Paragraph("Asset", s["th"]),
                Paragraph("Business Impact", s["th"]),
                Paragraph("Source", s["th"]),
            ]]
            for f in findings[:10]:
                sev = f.get("severity","?").lower()
                sev_color = self._RISK_COLORS.get(sev, self._C_BLACK)
                tbl_data.append([
                    Paragraph(f.get("severity","?").upper(), ParagraphStyle(
                        "SevCell", parent=s["td"], textColor=sev_color, fontName="Courier-Bold",
                    )),
                    Paragraph(f.get("title","")[:70], s["td"]),
                    Paragraph(f.get("asset","")[:40], s["td"]),
                    Paragraph(f.get("business_impact","")[:90], s["td"]),
                    Paragraph(f.get("evidence_ref","")[:30], s["td"]),
                ])
            t = Table(tbl_data, colWidths=[0.8*inch, 1.8*inch, 1.2*inch, 1.8*inch, 0.9*inch])
            t.setStyle(self._base_table_style())
            elements += [t, Spacer(1, 0.3*inch)]

        # Remediation roadmap
        roadmap = own.get("remediation_roadmap", [])
        if roadmap:
            elements.append(Paragraph("Remediation Roadmap", s["h2"]))
            for phase in roadmap:
                elements.append(Paragraph(f"Phase: {phase.get('phase','?')}", s["h3"]))
                for item in phase.get("items", []):
                    elements.append(Paragraph(f"  •  {item}", s["bullet"]))
            elements.append(Spacer(1, 0.2*inch))

        # Compliance notes
        notes = own.get("compliance_notes", [])
        if notes:
            elements.append(Paragraph("Compliance Notes", s["h2"]))
            for note in notes:
                elements.append(Paragraph(f"  •  {note}", s["bullet"]))

        elements.append(PageBreak())
        return elements

    def _pdf_hunter_section(self, hun: Dict) -> List:
        s = self._styles
        elements = [
            Paragraph("2. Hunter Perspective — Offensive Analysis", s["h1"]),
            HRFlowable(width="100%", thickness=2, color=self._C_ACCENT),
            Spacer(1, 0.2*inch),
            Paragraph("Threat Model", s["h2"]),
            Paragraph(hun.get("threat_model","N/A"), s["body"]),
            Spacer(1, 0.3*inch),
        ]

        # Critical attack paths
        paths = hun.get("critical_attack_paths", [])
        if paths:
            elements.append(Paragraph("Critical Attack Paths", s["h2"]))
            for path in paths:
                elements.append(Paragraph(
                    f"  {path.get('path_name','?')} "
                    f"[{path.get('severity','?').upper()}] — effort: {path.get('effort','?')}",
                    s["h3"],
                ))
                for step in path.get("steps", []):
                    elements.append(Paragraph(f"    → {step}", s["bullet"]))
                elements.append(Paragraph(
                    f"    Impact: {path.get('impact','')}", s["italic"]
                ))
                elements.append(Spacer(1, 0.1*inch))

        # Exploitation priority table
        ep = hun.get("exploitation_priority", [])
        if ep:
            elements.append(Paragraph("Exploitation Priority", s["h2"]))
            ep_data = [[
                Paragraph("#",          s["th"]),
                Paragraph("Target",     s["th"]),
                Paragraph("Technique",  s["th"]),
                Paragraph("Tool",       s["th"]),
                Paragraph("Est. Time",  s["th"]),
            ]]
            for item in ep[:8]:
                ep_data.append([
                    Paragraph(str(item.get("rank","?")), s["td"]),
                    Paragraph(item.get("target","")[:40],    s["td"]),
                    Paragraph(item.get("technique","")[:50], s["td"]),
                    Paragraph(item.get("tool","")[:30],      s["td"]),
                    Paragraph(item.get("estimated_time","?"), s["td"]),
                ])
            t = Table(ep_data, colWidths=[0.3*inch, 1.5*inch, 2.0*inch, 1.0*inch, 1.0*inch])
            t.setStyle(self._base_table_style())
            elements += [t, Spacer(1, 0.2*inch)]

        # MITRE ATT&CK TTP mapping
        ttps = hun.get("ttp_mapping", [])
        if ttps:
            elements.append(Paragraph("MITRE ATT&CK TTP Mapping", s["h2"]))
            ttp_data = [[
                Paragraph("ID",         s["th"]),
                Paragraph("Technique",  s["th"]),
                Paragraph("Tactic",     s["th"]),
                Paragraph("Evidence",   s["th"]),
            ]]
            for ttp in ttps[:12]:
                ttp_data.append([
                    Paragraph(ttp.get("technique_id","?"),    s["td"]),
                    Paragraph(ttp.get("technique_name","")[:50], s["td"]),
                    Paragraph(ttp.get("tactic","")[:30],      s["td"]),
                    Paragraph(ttp.get("evidence","")[:80],    s["td"]),
                ])
            t = Table(ttp_data, colWidths=[0.7*inch, 1.8*inch, 1.2*inch, 2.0*inch])
            t.setStyle(self._base_table_style())
            elements += [t, Spacer(1, 0.2*inch)]

        # Detection gaps
        gaps = hun.get("detection_gaps", [])
        if gaps:
            elements.append(Paragraph("Detection Gaps", s["h2"]))
            for gap in gaps:
                elements.append(Paragraph(f"  •  {gap}", s["bullet"]))

        # WAF evasion
        waf_guide = hun.get("waf_evasion_guide","")
        if waf_guide and "No WAF" not in waf_guide:
            elements += [
                Spacer(1, 0.2*inch),
                Paragraph("WAF Evasion Guide", s["h2"]),
                Paragraph(waf_guide, s["body"]),
            ]

        elements.append(PageBreak())
        return elements

    def _pdf_evidence_section(self, op_log: Dict) -> List:
        s = self._styles
        integrity_ok = op_log.get("integrity_ok", False)
        integrity_color = self._C_CHAIN_OK if integrity_ok else self._C_CHAIN_ERR
        integrity_text  = "✓ CHAIN INTEGRITY VERIFIED" if integrity_ok else "✗ CHAIN INTEGRITY BROKEN"

        elements = [
            Paragraph("3. AI Operation Log — Evidence Chain", s["h1"]),
            HRFlowable(width="100%", thickness=2, color=self._C_EVIDENCE),
            Spacer(1, 0.15*inch),
            Paragraph(
                f"Batch ID: {op_log.get('batch_id','?')} | "
                f"Target: {op_log.get('target','?')} | "
                f"Total Steps: {op_log.get('total_steps','?')}",
                s["body"],
            ),
            Paragraph(
                integrity_text,
                ParagraphStyle(
                    "IntegrityStatus", parent=s["body"],
                    textColor=integrity_color, fontName="Courier-Bold",
                ),
            ),
            Spacer(1, 0.2*inch),
            Paragraph(
                "Every AI-initiated action is recorded below with actual function calls, "
                "arguments, outputs, durations and a SHA-256 hash linking each record to "
                "the previous one. This log constitutes the evidentiary chain of custody "
                "confirming all operations remained within authorised scope.",
                s["notice"],
            ),
            Spacer(1, 0.3*inch),
        ]

        # Evidence table
        ev_hdr = [
            Paragraph("#",          s["th_ev"]),
            Paragraph("Agent",      s["th_ev"]),
            Paragraph("Action",     s["th_ev"]),
            Paragraph("Tool / Function", s["th_ev"]),
            Paragraph("Arguments (condensed)", s["th_ev"]),
            Paragraph("Duration / Exit", s["th_ev"]),
            Paragraph("Result Summary", s["th_ev"]),
            Paragraph("SHA-256 (prefix)", s["th_ev"]),
        ]
        ev_data = [ev_hdr]

        for rec in op_log.get("records", []):
            args_str = json.dumps(rec.get("arguments", {}), default=str)
            args_str = args_str[:60] + "…" if len(args_str) > 60 else args_str
            result_str = str(rec.get("result_summary",""))[:100]
            sha_prefix = rec.get("sha256","")[:20] + "…"

            ev_data.append([
                Paragraph(str(rec.get("sequence","?")), s["td_ev"]),
                Paragraph(rec.get("agent","")[:30],           s["td_ev"]),
                Paragraph(rec.get("action","")[:40],          s["td_ev"]),
                Paragraph(rec.get("tool_or_function","")[:45], s["td_ev"]),
                Paragraph(args_str,                           s["td_ev"]),
                Paragraph(
                    f"{rec.get('duration_s','?')}s / {rec.get('exit_code','?')}",
                    s["td_ev"],
                ),
                Paragraph(result_str, s["td_ev"]),
                Paragraph(sha_prefix, s["td_ev"]),
            ])

        t = Table(
            ev_data,
            colWidths=[0.3*inch, 1.0*inch, 1.0*inch, 1.0*inch,
                       1.1*inch, 0.6*inch, 1.3*inch, 1.0*inch],
            repeatRows=1,
        )
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), self._C_EVIDENCE),
            ("TEXTCOLOR",   (0,0), (-1,0), self._C_WHITE),
            ("GRID",        (0,0), (-1,-1), 0.5, self._C_BLACK),
            ("BOX",         (0,0), (-1,-1), 1.5, self._C_BLACK),
            ("BACKGROUND",  (0,1), (-1,-1), self._C_BG),
            ("FONTSIZE",    (0,0), (-1,-1), 7),
            ("LEADING",     (0,0), (-1,-1), 9),
            ("VALIGN",      (0,0), (-1,-1), "TOP"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [self._C_BG, colors.HexColor("#e8e8e8")]),
        ]))
        elements.append(t)
        elements.append(PageBreak())
        return elements

    def _pdf_metadata_section(self, meta: Dict) -> List:
        s = self._styles
        elements = [
            Paragraph("4. Report Metadata", s["h1"]),
            HRFlowable(width="100%", thickness=1, color=self._C_SECONDARY),
            Spacer(1, 0.15*inch),
        ]
        meta_data = [
            [Paragraph("Field", s["th"]), Paragraph("Value", s["th"])],
            [Paragraph("Generated At",          s["td"]), Paragraph(str(meta.get("generated_at","?")), s["td"])],
            [Paragraph("Domain",                s["td"]), Paragraph(meta.get("domain","?"),            s["td"])],
            [Paragraph("Batch ID",              s["td"]), Paragraph(meta.get("batch_id","?"),           s["td"])],
            [Paragraph("AI Model",              s["td"]), Paragraph(meta.get("groq_model_used","?"),    s["td"])],
            [Paragraph("Generation Time",       s["td"]), Paragraph(f"{meta.get('generation_duration_s','?')}s", s["td"])],
            [Paragraph("Evidence Records",      s["td"]), Paragraph(str(meta.get("total_evidence_records","?")), s["td"])],
            [Paragraph("Chain Integrity",       s["td"]), Paragraph(
                "VERIFIED" if meta.get("evidence_integrity") else "BROKEN", s["td"]
            )],
            [Paragraph("Modules Read",          s["td"]), Paragraph(
                ", ".join(meta.get("modules_read",[])), s["td"]
            )],
        ]
        t = Table(meta_data, colWidths=[2*inch, 4*inch])
        t.setStyle(self._base_table_style())
        elements += [
            t,
            Spacer(1, 0.3*inch),
            Paragraph(
                "This report was generated by ARTEX Autonomous AI Red Team Platform. "
                "All findings are based on evidence collected within the authorised assessment scope. "
                "The AI operation log in Section 3 provides a cryptographically chained record "
                "of every tool call, function invocation and AI inference performed during this assessment. "
                "Findings must be validated by a qualified human security professional before action.",
                s["notice"],
            ),
        ]
        return elements

    # ------------------------------------------------------------------
    # Style helpers
    # ------------------------------------------------------------------

    def _build_styles(self) -> Dict[str, ParagraphStyle]:
        base = getSampleStyleSheet()
        S    = {}

        def _make(name, parent="Normal", **kwargs) -> ParagraphStyle:
            return ParagraphStyle(name, parent=base[parent], **kwargs)

        S["title"]    = _make("NTitle",   "Title",   fontSize=20, fontName="Courier-Bold",
                               alignment=TA_CENTER, textColor=self._C_BLACK,
                               backColor=self._C_BG, borderWidth=2,
                               borderColor=self._C_BLACK, borderPadding=(5,5,5,5))
        S["subtitle"] = _make("NSubtitle","Normal",  fontSize=14, fontName="Courier-Bold",
                               alignment=TA_CENTER, textColor=self._C_SECONDARY)
        S["meta"]     = _make("NMeta",    "Normal",  fontSize=9,  fontName="Courier",
                               alignment=TA_CENTER, textColor=self._C_SECONDARY)
        S["h1"]       = _make("NH1",      "Heading1",fontSize=16, fontName="Courier-Bold",
                               textColor=self._C_BLACK, spaceAfter=6, spaceBefore=14)
        S["h2"]       = _make("NH2",      "Heading2",fontSize=12, fontName="Courier-Bold",
                               textColor=self._C_SECONDARY, spaceAfter=4, spaceBefore=10)
        S["h3"]       = _make("NH3",      "Normal",  fontSize=10, fontName="Courier-Bold",
                               textColor=self._C_SECONDARY, spaceAfter=2, spaceBefore=6)
        S["body"]     = _make("NBody",    "Normal",  fontSize=9,  fontName="Courier",
                               leading=13, spaceAfter=5, wordWrap="LTR")
        S["italic"]   = _make("NItalic",  "Normal",  fontSize=9,  fontName="Courier-Oblique",
                               textColor=self._C_SECONDARY, leading=13)
        S["bullet"]   = _make("NBullet",  "Normal",  fontSize=9,  fontName="Courier",
                               leading=12, leftIndent=12, spaceAfter=3)
        S["notice"]   = _make("NNotice",  "Normal",  fontSize=8,  fontName="Courier",
                               leading=11, alignment=TA_JUSTIFY, textColor=self._C_SECONDARY,
                               borderWidth=1, borderColor=self._C_SECONDARY,
                               borderPadding=(4,4,4,4), backColor=self._C_BG)
        S["th"]       = _make("NTH",      "Normal",  fontSize=9,  fontName="Courier-Bold",
                               textColor=self._C_WHITE, alignment=TA_CENTER, backColor=self._C_PRIMARY)
        S["td"]       = _make("NTD",      "Normal",  fontSize=8,  fontName="Courier",
                               leading=11, textColor=self._C_BLACK, wordWrap="LTR",
                               splitLongWords=True)
        S["th_ev"]    = _make("NTHev",    "Normal",  fontSize=7,  fontName="Courier-Bold",
                               textColor=self._C_WHITE, alignment=TA_CENTER, backColor=self._C_EVIDENCE)
        S["td_ev"]    = _make("NTDev",    "Normal",  fontSize=7,  fontName="Courier",
                               leading=9, textColor=self._C_BLACK, wordWrap="LTR",
                               splitLongWords=True)
        return S

    def _base_table_style(self) -> TableStyle:
        return TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), self._C_PRIMARY),
            ("TEXTCOLOR",   (0,0), (-1,0), self._C_WHITE),
            ("GRID",        (0,0), (-1,-1), 0.75, self._C_BLACK),
            ("BOX",         (0,0), (-1,-1), 1.5,  self._C_BLACK),
            ("BACKGROUND",  (0,1), (-1,-1), self._C_BG),
            ("FONTSIZE",    (0,0), (-1,-1), 8),
            ("LEADING",     (0,0), (-1,-1), 11),
            ("VALIGN",      (0,0), (-1,-1), "TOP"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [self._C_BG, colors.HexColor("#e8e8e8")]),
        ])

    # ------------------------------------------------------------------
    # Key summariser for evidence log
    # ------------------------------------------------------------------

    @staticmethod
    def _summarise_key(key: str, val: Any) -> str:
        try:
            if isinstance(val, list):
                return f"{key}: list with {len(val)} items"
            if isinstance(val, dict):
                return f"{key}: dict with keys {list(val.keys())[:6]}"
            return f"{key}: {str(val)[:80]}"
        except Exception:
            return f"{key}: unreadable"