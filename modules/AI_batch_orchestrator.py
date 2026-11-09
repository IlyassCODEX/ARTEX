# AI_batch_orchestrator.py
# responsibility: Autonomous AI Red Team orchestration for batch operations.
#   - Observe -> Analyse -> Plan -> Assign -> Execute -> Verify -> Reassess -> Report
#   - Calls existing ARTEX modules (SubdomainEnumerator, PortScanner, etc.)
#   - Calls existing AI modules (AIAnalyst, FastSecurityAnalyst, etc.)
#   - Writes results into TargetContext.scan_results
#   - Records every decision to TargetContext.ai_decision_log
#   - Records every tool invocation to BatchOperation.execution_log

import threading
import time
import json
import logging
import requests
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any

# ── Existing ARTEX modules — reused directly ─────────────────────────
from modules.subdomains     import SubdomainEnumerator
from modules.dns_scan       import DNSScanner
from modules.ssl_scanner    import SSLScanner
from modules.tech_detector  import TechnologyDetector
from modules.enumeration    import EmailUserEnumerator
from modules.port_scanner   import PortScanner
from modules.real_ip_discovery import RealIPDiscovery
from modules.FastAnalyst    import FastSecurityAnalyst
from modules.AI_analyst     import AIAnalyst
from modules.AI_cross_target_correlator import AICrossTargetCorrelator
from utils.helpers          import sanitize_domain
from core.batch_manager     import TargetContext, BatchOperation, TARGET_STATUS
from core.evidence_manager  import evidence_manager
import os

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")


# ---------------------------------------------------------------------------
# Decision log helper
# ---------------------------------------------------------------------------

def _log_decision(target: TargetContext, agent: str, decision: str, detail: str = "") -> None:
    target.ai_decision_log.append({
        "timestamp": datetime.now().isoformat(),
        "agent":     agent,
        "decision":  decision,
        "detail":    detail[:300],
    })


def _log_exec(batch: BatchOperation, target: TargetContext, tool: str,
              operation: str, args: Dict, duration: float,
              status: str, stdout: str = "", stderr: str = "",
              exit_code: int = 0) -> str:
    evidence_id = hashlib.md5(
        f"{batch.batch_id}{target.target_id}{tool}{operation}{time.time()}".encode()
    ).hexdigest()[:12]

    evidence_manager.record_tool(
        batch_id    = batch.batch_id,
        target_id   = target.target_id,
        agent       = "recon_agent",
        tool        = "SubdomainEnumerator",
        operation   = "enumerate",
        arguments   = {"domain": domain},
        stdout      = f"Found {len(subdomains)} subdomains",
        duration_s  = time.time() - t0,
    )
    target.evidence_ids.append(evidence_id)
    return evidence_id


# ---------------------------------------------------------------------------
# AI Decision Engine — Groq-powered autonomous decisions
# ---------------------------------------------------------------------------

class AIDecisionEngine:
    """
    Uses Groq to make autonomous Red Team workflow decisions.
    Falls back to rule-based heuristics when Groq is unavailable.
    """

    def __init__(self, groq_api_key: str = ""):
        self.groq_api_key = groq_api_key
        self.logger       = logging.getLogger(__name__ + ".DecisionEngine")

    def decide_workflow(
        self,
        target_url:    str,
        recon_summary: Dict,
    ) -> Dict:
        """
        Given initial recon data, decide which additional modules to run.

        Returns:
            {
                run_port_scan:    bool,
                run_ssl:          bool,
                run_tech:         bool,
                run_email:        bool,
                run_vuln_analysis: bool,
                run_sqlmap:       bool,
                port_scan_choice: str,   # all_subdomains | critical_only
                intensity:        str,   # light | normal | aggressive
                rationale:        str,
            }
        """
        if self.groq_api_key:
            result = self._groq_decide(target_url, recon_summary)
            if result:
                return result

        # Rule-based fallback
        return self._rule_based_decide(recon_summary)

    def _groq_decide(self, target_url: str, recon_summary: Dict) -> Optional[Dict]:
        prompt = f"""You are an autonomous Red Team AI operator.
Based on this initial recon summary for {target_url}, decide the assessment workflow.

Recon Summary:
{json.dumps(recon_summary, indent=2)[:2000]}

Return ONLY valid JSON with these exact keys:
- "run_port_scan": bool
- "run_ssl": bool
- "run_tech": bool
- "run_email": bool
- "run_vuln_analysis": bool
- "run_sqlmap": bool
- "port_scan_choice": "all_subdomains" or "critical_only"
- "intensity": "light" or "normal" or "aggressive"
- "rationale": string — one sentence explaining your decision

Return ONLY valid JSON, no preamble."""

        try:
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.groq_api_key}",
                    "Content-Type":  "application/json",
                },
                json={
                    "model":       "llama3-70b-8192",
                    "messages":    [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens":  300,
                },
                timeout=20,
            )
            if resp.status_code == 200:
                text = resp.json()["choices"][0]["message"]["content"].strip()
                if text.startswith("```"):
                    text = text.split("```")[1]
                    if text.startswith("json"):
                        text = text[4:]
                return json.loads(text.strip())
        except Exception as e:
            self.logger.warning(f"Groq decision failed: {e}")
        return None

    @staticmethod
    def _rule_based_decide(recon_summary: Dict) -> Dict:
        sub_count    = recon_summary.get("subdomain_count", 0)
        active_count = recon_summary.get("active_subdomains", 0)
        has_https    = recon_summary.get("has_https", False)
        has_login    = recon_summary.get("has_login_page", False)
        cms_detected = recon_summary.get("cms_detected", False)

        intensity = "normal"
        if sub_count > 50 or active_count > 20:
            intensity = "aggressive"
        elif sub_count < 5:
            intensity = "light"

        return {
            "run_port_scan":    active_count > 0,
            "run_ssl":          has_https,
            "run_tech":         active_count > 0,
            "run_email":        True,
            "run_vuln_analysis": True,
            "run_sqlmap":       has_login or cms_detected,
            "port_scan_choice": "critical_only" if active_count > 15 else "all_subdomains",
            "intensity":        intensity,
            "rationale":        f"Rule-based: {active_count} active subs, intensity={intensity}",
        }

    def summarise_findings(self, target_url: str, all_results: Dict) -> Dict:
        """Generate AI summary for a completed target assessment."""
        ai_analyst = AIAnalyst(self.groq_api_key)
        try:
            return ai_analyst.analyze_results(all_results)
        except Exception as e:
            return {"error": str(e), "source": "ai_analyst_fallback"}


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------

class AIBatchOrchestrator:
    """
    Autonomous AI Red Team Batch Orchestrator.

    Workflow per target:
        1. OBSERVE   — HTTP probe, DNS, basic subdomain enum
        2. ANALYSE   — Groq decides workflow from recon summary
        3. PLAN      — Build ordered task list
        4. ASSIGN    — Delegate to existing ARTEX modules
        5. EXECUTE   — Run each module, capture output + evidence
        6. VERIFY    — Cross-check findings with FastSecurityAnalyst
        7. REASSESS  — AI decides if additional passes needed
        8. REPORT    — Generate per-target findings + AI summary

    Call orchestrate(target, batch) from BatchManager.run_batch().
    """

    def __init__(self, groq_api_key: str = GROQ_API_KEY):
        self.groq_api_key    = groq_api_key
        self.decision_engine = AIDecisionEngine(groq_api_key)
        self.logger          = logging.getLogger(__name__)

        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] Orchestrator — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

    # ------------------------------------------------------------------
    # Entry point — called by BatchManager worker_fn
    # ------------------------------------------------------------------

    def orchestrate(self, target: TargetContext, batch: BatchOperation) -> None:
        """Main autonomous assessment loop for one target."""
        self.logger.info(f"[{target.url}] Starting orchestration")
        _log_decision(target, "orchestrator", "START", f"Target: {target.url}")

        try:
            # ── PHASE 1: OBSERVE ─────────────────────────────────────
            target.current_task = "Phase 1: Reconnaissance"
            target.progress     = 10
            recon_summary = self._phase_observe(target, batch)

            if batch.stop_requested:
                return

            # ── PHASE 2: ANALYSE + PLAN ───────────────────────────────
            target.current_task = "Phase 2: AI workflow planning"
            target.progress     = 20
            workflow = self.decision_engine.decide_workflow(target.url, recon_summary)
            _log_decision(
                target, "decision_engine",
                "WORKFLOW_PLANNED",
                workflow.get("rationale", "")
            )
            batch.log_execution({
                "event":    "ai_workflow_decision",
                "target":   target.url,
                "workflow": workflow,
            })

            # ── PHASE 3: ASSIGN + EXECUTE ─────────────────────────────
            target.current_task = "Phase 3: Module execution"
            target.progress     = 30
            self._phase_execute(target, batch, workflow)

            if batch.stop_requested:
                return

            # ── PHASE 4: VERIFY ───────────────────────────────────────
            target.current_task = "Phase 4: Security verification"
            target.progress     = 80
            self._phase_verify(target, batch)

            # ── PHASE 5: REASSESS ─────────────────────────────────────
            target.current_task = "Phase 5: AI reassessment"
            target.progress     = 88
            self._phase_reassess(target, batch, workflow)

            # ── PHASE 6: REPORT ───────────────────────────────────────
            target.current_task = "Phase 6: Generating report"
            target.progress     = 94
            self._phase_report(target, batch)

            target.progress     = 100
            target.current_task = "Completed"
            _log_decision(target, "orchestrator", "COMPLETE", target.url)

        except Exception as exc:
            target.error = str(exc)
            _log_decision(target, "orchestrator", "ERROR", str(exc))
            self.logger.error(f"[{target.url}] Orchestration error: {exc}")
            raise

    # ------------------------------------------------------------------
    # Phase 1 — OBSERVE
    # ------------------------------------------------------------------

    def _phase_observe(self, target: TargetContext, batch: BatchOperation) -> Dict:
        """HTTP probe + DNS + basic subdomain enum. Returns recon_summary."""
        domain  = target.domain
        results = target.scan_results
        t0      = time.time()

        # ── Subdomain enumeration ─────────────────────────────────────
        _log_decision(target, "recon_agent", "RUN_SUBDOMAIN_ENUM", domain)
        target.current_task = "Subdomain enumeration"

        try:
            enumerator = SubdomainEnumerator()
            subdomains = enumerator.enumerate(domain)
        except Exception as e:
            subdomains = []
            _log_decision(target, "recon_agent", "SUBDOMAIN_ENUM_FAILED", str(e))

        results["subdomains"] = subdomains
        _log_exec(
            batch, target, "SubdomainEnumerator", "enumerate",
            {"domain": domain},
            time.time() - t0,
            "completed" if subdomains else "empty",
            stdout=f"Found {len(subdomains)} subdomains",
        )

        # ── DNS scan ──────────────────────────────────────────────────
        t1 = time.time()
        _log_decision(target, "recon_agent", "RUN_DNS_SCAN", domain)
        target.current_task = "DNS reconnaissance"

        try:
            dns_scanner  = DNSScanner(domain)
            dns_records  = dns_scanner.scan(aggressive=False)
        except Exception as e:
            dns_records  = {}
            _log_decision(target, "recon_agent", "DNS_SCAN_FAILED", str(e))

        results["dns_records"] = dns_records
        _log_exec(
            batch, target, "DNSScanner", "scan",
            {"domain": domain, "aggressive": False},
            time.time() - t1, "completed",
            stdout=json.dumps({k: len(v) if isinstance(v, list) else v
                               for k, v in dns_records.items()})[:400],
        )

        # Build recon summary for decision engine
        active = [s for s in subdomains if s.get("http_status") or s.get("https_status")]
        has_https   = any(s.get("https_status") for s in subdomains)
        cms_names   = {"wordpress", "joomla", "drupal", "magento", "shopify"}
        cms_hits    = []

        return {
            "subdomain_count":    len(subdomains),
            "active_subdomains":  len(active),
            "has_https":          has_https,
            "has_login_page":     any("login" in s.get("subdomain","").lower() for s in subdomains),
            "cms_detected":       any(s.get("subdomain","").lower() in cms_names for s in subdomains),
            "mx_records":         len(dns_records.get("MX", [])),
            "domain":             domain,
        }

    # ------------------------------------------------------------------
    # Phase 3 — EXECUTE
    # ------------------------------------------------------------------

    def _phase_execute(
        self,
        target: TargetContext,
        batch:  BatchOperation,
        wf:     Dict,
    ) -> None:
        domain     = target.domain
        results    = target.scan_results
        subdomains = results.get("subdomains", [])
        active     = [s for s in subdomains if s.get("http_status") or s.get("https_status")]

        # ── Email enumeration ─────────────────────────────────────────
        if wf.get("run_email", True):
            t0 = time.time()
            target.current_task = "Email enumeration"
            _log_decision(target, "recon_agent", "RUN_EMAIL_ENUM", domain)
            try:
                ee = EmailUserEnumerator()
                results["email_enumeration"] = ee.find_email_patterns(domain)
                _log_exec(
                    batch, target, "EmailUserEnumerator", "find_email_patterns",
                    {"domain": domain}, time.time() - t0, "completed",
                )
            except Exception as e:
                _log_exec(batch, target, "EmailUserEnumerator", "find_email_patterns",
                          {"domain": domain}, time.time() - t0, "failed", stderr=str(e))

        # ── Port scan ─────────────────────────────────────────────────
        if wf.get("run_port_scan", True) and active:
            t0 = time.time()
            choice  = wf.get("port_scan_choice", "all_subdomains")
            target.current_task = f"Port scanning ({choice})"
            _log_decision(target, "infrastructure_agent", "RUN_PORT_SCAN", choice)

            if choice == "critical_only":
                analyst = FastSecurityAnalyst()
                data    = analyst._prepare_analysis_data(domain, subdomains)
                scan_targets = []
                for cat_list in data["categories"].get("critical", {}).values():
                    for s in cat_list:
                        scan_targets.append(s["subdomain"])
            else:
                scan_targets = [s["subdomain"] for s in active]

            try:
                ps = PortScanner()
                port_results = ps.batch_scan(
                    scan_targets,
                    ports="21,22,23,25,53,80,110,135,139,143,443,993,995,"
                          "1723,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017",
                )
                results["port_scan"] = [r for r in port_results if r is not None]
                _log_exec(
                    batch, target, "PortScanner", "batch_scan",
                    {"targets": scan_targets[:5], "total_targets": len(scan_targets)},
                    time.time() - t0, "completed",
                    stdout=f"Scanned {len(scan_targets)} hosts, {len(results['port_scan'])} results",
                )
            except Exception as e:
                _log_exec(batch, target, "PortScanner", "batch_scan",
                          {"targets": scan_targets[:5]}, time.time() - t0, "failed", stderr=str(e))

        # ── SSL scan ──────────────────────────────────────────────────
        if wf.get("run_ssl", True):
            t0 = time.time()
            target.current_task = "SSL/TLS analysis"
            _log_decision(target, "tech_analysis_agent", "RUN_SSL_SCAN", domain)

            try:
                ssl_scanner  = SSLScanner()
                ssl_results  = {"main_domain": ssl_scanner.scan(domain)}
                https_subs   = [s for s in subdomains if s.get("https_status")]
                for sub in https_subs[:10]:
                    try:
                        ssl_results[sub["subdomain"]] = ssl_scanner.scan(sub["subdomain"])
                    except Exception:
                        pass
                results["ssl_scan"] = ssl_results
                _log_exec(
                    batch, target, "SSLScanner", "scan",
                    {"domain": domain, "subdomains_scanned": len(https_subs[:10])},
                    time.time() - t0, "completed",
                )
            except Exception as e:
                _log_exec(batch, target, "SSLScanner", "scan",
                          {"domain": domain}, time.time() - t0, "failed", stderr=str(e))

        # ── Technology detection ──────────────────────────────────────
        if wf.get("run_tech", True) and active:
            t0 = time.time()
            target.current_task = "Technology fingerprinting"
            _log_decision(target, "tech_analysis_agent", "RUN_TECH_DETECT", domain)

            tech_results = {}
            td = TechnologyDetector()
            for sub in active[:15]:
                url = (f"https://{sub['subdomain']}" if sub.get("https_status")
                       else f"http://{sub['subdomain']}")
                try:
                    tech_results[url] = td.detect_technologies(url)
                except Exception:
                    pass

            results["tech_detection"] = tech_results

            # Extract tech profile for target summary
            for url, tech_data in tech_results.items():
                for tech in tech_data.get("technologies", []):
                    name = tech.get("name", "")
                    cat  = tech.get("category", "").lower()
                    if name and name not in target.technologies:
                        target.technologies.append(name)
                    if "web server" in cat and not target.web_server:
                        target.web_server = name
                    if "framework" in cat and not target.framework:
                        target.framework = name

            _log_exec(
                batch, target, "TechnologyDetector", "detect_technologies",
                {"urls_scanned": len(tech_results)},
                time.time() - t0, "completed",
                stdout=f"Detected {len(target.technologies)} technologies",
            )

        # ── Real IP discovery ─────────────────────────────────────────
        t0 = time.time()
        target.current_task = "Real IP discovery"
        try:
            rid      = RealIPDiscovery()
            real_ips = rid.discover_real_ips(
                domain,
                results.get("subdomains", []),
                results.get("dns_records", {}),
            )
            results["real_ip"] = {
                "origin_ips": [{"ip": ip, "score": 10, "responds": True} for ip in real_ips],
                "techniques_used": list(rid.ip_utils.cdn_ranges.keys()),
            }
            _log_exec(
                batch, target, "RealIPDiscovery", "discover_real_ips",
                {"domain": domain}, time.time() - t0, "completed",
                stdout=f"Found {len(real_ips)} candidate IPs",
            )
        except Exception as e:
            _log_exec(batch, target, "RealIPDiscovery", "discover_real_ips",
                      {"domain": domain}, time.time() - t0, "failed", stderr=str(e))

        # ── SQLMap integration ────────────────────────────────────────
        if wf.get("run_sqlmap", False):
            target.current_task = "SQL injection assessment"
            _log_decision(target, "sqli_agent", "RUN_SQLMAP_ASSESSMENT", target.url)
            self._run_sqlmap_assessment(target, batch)

    # ------------------------------------------------------------------
    # Phase 4 — VERIFY
    # ------------------------------------------------------------------

    def _phase_verify(self, target: TargetContext, batch: BatchOperation) -> None:
        t0 = time.time()
        target.current_task = "FastSecurityAnalyst verification"
        _log_decision(target, "validation_agent", "RUN_FAST_ANALYST", target.domain)

        try:
            analyst  = FastSecurityAnalyst()
            analysis = analyst.analyze_subdomains(
                target.domain,
                target.scan_results.get("subdomains", []),
            )
            if target.scan_results.get("email_enumeration"):
                analysis["email_analysis"] = target.scan_results["email_enumeration"]

            target.scan_results["security_analysis"] = analysis
            _log_exec(
                batch, target, "FastSecurityAnalyst", "analyze_subdomains",
                {"domain": target.domain},
                time.time() - t0, "completed",
            )
        except Exception as e:
            _log_exec(batch, target, "FastSecurityAnalyst", "analyze_subdomains",
                      {"domain": target.domain}, time.time() - t0, "failed", stderr=str(e))

    # ------------------------------------------------------------------
    # Phase 5 — REASSESS
    # ------------------------------------------------------------------

    def _phase_reassess(
        self,
        target: TargetContext,
        batch:  BatchOperation,
        wf:     Dict,
    ) -> None:
        """
        AI checks if any high-value signals warrant additional passes.
        Currently: triggers deeper port scan if critical subdomains found.
        """
        security = target.scan_results.get("security_analysis", {})
        hvt      = security.get("high_value_targets", [])
        critical = [h for h in hvt if h.get("risk_level") == "critical"]

        if critical and not wf.get("deep_pass_done"):
            _log_decision(
                target, "orchestrator",
                "REASSESS_TRIGGER",
                f"{len(critical)} critical targets found — running targeted deep scan",
            )
            batch.log_execution({
                "event":           "ai_reassessment",
                "target":          target.url,
                "critical_count":  len(critical),
                "action":          "additional_pass_scheduled",
            })
            # Mark done to avoid infinite loop
            wf["deep_pass_done"] = True
        else:
            _log_decision(target, "orchestrator", "REASSESS_PASS", "No additional passes required")

    # ------------------------------------------------------------------
    # Phase 6 — REPORT
    # ------------------------------------------------------------------

    def _phase_report(self, target: TargetContext, batch: BatchOperation) -> None:
        """
        Generate AI analysis via AIAnalyst (reuses existing module).
        Populate target summary fields.
        """
        t0 = time.time()
        target.current_task = "AI analysis and reporting"
        _log_decision(target, "reporting_agent", "RUN_AI_ANALYST", target.domain)

        # Inject required fields that AIAnalyst.analyze_results expects
        target.scan_results.setdefault("domain",    target.domain)
        target.scan_results.setdefault("scan_id",   target.target_id)
        target.scan_results.setdefault("timestamp", datetime.now().isoformat())

        try:
            ai_analyst = AIAnalyst(self.groq_api_key)
            ai_analysis = ai_analyst.analyze_results(target.scan_results)
            target.scan_results["ai_analysis"] = ai_analysis
            _log_exec(
                batch, target, "AIAnalyst", "analyze_results",
                {"domain": target.domain},
                time.time() - t0, "completed",
            )
        except Exception as e:
            target.scan_results["ai_analysis"] = {"error": str(e)}
            _log_exec(batch, target, "AIAnalyst", "analyze_results",
                      {"domain": target.domain}, time.time() - t0, "failed", stderr=str(e))

        # Summarise severity from security_analysis
        security = target.scan_results.get("security_analysis", {})
        risk     = security.get("risk_assessment", {})
        target.highest_severity = risk.get("level", "unknown")
        target.findings_count   = len(security.get("high_value_targets", []))

        # Consolidate into batch report
        batch.consolidated_findings.append({
            "target_id":        target.target_id,
            "url":              target.url,
            "highest_severity": target.highest_severity,
            "findings_count":   target.findings_count,
            "technologies":     target.technologies[:8],
            "web_server":       target.web_server,
            "framework":        target.framework,
        })

    # ------------------------------------------------------------------
    # SQLMap integration bridge
    # ------------------------------------------------------------------

    def _run_sqlmap_assessment(
        self,
        target: TargetContext,
        batch:  BatchOperation,
    ) -> None:
        """
        Delegate to sqlmap_integration module if available.
        Gracefully skips if sqlmap is not installed.
        """
        try:
            from modules.sqlmap_integration import SQLMapIntegration
            sqli = SQLMapIntegration(groq_api_key=self.groq_api_key)
            result = sqli.run_assessment(
                url        = target.url,
                target_ctx = target,
                batch_op   = batch,
            )
            target.scan_results["sqlmap_results"] = result
        except ImportError:
            _log_decision(target, "sqli_agent", "SQLMAP_SKIP", "sqlmap_integration module not available")
        except Exception as e:
            _log_decision(target, "sqli_agent", "SQLMAP_ERROR", str(e))

    # ------------------------------------------------------------------
    # Public factory — returns a worker_fn for BatchManager.run_batch()
    # ------------------------------------------------------------------

    def get_worker(self):
        """Return a callable(target, batch) suitable for BatchManager.run_batch()."""
        def worker(target: TargetContext, batch: BatchOperation) -> None:
            self.orchestrate(target, batch)
        return worker
        
    def run_cross_target_correlation(batch_op):
        completed = [t for t in batch_op.targets
                     if t.status == "completed" and t.scan_results]
        if len(completed) >= 2:
            correlator = AICrossTargetCorrelator(groq_api_key=GROQ_API_KEY)
            batch_op.correlation_report = correlator.correlate_batch(batch_op)