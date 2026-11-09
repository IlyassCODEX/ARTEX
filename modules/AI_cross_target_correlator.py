# AI_cross_target_correlator.py
import json
import hashlib
import logging
import time
import requests
import re
import ipaddress
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any
from itertools import combinations


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GROQ_API_KEY = __import__("os").getenv("GROQ_API_KEY", "")

# Minimum number of targets that must share something for it to be "common"
COMMONALITY_THRESHOLD = 2

# Pivot probability weights — how likely is it to pivot from T1 to T2
# given shared asset type
PIVOT_WEIGHT = {
    "shared_ip":           0.90,
    "shared_hosting_org":  0.75,
    "shared_cdn":          0.60,
    "shared_ns":           0.80,
    "credential_reuse":    0.85,
    "shared_tech_stack":   0.55,
    "shared_vuln_class":   0.70,
    "shared_email_domain": 0.65,
    "network_adjacency":   0.80,
}

# Severity numeric weight for scoring
SEV_WEIGHT = {
    "critical": 10,
    "high":      7,
    "medium":    4,
    "low":       2,
    "info":      1,
    "unknown":   0,
}

# Private IP ranges — shared private IPs are not interesting correlation signals
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def _is_private(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Correlation graph node types
# ---------------------------------------------------------------------------

NODE_ASSET    = "asset"       # a URL / domain
NODE_IP       = "ip"          # an IP address
NODE_INFRA    = "infra"       # hosting org / ASN / CDN
NODE_TECH     = "tech"        # technology (nginx, PHP, WordPress…)
NODE_VULN     = "vuln"        # vulnerability class (sqli, xss…)
NODE_CRED     = "cred"        # credential leak signal
NODE_EMAIL    = "email_domain"  # email domain (@corp.com)
NODE_NS       = "nameserver"  # nameserver
NODE_MX       = "mx"          # mail exchanger

EDGE_SHARES     = "shares"
EDGE_HOSTED_ON  = "hosted_on"
EDGE_USES       = "uses"
EDGE_VULNERABLE = "vulnerable_to"
EDGE_PIVOT      = "can_pivot_to"
EDGE_EXPOSES    = "exposes"


# ---------------------------------------------------------------------------
# Lightweight graph
# ---------------------------------------------------------------------------

class CorrelationGraph:
    """
    Directed multigraph for cross-target correlation.
    Nodes and edges carry metadata dicts.
    Supports:
        - Add / merge nodes (merge increments a 'count' field)
        - Add edges with probability and evidence
        - Enumerate paths between node types
        - Export to dict for JSON / Groq prompt
    """

    def __init__(self):
        self._nodes: Dict[str, Dict]              = {}
        self._edges: List[Dict]                   = []
        self._adj:   Dict[str, List[str]]         = defaultdict(list)
        self._radj:  Dict[str, List[str]]         = defaultdict(list)

    # ── Node management ───────────────────────────────────────────────

    def _node_id(self, node_type: str, label: str) -> str:
        raw = f"{node_type}::{label.lower().strip()}"
        return hashlib.md5(raw.encode()).hexdigest()[:14]

    def add_node(
        self,
        node_type: str,
        label:     str,
        metadata:  Optional[Dict] = None,
    ) -> str:
        nid = self._node_id(node_type, label)
        if nid in self._nodes:
            self._nodes[nid]["count"] = self._nodes[nid].get("count", 1) + 1
            if metadata:
                # Merge sets / lists in metadata
                for k, v in metadata.items():
                    existing = self._nodes[nid].get(k)
                    if isinstance(existing, list) and isinstance(v, list):
                        combined = existing + [x for x in v if x not in existing]
                        self._nodes[nid][k] = combined[:50]
                    elif existing is None:
                        self._nodes[nid][k] = v
        else:
            self._nodes[nid] = {
                "node_id":   nid,
                "node_type": node_type,
                "label":     label,
                "count":     1,
                **(metadata or {}),
            }
        return nid

    def get_node(self, node_type: str, label: str) -> Optional[Dict]:
        nid = self._node_id(node_type, label)
        return self._nodes.get(nid)

    def nodes_by_type(self, node_type: str) -> List[Dict]:
        return [n for n in self._nodes.values() if n["node_type"] == node_type]

    # ── Edge management ───────────────────────────────────────────────

    def add_edge(
        self,
        src_type:    str,
        src_label:   str,
        dst_type:    str,
        dst_label:   str,
        edge_type:   str,
        probability: float = 1.0,
        evidence:    Optional[List[str]] = None,
        metadata:    Optional[Dict] = None,
    ) -> str:
        src_id  = self._node_id(src_type, src_label)
        dst_id  = self._node_id(dst_type, dst_label)
        edge_id = hashlib.md5(
            f"{src_id}|{dst_id}|{edge_type}".encode()
        ).hexdigest()[:12]

        # Update probability and evidence on duplicate edge
        for existing in self._edges:
            if existing["edge_id"] == edge_id:
                existing["probability"] = max(existing["probability"], probability)
                existing["evidence"] = list(
                    set(existing.get("evidence", []) + (evidence or []))
                )[:20]
                return edge_id

        edge = {
            "edge_id":    edge_id,
            "src_id":     src_id,
            "dst_id":     dst_id,
            "src_label":  src_label,
            "dst_label":  dst_label,
            "edge_type":  edge_type,
            "probability": round(probability, 3),
            "evidence":   evidence or [],
            **(metadata or {}),
        }
        self._edges.append(edge)
        self._adj[src_id].append(dst_id)
        self._radj[dst_id].append(src_id)
        return edge_id

    def edges_between(self, src_type: str, src_label: str,
                      dst_type: str, dst_label: str) -> List[Dict]:
        s = self._node_id(src_type, src_label)
        d = self._node_id(dst_type, dst_label)
        return [e for e in self._edges if e["src_id"] == s and e["dst_id"] == d]

    def neighbours(self, node_type: str, label: str) -> List[Dict]:
        nid = self._node_id(node_type, label)
        result = []
        for neighbour_id in self._adj.get(nid, []):
            if neighbour_id in self._nodes:
                result.append(self._nodes[neighbour_id])
        return result

    # ── BFS pivot path search ─────────────────────────────────────────

    def pivot_paths(
        self,
        src_type:  str,
        src_label: str,
        dst_type:  str,
        dst_label: str,
        max_depth: int = 5,
    ) -> List[List[Dict]]:
        """BFS — find all simple paths from src to dst up to max_depth hops."""
        from collections import deque
        s   = self._node_id(src_type, src_label)
        d   = self._node_id(dst_type, dst_label)
        all_paths: List[List[str]] = []
        queue = deque([(s, [s])])

        while queue:
            cur, path = queue.popleft()
            if len(path) > max_depth:
                continue
            for nxt in self._adj.get(cur, []):
                if nxt in path:
                    continue
                new_path = path + [nxt]
                if nxt == d:
                    all_paths.append(new_path)
                else:
                    queue.append((nxt, new_path))

        # Convert node_id paths → node dicts
        return [
            [self._nodes[nid] for nid in path if nid in self._nodes]
            for path in all_paths
        ]

    # ── Stats ─────────────────────────────────────────────────────────

    def stats(self) -> Dict:
        edge_types: Dict[str, int] = defaultdict(int)
        node_types: Dict[str, int] = defaultdict(int)
        for e in self._edges:
            edge_types[e["edge_type"]] += 1
        for n in self._nodes.values():
            node_types[n["node_type"]] += 1
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "nodes_by_type": dict(node_types),
            "edges_by_type": dict(edge_types),
        }

    def to_dict(self) -> Dict:
        return {
            "nodes": list(self._nodes.values()),
            "edges": self._edges,
            "stats": self.stats(),
        }


# ---------------------------------------------------------------------------
# Shared asset extractors — read confirmed scan_results keys
# ---------------------------------------------------------------------------

class _Extractor:
    """
    Static methods that read confirmed scan_results schemas and
    return structured dicts for correlation.
    """

    @staticmethod
    def ips(scan_results: Dict) -> Set[str]:
        """Extract all IP addresses seen for this target."""
        ips: Set[str] = set()

        # From subdomains
        for sub in scan_results.get("subdomains", []):
            ip = sub.get("ip", "")
            if ip and not _is_private(ip):
                ips.add(ip)

        # From real_ip discovery
        for entry in scan_results.get("real_ip", {}).get("origin_ips", []):
            ip = entry.get("ip", "")
            if ip and not _is_private(ip):
                ips.add(ip)

        # From dns_records A
        for ip in scan_results.get("dns_records", {}).get("A", []):
            if isinstance(ip, str) and ip and not _is_private(ip):
                ips.add(ip)

        # From port_scan targets
        for host_data in scan_results.get("port_scan", []):
            tgt = host_data.get("target", "")
            # Only add if it looks like an IP
            try:
                ipaddress.ip_address(tgt)
                if not _is_private(tgt):
                    ips.add(tgt)
            except ValueError:
                pass

        # From osint_correlation if present
        osint = scan_results.get("osint_correlation", {})
        for ip_entry in osint.get("infrastructure", {}).get("all_ips", []):
            ip = ip_entry.get("ip", "")
            if ip and not _is_private(ip):
                ips.add(ip)

        return ips

    @staticmethod
    def technologies(scan_results: Dict) -> Set[str]:
        """Extract all technology names (lowercase)."""
        techs: Set[str] = set()
        for url, tech_data in scan_results.get("tech_detection", {}).items():
            if not isinstance(tech_data, dict):
                continue
            for t in tech_data.get("technologies", []):
                name = t.get("name", "").strip().lower()
                if name and len(name) > 1:
                    techs.add(name)
        return techs

    @staticmethod
    def nameservers(scan_results: Dict) -> Set[str]:
        """Extract NS records (lowercase, trailing dot removed)."""
        ns_set: Set[str] = set()
        for ns in scan_results.get("dns_records", {}).get("NS", []):
            ns_str = str(ns).lower().rstrip(".")
            if ns_str:
                ns_set.add(ns_str)
        return ns_set

    @staticmethod
    def mx_records(scan_results: Dict) -> Set[str]:
        """Extract MX records."""
        mx_set: Set[str] = set()
        for mx in scan_results.get("dns_records", {}).get("MX", []):
            mx_str = str(mx).lower().rstrip(".")
            # Strip priority number if present
            parts = mx_str.split()
            mx_host = parts[-1] if parts else mx_str
            if mx_host:
                mx_set.add(mx_host)
        return mx_set

    @staticmethod
    def risky_ports(scan_results: Dict) -> Set[int]:
        """Extract all risky open port numbers across all scanned hosts."""
        ports: Set[int] = set()
        for host_data in scan_results.get("port_scan", []):
            for rp in host_data.get("risky_ports", []):
                port = rp.get("port")
                if port:
                    ports.add(int(port))
        return ports

    @staticmethod
    def ssl_vulns(scan_results: Dict) -> Set[str]:
        """Extract confirmed SSL/TLS CVE names."""
        vulns: Set[str] = set()
        for host, ssl_data in scan_results.get("ssl_scan", {}).items():
            if not isinstance(ssl_data, dict):
                continue
            for vuln_key, is_vuln in ssl_data.get("vulnerabilities", {}).items():
                if is_vuln:
                    vulns.add(vuln_key)
        return vulns

    @staticmethod
    def vuln_classes(scan_results: Dict) -> Set[str]:
        """Extract vuln classes from payload_analysis if present."""
        pa = scan_results.get("payload_analysis", {})
        return set(pa.get("vuln_classes", []))

    @staticmethod
    def hosting_orgs(scan_results: Dict) -> Set[str]:
        """Extract hosting org names from osint_correlation if present."""
        orgs: Set[str] = set()
        osint = scan_results.get("osint_correlation", {})
        for org in osint.get("infrastructure", {}).get("hosting_orgs", []):
            if org:
                orgs.add(str(org).lower().strip())
        shodan_org = osint.get("infrastructure", {}).get("shodan_org", "")
        if shodan_org:
            orgs.add(shodan_org.lower().strip())
        return orgs

    @staticmethod
    def cloud_providers(scan_results: Dict) -> Set[str]:
        """Extract cloud provider names from osint_correlation."""
        providers: Set[str] = set()
        osint = scan_results.get("osint_correlation", {})
        for entry in osint.get("infrastructure", {}).get("cloud_ips", []):
            p = entry.get("provider", "")
            if p:
                providers.add(p)
        return providers

    @staticmethod
    def email_domains(scan_results: Dict) -> Set[str]:
        """Extract email domains from email_enumeration."""
        domains: Set[str] = set()
        email_enum = scan_results.get("email_enumeration", {})
        for entry in email_enum.get("found_emails", []):
            email = entry.get("email", "")
            if "@" in email:
                domains.add(email.split("@")[1].lower())
        pattern = email_enum.get("email_formats", [{}])[0].get("pattern", "") if email_enum.get("email_formats") else ""
        if pattern and "@" in pattern:
            domains.add(pattern.split("@")[1].lower())
        return domains

    @staticmethod
    def credential_leak_signals(scan_results: Dict) -> List[str]:
        """Extract credential leak signal types."""
        signals: List[str] = []
        osint = scan_results.get("osint_correlation", {})
        for sig in osint.get("credential_leaks", {}).get("secret_signals", []):
            t = sig.get("type", "")
            if t:
                signals.append(t)
        # From vuln_prioritization findings
        for f in scan_results.get("vuln_prioritization", {}).get("findings", []):
            if f.get("source") == "credential_leak":
                signals.append("credential_leak_confirmed")
        return signals

    @staticmethod
    def high_value_subdomains(scan_results: Dict) -> List[Dict]:
        """Extract high_value_targets from security_analysis."""
        return scan_results.get("security_analysis", {}).get("high_value_targets", [])

    @staticmethod
    def takeover_candidates(scan_results: Dict) -> List[Dict]:
        """Extract subdomain takeover candidates."""
        ta = scan_results.get("takeover_analysis", {})
        return ta.get("vulnerable", [])

    @staticmethod
    def top_findings(scan_results: Dict, max_items: int = 15) -> List[Dict]:
        """Extract top scored findings from vuln_prioritization."""
        vp = scan_results.get("vuln_prioritization", {})
        return vp.get("prioritized", vp.get("findings", []))[:max_items]

    @staticmethod
    def fuzz_findings(scan_results: Dict) -> List[Dict]:
        """Extract API fuzzer confirmed/likely findings."""
        afr = scan_results.get("api_fuzz_results", {})
        return [
            f for f in afr.get("findings", [])
            if f.get("verdict") in ("confirmed", "likely")
        ]

    @staticmethod
    def risk_level(scan_results: Dict) -> str:
        """Return the risk level string from security_analysis."""
        return (scan_results.get("security_analysis", {})
                .get("risk_assessment", {})
                .get("level", "unknown"))

    @staticmethod
    def risk_score(scan_results: Dict) -> float:
        """Return the risk score from vuln_prioritization or security_analysis."""
        vp_score = (scan_results.get("vuln_prioritization", {})
                    .get("overall_risk", {}).get("score", 0))
        if vp_score:
            return float(vp_score)
        sa_score = (scan_results.get("security_analysis", {})
                    .get("risk_assessment", {}).get("score", 0))
        return float(sa_score or 0)


# ---------------------------------------------------------------------------
# Target profile — one per target, holds all extracted data
# ---------------------------------------------------------------------------

class TargetProfile:
    """
    Pre-extracted correlation data for one target.
    Built once from scan_results to avoid repeated extraction.
    """

    def __init__(self, target_id: str, url: str, scan_results: Dict):
        self.target_id    = target_id
        self.url          = url
        self.domain       = scan_results.get("domain", url)
        self.scan_results = scan_results

        # Extract all correlation-relevant data
        ex = _Extractor
        self.ips               = ex.ips(scan_results)
        self.technologies      = ex.technologies(scan_results)
        self.nameservers       = ex.nameservers(scan_results)
        self.mx_records        = ex.mx_records(scan_results)
        self.risky_ports       = ex.risky_ports(scan_results)
        self.ssl_vulns         = ex.ssl_vulns(scan_results)
        self.vuln_classes      = ex.vuln_classes(scan_results)
        self.hosting_orgs      = ex.hosting_orgs(scan_results)
        self.cloud_providers   = ex.cloud_providers(scan_results)
        self.email_domains     = ex.email_domains(scan_results)
        self.cred_signals      = ex.credential_leak_signals(scan_results)
        self.high_value_subs   = ex.high_value_subdomains(scan_results)
        self.takeover_cands    = ex.takeover_candidates(scan_results)
        self.top_findings      = ex.top_findings(scan_results)
        self.fuzz_findings     = ex.fuzz_findings(scan_results)
        self.risk_level        = ex.risk_level(scan_results)
        self.risk_score        = ex.risk_score(scan_results)

        # From consolidated_findings summary (always present in batch)
        self.highest_severity  = ""
        self.findings_count    = 0
        self.web_server        = ""
        self.framework         = ""
        self.tech_summary      = []

    def apply_consolidated(self, cf: Dict) -> None:
        """Merge data from BatchOperation.consolidated_findings entry."""
        self.highest_severity = cf.get("highest_severity", "")
        self.findings_count   = cf.get("findings_count", 0)
        self.web_server       = cf.get("web_server", "")
        self.framework        = cf.get("framework", "")
        self.tech_summary     = cf.get("technologies", [])

    def to_summary(self) -> Dict:
        return {
            "target_id":        self.target_id,
            "url":              self.url,
            "domain":           self.domain,
            "risk_level":       self.risk_level,
            "risk_score":       self.risk_score,
            "highest_severity": self.highest_severity,
            "findings_count":   self.findings_count,
            "ip_count":         len(self.ips),
            "tech_count":       len(self.technologies),
            "risky_ports":      sorted(self.risky_ports),
            "ssl_vulns":        sorted(self.ssl_vulns),
            "vuln_classes":     sorted(self.vuln_classes),
            "hosting_orgs":     sorted(self.hosting_orgs),
            "cloud_providers":  sorted(self.cloud_providers),
            "cred_signals":     self.cred_signals[:5],
            "takeover_count":   len(self.takeover_cands),
        }


# ---------------------------------------------------------------------------
# Main correlator
# ---------------------------------------------------------------------------

class AICrossTargetCorrelator:
    """
    Cross-target correlation engine for ARTEX batch assessments.

    Takes a list of TargetProfile objects (or builds them from raw data),
    runs seven correlation passes, builds a CorrelationGraph, identifies
    pivot paths, then sends a condensed profile to Groq for analyst narrative.

    Correlation passes:
        1. Infrastructure correlation  — shared IPs, hosting org, CDN
        2. Technology correlation      — shared web server, framework, CMS, stack
        3. Vulnerability correlation   — shared vuln classes, SSL CVEs, risky ports
        4. DNS / nameserver correlation — shared NS, MX → same DNS provider
        5. Email & credential correlation — shared email domains, overlapping leaks
        6. Attack pivot path analysis  — which targets can be pivoted to from another
        7. Systemic risk identification — patterns that affect ≥50% of targets

    Slot in AI_batch_orchestrator after all per-target assessments complete:
        correlator = AICrossTargetCorrelator(groq_api_key=GROQ_API_KEY)
        batch_op.correlation_report = correlator.correlate(batch_op)
    """

    def __init__(
        self,
        groq_api_key:            str = GROQ_API_KEY,
        commonality_threshold:   int = COMMONALITY_THRESHOLD,
        min_pivot_probability:   float = 0.55,
    ):
        self.groq_api_key           = groq_api_key
        self.commonality_threshold  = commonality_threshold
        self.min_pivot_probability  = min_pivot_probability
        self.logger                 = logging.getLogger(__name__)

        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] AICrossTargetCorrelator — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

    # ------------------------------------------------------------------
    # Public entry point — accepts BatchOperation directly
    # ------------------------------------------------------------------

    def correlate_batch(self, batch_op: Any) -> Dict:
        """
        Primary entry point. Accepts a BatchOperation from core/batch_manager.

        Args:
            batch_op: core.batch_manager.BatchOperation instance.

        Returns the full correlation report dict.
        """
        targets_data: List[Tuple[str, str, Dict, Dict]] = []

        for target_ctx in batch_op.targets:
            if not hasattr(target_ctx, "scan_results") or not target_ctx.scan_results:
                continue
            # Find matching consolidated_findings entry
            cf = next(
                (f for f in batch_op.consolidated_findings
                 if f.get("target_id") == target_ctx.target_id),
                {}
            )
            targets_data.append((
                target_ctx.target_id,
                target_ctx.url,
                target_ctx.scan_results,
                cf,
            ))

        return self.correlate(
            batch_id      = batch_op.batch_id,
            targets_data  = targets_data,
        )

    # ------------------------------------------------------------------
    # Core correlate method — accepts raw data lists
    # ------------------------------------------------------------------

    def correlate(
        self,
        batch_id:    str,
        targets_data: List[Tuple[str, str, Dict, Dict]],
        # (target_id, url, scan_results, consolidated_findings_entry)
    ) -> Dict:
        """
        Args:
            batch_id:      Batch identifier.
            targets_data:  List of (target_id, url, scan_results, consolidated_entry).

        Returns full correlation report dict.
        """
        if len(targets_data) < 2:
            return self._single_target_result(batch_id, targets_data)

        self.logger.info(
            f"Cross-target correlation — batch={batch_id}, "
            f"targets={len(targets_data)}"
        )
        start = time.time()

        # ── Build target profiles ─────────────────────────────────────
        profiles: List[TargetProfile] = []
        for tid, url, sr, cf in targets_data:
            p = TargetProfile(tid, url, sr)
            p.apply_consolidated(cf)
            profiles.append(p)

        # ── Build correlation graph ───────────────────────────────────
        graph = CorrelationGraph()

        # Seed asset nodes
        for p in profiles:
            graph.add_node(NODE_ASSET, p.url, {
                "target_id":        p.target_id,
                "domain":           p.domain,
                "risk_level":       p.risk_level,
                "risk_score":       p.risk_score,
                "highest_severity": p.highest_severity,
                "findings_count":   p.findings_count,
            })

        # ── Pass 1: Infrastructure ────────────────────────────────────
        infra_findings = self._correlate_infrastructure(profiles, graph)

        # ── Pass 2: Technology stack ──────────────────────────────────
        tech_findings = self._correlate_technology(profiles, graph)

        # ── Pass 3: Vulnerabilities ───────────────────────────────────
        vuln_findings = self._correlate_vulnerabilities(profiles, graph)

        # ── Pass 4: DNS / nameservers ─────────────────────────────────
        dns_findings = self._correlate_dns(profiles, graph)

        # ── Pass 5: Email & credentials ───────────────────────────────
        cred_findings = self._correlate_credentials(profiles, graph)

        # ── Pass 6: Pivot path analysis ───────────────────────────────
        pivot_paths = self._analyse_pivot_paths(profiles, graph)

        # ── Pass 7: Systemic risk patterns ───────────────────────────
        systemic_risks = self._identify_systemic_risks(profiles, graph)

        # ── Aggregate all findings ────────────────────────────────────
        all_findings = (
            infra_findings + tech_findings + vuln_findings +
            dns_findings + cred_findings
        )
        all_findings.sort(
            key=lambda x: SEV_WEIGHT.get(x.get("severity", "info"), 0),
            reverse=True,
        )

        # ── Risk matrix ───────────────────────────────────────────────
        risk_matrix = self._build_risk_matrix(profiles, pivot_paths)

        # ── AI enrichment ─────────────────────────────────────────────
        ai_result = None
        if self.groq_api_key and (all_findings or pivot_paths):
            ai_result = self._ai_analysis(
                batch_id, profiles, all_findings,
                pivot_paths, systemic_risks, risk_matrix
            )

        duration = round(time.time() - start, 2)
        self.logger.info(
            f"Correlation complete — {len(all_findings)} findings, "
            f"{len(pivot_paths)} pivot paths in {duration}s"
        )

        return {
            "batch_id":          batch_id,
            "targets_analysed":  len(profiles),
            "target_summaries":  [p.to_summary() for p in profiles],
            "correlation_graph": graph.to_dict(),
            "common_findings":   all_findings,
            "pivot_paths":       pivot_paths,
            "systemic_risks":    systemic_risks,
            "risk_matrix":       risk_matrix,
            "ai_analysis":       ai_result,
            "scan_metadata": {
                "batch_id":               batch_id,
                "scan_duration_seconds":  duration,
                "timestamp":              datetime.now().isoformat(),
                "ai_model":               "Groq Llama3-70B" if ai_result else "Rule-based only",
                "graph_stats":            graph.stats(),
            },
        }

    # ------------------------------------------------------------------
    # Pass 1 — Infrastructure correlation
    # ------------------------------------------------------------------

    def _correlate_infrastructure(
        self,
        profiles: List[TargetProfile],
        graph:    CorrelationGraph,
    ) -> List[Dict]:
        findings: List[Dict] = []

        # ── Shared public IPs ─────────────────────────────────────────
        ip_to_targets: Dict[str, List[str]] = defaultdict(list)
        ip_to_urls:    Dict[str, List[str]] = defaultdict(list)
        for p in profiles:
            for ip in p.ips:
                ip_to_targets[ip].append(p.target_id)
                ip_to_urls[ip].append(p.url)

        for ip, tids in ip_to_targets.items():
            if len(tids) < self.commonality_threshold:
                continue
            urls = ip_to_urls[ip]
            ip_node = graph.add_node(NODE_IP, ip, {
                "targets": tids,
                "target_count": len(tids),
            })
            for url in urls:
                graph.add_edge(
                    NODE_ASSET, url, NODE_IP, ip,
                    EDGE_HOSTED_ON,
                    probability = PIVOT_WEIGHT["shared_ip"],
                    evidence    = [f"IP {ip} seen in subdomains/DNS/real_ip scan"],
                )
            # Pivot edges between all co-hosted targets
            for u1, u2 in combinations(urls, 2):
                graph.add_edge(
                    NODE_ASSET, u1, NODE_ASSET, u2,
                    EDGE_PIVOT,
                    probability = PIVOT_WEIGHT["shared_ip"],
                    evidence    = [f"Same IP {ip}"],
                    metadata    = {"pivot_type": "shared_ip", "shared_ip": ip},
                )
            findings.append({
                "finding_type":     "shared_infrastructure",
                "subtype":          "shared_ip",
                "severity":         "high",
                "shared_value":     ip,
                "affected_targets": urls,
                "target_count":     len(urls),
                "description": (
                    f"IP {ip} is shared by {len(urls)} targets: "
                    f"{', '.join(urls[:4])}{'...' if len(urls) > 4 else ''}. "
                    f"Compromise of any host at this IP may directly impact all co-hosted targets."
                ),
                "attack_implication": (
                    f"Lateral movement via shared network interface. "
                    f"ARP poisoning, host-level pivot, shared server misconfiguration "
                    f"could expose all {len(urls)} co-hosted targets simultaneously."
                ),
            })

        # ── Shared hosting org ────────────────────────────────────────
        org_to_targets: Dict[str, List[str]] = defaultdict(list)
        for p in profiles:
            for org in p.hosting_orgs:
                org_to_targets[org].append(p.url)

        for org, urls in org_to_targets.items():
            if len(urls) < self.commonality_threshold or not org:
                continue
            graph.add_node(NODE_INFRA, org, {"type": "hosting_org"})
            for url in urls:
                graph.add_edge(
                    NODE_ASSET, url, NODE_INFRA, org,
                    EDGE_HOSTED_ON,
                    probability = PIVOT_WEIGHT["shared_hosting_org"],
                    evidence    = [f"Hosting org: {org}"],
                )
            for u1, u2 in combinations(urls, 2):
                graph.add_edge(
                    NODE_ASSET, u1, NODE_ASSET, u2,
                    EDGE_PIVOT,
                    probability = PIVOT_WEIGHT["shared_hosting_org"],
                    evidence    = [f"Same hosting org: {org}"],
                    metadata    = {"pivot_type": "shared_hosting_org", "org": org},
                )
            findings.append({
                "finding_type":     "shared_infrastructure",
                "subtype":          "shared_hosting_org",
                "severity":         "medium",
                "shared_value":     org,
                "affected_targets": urls,
                "target_count":     len(urls),
                "description": (
                    f"Hosting organisation '{org}' is shared by {len(urls)} targets. "
                    f"A supply-chain or provider-level incident could affect all of them."
                ),
                "attack_implication": (
                    f"Hosting provider compromise, misconfigured shared hosting, "
                    f"or provider credential reuse could cascade across all targets."
                ),
            })

        # ── Shared cloud provider ─────────────────────────────────────
        cloud_to_targets: Dict[str, List[str]] = defaultdict(list)
        for p in profiles:
            for cp in p.cloud_providers:
                cloud_to_targets[cp].append(p.url)

        for cloud, urls in cloud_to_targets.items():
            if len(urls) < self.commonality_threshold:
                continue
            graph.add_node(NODE_INFRA, cloud, {"type": "cloud_provider"})
            for url in urls:
                graph.add_edge(
                    NODE_ASSET, url, NODE_INFRA, cloud,
                    EDGE_HOSTED_ON,
                    probability = PIVOT_WEIGHT["shared_cdn"],
                    evidence    = [f"Cloud provider: {cloud}"],
                )
            findings.append({
                "finding_type":     "shared_infrastructure",
                "subtype":          "shared_cloud_provider",
                "severity":         "low",
                "shared_value":     cloud,
                "affected_targets": urls,
                "target_count":     len(urls),
                "description": (
                    f"All {len(urls)} targets hosted on {cloud}. "
                    f"SSRF → cloud IMDS attacks could yield cross-target IAM credentials."
                ),
                "attack_implication": (
                    f"Single SSRF on any target → {cloud} IMDS → IAM credentials → "
                    f"potential access to all co-hosted resources."
                ),
            })

        return findings

    # ------------------------------------------------------------------
    # Pass 2 — Technology correlation
    # ------------------------------------------------------------------

    def _correlate_technology(
        self,
        profiles: List[TargetProfile],
        graph:    CorrelationGraph,
    ) -> List[Dict]:
        findings: List[Dict] = []

        # ── Shared technologies (any type) ────────────────────────────
        tech_to_targets: Dict[str, List[str]] = defaultdict(list)
        for p in profiles:
            for tech in p.technologies | {t for t in [p.web_server, p.framework] if t}:
                tech = tech.lower().strip()
                if tech:
                    tech_to_targets[tech].append(p.url)

        # Classify shared techs by significance
        CRITICAL_TECHS = {
            "wordpress", "joomla", "drupal", "magento",
            "phpmyadmin", "jenkins", "gitlab", "struts",
            "log4j", "spring", "rails",
        }
        HIGH_TECHS = {
            "php", "mysql", "postgresql", "mongodb", "redis",
            "elasticsearch", "tomcat", "weblogic", "jboss",
        }

        for tech, urls in tech_to_targets.items():
            if len(urls) < self.commonality_threshold:
                continue
            if tech in CRITICAL_TECHS:
                sev = "critical"
            elif tech in HIGH_TECHS:
                sev = "high"
            else:
                sev = "medium"

            graph.add_node(NODE_TECH, tech, {"severity_implication": sev})
            for url in urls:
                graph.add_edge(
                    NODE_ASSET, url, NODE_TECH, tech,
                    EDGE_USES,
                    probability = 1.0,
                    evidence    = [f"Technology {tech} detected"],
                )
            for u1, u2 in combinations(urls, 2):
                graph.add_edge(
                    NODE_ASSET, u1, NODE_ASSET, u2,
                    EDGE_PIVOT,
                    probability = PIVOT_WEIGHT["shared_tech_stack"],
                    evidence    = [f"Same tech: {tech}"],
                    metadata    = {"pivot_type": "shared_tech_stack", "tech": tech},
                )

            if sev in ("critical", "high"):
                findings.append({
                    "finding_type":     "common_technology",
                    "subtype":          f"shared_{tech.replace(' ','_')}",
                    "severity":         sev,
                    "shared_value":     tech,
                    "affected_targets": urls,
                    "target_count":     len(urls),
                    "description": (
                        f"{tech.title()} detected on {len(urls)} targets. "
                        f"A single unpatched CVE in this stack could yield "
                        f"a one-shot compromise of all affected targets."
                    ),
                    "attack_implication": (
                        f"CVE search for '{tech}' — if any target runs an "
                        f"unpatched version, the same exploit likely works "
                        f"across all {len(urls)} targets with identical stack."
                    ),
                })

        # ── Web server homogeneity ─────────────────────────────────────
        ws_map: Dict[str, List[str]] = defaultdict(list)
        for p in profiles:
            if p.web_server:
                ws_map[p.web_server.lower()].append(p.url)
        for ws, urls in ws_map.items():
            if len(urls) >= max(2, len(profiles) // 2):
                findings.append({
                    "finding_type":     "homogeneous_infrastructure",
                    "subtype":          "same_web_server",
                    "severity":         "medium",
                    "shared_value":     ws,
                    "affected_targets": urls,
                    "target_count":     len(urls),
                    "description": (
                        f"{len(urls)} targets run the same web server: {ws}. "
                        f"Server-level misconfigurations or CVEs have batch impact."
                    ),
                    "attack_implication": (
                        f"One confirmed {ws} exploit is reusable across all targets. "
                        f"Check for version homogeneity — same version = same CVE window."
                    ),
                })

        return findings

    # ------------------------------------------------------------------
    # Pass 3 — Vulnerability correlation
    # ------------------------------------------------------------------

    def _correlate_vulnerabilities(
        self,
        profiles: List[TargetProfile],
        graph:    CorrelationGraph,
    ) -> List[Dict]:
        findings: List[Dict] = []

        # ── Shared vuln classes ────────────────────────────────────────
        vc_to_targets: Dict[str, List[str]] = defaultdict(list)
        for p in profiles:
            for vc in p.vuln_classes:
                vc_to_targets[vc].append(p.url)

        HIGH_IMPACT_VC = {
            "sqli", "sqli_mysql", "sqli_mssql", "sqli_postgres",
            "ssti", "cmdi", "ssrf", "nosql",
        }

        for vc, urls in vc_to_targets.items():
            if len(urls) < self.commonality_threshold:
                continue
            sev = "critical" if vc in HIGH_IMPACT_VC else "high"
            graph.add_node(NODE_VULN, vc, {"class": vc, "severity": sev})
            for url in urls:
                graph.add_edge(
                    NODE_ASSET, url, NODE_VULN, vc,
                    EDGE_VULNERABLE,
                    probability = PIVOT_WEIGHT["shared_vuln_class"],
                    evidence    = [f"Vuln class {vc} inferred from tech stack"],
                )
            findings.append({
                "finding_type":     "common_vulnerability_class",
                "subtype":          vc,
                "severity":         sev,
                "shared_value":     vc,
                "affected_targets": urls,
                "target_count":     len(urls),
                "description": (
                    f"Vulnerability class '{vc}' identified on {len(urls)} targets. "
                    f"Shared stack implies the same exploit path works across all."
                ),
                "attack_implication": (
                    f"One working {vc.upper()} payload reusable against {len(urls)} targets. "
                    f"Automate with sqlmap/tplmap/commix across the target list."
                ),
            })

        # ── Shared SSL/TLS CVEs ───────────────────────────────────────
        ssl_to_targets: Dict[str, List[str]] = defaultdict(list)
        for p in profiles:
            for vuln in p.ssl_vulns:
                ssl_to_targets[vuln].append(p.url)

        SSL_SEVERITY = {
            "heartbleed": "critical",
            "poodle":     "high",
            "drown":      "high",
            "ccs_injection": "high",
            "freak":      "high",
            "sweet32":    "medium",
            "beast":      "medium",
            "logjam":     "medium",
        }
        for ssl_vuln, urls in ssl_to_targets.items():
            if len(urls) < self.commonality_threshold:
                continue
            sev = SSL_SEVERITY.get(ssl_vuln, "medium")
            findings.append({
                "finding_type":     "common_ssl_vulnerability",
                "subtype":          ssl_vuln,
                "severity":         sev,
                "shared_value":     ssl_vuln.upper(),
                "affected_targets": urls,
                "target_count":     len(urls),
                "description": (
                    f"SSL/TLS vulnerability {ssl_vuln.upper()} confirmed on {len(urls)} targets. "
                    f"Shared TLS stack version implies same OpenSSL/TLS library in use."
                ),
                "attack_implication": (
                    f"MITM + {ssl_vuln.upper()} exploit against any target in-scope. "
                    f"Session decryption possible for all {len(urls)} affected hosts."
                ),
            })

        # ── Shared risky ports ────────────────────────────────────────
        port_to_targets: Dict[int, List[str]] = defaultdict(list)
        for p in profiles:
            for port in p.risky_ports:
                port_to_targets[port].append(p.url)

        HIGH_RISK_PORTS = {22, 23, 3306, 3389, 5432, 5900, 6379, 9200, 27017, 445}
        for port, urls in port_to_targets.items():
            if len(urls) < self.commonality_threshold:
                continue
            sev = "critical" if port in HIGH_RISK_PORTS else "medium"
            service_map = {
                22: "SSH", 23: "Telnet", 3306: "MySQL", 3389: "RDP",
                5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
                9200: "Elasticsearch", 27017: "MongoDB", 445: "SMB",
            }
            service = service_map.get(port, f"port/{port}")
            findings.append({
                "finding_type":     "common_exposed_service",
                "subtype":          f"exposed_{service.lower()}",
                "severity":         sev,
                "shared_value":     f"{service} (port {port})",
                "affected_targets": urls,
                "target_count":     len(urls),
                "description": (
                    f"{service} (port {port}) exposed on {len(urls)} targets. "
                    f"Internet-facing {service} is a consistent high-value attack surface."
                ),
                "attack_implication": (
                    f"Brute-force / credential spray against all {len(urls)} targets "
                    f"simultaneously. Single credential hit = {len(urls)}-target blast radius."
                ),
            })

        # ── Cross-target subdomain takeover ───────────────────────────
        all_takeover_subs: Dict[str, List[str]] = {}  # service → [target_urls]
        for p in profiles:
            for tc in p.takeover_cands:
                svc = tc.get("service", "unknown")
                all_takeover_subs.setdefault(svc, []).append(p.url)

        for svc, urls in all_takeover_subs.items():
            if len(urls) < self.commonality_threshold:
                continue
            findings.append({
                "finding_type":     "common_takeover_provider",
                "subtype":          f"takeover_{svc}",
                "severity":         "high",
                "shared_value":     svc,
                "affected_targets": urls,
                "target_count":     len(urls),
                "description": (
                    f"Subdomain takeover candidates pointing to {svc} found "
                    f"across {len(urls)} targets. Org-wide use of {svc} with "
                    f"dangling DNS records."
                ),
                "attack_implication": (
                    f"Register one {svc} account → serve malicious content on "
                    f"trusted subdomains of {len(urls)} targets simultaneously. "
                    f"Org-wide phishing / cookie theft at scale."
                ),
            })

        # ── Fuzz finding correlation ───────────────────────────────────
        fuzz_class_targets: Dict[str, List[str]] = defaultdict(list)
        for p in profiles:
            for ff in p.fuzz_findings:
                fuzz_class_targets[ff.get("payload_class", "unknown")].append(p.url)

        for fc, urls in fuzz_class_targets.items():
            if len(urls) < self.commonality_threshold:
                continue
            findings.append({
                "finding_type":     "common_fuzz_finding",
                "subtype":          fc,
                "severity":         "high",
                "shared_value":     fc,
                "affected_targets": list(set(urls)),
                "target_count":     len(set(urls)),
                "description": (
                    f"API fuzz finding class '{fc}' confirmed/likely "
                    f"on {len(set(urls))} targets. Same vulnerable pattern "
                    f"across the batch."
                ),
                "attack_implication": (
                    f"Automated exploitation of {fc} across all affected targets "
                    f"using the same payload set."
                ),
            })

        return findings

    # ------------------------------------------------------------------
    # Pass 4 — DNS correlation
    # ------------------------------------------------------------------

    def _correlate_dns(
        self,
        profiles: List[TargetProfile],
        graph:    CorrelationGraph,
    ) -> List[Dict]:
        findings: List[Dict] = []

        # ── Shared nameservers ────────────────────────────────────────
        ns_to_targets: Dict[str, List[str]] = defaultdict(list)
        for p in profiles:
            for ns in p.nameservers:
                ns_to_targets[ns].append(p.url)

        for ns, urls in ns_to_targets.items():
            if len(urls) < self.commonality_threshold:
                continue
            graph.add_node(NODE_NS, ns, {"target_count": len(urls)})
            for url in urls:
                graph.add_edge(
                    NODE_ASSET, url, NODE_NS, ns,
                    EDGE_USES,
                    probability = PIVOT_WEIGHT["shared_ns"],
                    evidence    = [f"NS record: {ns}"],
                )
            for u1, u2 in combinations(urls, 2):
                graph.add_edge(
                    NODE_ASSET, u1, NODE_ASSET, u2,
                    EDGE_PIVOT,
                    probability = PIVOT_WEIGHT["shared_ns"],
                    evidence    = [f"Same NS: {ns}"],
                    metadata    = {"pivot_type": "shared_ns", "ns": ns},
                )
            findings.append({
                "finding_type":     "shared_dns_provider",
                "subtype":          "shared_nameserver",
                "severity":         "medium",
                "shared_value":     ns,
                "affected_targets": urls,
                "target_count":     len(urls),
                "description": (
                    f"Nameserver {ns} used by {len(urls)} targets. "
                    f"Compromise of this NS = DNS hijack across all targets."
                ),
                "attack_implication": (
                    f"DNS provider account takeover or NS zone transfer → "
                    f"redirect all {len(urls)} targets to attacker-controlled hosts."
                ),
            })

        # ── Shared MX provider ────────────────────────────────────────
        mx_provider_targets: Dict[str, List[str]] = defaultdict(list)
        GOOGLE_MX = {"aspmx.l.google.com", "alt1.aspmx.l.google.com", "alt2.aspmx.l.google.com"}
        O365_MX   = {"mail.protection.outlook.com"}

        for p in profiles:
            for mx in p.mx_records:
                provider = None
                if any(g in mx for g in GOOGLE_MX) or "google" in mx:
                    provider = "Google Workspace"
                elif any(o in mx for o in O365_MX) or "outlook.com" in mx:
                    provider = "Microsoft 365"
                elif "zoho" in mx:
                    provider = "Zoho Mail"
                elif "amazonses" in mx:
                    provider = "Amazon SES"
                elif "proofpoint" in mx or "pphosted" in mx:
                    provider = "Proofpoint"
                elif "mimecast" in mx:
                    provider = "Mimecast"
                if provider:
                    mx_provider_targets[provider].append(p.url)

        for provider, urls in mx_provider_targets.items():
            if len(urls) < self.commonality_threshold:
                continue
            graph.add_node(NODE_MX, provider, {"target_count": len(urls)})
            for url in urls:
                graph.add_edge(
                    NODE_ASSET, url, NODE_MX, provider,
                    EDGE_USES,
                    probability = 1.0,
                    evidence    = [f"MX provider: {provider}"],
                )
            findings.append({
                "finding_type":     "shared_mail_provider",
                "subtype":          "shared_mx_provider",
                "severity":         "low",
                "shared_value":     provider,
                "affected_targets": urls,
                "target_count":     len(urls),
                "description": (
                    f"All {len(urls)} targets use {provider} for email. "
                    f"A phishing campaign targeting one domain's users could "
                    f"be extended to all targets with the same mail infrastructure."
                ),
                "attack_implication": (
                    f"OAuth consent phishing, {provider} admin portal credential reuse, "
                    f"or email-forwarding rule injection could affect all {len(urls)} targets."
                ),
            })

        return findings

    # ------------------------------------------------------------------
    # Pass 5 — Email & credential correlation
    # ------------------------------------------------------------------

    def _correlate_credentials(
        self,
        profiles: List[TargetProfile],
        graph:    CorrelationGraph,
    ) -> List[Dict]:
        findings: List[Dict] = []

        # ── Shared email domain ───────────────────────────────────────
        email_domain_to_targets: Dict[str, List[str]] = defaultdict(list)
        for p in profiles:
            for ed in p.email_domains:
                email_domain_to_targets[ed].append(p.url)

        for ed, urls in email_domain_to_targets.items():
            if len(urls) < self.commonality_threshold:
                continue
            graph.add_node(NODE_EMAIL, ed, {"target_count": len(urls)})
            for url in urls:
                graph.add_edge(
                    NODE_ASSET, url, NODE_EMAIL, ed,
                    EDGE_EXPOSES,
                    probability = PIVOT_WEIGHT["shared_email_domain"],
                    evidence    = [f"Email domain: {ed}"],
                )
            for u1, u2 in combinations(urls, 2):
                graph.add_edge(
                    NODE_ASSET, u1, NODE_ASSET, u2,
                    EDGE_PIVOT,
                    probability = PIVOT_WEIGHT["credential_reuse"],
                    evidence    = [f"Shared email domain {ed} → credential reuse"],
                    metadata    = {"pivot_type": "credential_reuse", "domain": ed},
                )
            findings.append({
                "finding_type":     "shared_email_domain",
                "subtype":          "credential_pivot_surface",
                "severity":         "high",
                "shared_value":     ed,
                "affected_targets": urls,
                "target_count":     len(urls),
                "description": (
                    f"Email domain @{ed} used across {len(urls)} targets. "
                    f"Harvested employee emails from any target are likely "
                    f"reusable as credentials across the entire batch."
                ),
                "attack_implication": (
                    f"One leaked {ed} credential can be sprayed against all {len(urls)} "
                    f"targets — VPN, SSH, admin portals, cloud consoles. "
                    f"SSO / federated identity means single account = multi-target access."
                ),
            })

        # ── Shared credential leak signal types ───────────────────────
        cred_type_to_targets: Dict[str, List[str]] = defaultdict(list)
        for p in profiles:
            for sig_type in set(p.cred_signals):
                cred_type_to_targets[sig_type].append(p.url)

        for cred_type, urls in cred_type_to_targets.items():
            if len(urls) < self.commonality_threshold or not cred_type:
                continue
            graph.add_node(NODE_CRED, cred_type, {"target_count": len(urls)})
            for url in urls:
                graph.add_edge(
                    NODE_ASSET, url, NODE_CRED, cred_type,
                    EDGE_EXPOSES,
                    probability = PIVOT_WEIGHT["credential_reuse"],
                    evidence    = [f"Credential type leaked: {cred_type}"],
                )
            findings.append({
                "finding_type":     "cross_target_credential_leak",
                "subtype":          cred_type,
                "severity":         "critical",
                "shared_value":     cred_type,
                "affected_targets": urls,
                "target_count":     len(urls),
                "description": (
                    f"Credential type '{cred_type}' found in public sources "
                    f"for {len(urls)} targets. Org-wide credential hygiene issue."
                ),
                "attack_implication": (
                    f"Leaked {cred_type} likely valid across all {len(urls)} targets "
                    f"if SSO or shared credential policy is in place. "
                    f"Immediate rotation required for entire batch."
                ),
            })

        return findings

    # ------------------------------------------------------------------
    # Pass 6 — Pivot path analysis
    # ------------------------------------------------------------------

    def _analyse_pivot_paths(
        self,
        profiles: List[TargetProfile],
        graph:    CorrelationGraph,
    ) -> List[Dict]:
        """
        Identify concrete attack pivot paths between targets.
        A pivot path is: attacker compromises T1 via known vuln →
        reaches T2 via shared infrastructure/credentials.
        """
        pivot_paths: List[Dict] = []
        seen_pairs: Set[Tuple[str, str]] = set()

        # Score each target by how easy it is to compromise initially
        def initial_access_score(p: TargetProfile) -> float:
            score = 0.0
            if p.cred_signals:
                score += 40.0
            if p.takeover_cands:
                score += 30.0
            score += len(p.risky_ports) * 8.0
            score += len(p.ssl_vulns) * 5.0
            score += p.risk_score * 0.3
            if p.highest_severity == "critical":
                score += 25.0
            elif p.highest_severity == "high":
                score += 15.0
            return min(100.0, score)

        # For every pair of targets, check if any shared asset enables pivot
        for p1, p2 in combinations(profiles, 2):
            # Shared IPs
            shared_ips = p1.ips & p2.ips
            # Shared NS
            shared_ns = p1.nameservers & p2.nameservers
            # Shared hosting org
            shared_orgs = p1.hosting_orgs & p2.hosting_orgs
            # Shared email domain
            shared_email = p1.email_domains & p2.email_domains
            # Shared vuln class
            shared_vulns = p1.vuln_classes & p2.vuln_classes
            # Network adjacency (same /24)
            shared_subnets = self._shared_subnets(p1.ips, p2.ips)

            pivot_evidence: List[Dict] = []

            if shared_ips:
                pivot_evidence.append({
                    "pivot_mechanism": "shared_ip",
                    "detail":          f"IP(s): {', '.join(list(shared_ips)[:3])}",
                    "probability":     PIVOT_WEIGHT["shared_ip"],
                    "technique":       (
                        "Lateral movement via shared network interface. "
                        "If T1 is compromised at host level, direct access to T2 on same IP."
                    ),
                })

            if shared_subnets:
                pivot_evidence.append({
                    "pivot_mechanism": "network_adjacency",
                    "detail":          f"Shared /24: {', '.join(list(shared_subnets)[:3])}",
                    "probability":     PIVOT_WEIGHT["network_adjacency"],
                    "technique":       (
                        "Internal network reachability. ARP scan from T1 host "
                        "reveals T2 on same subnet. Direct port scan + exploitation."
                    ),
                })

            if shared_email and p1.cred_signals:
                pivot_evidence.append({
                    "pivot_mechanism": "credential_reuse",
                    "detail":          f"Email domain: @{', @'.join(list(shared_email)[:2])}",
                    "probability":     PIVOT_WEIGHT["credential_reuse"],
                    "technique":       (
                        "Credentials harvested from T1 (phishing/leak) sprayed against "
                        "T2 login surfaces — same employee accounts, same AD/SSO."
                    ),
                })

            if shared_ns:
                pivot_evidence.append({
                    "pivot_mechanism": "shared_nameserver",
                    "detail":          f"NS: {', '.join(list(shared_ns)[:2])}",
                    "probability":     PIVOT_WEIGHT["shared_ns"],
                    "technique":       (
                        "DNS provider account compromise → zone modification for T2. "
                        "T1 compromise may expose NS credentials shared with T2."
                    ),
                })

            if shared_orgs:
                pivot_evidence.append({
                    "pivot_mechanism": "shared_hosting_org",
                    "detail":          f"Org: {', '.join(list(shared_orgs)[:2])}",
                    "probability":     PIVOT_WEIGHT["shared_hosting_org"],
                    "technique":       (
                        "Hosting control panel credential reuse. "
                        "cPanel/Plesk/cloud console access from T1 → reach T2."
                    ),
                })

            if not pivot_evidence:
                continue

            pair_key = tuple(sorted([p1.target_id, p2.target_id]))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            # Pick highest-probability pivot mechanism
            best = max(pivot_evidence, key=lambda x: x["probability"])
            overall_prob = min(
                1.0,
                sum(e["probability"] for e in pivot_evidence) / len(pivot_evidence) + 0.1
            )

            # Determine pivot direction — attack from easier target to harder
            ia1 = initial_access_score(p1)
            ia2 = initial_access_score(p2)
            if ia1 >= ia2:
                entry_target, pivot_target = p1, p2
            else:
                entry_target, pivot_target = p2, p1

            pivot_paths.append({
                "path_id":          hashlib.md5(
                    f"{pair_key[0]}|{pair_key[1]}".encode()
                ).hexdigest()[:10],
                "entry_target":     entry_target.url,
                "entry_target_id":  entry_target.target_id,
                "pivot_target":     pivot_target.url,
                "pivot_target_id":  pivot_target.target_id,
                "probability":      round(overall_prob, 2),
                "pivot_mechanisms": pivot_evidence,
                "best_mechanism":   best["pivot_mechanism"],
                "severity":         (
                    "critical" if overall_prob > 0.75
                    else "high" if overall_prob > 0.55
                    else "medium"
                ),
                "attack_narrative": (
                    f"Compromise {entry_target.url} via "
                    f"{entry_target.highest_severity or 'identified'} vulnerability "
                    f"(risk score: {entry_target.risk_score:.0f}/100). "
                    f"Pivot to {pivot_target.url} using {best['pivot_mechanism'].replace('_',' ')} "
                    f"({best['detail']}). "
                    f"Technique: {best['technique']}"
                ),
                "steps": [
                    f"1. Exploit highest-severity finding on {entry_target.url}",
                    f"2. Establish foothold / extract {best['pivot_mechanism'].replace('_',' ')}",
                    f"3. Apply {best['technique'][:100]}",
                    f"4. Access {pivot_target.url} using pivoted asset",
                    f"5. Enumerate {pivot_target.url} from new vantage point",
                ],
            })

        # Sort by probability descending
        pivot_paths.sort(key=lambda x: x["probability"], reverse=True)
        return pivot_paths[:25]   # cap output

    @staticmethod
    def _shared_subnets(ips1: Set[str], ips2: Set[str]) -> Set[str]:
        """Return /24 networks shared between two IP sets."""
        def to_24(ip: str) -> Optional[str]:
            try:
                parts = ip.split(".")
                if len(parts) == 4:
                    return ".".join(parts[:3])
            except Exception:
                pass
            return None

        nets1 = {to_24(ip) for ip in ips1 if to_24(ip)}
        nets2 = {to_24(ip) for ip in ips2 if to_24(ip)}
        return nets1 & nets2

    # ------------------------------------------------------------------
    # Pass 7 — Systemic risk patterns
    # ------------------------------------------------------------------

    def _identify_systemic_risks(
        self,
        profiles:    List[TargetProfile],
        graph:       CorrelationGraph,
    ) -> List[Dict]:
        """
        Identify patterns that affect ≥50% of targets.
        These represent organisation-level security failures.
        """
        systemic: List[Dict] = []
        n = len(profiles)
        threshold = max(2, n // 2)

        # SPF / DMARC absence
        no_spf_count = sum(
            1 for p in profiles
            if not any("v=spf1" in str(r).lower()
                       for r in p.scan_results.get("dns_records", {}).get("TXT", []))
        )
        if no_spf_count >= threshold:
            systemic.append({
                "pattern":          "missing_email_authentication",
                "severity":         "high",
                "affected_count":   no_spf_count,
                "total_targets":    n,
                "pct_affected":     round(no_spf_count / n * 100, 1),
                "description": (
                    f"{no_spf_count}/{n} targets ({no_spf_count/n*100:.0f}%) "
                    f"lack proper SPF/DMARC records. "
                    f"Organisation-wide email spoofing risk."
                ),
                "recommendation": (
                    "Implement DMARC p=quarantine → p=reject policy org-wide. "
                    "Enforce SPF -all across all domains. "
                    "Consider a centralised DMARC reporting platform (DMARC Analyser, Valimail)."
                ),
            })

        # No HTTPS on active subdomains
        http_only_count = sum(
            1 for p in profiles
            if any(s.get("http_status") and not s.get("https_status")
                   for s in p.scan_results.get("subdomains", []))
        )
        if http_only_count >= threshold:
            systemic.append({
                "pattern":          "http_without_https",
                "severity":         "high",
                "affected_count":   http_only_count,
                "total_targets":    n,
                "pct_affected":     round(http_only_count / n * 100, 1),
                "description": (
                    f"{http_only_count}/{n} targets have subdomains accessible "
                    f"over plain HTTP. Organisation-wide TLS enforcement gap."
                ),
                "recommendation": (
                    "Enforce HTTPS-only via HSTS with includeSubDomains. "
                    "HTTP → HTTPS redirect at load balancer level. "
                    "Implement a certificate lifecycle management platform."
                ),
            })

        # Outdated SSL grade
        poor_ssl_count = sum(
            1 for p in profiles
            if any(
                hdata.get("grade", "A") in ("C", "D", "E", "F", "T")
                for hdata in p.scan_results.get("ssl_scan", {}).values()
                if isinstance(hdata, dict)
            )
        )
        if poor_ssl_count >= threshold:
            systemic.append({
                "pattern":          "poor_ssl_posture",
                "severity":         "high",
                "affected_count":   poor_ssl_count,
                "total_targets":    n,
                "pct_affected":     round(poor_ssl_count / n * 100, 1),
                "description": (
                    f"{poor_ssl_count}/{n} targets have SSL grades of C or below. "
                    f"Organisation is not enforcing TLS best practices."
                ),
                "recommendation": (
                    "Minimum TLS 1.2, prefer TLS 1.3. "
                    "Disable all weak cipher suites (RC4, 3DES, export grades). "
                    "Enable OCSP stapling and implement certificate pinning for critical assets."
                ),
            })

        # Missing security headers across the board
        missing_headers_count = sum(
            1 for p in profiles
            if any(
                f.get("type") == "missing_security_header"
                and f.get("header") in ("Content-Security-Policy", "Strict-Transport-Security")
                for td in p.scan_results.get("header_analysis", {}).get("targets", {}).values()
                if isinstance(td, dict)
                for f in td.get("findings", [])
            )
        )
        if missing_headers_count >= threshold:
            systemic.append({
                "pattern":          "missing_security_headers",
                "severity":         "medium",
                "affected_count":   missing_headers_count,
                "total_targets":    n,
                "pct_affected":     round(missing_headers_count / n * 100, 1),
                "description": (
                    f"{missing_headers_count}/{n} targets missing critical security headers "
                    f"(CSP, HSTS). Organisation-level web security policy gap."
                ),
                "recommendation": (
                    "Implement security headers at reverse proxy / CDN level for all origins. "
                    "Use Content-Security-Policy with nonces. "
                    "HSTS preload all public-facing domains."
                ),
            })

        # Homogeneous critical vulnerabilities
        critical_vuln_classes: Dict[str, int] = defaultdict(int)
        for p in profiles:
            for vc in p.vuln_classes:
                if vc in {"sqli", "sqli_mysql", "sqli_mssql",
                           "sqli_postgres", "ssti", "cmdi"}:
                    critical_vuln_classes[vc] += 1
        for vc, count in critical_vuln_classes.items():
            if count >= threshold:
                systemic.append({
                    "pattern":          f"systemic_{vc}",
                    "severity":         "critical",
                    "affected_count":   count,
                    "total_targets":    n,
                    "pct_affected":     round(count / n * 100, 1),
                    "description": (
                        f"{count}/{n} targets potentially vulnerable to {vc.upper()}. "
                        f"Shared tech stack creates org-wide injection risk."
                    ),
                    "recommendation": (
                        f"Parameterised queries / input validation framework "
                        f"deployed org-wide. WAF rule tuned for {vc.upper()} payloads. "
                        f"Code review mandate for all {vc}-relevant data paths."
                    ),
                })

        systemic.sort(
            key=lambda x: (SEV_WEIGHT.get(x["severity"], 0), x["pct_affected"]),
            reverse=True,
        )
        return systemic

    # ------------------------------------------------------------------
    # Risk matrix
    # ------------------------------------------------------------------

    def _build_risk_matrix(
        self,
        profiles:    List[TargetProfile],
        pivot_paths: List[Dict],
    ) -> Dict:
        """
        Build a target × target risk matrix showing pivot probability
        and a combined risk score for each target.
        """
        # target_id → index
        idx = {p.target_id: i for i, p in enumerate(profiles)}
        n   = len(profiles)
        matrix: List[List[float]] = [[0.0] * n for _ in range(n)]

        for path in pivot_paths:
            i = idx.get(path["entry_target_id"])
            j = idx.get(path["pivot_target_id"])
            if i is not None and j is not None:
                matrix[i][j] = max(matrix[i][j], path["probability"])
                # Bidirectional — pivot works both ways if infrastructure is shared
                if path["best_mechanism"] in ("shared_ip", "network_adjacency", "shared_hosting_org"):
                    matrix[j][i] = max(matrix[j][i], path["probability"] * 0.85)

        # Blast radius — sum of pivot probabilities OUT from each target
        blast_radius: List[Dict] = []
        for i, p in enumerate(profiles):
            outbound   = sum(matrix[i])
            inbound    = sum(matrix[r][i] for r in range(n))
            blast_radius.append({
                "target_id":           p.target_id,
                "url":                 p.url,
                "risk_score":          p.risk_score,
                "risk_level":          p.risk_level,
                "outbound_pivot_prob": round(outbound, 2),
                "inbound_pivot_prob":  round(inbound, 2),
                "combined_risk":       round(
                    p.risk_score * 0.5 + outbound * 15 + inbound * 10, 1
                ),
            })

        blast_radius.sort(key=lambda x: x["combined_risk"], reverse=True)

        return {
            "targets":        [p.url for p in profiles],
            "matrix":         [[round(v, 2) for v in row] for row in matrix],
            "blast_radius":   blast_radius,
            "highest_risk_target": blast_radius[0] if blast_radius else None,
        }

    # ------------------------------------------------------------------
    # Pass 2 — Groq AI analysis
    # ------------------------------------------------------------------

    def _ai_analysis(
        self,
        batch_id:      str,
        profiles:      List[TargetProfile],
        all_findings:  List[Dict],
        pivot_paths:   List[Dict],
        systemic_risks: List[Dict],
        risk_matrix:   Dict,
    ) -> Optional[Dict]:
        try:
            prompt = self._build_prompt(
                batch_id, profiles, all_findings,
                pivot_paths, systemic_risks, risk_matrix
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
        batch_id:      str,
        profiles:      List[TargetProfile],
        all_findings:  List[Dict],
        pivot_paths:   List[Dict],
        systemic_risks: List[Dict],
        risk_matrix:   Dict,
    ) -> str:
        # Condense everything to fit token budget
        profile_summaries = [p.to_summary() for p in profiles[:12]]

        condensed_findings = []
        for f in all_findings[:12]:
            condensed_findings.append({
                "type":     f["finding_type"],
                "subtype":  f["subtype"],
                "severity": f["severity"],
                "shared":   f["shared_value"],
                "targets":  len(f["affected_targets"]),
                "implication": f.get("attack_implication", "")[:120],
            })

        condensed_pivots = []
        for p in pivot_paths[:6]:
            condensed_pivots.append({
                "from":        p["entry_target"],
                "to":          p["pivot_target"],
                "mechanism":   p["best_mechanism"],
                "probability": p["probability"],
                "severity":    p["severity"],
            })

        condensed_systemic = []
        for sr in systemic_risks[:5]:
            condensed_systemic.append({
                "pattern":    sr["pattern"],
                "severity":   sr["severity"],
                "pct":        sr["pct_affected"],
                "count":      f"{sr['affected_count']}/{sr['total_targets']}",
            })

        highest_risk = risk_matrix.get("highest_risk_target", {})

        return f"""You are a lead red team operator and threat intelligence analyst.
Analyze this cross-target correlation report for batch {batch_id} and return ONLY valid JSON.

Batch size: {len(profiles)} targets
Common findings ({len(all_findings)} total): {json.dumps(condensed_findings, indent=2)}
Pivot paths ({len(pivot_paths)} total): {json.dumps(condensed_pivots, indent=2)}
Systemic risks: {json.dumps(condensed_systemic, indent=2)}
Highest risk target: {json.dumps(highest_risk, indent=2)}
Target summaries: {json.dumps(profile_summaries[:6], indent=2)}

Return a JSON object with EXACTLY these keys:
- "batch_threat_narrative": string — 4-5 sentences describing the most dangerous cross-target attack scenario an adversary would pursue against this batch. Be specific about which targets, which pivot mechanisms, and what the final impact would be.
- "highest_impact_pivot_chain": object with "targets" (array of URLs in order), "total_steps" (int), "narrative" (string — step-by-step attack from first entry point to deepest target), "estimated_attacker_time" (string).
- "systemic_risk_assessment": string — 2-3 sentences on organisation-level security posture based on cross-target patterns. What does the correlation reveal about the security culture?
- "critical_cross_target_actions": array of objects (max 5) ordered by urgency, each with "action" (string — specific), "addresses_findings" (array of finding subtypes), "blast_radius_reduction" (string — how many targets this protects).
- "attacker_perspective": object with "entry_target" (string — URL of recommended first target for an attacker), "reason" (string), "full_kill_chain" (array of strings — ordered steps from initial access to full batch compromise).
- "defender_blind_spots": array of strings — 3-5 cross-target detection gaps that standard per-target scanning would miss.
- "shared_infrastructure_risk_level": one of [critical, high, medium, low] — overall risk from shared assets.

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
                resp = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers = headers,
                    json    = payload,
                    timeout = 50,
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
                if resp.status_code == 429:
                    time.sleep(15 * (attempt + 1))
                    continue
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

    # ------------------------------------------------------------------
    # Single-target fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _single_target_result(batch_id: str, targets_data: List) -> Dict:
        return {
            "batch_id":          batch_id,
            "targets_analysed":  len(targets_data),
            "common_findings":   [],
            "pivot_paths":       [],
            "systemic_risks":    [],
            "ai_analysis":       None,
            "scan_metadata": {
                "note":      "Cross-target correlation requires at least 2 targets.",
                "timestamp": datetime.now().isoformat(),
            },
        }