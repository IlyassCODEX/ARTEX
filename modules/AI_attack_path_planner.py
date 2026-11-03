# AI_attack_path_planner.py
# reads from confirmed scan_results keys:
#   subdomains        -> [{subdomain, ip, http_status, https_status, title}]
#   port_scan         -> [{target, ports:[{port,service,state,risk}], risky_ports, vulnerabilities, os_guess}]
#   ssl_scan          -> {host: {vulnerabilities:{heartbleed:bool,...}, grade, protocols}}
#   dns_records       -> {A:[], MX:[], NS:[], TXT:[], SPF:[]}
#   real_ip           -> {origin_ips:[], techniques_used:[]}
#   tech_detection    -> {url: {technologies:[{name,version,category}]}}
#   email_enumeration -> {found_emails:[{email,type,confidence}], login_pages:[{url,type,source}],
#                        password_reset_pages:[{url}], email_formats:[{pattern,confidence}]}
#   security_analysis -> {high_value_targets:[{subdomain,security_score,risk_level,reasons}],
#                        risk_assessment:{level,score,factors}, attack_surface:{vectors:[]}}
#   header_analysis   -> {targets:{url:{findings:[{type,header,severity,attack_class}]}}}
#   takeover_analysis -> {vulnerable:[{subdomain,service,confidence_level,cname_chain}],
#                        dangling_dns:[{subdomain,dangling_reason}]}
#   payload_analysis  -> {vuln_classes:[], tech_profile:{language,framework,database,cms,cdn_waf},
#                        waf_detected:{detected,name}, injection_points:[{surface,url,method,param_type}]}
#   osint_correlation -> {infrastructure:{all_ips,cloud_ips}, emails:[],
#                        credential_leaks:{github_hits,secret_signals},
#                        dns_intelligence:{spf_analysis,dmarc_analysis,open_resolver}}
#   vuln_prioritization -> {findings:[{vuln_id,title,severity,final_score,source,affected_asset,
#                           business_tags,attack_vector}], attack_chains:[{chain_name,severity,steps}]}

import json
import time
import logging
import requests
import hashlib
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple, Any


# ---------------------------------------------------------------------------
# Node and Edge type taxonomy
# ---------------------------------------------------------------------------

# Node categories — what kind of asset/component this node represents
NODE_TYPES = {
    # External entry points — internet-facing, attacker starts here
    "internet_entry":        {"icon": "🌐", "layer": 0, "description": "Public internet entry point"},
    "subdomain_web":         {"icon": "🖥",  "layer": 1, "description": "Active web subdomain"},
    "subdomain_takeover":    {"icon": "☠",  "layer": 1, "description": "Subdomain takeover candidate"},
    "login_page":            {"icon": "🔐", "layer": 1, "description": "Authentication endpoint"},
    "api_endpoint":          {"icon": "⚙",  "layer": 1, "description": "API surface"},
    "exposed_port":          {"icon": "🔌", "layer": 1, "description": "Directly exposed network port"},
    "email_surface":         {"icon": "📧", "layer": 1, "description": "Email attack surface (phishing/spoofing)"},
    "credential_leak":       {"icon": "🗝",  "layer": 1, "description": "Leaked credential in public source"},
    # Internal / post-exploitation nodes
    "web_app":               {"icon": "💻", "layer": 2, "description": "Web application"},
    "database":              {"icon": "🗄",  "layer": 3, "description": "Database service"},
    "internal_service":      {"icon": "🔧", "layer": 3, "description": "Internal networked service"},
    "file_system":           {"icon": "📁", "layer": 3, "description": "File system access"},
    "cloud_metadata":        {"icon": "☁",  "layer": 2, "description": "Cloud instance metadata endpoint"},
    "admin_panel":           {"icon": "👑", "layer": 2, "description": "Administrative interface"},
    "mail_server":           {"icon": "📮", "layer": 2, "description": "Mail exchange server"},
    # Target assets — what attacker ultimately wants
    "target_data":           {"icon": "💰", "layer": 4, "description": "Sensitive data store"},
    "target_credentials":    {"icon": "🔑", "layer": 4, "description": "Credential store"},
    "target_infrastructure": {"icon": "🏗",  "layer": 4, "description": "Infrastructure control"},
    "target_domain_control": {"icon": "🎯", "layer": 4, "description": "Domain / DNS control"},
    "target_full_pwn":       {"icon": "💥", "layer": 4, "description": "Full system compromise"},
}

# Edge types — what technique connects two nodes
EDGE_TYPES = {
    "exploit":           {"color": "#e74c3c", "weight": 3, "description": "Direct exploitation"},
    "credential_reuse":  {"color": "#e67e22", "weight": 2, "description": "Credential reuse / stuffing"},
    "pivot":             {"color": "#9b59b6", "weight": 2, "description": "Post-exploitation pivot"},
    "phishing":          {"color": "#f39c12", "weight": 2, "description": "Social engineering / phishing"},
    "dns_abuse":         {"color": "#1abc9c", "weight": 1, "description": "DNS misconfiguration abuse"},
    "takeover":          {"color": "#e74c3c", "weight": 3, "description": "Subdomain/resource takeover"},
    "ssrf":              {"color": "#c0392b", "weight": 2, "description": "SSRF internal access"},
    "scan":              {"color": "#95a5a6", "weight": 1, "description": "Passive recon / scanning"},
    "brute_force":       {"color": "#d35400", "weight": 2, "description": "Authentication brute force"},
    "injection":         {"color": "#e74c3c", "weight": 3, "description": "Injection attack (SQLi/SSTI/CMDi)"},
    "data_exfil":        {"color": "#c0392b", "weight": 3, "description": "Data exfiltration"},
    "lateral_movement":  {"color": "#8e44ad", "weight": 2, "description": "Lateral movement"},
    "privilege_escalation": {"color": "#d35400", "weight": 2, "description": "Privilege escalation"},
}

# Severity → numeric for path scoring
SEVERITY_WEIGHT = {
    "critical": 10,
    "high":     7,
    "medium":   4,
    "low":      2,
    "info":     1,
}

# Service → target asset mapping
SERVICE_TO_TARGET = {
    "mysql":         "target_data",
    "postgresql":    "target_data",
    "mssql":         "target_data",
    "oracle":        "target_data",
    "mongodb":       "target_data",
    "redis":         "target_data",
    "elasticsearch": "target_data",
    "ssh":           "target_infrastructure",
    "rdp":           "target_infrastructure",
    "smb":           "target_infrastructure",
    "ftp":           "target_data",
    "telnet":        "target_infrastructure",
    "vnc":           "target_infrastructure",
    "ldap":          "target_credentials",
}

# Vuln class → edge type
VULN_TO_EDGE = {
    "sqli":               "injection",
    "sqli_mysql":         "injection",
    "sqli_mssql":         "injection",
    "sqli_postgres":      "injection",
    "sqli_oracle":        "injection",
    "xss":                "exploit",
    "ssti":               "injection",
    "ssrf":               "ssrf",
    "cmdi":               "injection",
    "xxe":                "exploit",
    "nosql":              "injection",
    "path_traversal":     "exploit",
    "jwt_attacks":        "credential_reuse",
    "graphql":            "exploit",
    "http_request_smuggling": "exploit",
    "open_redirect":      "phishing",
    "csrf":               "exploit",
    "idor":               "exploit",
}


# ---------------------------------------------------------------------------
# Graph primitives
# ---------------------------------------------------------------------------

class Node:
    __slots__ = ("node_id", "label", "node_type", "asset", "metadata",
                 "risk_score", "layer", "reachable_from_internet")

    def __init__(
        self,
        node_id:   str,
        label:     str,
        node_type: str,
        asset:     str = "",
        metadata:  Optional[Dict] = None,
        risk_score: float = 0.0,
    ):
        self.node_id   = node_id
        self.label     = label
        self.node_type = node_type
        self.asset     = asset
        self.metadata  = metadata or {}
        self.risk_score = risk_score
        self.layer     = NODE_TYPES.get(node_type, {}).get("layer", 2)
        self.reachable_from_internet = (self.layer <= 1)

    def to_dict(self) -> Dict:
        return {
            "node_id":    self.node_id,
            "label":      self.label,
            "node_type":  self.node_type,
            "icon":       NODE_TYPES.get(self.node_type, {}).get("icon", "●"),
            "layer":      self.layer,
            "asset":      self.asset,
            "risk_score": round(self.risk_score, 2),
            "reachable_from_internet": self.reachable_from_internet,
            "metadata":   self.metadata,
        }


class Edge:
    __slots__ = ("edge_id", "source_id", "target_id", "edge_type",
                 "technique", "severity", "probability", "prerequisites",
                 "evidence", "tools")

    def __init__(
        self,
        source_id:    str,
        target_id:    str,
        edge_type:    str,
        technique:    str,
        severity:     str = "medium",
        probability:  float = 0.5,
        prerequisites: Optional[List[str]] = None,
        evidence:     Optional[Dict] = None,
        tools:        Optional[List[str]] = None,
    ):
        raw = f"{source_id}|{target_id}|{edge_type}|{technique}"
        self.edge_id      = hashlib.md5(raw.encode()).hexdigest()[:10]
        self.source_id    = source_id
        self.target_id    = target_id
        self.edge_type    = edge_type
        self.technique    = technique
        self.severity     = severity
        self.probability  = probability
        self.prerequisites = prerequisites or []
        self.evidence     = evidence or {}
        self.tools        = tools or []

    def to_dict(self) -> Dict:
        return {
            "edge_id":      self.edge_id,
            "source":       self.source_id,
            "target":       self.target_id,
            "edge_type":    self.edge_type,
            "color":        EDGE_TYPES.get(self.edge_type, {}).get("color", "#95a5a6"),
            "weight":       EDGE_TYPES.get(self.edge_type, {}).get("weight", 1),
            "technique":    self.technique,
            "severity":     self.severity,
            "probability":  round(self.probability, 2),
            "prerequisites": self.prerequisites,
            "evidence":     self.evidence,
            "tools":        self.tools,
        }


class AttackGraph:
    """Directed graph — nodes are assets, edges are attack techniques."""

    def __init__(self):
        self._nodes: Dict[str, Node]        = {}
        self._edges: Dict[str, Edge]        = {}
        self._adj:   Dict[str, Set[str]]    = defaultdict(set)   # source → {target_ids}
        self._radj:  Dict[str, Set[str]]    = defaultdict(set)   # target → {source_ids}

    # ── Mutation ──────────────────────────────────────────────────────

    def add_node(self, node: Node) -> None:
        if node.node_id not in self._nodes:
            self._nodes[node.node_id] = node

    def add_edge(self, edge: Edge) -> None:
        if edge.source_id not in self._nodes or edge.target_id not in self._nodes:
            return
        if edge.edge_id not in self._edges:
            self._edges[edge.edge_id] = edge
            self._adj[edge.source_id].add(edge.target_id)
            self._radj[edge.target_id].add(edge.source_id)

    def get_node(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id)

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def has_edge(self, source_id: str, target_id: str) -> bool:
        return target_id in self._adj.get(source_id, set())

    # ── Path finding ──────────────────────────────────────────────────
    
    def all_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 6,
    ) -> List[List[str]]:
        """BFS — find all simple paths from source to target up to max_depth."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return []
            
        paths:   List[List[str]] = []
        queue:   deque           = deque([(source_id, [source_id])])
        
        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue
            for neighbour in self._adj.get(current, set()):
                if neighbour in path:   # avoid cycles
                    continue
                new_path = path + [neighbour]
                if neighbour == target_id:
                    paths.append(new_path)
                else:
                    queue.append((neighbour, new_path))
                    
        return paths
        
    def shortest_path(self, source_id: str, target_id: str) -> Optional[List[str]]:
        """BFS shortest hop path."""
        paths = self.all_paths(source_id, target_id)
        if not paths:
            return None
        return min(paths, key=len)
        
    def reachable_targets(self, source_id: str) -> Set[str]:
        """All nodes reachable from source via BFS."""
        visited: Set[str] = set()
        queue: deque       = deque([source_id])
        while queue:
            node_id = queue.popleft()
            if node_id in visited:
                continue
            visited.add(node_id)
            for n in self._adj.get(node_id, set()):
                if n not in visited:
                    queue.append(n)
        visited.discard(source_id)
        return visited
        
    def critical_path_score(self, path: List[str]) -> float:
        """Score a path: sum of edge severity weights × edge probability."""
        score = 0.0
        for i in range(len(path) - 1):
            src, tgt = path[i], path[i + 1]
            for edge in self._edges.values():
                if edge.source_id == src and edge.target_id == tgt:
                    score += SEVERITY_WEIGHT.get(edge.severity, 2) * edge.probability
                    break
        # Shorter path = more dangerous
        length_bonus = max(0, (7 - len(path)) * 0.5)
        return score + length_bonus

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> Dict:
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges.values()],
            "node_count": len(self._nodes),
            "edge_count":  len(self._edges),
        }

    def nodes_by_layer(self) -> Dict[int, List[Dict]]:
        result: Dict[int, List[Dict]] = defaultdict(list)
        for node in self._nodes.values():
            result[node.layer].append(node.to_dict())
        return dict(result)

    def stats(self) -> Dict:
        layers = defaultdict(int)
        for n in self._nodes.values():
            layers[n.layer] += 1
        edge_types = defaultdict(int)
        for e in self._edges.values():
            edge_types[e.edge_type] += 1
        return {
            "total_nodes":   len(self._nodes),
            "total_edges":   len(self._edges),
            "nodes_by_layer": dict(layers),
            "edges_by_type":  dict(edge_types),
        }


# ---------------------------------------------------------------------------
# Main planner
# ---------------------------------------------------------------------------

class AIAttackPathPlanner:
    """
    Builds a directed attack-path graph from all ARTEX scan_results sources.

    Pass 1 — deterministic graph construction:
        Reads every confirmed scan_results key, creates typed nodes for each
        asset and typed directed edges for each known attack technique between
        them. Runs BFS to enumerate all viable paths from internet entry points
        to target-asset nodes. Scores each path.

    Pass 2 — Groq AI enrichment:
        Sends the top-N scored paths + graph stats to Groq.
        Groq returns: narrative per critical path, attacker profiling,
        MITRE ATT&CK technique mapping, detection opportunities per edge.

    Slot in run_scan() as last step before ai_analysis:

        planner = AIAttackPathPlanner(groq_api_key=GROQ_API_KEY)
        scan_results[scan_id]['attack_path_graph'] = planner.plan(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    # Shared internet entry node — every attack starts here
    INTERNET_NODE_ID = "node__internet"

    def __init__(
        self,
        groq_api_key: Optional[str] = None,
        timeout:      int = 12,
        max_paths_per_target: int = 5,
    ):
        self.groq_api_key         = groq_api_key
        self.timeout              = timeout
        self.max_paths_per_target = max_paths_per_target
        self.logger = logging.getLogger(__name__)

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

    def plan(self, domain: str, scan_results: Dict) -> Dict:
        """
        Args:
            domain:       Primary target domain string.
            scan_results: Full ARTEX scan_results dict for this scan_id.

        Returns dict with keys:
            graph               — full node/edge graph dict
            graph_stats         — {total_nodes, total_edges, nodes_by_layer, edges_by_type}
            nodes_by_layer      — {0:[...], 1:[...], 2:[...], 3:[...], 4:[...]}
            attack_paths        — all viable entry→target paths, scored and annotated
            critical_paths      — top 5 highest-scored paths
            target_nodes        — list of target-layer node dicts
            entry_nodes         — list of layer-0/1 entry node dicts
            path_summary        — counts, severity distribution
            ai_analysis         — Groq narrative (or None)
            scan_metadata
        """
        self.logger.info(f"Attack path planning — domain: {domain}")
        start = time.time()

        graph = AttackGraph()

        # ── Step 1: seed the shared internet entry node ───────────────
        internet_node = Node(
            node_id    = self.INTERNET_NODE_ID,
            label      = "Internet (Attacker)",
            node_type  = "internet_entry",
            asset      = "external",
            risk_score = 0.0,
        )
        graph.add_node(internet_node)

        # ── Step 2: build nodes and edges from each source ────────────
        self._build_from_subdomains(graph, scan_results)
        self._build_from_port_scan(graph, scan_results)
        self._build_from_ssl_scan(graph, scan_results)
        self._build_from_email_enumeration(graph, scan_results)
        self._build_from_takeover_analysis(graph, scan_results)
        self._build_from_payload_analysis(graph, scan_results)
        self._build_from_osint_correlation(graph, scan_results)
        self._build_from_header_analysis(graph, scan_results)
        self._build_from_vuln_prioritization(graph, scan_results)
        self._build_from_security_analysis(graph, scan_results)
        self._build_target_nodes(graph, scan_results, domain)

        self.logger.info(
            f"Graph built: {graph.stats()['total_nodes']} nodes, "
            f"{graph.stats()['total_edges']} edges"
        )

        # ── Step 3: enumerate attack paths ────────────────────────────
        entry_nodes  = [n for n in graph._nodes.values() if n.layer <= 1]
        target_nodes = [n for n in graph._nodes.values() if n.layer == 4]

        attack_paths = self._enumerate_paths(graph, entry_nodes, target_nodes)

        # ── Step 4: score and sort paths ──────────────────────────────
        for path in attack_paths:
            path["score"] = round(
                graph.critical_path_score(path["node_ids"]), 2
            )
        attack_paths.sort(key=lambda x: x["score"], reverse=True)

        critical_paths = attack_paths[:5]

        # ── Step 5: path summary ──────────────────────────────────────
        path_summary = self._summarise_paths(attack_paths)

        # ── Step 6: AI enrichment ─────────────────────────────────────
        ai_result = None
        if self.groq_api_key and critical_paths:
            ai_result = self._ai_analysis(
                domain, graph, critical_paths,
                entry_nodes, target_nodes, path_summary
            )

        duration = round(time.time() - start, 2)
        self.logger.info(f"Path planning complete in {duration}s — {len(attack_paths)} paths found")

        return {
            "graph":          graph.to_dict(),
            "graph_stats":    graph.stats(),
            "nodes_by_layer": graph.nodes_by_layer(),
            "attack_paths":   attack_paths[:30],     # cap output
            "critical_paths": critical_paths,
            "target_nodes":   [n.to_dict() for n in target_nodes],
            "entry_nodes":    [n.to_dict() for n in entry_nodes],
            "path_summary":   path_summary,
            "ai_analysis":    ai_result,
            "scan_metadata":  {
                "domain":                domain,
                "scan_duration_seconds": duration,
                "timestamp":             datetime.now().isoformat(),
                "ai_model":              "Groq Llama3-70B" if ai_result else "Rule-based only",
            },
        }

    # ------------------------------------------------------------------
    # Node ID helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _nid(prefix: str, label: str) -> str:
        slug = label.lower().replace(" ", "_").replace(".", "_").replace("/", "_")[:40]
        return f"node__{prefix}__{slug}"

    # ------------------------------------------------------------------
    # Graph builders — one per scan_results source
    # ------------------------------------------------------------------

    def _build_from_subdomains(self, graph: AttackGraph, sr: Dict) -> None:
        """
        subdomains -> [{subdomain, ip, http_status, https_status, title}]
        Creates a web node per active subdomain + edge from internet.
        """
        for sub in sr.get("subdomains", []):
            if not isinstance(sub, dict):
                continue
            name        = sub.get("subdomain", "")
            http_status = sub.get("http_status")
            https_status = sub.get("https_status")

            if not (http_status or https_status):
                continue   # not reachable

            # Classify node type by subdomain name
            node_type = "subdomain_web"
            name_lower = name.lower()
            if any(k in name_lower for k in ["admin", "cpanel", "whm", "plesk", "phpmyadmin"]):
                node_type = "admin_panel"
            elif any(k in name_lower for k in ["api", "rest", "graphql", "service", "ws"]):
                node_type = "api_endpoint"
            elif any(k in name_lower for k in ["mail", "smtp", "exchange", "webmail"]):
                node_type = "mail_server"

            risk = 0.0
            if http_status in (401, 403):
                risk += 30
            if https_status in (401, 403):
                risk += 30
            if node_type == "admin_panel":
                risk += 40

            nid = self._nid("sub", name)
            node = Node(
                node_id    = nid,
                label      = name,
                node_type  = node_type,
                asset      = name,
                risk_score = risk,
                metadata   = {
                    "ip":           sub.get("ip", ""),
                    "http_status":  http_status,
                    "https_status": https_status,
                    "title":        sub.get("title", ""),
                },
            )
            graph.add_node(node)
            
            # Edge: internet -> subdomain
            edge_type   = "exploit" if node_type == "admin_panel" else "scan"
            probability = 0.9 if (http_status == 200 or https_status == 200) else 0.6
            tools       = ["Browser", "curl", "Burp Suite"]
            if node_type == "admin_panel":
                tools = ["Burp Suite", "Hydra", "ffuf"]

            graph.add_edge(Edge(
                source_id   = self.INTERNET_NODE_ID,
                target_id   = nid,
                edge_type   = edge_type,
                technique   = f"Direct HTTP access to {name} (status {http_status or https_status})",
                severity    = "high" if node_type == "admin_panel" else "medium",
                probability = probability,
                evidence    = {"http_status": http_status, "https_status": https_status},
                tools       = tools,
            ))

    def _build_from_port_scan(self, graph: AttackGraph, sr: Dict) -> None:
        """
        port_scan -> [{target, ports:[{port,service,state,risk}],
                      risky_ports, vulnerabilities, os_guess}]
        Creates exposed_port nodes and internet->port edges.
        For services that map to target assets, adds port->target edges.
        """
        for host_data in sr.get("port_scan", []):
            if not isinstance(host_data, dict):
                continue
            target = host_data.get("target", "")

            # Try to find or create a node for this host
            # It may already exist as a subdomain node
            host_nid = self._nid("sub", target)
            if not graph.has_node(host_nid):
                host_nid = self._nid("port_host", target)
                graph.add_node(Node(
                    node_id    = host_nid,
                    label      = target,
                    node_type  = "subdomain_web",
                    asset      = target,
                    risk_score = 20.0,
                    metadata   = {"os_guess": host_data.get("os_guess", "")},
                ))
                graph.add_edge(Edge(
                    source_id   = self.INTERNET_NODE_ID,
                    target_id   = host_nid,
                    edge_type   = "scan",
                    technique   = f"Network reachability to {target}",
                    severity    = "low",
                    probability = 0.9,
                    tools       = ["nmap"],
                ))

            # Risky ports -> exposed_port nodes -> target asset edges
            for rp in host_data.get("risky_ports", []):
                if not isinstance(rp, dict):
                    continue
                port    = rp.get("port")
                service = rp.get("service", f"port-{port}").lower()
                version = rp.get("version", "")
                risk_obj = rp.get("risk", {})
                risk_lvl = risk_obj.get("level", "medium") if isinstance(risk_obj, dict) else "medium"

                port_nid = self._nid("port", f"{target}_{port}")
                graph.add_node(Node(
                    node_id    = port_nid,
                    label      = f"{service.upper()}:{port} on {target}",
                    node_type  = "exposed_port",
                    asset      = f"{target}:{port}",
                    risk_score = SEVERITY_WEIGHT.get(risk_lvl, 4) * 10.0,
                    metadata   = {
                        "port":    port,
                        "service": service,
                        "version": version,
                        "host":    target,
                    },
                ))

                # Internet -> port
                graph.add_edge(Edge(
                    source_id   = self.INTERNET_NODE_ID,
                    target_id   = port_nid,
                    edge_type   = "exploit",
                    technique   = f"Direct connection to {service.upper()} port {port} on {target}",
                    severity    = risk_lvl,
                    probability = 0.95,
                    tools       = self._tools_for_service(service),
                    evidence    = {"port": port, "service": service, "version": version},
                ))

                # Port -> target asset
                target_asset_type = SERVICE_TO_TARGET.get(service.lower())
                if target_asset_type:
                    asset_nid = self._nid("target", target_asset_type)
                    if not graph.has_node(asset_nid):
                        graph.add_node(Node(
                            node_id    = asset_nid,
                            label      = NODE_TYPES[target_asset_type]["description"],
                            node_type  = target_asset_type,
                            asset      = target_asset_type,
                            risk_score = 90.0,
                        ))

                    technique_map = {
                        "mysql": "SQL queries / credential brute-force → data dump",
                        "redis": "Unauthenticated Redis commands → CONFIG SET / SLAVEOF",
                        "mongodb": "No-auth MongoDB → db.collection.find() data dump",
                        "ssh": "SSH brute-force / key theft → interactive shell",
                        "rdp": "RDP brute-force / credential stuffing → desktop access",
                        "smb": "EternalBlue / credential relay → file system access",
                        "mssql": "xp_cmdshell / SQLi → OS command execution",
                        "postgresql": "COPY TO/FROM PROGRAM → OS RCE",
                        "ftp": "Anonymous FTP / credential brute-force → file access",
                    }
                    edge_tech = technique_map.get(
                        service.lower(),
                        f"{service.upper()} exploitation → target asset access"
                    )

                    graph.add_edge(Edge(
                        source_id    = port_nid,
                        target_id    = asset_nid,
                        edge_type    = "exploit",
                        technique    = edge_tech,
                        severity     = risk_lvl,
                        probability  = 0.70,
                        prerequisites = [f"Access to port {port}"],
                        tools        = self._tools_for_service(service),
                    ))

                # Also link host node -> port node (host discovery → service exploitation)
                if not graph.has_edge(host_nid, port_nid):
                    graph.add_edge(Edge(
                        source_id  = host_nid,
                        target_id  = port_nid,
                        edge_type  = "pivot",
                        technique  = f"Service enumeration reveals {service.upper()} on port {port}",
                        severity   = "low",
                        probability = 0.95,
                        tools      = ["nmap", "masscan"],
                    ))

            # nmap vuln script findings -> inject into graph as high-severity edges
            for vuln in host_data.get("vulnerabilities", []):
                if not isinstance(vuln, dict):
                    continue
                cve_id  = vuln.get("cve") or vuln.get("id", "UNKNOWN")
                risk    = vuln.get("risk", "high").lower()
                target_type = "target_infrastructure"

                target_nid = self._nid("target", target_type)
                if not graph.has_node(target_nid):
                    graph.add_node(Node(
                        node_id    = target_nid,
                        label      = NODE_TYPES[target_type]["description"],
                        node_type  = target_type,
                        asset      = target_type,
                        risk_score = 95.0,
                    ))

                graph.add_edge(Edge(
                    source_id   = host_nid,
                    target_id   = target_nid,
                    edge_type   = "exploit",
                    technique   = f"CVE exploit: {cve_id} — {vuln.get('title', 'nmap detection')}",
                    severity    = risk,
                    probability = 0.85,
                    evidence    = {"cve": cve_id, "description": vuln.get("description", "")[:120]},
                    tools       = ["Metasploit", "exploit-db", "custom PoC"],
                ))

    def _build_from_ssl_scan(self, graph: AttackGraph, sr: Dict) -> None:
        """
        ssl_scan → {host: {vulnerabilities:{heartbleed:bool,...}, grade, protocols}}
        Adds exploit edges from subdomain → credential/data target for active SSL CVEs.
        """
        ssl_scan = sr.get("ssl_scan", {})
        if not isinstance(ssl_scan, dict):
            return

        ssl_cve_severity = {
            "heartbleed":   ("critical", 0.90),
            "poodle":       ("high",     0.65),
            "freak":        ("high",     0.70),
            "drown":        ("high",     0.65),
            "ccs_injection":("high",     0.75),
            "sweet32":      ("medium",   0.50),
            "beast":        ("medium",   0.45),
            "logjam":       ("medium",   0.55),
            "crime":        ("medium",   0.50),
            "breach":       ("medium",   0.50),
            "lucky13":      ("low",      0.35),
        }

        deprecated_protocols = {
            "SSLv2":   ("critical", 0.95),
            "SSLv3":   ("high",     0.80),
            "TLSv1":   ("medium",   0.65),
            "TLSv1.1": ("low",      0.45),
        }

        for host, ssl_data in ssl_scan.items():
            if not isinstance(ssl_data, dict):
                continue

            host_nid = self._nid("sub", host)
            if not graph.has_node(host_nid):
                continue   # only add SSL edges to already-known hosts

            cred_target_nid = self._nid("target", "target_credentials")
            if not graph.has_node(cred_target_nid):
                graph.add_node(Node(
                    node_id    = cred_target_nid,
                    label      = NODE_TYPES["target_credentials"]["description"],
                    node_type  = "target_credentials",
                    asset      = "target_credentials",
                    risk_score = 90.0,
                ))

            # SSL CVEs
            for cve_key, is_vuln in ssl_data.get("vulnerabilities", {}).items():
                if not is_vuln:
                    continue
                sev, prob = ssl_cve_severity.get(cve_key, ("medium", 0.5))
                graph.add_edge(Edge(
                    source_id   = host_nid,
                    target_id   = cred_target_nid,
                    edge_type   = "exploit",
                    technique   = f"SSL/TLS exploit: {cve_key.upper()} — MITM session decryption",
                    severity    = sev,
                    probability = prob,
                    evidence    = {
                        "cve_key":  cve_key,
                        "ssl_grade": ssl_data.get("grade", "?"),
                    },
                    tools       = ["testssl.sh", "sslscan", "BEAST PoC", "Heartbleeder"],
                ))

            # Deprecated protocols
            for proto, (sev, prob) in deprecated_protocols.items():
                if ssl_data.get("protocols", {}).get(proto, False):
                    graph.add_edge(Edge(
                        source_id   = host_nid,
                        target_id   = cred_target_nid,
                        edge_type   = "exploit",
                        technique   = f"Deprecated {proto} enabled — downgrade + MITM attack",
                        severity    = sev,
                        probability = prob,
                        evidence    = {"protocol": proto},
                        tools       = ["testssl.sh", "openssl s_client"],
                    ))

    def _build_from_email_enumeration(self, graph: AttackGraph, sr: Dict) -> None:
        """
        email_enumeration → {found_emails:[{email,type,confidence}],
                             login_pages:[{url,type,source}],
                             password_reset_pages:[{url}],
                             email_formats:[{pattern,confidence}]}
        """
        email_enum = sr.get("email_enumeration", {})
        if not isinstance(email_enum, dict):
            return

        # Email attack surface node
        if email_enum.get("found_emails") or email_enum.get("email_formats"):
            email_nid = self._nid("surface", "email")
            if not graph.has_node(email_nid):
                graph.add_node(Node(
                    node_id    = email_nid,
                    label      = "Email Attack Surface (phishing / spoofing)",
                    node_type  = "email_surface",
                    asset      = "email",
                    risk_score = 60.0,
                    metadata   = {
                        "email_count":   len(email_enum.get("found_emails", [])),
                        "email_formats": [f["pattern"] for f in email_enum.get("email_formats", [])[:3]],
                    },
                ))
                graph.add_edge(Edge(
                    source_id   = self.INTERNET_NODE_ID,
                    target_id   = email_nid,
                    edge_type   = "phishing",
                    technique   = "Phishing / spear-phishing using harvested employee emails",
                    severity    = "high",
                    probability = 0.75,
                    tools       = ["GoPhish", "setoolkit", "evilginx2"],
                ))

            # Email surface -> credential target
            cred_nid = self._nid("target", "target_credentials")
            if not graph.has_node(cred_nid):
                graph.add_node(Node(
                    node_id    = cred_nid,
                    label      = NODE_TYPES["target_credentials"]["description"],
                    node_type  = "target_credentials",
                    asset      = "target_credentials",
                    risk_score = 90.0,
                ))
            graph.add_edge(Edge(
                source_id    = email_nid,
                target_id    = cred_nid,
                edge_type    = "phishing",
                technique    = "Credential harvest via phishing page mimicking internal login",
                severity     = "high",
                probability  = 0.60,
                prerequisites = ["Valid email list", "Convincing lure"],
                tools        = ["evilginx2", "modlishka", "GoPhish"],
            ))

        # Login pages -> web_app nodes
        for lp in email_enum.get("login_pages", []):
            if not isinstance(lp, dict):
                continue
            url = lp.get("url", "")
            if not url:
                continue
            lp_nid = self._nid("login", url)
            if not graph.has_node(lp_nid):
                graph.add_node(Node(
                    node_id    = lp_nid,
                    label      = f"Login page: {url[:60]}",
                    node_type  = "login_page",
                    asset      = url,
                    risk_score = 55.0,
                    metadata   = {"url": url, "type": lp.get("type", "")},
                ))
                graph.add_edge(Edge(
                    source_id   = self.INTERNET_NODE_ID,
                    target_id   = lp_nid,
                    edge_type   = "scan",
                    technique   = f"Direct navigation to login page at {url[:60]}",
                    severity    = "medium",
                    probability = 0.95,
                    tools       = ["Browser", "curl"],
                ))

            # Login page -> credential brute force -> target
            cred_nid = self._nid("target", "target_credentials")
            if graph.has_node(cred_nid):
                graph.add_edge(Edge(
                    source_id    = lp_nid,
                    target_id    = cred_nid,
                    edge_type    = "brute_force",
                    technique    = "Credential stuffing / password spray against login form",
                    severity     = "high",
                    probability  = 0.45,
                    prerequisites = ["Credential list", "No rate-limiting detected"],
                    tools        = ["Hydra", "Burp Intruder", "ffuf", "spray.sh"],
                ))

    def _build_from_takeover_analysis(self, graph: AttackGraph, sr: Dict) -> None:
        """
        takeover_analysis → {vulnerable:[{subdomain,service,confidence_level,
                             cname_chain,takeover_method,http_evidence,difficulty}],
                             dangling_dns:[{subdomain,dangling_reason,cname_chain}]}
        """
        ta = sr.get("takeover_analysis", {})
        if not isinstance(ta, dict):
            return

        for entry in ta.get("vulnerable", []):
            if not isinstance(entry, dict):
                continue
            sub        = entry.get("subdomain", "")
            service    = entry.get("service", "unknown")
            confidence = entry.get("confidence_level", "medium")
            confirmed  = entry.get("http_evidence", {}).get("confirmed", False)

            nid = self._nid("takeover", sub)
            if not graph.has_node(nid):
                graph.add_node(Node(
                    node_id    = nid,
                    label      = f"Takeover: {sub} → {service}",
                    node_type  = "subdomain_takeover",
                    asset      = sub,
                    risk_score = 85.0 if confirmed else 65.0,
                    metadata   = {
                        "service":    service,
                        "confidence": confidence,
                        "confirmed":  confirmed,
                        "cname":      entry.get("cname_chain", []),
                        "method":     entry.get("takeover_method", ""),
                    },
                ))

            prob = {"high": 0.95, "medium": 0.75, "low": 0.55}.get(confidence, 0.65)

            # Internet -> takeover node
            graph.add_edge(Edge(
                source_id   = self.INTERNET_NODE_ID,
                target_id   = nid,
                edge_type   = "takeover",
                technique   = f"Register unclaimed {service} resource for {sub}",
                severity    = "high" if confirmed else "medium",
                probability = prob,
                evidence    = {
                    "service":   service,
                    "confirmed": confirmed,
                    "cname":     entry.get("cname_chain", [])[:3],
                },
                tools       = ["Browser", "curl", f"{service} account registration"],
            ))

            # Takeover -> domain control target
            domain_ctrl_nid = self._nid("target", "target_domain_control")
            if not graph.has_node(domain_ctrl_nid):
                graph.add_node(Node(
                    node_id    = domain_ctrl_nid,
                    label      = NODE_TYPES["target_domain_control"]["description"],
                    node_type  = "target_domain_control",
                    asset      = "target_domain_control",
                    risk_score = 90.0,
                ))
            graph.add_edge(Edge(
                source_id    = nid,
                target_id    = domain_ctrl_nid,
                edge_type    = "takeover",
                technique    = f"Serve malicious content on trusted subdomain {sub} — cookie theft, phishing",
                severity     = "critical",
                probability  = 0.90,
                prerequisites = [f"Claim {service} resource"],
                tools        = ["Browser", "HTTPS cert (Let's Encrypt)"],
            ))

    def _build_from_payload_analysis(self, graph: AttackGraph, sr: Dict) -> None:
        """
        payload_analysis → {vuln_classes:[], tech_profile:{language,framework,database,cms},
                            waf_detected:{detected,name},
                            injection_points:[{surface,url,method,param_type,notes}]}
        """
        pa = sr.get("payload_analysis", {})
        if not isinstance(pa, dict):
            return

        vuln_classes    = pa.get("vuln_classes", [])
        tech_profile    = pa.get("tech_profile", {})
        waf             = pa.get("waf_detected", {})
        inj_points      = pa.get("injection_points", [])

        waf_note  = f" [WAF: {waf.get('name')}]" if waf.get("detected") else ""
        waf_prob_penalty = 0.75 if waf.get("detected") else 1.0

        for vc in vuln_classes:
            edge_type = VULN_TO_EDGE.get(vc, "exploit")

            # Pick the best injection point for this class
            best_ip = self._best_injection_point(inj_points, vc)
            if best_ip:
                ip_url  = best_ip.get("url", "")
                ip_nid  = self._nid("sub", ip_url) if ip_url else None

                # Create the injection-point node if not already present
                if ip_nid and not graph.has_node(ip_nid):
                    graph.add_node(Node(
                        node_id    = ip_nid,
                        label      = ip_url[:60],
                        node_type  = "api_endpoint" if "api" in best_ip.get("surface","") else "web_app",
                        asset      = ip_url,
                        risk_score = 50.0,
                        metadata   = best_ip,
                    ))
                    graph.add_edge(Edge(
                        source_id   = self.INTERNET_NODE_ID,
                        target_id   = ip_nid,
                        edge_type   = "scan",
                        technique   = f"HTTP access to {ip_url[:60]}",
                        severity    = "low",
                        probability = 0.9,
                        tools       = ["Browser", "curl"],
                    ))

                source_nid = ip_nid or self.INTERNET_NODE_ID
            else:
                source_nid = self.INTERNET_NODE_ID

            # Determine target asset node
            target_asset = self._vuln_class_to_target(vc)
            asset_nid    = self._nid("target", target_asset)
            if not graph.has_node(asset_nid):
                graph.add_node(Node(
                    node_id    = asset_nid,
                    label      = NODE_TYPES.get(target_asset, {}).get("description", target_asset),
                    node_type  = target_asset,
                    asset      = target_asset,
                    risk_score = 90.0,
                ))

            # Build technique string
            stack = f"{tech_profile.get('language','?')}/{tech_profile.get('framework','?')}"
            technique = f"{vc.upper()} on {stack} stack{waf_note}"

            sev   = "critical" if vc in ("ssti","cmdi","sqli_mssql") else \
                    "high"     if vc in ("sqli","sqli_mysql","sqli_postgres","ssrf","nosql") else \
                    "medium"

            prob  = {
                "critical": 0.65,
                "high":     0.55,
                "medium":   0.45,
            }.get(sev, 0.40) * waf_prob_penalty

            tools = self._tools_for_vuln_class(vc)

            if not graph.has_edge(source_nid, asset_nid):
                graph.add_edge(Edge(
                    source_id    = source_nid,
                    target_id    = asset_nid,
                    edge_type    = edge_type,
                    technique    = technique,
                    severity     = sev,
                    probability  = round(prob, 2),
                    prerequisites = [f"Injectable {vc.split('_')[0].upper()} parameter"],
                    evidence     = {
                        "vuln_class": vc,
                        "tech_stack": stack,
                        "waf":        waf.get("name") if waf.get("detected") else None,
                    },
                    tools        = tools,
                ))

    def _build_from_osint_correlation(self, graph: AttackGraph, sr: Dict) -> None:
        """
        osint_correlation → {credential_leaks:{github_hits:[{repo,file,secrets_found}],
                             secret_signals:[]}, dns_intelligence:{dmarc_analysis,spf_analysis}}
        """
        osint = sr.get("osint_correlation", {})
        if not isinstance(osint, dict):
            return

        # ── Credential leak nodes ─────────────────────────────────────
        cred_leaks = osint.get("credential_leaks", {})
        for hit in cred_leaks.get("github_hits", []):
            if not isinstance(hit, dict) or not hit.get("secrets_found"):
                continue

            leak_nid = self._nid("cred_leak", hit.get("repo", "unknown"))
            if not graph.has_node(leak_nid):
                graph.add_node(Node(
                    node_id    = leak_nid,
                    label      = f"Credential leak: {hit.get('repo','')[:50]}",
                    node_type  = "credential_leak",
                    asset      = hit.get("repo", ""),
                    risk_score = 88.0,
                    metadata   = {
                        "repo":     hit.get("repo"),
                        "file":     hit.get("file"),
                        "secrets":  [s["type"] for s in hit.get("secrets_found", [])[:5]],
                    },
                ))
                graph.add_edge(Edge(
                    source_id   = self.INTERNET_NODE_ID,
                    target_id   = leak_nid,
                    edge_type   = "scan",
                    technique   = f"GitHub dork finds credentials in {hit.get('repo','')}",
                    severity    = "critical",
                    probability = 0.98,
                    tools       = ["GitHub search", "trufflehog", "gitleaks"],
                ))

            # Leak -> pivot to any service that accepts those credentials
            infra_nid = self._nid("target", "target_infrastructure")
            if not graph.has_node(infra_nid):
                graph.add_node(Node(
                    node_id    = infra_nid,
                    label      = NODE_TYPES["target_infrastructure"]["description"],
                    node_type  = "target_infrastructure",
                    asset      = "target_infrastructure",
                    risk_score = 95.0,
                ))
            graph.add_edge(Edge(
                source_id    = leak_nid,
                target_id    = infra_nid,
                edge_type    = "credential_reuse",
                technique    = "Reuse leaked credentials against SSH, cloud console, VPN, CI/CD",
                severity     = "critical",
                probability  = 0.70,
                prerequisites = ["Valid leaked credential"],
                tools        = ["ssh", "aws cli", "kubectl", "GitHub Actions"],
            ))

        # ── DNS weakness -> phishing amplification ────────────────────
        dns_intel = osint.get("dns_intelligence", {})
        if isinstance(dns_intel, dict):
            dmarc = dns_intel.get("dmarc_analysis", {}) or {}
            spf   = dns_intel.get("spf_analysis", {}) or {}

            weak_dns = (
                not dmarc.get("present", True) or
                dmarc.get("policy") == "none" or
                not spf.get("present", True) or
                spf.get("risk") == "high"
            )

            if weak_dns:
                email_nid = self._nid("surface", "email")
                if not graph.has_node(email_nid):
                    graph.add_node(Node(
                        node_id    = email_nid,
                        label      = "Email Attack Surface (phishing / spoofing)",
                        node_type  = "email_surface",
                        asset      = "email",
                        risk_score = 70.0,
                        metadata   = {
                            "dmarc_policy": dmarc.get("policy", "absent"),
                            "spf_risk":     spf.get("risk", "absent"),
                        },
                    ))
                    graph.add_edge(Edge(
                        source_id   = self.INTERNET_NODE_ID,
                        target_id   = email_nid,
                        edge_type   = "dns_abuse",
                        technique   = "Send spoofed email impersonating domain — DMARC/SPF not enforced",
                        severity    = "high",
                        probability = 0.90,
                        tools       = ["swaks", "sendmail", "GoPhish"],
                    ))

        # ── Cloud IPs -> cloud metadata SSRF path ─────────────────────
        infra = osint.get("infrastructure", {})
        for cloud_ip in infra.get("cloud_ips", [])[:3]:
            provider = cloud_ip.get("provider", "")
            if not provider:
                continue
            meta_nid = self._nid("cloud_meta", provider.replace(" ", "_"))
            if not graph.has_node(meta_nid):
                graph.add_node(Node(
                    node_id    = meta_nid,
                    label      = f"Cloud IMDS: {provider}",
                    node_type  = "cloud_metadata",
                    asset      = f"cloud_metadata_{provider}",
                    risk_score = 75.0,
                    metadata   = {"provider": provider, "ip": cloud_ip.get("ip")},
                ))

            infra_nid = self._nid("target", "target_infrastructure")
            if not graph.has_node(infra_nid):
                graph.add_node(Node(
                    node_id    = infra_nid,
                    label      = NODE_TYPES["target_infrastructure"]["description"],
                    node_type  = "target_infrastructure",
                    asset      = "target_infrastructure",
                    risk_score = 95.0,
                ))
            graph.add_edge(Edge(
                source_id    = meta_nid,
                target_id    = infra_nid,
                edge_type    = "ssrf",
                technique    = f"SSRF → {provider} IMDS → IAM credential exfiltration",
                severity     = "critical",
                probability  = 0.80,
                prerequisites = ["SSRF vulnerability confirmed"],
                tools        = ["curl", "Burp Collaborator"],
            ))

    def _build_from_header_analysis(self, graph: AttackGraph, sr: Dict) -> None:
        """
        header_analysis → {targets:{url:{findings:[{type,header,severity,attack_class}]}}}
        Adds edges for CORS wildcard, CSP bypass, cookie theft chains.
        """
        ha = sr.get("header_analysis", {})
        if not isinstance(ha, dict):
            return

        for url, target_data in ha.get("targets", {}).items():
            if not isinstance(target_data, dict) or not target_data.get("reachable", True):
                continue

            host_nid = self._nid("sub", url)
            if not graph.has_node(host_nid):
                continue   # only annotate already-known nodes

            for finding in target_data.get("findings", []):
                if not isinstance(finding, dict):
                    continue
                sev        = finding.get("severity", "low")
                f_type     = finding.get("type", "")
                attack_cls = finding.get("attack_class", [])

                if sev not in ("critical", "high", "medium"):
                    continue   # skip low/info to keep graph lean

                # CORS misconfiguration -> XSS / data theft path
                if f_type in ("cors_wildcard", "cors_credentials_wildcard", "cors_null_origin"):
                    cred_nid = self._nid("target", "target_credentials")
                    if not graph.has_node(cred_nid):
                        graph.add_node(Node(
                            node_id=cred_nid, label=NODE_TYPES["target_credentials"]["description"],
                            node_type="target_credentials", asset="target_credentials", risk_score=90.0,
                        ))
                    graph.add_edge(Edge(
                        source_id    = host_nid,
                        target_id    = cred_nid,
                        edge_type    = "exploit",
                        technique    = f"CORS {f_type}: attacker origin reads cross-origin responses including session tokens",
                        severity     = sev,
                        probability  = 0.70,
                        evidence     = {"header": finding.get("header"), "type": f_type, "url": url},
                        tools        = ["Browser fetch()", "Burp Suite", "CORScanner"],
                    ))

                # Missing CSP -> XSS -> cookie exfil
                if f_type in ("missing_security_header",) and finding.get("header") == "Content-Security-Policy":
                    data_nid = self._nid("target", "target_data")
                    if not graph.has_node(data_nid):
                        graph.add_node(Node(
                            node_id=data_nid, label=NODE_TYPES["target_data"]["description"],
                            node_type="target_data", asset="target_data", risk_score=85.0,
                        ))
                    graph.add_edge(Edge(
                        source_id  = host_nid,
                        target_id  = data_nid,
                        edge_type  = "exploit",
                        technique  = "No CSP → XSS unrestricted → document.cookie / localStorage exfiltration",
                        severity   = "high",
                        probability = 0.65,
                        evidence   = {"header": "Content-Security-Policy", "url": url},
                        tools      = ["Burp Suite", "dalfox", "XSSHunter"],
                    ))

                # Missing HSTS -> SSL strip -> MITM
                if f_type in ("missing_security_header", "weak_hsts") and "Strict-Transport-Security" in finding.get("header", ""):
                    cred_nid = self._nid("target", "target_credentials")
                    if not graph.has_node(cred_nid):
                        graph.add_node(Node(
                            node_id=cred_nid, label=NODE_TYPES["target_credentials"]["description"],
                            node_type="target_credentials", asset="target_credentials", risk_score=90.0,
                        ))
                    graph.add_edge(Edge(
                        source_id  = host_nid,
                        target_id  = cred_nid,
                        edge_type  = "exploit",
                        technique  = "Missing/weak HSTS → SSL strip attack → plaintext credential interception",
                        severity   = "high",
                        probability = 0.55,
                        evidence   = {"header": "Strict-Transport-Security", "url": url},
                        tools      = ["sslstrip", "mitmproxy", "Bettercap"],
                    ))

    def _build_from_vuln_prioritization(self, graph: AttackGraph, sr: Dict) -> None:
        """
        vuln_prioritization → {findings:[{vuln_id,title,severity,final_score,source,
                               affected_asset,business_tags,attack_vector}],
                               attack_chains:[{chain_name,severity,steps,finding_sources}]}
        Annotates existing nodes with risk scores and adds edges from pre-computed chains.
        """
        vp = sr.get("vuln_prioritization", {})
        if not isinstance(vp, dict):
            return

        # Annotate node risk scores from prioritized findings
        for finding in vp.get("findings", []):
            if not isinstance(finding, dict):
                continue
            asset   = finding.get("affected_asset", "")
            score   = finding.get("final_score", 0.0)
            sev     = finding.get("severity", "low")

            # Try to find the matching node
            candidate_nid = self._nid("sub", asset)
            if graph.has_node(candidate_nid):
                n = graph.get_node(candidate_nid)
                if n:
                    n.risk_score = max(n.risk_score, score)

        # Add edges from pre-computed attack chains
        chain_source_map = {
            "credential_leak": self._nid("cred_leak", "github"),
            "subdomain_takeover": self._nid("takeover", ""),
            "port_exposure": self.INTERNET_NODE_ID,
            "payload_class": self.INTERNET_NODE_ID,
            "ssl_cve": self.INTERNET_NODE_ID,
        }

        for chain in vp.get("attack_chains", []):
            if not isinstance(chain, dict):
                continue
            chain_sev = chain.get("severity", "high")
            sources   = chain.get("finding_sources", [])

            # Create a chain pivot node
            chain_nid = self._nid("chain", chain.get("chain_name", "unknown")[:30])
            if not graph.has_node(chain_nid):
                graph.add_node(Node(
                    node_id    = chain_nid,
                    label      = f"⛓ {chain.get('chain_name', 'Attack Chain')}",
                    node_type  = "web_app",
                    asset      = chain.get("chain_name", ""),
                    risk_score = SEVERITY_WEIGHT.get(chain_sev, 7) * 10.0,
                    metadata   = {
                        "chain_name": chain.get("chain_name"),
                        "steps":      chain.get("steps", []),
                        "impact":     chain.get("impact", ""),
                    },
                ))

            # Wire first source -> chain node → target
            for src_key in sources[:1]:
                src_nid = chain_source_map.get(src_key, self.INTERNET_NODE_ID)
                if graph.has_node(src_nid):
                    graph.add_edge(Edge(
                        source_id  = src_nid,
                        target_id  = chain_nid,
                        edge_type  = "exploit",
                        technique  = f"Attack chain: {chain.get('chain_name','')}",
                        severity   = chain_sev,
                        probability = 0.70,
                        evidence   = {"chain": chain.get("chain_name"), "impact": chain.get("impact","")},
                    ))

            # Chain -> full_pwn target
            pwn_nid = self._nid("target", "target_full_pwn")
            if not graph.has_node(pwn_nid):
                graph.add_node(Node(
                    node_id    = pwn_nid,
                    label      = NODE_TYPES["target_full_pwn"]["description"],
                    node_type  = "target_full_pwn",
                    asset      = "target_full_pwn",
                    risk_score = 100.0,
                ))
            if not graph.has_edge(chain_nid, pwn_nid):
                graph.add_edge(Edge(
                    source_id  = chain_nid,
                    target_id  = pwn_nid,
                    edge_type  = "exploit",
                    technique  = chain.get("impact", "Full compromise"),
                    severity   = chain_sev,
                    probability = 0.65,
                ))

    def _build_from_security_analysis(self, graph: AttackGraph, sr: Dict) -> None:
        """
        security_analysis -> {high_value_targets:[{subdomain,security_score,risk_level,reasons}]}
        Upgrades node risk scores for critical/high targets already in graph.
        Adds admin_panel -> target_credentials edge for admin panels not yet wired.
        """
        sa = sr.get("security_analysis", {})
        if not isinstance(sa, dict):
            return

        for target in sa.get("high_value_targets", []):
            if not isinstance(target, dict):
                continue
            sub      = target.get("subdomain", "")
            risk_lvl = target.get("risk_level", "low").lower()
            if risk_lvl not in ("critical", "high"):
                continue
            score    = float(target.get("security_score", 0))
            reasons  = target.get("reasons", [])

            nid = self._nid("sub", sub)
            if graph.has_node(nid):
                n = graph.get_node(nid)
                if n:
                    n.risk_score = max(n.risk_score, score)
                    if "Admin" in " ".join(reasons) or any("admin" in r.lower() for r in reasons):
                        n.node_type = "admin_panel"

                    # Admin panel -> credential target
                    if n.node_type == "admin_panel":
                        cred_nid = self._nid("target", "target_credentials")
                        if not graph.has_node(cred_nid):
                            graph.add_node(Node(
                                node_id    = cred_nid,
                                label      = NODE_TYPES["target_credentials"]["description"],
                                node_type  = "target_credentials",
                                asset      = "target_credentials",
                                risk_score = 90.0,
                            ))
                        if not graph.has_edge(nid, cred_nid):
                            graph.add_edge(Edge(
                                source_id    = nid,
                                target_id    = cred_nid,
                                edge_type    = "brute_force",
                                technique    = f"Admin panel {sub} — credential brute-force / default password",
                                severity     = "high",
                                probability  = 0.55,
                                prerequisites = ["Access to admin panel"],
                                tools        = ["Burp Intruder", "Hydra", "Medusa"],
                            ))

    def _build_target_nodes(self, graph: AttackGraph, sr: Dict, domain: str) -> None:
        """
        Ensure all target-layer nodes that should exist do exist,
        even if no specific source created them yet.
        Connect any target nodes that have no incoming edges from full_pwn chain.
        """
        always_create = [
            "target_data",
            "target_credentials",
            "target_infrastructure",
        ]

        for t_type in always_create:
            nid = self._nid("target", t_type)
            if not graph.has_node(nid):
                graph.add_node(Node(
                    node_id    = nid,
                    label      = NODE_TYPES[t_type]["description"],
                    node_type  = t_type,
                    asset      = t_type,
                    risk_score = 90.0,
                ))

        # Lateral movement — infra -> data -> full_pwn
        infra_nid = self._nid("target", "target_infrastructure")
        data_nid  = self._nid("target", "target_data")
        pwn_nid   = self._nid("target", "target_full_pwn")

        if not graph.has_node(pwn_nid):
            graph.add_node(Node(
                node_id    = pwn_nid,
                label      = NODE_TYPES["target_full_pwn"]["description"],
                node_type  = "target_full_pwn",
                asset      = "target_full_pwn",
                risk_score = 100.0,
            ))

        if graph.has_node(infra_nid) and not graph.has_edge(infra_nid, pwn_nid):
            graph.add_edge(Edge(
                source_id  = infra_nid,
                target_id  = pwn_nid,
                edge_type  = "privilege_escalation",
                technique  = "Infrastructure access → privilege escalation → full domain/system compromise",
                severity   = "critical",
                probability = 0.80,
                tools      = ["linpeas", "winpeas", "BloodHound", "Mimikatz"],
            ))

        if graph.has_node(data_nid) and not graph.has_edge(data_nid, pwn_nid):
            graph.add_edge(Edge(
                source_id  = data_nid,
                target_id  = pwn_nid,
                edge_type  = "data_exfil",
                technique  = "Data store access → credential extraction → lateral movement → full compromise",
                severity   = "critical",
                probability = 0.75,
                tools      = ["sqlmap", "mongodump", "redis-cli"],
            ))

    # ------------------------------------------------------------------
    # Path enumeration
    # ------------------------------------------------------------------

    def _enumerate_paths(
        self,
        graph:        AttackGraph,
        entry_nodes:  List[Node],
        target_nodes: List[Node],
    ) -> List[Dict]:
        all_paths: List[Dict] = []
        seen_sigs: Set[str]   = set()

        for entry in entry_nodes:
            for target in target_nodes:
                if entry.node_id == target.node_id:
                    continue
                paths = graph.all_paths(
                    entry.node_id, target.node_id, max_depth=7
                )
                for path_ids in paths[:self.max_paths_per_target]:
                    sig = "->".join(path_ids)
                    if sig in seen_sigs:
                        continue
                    seen_sigs.add(sig)

                    # Collect edge data for the path
                    path_edges = []
                    for i in range(len(path_ids) - 1):
                        src, tgt = path_ids[i], path_ids[i + 1]
                        for edge in graph._edges.values():
                            if edge.source_id == src and edge.target_id == tgt:
                                path_edges.append(edge.to_dict())
                                break

                    # Build node label sequence
                    node_labels = []
                    for nid in path_ids:
                        n = graph.get_node(nid)
                        node_labels.append(n.label if n else nid)

                    # Worst severity along path
                    severities  = [e.get("severity","low") for e in path_edges]
                    worst_sev   = max(severities, key=lambda s: SEVERITY_WEIGHT.get(s, 2)) if severities else "low"

                    # Tools needed
                    all_tools: Set[str] = set()
                    for e in path_edges:
                        all_tools.update(e.get("tools", []))

                    all_paths.append({
                        "path_id":      hashlib.md5(sig.encode()).hexdigest()[:8],
                        "entry_node":   entry.node_id,
                        "target_node":  target.node_id,
                        "entry_label":  entry.label,
                        "target_label": target.label,
                        "node_ids":     path_ids,
                        "node_labels":  node_labels,
                        "edges":        path_edges,
                        "hop_count":    len(path_ids) - 1,
                        "worst_severity": worst_sev,
                        "tools_needed": sorted(all_tools),
                        "score":        0.0,   # filled in after
                    })

        return all_paths

    # ------------------------------------------------------------------
    # Path summary
    # ------------------------------------------------------------------

    def _summarise_paths(self, attack_paths: List[Dict]) -> Dict:
        if not attack_paths:
            return {"total_paths": 0}

        sev_counts: Dict[str, int] = defaultdict(int)
        hop_counts: List[int]      = []
        entry_freq: Dict[str, int] = defaultdict(int)
        target_freq: Dict[str, int] = defaultdict(int)

        for p in attack_paths:
            sev_counts[p["worst_severity"]] += 1
            hop_counts.append(p["hop_count"])
            entry_freq[p["entry_label"]] += 1
            target_freq[p["target_label"]] += 1

        return {
            "total_paths":          len(attack_paths),
            "severity_distribution": dict(sev_counts),
            "avg_hop_count":        round(sum(hop_counts) / len(hop_counts), 1),
            "min_hop_count":        min(hop_counts),
            "max_hop_count":        max(hop_counts),
            "top_entry_points":     sorted(entry_freq.items(), key=lambda x: x[1], reverse=True)[:5],
            "top_targets":          sorted(target_freq.items(), key=lambda x: x[1], reverse=True)[:5],
            "critical_path_count":  sum(1 for p in attack_paths if p["worst_severity"] == "critical"),
        }

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tools_for_service(service: str) -> List[str]:
        tool_map = {
            "ssh":   ["ssh", "Hydra", "Medusa", "patator"],
            "rdp":   ["xfreerdp", "Hydra", "rdesktop"],
            "mysql": ["mysql client", "sqlmap", "Hydra"],
            "postgresql": ["psql", "sqlmap", "Hydra"],
            "mssql": ["mssqlclient.py", "sqlmap", "Hydra"],
            "redis": ["redis-cli", "redis-rogue-server"],
            "mongodb": ["mongo", "mongodump"],
            "ftp":   ["ftp client", "Hydra", "anonymous login"],
            "smb":   ["smbclient", "CrackMapExec", "impacket"],
            "elasticsearch": ["curl", "Kibana console"],
            "vnc":   ["vncviewer", "Hydra"],
            "telnet": ["telnet client", "Hydra"],
        }
        return tool_map.get(service.lower(), ["nmap", "netcat", "Metasploit"])

    @staticmethod
    def _tools_for_vuln_class(vc: str) -> List[str]:
        tool_map = {
            "sqli":               ["sqlmap", "ghauri", "Burp Suite"],
            "sqli_mysql":         ["sqlmap", "ghauri", "MySQL client"],
            "sqli_mssql":         ["sqlmap", "mssqlclient.py"],
            "xss":                ["dalfox", "XSSHunter", "Burp Suite"],
            "ssti":               ["tplmap", "Burp Suite", "manual"],
            "ssrf":               ["Burp Collaborator", "ssrfmap", "curl"],
            "cmdi":               ["commix", "Burp Suite", "manual"],
            "xxe":                ["XXEinjector", "Burp Suite", "manual"],
            "nosql":              ["nosqlmap", "Burp Suite", "manual"],
            "path_traversal":     ["dotdotpwn", "Burp Suite", "ffuf"],
            "jwt_attacks":        ["jwt_tool", "hashcat", "manual"],
            "graphql":            ["graphql-cop", "InQL", "Burp Suite"],
            "http_request_smuggling": ["smuggler.py", "Burp Suite"],
            "open_redirect":      ["Burp Suite", "manual", "OpenRedireX"],
        }
        return tool_map.get(vc, ["Burp Suite", "manual testing"])

    @staticmethod
    def _vuln_class_to_target(vc: str) -> str:
        mapping = {
            "sqli":           "target_data",
            "sqli_mysql":     "target_data",
            "sqli_mssql":     "target_full_pwn",
            "sqli_postgres":  "target_data",
            "xss":            "target_credentials",
            "ssti":           "target_full_pwn",
            "ssrf":           "target_infrastructure",
            "cmdi":           "target_full_pwn",
            "xxe":            "target_data",
            "nosql":          "target_data",
            "path_traversal": "target_data",
            "jwt_attacks":    "target_credentials",
            "graphql":        "target_data",
            "http_request_smuggling": "target_credentials",
            "open_redirect":  "target_credentials",
            "csrf":           "target_credentials",
            "idor":           "target_data",
        }
        return mapping.get(vc, "target_data")

    @staticmethod
    def _best_injection_point(inj_points: List[Dict], vc: str) -> Optional[Dict]:
        """Pick the injection point most relevant to a vuln class."""
        param_pref = {
            "sqli":       ["url_param", "form_fields", "json_body"],
            "xss":        ["url_param", "form_fields", "json_body"],
            "ssti":       ["url_param", "form_fields", "json_body"],
            "ssrf":       ["url_param", "json_body"],
            "xxe":        ["xml_body", "multipart"],
            "cmdi":       ["url_param", "form_fields"],
            "nosql":      ["json_body", "url_param"],
            "path_traversal": ["url_param", "path_param"],
            "idor":       ["path_param", "url_param"],
            "graphql":    ["json_body"],
        }
        preferred = param_pref.get(vc, ["url_param"])
        for pref in preferred:
            for ip in inj_points:
                if ip.get("param_type") == pref:
                    return ip
        return inj_points[0] if inj_points else None

    # ------------------------------------------------------------------
    # Pass 2 — Groq AI enrichment
    # ------------------------------------------------------------------

    def _ai_analysis(
        self,
        domain:        str,
        graph:         AttackGraph,
        critical_paths: List[Dict],
        entry_nodes:   List[Node],
        target_nodes:  List[Node],
        path_summary:  Dict,
    ) -> Optional[Dict]:
        try:
            prompt = self._build_prompt(
                domain, graph, critical_paths,
                entry_nodes, target_nodes, path_summary
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
        domain:        str,
        graph:         AttackGraph,
        critical_paths: List[Dict],
        entry_nodes:   List[Node],
        target_nodes:  List[Node],
        path_summary:  Dict,
    ) -> str:
        # Condense paths to stay inside token budget
        condensed_paths = []
        for p in critical_paths[:5]:
            condensed_paths.append({
                "path_id":        p["path_id"],
                "route":          " → ".join(p["node_labels"]),
                "hop_count":      p["hop_count"],
                "severity":       p["worst_severity"],
                "score":          p["score"],
                "techniques":     [e["technique"][:80] for e in p["edges"][:5]],
                "tools":          p["tools_needed"][:6],
            })

        entry_summary = [
            {"label": n.label, "type": n.node_type, "risk": n.risk_score}
            for n in sorted(entry_nodes, key=lambda x: x.risk_score, reverse=True)[:8]
        ]
        target_summary = [
            {"label": n.label, "type": n.node_type}
            for n in target_nodes
        ]

        return f"""You are a lead red team operator and threat modelling expert.
Analyze the following attack path graph for {domain} and return ONLY valid JSON.

Graph Stats: {json.dumps(graph.stats(), indent=2)}
Path Summary: {json.dumps(path_summary, indent=2)}
Entry Points: {json.dumps(entry_summary, indent=2)}
Target Assets: {json.dumps(target_summary, indent=2)}
Critical Paths (top 5 by score):
{json.dumps(condensed_paths, indent=2)}

Return a JSON object with EXACTLY these keys:
- "threat_narrative": string — 4-5 sentences describing the most dangerous attack scenario
  an attacker would realistically execute against this target. Specific, technical, no vague language.
- "critical_path_analysis": array of objects (one per critical path), each with:
    "path_id" (string), "attacker_story" (string — 2-3 sentences narrating the attack step by step),
    "mitre_techniques" (array of strings — ATT&CK technique IDs like T1190, T1078, etc.),
    "detection_opportunities" (array of strings — where defenders can catch this path),
    "likelihood" (string — Likely/Possible/Unlikely with one-line reason).
- "attacker_profile": object with:
    "skill_level" (string — Script Kiddie / Intermediate / Advanced / Nation-State),
    "motivation" (string — most likely motive given the target profile),
    "time_to_compromise_estimate" (string — realistic time range),
    "resources_needed" (string).
- "defender_blind_spots": array of strings — 3-5 detection gaps this path graph reveals.
- "quick_win_detections": array of objects, each with:
    "detection" (string — specific log source, alert, or rule),
    "covers_paths" (array of path_ids),
    "implementation_effort" (low/medium/high).
- "graph_visualization_hint": string — brief description of how to visually lay out
  this graph (layer labels, most important node clusters, recommended colors).

Return ONLY valid JSON. No markdown fences, no preamble, no trailing text."""

    def _call_groq(self, prompt: str) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type":  "application/json",
        }
        payload = {
            "model":       "llama3-70b-8192",
            "messages":    [{"role": "user", "content": prompt}],
            "temperature": 0.25,
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