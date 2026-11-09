# utils/ai_recon_orchestrator.py
import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any
from urllib.parse import urlparse


class ModuleID(Enum):
    WAF_FINGERPRINT     = "waf_fingerprint"
    HEADER_INJECTION    = "header_injection"
    CORS_AUDIT          = "cors_audit"
    JS_SECRETS          = "js_secrets"
    SSRF_PROBE          = "ssrf_probe"
    REDIRECT_TRACE      = "redirect_trace"
    CREDENTIAL_SPRAY    = "credential_spray"
    AI_MOUSE_AGENT      = "ai_mouse_agent"


class ModuleStatus(Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETE  = "complete"
    SKIPPED   = "skipped"
    FAILED    = "failed"


class DecisionSignal(Enum):
    WAF_DETECTED          = "waf_detected"
    WAF_CLOUDFLARE        = "waf_cloudflare"
    WAF_AKAMAI            = "waf_akamai"
    WAF_IMPERVA           = "waf_imperva"
    WAF_AWS               = "waf_aws"
    NO_WAF                = "no_waf"
    CORS_MISCONFIGURED    = "cors_misconfigured"
    OPEN_REDIRECT_FOUND   = "open_redirect_found"
    SSRF_FOUND            = "ssrf_found"
    SECRETS_FOUND         = "secrets_found"
    AUTH_PAGE_FOUND       = "auth_page_found"
    RATE_LIMIT_DETECTED   = "rate_limit_detected"
    HIGH_LATENCY          = "high_latency"
    HEADERS_INJECTABLE    = "headers_injectable"
    CREDS_SUCCESS         = "creds_success"
    CREDS_FAILED          = "creds_failed"
    MFA_REQUIRED          = "mfa_required"


class InstructionMode(Enum):
    FULL_RECON        = "full_recon"
    AUTH_BYPASS       = "auth_bypass"
    SECRETS_FOCUS     = "secrets_focus"
    INJECTION_FOCUS   = "injection_focus"
    STEALTH           = "stealth"
    FAST              = "fast"
    CUSTOM            = "custom"


@dataclass
class ModuleResult:
    module_id: ModuleID
    status: ModuleStatus
    output: dict
    duration_seconds: float
    signals: list[DecisionSignal]
    error: str = ""
    skipped_reason: str = ""


@dataclass
class OrchestratorDecision:
    timestamp: float
    trigger_signal: list[DecisionSignal]
    action: str
    affected_modules: list[ModuleID]
    rationale: str
    param_overrides: dict


@dataclass
class AttackPath:
    path_id: str
    steps: list[str]
    chaining_score: float
    entry_module: ModuleID
    pivot_signals: list[DecisionSignal]
    narrative: str


@dataclass
class OrchestratorReport:
    target_url: str
    session_id: str
    instruction_mode: InstructionMode
    module_results: dict[str, ModuleResult]
    decisions: list[OrchestratorDecision]
    signals_emitted: list[DecisionSignal]
    attack_paths: list[AttackPath]
    total_findings: int
    critical_count: int
    high_count: int
    duration_seconds: float
    execution_order: list[str]
    summary: str


MODULE_BASE_PARAMS: dict[ModuleID, dict] = {
    ModuleID.WAF_FINGERPRINT:   {"concurrency": 15, "delay": 0.1,  "run_timing_probes": True},
    ModuleID.HEADER_INJECTION:  {"concurrency": 20, "delay": 0.05, "method": "GET"},
    ModuleID.CORS_AUDIT:        {"concurrency": 10, "delay": 0.1},
    ModuleID.JS_SECRETS:        {"concurrency": 10, "max_js_files": 100, "follow_sourcemaps": True, "redact_values": True},
    ModuleID.SSRF_PROBE:        {"concurrency": 8,  "delay": 0.15, "max_params": 20, "test_headers": True, "test_json": True},
    ModuleID.REDIRECT_TRACE:    {"concurrency": 10, "delay": 0.1,  "max_hops": 15, "max_params": 15, "max_payloads": 10},
    ModuleID.CREDENTIAL_SPRAY:  {"delay": 2.0, "jitter": 1.0, "stop_on_success": False, "stop_on_lockout": True, "max_attempts": 100},
    ModuleID.AI_MOUSE_AGENT:    {"max_attempts": 5, "headless": True, "capture_screenshots": True},
}

MODE_MODULE_SETS: dict[InstructionMode, list[ModuleID]] = {
    InstructionMode.FULL_RECON: [
        ModuleID.WAF_FINGERPRINT,
        ModuleID.HEADER_INJECTION,
        ModuleID.CORS_AUDIT,
        ModuleID.JS_SECRETS,
        ModuleID.SSRF_PROBE,
        ModuleID.REDIRECT_TRACE,
    ],
    InstructionMode.AUTH_BYPASS: [
        ModuleID.WAF_FINGERPRINT,
        ModuleID.HEADER_INJECTION,
        ModuleID.REDIRECT_TRACE,
        ModuleID.CREDENTIAL_SPRAY,
        ModuleID.AI_MOUSE_AGENT,
    ],
    InstructionMode.SECRETS_FOCUS: [
        ModuleID.WAF_FINGERPRINT,
        ModuleID.JS_SECRETS,
        ModuleID.SSRF_PROBE,
        ModuleID.REDIRECT_TRACE,
    ],
    InstructionMode.INJECTION_FOCUS: [
        ModuleID.WAF_FINGERPRINT,
        ModuleID.HEADER_INJECTION,
        ModuleID.CORS_AUDIT,
        ModuleID.SSRF_PROBE,
    ],
    InstructionMode.STEALTH: [
        ModuleID.WAF_FINGERPRINT,
        ModuleID.JS_SECRETS,
        ModuleID.CORS_AUDIT,
    ],
    InstructionMode.FAST: [
        ModuleID.WAF_FINGERPRINT,
        ModuleID.HEADER_INJECTION,
        ModuleID.CORS_AUDIT,
    ],
    InstructionMode.CUSTOM: [],
}

STEALTH_PARAM_OVERRIDES: dict[ModuleID, dict] = {
    ModuleID.WAF_FINGERPRINT:   {"concurrency": 5,  "delay": 0.5,  "run_timing_probes": False},
    ModuleID.HEADER_INJECTION:  {"concurrency": 5,  "delay": 0.3},
    ModuleID.CORS_AUDIT:        {"concurrency": 4,  "delay": 0.4},
    ModuleID.JS_SECRETS:        {"concurrency": 4,  "delay": 0.2},
    ModuleID.SSRF_PROBE:        {"concurrency": 4,  "delay": 0.5},
    ModuleID.REDIRECT_TRACE:    {"concurrency": 4,  "delay": 0.4,  "max_payloads": 5},
    ModuleID.CREDENTIAL_SPRAY:  {"delay": 5.0, "jitter": 3.0},
    ModuleID.AI_MOUSE_AGENT:    {"headless": True},
}

WAF_EVASION_OVERRIDES: dict[str, dict[ModuleID, dict]] = {
    "CLOUDFLARE": {
        ModuleID.HEADER_INJECTION:  {"delay": 0.4, "concurrency": 8},
        ModuleID.SSRF_PROBE:        {"delay": 0.5, "concurrency": 4},
        ModuleID.CORS_AUDIT:        {"delay": 0.3, "concurrency": 6},
        ModuleID.CREDENTIAL_SPRAY:  {"delay": 4.0, "jitter": 2.0},
    },
    "AKAMAI": {
        ModuleID.HEADER_INJECTION:  {"delay": 0.6, "concurrency": 6},
        ModuleID.SSRF_PROBE:        {"delay": 0.6, "concurrency": 3},
        ModuleID.CORS_AUDIT:        {"delay": 0.4, "concurrency": 5},
    },
    "IMPERVA": {
        ModuleID.HEADER_INJECTION:  {"delay": 0.5, "concurrency": 6},
        ModuleID.SSRF_PROBE:        {"delay": 0.4, "concurrency": 4},
    },
    "AWS_WAF": {
        ModuleID.HEADER_INJECTION:  {"delay": 0.3, "concurrency": 10},
        ModuleID.SSRF_PROBE:        {"delay": 0.3, "concurrency": 6},
    },
}

CHAINING_SCORE_MATRIX: dict[tuple[DecisionSignal, DecisionSignal], float] = {
    (DecisionSignal.OPEN_REDIRECT_FOUND,  DecisionSignal.SSRF_FOUND):          0.95,
    (DecisionSignal.OPEN_REDIRECT_FOUND,  DecisionSignal.CORS_MISCONFIGURED):   0.80,
    (DecisionSignal.HEADERS_INJECTABLE,   DecisionSignal.SSRF_FOUND):           0.90,
    (DecisionSignal.HEADERS_INJECTABLE,   DecisionSignal.CORS_MISCONFIGURED):   0.75,
    (DecisionSignal.SECRETS_FOUND,        DecisionSignal.AUTH_PAGE_FOUND):      0.88,
    (DecisionSignal.SECRETS_FOUND,        DecisionSignal.SSRF_FOUND):           0.85,
    (DecisionSignal.SSRF_FOUND,           DecisionSignal.SECRETS_FOUND):        0.92,
    (DecisionSignal.CORS_MISCONFIGURED,   DecisionSignal.SECRETS_FOUND):        0.78,
    (DecisionSignal.AUTH_PAGE_FOUND,      DecisionSignal.HEADERS_INJECTABLE):   0.70,
    (DecisionSignal.CREDS_SUCCESS,        DecisionSignal.SECRETS_FOUND):        0.98,
    (DecisionSignal.CREDS_SUCCESS,        DecisionSignal.SSRF_FOUND):           0.96,
    (DecisionSignal.OPEN_REDIRECT_FOUND,  DecisionSignal.AUTH_PAGE_FOUND):      0.72,
}


def _session_id() -> str:
    return hashlib.md5(f"{time.time()}".encode()).hexdigest()[:10]


def _extract_signals_from_waf(result: dict) -> list[DecisionSignal]:
    signals: list[DecisionSignal] = []
    vendor = result.get("vendor", "").upper()
    if vendor and vendor != "NO_WAF" and vendor != "UNKNOWN_WAF":
        signals.append(DecisionSignal.WAF_DETECTED)
        vendor_map = {
            "CLOUDFLARE":    DecisionSignal.WAF_CLOUDFLARE,
            "AKAMAI":        DecisionSignal.WAF_AKAMAI,
            "IMPERVA":       DecisionSignal.WAF_IMPERVA,
            "AWS_WAF":       DecisionSignal.WAF_AWS,
        }
        if vendor in vendor_map:
            signals.append(vendor_map[vendor])
    elif vendor in ("NO_WAF", ""):
        signals.append(DecisionSignal.NO_WAF)
    avg_latency = result.get("avg_latency_ms", 0)
    if avg_latency > 2000:
        signals.append(DecisionSignal.HIGH_LATENCY)
    return signals


def _extract_signals_from_headers(result: dict) -> list[DecisionSignal]:
    signals: list[DecisionSignal] = []
    findings = result.get("findings", [])
    injectable = any(
        f.get("severity") in ("critical", "high")
        for f in findings
    )
    if injectable:
        signals.append(DecisionSignal.HEADERS_INJECTABLE)
    return signals


def _extract_signals_from_cors(result: dict) -> list[DecisionSignal]:
    signals: list[DecisionSignal] = []
    total = result.get("total_findings", 0)
    critical = result.get("findings_by_severity", {}).get("critical", 0)
    high = result.get("findings_by_severity", {}).get("high", 0)
    if critical > 0 or high > 0 or total > 0:
        signals.append(DecisionSignal.CORS_MISCONFIGURED)
    return signals


def _extract_signals_from_js_secrets(result: dict) -> list[DecisionSignal]:
    signals: list[DecisionSignal] = []
    total = result.get("total_secrets", 0)
    if total > 0:
        signals.append(DecisionSignal.SECRETS_FOUND)
    return signals


def _extract_signals_from_ssrf(result: dict) -> list[DecisionSignal]:
    signals: list[DecisionSignal] = []
    critical = result.get("findings_by_severity", {}).get("critical", 0)
    high = result.get("findings_by_severity", {}).get("high", 0)
    if critical > 0 or high > 0:
        signals.append(DecisionSignal.SSRF_FOUND)
    return signals


def _extract_signals_from_redirect(result: dict) -> list[DecisionSignal]:
    signals: list[DecisionSignal] = []
    if result.get("open_redirect_params"):
        signals.append(DecisionSignal.OPEN_REDIRECT_FOUND)
    return signals


def _extract_signals_from_spray(result: dict) -> list[DecisionSignal]:
    signals: list[DecisionSignal] = []
    summary = result.get("summary", {})
    if summary.get("successful_logins", 0) > 0:
        signals.append(DecisionSignal.CREDS_SUCCESS)
    elif result.get("result") == "mfa_required":
        signals.append(DecisionSignal.MFA_REQUIRED)
    elif summary.get("lockouts_detected", 0) > 0 or result.get("rate_limited"):
        signals.append(DecisionSignal.RATE_LIMIT_DETECTED)
    else:
        signals.append(DecisionSignal.CREDS_FAILED)
    return signals


def _extract_signals_from_mouse(result: dict) -> list[DecisionSignal]:
    signals: list[DecisionSignal] = []
    findings = result.get("findings", {})
    res = findings.get("result", "")
    if res == "success":
        signals.append(DecisionSignal.CREDS_SUCCESS)
    elif res == "mfa_required":
        signals.append(DecisionSignal.MFA_REQUIRED)
    elif findings.get("captcha_encountered"):
        signals.append(DecisionSignal.RATE_LIMIT_DETECTED)
    return signals


SIGNAL_EXTRACTORS = {
    ModuleID.WAF_FINGERPRINT:   _extract_signals_from_waf,
    ModuleID.HEADER_INJECTION:  _extract_signals_from_headers,
    ModuleID.CORS_AUDIT:        _extract_signals_from_cors,
    ModuleID.JS_SECRETS:        _extract_signals_from_js_secrets,
    ModuleID.SSRF_PROBE:        _extract_signals_from_ssrf,
    ModuleID.REDIRECT_TRACE:    _extract_signals_from_redirect,
    ModuleID.CREDENTIAL_SPRAY:  _extract_signals_from_spray,
    ModuleID.AI_MOUSE_AGENT:    _extract_signals_from_mouse,
}


def _count_findings(result: dict) -> tuple[int, int, int]:
    sev = result.get("findings_by_severity", {})
    critical = sev.get("critical", 0)
    high = sev.get("high", 0)
    total = result.get("total_findings", 0)
    if not total:
        total = sum(sev.values())
    return total, critical, high


def _compute_attack_paths(
    signals: list[DecisionSignal],
    module_results: dict[str, ModuleResult],
) -> list[AttackPath]:
    paths: list[AttackPath] = []
    signal_set = set(signals)

    for (sig_a, sig_b), score in CHAINING_SCORE_MATRIX.items():
        if sig_a in signal_set and sig_b in signal_set:
            entry_mod = None
            pivot_mods: list[str] = []
            for mid, mr in module_results.items():
                if sig_a in mr.signals:
                    entry_mod = mr.module_id
                if sig_b in mr.signals:
                    pivot_mods.append(mid)

            if not entry_mod:
                continue

            path_steps = [
                f"[{entry_mod.value}] triggers signal: {sig_a.value}",
                f"pivot via chaining score {score:.2f}",
                f"[{', '.join(pivot_mods)}] signal: {sig_b.value}",
            ]

            narrative_map = {
                (DecisionSignal.OPEN_REDIRECT_FOUND,  DecisionSignal.SSRF_FOUND):
                    "Open redirect can be used as a SSRF pivot — attacker controls destination URL passed to server-side fetch",
                (DecisionSignal.OPEN_REDIRECT_FOUND,  DecisionSignal.CORS_MISCONFIGURED):
                    "Open redirect combined with CORS misconfiguration allows cross-origin credential theft via redirect chain",
                (DecisionSignal.HEADERS_INJECTABLE,   DecisionSignal.SSRF_FOUND):
                    "Injectable headers (Host/X-Forwarded-For) can be combined with SSRF to bypass IP-based access controls on internal services",
                (DecisionSignal.HEADERS_INJECTABLE,   DecisionSignal.CORS_MISCONFIGURED):
                    "Header injection + CORS misconfiguration enables cache poisoning attacks targeting authenticated users",
                (DecisionSignal.SECRETS_FOUND,        DecisionSignal.AUTH_PAGE_FOUND):
                    "Hardcoded credentials or API keys found in JS can be replayed directly against the discovered auth endpoint",
                (DecisionSignal.SECRETS_FOUND,        DecisionSignal.SSRF_FOUND):
                    "SSRF + extracted cloud credentials enables lateral movement to internal metadata services or cloud APIs",
                (DecisionSignal.SSRF_FOUND,           DecisionSignal.SECRETS_FOUND):
                    "SSRF against metadata endpoint likely yields IAM credentials — pivot to full cloud environment compromise",
                (DecisionSignal.CORS_MISCONFIGURED,   DecisionSignal.SECRETS_FOUND):
                    "CORS misconfiguration allows attacker-controlled origin to read responses containing embedded secrets",
                (DecisionSignal.AUTH_PAGE_FOUND,      DecisionSignal.HEADERS_INJECTABLE):
                    "Auth page with injectable headers may allow password reset poisoning or IP spoofing to bypass lockout",
                (DecisionSignal.CREDS_SUCCESS,        DecisionSignal.SECRETS_FOUND):
                    "Successful credential spray combined with JS secrets gives authenticated access plus API key material",
                (DecisionSignal.CREDS_SUCCESS,        DecisionSignal.SSRF_FOUND):
                    "Post-auth SSRF with valid session token bypasses many internal access controls",
                (DecisionSignal.OPEN_REDIRECT_FOUND,  DecisionSignal.AUTH_PAGE_FOUND):
                    "Open redirect on auth flow enables phishing via trusted domain — steal credentials via redirect to attacker page",
            }

            narrative = narrative_map.get((sig_a, sig_b), f"{sig_a.value} → {sig_b.value} chaining opportunity")
            path_id = hashlib.md5(f"{sig_a.value}:{sig_b.value}".encode()).hexdigest()[:8]

            paths.append(AttackPath(
                path_id=path_id,
                steps=path_steps,
                chaining_score=score,
                entry_module=entry_mod,
                pivot_signals=[sig_a, sig_b],
                narrative=narrative,
            ))

    paths.sort(key=lambda p: -p.chaining_score)
    return paths


def _generate_summary(
    report: "OrchestratorReport",
    signals: list[DecisionSignal],
) -> str:
    signal_names = [s.value for s in signals]
    waf_vendor = ""
    waf_result = report.module_results.get(ModuleID.WAF_FINGERPRINT.value)
    if waf_result and waf_result.output:
        waf_vendor = waf_result.output.get("vendor", "")

    parts: list[str] = []
    parts.append(f"Target: {report.target_url}")
    parts.append(f"Mode: {report.instruction_mode.value}")
    parts.append(f"Modules run: {len([r for r in report.module_results.values() if r.status == ModuleStatus.COMPLETE])}/{len(report.module_results)}")
    if waf_vendor:
        parts.append(f"WAF detected: {waf_vendor}")
    else:
        parts.append("WAF: none detected")
    parts.append(f"Total findings: {report.total_findings} (critical={report.critical_count}, high={report.high_count})")
    parts.append(f"Attack paths identified: {len(report.attack_paths)}")
    if report.attack_paths:
        top = report.attack_paths[0]
        parts.append(f"Top chain [{top.chaining_score:.2f}]: {top.narrative[:120]}")
    parts.append(f"Duration: {report.duration_seconds:.1f}s")
    return " | ".join(parts)


class ReconOrchestrator:
    def __init__(
        self,
        instruction_mode: InstructionMode = InstructionMode.FULL_RECON,
        custom_modules: Optional[list[ModuleID]] = None,
        custom_params: Optional[dict[ModuleID, dict]] = None,
        credentials: Optional[list[tuple[str, str]]] = None,
        credential_spray_url: Optional[str] = None,
        mouse_agent_url: Optional[str] = None,
        status_callback: Optional[callable] = None,
    ):
        self.instruction_mode = instruction_mode
        self.custom_modules = custom_modules or []
        self.custom_params = custom_params or {}
        self.credentials = credentials or [("admin", "admin"), ("admin", "password")]
        self.credential_spray_url = credential_spray_url
        self.mouse_agent_url = mouse_agent_url
        self.status_callback = status_callback
        self._decisions: list[OrchestratorDecision] = []
        self._all_signals: list[DecisionSignal] = []
        self._module_params: dict[ModuleID, dict] = {}
        self._execution_order: list[str] = []

    def _notify(self, msg: str) -> None:
        if self.status_callback:
            try:
                self.status_callback(msg)
            except Exception:
                pass

    def _init_params(self, target_url: str) -> None:
        for mid in ModuleID:
            base = dict(MODULE_BASE_PARAMS.get(mid, {}))
            if self.instruction_mode == InstructionMode.STEALTH:
                base.update(STEALTH_PARAM_OVERRIDES.get(mid, {}))
            if mid in self.custom_params:
                base.update(self.custom_params[mid])
            self._module_params[mid] = base

        spray_url = self.credential_spray_url or target_url + "/login"
        self._module_params[ModuleID.CREDENTIAL_SPRAY]["target_url"] = spray_url
        self._module_params[ModuleID.CREDENTIAL_SPRAY]["usernames"] = [c[0] for c in self.credentials]
        self._module_params[ModuleID.CREDENTIAL_SPRAY]["passwords"] = [c[1] for c in self.credentials]

        mouse_url = self.mouse_agent_url or target_url + "/login"
        self._module_params[ModuleID.AI_MOUSE_AGENT]["target_url"] = mouse_url
        self._module_params[ModuleID.AI_MOUSE_AGENT]["credentials"] = self.credentials

    def _apply_waf_evasion(self, vendor: str) -> None:
        overrides = WAF_EVASION_OVERRIDES.get(vendor.upper(), {})
        if not overrides:
            return
        decision = OrchestratorDecision(
            timestamp=time.time(),
            trigger_signal=[DecisionSignal.WAF_DETECTED],
            action=f"apply_waf_evasion:{vendor}",
            affected_modules=list(overrides.keys()),
            rationale=f"{vendor} WAF detected — increasing delays and reducing concurrency on probe modules",
            param_overrides={mid.value: params for mid, params in overrides.items()},
        )
        self._decisions.append(decision)
        for mid, params in overrides.items():
            self._module_params[mid].update(params)

    def _decide_module_additions(
        self,
        completed: ModuleID,
        signals: list[DecisionSignal],
        pending: list[ModuleID],
    ) -> list[OrchestratorDecision]:
        decisions: list[OrchestratorDecision] = []
        signal_set = set(signals)

        if DecisionSignal.SECRETS_FOUND in signal_set:
            if ModuleID.SSRF_PROBE not in pending and ModuleID.SSRF_PROBE.value not in [
                r for r in self._execution_order
            ]:
                pending.append(ModuleID.SSRF_PROBE)
                decisions.append(OrchestratorDecision(
                    timestamp=time.time(),
                    trigger_signal=[DecisionSignal.SECRETS_FOUND],
                    action="add_module",
                    affected_modules=[ModuleID.SSRF_PROBE],
                    rationale="JS secrets found — adding SSRF probe to test if extracted URLs/endpoints are internally reachable",
                    param_overrides={},
                ))

        if DecisionSignal.OPEN_REDIRECT_FOUND in signal_set:
            if ModuleID.SSRF_PROBE not in pending:
                pending.append(ModuleID.SSRF_PROBE)
                decisions.append(OrchestratorDecision(
                    timestamp=time.time(),
                    trigger_signal=[DecisionSignal.OPEN_REDIRECT_FOUND],
                    action="add_module",
                    affected_modules=[ModuleID.SSRF_PROBE],
                    rationale="Open redirect found — SSRF via redirect chain is a confirmed attack vector, adding probe",
                    param_overrides={},
                ))

        if DecisionSignal.HEADERS_INJECTABLE in signal_set:
            if ModuleID.CORS_AUDIT not in pending:
                pending.append(ModuleID.CORS_AUDIT)
                decisions.append(OrchestratorDecision(
                    timestamp=time.time(),
                    trigger_signal=[DecisionSignal.HEADERS_INJECTABLE],
                    action="add_module",
                    affected_modules=[ModuleID.CORS_AUDIT],
                    rationale="Injectable headers detected — adding CORS audit to test cache poisoning via Origin/Host header manipulation",
                    param_overrides={},
                ))

        if DecisionSignal.RATE_LIMIT_DETECTED in signal_set:
            self._module_params[ModuleID.CREDENTIAL_SPRAY].update({"delay": 6.0, "jitter": 3.0})
            decisions.append(OrchestratorDecision(
                timestamp=time.time(),
                trigger_signal=[DecisionSignal.RATE_LIMIT_DETECTED],
                action="adjust_params",
                affected_modules=[ModuleID.CREDENTIAL_SPRAY],
                rationale="Rate limit detected — increasing spray delay and jitter to avoid lockout",
                param_overrides={ModuleID.CREDENTIAL_SPRAY.value: {"delay": 6.0, "jitter": 3.0}},
            ))

        if DecisionSignal.CREDS_SUCCESS in signal_set:
            if ModuleID.SSRF_PROBE not in pending:
                pending.append(ModuleID.SSRF_PROBE)
                decisions.append(OrchestratorDecision(
                    timestamp=time.time(),
                    trigger_signal=[DecisionSignal.CREDS_SUCCESS],
                    action="add_module",
                    affected_modules=[ModuleID.SSRF_PROBE],
                    rationale="Credentials valid — adding post-auth SSRF probe to test internal reachability with authenticated session",
                    param_overrides={},
                ))

        return decisions

    def _run_module_sync(self, mid: ModuleID, target_url: str) -> ModuleResult:
        params = dict(self._module_params.get(mid, {}))
        t0 = time.monotonic()

        try:
            if mid == ModuleID.WAF_FINGERPRINT:
                from utils.waf_fingerprinter import run_waf_fingerprint
                output = run_waf_fingerprint(target_url, **{
                    k: v for k, v in params.items()
                    if k in ("concurrency", "delay", "run_timing_probes")
                })

            elif mid == ModuleID.HEADER_INJECTION:
                from utils.header_injector import run_header_injection
                output = run_header_injection(target_url, **{
                    k: v for k, v in params.items()
                    if k in ("concurrency", "delay", "method")
                })

            elif mid == ModuleID.CORS_AUDIT:
                from utils.cors_auditor import run_cors_audit
                output = run_cors_audit(target_url, **{
                    k: v for k, v in params.items()
                    if k in ("concurrency", "delay", "test_methods")
                })

            elif mid == ModuleID.JS_SECRETS:
                from utils.js_secret_extractor import run_js_secret_extraction
                output = run_js_secret_extraction(target_url, **{
                    k: v for k, v in params.items()
                    if k in ("concurrency", "max_js_files", "follow_sourcemaps", "redact_values")
                })

            elif mid == ModuleID.SSRF_PROBE:
                from utils.ssrf_prober import run_ssrf_probe
                output = run_ssrf_probe(target_url, **{
                    k: v for k, v in params.items()
                    if k in ("concurrency", "delay", "max_params", "test_headers", "test_json")
                })

            elif mid == ModuleID.REDIRECT_TRACE:
                from utils.redirect_tracer import run_redirect_trace
                output = run_redirect_trace(target_url, **{
                    k: v for k, v in params.items()
                    if k in ("concurrency", "delay", "max_hops", "max_params", "max_payloads")
                })

            elif mid == ModuleID.CREDENTIAL_SPRAY:
                from utils.credential_sprayer import run_credential_spray
                spray_url = params.pop("target_url", target_url + "/login")
                output = run_credential_spray(spray_url, **{
                    k: v for k, v in params.items()
                    if k in (
                        "usernames", "passwords", "delay", "jitter",
                        "stop_on_success", "stop_on_lockout", "max_attempts",
                    )
                })

            elif mid == ModuleID.AI_MOUSE_AGENT:
                from utils.ai_mouse_agent import run_ai_mouse_agent
                mouse_url = params.pop("target_url", target_url + "/login")
                mouse_creds = params.pop("credentials", self.credentials)
                output = run_ai_mouse_agent(
                    target_url=mouse_url,
                    credentials=mouse_creds,
                    **{
                        k: v for k, v in params.items()
                        if k in ("max_attempts", "headless", "capture_screenshots", "proxy")
                    }
                )
            else:
                output = {}

            extractor = SIGNAL_EXTRACTORS.get(mid)
            signals = extractor(output) if extractor else []
            duration = time.monotonic() - t0

            return ModuleResult(
                module_id=mid,
                status=ModuleStatus.COMPLETE,
                output=output,
                duration_seconds=round(duration, 2),
                signals=signals,
            )

        except ImportError as e:
            return ModuleResult(
                module_id=mid,
                status=ModuleStatus.FAILED,
                output={},
                duration_seconds=round(time.monotonic() - t0, 2),
                signals=[],
                error=f"ImportError: {e}",
            )
        except Exception as e:
            return ModuleResult(
                module_id=mid,
                status=ModuleStatus.FAILED,
                output={},
                duration_seconds=round(time.monotonic() - t0, 2),
                signals=[],
                error=str(e)[:400],
            )

    def run(self, target_url: str) -> OrchestratorReport:
        t_start = time.monotonic()
        self._init_params(target_url)
        self._decisions = []
        self._all_signals = []
        self._execution_order = []

        if self.instruction_mode == InstructionMode.CUSTOM:
            pipeline = list(self.custom_modules)
        else:
            pipeline = list(MODE_MODULE_SETS[self.instruction_mode])

        module_results: dict[str, ModuleResult] = {}
        total_findings = 0
        critical_count = 0
        high_count = 0

        while pipeline:
            mid = pipeline.pop(0)

            if mid.value in self._execution_order:
                continue

            self._notify(f"running:{mid.value}")
            self._execution_order.append(mid.value)

            result = self._run_module_sync(mid, target_url)
            module_results[mid.value] = result

            if result.status == ModuleStatus.COMPLETE:
                self._all_signals.extend(result.signals)

                tf, cr, hi = _count_findings(result.output)
                total_findings += tf
                critical_count += cr
                high_count += hi

                if mid == ModuleID.WAF_FINGERPRINT and result.output:
                    vendor = result.output.get("vendor", "")
                    if vendor and vendor not in ("NO_WAF", "UNKNOWN_WAF", ""):
                        self._apply_waf_evasion(vendor)

                new_decisions = self._decide_module_additions(mid, result.signals, pipeline)
                self._decisions.extend(new_decisions)

                self._notify(f"complete:{mid.value}:signals={[s.value for s in result.signals]}")
            else:
                self._notify(f"failed:{mid.value}:error={result.error[:80]}")

        attack_paths = _compute_attack_paths(self._all_signals, module_results)
        duration = time.monotonic() - t_start

        report = OrchestratorReport(
            target_url=target_url,
            session_id=_session_id(),
            instruction_mode=self.instruction_mode,
            module_results=module_results,
            decisions=self._decisions,
            signals_emitted=list(set(self._all_signals)),
            attack_paths=attack_paths,
            total_findings=total_findings,
            critical_count=critical_count,
            high_count=high_count,
            duration_seconds=round(duration, 2),
            execution_order=self._execution_order,
            summary="",
        )
        report.summary = _generate_summary(report, self._all_signals)
        return report


def serialize_report(report: OrchestratorReport) -> dict:
    def decision_to_dict(d: OrchestratorDecision) -> dict:
        return {
            "timestamp": d.timestamp,
            "trigger_signals": [s.value for s in d.trigger_signal],
            "action": d.action,
            "affected_modules": [m.value for m in d.affected_modules],
            "rationale": d.rationale,
            "param_overrides": {
                k: v for k, v in d.param_overrides.items()
            },
        }

    def path_to_dict(p: AttackPath) -> dict:
        return {
            "path_id": p.path_id,
            "chaining_score": p.chaining_score,
            "entry_module": p.entry_module.value,
            "pivot_signals": [s.value for s in p.pivot_signals],
            "steps": p.steps,
            "narrative": p.narrative,
        }

    def result_to_dict(r: ModuleResult) -> dict:
        return {
            "module": r.module_id.value,
            "status": r.status.value,
            "duration_seconds": r.duration_seconds,
            "signals": [s.value for s in r.signals],
            "error": r.error,
            "skipped_reason": r.skipped_reason,
            "output": r.output,
        }

    return {
        "session_id": report.session_id,
        "target": report.target_url,
        "instruction_mode": report.instruction_mode.value,
        "summary": report.summary,
        "execution_order": report.execution_order,
        "duration_seconds": report.duration_seconds,
        "total_findings": report.total_findings,
        "critical_count": report.critical_count,
        "high_count": report.high_count,
        "signals_emitted": [s.value for s in report.signals_emitted],
        "attack_paths": [path_to_dict(p) for p in report.attack_paths],
        "decisions": [decision_to_dict(d) for d in report.decisions],
        "module_results": {k: result_to_dict(v) for k, v in report.module_results.items()},
    }


def run_recon_orchestrator(
    target_url: str,
    instruction_mode: str = "full_recon",
    custom_modules: Optional[list[str]] = None,
    custom_params: Optional[dict] = None,
    credentials: Optional[list[tuple[str, str]]] = None,
    credential_spray_url: Optional[str] = None,
    mouse_agent_url: Optional[str] = None,
    status_callback: Optional[callable] = None,
) -> dict:
    try:
        mode = InstructionMode(instruction_mode)
    except ValueError:
        mode = InstructionMode.FULL_RECON

    parsed_custom_modules: list[ModuleID] = []
    if custom_modules:
        for m in custom_modules:
            try:
                parsed_custom_modules.append(ModuleID(m))
            except ValueError:
                pass

    parsed_custom_params: dict[ModuleID, dict] = {}
    if custom_params:
        for k, v in custom_params.items():
            try:
                parsed_custom_params[ModuleID(k)] = v
            except ValueError:
                pass

    orchestrator = ReconOrchestrator(
        instruction_mode=mode,
        custom_modules=parsed_custom_modules,
        custom_params=parsed_custom_params,
        credentials=credentials,
        credential_spray_url=credential_spray_url,
        mouse_agent_url=mouse_agent_url,
        status_callback=status_callback,
    )
    report = orchestrator.run(target_url)
    return serialize_report(report)