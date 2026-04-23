"""Fix remaining VPS issues with reconnection."""
import paramiko
import re
import time

host = '68.183.226.160'
user = 'root'
key_path = r'C:\Users\ASUS\SSH KEY'

def connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key = None
    for cls in ['Ed25519Key', 'RSAKey', 'ECDSAKey']:
        try:
            key = getattr(paramiko, cls).from_private_key_file(key_path)
            break
        except Exception:
            continue
    client.connect(hostname=host, username=user, pkey=key, timeout=20)
    transport = client.get_transport()
    if transport:
        transport.set_keepalive(10)
    return client

def run(name, cmd, timeout=120):
    """Run a single command with fresh connection."""
    print(f'\n--- {name} ---')
    try:
        c = connect()
        stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode('utf-8', errors='replace')
        clean = re.sub(r'\x1B\[[0-9;]*m', '', out)
        safe = ''.join(ch if ord(ch) < 128 else '?' for ch in clean)
        print(safe[-800:].strip())
        c.close()
        return safe
    except Exception as e:
        print(f'  ERROR: {e}')
        return ''

# 1. Fix theHarvester properly
run("Remove broken theHarvester",
    "rm -rf /root/theHarvester /usr/local/bin/theHarvester")

run("Install theHarvester via pip",
    "pip3 install theHarvester --break-system-packages -q 2>&1; "
    "python3 -m theHarvester.theHarvester -h 2>&1 | head -2 || echo 'PIP_METHOD_FAILED'")

run("Create theHarvester wrapper",
    "cat > /usr/local/bin/theHarvester << 'WRAPPER'\n"
    "#!/bin/bash\n"
    "python3 -m theHarvester.theHarvester \"$@\"\n"
    "WRAPPER\n"
    "chmod +x /usr/local/bin/theHarvester; "
    "theHarvester -h 2>&1 | head -2 || echo 'WRAPPER_FAILED'")

# 2. Wordlists
run("Fix Wordlists",
    "if [ ! -f /tmp/wordlist_common.txt ] || [ $(wc -l < /tmp/wordlist_common.txt) -lt 100 ]; then "
    "  curl -sL 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt' -o /tmp/wordlist_common.txt; "
    "fi; "
    "wc -l /usr/share/wordlists/dirb/common.txt /tmp/wordlist_common.txt 2>/dev/null || echo 'NO_WORDLISTS'")

# 3. Final comprehensive audit
run("FINAL AUDIT",
    "echo '=== TOOL STATUS ==='; "
    "for tool in nmap masscan whois dig gobuster wafw00f curl wget nikto nuclei ffuf dirb sqlmap hydra nc john smbclient enum4linux playwright curl-impersonate-chrome theHarvester; do "
    "  if command -v $tool >/dev/null 2>&1; then "
    "    V=$($tool --version 2>/dev/null | head -1 || echo 'ok'); "
    "    echo \"  [OK] $tool\"; "
    "  else "
    "    echo \"  [!!] $tool - MISSING\"; "
    "  fi; "
    "done; "
    "echo ''; "
    "echo '=== PLAYWRIGHT ==='; "
    "python3 -c 'from playwright.sync_api import sync_playwright; print(\"  [OK] Chromium importable\")' 2>/dev/null || echo '  [!!] Chromium broken'; "
    "echo ''; "
    "echo '=== NUCLEI TEMPLATES ==='; "
    "TMPL=$(find ~/nuclei-templates -name '*.yaml' 2>/dev/null | wc -l); "
    "echo \"  Templates: $TMPL\"; "
    "echo ''; "
    "echo '=== WORDLISTS ==='; "
    "for f in /usr/share/wordlists/dirb/common.txt /tmp/wordlist_common.txt; do "
    "  if [ -f $f ]; then echo \"  [OK] $f ($(wc -l < $f) words)\"; fi; "
    "done; "
    "echo ''; "
    "echo '=== SYSTEM ==='; "
    "echo \"  RAM: $(free -h | awk '/Mem:/{print $7}') available\"; "
    "echo \"  Disk: $(df -h / | awk 'NR==2{print $4}') free\"; "
    "echo ''; "
    "echo 'AUDIT_COMPLETE'")

print('\nAll done!')
