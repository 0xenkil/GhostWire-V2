from config import (
    TOOL_NMAP_TIMEOUT, TOOL_MASSCAN_TIMEOUT, TOOL_NUCLEI_TIMEOUT,
    TOOL_GOBUSTER_TIMEOUT, TOOL_FFUF_TIMEOUT, TOOL_METASPLOIT_TIMEOUT,
    TOOL_WAF_TIMEOUT
)

TOOL_TIMEOUTS = {
    "nikto":       600,
    "nuclei":      TOOL_NUCLEI_TIMEOUT,
    "sslscan":     180,
    "whatweb":     90,
    "gobuster":    TOOL_GOBUSTER_TIMEOUT,
    "ffuf":        TOOL_FFUF_TIMEOUT,
    "masscan":     TOOL_MASSCAN_TIMEOUT,
    "nmap":        TOOL_NMAP_TIMEOUT,
    "hydra":       240,
    "sqlmap":      300,
    "default":     120,
}

# ── V6: Virtual & AI-Driven Tools ───────────────────────────
# These tools bypass standard installation checks and use custom logic
VIRTUAL_TOOLS = {
    "ssh_cmd", "remote_exec", "python", "python3",
    "ai_dynamic_recon", "ai_dynamic_exploit", "react_payload", "python_payload"
}

# Tools that specifically require Guardian AI validation before execution
VIRTUAL_AI_TOOLS = {
    "ai_dynamic_recon", "ai_dynamic_exploit", "react_payload", "python_payload"
}

# Tools that primarily use HTTP/S and benefit from WAF evasion/TLS circuit breaking
HTTP_TOOLS = {
    "curl", "nikto", "ffuf", "gobuster", "dirb", "dirsearch", 
    "whatweb", "wafw00f", "sslscan", "dalfox", "wget"
}

# Tools that benefit from real-time streaming (long-running)
STREAMING_TOOLS = {
    "nmap", "nuclei", "gobuster", "nikto", "masscan", "ffuf",
    "hydra", "sqlmap", "theharvester", "enum4linux"
}

# Tools with fast execution - only 1 retry needed
FAST_TOOLS = {"dig", "curl", "whois", "nc"}

# Command wrappers that shouldn't be counted as the primary tool in validation
WRAPPER_TOOLS = {"timeout", "sudo", "env", "nice", "proxychains4", "proxychains"}

# Tools that write to a file (-o, -oG, -oN, etc.) - prefer file readback on VPS
FILE_OUTPUT_TOOLS = {"nuclei", "nmap", "nikto", "masscan", "gobuster"}

# Tool fallback mappings: if primary tool unavailable, use alternatives
# Phase 4 Fix: Expanded fallback chains to improve resilience
TOOL_FALLBACKS = {
    "nuclei": ["nikto", "ffuf", "curl"],           # if nuclei fails, try nikto web scanner
    "nikto": ["gobuster", "ffuf", "curl"],        # if nikto fails, try dir brute-force
    "gobuster": ["ffuf", "dirbuster", "curl"],    # if gobuster fails, try ffuf
    "ffuf": ["gobuster", "curl"],                  # if ffuf fails, try gobuster
    "nmap": ["masscan", "curl"],                   # if nmap fails, try masscan port scan
    "masscan": ["nmap", "curl"],                   # if masscan fails, try nmap
    "curl": ["wget", "nc"],                        # if curl network fails, try wget
    "wget": ["curl"],                              # if wget fails, try curl
    "sqlmap": ["curl", "nikto"],                   # if sqlmap fails, try manual curl probes
    "theharvester": ["curl", "dig"],               # if theharvester fails, try dig
    "dig": ["nslookup", "host"],                   # if dig fails, try nslookup
    "subfinder": ["amass", "curl"],                # if subfinder fails, try amass
    "amass": ["subfinder", "curl"],                # if amass fails, try subfinder
}

TOOL_REGISTRY = {
    "nmap": {
        "binary": "nmap",
        "install": "apt-get update && apt-get install -y nmap dnsutils",
        "category": "scanning",
        "timeout": TOOL_NMAP_TIMEOUT,
        "description": "Network port scanner",
    },
    "masscan": {
        "binary": "masscan",
        "install": "apt-get update && apt-get install -y masscan",
        "category": "scanning",
        "timeout": TOOL_MASSCAN_TIMEOUT,
        "description": "Fast port scanner",
    },
    "nikto": {
        "binary": "nikto",
        "install": "apt-get install -y nikto",
        "category": "web",
        "timeout": 600,
        "description": "Web server vulnerability scanner",
    },
    "nuclei": {
        "binary": "nuclei",
        "timeout": TOOL_NUCLEI_TIMEOUT,
        # Use GitHub latest release API instead of hardcoded version
        "install": (
            "NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei"
            "/releases/latest | grep 'tag_name' | cut -d '\"' -f 4 | tr -d 'v') && "
            "curl -sL \"https://github.com/projectdiscovery/nuclei/releases/download"
            "/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip\" -o /tmp/nuclei.zip && "
            "cd /tmp && unzip -o nuclei.zip nuclei && "
            "chmod +x nuclei && mv nuclei /usr/local/bin/nuclei && "
            "/usr/local/bin/nuclei -version && "
            "/usr/local/bin/nuclei -ut -silent || true"
        ),
        "category": "vulnerability",
        "description": "Template-based vulnerability scanner",
    },
    "ffuf": {
        "binary": "ffuf",
        "install": (
            "apt-get install -y ffuf 2>/dev/null || ("
            "FFUF_VER=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest"
            " | grep -oP '(?<=\"tag_name\": \"v)[^\"]+') && "
            "curl -sL \"https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}"
            "/ffuf_${FFUF_VER}_linux_amd64.tar.gz\" -o /tmp/ffuf.tar.gz && "
            "tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf && "
            "chmod +x /usr/local/bin/ffuf)"
        ),
        "category": "web",
        "timeout": TOOL_FFUF_TIMEOUT,
        "description": "Web fuzzer",
    },
    "gobuster": {
        "binary": "gobuster",
        "install": "apt-get install -y gobuster",
        "category": "recon",
        "timeout": TOOL_GOBUSTER_TIMEOUT,
        "description": "URI and DNS subdomain brute-forcer",
    },
    "dirb": {
        "binary": "dirb",
        "install": "apt-get install -y dirb",
        "category": "web",
        "timeout": 300,
        "description": "Web directory scanner",
    },
    "sqlmap": {
        "binary": "sqlmap",
        "install": "apt-get install -y sqlmap",
        "category": "exploitation",
        "timeout": 600,
        "description": "SQL injection tool",
    },
    "hydra": {
        "binary": "hydra",
        "install": "apt-get install -y hydra",
        "category": "exploitation",
        "timeout": 360,
        "description": "Login brute forcer",
    },
    "msfconsole": {
        "binary": "msfconsole",
        "install": (
            "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus"
            "/master/config/templates/metasploit-framework-wrappers/msfupdate.erb"
            " > /tmp/msfinstall && chmod 755 /tmp/msfinstall && /tmp/msfinstall"
        ),
        "category": "exploitation",
        "timeout": TOOL_METASPLOIT_TIMEOUT,
        "description": "Metasploit framework",
    },
    "enum4linux": {
        "binary": "enum4linux",
        "install": "apt-get install -y enum4linux",
        "category": "recon",
        "timeout": 120,
        "description": "Windows/Samba enumeration",
    },
    "theharvester": {
        "binary": "theharvester",
        "timeout": 120,
        "install": (
            "apt-get update && apt-get install -y python3-venv git 2>/dev/null; "
            "mkdir -p /opt/theHarvester; "
            "python3 -m venv /opt/theHarvester/venv; "
            "/opt/theHarvester/venv/bin/pip install git+https://github.com/laramies/theHarvester.git --quiet; "
            "ln -sf /opt/theHarvester/venv/bin/theHarvester /usr/local/bin/theharvester"
        ),
        "category": "recon",
        "description": "OSINT email/subdomain harvester",
    },
    "whois": {
        "binary": "whois",
        "install": "apt-get install -y whois",
        "category": "recon",
        "timeout": 30,
        "description": "WHOIS lookup",
    },
    "subfinder": {
        "binary": "subfinder",
        "install": "apt-get install -y subfinder 2>/dev/null || (SUBFINDER_VER=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep 'tag_name' | cut -d '\"' -f 4 | tr -d 'v') && curl -sL \"https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VER}/subfinder_${SUBFINDER_VER}_linux_amd64.zip\" -o /tmp/subfinder.zip && cd /tmp && unzip -o subfinder.zip subfinder && chmod +x subfinder && mv subfinder /usr/local/bin/subfinder)",
        "category": "recon",
        "timeout": 300,
        "description": "Subdomain discovery tool",
    },
    "dig": {
        "binary": "dig",
        "install": "apt-get install -y dnsutils",
        "category": "recon",
        "timeout": 30,
        "description": "DNS lookup",
    },
    "curl": {
        "binary": "curl",
        "install": "apt-get install -y curl",
        "category": "web",
        "timeout": 30,
        "description": "HTTP client",
    },
    "smbclient": {
        "binary": "smbclient",
        "install": "apt-get install -y smbclient",
        "category": "recon",
        "timeout": 60,
        "description": "SMB enumeration",
    },
    "john": {
        "binary": "john",
        "install": "apt-get install -y john",
        "category": "post_exploitation",
        "timeout": 600,
        "description": "Password cracker",
    },
    "jq": {
        "binary": "jq",
        "install": "apt-get install -y jq",
        "category": "utility",
        "timeout": 30,
        "description": "JSON processor",
    },
    "dirsearch": {
        "binary": "dirsearch",
        "install": "pip3 install dirsearch --break-system-packages 2>/dev/null || apt-get install -y dirsearch",
        "category": "web",
        "timeout": 600,
        "description": "Web path scanner",
    },
    "nc": {
        "binary": "nc",
        "install": "apt-get install -y netcat-openbsd",
        "category": "exploitation",
        "timeout": 60,
        "description": "Netcat",
    },
    "wafw00f": {
        "binary": "wafw00f",
        "install": (
            "apt-get install -y wafw00f 2>/dev/null || "
            "pip3 install wafw00f --break-system-packages 2>/dev/null || "
            "pip3 install wafw00f"
        ),
        "category": "recon",
        "timeout": TOOL_WAF_TIMEOUT,
        "description": "WAF fingerprinting tool",
    },
    "wget": {
        "binary": "wget",
        "install": "apt-get install -y wget",
        "category": "web",
        "timeout": 30,
        "description": "HTTP client (Fallback)",
    },
    "curl-impersonate": {
        "binary": "curl-impersonate-chrome",
        "install": "apt-get update && apt-get install -y curl-impersonate 2>/dev/null || (curl -sL https://github.com/lwthiker/curl-impersonate/releases/download/v0.6.1/curl-impersonate-v0.6.1.x86_64-linux-gnu.tar.gz -o /tmp/curl-imp.tar.gz && tar -xzf /tmp/curl-imp.tar.gz -C /usr/local/bin)",
        "category": "web",
        "timeout": 30,
        "description": "Custom curl build for TLS fingerprinting impersonation",
    },
    "playwright": {
        "binary": "playwright",
        "install": (
            "apt-get install -y libnss3 libatk-bridge2.0-0 libdrm2 "
            "libxkbcommon0 libgbm1 libasound2 2>/dev/null; "
            "pip3 install playwright --break-system-packages --quiet && "
            "playwright install chromium"
        ),
        "install_timeout": 600,
        "category": "web",
        "timeout": 60,
        "description": "Headless browser automation",
    },
    "sslscan": {
        "binary": "sslscan",
        "install": "apt-get install -y sslscan",
        "category": "recon",
        "timeout": 180,
        "description": "TLS protocol and cipher scanner",
    },
    "whatweb": {
        "binary": "whatweb",
        "install": "apt-get install -y whatweb",
        "category": "recon",
        "timeout": 90,
        "description": "Web stack fingerprinting tool",
    },
    "ai_dynamic_recon": {
        "binary": "ai_dynamic_recon",
        "category": "virtual_recon",
        "timeout": 120,
        "description": "AI-generated dynamic recon/exploit commands with Guardian validation",
    },
    "tor": {
        "binary": "tor",
        "install": "apt-get update && apt-get install -y tor proxychains4",
        "category": "proxy",
        "timeout": 120,
        "description": "Tor routing and proxychains support",
    },
    "dalfox": {
        "binary": "dalfox",
        "install": (
            "DALFOX_VER=$(curl -s https://api.github.com/repos/hahwul/dalfox/releases/latest | grep 'tag_name' | cut -d '\"' -f 4) && "
            "curl -sL \"https://github.com/hahwul/dalfox/releases/download/${DALFOX_VER}/dalfox_${DALFOX_VER#v}_linux_amd64.tar.gz\" -o /tmp/dalfox.tar.gz && "
            "tar -xzf /tmp/dalfox.tar.gz -C /usr/local/bin dalfox && "
            "chmod +x /usr/local/bin/dalfox"
        ),
        "category": "exploitation",
        "timeout": 300,
        "description": "Parameter analysis and XSS scanner",
    },
    "amass": {
        "binary": "amass",
        "install": (
            "apt-get update && apt-get install -y amass 2>/dev/null || ("
            "AMASS_VER=$(curl -s https://api.github.com/repos/owasp-amass/amass/releases/latest | grep 'tag_name' | cut -d '\"' -f 4 | tr -d 'v') && "
            "curl -sL \"https://github.com/owasp-amass/amass/releases/download/v${AMASS_VER}/amass_linux_amd64.zip\" -o /tmp/amass.zip && "
            "cd /tmp && unzip -o amass.zip && "
            "mv amass_linux_amd64/amass /usr/local/bin/amass && "
            "chmod +x /usr/local/bin/amass)"
        ),
        "category": "recon",
        "timeout": 300,
        "description": "Subdomain enumeration via active/passive discovery",
    },
}
