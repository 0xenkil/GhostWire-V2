from config import (
    TOOL_NMAP_TIMEOUT, TOOL_MASSCAN_TIMEOUT, TOOL_NUCLEI_TIMEOUT,
    TOOL_GOBUSTER_TIMEOUT, TOOL_FFUF_TIMEOUT, TOOL_METASPLOIT_TIMEOUT,
    TOOL_WAF_TIMEOUT
)

TOOL_TIMEOUTS = {
    "nikto":       600,
    "nuclei":      TOOL_NUCLEI_TIMEOUT,
    "gobuster":    TOOL_GOBUSTER_TIMEOUT,
    "ffuf":        TOOL_FFUF_TIMEOUT,
    "masscan":     TOOL_MASSCAN_TIMEOUT,
    "nmap":        TOOL_NMAP_TIMEOUT,
    "hydra":       240,
    "sqlmap":      300,
    "default":     120,
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
        "binary": "theHarvester",
        "timeout": 120,
        "install": (
            "apt-get update && apt-get install -y theharvester 2>/dev/null; "
            "pip3 install theHarvester --break-system-packages --quiet 2>/dev/null; "
            "TH_PATH=$(which theHarvester || which theharvester); "
            "if [ ! -z \"$TH_PATH\" ]; then ln -sf \"$TH_PATH\" /usr/local/bin/theharvester; fi"
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
        "install": (
            "apt-get install -y curl-impersonate 2>/dev/null || "
            "( curl -sL https://github.com/lwthiker/curl-impersonate/releases/download/"
            "v0.6.1/curl-impersonate-v0.6.1.x86_64-linux-gnu.tar.gz "
            "-o /tmp/curl-imp.tar.gz && "
            "tar -xzf /tmp/curl-imp.tar.gz -C /usr/local/bin/ && "
            "chmod +x /usr/local/bin/curl-impersonate-chrome )"
        ),
        "category": "web",
        "timeout": 30,
        "description": "Chrome-fingerprint curl (JA3 bypass)",
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
        "description": "Headless browser automation (JS challenge bypass)",
    },
}
