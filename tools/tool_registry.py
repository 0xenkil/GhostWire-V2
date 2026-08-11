from config_thresholds import (
    TOOL_NMAP_TIMEOUT, TOOL_MASSCAN_TIMEOUT, TOOL_NUCLEI_TIMEOUT,
    TOOL_GOBUSTER_TIMEOUT, TOOL_FFUF_TIMEOUT, TOOL_METASPLOIT_TIMEOUT,
    TOOL_WAF_TIMEOUT
)

import json
from pathlib import Path
from utils.logger import get_logger

log = get_logger("tool_registry")

TOOL_TIMEOUTS = {
    "nikto": 600,
    "nuclei": TOOL_NUCLEI_TIMEOUT,
    "sslscan": 180,
    "whatweb": 90,
    "gobuster": TOOL_GOBUSTER_TIMEOUT,
    "ffuf": TOOL_FFUF_TIMEOUT,
    "masscan": TOOL_MASSCAN_TIMEOUT,
    "nmap": TOOL_NMAP_TIMEOUT,
    "hydra": 240,
    "sqlmap": 300,
    "default": 120,
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

# Tools that primarily use HTTP/S and benefit from WAF evasion/TLS circuit
# breaking
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
WRAPPER_TOOLS = {
    "timeout",
    "sudo",
    "env",
    "nice",
    "proxychains4",
    "proxychains"}

# Tools that write to a file (-o, -oG, -oN, etc.) - prefer file readback on VPS
FILE_OUTPUT_TOOLS = {"nuclei", "nmap", "nikto", "masscan", "gobuster"}

# Tool fallback mappings: if primary tool unavailable, use alternatives
# Phase 4 Fix: Expanded fallback chains to improve resilience
TOOL_FALLBACKS = {
    # if nuclei fails, try nikto web scanner
    "nuclei": ["nikto", "ffuf", "curl"],
    # if nikto fails, try dir brute-force
    "nikto": ["gobuster", "ffuf", "curl"],
    "gobuster": ["ffuf", "dirbuster", "curl"],    # if gobuster fails, try ffuf
    # if ffuf fails, try gobuster
    "ffuf": ["gobuster", "curl"],
    # if nmap fails, try masscan port scan
    "nmap": ["masscan", "curl"],
    "masscan": ["nmap", "curl"],                   # if masscan fails, try nmap
    # if curl network fails, try wget
    "curl": ["wget", "nc"],
    "wget": ["curl"],                              # if wget fails, try curl
    # if sqlmap fails, try manual curl probes
    "sqlmap": ["curl", "nikto"],
    # if theharvester fails, try dig
    "theharvester": ["curl", "dig"],
    "dig": ["nslookup", "host"],                   # if dig fails, try nslookup
    # if subfinder fails, try amass
    "subfinder": ["amass", "curl"],
    # if amass fails, try subfinder
    "amass": ["subfinder", "curl"],
}

_RAW_TOOL_REGISTRY = {   # authored seed; public TOOL_REGISTRY (below) is a generated view (P2-4)
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
        "description": "Template-based vulnerability scanner. Target URL must include http:// or https:// scheme.",
    },
    "nmap": {
        "binary": "nmap",
        "install": "apt-get update && apt-get install -y nmap dnsutils",
        "category": "scanning",
        "timeout": TOOL_NMAP_TIMEOUT,
        "description": "Network port scanner. CRITICAL CONSTRAINT: Always use -T4 for speed and avoid interactive flags.",
    },
    "masscan": {
        "binary": "masscan",
        "install": "apt-get update && apt-get install -y masscan",
        "category": "scanning",
        "timeout": TOOL_MASSCAN_TIMEOUT,
        "description": "Fast port scanner. CRITICAL CONSTRAINT: You MUST prefix this command with 'sudo'. ONLY accepts IP addresses or CIDR ranges. NEVER pass a domain name or hostname. The IP MUST be the very last argument.",
    },
    "nikto": {
        "binary": "nikto",
        "install": "apt-get install -y nikto libnet-ssleay-perl",
        "category": "web",
        "timeout": 600,
        "description": "Web server vulnerability scanner. CRITICAL CONSTRAINT: MUST pass target with -h <URL>.",
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
        "description": "Web fuzzer. CRITICAL CONSTRAINT: Must use -w with a wordlist and the target URL MUST contain the word FUZZ.",
    },
    "gobuster": {
        "binary": "gobuster",
        "install": "apt-get install -y gobuster",
        "category": "recon",
        "timeout": TOOL_GOBUSTER_TIMEOUT,
        "description": "URI and DNS subdomain brute-forcer. CRITICAL CONSTRAINT: Use 'gobuster dir -u <URL> -w <wordlist>' for directories.",
    },
    "dirb": {
        "binary": "dirb",
        "install": "apt-get install -y dirb",
        "category": "web",
        "timeout": 300,
        "description": "Web directory scanner",
    },
    "wpscan": {
        "binary": "wpscan",
        "install": "apt-get install -y ruby-dev && gem install wpscan",
        "category": "recon",
        "timeout": 600,
        "description": "WordPress vulnerability scanner",
    },
    "sqlmap": {
        "binary": "sqlmap",
        "install": "apt-get install -y sqlmap",
        "category": "exploitation",
        "timeout": 600,
        "description": "SQL injection tool. CRITICAL CONSTRAINT: MUST include --batch to run non-interactively.",
    },
    "hydra": {
        "binary": "hydra",
        "install": "apt-get install -y hydra",
        "category": "exploitation",
        "timeout": 360,
        "description": "Login brute-forcer. CRITICAL CONSTRAINT: Do not prompt for input.",
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
        "description": "Metasploit framework. CRITICAL CONSTRAINT: MUST be run non-interactively using: msfconsole -q -x 'use <module>; set RHOSTS <target>; run; exit'",
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
        "timeout": 60,
        "description": "Command line HTTP client. CRITICAL CONSTRAINT: ALWAYS use -s (silent) and -L (follow redirects).",
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
        "install": (
            "apt-get update && apt-get install -y ruby ruby-dev git --no-install-recommends; "
            "rm -rf /opt/whatweb; "
            "git clone https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb; "
            "ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb; "
            "chmod +x /opt/whatweb/whatweb"
        ),
        "category": "recon",
        "timeout": 180,
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


def _build_registry_view() -> dict:
    """P2-4: TOOL_REGISTRY is a GENERATED view over the private authored seed
    (_RAW_TOOL_REGISTRY) merged with the ToolCatalog. Authored tools keep their
    exact entry (zero behaviour change for existing consumers); catalog-only
    tools (the modern Go arsenal seeded in the catalog) appear here automatically
    — one source of truth, deduped by name. Safe: a catalog failure degrades to
    the raw seed rather than raising."""
    view = dict(_RAW_TOOL_REGISTRY)
    try:
        from tools.tool_catalog import get_catalog
        cat = get_catalog()
        for e in cat.all():
            key = (getattr(e, "name", "") or "").lower()
            if not key or key in view:
                continue
            view[key] = {
                "binary": getattr(e, "binary", key) or key,
                "install": cat.install_command(key) or "",
                "category": (getattr(e, "primary_capability", "")
                             or getattr(e, "category", "utility")),
                "timeout": 120,
                "description": "",
            }
    except Exception as _e:
        log.debug(f"[P2-4] catalog view merge skipped: {_e}")
    return view


# Public generated view (a plain dict so register_tool can mutate it in place and
# all existing `from tools.tool_registry import TOOL_REGISTRY` consumers keep working).
TOOL_REGISTRY = _build_registry_view()


def register_tool(name: str, config: dict) -> None:
    """Register a new tool dynamically."""
    TOOL_REGISTRY[name] = config

    # Dynamically update related sets based on properties
    timeout = config.get("timeout", 120)
    TOOL_TIMEOUTS[name] = timeout

    # Ensure fallbacks are registered if provided
    if "fallbacks" in config:
        TOOL_FALLBACKS[name] = config["fallbacks"]

    log.info(f"Dynamically registered tool: {name}")


def load_custom_tools(tools_dir: str) -> None:
    """Load all custom tools from JSON files in the specified directory."""
    dir_path = Path(tools_dir)
    if not dir_path.exists():
        return

    for file_path in dir_path.glob("*.json"):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    for tool_name, tool_config in data.items():
                        register_tool(tool_name, tool_config)
        except Exception as e:
            log.warning(
                f"Failed to load custom tool from {
                    file_path.name}: {e}")
