"""
capability_registry.py - Ghostwire V6 Universal Capability Engine

Replaces hardcoded tool lists with a capability-driven architecture.
The system asks: "Can I discover subdomains?" not "Is subfinder installed?"
"""
from __future__ import annotations
import time
import copy
from core.result_contracts import FragileParseFixer
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable, Optional
from utils.logger import get_logger
from core.config_loader import get_config_manager  # P5-2: one config authority
from core.config_loader import get_config  # For YAML-based config (2-arg getter)

log = get_logger("capability")

# Load config with safe defaults (prevent import-time crash)
try:
    _config = get_config_manager()
    TOOL_INSTALL_CHECK_TIMEOUT = getattr(
        _config.timeout, 'tool_install_check', 30)
    TOOL_VERIFY_TIMEOUT = _config.timeout.tool_verify
except Exception:
    log.warning("Failed to load config, using safe defaults for tool timeouts")
    TOOL_INSTALL_CHECK_TIMEOUT = 30
    TOOL_VERIFY_TIMEOUT = 30


# ── Tool URLs (Sync with tools.yaml) ──────────────────────────────────────
def _safe_get_config(path: str, key: str, default: str) -> str:
    try:
        return get_config(path, key, default)
    except Exception as e:
        import logging as __logging_tmp
        __logging_tmp.getLogger(__name__).error(
            f"Unhandled exception: {e}", exc_info=True)
        return default


URL_AMASS_API = _safe_get_config(
    "tools",
    "urls.amass_api",
    "https://api.github.com/repos/owasp-amass/amass/releases/latest")
URL_AMASS_DL = _safe_get_config(
    "tools",
    "urls.amass_download",
    "https://github.com/owasp-amass/amass/releases/download")
URL_SUBFINDER_API = _safe_get_config(
    "tools",
    "urls.subfinder_api",
    "https://api.github.com/repos/projectdiscovery/subfinder/releases/latest")
URL_SUBFINDER_DL = _safe_get_config(
    "tools",
    "urls.subfinder_download",
    "https://github.com/projectdiscovery/subfinder/releases/download")
URL_NUCLEI_API = _safe_get_config(
    "tools",
    "urls.nuclei_api",
    "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest")
URL_NUCLEI_DL = _safe_get_config(
    "tools",
    "urls.nuclei_download",
    "https://github.com/projectdiscovery/nuclei/releases/download")
URL_FFUF_API = _safe_get_config(
    "tools",
    "urls.ffuf_api",
    "https://api.github.com/repos/ffuf/ffuf/releases/latest")
URL_FFUF_DL = _safe_get_config(
    "tools",
    "urls.ffuf_download",
    "https://github.com/ffuf/ffuf/releases/download")

# ── Fallback Versions (Resilience for GitHub API failures) ───────────────
FALLBACK_AMASS = _safe_get_config("tools", "fallbacks.amass_version", "4.2.0")
FALLBACK_SUBFINDER = _safe_get_config(
    "tools", "fallbacks.subfinder_version", "2.6.6")
FALLBACK_NUCLEI = _safe_get_config(
    "tools", "fallbacks.nuclei_version", "3.2.9")
FALLBACK_FFUF = _safe_get_config("tools", "fallbacks.ffuf_version", "2.1.0")


class CapabilityCategory(str, Enum):
    RECON = "recon"
    SCAN = "scan"
    WEB = "web"
    EXPLOIT = "exploit"
    POST = "post"
    UTILITY = "utility"
    PROXY = "proxy"


class RiskLevel(str, Enum):
    NONE = "none"         # read-only
    LOW = "low"           # probe / enumerate
    MEDIUM = "medium"     # fuzz / brute
    HIGH = "high"         # exploit attempts
    DESTRUCTIVE = "destructive"  # writes / persistence


@dataclass
class ToolCapability:
    """A single tool that satisfies one or more capabilities."""
    name: str
    binary: str
    capabilities: list[str]                  # e.g. ["discover_subdomains"]
    install_cmds: dict[str, str] = field(
        default_factory=dict)  # OS -> install script
    install_timeout: int = 300
    category: CapabilityCategory = CapabilityCategory.UTILITY
    risk: RiskLevel = RiskLevel.LOW
    timeout_default: int = 120
    description: str = ""
    # Path C auto-install gates
    # Gate 1: is this in the pre-approved installable list?
    can_auto_install: bool = True
    min_disk_mb: int = 100              # Gate 4: minimum free disk needed on VPS
    min_ram_mb: int = 50                # Gate 4: minimum free RAM needed on VPS
    # Optional: function to detect if the tool is present without running it
    check_present: Optional[Callable[[str], bool]] = None
    sha256: str = ""  # Gate 6: optional SHA256 checksum for binary integrity


# ═══════════════════════════════════════════════════════════════════════════
# MASTER CAPABILITY DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════

DISCOVER_SUBDOMAINS = ToolCapability(
    name="subfinder",
    binary="subfinder",
    capabilities=["discover_subdomains", "dns_enum"],
    install_cmds={
        "debian": "apt-get install -y subfinder 2>/dev/null || (curl -sL 'https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip' -o /tmp/sf.zip && unzip -o /tmp/sf.zip -d /usr/local/bin && chmod +x /usr/local/bin/subfinder)",
        "alpine": "apk add --no-cache subfinder 2>/dev/null || (wget -O /tmp/sf.zip 'https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip' && unzip -o /tmp/sf.zip -d /usr/local/bin && chmod +x /usr/local/bin/subfinder)",
        "redhat": "dnf install -y subfinder 2>/dev/null || (curl -sL 'https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip' -o /tmp/sf.zip && unzip -o /tmp/sf.zip -d /usr/local/bin && chmod +x /usr/local/bin/subfinder)",
        "arch": "pacman -Sy --noconfirm subfinder 2>/dev/null || (curl -sL 'https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip' -o /tmp/sf.zip && unzip -o /tmp/sf.zip -d /usr/local/bin && chmod +x /usr/local/bin/subfinder)",
        "generic": "curl -sL 'https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip' -o /tmp/sf.zip && unzip -o /tmp/sf.zip -d /usr/local/bin && chmod +x /usr/local/bin/subfinder",
    },
    category=CapabilityCategory.RECON,
    timeout_default=300,
    description="Subdomain discovery via ProjectDiscovery",
)

DISCOVER_SUBDOMAINS_ALT = ToolCapability(
    name="amass",
    binary="amass",
    capabilities=["discover_subdomains", "dns_enum"],
    install_cmds={
        "debian": "apt-get update && apt-get install -y amass 2>/dev/null",
        "generic": (
            f"V=$(curl -s {URL_AMASS_API} | grep 'tag_name' | cut -d '\"' -f 4 | tr -d 'v'); "
            f"[ -z \"$V\" ] && V={FALLBACK_AMASS}; "
            f"curl -sL \"{URL_AMASS_DL}/v${{V}}/amass_linux_amd64.zip\" -o /tmp/amass.zip || curl -sL \"{URL_AMASS_DL}/v${{V}}/amass_linux_amd64.tar.gz\" -o /tmp/amass.tar.gz && "
            f"mkdir -p /tmp/amass_extracted && (unzip -o /tmp/amass.zip -d /tmp/amass_extracted 2>/dev/null || tar -xzf /tmp/amass.tar.gz -C /tmp/amass_extracted 2>/dev/null) && "
            f"find /tmp/amass_extracted -name amass -type f -exec mv {{}} /usr/local/bin/amass \\; && "
            f"chmod +x /usr/local/bin/amass && rm -rf /tmp/amass_extracted /tmp/amass.zip /tmp/amass.tar.gz"
        ),
    },
    category=CapabilityCategory.RECON,
    timeout_default=300,
    description="OWASP Amass subdomain enumeration",
)

DNS_LOOKUP = ToolCapability(
    name="dig",
    binary="dig",
    capabilities=["dns_lookup", "dns_enum"],
    install_cmds={
        "debian": "apt-get install -y dnsutils",
        "alpine": "apk add --no-cache bind-tools",
        "redhat": "dnf install -y bind-utils",
        "arch": "pacman -Sy --noconfirm bind",
        "generic": "apt-get install -y dnsutils",
    },
    category=CapabilityCategory.RECON,
    timeout_default=30,
    description="DNS lookup via ISC BIND dig",
)

PORT_SCAN = ToolCapability(
    name="nmap",
    binary="nmap",
    capabilities=["port_scan", "service_detect", "os_detect"],
    install_cmds={
        "debian": "apt-get install -y nmap",
        "alpine": "apk add --no-cache nmap",
        "redhat": "dnf install -y nmap",
        "arch": "pacman -Sy --noconfirm nmap",
        "generic": "apt-get install -y nmap",
    },
    category=CapabilityCategory.SCAN,
    timeout_default=600,
    description="Network port scanner. CRITICAL CONSTRAINT: Always use -T4 for speed and avoid interactive flags.",
)

FAST_PORT_SCAN = ToolCapability(
    name="masscan",
    binary="masscan",
    capabilities=["fast_port_scan"],
    install_cmds={
        "debian": "apt-get install -y masscan",
        "alpine": "apk add --no-cache masscan",
        "redhat": "dnf install -y masscan",
        "arch": "pacman -Sy --noconfirm masscan",
        "generic": "apt-get install -y masscan",
    },
    category=CapabilityCategory.SCAN,
    timeout_default=1800,
    description="High-speed asynchronous port scanner. CRITICAL CONSTRAINT: ONLY accepts IP addresses or CIDR ranges. NEVER pass a domain name or hostname.",
)

WEB_VULN_SCAN = ToolCapability(
    name="nuclei",
    binary="nuclei",
    capabilities=["web_vuln_scan", "cve_scan", "misconfig_scan"],
    install_cmds={
        "debian": "apt-get install -y nuclei 2>/dev/null",
        "generic": (
            f"NUCLEI_VER=$(curl -s {URL_NUCLEI_API} | grep 'tag_name' | cut -d '\"' -f 4 | tr -d 'v') && "
            f"curl -sL \"{URL_NUCLEI_DL}/v${{NUCLEI_VER}}/nuclei_${{NUCLEI_VER}}_linux_amd64.zip\" -o /tmp/nuclei.zip && "
            f"unzip -o /tmp/nuclei.zip nuclei && chmod +x nuclei && mv nuclei /usr/local/bin/ && "
            f"nuclei -ut -silent || true"
        ),
    },
    category=CapabilityCategory.WEB,
    timeout_default=2400,
    description="Template-based vulnerability scanner. Target URL must include http:// or https:// scheme.",
)

WEB_SERVER_SCAN = ToolCapability(
    name="nikto",
    binary="nikto",
    capabilities=["web_server_scan", "misconfig_scan"],
    install_cmds={
        "debian": "apt-get install -y nikto libnet-ssleay-perl",
        "alpine": "apk add --no-cache nikto",
        "redhat": "dnf install -y nikto",
        "arch": "pacman -Sy --noconfirm nikto",
        "generic": "apt-get install -y nikto",
    },
    category=CapabilityCategory.WEB,
    timeout_default=600,
    description="Web server vulnerability scanner. CRITICAL CONSTRAINT: MUST pass target with -h <URL>.",
)

DIRECTORY_FUZZ = ToolCapability(
    name="gobuster",
    binary="gobuster",
    capabilities=["directory_fuzz", "dns_enum"],
    install_cmds={
        "debian": "apt-get install -y gobuster",
        "alpine": "apk add --no-cache gobuster",
        "redhat": "dnf install -y gobuster",
        "arch": "pacman -Sy --noconfirm gobuster",
        "generic": "apt-get install -y gobuster",
    },
    category=CapabilityCategory.WEB,
    timeout_default=900,
    description="Directory and DNS brute-forcer. CRITICAL CONSTRAINT: Use 'gobuster dir -u <URL> -w <wordlist>' for directories.",
)

WEB_FUZZ = ToolCapability(
    name="ffuf",
    binary="ffuf",
    capabilities=["directory_fuzz", "web_fuzz"],
    install_cmds={
        "debian": "apt-get install -y ffuf 2>/dev/null || (FFUF_VER=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | grep -oP '(?<=\"tag_name\": \"v)[^\"]+') && curl -sL \"https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_amd64.tar.gz\" -o /tmp/ffuf.tar.gz && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf && chmod +x /usr/local/bin/ffuf)",
        "generic": "FFUF_VER=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | grep -oP '(?<=\"tag_name\": \"v)[^\"]+') && curl -sL \"https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_amd64.tar.gz\" -o /tmp/ffuf.tar.gz && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf && chmod +x /usr/local/bin/ffuf",
    },
    category=CapabilityCategory.WEB,
    timeout_default=1200,
    description="Fast web fuzzer. CRITICAL CONSTRAINT: Must use -w with a wordlist and the target URL MUST contain the word FUZZ.",
)

HTTP_PROBE = ToolCapability(
    name="curl",
    binary="curl",
    capabilities=["http_probe", "http_download", "header_extract"],
    install_cmds={
        "debian": "apt-get install -y curl",
        "alpine": "apk add --no-cache curl",
        "redhat": "dnf install -y curl",
        "arch": "pacman -Sy --noconfirm curl",
        "generic": "apt-get install -y curl",
    },
    category=CapabilityCategory.UTILITY,
    timeout_default=30,
    description="HTTP/HTTPS client. CRITICAL CONSTRAINT: ALWAYS use -s (silent) and -L (follow redirects).",
)

SQL_INJECTION_TEST = ToolCapability(
    name="sqlmap",
    binary="sqlmap",
    capabilities=["sql_injection_test"],
    install_cmds={
        "debian": "apt-get install -y sqlmap",
        "alpine": "apk add --no-cache sqlmap",
        "redhat": "dnf install -y sqlmap",
        "arch": "pacman -Sy --noconfirm sqlmap",
        "generic": "apt-get install -y sqlmap",
    },
    category=CapabilityCategory.EXPLOIT,
    risk=RiskLevel.HIGH,
    timeout_default=300,
    description="SQL injection automation. CRITICAL CONSTRAINT: MUST include --batch to run non-interactively.",
)

CREDENTIAL_BRUTE = ToolCapability(
    name="hydra",
    binary="hydra",
    capabilities=["credential_brute"],
    install_cmds={
        "debian": "apt-get install -y hydra",
        "alpine": "apk add --no-cache hydra",
        "redhat": "dnf install -y hydra",
        "arch": "pacman -Sy --noconfirm hydra",
        "generic": "apt-get install -y hydra",
    },
    category=CapabilityCategory.EXPLOIT,
    risk=RiskLevel.MEDIUM,
    timeout_default=360,
    description="Login brute-forcer. CRITICAL CONSTRAINT: Do not prompt for input.",
)

SSL_AUDIT = ToolCapability(
    name="sslscan",
    binary="sslscan",
    capabilities=["ssl_audit", "tls_audit"],
    install_cmds={
        "debian": "apt-get install -y sslscan",
        "alpine": "apk add --no-cache sslscan",
        "redhat": "dnf install -y sslscan",
        "arch": "pacman -Sy --noconfirm sslscan",
        "generic": "apt-get install -y sslscan",
    },
    category=CapabilityCategory.WEB,
    timeout_default=180,
    description="TLS/SSL cipher and certificate scanner. CRITICAL CONSTRAINT: Target must be domain or IP, NOT http://.",
)

TECH_FINGERPRINT = ToolCapability(
    name="whatweb",
    binary="whatweb",
    capabilities=["tech_fingerprint", "web_stack_detect"],
    install_cmds={
        "debian": "apt-get install -y whatweb",
        "alpine": "apk add --no-cache whatweb",
        "redhat": "dnf install -y whatweb",
        "arch": "pacman -Sy --noconfirm whatweb",
        "generic": "apt-get install -y whatweb",
    },
    category=CapabilityCategory.RECON,
    timeout_default=90,
    description="Web technology fingerprinting. CRITICAL CONSTRAINT: ALWAYS use -a 1 for stealth.",
)

WAF_DETECT = ToolCapability(
    name="wafw00f",
    binary="wafw00f",
    capabilities=["waf_detect", "cdn_detect"],
    install_cmds={
        "debian": "apt-get install -y wafw00f 2>/dev/null || pip3 install wafw00f",
        "alpine": "pip3 install wafw00f",
        "redhat": "pip3 install wafw00f",
        "arch": "pip3 install wafw00f",
        "generic": "pip3 install wafw00f",
    },
    category=CapabilityCategory.RECON,
    timeout_default=120,
    description="WAF fingerprinting tool. CRITICAL CONSTRAINT: ALWAYS use -a to find all WAFs.",
)

TOR_PROXY = ToolCapability(
    name="tor",
    binary="tor",
    capabilities=["tor_proxy", "ip_rotation"],
    install_cmds={
        "debian": "apt-get install -y tor proxychains4",
        "alpine": "apk add --no-cache tor proxychains-ng",
        "redhat": "dnf install -y tor proxychains-ng",
        "arch": "pacman -Sy --noconfirm tor proxychains-ng",
        "generic": "apt-get install -y tor proxychains4",
    },
    category=CapabilityCategory.PROXY,
    timeout_default=120,
    description="Tor routing and proxychains",
)

OSINT_HARVEST = ToolCapability(
    name="theharvester",
    binary="theharvester",
    capabilities=["osint_harvest", "email_discover"],
    install_cmds={
        "debian": "apt-get update && apt-get install -y theharvester 2>/dev/null; pip3 install theHarvester --break-system-packages --quiet 2>/dev/null; TH_PATH=$(which theHarvester || which theharvester); if [ ! -z \"$TH_PATH\" ]; then ln -sf \"$TH_PATH\" /usr/local/bin/theharvester; fi",
        "generic": "pip3 install theHarvester",
    },
    category=CapabilityCategory.RECON,
    timeout_default=120,
    description="OSINT email and subdomain harvester. CRITICAL CONSTRAINT: MUST use -d <domain> and -b <source>.",
)

# ── Extended Tool Registry (Path C additions) ─────────────────────────────

WEB_FUZZ_ALT = ToolCapability(
    name="wfuzz",
    binary="wfuzz",
    capabilities=["directory_fuzz", "web_fuzz", "parameter_fuzz"],
    install_cmds={
        "debian": "apt-get install -y wfuzz 2>/dev/null || pip3 install wfuzz",
        "generic": "pip3 install wfuzz",
    },
    category=CapabilityCategory.WEB,
    timeout_default=900,
    description="Web application fuzzer. CRITICAL CONSTRAINT: MUST pass wordlist with -z file,<wordlist>.",
    min_disk_mb=50,
)

FAST_DIR_FUZZ = ToolCapability(
    name="feroxbuster",
    binary="feroxbuster",
    capabilities=["directory_fuzz", "web_fuzz"],
    install_cmds={
        "debian": "apt-get install -y feroxbuster 2>/dev/null || curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin",
        "generic": "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin",
    },
    category=CapabilityCategory.WEB,
    risk=RiskLevel.LOW,
    timeout_default=900,
    description="Fast recursive directory fuzzer. CRITICAL CONSTRAINT: ALWAYS use --silent and -u <URL>.",
    min_disk_mb=80,
)

HTTP_PROBE_FAST = ToolCapability(
    name="httpx",
    binary="httpx",
    capabilities=["http_probe", "tech_fingerprint", "web_stack_detect"],
    install_cmds={
        "debian": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && mv ~/go/bin/httpx /usr/local/bin/",
        "generic": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && mv ~/go/bin/httpx /usr/local/bin/",
    },
    category=CapabilityCategory.RECON,
    timeout_default=180,
    description="Fast HTTP probing and fingerprinting",
    min_disk_mb=60,
)

PORT_SCAN_FAST = ToolCapability(
    name="naabu",
    binary="naabu",
    capabilities=["port_scan", "fast_port_scan"],
    install_cmds={
        "debian": "apt-get install -y naabu 2>/dev/null || go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && mv ~/go/bin/naabu /usr/local/bin/",
        "generic": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && mv ~/go/bin/naabu /usr/local/bin/",
    },
    category=CapabilityCategory.SCAN,
    timeout_default=300,
    description="Fast port scanner from ProjectDiscovery",
    min_disk_mb=60,
)

DNS_BRUTE = ToolCapability(
    name="dnsx",
    binary="dnsx",
    capabilities=["dns_enum", "dns_brute"],
    install_cmds={
        "debian": "apt-get install -y dnsx 2>/dev/null || go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && mv ~/go/bin/dnsx /usr/local/bin/",
        "generic": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && mv ~/go/bin/dnsx /usr/local/bin/",
    },
    category=CapabilityCategory.RECON,
    timeout_default=300,
    description="Fast DNS resolver and brute-forcer",
    min_disk_mb=50,
)

TLS_SCAN = ToolCapability(
    name="tlsx",
    binary="tlsx",
    capabilities=["ssl_audit", "tls_audit", "cert_inspect"],
    install_cmds={
        "generic": "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest && mv ~/go/bin/tlsx /usr/local/bin/",
    },
    category=CapabilityCategory.WEB,
    timeout_default=120,
    description="Fast TLS grabber and analyzer",
    min_disk_mb=50,
)

PARAM_DISCOVER = ToolCapability(
    name="arjun",
    binary="arjun",
    capabilities=["parameter_discover", "web_fuzz"],
    install_cmds={
        "debian": "pip3 install arjun",
        "generic": "pip3 install arjun",
    },
    category=CapabilityCategory.WEB,
    timeout_default=300,
    description="HTTP parameter discovery tool",
    min_disk_mb=30,
)

XSS_SCAN = ToolCapability(
    name="dalfox",
    binary="dalfox",
    capabilities=["xss_scan", "web_fuzz"],
    install_cmds={
        "generic": "go install github.com/hahwul/dalfox/v2@latest && mv ~/go/bin/dalfox /usr/local/bin/",
    },
    category=CapabilityCategory.EXPLOIT,
    risk=RiskLevel.MEDIUM,
    timeout_default=300,
    description="XSS vulnerability scanner",
    min_disk_mb=60,
)

CMS_SCAN_WP = ToolCapability(
    name="wpscan",
    binary="wpscan",
    capabilities=["cms_scan", "wordpress_scan"],
    install_cmds={
        "debian": "apt-get install -y wpscan 2>/dev/null || gem install wpscan",
        "generic": "gem install wpscan",
    },
    category=CapabilityCategory.WEB,
    risk=RiskLevel.MEDIUM,
    timeout_default=600,
    description="WordPress vulnerability scanner",
    min_disk_mb=100,
)

DIR_SCAN = ToolCapability(
    name="dirsearch",
    binary="dirsearch",
    capabilities=["directory_fuzz", "web_fuzz"],
    install_cmds={
        "debian": "apt-get install -y dirsearch 2>/dev/null || pip3 install dirsearch",
        "generic": "pip3 install dirsearch",
    },
    category=CapabilityCategory.WEB,
    timeout_default=600,
    description="Web path brute-forcer",
    min_disk_mb=30,
)

WEB_CRAWL = ToolCapability(
    name="katana",
    binary="katana",
    capabilities=["web_crawl", "js_crawl"],
    install_cmds={
        "generic": "go install github.com/projectdiscovery/katana/cmd/katana@latest && mv ~/go/bin/katana /usr/local/bin/",
    },
    category=CapabilityCategory.RECON,
    timeout_default=300,
    description="Next-generation web crawler",
    min_disk_mb=80,
)

WEB_CRAWL_ALT = ToolCapability(
    name="gospider",
    binary="gospider",
    capabilities=["web_crawl"],
    install_cmds={
        "generic": "go install github.com/jaeles-project/gospider@latest && mv ~/go/bin/gospider /usr/local/bin/",
    },
    category=CapabilityCategory.RECON,
    timeout_default=300,
    description="Fast web spider",
    min_disk_mb=60,
)

DNS_RECON = ToolCapability(
    name="dnsrecon",
    binary="dnsrecon",
    capabilities=["dns_enum", "dns_recon", "zone_transfer"],
    install_cmds={
        "debian": "apt-get install -y dnsrecon 2>/dev/null || pip3 install dnsrecon",
        "generic": "pip3 install dnsrecon",
    },
    category=CapabilityCategory.RECON,
    timeout_default=300,
    description="DNS enumeration and zone transfer tool",
    min_disk_mb=30,
)

URL_HISTORY = ToolCapability(
    name="waybackurls",
    binary="waybackurls",
    capabilities=["url_discover", "osint_harvest"],
    install_cmds={
        "generic": "go install github.com/tomnomnom/waybackurls@latest && mv ~/go/bin/waybackurls /usr/local/bin/",
    },
    category=CapabilityCategory.RECON,
    timeout_default=120,
    description="Fetch URLs from Wayback Machine",
    min_disk_mb=30,
)

URL_HISTORY_ALT = ToolCapability(
    name="gau",
    binary="gau",
    capabilities=["url_discover", "osint_harvest"],
    install_cmds={
        "generic": "go install github.com/lc/gau/v2/cmd/gau@latest && mv ~/go/bin/gau /usr/local/bin/",
    },
    category=CapabilityCategory.RECON,
    timeout_default=120,
    description="Get all URLs from AlienVault, Wayback, Common Crawl",
    min_disk_mb=30,
)

SMB_ENUM = ToolCapability(
    name="smbclient",
    binary="smbclient",
    capabilities=["smb_enum", "file_share_enum"],
    install_cmds={
        "debian": "apt-get install -y smbclient",
        "alpine": "apk add --no-cache samba-client",
        "redhat": "dnf install -y samba-client",
        "generic": "apt-get install -y smbclient",
    },
    category=CapabilityCategory.RECON,
    timeout_default=120,
    description="SMB share enumeration",
    min_disk_mb=30,
)

LDAP_ENUM = ToolCapability(
    name="ldapsearch",
    binary="ldapsearch",
    capabilities=["ldap_enum"],
    install_cmds={
        "debian": "apt-get install -y ldap-utils",
        "redhat": "dnf install -y openldap-clients",
        "generic": "apt-get install -y ldap-utils",
    },
    category=CapabilityCategory.RECON,
    timeout_default=60,
    description="LDAP directory enumeration",
    min_disk_mb=20,
)

OPENSSL_TOOL = ToolCapability(
    name="openssl",
    binary="openssl",
    capabilities=["ssl_audit", "cert_inspect", "tls_audit"],
    install_cmds={
        "debian": "apt-get install -y openssl",
        "alpine": "apk add --no-cache openssl",
        "redhat": "dnf install -y openssl",
        "generic": "apt-get install -y openssl",
    },
    category=CapabilityCategory.UTILITY,
    timeout_default=30,
    description="OpenSSL command-line tool",
    min_disk_mb=10,
)

NETCAT_TOOL = ToolCapability(
    name="nc",
    binary="nc",
    capabilities=["network_connect", "port_check", "banner_grab"],
    install_cmds={
        "debian": "apt-get install -y netcat-openbsd",
        "alpine": "apk add --no-cache netcat-openbsd",
        "redhat": "dnf install -y nmap-ncat",
        "generic": "apt-get install -y netcat-openbsd",
    },
    category=CapabilityCategory.UTILITY,
    timeout_default=30,
    description="Netcat networking utility",
    min_disk_mb=5,
)

WHOIS_TOOL = ToolCapability(
    name="whois",
    binary="whois",
    capabilities=["osint_harvest", "domain_info"],
    install_cmds={
        "debian": "apt-get install -y whois",
        "alpine": "apk add --no-cache whois",
        "redhat": "dnf install -y whois",
        "generic": "apt-get install -y whois",
    },
    category=CapabilityCategory.RECON,
    timeout_default=30,
    description="Domain WHOIS lookup",
    min_disk_mb=5,
)

SQLI_ALT = ToolCapability(
    name="ghauri",
    binary="ghauri",
    capabilities=["sql_injection_test"],
    install_cmds={
        "generic": "pip3 install ghauri",
    },
    category=CapabilityCategory.EXPLOIT,
    risk=RiskLevel.HIGH,
    timeout_default=300,
    description="Advanced SQL injection detection tool",
    min_disk_mb=30,
)

CMD_INJECT = ToolCapability(
    name="commix",
    binary="commix",
    capabilities=["command_injection_test"],
    install_cmds={
        "debian": "apt-get install -y commix 2>/dev/null || pip3 install commix",
        "generic": "pip3 install commix",
    },
    category=CapabilityCategory.EXPLOIT,
    risk=RiskLevel.HIGH,
    timeout_default=300,
    description="Command injection exploitation tool",
    min_disk_mb=30,
)

PASSWD_CRACK = ToolCapability(
    name="john",
    binary="john",
    capabilities=["password_crack", "hash_crack"],
    install_cmds={
        "debian": "apt-get install -y john",
        "alpine": "apk add --no-cache john",
        "redhat": "dnf install -y john",
        "generic": "apt-get install -y john",
    },
    category=CapabilityCategory.EXPLOIT,
    risk=RiskLevel.MEDIUM,
    timeout_default=3600,
    description="Password hash cracker",
    min_disk_mb=50,
)

MASSRECON = ToolCapability(
    name="massdns",
    binary="massdns",
    capabilities=["dns_enum", "dns_brute"],
    install_cmds={
        "debian": "apt-get install -y massdns 2>/dev/null || (git clone https://github.com/blechschmidt/massdns /tmp/massdns && cd /tmp/massdns && make && cp bin/massdns /usr/local/bin/)",
        "generic": "git clone https://github.com/blechschmidt/massdns /tmp/massdns && cd /tmp/massdns && make && cp bin/massdns /usr/local/bin/",
    },
    category=CapabilityCategory.RECON,
    timeout_default=300,
    description="High-performance DNS stub resolver",
    min_disk_mb=30,
)

ASN_RECON = ToolCapability(
    name="assetfinder",
    binary="assetfinder",
    capabilities=["discover_subdomains", "osint_harvest"],
    install_cmds={
        "generic": "go install github.com/tomnomnom/assetfinder@latest && mv ~/go/bin/assetfinder /usr/local/bin/",
    },
    category=CapabilityCategory.RECON,
    timeout_default=120,
    description="Find domains and subdomains related to a target",
    min_disk_mb=20,
)

GF_PATTERNS = ToolCapability(
    name="gf",
    binary="gf",
    capabilities=["pattern_match", "url_filter"],
    install_cmds={
        "generic": "go install github.com/tomnomnom/gf@latest && mv ~/go/bin/gf /usr/local/bin/",
    },
    category=CapabilityCategory.UTILITY,
    timeout_default=30,
    description="grep wrapper for finding interesting strings",
    min_disk_mb=20,
    can_auto_install=True,
)

# ── System Utilities (Guardian Prerequisites) ─────────────────────────────

SYSTEM_GCC = ToolCapability(
    name="gcc",
    binary="gcc",
    capabilities=["compile_c", "build_tools"],
    install_cmds={
        "debian": "apt-get update && apt-get install -y build-essential",
        "alpine": "apk add --no-cache build-base",
        "generic": "apt-get install -y gcc",
    },
    category=CapabilityCategory.UTILITY,
    description="GNU Project C and C++ compiler",
)

SYSTEM_PIP3 = ToolCapability(
    name="pip3",
    binary="pip3",
    capabilities=["install_python_pkg"],
    install_cmds={
        "debian": "apt-get update && apt-get install -y python3-pip",
        "alpine": "apk add --no-cache py3-pip",
        "generic": "apt-get install -y python3-pip",
    },
    category=CapabilityCategory.UTILITY,
    description="Python package installer",
)

SYSTEM_GIT = ToolCapability(
    name="git",
    binary="git",
    capabilities=["clone_repo", "vcs"],
    install_cmds={
        "debian": "apt-get update && apt-get install -y git",
        "alpine": "apk add --no-cache git",
        "generic": "apt-get install -y git",
    },
    category=CapabilityCategory.UTILITY,
    description="Distributed version control system",
)


# ── Registry of ALL known tools (source of truth for Guardian allowlist) ──
_RAW_ALL_TOOLS: list[ToolCapability] = [
    # Original 17
    DISCOVER_SUBDOMAINS,
    DISCOVER_SUBDOMAINS_ALT,
    DNS_LOOKUP,
    PORT_SCAN,
    FAST_PORT_SCAN,
    WEB_VULN_SCAN,
    WEB_SERVER_SCAN,
    DIRECTORY_FUZZ,
    WEB_FUZZ,
    HTTP_PROBE,
    SQL_INJECTION_TEST,
    CREDENTIAL_BRUTE,
    SSL_AUDIT,
    TECH_FINGERPRINT,
    WAF_DETECT,
    TOR_PROXY,
    OSINT_HARVEST,
    # Path C additions
    WEB_FUZZ_ALT,
    FAST_DIR_FUZZ,
    HTTP_PROBE_FAST,
    PORT_SCAN_FAST,
    DNS_BRUTE,
    TLS_SCAN,
    PARAM_DISCOVER,
    XSS_SCAN,
    CMS_SCAN_WP,
    DIR_SCAN,
    WEB_CRAWL,
    WEB_CRAWL_ALT,
    DNS_RECON,
    URL_HISTORY,
    URL_HISTORY_ALT,
    SMB_ENUM,
    LDAP_ENUM,
    OPENSSL_TOOL,
    NETCAT_TOOL,
    WHOIS_TOOL,
    SQLI_ALT,
    CMD_INJECT,
    PASSWD_CRACK,
    MASSRECON,
    ASN_RECON,
    GF_PATTERNS,
    SYSTEM_GCC,
    SYSTEM_PIP3,
    SYSTEM_GIT,
]


def _build_all_tools_view() -> "list[ToolCapability]":
    """P2-4: ALL_TOOLS is a GENERATED view over the private authored seed
    (_RAW_ALL_TOOLS) plus catalog tools not already covered (deduped by binary).
    Authored capabilities are preserved verbatim; catalog-only tools appear as
    minimal capability entries so the installer/registry see one source of truth.
    Safe: a catalog failure degrades to the raw seed."""
    view = list(_RAW_ALL_TOOLS)
    have = {((t.binary or t.name) or "").lower() for t in view}
    try:
        from tools.tool_catalog import get_catalog
        cat = get_catalog()
        for e in cat.all():
            b = (getattr(e, "binary", "") or getattr(e, "name", "") or "").lower()
            if not b or b in have:
                continue
            cap = getattr(e, "primary_capability", "") or "utility"
            view.append(ToolCapability(
                name=getattr(e, "name", b) or b,
                binary=getattr(e, "binary", b) or b,
                capabilities=[cap],
                install_cmds={"generic": cat.install_command(b) or ""},
                description=getattr(e, "description", "") or ""))
            have.add(b)
    except Exception:
        pass
    return view


# Public generated view (P2-4).
ALL_TOOLS: list[ToolCapability] = _build_all_tools_view()

# Build capability -> tools lookup
_CAPABILITY_MAP: dict[str, list[ToolCapability]] = {}
for _tool in ALL_TOOLS:
    for _cap in _tool.capabilities:
        _CAPABILITY_MAP.setdefault(_cap, []).append(_tool)


class CapabilityRegistry:
    """
    Universal tool resolver.
    Detects VPS OS, resolves capabilities to available tools, handles installation.
    """

    def __init__(self, remote_executor=None, ai_backend=None):
        self.ssh = remote_executor
        self.ai = ai_backend
        self._os_id: str | None = None
        # RLock (reentrant): _install_tool() holds this lock and then calls
        # _is_installed() to validate, which re-acquires it. A plain Lock is
        # non-reentrant, so every SUCCESSFUL install would deadlock the thread.
        self._install_lock = threading.RLock()
        self._installed_cache: set[str] = set()
        self._failed_cache: dict[str, float] = {}
        self._capability_map = copy.deepcopy(_CAPABILITY_MAP)

    def invalidate_cache(self, tool_name: str | None = None) -> None:
        """Invalidate the installation caches. If tool_name is provided, only that tool is removed."""
        with self._install_lock:
            if tool_name:
                self._installed_cache.discard(tool_name)
                self._failed_cache.pop(tool_name, None)
            else:
                self._installed_cache.clear()
                self._failed_cache.clear()

    def _detect_os(self) -> str:
        """Determine VPS OS family for choosing correct package manager."""
        if self._os_id:
            return self._os_id
        if not self.ssh:
            return "generic"

        # Try multiple detection methods in order of reliability
        checks = [
            ("cat /etc/os-release 2>/dev/null | grep -i '^ID=' | cut -d= -f2 | tr -d '\"'", "os-release"),
            ("cat /etc/alpine-release 2>/dev/null && echo alpine", "alpine-release"),
            ("command -v apt-get 2>/dev/null && echo debian", "apt-get"),
            ("command -v apk 2>/dev/null && echo alpine", "apk"),
            ("command -v dnf 2>/dev/null && echo redhat", "dnf"),
            ("command -v pacman 2>/dev/null && echo arch", "pacman"),
        ]

        for cmd, source in checks:
            ec, out, _ = self.ssh.execute(
                cmd, timeout=TOOL_INSTALL_CHECK_TIMEOUT)
            if ec == 0 and out.strip():
                raw = out.strip().lower()
                if raw in ("debian", "ubuntu", "linuxmint",
                           "pop", "elementary"):
                    self._os_id = "debian"
                elif raw in ("alpine"):
                    self._os_id = "alpine"
                elif raw in ("fedora", "rhel", "centos", "rocky", "almalinux"):
                    self._os_id = "redhat"
                elif raw in ("arch", "manjaro", "endeavouros"):
                    self._os_id = "arch"
                else:
                    continue
                log.info(f"V6 OS detected: {self._os_id} (via {source})")
                return self._os_id

        log.warning(
            "Could not detect VPS OS. Falling back to generic (direct downloads).")
        self._os_id = "generic"
        return self._os_id

    def _is_installed(self, tool: ToolCapability) -> bool:
        """Check if tool binary exists on the VPS."""
        with self._install_lock:
            if tool.name in self._installed_cache:
                return True
            if tool.name in self._failed_cache:
                if time.time() - self._failed_cache[tool.name] < 60:
                    return False
                del self._failed_cache[tool.name]

            if not self.ssh:
                import shutil
                import os
                if os.name == "nt":
                    return False
                found = shutil.which(
                    tool.binary) or shutil.which(
                    tool.binary.lower())
                if found:
                    self._installed_cache.add(tool.name)
                return bool(found)

            theharvester_dir = "/opt/theHarvester"
            try:
                theharvester_dir = get_config(
                    "paths", "wsl_settings.theharvester_dir", get_config(
                        "paths", "vps_settings.theharvester_dir", "/opt/theHarvester"))
            except Exception as _e:
                import logging
                logging.getLogger(__name__).warning(
                    f"Swallowed exception: {_e}")
            vps_tool_path = "$HOME/.local/bin:/root/.local/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games"
            try:
                vps_tool_path = get_config(
                    "paths", "vps_settings.tool_path", vps_tool_path)
            except Exception as _e:
                import logging
                logging.getLogger(__name__).warning(
                    f"Swallowed exception: {_e}")

            path_setup = f"export PATH={vps_tool_path}:{theharvester_dir}:$PATH && "
            check_cmd = f"{path_setup}which {
                tool.binary} 2>/dev/null || which {
                tool.binary.lower()} 2>/dev/null"
            if tool.name == "theharvester":
                check_cmd += f" || ls {theharvester_dir}/theHarvester.py 2>/dev/null"

            ec, out, _ = self.ssh.execute(
                check_cmd, timeout=TOOL_VERIFY_TIMEOUT)
            if ec == 0 and out.strip():
                self._installed_cache.add(tool.name)
                return True
            return False

    def resolve(
        self,
        capability: str,
        risk_cap: RiskLevel | None = None,
        destructive_allowed: bool = False,
    ) -> ToolCapability | None:
        """
        Find the best available tool for a capability.
        Respects risk levels and installation status.
        """
        capability = capability.lower()
        candidates = self._capability_map.get(capability, [])
        if not candidates:
            log.warning(f"No tool registered for capability: {capability}")
            return None

        # Filter by risk
        if risk_cap:
            candidates = [
                c for c in candidates if self._risk_gte(
                    c.risk, risk_cap)]

        # Filter by destructive permission
        if not destructive_allowed:
            candidates = [
                c for c in candidates if c.risk != RiskLevel.DESTRUCTIVE]

        # Pick the first one that is installed (or can be installed)
        for tool in candidates:
            if self._is_installed(tool):
                return tool

        # None installed - try to install the first candidate
        for tool in candidates:
            if self._install_tool(tool):
                return tool

        log.error(
            f"No tool available for capability '{capability}' after install attempts.")
        return None

    def _install_tool(self, tool: ToolCapability) -> bool:
        """Attempt universal installation based on detected OS."""
        if not self.ssh:
            log.warning(
                f"Local mode: cannot auto-install '{tool.name}'. Install manually or use VPS mode.")
            return False

        with self._install_lock:
            if tool.name in self._installed_cache:
                return True
            if tool.name in self._failed_cache:
                if time.time() - self._failed_cache[tool.name] < 60:
                    return False

            os_family = self._detect_os()

            arch = "amd64"
            if self.ssh:
                ec, out, _ = self.ssh.execute("uname -m", timeout=15)
                if ec == 0 and ("aarch64" in out.lower()
                                or "arm64" in out.lower()):
                    arch = "arm64"
            else:
                import platform
                if platform.machine().lower() in ["arm64", "aarch64"]:
                    arch = "arm64"

            install_script = tool.install_cmds.get(
                os_family) or tool.install_cmds.get("generic")
            if install_script and arch == "arm64":
                install_script = install_script.replace("amd64", "arm64")
            if not install_script or not install_script.strip():
                log.error(
                    f"No install script for '{
                        tool.name}' on OS '{os_family}' or generic")
                self._failed_cache[tool.name] = time.time()
                return False

            log.info(f"V6 Installing '{tool.name}' on {os_family}...")
            env_prefix = "export DEBIAN_FRONTEND=noninteractive && " if os_family == "debian" else ""
            ec, out, err = self.ssh.execute(
                f"{env_prefix}{install_script}",
                timeout=tool.install_timeout,
            )

            if ec == 0:
                # Validate
                if self._is_installed(tool):
                    self._installed_cache.add(tool.name)
                    log.info(
                        f"'{tool.name}' installed and validated successfully.")
                    return True
                else:
                    log.warning(
                        f"'{tool.name}' install seemed OK but binary not found.")
            else:
                log.error(
                    f"Install failed for '{tool.name}': {(err or '')[:200]}")

            self._failed_cache[tool.name] = time.time()
            return False

    @staticmethod
    def _risk_gte(tool_risk: RiskLevel, required: RiskLevel) -> bool:
        """Check if tool risk is at or below required level (tool is safe enough for the given cap)."""
        order = {
            RiskLevel.NONE: 0, RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3,
            RiskLevel.DESTRUCTIVE: 4,
        }
        return order.get(tool_risk, 99) <= order.get(required, 99)

    def list_capabilities(self) -> list[str]:
        return sorted(self._capability_map.keys())

    def list_all_tool_binaries(self) -> frozenset[str]:
        """Return every binary name across both static and custom-discovered tools."""
        binaries: set[str] = set()
        for tool in ALL_TOOLS:
            binaries.add(tool.binary.lower())
            binaries.add(tool.name.lower())
        for cap_list in self._capability_map.values():
            for tool in cap_list:
                if tool not in ALL_TOOLS:
                    binaries.add(tool.binary.lower())
                    binaries.add(tool.name.lower())
        return frozenset(binaries)

    def get_installable_tools(self) -> list[ToolCapability]:
        """Return only tools flagged can_auto_install=True (Path C gate 1 source)."""
        seen = set()
        result = []
        for tool in ALL_TOOLS:
            if getattr(tool, 'can_auto_install', True):
                result.append(tool)
                seen.add(id(tool))
        for cap_list in self._capability_map.values():
            for tool in cap_list:
                if id(tool) not in seen and getattr(
                        tool, 'can_auto_install', True):
                    result.append(tool)
                    seen.add(id(tool))
        return result

    def get_tool_by_name(self, name: str) -> ToolCapability | None:
        """Lookup a ToolCapability by binary or name, including custom-discovered tools."""
        name_lower = name.lower()
        for tool in ALL_TOOLS:
            if tool.name.lower() == name_lower or tool.binary.lower() == name_lower:
                return tool
        for cap_list in self._capability_map.values():
            for tool in cap_list:
                if tool not in ALL_TOOLS and (
                        tool.name.lower() == name_lower or tool.binary.lower() == name_lower):
                    return tool
        return None

    def discover_custom_tool(self, capability: str) -> ToolCapability | None:
        """AI-driven tool discovery when no registered tool matches."""
        capability = capability.lower()
        if not self.ai:
            return None
        log.info(
            f"AI Discovery: researching tool for capability '{capability}'")
        prompt = (
            f"I need a Linux CLI tool that can perform: {capability}\n"
            f"Return STRICT JSON with keys: name, binary, install_debian, install_generic, category, timeout_sec.\n"
            f"If no dedicated tool exists, suggest how to achieve it with standard Linux utilities (curl, python3, etc)."
        )
        try:
            resp = self.ai.query(
                "You are a Linux sysadmin. Be concise.", prompt)
            data = FragileParseFixer.safe_split_json_extraction(
                resp, default={})
            if not isinstance(data, dict):
                raise ValueError(f"Expected dict, got {type(data).__name__}")
            name = data.get("name", capability)
            binary = data.get("binary", data.get("name", capability))
            if not isinstance(name, str) or not isinstance(binary, str):
                raise ValueError("name and binary must be strings")
            timeout_val = int(data.get("timeout_sec") or 120)
            category_val = data.get("category", "utility")
            try:
                category_enum = CapabilityCategory(category_val)
            except ValueError:
                category_enum = CapabilityCategory.UTILITY
            cap = ToolCapability(
                name=name,
                binary=binary,
                capabilities=[capability],
                install_cmds={
                    "debian": data.get("install_debian", ""),
                    "generic": data.get("install_generic", data.get("install_debian", "")),
                },
                timeout_default=timeout_val,
                category=category_enum,
            )
            self._capability_map.setdefault(capability, []).append(cap)
            return cap
        except Exception as e:
            log.error(f"AI tool discovery failed: {e}")
            return None


_registry_instance: Optional[CapabilityRegistry] = None
_registry_lock = threading.Lock()

# P0-9: lightweight name -> capability keyword lookup, built once from the
# static ALL_TOOLS table. No registry instantiation (no OS detection / install
# probing), so it is cheap to call on every tool run for produced_result()'s
# capability keying. Keyed on both name and binary.
_PRIMARY_CAP_INDEX: dict[str, str] = {}
for _t in ALL_TOOLS:
    _cap = (_t.capabilities[0] if getattr(_t, "capabilities", None)
            else getattr(getattr(_t, "category", None), "value", ""))
    for _k in {str(getattr(_t, "name", "")).lower(), str(getattr(_t, "binary", "")).lower()}:
        if _k:
            _PRIMARY_CAP_INDEX.setdefault(_k, str(_cap or ""))


def tool_primary_capability(name: str) -> str:
    """Return a tool's primary capability keyword (e.g. 'port_scan',
    'http_probe', 'discover_subdomains') from the static capability table, or ''
    if unknown. Used to key ToolResult.produced_result() without a per-tool
    banner table (P0-9)."""
    if not name:
        return ""
    return _PRIMARY_CAP_INDEX.get(str(name).strip().lower(), "")


def get_registry(remote_executor=None, ai=None,
                 force: bool = False) -> CapabilityRegistry:
    """Get or create the global CapabilityRegistry instance."""
    global _registry_instance
    with _registry_lock:
        if _registry_instance is None:
            _registry_instance = CapabilityRegistry(remote_executor, ai)
        else:
            if force or (remote_executor and not _registry_instance.ssh):
                _registry_instance.ssh = remote_executor
            if force or (ai and not _registry_instance.ai):
                _registry_instance.ai = ai
        return _registry_instance
