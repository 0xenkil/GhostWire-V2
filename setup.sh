#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# GHOSTWIRE V7 — Full WSL Audit & Setup Script
# Checks all tools, installs missing ones, updates system
# Run this INSIDE your WSL terminal (not PowerShell)
# ═══════════════════════════════════════════════════════════════
set -o pipefail
set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
INSTALLED=0

check_tool() {
    local name=$1
    local binary=$2
    if command -v "$binary" &>/dev/null || [ -f "/usr/local/bin/$binary" ] || [ -f "/usr/bin/$binary" ]; then
        echo -e "  ${GREEN}✓${NC} $name ($binary)"
        PASS=$((PASS + 1))
        return 0
    else
        echo -e "  ${RED}✗${NC} $name ($binary) — MISSING"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

echo -e "\n${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  GHOSTWIRE V7 — WSL Audit & Provisioning${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════${NC}\n"

# ── Phase 0: System Info ──────────────────────────────────────
echo -e "${YELLOW}[0/7] System Info${NC}"
echo "  OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
echo "  Kernel: $(uname -r)"
echo "  CPU: $(nproc) cores"
echo "  RAM: $(free -h | awk '/^Mem:/{print $2}') total, $(free -h | awk '/^Mem:/{print $7}') available"
echo "  Disk: $(df -h / | awk 'NR==2{print $4}') free on /"
echo "  Disk /tmp: $(df -h /tmp | awk 'NR==2{print $4}') free"
echo ""

# ── Phase 1: System Update ───────────────────────────────────
echo -e "${YELLOW}[1/7] Updating System Packages...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq 2>/dev/null
apt-get upgrade -y -qq 2>/dev/null
echo -e "  ${GREEN}✓${NC} System updated"
echo ""

# ── Phase 2: Install Core System Tools ────────────────────────
echo -e "${YELLOW}[2/7] Installing Core System Tools...${NC}"
CORE_PACKAGES=(
    # Build essentials
    build-essential git unzip wget curl ca-certificates
    # Python
    python3 python3-pip python3-venv python3-dev
    # Network tools
    dnsutils whois netcat-openbsd traceroute net-tools iputils-ping
    # Security tools
    nmap masscan nikto gobuster dirb sqlmap hydra
    smbclient john hashcat
    # Playwright system deps (V2 Phase E)
    libnss3 libatk-bridge2.0-0 libdrm2 libxkbcommon0 libgbm1
    libxshmfence1 libx11-xcb1 libxcomposite1
    libxdamage1 libxrandr2 libpango-1.0-0 libcairo2 libcups2
    libatk1.0-0 libnspr4 libgdk-pixbuf-2.0-0 libgtk-3-0
    libxss1 fonts-liberation xdg-utils
)

# Robust Individual Package Installer Loop
for pkg in "${CORE_PACKAGES[@]}"; do
    echo -e "  → Installing $pkg..."
    apt-get install -y -qq "$pkg" 2>/dev/null || echo -e "  ${YELLOW}⚠${NC} Could not install $pkg via standard repo - skipping"
done

# Resilient Virtual Package Fallback Check
echo -e "  → Installing libasound2 dependency..."
apt-get install -y -qq libasound2 2>/dev/null || apt-get install -y -qq libasound2t64 2>/dev/null || echo -e "  ${YELLOW}⚠${NC} libasound2 package skipped"

echo -e "  ${GREEN}✓${NC} Core packages installed"
echo ""

# ── Phase 3: Install Specialized Tools ────────────────────────
echo -e "${YELLOW}[3/7] Installing Specialized Security Tools...${NC}"

# --- wafw00f ---
if ! command -v wafw00f &>/dev/null; then
    echo -e "  ${YELLOW}→${NC} Installing wafw00f..."
    pip3 install wafw00f --break-system-packages --quiet 2>/dev/null
    INSTALLED=$((INSTALLED + 1))
fi

# --- theHarvester ---
if ! command -v theHarvester &>/dev/null && ! command -v theharvester &>/dev/null; then
    echo -e "  ${YELLOW}→${NC} Installing theHarvester..."
    pip3 install theHarvester --break-system-packages --quiet 2>/dev/null
    TH_PATH=$(which theHarvester 2>/dev/null || which theharvester 2>/dev/null)
    if [ ! -z "$TH_PATH" ]; then
        ln -sf "$TH_PATH" /usr/local/bin/theharvester 2>/dev/null
    fi
    INSTALLED=$((INSTALLED + 1))
fi

# --- ffuf (from GitHub if apt failed) ---
if ! command -v ffuf &>/dev/null; then
    echo -e "  ${YELLOW}→${NC} Installing ffuf from GitHub..."
    FFUF_VER=$(curl -sL --max-time 120 https://api.github.com/repos/ffuf/ffuf/releases/latest | grep -oP '(?<="tag_name": "v)[^"]+') 2>/dev/null
    if [ ! -z "$FFUF_VER" ]; then
        curl -sL --max-time 120 "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_amd64.tar.gz" -o /tmp/ffuf.tar.gz
        tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf 2>/dev/null
        chmod +x /usr/local/bin/ffuf
        rm -f /tmp/ffuf.tar.gz
        INSTALLED=$((INSTALLED + 1))
    fi
fi

# --- nuclei ---
if ! command -v nuclei &>/dev/null; then
    echo -e "  ${YELLOW}→${NC} Installing nuclei from GitHub..."
    NUCLEI_VER=$(curl -sL --max-time 120 https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep 'tag_name' | cut -d '"' -f 4 | tr -d 'v')
    if [ ! -z "$NUCLEI_VER" ]; then
        curl -sL --max-time 120 "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" -o /tmp/nuclei.zip
        (cd /tmp && unzip -o nuclei.zip nuclei && chmod +x nuclei && mv nuclei /usr/local/bin/nuclei) 2>/dev/null
        rm -f /tmp/nuclei.zip
        INSTALLED=$((INSTALLED + 1))
    fi
fi

# --- Update nuclei templates ---
echo -e "  ${YELLOW}→${NC} Updating nuclei templates..."
timeout 120 nuclei -ut -silent 2>/dev/null || true

# --- curl-impersonate (JA3 bypass) ---
if ! command -v curl-impersonate-chrome &>/dev/null; then
    echo -e "  ${YELLOW}→${NC} Installing curl-impersonate..."
    curl -sL --max-time 120 "https://github.com/lwthiker/curl-impersonate/releases/download/v0.6.1/curl-impersonate-v0.6.1.x86_64-linux-gnu.tar.gz" -o /tmp/curl-imp.tar.gz 2>/dev/null
    tar -xzf /tmp/curl-imp.tar.gz -C /usr/local/bin/ 2>/dev/null
    chmod +x /usr/local/bin/curl-impersonate-chrome 2>/dev/null
    rm -f /tmp/curl-imp.tar.gz
    INSTALLED=$((INSTALLED + 1))
fi

# --- Playwright (V2 Phase E: Headless Browser) ---
echo -e "  ${YELLOW}→${NC} Setting up Playwright + Chromium..."
pip3 install playwright --break-system-packages --quiet 2>/dev/null

# Attempt native Playwright installation
if ! timeout 600 playwright install chromium 2>/dev/null; then
    echo -e "  ${YELLOW}⚠${NC} Playwright native install failed (likely unsupported OS like Ubuntu 26.04). Using fallback..."
    # Attempt apt install
    apt-get install -y -qq chromium-browser 2>/dev/null || apt-get install -y -qq chromium 2>/dev/null
    
    # If apt failed, attempt direct Google Chrome deb installation
    if ! command -v chromium-browser &>/dev/null && ! command -v chromium &>/dev/null; then
        echo -e "  ${YELLOW}→${NC} Downloading and installing Google Chrome stable..."
        wget -q --timeout=120 https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O /tmp/google-chrome.deb
        apt-get install -y -qq /tmp/google-chrome.deb 2>/dev/null || true
        rm -f /tmp/google-chrome.deb
    fi
    
    # Tell Playwright to look for system browsers
    echo "export PLAYWRIGHT_BROWSERS_PATH=0" >> ~/.bashrc
    export PLAYWRIGHT_BROWSERS_PATH=0
fi
INSTALLED=$((INSTALLED + 1))

echo ""

# ── Phase 4: Python Dependencies ─────────────────────────────
echo -e "${YELLOW}[4/7] Installing/Updating Python Dependencies...${NC}"
pip3 install --upgrade pip --break-system-packages --quiet 2>/dev/null
pip3 install rich requests python-dotenv ollama groq openai pyyaml jinja2 dnspython paramiko --break-system-packages --quiet 2>/dev/null
echo -e "  ${GREEN}✓${NC} Python dependencies installed"
echo ""

# ── Phase 5: Create Required Directories ──────────────────────
echo -e "${YELLOW}[5/7] Setting Up WSL Directories...${NC}"
mkdir -p /tmp/antigravity/buffers
mkdir -p /tmp/antigravity/results
mkdir -p /root/results
echo -e "  ${GREEN}✓${NC} Directories created"
echo ""

# ── Phase 6: Download Wordlists ───────────────────────────────
echo -e "${YELLOW}[6/7] Ensuring Wordlists Are Available...${NC}"
if [ ! -f "/usr/share/wordlists/dirb/common.txt" ]; then
    apt-get install -y -qq wordlists 2>/dev/null || true
fi
# Fallback: download SecLists common.txt
if [ ! -f "/tmp/wordlist_common.txt" ]; then
    echo -e "  ${YELLOW}→${NC} Downloading SecLists common.txt..."
    curl -sL --max-time 120 "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -o /tmp/wordlist_common.txt 2>/dev/null
fi
echo -e "  ${GREEN}✓${NC} Wordlists ready"
echo ""

# ── Phase 7: Full Tool Audit ─────────────────────────────────
echo -e "${YELLOW}[7/7] Running Full Tool Audit...${NC}"
echo ""

echo -e "  ${CYAN}── Recon Tools ──${NC}"
check_tool "Nmap" "nmap"
check_tool "Masscan" "masscan"
check_tool "WHOIS" "whois"
check_tool "Dig (DNS)" "dig"
check_tool "theHarvester" "theHarvester" || check_tool "theHarvester (alt)" "theharvester"
check_tool "Gobuster" "gobuster"
check_tool "wafw00f" "wafw00f"
check_tool "enum4linux" "enum4linux"
check_tool "SMBClient" "smbclient"

echo ""
echo -e "  ${CYAN}── Web Tools ──${NC}"
check_tool "Curl" "curl"
check_tool "Wget" "wget"
check_tool "Nikto" "nikto"
check_tool "Nuclei" "nuclei"
check_tool "FFuf" "ffuf"
check_tool "Dirb" "dirb"
check_tool "curl-impersonate" "curl-impersonate-chrome"
check_tool "Playwright" "playwright"

echo ""
echo -e "  ${CYAN}── Exploitation Tools ──${NC}"
check_tool "SQLMap" "sqlmap"
check_tool "Hydra" "hydra"
check_tool "Netcat" "nc"
check_tool "John" "john"

echo ""
echo -e "  ${CYAN}── Infrastructure ──${NC}"
check_tool "Python3" "python3"
check_tool "Pip3" "pip3"
check_tool "Git" "git"
check_tool "Unzip" "unzip"

# Playwright browser check
echo ""
echo -e "  ${CYAN}── Playwright Browsers ──${NC}"
if python3 -c "from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(headless=True, args=['--no-sandbox']); b.close(); p.stop(); print('OK')" 2>/dev/null | grep -q "OK"; then
    echo -e "  ${GREEN}✓${NC} Chromium (Playwright) — functional"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}✗${NC} Chromium (Playwright) — not working"
    FAIL=$((FAIL + 1))
fi

# Nuclei templates check
echo ""
echo -e "  ${CYAN}── Template Database ──${NC}"
NUCLEI_TMPL_COUNT=$(nuclei -tl 2>/dev/null | wc -l)
if [ "$NUCLEI_TMPL_COUNT" -gt 100 ]; then
    echo -e "  ${GREEN}✓${NC} Nuclei templates: $NUCLEI_TMPL_COUNT loaded"
else
    echo -e "  ${YELLOW}⚠${NC} Nuclei templates: only $NUCLEI_TMPL_COUNT (run: nuclei -ut)"
fi

# Wordlist check
echo ""
echo -e "  ${CYAN}── Wordlists ──${NC}"
for wl in "/usr/share/wordlists/dirb/common.txt" "/tmp/wordlist_common.txt" "/usr/share/seclists/Discovery/Web-Content/common.txt"; do
    if [ -f "$wl" ]; then
        WC=$(wc -l < "$wl" 2>/dev/null)
        echo -e "  ${GREEN}✓${NC} $wl ($WC words)"
    fi
done

# ── Summary ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}PASS: $PASS${NC}  ${RED}FAIL: $FAIL${NC}  ${YELLOW}INSTALLED: $INSTALLED${NC}"
if [ $FAIL -eq 0 ]; then
    echo -e "  ${GREEN}★ WSL IS FULLY OPERATIONAL ★${NC}"
else
    echo -e "  ${YELLOW}⚠ $FAIL tool(s) may need manual installation${NC}"
fi
echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
echo ""
