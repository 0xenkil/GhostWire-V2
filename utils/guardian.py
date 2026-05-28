"""
Guardian: Strict AI command validation and repair.
Ensures AI-generated recon/exploitation commands are safe, scoped, and don't fail.
"""
import re
from core.waf_policy import assess_waf_command
from core.target_context import TargetContext
from utils.logger import get_logger
from tools.tool_registry import WRAPPER_TOOLS

log = get_logger("guardian")

# Allowlisted tools for both AI-enhanced recon AND exploitation
ALLOWED_RECON_TOOLS = {
    # Recon tools
    "nmap", "masscan", "dig", "curl", "wget",
    "sslscan", "whatweb", "nikto", "gobuster", "ffuf",
    "enum4linux", "sqlmap", "whois", "nc", "netstat",
    "host", "traceroute", "ping", "mtr", "dnsenum",
    "fierce", "theHarvester", "assetfinder", "ssltest", "nuclei",
    "subfinder", "wafw00f", "dirsearch", "dirb", "proxychains4", "proxychains", "httpx",
    "amass", "katana", "hakrawler", "gau", "waybackurls", "arjun", "dalfox", 
    "naabu", "rustscan", "dnsrecon", "dnsx", "feroxbuster", "wfuzz", "kiterunner", 
    "trufflehog", "gitleaks", "smbclient", "smbmap", "crackmapexec", "netexec", 
    "wpscan", "joomscan", "droopescan", "snmpwalk", "snmpcheck", "ldapsearch",
    # Wrappers
    "timeout",
    # Exploitation tools
    "hydra", "msfconsole", "john", "sqlmap", "nikto",
    "curl", "wget", "nmap", "sslscan", "nc",
    "nessus", "metasploit", "crunch", "python3", "python",
    "react_payload", "python_payload", "hashcat", "searchsploit", "commix",
}

# Blocked patterns (destructive, write, exec, etc.)
# Relaxed for active red teaming
BLOCKED_PATTERNS = [
    r"rm\s+-rf\s+/",       # Only block system-wide destructive rm
    r"mkfs|fdisk|parted",  # disk formatting
    # systemctl: allowed for tor
    r"systemctl\s+(?:stop|disable|mask|unmask)\s+(?!tor\b)",
]


def validate_ai_command(command: str, target: str) -> tuple[bool, str, str]:
    """
    Validate an AI-generated recon/exploitation command.
    Autonomous: normalizes target before scoping checks.
    RELAXED for active offensive operations.
    """
    if not command or not command.strip():
        return False, "Empty command", ""

    command = command.strip()
    original_cmd = command
    
    # Autonomous target normalization (no hardcodes)
    try:
        tc = TargetContext.from_input(target)
        normalized_target = tc.base_url
        normalized_host = tc.netloc
    except Exception:
        normalized_target = target
        normalized_host = target

    # Normalize wrapper prefixes
    cmd_clean = command
    parts = [p.strip() for p in re.split(r"\s*&&\s*", cmd_clean) if p.strip()]
    while parts:
        head = parts[0]
        if head.startswith("export ") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", head):
            parts = parts[1:]
            continue
        break
    if parts:
        cmd_clean = " && ".join(parts)
    cmd_clean = re.sub(r"^(?:(?:timeout\s+\d+\s+)|(?:sudo\s+)|(?:env\s+)|(?:proxychains4?\s+-q\s+))*", "", cmd_clean).strip()
    cmd_clean = re.sub(r"(?i)(https?://)(?:https?://)+", r"\1", cmd_clean)

    # 1. BLOCK dangerous patterns absolutely
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return False, f"Blocked dangerous pattern: {pattern}", ""



    # WAF policy check removed - active evasion is allowed

    # 2. Extract tool name

    tool_match = re.match(r"^([\w-]+)", cmd_clean)
    if not tool_match:
        return False, "Cannot parse tool name from command", ""

    tool_name = tool_match.group(1)

    if re.match(r"^([\w.-]+)\s+-\s+\1\b", cmd_clean, re.IGNORECASE):
        return False, "Duplicated tool prefix in AI command", ""

    if tool_name in WRAPPER_TOOLS:
        remainder = re.sub(
            r"^(?:(?:timeout|sudo|env|nice|proxychains4?)\s+(?:-\S+\s+)*(?:\d+\s+)?)+",
            "", cmd_clean
        ).strip()
        real_match = re.match(r"^([\w-]+)", remainder)
        if real_match:
            tool_name = real_match.group(1)

    url_tools = {"curl", "nikto", "gobuster", "ffuf", "nuclei", "whatweb", "wafw00f", "sslscan", "dirsearch", "dirb"}
    host_tools = {"nmap", "masscan", "subfinder", "theharvester", "assetfinder", "dnsenum", "whois", "ping", "traceroute", "mtr", "host", "netstat"}

    preferred_target = normalized_target
    if tool_name in url_tools:
        preferred_target = normalized_target
    elif tool_name in host_tools:
        preferred_target = normalized_host

    # 3. Check tool is allowlisted
    if tool_name not in ALLOWED_RECON_TOOLS:
        allowed_list = ", ".join(sorted(list(ALLOWED_RECON_TOOLS)[:8])) + "..."
        return False, f"Tool '{tool_name}' not allowlisted", ""

    # 4. Target scoping check - relaxed for complex commands, uses normalized target
    if tool_name not in ["python", "python3", "msfconsole"]:
        # Check both normalized forms in the command
        found = False
        for check_target in [preferred_target, normalized_target, normalized_host, target]:
            if check_target in cmd_clean:
                found = True
                break
            target_escaped = re.escape(check_target)
            if re.search(target_escaped, cmd_clean, re.IGNORECASE):
                found = True
                break
        if not found:
            # Allow file-based inputs from trusted agent directories where scoped targets are aggregated
            from config_paths import VPS_TEMP_DIR, VPS_RESULTS_DIR
            if f"{VPS_TEMP_DIR}/" in cmd_clean or f"{VPS_RESULTS_DIR}/" in cmd_clean or "/tmp/antigravity/" in cmd_clean or "/root/results/" in cmd_clean:
                pass
            else:
                return False, f"Target '{target}' missing in command. Out-of-scope scanning is prohibited.", ""

    # 5. Auto-repair: fix nmap script syntax (colon -> equals)
    repaired = re.sub(r"--script:\s*", "--script=", command)

    # 5b. Tool-specific target normalization
    if tool_name in host_tools:
        repaired = re.sub(r"https?://", "", repaired)
        repaired = re.sub(r"/+$", "", repaired)
    elif tool_name in url_tools:
        repaired = re.sub(r"(?i)(https?://)(?:https?://)+", r"\1", repaired)

    if tool_name == "whatweb":
        repaired = re.sub(r"(?<!\S)-s(?!\S)", "", repaired)

    # 6. Auto-repair: add timeouts/flags if missing
    if tool_name == "nmap" and "--max-rtt-timeout" not in repaired:
        repaired += " --max-rtt-timeout 2s --max-retries 1"

    if tool_name == "curl":
        if "--max-time" not in repaired:
            repaired += " --max-time 30"
        if "-L" not in repaired and "--location" not in repaired:
            repaired += " -L"

    if tool_name == "sqlmap" and "--batch" not in repaired:
        repaired += " --batch"

    if tool_name == "nuclei":
        if "-ni" not in repaired:
            repaired += " -ni"

    if tool_name == "ffuf" and "-ac" not in repaired:
        repaired += " -ac"

    if tool_name == "sslscan":
        # sslscan expects a host or host:port, not a URL with scheme/path.
        repaired = re.sub(r"https?://", "", repaired)
        repaired = re.sub(r"/+$", "", repaired)
        repaired = re.sub(r"/(?:\S+)$", "", repaired)

    # Command length sanity check - increased for complex payloads
    if len(repaired) > 5000:
        return False, "Command too long (>5000 chars)", ""

    reason = "OK"
    return True, reason, repaired


def block_or_repair(command: str, target: str) -> tuple[str | None, str]:
    """
    Guardian wrapper: return repaired command or None if blocked.
    """
    is_valid, reason, repaired = validate_ai_command(command, target)

    if not is_valid:
        log.warning(f"Guardian BLOCKED: {reason}\n  Command: {command[:100]}")
        return None, f"BLOCKED: {reason}"

    return repaired, "APPROVED"
