"""
Guardian: Strict AI command validation and repair.
Ensures AI-generated recon/exploitation commands are safe, scoped, and don't fail.
"""
import re
from core.target_context import TargetContext
from utils.logger import get_logger
from tools.tool_registry import WRAPPER_TOOLS
from core.provisioning_policy import is_run_blocked
from core.capability_registry import tool_primary_capability

log = get_logger("guardian")

# P2-2 (GUARDIAN-ALLOWLIST-1): the ALLOWED_RECON_TOOLS allowlist is GONE. It was
# the autonomy limiter — it blocked every modern recon tool nobody had
# pre-registered (the "Tool X not allowlisted" reject). Safety is now a
# deny+scope gate: the destructive-verb RUN_DENY list (core.provisioning_policy)
# + the pattern rails + the target-scope check + the length cap below. Any
# non-destructive, in-scope tool the AI picks is allowed.

# Launcher/wrapper prefixes and value-assignments that legitimately begin a
# command line — used only to anchor prose/markdown command extraction, never as
# an allow/deny authority.
_LINE_LEADERS = {"export", "sudo", "timeout", "env", "nice",
                 "proxychains4", "proxychains"}


def _is_known_or_leader(first_word: str) -> bool:
    """Heuristic anchor for pulling a command line out of prose/markdown: a token
    that is a KNOWN tool binary (capability registry), a ``VAR=val`` assignment,
    or a recognized launcher prefix. Not an allow/deny gate — unknown tools are
    still executable, they just don't anchor prose extraction."""
    if not first_word:
        return False
    if "=" in first_word or first_word in _LINE_LEADERS:
        return True
    return bool(tool_primary_capability(first_word))

# Blocked patterns (destructive, write, exec, etc.)
# Relaxed for active red teaming
BLOCKED_PATTERNS = [
    r"rm\s+-rf\s+/",       # Only block system-wide destructive rm
    r"mkfs|fdisk|parted",  # disk formatting
    # systemctl: allowed for tor
    r"systemctl\s+(?:stop|disable|mask|unmask)\s+(?!tor\b)",
]

# Destructive patterns that require human approval
DESTRUCTIVE_PATTERNS = [
    r"drop\s+(?:database|table)",
    r"delete\s+from",
    # Catch all rm commands EXCEPT system-wide rm -rf / (which is absolutely
    # blocked above). Requires human approval.
    r"(?:^|&&|\|\||;)\s*rm\s+(?!-rf\s+/)",
    r"truncate\s+table",
    r"update\s+.*\s+set",
]


def validate_ai_command(command: str, target: str,
                        target_context: TargetContext | None = None) -> tuple[bool, str, str]:
    """
    Validate an AI-generated recon/exploitation command.
    Autonomous: normalizes target before scoping checks.
    RELAXED for active offensive operations.
    """
    if not command or not command.strip():
        return False, "Empty command", ""

    command = command.strip()

    # Extract command if wrapped in markdown code blocks or prose
    code_block_match = re.search(r"```(?:bash|sh)?\s*\n?(.*?)\n?```", command, re.DOTALL | re.IGNORECASE)
    if code_block_match:
        command = code_block_match.group(1).strip()
    else:
        # If output contains newline with prose before a command line
        lines = [line.strip() for line in command.splitlines() if line.strip()]
        for line in lines:
            # Pick first line that starts with a known tool, a VAR=val, or a
            # launcher prefix (P2-2: anchored on the capability registry, not the
            # deleted allowlist).
            first_word = line.split()[0] if line.split() else ""
            if _is_known_or_leader(first_word):
                command = line
                break

    original_cmd = command

    # Autonomous target normalization (no hardcodes)
    tc = None
    try:
        tc = target_context if target_context else TargetContext.from_input(
            target)
        normalized_target = tc.base_url
        normalized_host = tc.netloc
    except Exception as _e:
        import logging
        logging.getLogger(__name__).warning(f"Swallowed exception: {_e}")
        normalized_target = target
        normalized_host = target

    # Normalize wrapper prefixes
    cmd_clean = command
    parts = [p.strip() for p in re.split(r"\s*&&\s*", cmd_clean) if p.strip()]
    while parts:
        head = parts[0]
        if head.startswith("export ") or re.match(
                r"^[A-Za-z_][A-Za-z0-9_]*=.*$", head):
            parts = parts[1:]
            continue
        break
    if parts:
        cmd_clean = " && ".join(parts)
    cmd_clean = re.sub(
        r"^(?:(?:timeout\s+\d+\s+)|(?:sudo\s+)|(?:env\s+)|(?:proxychains4?\s+-q\s+))*",
        "",
        cmd_clean).strip()
    cmd_clean = re.sub(r"(?i)(https?://)(?:https?://)+", r"\1", cmd_clean)

    # 1. BLOCK dangerous patterns absolutely
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return False, f"Blocked dangerous pattern: {pattern}", ""

    # 1b. Flag destructive patterns for approval
    for pattern in DESTRUCTIVE_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return False, f"REQUIRES_APPROVAL: Destructive action detected: {pattern}", ""

    # Relaxed pipe checks: allow pipes so AI can chain grep/jq
    # if "|" in command:
    # return False, "Piped commands are not supported by the system parser.
    # Please run tools sequentially.", ""

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

    url_tools = {
        "curl",
        "nikto",
        "gobuster",
        "ffuf",
        "nuclei",
        "whatweb",
        "wafw00f",
        "sslscan",
        "dirsearch",
        "dirb"}
    host_tools = {
        "nmap",
        "masscan",
        "subfinder",
        "theharvester",
        "assetfinder",
        "dnsenum",
        "whois",
        "ping",
        "traceroute",
        "mtr",
        "host",
        "netstat"}

    preferred_target = normalized_target
    if tool_name in url_tools:
        preferred_target = normalized_target
    elif tool_name in host_tools:
        preferred_target = normalized_host

    # 3. Deny only genuinely destructive binaries (P2-2: deny+scope replaces the
    # allowlist). Any other tool the AI picks is allowed — the target-scope check
    # (step 4) and the pattern/length rails are what keep it safe.
    if is_run_blocked(tool_name):
        return False, f"Tool '{tool_name}' is on the destructive run-deny list", ""

    # 4. Target scoping check - relaxed for complex commands, uses normalized
    # target
    local_tools = {
        "cat",
        "grep",
        "jq",
        "awk",
        "cut",
        "tee",
        "sort",
        "uniq",
        "test",
        "id",
        "whoami",
        "ip",
        "ifconfig",
        "uname",
        "crontab",
        "ps",
        "top",
        "w",
        "last",
        "history",
        "pwd",
        "cd",
        "find",
        "chown",
        "chmod",
        "echo",
        "printf",
        "searchsploit",
        "timeout"}
    is_help_cmd = "--help" in cmd_clean or "-h" in cmd_clean.split()

    if tool_name not in ["python", "python3",
                         "msfconsole"] and tool_name not in local_tools and not is_help_cmd:
        # Check both normalized forms in the command
        found = False
        check_targets = [
            preferred_target,
            normalized_target,
            normalized_host,
            target]

        # Also check if target's resolved IPs are in the command
        import socket
        if tc:
            try:
                _, _, ips = socket.gethostbyname_ex(tc.host)
                check_targets.extend(ips)
            except Exception as _e:
                import logging
                logging.getLogger(__name__).warning(
                    f"Swallowed exception: {_e}")

            check_targets.append(tc.host)

        for check_target in check_targets:
            if check_target in cmd_clean:
                found = True
                break
            target_escaped = re.escape(check_target)
            if re.search(target_escaped, cmd_clean, re.IGNORECASE):
                found = True
                break
        if not found:
            # Allow file-based inputs from trusted agent directories where
            # scoped targets are aggregated
            from config_paths import WSL_TEMP_DIR, WSL_RESULTS_DIR, VPS_TEMP_DIR, VPS_RESULTS_DIR
            trusted_paths = [
                WSL_TEMP_DIR,
                WSL_RESULTS_DIR,
                VPS_TEMP_DIR,
                VPS_RESULTS_DIR,
                "~/redteam-workspace",
                "redteam-workspace"]
            if any(tp and tp in cmd_clean for tp in trusted_paths):
                found = True
            else:
                # V6 FIX: AI might hallucinate an old Cloudflare IP that doesn't match current local DNS.
                # If we see a public IP in the command that isn't our target,
                # auto-replace it with the target IP.
                ip_match = re.search(
                    r'\b(?:[1-9]|1\d|2[0-4]|25[0-5])(?:\.\d{1,3}){3}\b', cmd_clean)
                if ip_match and ip_match.group(
                        0) not in ("127.0.0.1", "0.0.0.0"):
                    if 'ips' in locals() and ips:
                        command = command.replace(ip_match.group(0), ips[0])
                        cmd_clean = command.strip()
                        found = True

            if not found:
                return False, f"Target '{target}' missing in command. Out-of-scope scanning is prohibited.", ""

    # 5. Auto-repair: fix nmap script syntax (colon -> equals)
    repaired = re.sub(r"--script:\s*", "--script=", command)

    # 5b. Tool-specific target normalization
    if tool_name in host_tools:
        repaired = re.sub(r"https?://", "", repaired)
        repaired = re.sub(r"/+$", "", repaired)

        if tool_name == "masscan":
            import socket
            try:
                ip = socket.gethostbyname(normalized_host)
                # Replace the hostname with the IP in the repaired command
                repaired = re.sub(
                    r'\b' +
                    re.escape(normalized_host) +
                    r'\b',
                    ip,
                    repaired)
            except Exception as e:
                log.warning(
                    f"Could not resolve {normalized_host} for masscan: {e}")

    elif tool_name in url_tools:
        repaired = re.sub(r"(?i)(https?://)(?:https?://)+", r"\1", repaired)

    if tool_name == "whatweb":
        repaired = re.sub(r"(?<!\S)-s(?!\S)", "", repaired)

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


def block_or_repair(command: str, target: str,
                    target_context: TargetContext | None = None) -> tuple[str | None, str]:
    """
    Guardian wrapper: return repaired command or None if blocked.
    """
    is_valid, reason, repaired = validate_ai_command(
        command, target, target_context)

    if not is_valid:
        log.warning(f"Guardian BLOCKED: {reason}\n  Command: {command[:100]}")
        return None, f"BLOCKED: {reason}"

    return repaired, "APPROVED"
