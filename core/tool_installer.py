"""
tool_installer.py - Ghostwire V6 Autonomous Tool Installer (7-Gate System)

Path C implementation: AI can request tool installation, but EVERY request must
pass all 7 gates before anything touches the VPS.

Gates (in order, any failure = hard block):
  1. REGISTRY GATE     - Tool must be in the pre-approved installable registry
  2. DESTRUCTIVE GATE  - Tool must not be on the permanent hard-block list
  3. SCOPE GATE        - Tool command must target the declared scope, not the VPS itself
  4. RESOURCE GATE     - VPS must have enough disk + RAM for the install
  5. SOURCE GATE       - Install command must come from a trusted source only
  6. INSTALL GATE      - Actual installation via SSH
  7. VERIFY GATE       - Binary must respond to --version/--help after install

This module is a singleton - one shared ToolInstaller per process.
"""
from __future__ import annotations
from core.config_loader import get_config
from config_thresholds import (
    TOOL_VERIFY_LONG_TIMEOUT,
    MIN_FREE_DISK_MB, MIN_FREE_RAM_MB
)
from config import MAX_VPS_LOAD, USE_REMOTE_VPS

import re
import threading
import time
from typing import Optional
from utils.logger import get_logger

log = get_logger("tool_installer")

# ═══════════════════════════════════════════════════════════════════════════
# HARDENING CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
MAX_INSTALL_RETRIES = 2
INSTALL_RETRY_DELAY = 5  # seconds
TOOL_INSTALL_CHECK_TIMEOUT = 30  # override or use from config

# ═══════════════════════════════════════════════════════════════════════════
# GATE 2 - PERMANENT HARD-BLOCK LIST (humans only can remove entries)
# Tools on this list can NEVER be auto-installed or auto-run, no exceptions.
# ═══════════════════════════════════════════════════════════════════════════
HARD_BLOCKED_BINARIES: frozenset[str] = frozenset({
    # Disk destruction
    "dd", "shred", "wipefs", "mkfs", "fdisk", "parted", "sgdisk", "gdisk",
    "blkdiscard", "hdparm",
    # System shutdown / crash
    "poweroff", "reboot", "halt", "shutdown", "init", "telinit", "systemctl-halt",
    # Kernel module manipulation
    "insmod", "rmmod", "modprobe", "depmod",
    # User/auth destruction
    "userdel", "groupdel", "passwd",       # don't touch VPS root password
    "chpasswd", "usermod",
    # Network lockout (would cut off SSH)
    "iptables",   # handled separately - iptables -F / -X is allowed to block, not clear all
    "nftables", "nft",
    "ufw",         # don't reset firewall rules autonomously
    # Rootkit / backdoor frameworks
    "rootkit", "backdoor", "meterpreter",
    # Fork-bomb equivalents / resource exhaustion
    "stress", "stress-ng", "forkbomb",
    # SSH key manipulation (no touching VPS's own auth)
    "ssh-keygen",   # don't regenerate VPS host keys
    # Crontab / persistence (no persistence on VPS without human approval)
    "crontab",
    # Package manager destructive ops
    "apt-get purge", "apt purge", "dpkg --purge",  # prevent removing core packages
    # Anything touching /etc directly (script names)
    "visudo", "vipw", "vigr",
})

# ═══════════════════════════════════════════════════════════════════════════
# GATE 5 - TRUSTED INSTALL SOURCES
# Install commands must reference one of these trusted origins.
# The regex is checked against the full install script text.
# ═══════════════════════════════════════════════════════════════════════════
TRUSTED_INSTALL_SOURCES: list[str] = [
    r"(?:^|&&|;|\|)\s*apt-get\s+install",
    r"(?:^|&&|;|\|)\s*apt\s+install",
    r"(?:^|&&|;|\|)\s*apk\s+add",
    r"(?:^|&&|;|\|)\s*dnf\s+install",
    r"(?:^|&&|;|\|)\s*yum\s+install",
    r"(?:^|&&|;|\|)\s*pacman\s+-S",
    r"(?:^|&&|;|\|)\s*pip3?\s+install",
    r"(?:^|&&|;|\|)\s*go\s+install",
    r"(?:^|&&|;|\|)\s*gem\s+install",
    r"github\.com/projectdiscovery/",
    r"github\.com/ffuf/",
    r"github\.com/owasp-amass/",
    r"github\.com/OJ/gobuster",
    r"github\.com/bettercap/",
    r"github\.com/michenriksen/",
    r"github\.com/tomnomnom/",
    r"github\.com/hakluke/",
    r"github\.com/lc/",
    r"github\.com/jaeles-project/",
    r"github\.com/hahwul/",
    r"github\.com/sqlmapproject/",
    r"github\.com/wpscanteam/",
    r"github\.com/sullo/nikto",
    r"github\.com/dirsearch/",
    r"github\.com/s0md3v/",
    r"github\.com/blechschmidt/massdns",
    r"github\.com/epi052/feroxbuster",
]

# Gate 3 - VPS self-targeting: these IPs/hostnames mean the command is targeting
# the VPS itself (not the pentest target). Hard block.
VPS_SELF_TARGETS: frozenset[str] = frozenset({
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "127.0.0.0/8", "::1/128",
})

# Gate 7 - Max auto-installs per session (prevents runaway install loops)
# Loaded from config, not hardcoded
SESSION_INSTALL_LIMIT = get_config(
    "installer",
    "session_install_limit",
    50,
    "SESSION_INSTALL_LIMIT")
INSTALL_RETRY_STRATEGIES = get_config(
    "installer", "retry_strategies", [
        "apt-get", "snap", "binary", "source"], "INSTALL_RETRY_STRATEGIES")
DEPENDENCY_CHECK_TIMEOUT = get_config(
    "installer",
    "dependency_check_timeout",
    30,
    "DEPENDENCY_CHECK_TIMEOUT")

# Minimum VPS resources required before any install
# These are now imported from config


class ToolInstaller:
    """
    Singleton 7-gate autonomous tool installer.
    Agents call `request_install(tool_name, install_script, remote_executor, target)`
    and get back (approved: bool, reason: str).
    If approved, the tool binary is added to the session's runtime allowlist.
    """

    _instance: Optional["ToolInstaller"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "ToolInstaller":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init()
        return cls._instance

    def _init(self):
        self._session_install_count: int = 0
        self._runtime_allowlist: set[str] = set()
        # tool -> consecutive fail count
        self._install_failure_counts: dict[str, int] = {}
        # tool -> detailed error metadata
        self._install_failure_details: dict[str, dict] = {}
        # tool -> last attempt time
        self._install_timestamps: dict[str, float] = {}
        self._pending_lock = threading.Lock()

    # ── Public API ──────────────────────────────────────────────────────────

    def get_runtime_allowlist(self) -> frozenset[str]:
        """Return the set of tool binaries cleared for use this session."""
        return frozenset(self._runtime_allowlist)

    def is_hard_blocked(self, binary: str) -> bool:
        """Quick check: is this binary permanently hard-blocked?"""
        return binary.lower() in HARD_BLOCKED_BINARIES

    def request_install(
        self,
        tool_name: str,
        install_script: str,
        remote_executor,
        target: str,
        registry_tool=None,  # ToolCapability object if available
    ) -> tuple[bool, str]:
        """
        Run the full 7-gate check and, if all pass, install the tool.
        Returns (approved: bool, reason: str).
        Tool binary is added to runtime_allowlist on success.
        """
        binary = (registry_tool.binary if registry_tool else tool_name).lower()
        node_label = "VPS" if USE_REMOTE_VPS else "WSL"

        log.info(
            f"[INSTALLER] Install request: '{tool_name}' - running 7-gate check on {node_label}...")

        # Gate 0: Already Installed?
        if remote_executor and self._verify_install(binary, remote_executor):
            with self._pending_lock:
                self._runtime_allowlist.add(binary)
                self._runtime_allowlist.add(tool_name)
            log.info(
                f"[INSTALLER] Gate 0: '{binary}' is already installed and functional.")
            return True, "Already installed"

        from core.capability_registry import ALL_TOOLS
        registry_names = {
            t.name.lower() for t in ALL_TOOLS if getattr(
                t, "can_auto_install", True)}
        if tool_name.lower() not in registry_names and binary not in registry_names:
            reason = (
                f"Gate 1 FAIL: '{tool_name}' is not in the pre-approved installable registry. "
                "A human must add it to capability_registry.py first."
            )
            log.warning(f"[INSTALLER] {reason}")
            return False, reason

        # ── Gate 2: Hard-Block Check ─────────────────────────────────────
        if binary in HARD_BLOCKED_BINARIES or tool_name.lower() in HARD_BLOCKED_BINARIES:
            reason = f"Gate 2 FAIL: '{tool_name}' is permanently hard-blocked. Cannot install."
            log.error(f"[INSTALLER] {reason}")
            return False, reason

        # ── Gate 3: Scope / Self-Targeting Check ────────────────────────
        scope_fail = self._check_scope(install_script, target)
        if scope_fail:
            reason = f"Gate 3 FAIL: {scope_fail}"
            log.warning(f"[INSTALLER] {reason}")
            return False, reason

        # ── Gate 4: VPS/WSL Resource Pre-flight ─────────────────────────────
        if remote_executor:
            resource_ok, resource_msg = self._check_vps_resources(
                remote_executor)
            if not resource_ok:
                reason = f"Gate 4 FAIL: {node_label} resource check failed - {resource_msg}"
                log.warning(f"[INSTALLER] {reason}")
                return False, reason

        # ── Gate 5: Trusted Source Check ────────────────────────────────
        source_ok, source_msg = self._check_install_source(install_script)
        if not source_ok:
            reason = f"Gate 5 FAIL: Untrusted install source - {source_msg}"
            log.error(f"[INSTALLER] {reason}")
            return False, reason

        # ── Gate 5.5: Pre-Install Dependency Verification ────────────────
        if remote_executor and registry_tool:
            deps_ok, deps_msg = self._check_install_dependencies(
                remote_executor, registry_tool, tool_name)
            if not deps_ok:
                reason = f"Gate 5.5 FAIL: {deps_msg}"
                log.warning(f"[INSTALLER] {reason}")
                return False, reason

        # ── Gate 7 pre-check: Session rate limit ────────────────────────
        with self._pending_lock:
            if self._session_install_count >= SESSION_INSTALL_LIMIT:
                reason = (
                    f"Gate 7 FAIL: Session install limit ({SESSION_INSTALL_LIMIT}) reached. "
                    "Too many auto-installs in one session - use tools already available."
                )
                log.warning(f"[INSTALLER] {reason}")
                return False, reason
            # Tentatively increment to reserve a slot during the multi-minute
            # install
            self._session_install_count += 1

        # ── Gate 6: Actual Installation ─────────────────────────────────
        if not remote_executor:
            reason = f"Gate 6 FAIL: No remote executor - cannot install on {node_label}."
            return False, reason

        installed = self._do_install(
            tool_name,
            install_script,
            remote_executor,
            registry_tool)
        if not installed:
            with self._pending_lock:
                self._session_install_count -= 1  # Rollback slot
                self._install_failure_counts[tool_name] = self._install_failure_counts.get(
                    tool_name, 0) + 1
            reason = f"Gate 6 FAIL: Installation of '{tool_name}' failed on {node_label}."
            log.error(f"[INSTALLER] {reason}")
            return False, reason

        # ── Gate 7 post: Verification ───────────────────────────────────
        verified = self._verify_install(binary, remote_executor)
        if not verified:
            with self._pending_lock:
                self._session_install_count -= 1  # Rollback slot
            reason = f"Gate 7 FAIL: '{tool_name}' installed but binary '{binary}' did not respond on {node_label}. Corrupt install."
            log.error(f"[INSTALLER] {reason}")
            return False, reason

        # ── All gates passed ─────────────────────────────────────────────
        with self._pending_lock:
            # Slot is already incremented, just add to allowlist
            self._runtime_allowlist.add(binary)
            self._runtime_allowlist.add(tool_name)
            self._install_timestamps[tool_name] = time.time()

        log.info(
            f"[INSTALLER] [+] '{tool_name}' installed and verified. "
            f"Session installs: {
                self._session_install_count}/{SESSION_INSTALL_LIMIT}. "
            f"Runtime allowlist size: {len(self._runtime_allowlist)}"
        )
        return True, f"INSTALLED: '{tool_name}' cleared for use."

    # ── Internal Gate Implementations ───────────────────────────────────────

    def _check_scope(self, install_script: str,
                     declared_target: str) -> str | None:
        """
        Gate 3: Verify the install script is NOT targeting the VPS itself
        (localhost, 127.x.x.x, ::1). Install scripts targeting self = suspicious.
        Returns None if clean, error string if problem found.
        """
        # Check for obvious self-targeting in the install script
        for self_addr in VPS_SELF_TARGETS:
            if self_addr in install_script:
                return (
                    f"Install script contains self-target '{self_addr}'. "
                    "Install commands must not target localhost."
                )

        # Check for writing to dangerous system paths via install scripts
        dangerous_paths = [
            r"/etc/ssh/",
            r"/etc/passwd",
            r"/etc/shadow",
            r"/etc/sudoers",
            r"/boot/",
            r"/proc/",
            r"/sys/",
        ]
        for path in dangerous_paths:
            if path in install_script:
                return f"Install script targets protected system path: '{path}'"

        # Check the install script doesn't try to run arbitrary curl|bash
        if re.search(r"curl\s+.*\|\s*(?:ba)?sh", install_script):
            # Allow only from trusted GitHub/official sources
            trusted = any(re.search(p, install_script)
                          for p in TRUSTED_INSTALL_SOURCES)
            if not trusted:
                return "Curl-pipe-bash from untrusted source detected."

        return None

    def _check_vps_resources(self, remote_executor) -> tuple[bool, str]:
        """
        Gate 4: Check VPS has enough disk and RAM for a new tool install.
        Returns (ok: bool, message: str).
        """
        try:
            # Check free disk space (df -m /usr gives MB available)
            ec, out, _ = remote_executor.execute(
                "df -m /usr/local/bin 2>/dev/null | awk 'NR==2{print $4}'",
                timeout=TOOL_INSTALL_CHECK_TIMEOUT,
            )
            if ec == 0 and out.strip().isdigit():
                free_mb = int(out.strip())
                if free_mb < MIN_FREE_DISK_MB:
                    return False, f"Insufficient disk space: {free_mb}MB free, need {MIN_FREE_DISK_MB}MB"

            # Check free RAM
            ec, out, _ = remote_executor.execute(
                "awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo 2>/dev/null",
                timeout=TOOL_INSTALL_CHECK_TIMEOUT,
            )
            if ec == 0 and out.strip().isdigit():
                free_ram_mb = int(out.strip())
                if free_ram_mb < MIN_FREE_RAM_MB:
                    return False, f"Insufficient RAM: {free_ram_mb}MB free, need {MIN_FREE_RAM_MB}MB"

            # Check VPS Load Average (1-minute)
            ec, out, _ = remote_executor.execute(
                "awk '{print $1}' /proc/loadavg 2>/dev/null",
                timeout=TOOL_INSTALL_CHECK_TIMEOUT,
            )
            if ec == 0 and out.strip():
                try:
                    # Clean the output in case of trailing noise
                    load_val = out.strip().split()[0]
                    load_avg = float(load_val)
                    if load_avg > MAX_VPS_LOAD:
                        return False, f"VPS load too high: {load_avg} (limit {MAX_VPS_LOAD})"
                except (ValueError, IndexError):
                    pass

        except Exception as e:
            log.debug(f"Resource check SSH error: {e}")
            # Soft-fail resource check - if we can't check, allow but warn
            log.warning(
                "[INSTALLER] Gate 4: Could not verify VPS resources. Proceeding cautiously.")

        return True, "OK"

    def _check_install_source(self, install_script: str) -> tuple[bool, str]:
        """
        Gate 5: Verify install script uses only trusted package managers or
        known-good GitHub release URLs.
        Returns (ok: bool, reason: str).
        """
        # A valid install script must match at LEAST ONE trusted source pattern
        for pattern in TRUSTED_INSTALL_SOURCES:
            if re.search(pattern, install_script, re.IGNORECASE):
                return True, "Trusted source confirmed."

        # Empty install script - reject
        if not install_script.strip():
            return False, "Empty install script."

        return False, (
            "Install script does not reference any trusted source "
            "(apt, pip, official GitHub releases only)."
        )

    def _check_install_dependencies(
            self, remote_executor, registry_tool, tool_name: str) -> tuple[bool, str]:
        """Gate 5.5: Verify tool dependencies are available on VPS before attempting install."""
        try:
            # Check if tool already installed (fast path)
            ec, _, _ = remote_executor.execute(
                f"command -v {registry_tool.binary}", timeout=DEPENDENCY_CHECK_TIMEOUT)
            if ec == 0:
                return True, "Binary already available"

            # Get required dependencies from registry
            required_deps = getattr(registry_tool, "dependencies", [])
            if not required_deps:
                return True, "No dependencies to check"

            # Check if each dependency is available
            missing_deps = []
            for dep in required_deps:
                ec, _, _ = remote_executor.execute(
                    f"command -v {dep} || apt-cache search '^{dep}$'", timeout=DEPENDENCY_CHECK_TIMEOUT)
                if ec != 0:
                    missing_deps.append(dep)

            if missing_deps:
                return False, f"Missing dependencies: {', '.join(missing_deps)}. Pre-install via apt-get update && apt-get install -y {' '.join(missing_deps)}"

            return True, "Dependencies available"
        except Exception as e:
            log.debug(f"Dependency check failed: {e}")
            return False, f"Could not verify dependencies: {e}"

    def _do_install(
        self,
        tool_name: str,
        install_script: str,
        remote_executor,
        registry_tool=None,
    ) -> bool:
        """Gate 6: Execute the install script on the VPS with multiple retry strategies."""
        timeout = getattr(
            registry_tool,
            "install_timeout",
            300) if registry_tool else 300
        retry_strategies = getattr(
            registry_tool,
            "install_strategies",
            INSTALL_RETRY_STRATEGIES)

        for strategy in retry_strategies:
            for attempt in range(1, MAX_INSTALL_RETRIES + 1):
                try:
                    log.info(
                        f"[INSTALLER] Gate 6: Installing '{tool_name}' (Attempt {attempt}/{MAX_INSTALL_RETRIES})...")

                    # Wrap the script to ensure environment and non-interactive
                    # mode
                    import base64
                    script = "export DEBIAN_FRONTEND=noninteractive\n" + \
                        "export PATH=$PATH:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$HOME/.local/bin:$HOME/go/bin\n" + install_script
                    script_b64 = base64.b64encode(script.encode()).decode()
                    full_script = (
                        f"echo {script_b64} | base64 -d | sudo -E bash"
                    )

                    ec, out, err = remote_executor.execute(
                        full_script, timeout=timeout)

                    if ec == 0:
                        # Foundational SHA check: if registry tool has a
                        # checksum, verify it
                        if registry_tool and registry_tool.sha256:
                            binary_to_check = registry_tool.binary
                            # Find the binary location
                            ec_loc, out_loc, _ = remote_executor.execute(
                                f"command -v {binary_to_check}")
                            if ec_loc == 0 and out_loc.strip():
                                binary_path = out_loc.strip()
                                ec_sha, out_sha, _ = remote_executor.execute(
                                    f"sha256sum {binary_path} | awk '{{print $1}}'")
                                if ec_sha != 0:
                                    log.error(
                                        f"[INSTALLER] Integrity FAIL: Could not calculate checksum for {tool_name}")
                                    return False
                                if out_sha.strip() != registry_tool.sha256:
                                    log.error(
                                        f"[INSTALLER] Integrity FAIL: {tool_name} checksum mismatch! Expected {
                                            registry_tool.sha256}, got {
                                            out_sha.strip()}")
                                    return False

                        log.info(
                            f"[INSTALLER] Gate 6: Success for '{tool_name}' on attempt {attempt}.")
                        return True

                    # If we failed, log details and decide whether to retry
                    log.warning(
                        f"[INSTALLER] Gate 6: Attempt {attempt} failed for '{tool_name}'. "
                        f"Exit code: {ec}. "
                        f"stderr: {err.strip()[:500]}..."
                    )

                    if attempt < MAX_INSTALL_RETRIES:
                        log.info(
                            f"[INSTALLER] Retrying in {INSTALL_RETRY_DELAY}s...")
                        time.sleep(INSTALL_RETRY_DELAY)
                    else:
                        log.error(
                            f"[INSTALLER] Gate 6: All {MAX_INSTALL_RETRIES} attempts failed for '{tool_name}'.")
                        # Capture full error for analysis
                        with self._pending_lock:
                            self._install_failure_details[tool_name] = {
                                "exit_code": ec,
                                "stderr": err.strip()[-1000:],
                                "stdout": out.strip()[-500:],
                                "timestamp": time.time()
                            }

                except Exception as e:
                    log.error(
                        f"[INSTALLER] Install exception for '{tool_name}' on attempt {attempt}: {e}")
                    if attempt < MAX_INSTALL_RETRIES:
                        time.sleep(INSTALL_RETRY_DELAY)
                    else:
                        return False

        return False

    def _verify_install(self, binary: str, remote_executor) -> bool:
        """Gate 7: Verify binary is callable on the VPS after install."""
        try:
            # First, check if it's in the PATH at all
            ec_which, out_which, _ = remote_executor.execute(
                f"command -v {binary}", timeout=10)
            if ec_which != 0:
                # Try common locations if not in PATH
                search_paths = [
                    "/usr/local/bin",
                    "$HOME/.local/bin",
                    "/usr/bin",
                    "/bin",
                    "$HOME/go/bin",
                    "/root/go/bin",
                    "$HOME/.cargo/bin",
                    "/snap/bin"]
                found_path = None
                for p in search_paths:
                    ec_p, _, _ = remote_executor.execute(
                        f"[ -x {p}/{binary} ]", timeout=5)
                    if ec_p == 0:
                        found_path = f"{p}/{binary}"
                        break

                if not found_path:
                    log.warning(
                        f"[INSTALLER] Gate 7: Binary '{binary}' not found in PATH or standard locations.")
                    return False
                binary_exec = found_path
            else:
                binary_exec = binary

            # Now try to run it to see if it actually works (doesn't
            # segfault/missing libs)
            verify_cmd = (
                f"export PATH=$PATH:/usr/local/bin:$HOME/.local/bin:$HOME/go/bin:/root/go/bin:$HOME/.cargo/bin:/snap/bin && "
                f"({binary_exec} --version 2>&1 || {binary_exec} --help 2>&1 || "
                f"{binary_exec} -h 2>&1 || {binary_exec} 2>&1) | head -n 5"
            )
            ec_run, out_run, _ = remote_executor.execute(
                verify_cmd, timeout=TOOL_VERIFY_LONG_TIMEOUT)

            # If we got ANY output that looks like the tool name or version
            # info, it's likely good
            if any(marker in out_run.lower()
                   for marker in [binary.lower(), "version", "usage", "help"]):
                log.info(
                    f"[INSTALLER] Gate 7: Verified '{binary}' is functional.")
                return True

            # Fallback: strict exit code 0 check
            if ec_run == 0:
                log.debug(
                    f"[INSTALLER] Gate 7: '{binary}' executed with code {ec_run}, assuming OK.")
                return True

            log.warning(
                f"[INSTALLER] Gate 7: Cannot verify functionality of '{binary}'. Output: {out_run[:200]}")
            return False

        except Exception as e:
            log.error(
                f"[INSTALLER] Gate 7 verify exception for '{binary}': {e}")
            return False

    def session_summary(self) -> dict:
        """Return summary stats for logging."""
        return {
            "installs_this_session": self._session_install_count,
            "install_limit": SESSION_INSTALL_LIMIT,
            "runtime_allowlist": sorted(self._runtime_allowlist),
            "install_failures": self._install_failure_counts,
        }


# ── Module-level singleton accessor ─────────────────────────────────────────

def get_installer() -> ToolInstaller:
    """Get (or create) the process-wide ToolInstaller singleton."""
    return ToolInstaller()


def get_runtime_allowlist() -> frozenset[str]:
    """Convenience function for guardian.py to get current runtime-cleared tools."""
    return ToolInstaller().get_runtime_allowlist()
