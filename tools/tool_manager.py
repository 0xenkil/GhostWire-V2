from tools.tool_registry import VIRTUAL_TOOLS, VIRTUAL_AI_TOOLS, TOOL_FALLBACKS
import os as _os
import subprocess
import time
import os
import signal
import json
import re
import shlex
from pathlib import Path
from typing import TYPE_CHECKING
from tools.tool_registry import TOOL_REGISTRY, load_custom_tools
from tools.output_parser import OutputParser
from core.ssh_executor import SSHExecutor
from core.result_contracts import FragileParseFixer, ToolResult, ResultStatus
from utils.logger import get_logger
from utils.display import warning, success
from utils.sanitizer import clean_text
from core.config_manager import get_config
import config_paths
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from config_thresholds import TOOL_DEFAULT_TIMEOUT
TOOL_RETRY_COUNT = 3  # Default retry count

# Read from .env. Defaults to TRUE because GHOSTWIRE is designed to run fully
# autonomously: when the AI prescribes a tool that isn't installed, the engine
# must be able to install it (apt/pip only, package names validated, apt
# simulated first) without a human in the loop. Set AUTO_APPROVE_INSTALLS=false
# in .env to require manual approval for installs.
AUTO_APPROVE_INSTALLS = _os.getenv(
    "AUTO_APPROVE_INSTALLS", "true").lower() in (
        "true", "1", "yes")


if TYPE_CHECKING:
    from core.session import EngagementSession
    from core.state_store import StateStore
    from core.ai_backend import AIBackend

log = get_logger("tool_manager")


# Markers that, when they are essentially the ONLY thing a tool prints, mean the
# run was a usage/help/error dump rather than a real result.
_USAGE_DUMP_MARKERS = (
    "usage:", "usage ", "options:", "flags:", "incorrect usage",
    "command not found", "not recognized",
)


def _produced_real_output(stdout: str) -> bool:
    """Heuristic: did an exit-0 tool produce substantial *real* output, as
    opposed to just a usage/help/error dump?

    Used to stop the engine from overriding genuinely successful runs to
    FAILED merely because their output contains an error-marker substring
    (e.g. whatweb prints a real fingerprint to stdout while a benign
    "Unknown option" warning lands in stderr). Generic on purpose — no
    per-tool special-casing — so it honours the "let the tool's real result
    stand" design rule.
    """
    text = (stdout or "").strip()
    if len(text) < 40:
        # Nothing meaningful was produced.
        return False
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return False
    # If the very first non-empty line is a usage/help header, this is a dump.
    first = lines[0].lower()
    if first.startswith(("usage:", "usage ", "incorrect usage")):
        return False
    # Count lines that look like genuine content (not option listings / usage
    # boilerplate). Option-listing lines typically start with '-' or are pure
    # "  --flag   description" rows.
    content_lines = [
        ln for ln in lines
        if not ln.lstrip().startswith("-")
        and not any(m in ln.lower() for m in _USAGE_DUMP_MARKERS)
    ]
    content_chars = sum(len(ln) for ln in content_lines)
    # Real results: at least a couple of substantive content lines with body.
    return len(content_lines) >= 1 and content_chars >= 40


def _agent_debug_log(location: str, message: str, data: dict,
                     run_id: str = "run1", hypothesis_id: str = "H4") -> None:
    # Use centralized debug file from config_paths; include session/run
    # metadata when available
    try:
        session_id = data.get("sessionId") if isinstance(
            data, dict) and data.get("sessionId") else run_id
        log_path = config_paths.DEBUG_LOG_FILE if hasattr(
            config_paths, "DEBUG_LOG_FILE") else Path("debug.log")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "sessionId": session_id,
                "runId": run_id,
                "hypothesisId": hypothesis_id,
                "location": location,
                "message": message,
                "data": data,
                "timestamp": int(time.time() * 1000),
            }, ensure_ascii=True) + "\n")
    except Exception as _e:
        import logging
        logging.getLogger(__name__).warning(f"Swallowed exception: {_e}")


def _wsl_which(tool_name: str) -> bool:
    """
    Check if a tool is available inside WSL (Ubuntu Linux subsystem).
    shutil.which() only sees Windows PATH — it misses tools installed in WSL.
    This fixes the false "not installed" report for nmap, gcc, etc.
    """
    try:
        import subprocess
        result = subprocess.run(
            ["wsl", "-e", "which", tool_name],
            capture_output=True, text=True, timeout=6
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except Exception as e:
        import logging as __logging_tmp
        __logging_tmp.getLogger(__name__).error(
            f"Unhandled exception: {e}", exc_info=True)
        return False


# Tools that benefit from real-time streaming (long-running)
STREAMING_TOOLS = {"nmap", "nuclei", "gobuster", "nikto", "masscan", "ffuf",
                   "hydra", "sqlmap", "theharvester", "enum4linux"}

# Tools with fast execution - only 1 retry needed
FAST_TOOLS = {"dig", "curl", "whois", "nc"}

# Virtual tools (internal meta-tools) always 'installed'


# NOTE: ToolResult is the canonical dataclass imported from core.result_contracts
# (see top of file). A second, divergent ToolResult used to be defined here, which
# shadowed the import and put two incompatible result types into circulation. It
# was removed — the contract type is a full superset (success get/set incl.
# FALLBACK_SUCCESS, duration/duration_seconds, parsed, str-enum status) and every
# construction in this file uses keyword args that match the contract's fields.


class ToolManager:
    def __init__(self, session: "EngagementSession",
                 state_store: "StateStore", ai_backend: "AIBackend" = None) -> None:
        # Load any dynamic tools before starting
        try:
            load_custom_tools(str(config_paths.CUSTOM_TOOLS_DIR))
        except Exception as e:
            log.warning(f"Failed to load custom tools: {e}")

        self.session = session
        self.store = state_store
        self.ai = ai_backend
        self.parser = OutputParser()
        self._installed_cache: set = set()
        self._failed_cache: dict = {}  # tool -> timestamp
        self._valid_flags_cache: dict = {}  # tool_key -> set of flags
        self._help_brief_cache: dict = {}  # tool_key -> compact --help text
        self.remote = None

        if get_config().vps.use_remote_vps:
            self.remote = SSHExecutor()
            if not self.remote.connect():
                import sys
                warning(
                    "FATAL: get_config().vps.use_remote_vps is enabled but SSH connection failed.")
                sys.exit(1)
        else:
            # WSL LOCAL MODE: wire WSLExecutor as the remote backend so that
            # all tool commands (nmap, curl, gobuster, etc.) execute inside WSL Ubuntu,
            # NOT on Windows where they don't exist.
            # Without this, _execute() falls to the Windows subprocess path →
            # FileNotFoundError.
            try:
                from config_backends import USE_WSL as _use_wsl
            except ImportError:
                import os as _os
                _use_wsl = _os.getenv(
                    "USE_WSL", "true").lower() in (
                    "true", "1", "yes")

            if _use_wsl:
                from core.wsl_executor import WSLExecutor as _WSLExecutor
                _wsl_exec = _WSLExecutor()
                if _wsl_exec.connect():
                    self.remote = _wsl_exec
                    log.info(
                        "WSL executor wired as remote backend. Tools will execute inside WSL Ubuntu.")
                else:
                    warning(
                        "WSL executor failed to connect — "
                        "tool commands will run on Windows (DEGRADED: most tools will not be found)"
                    )

    def vps_path(self, local_path: str | Path) -> str:
        """Translate a local path to the VPS results tree."""
        if not get_config().vps.use_remote_vps:
            return str(local_path)
        posix = Path(local_path).as_posix()
        if "results/" in posix:
            rel = posix.split("results/")[-1]
        else:
            rel = posix.replace(":", "").replace("\\", "/").lstrip("/")
        return f"{config_paths.VPS_RESULTS_DIR.rstrip('/')}/{rel}"

    def ensure_installed(self, tool_name: str,
                         force_install: bool = False) -> bool:
        if not hasattr(self, '_install_lock'):
            import threading
            self._install_lock = threading.Lock()
        with self._install_lock:
            return self._ensure_installed_unlocked(tool_name, force_install)

    def _ensure_installed_unlocked(
            self, tool_name: str, force_install: bool = False) -> bool:
        """Check if a tool is installed; attempt installation if not."""
        tool_name = tool_name.lower()
        if tool_name in VIRTUAL_TOOLS:
            return True

        if not force_install and tool_name in self._installed_cache:
            return True

        # Failed cache expires after 5 mins to allow retries
        if tool_name in self._failed_cache:
            if time.time() - self._failed_cache[tool_name] < 300:
                return False
            else:
                del self._failed_cache[tool_name]

        # 1. Fast path: check if natively available on OS before consulting registry/AI
        # Also checks WSL because shutil.which() only sees Windows PATH, not
        # WSL binaries.
        if not get_config().vps.use_remote_vps:
            if _wsl_which(tool_name):
                self._installed_cache.add(tool_name)
                return True
        else:
            path_prefix = f"export PATH={config_paths.VPS_TOOL_PATH}:$PATH && "
            check_cmd = f"{path_prefix}which {tool_name} 2>/dev/null || which {
                tool_name.lower()} 2>/dev/null"
            if self.remote:
                exit_code, out, _ = self.remote.execute(check_cmd)
                if exit_code == 0 and out.strip():
                    self._installed_cache.add(tool_name)
                    return True

        tool_info = TOOL_REGISTRY.get(tool_name)
        if not tool_info:
            log.info(
                f"Tool '{tool_name}' not in registry. Invoking AI Discovery...")
            tool_info = self.discover_tool(tool_name)
            if not tool_info:
                self._failed_cache[tool_name] = time.time()
                return False

        binary = tool_info.get("binary") or tool_name

        # 2. Check if already installed (using canonical binary name from
        # registry)
        if binary != tool_name:
            if not get_config().vps.use_remote_vps:
                if _wsl_which(binary):
                    self._installed_cache.add(tool_name)
                    return True
            else:
                path_prefix = f"export PATH={
                    config_paths.VPS_TOOL_PATH}:$PATH && "
                check_cmd = f"{path_prefix}which {binary} 2>/dev/null || which {
                    binary.lower()} 2>/dev/null"
                if tool_name == "theharvester":
                    check_cmd += f" || ls {
                        config_paths.THEHARVESTER_DIR}/theHarvester.py 2>/dev/null"
                if self.remote:
                    exit_code, out, _ = self.remote.execute(check_cmd)
                    if exit_code == 0 and out.strip():
                        self._installed_cache.add(tool_name)
                        return True

        # 2. Attempt installation
        log.info(f"Tool '{tool_name}' not found. Installing...")
        install_cmd = tool_info.get("install", "")
        install_success = False
        err = ""

        if get_config().vps.use_remote_vps:
            # Sanitize AI-provided install commands: reject extremely
            # complex/destructive shell constructs, but allow && and | for
            # valid install scripts
            forbidden_ops = [";", "`", "$(`", "\n"]
            if any(op in install_cmd for op in forbidden_ops):
                log.warning(
                    f"Rejected unsafe AI install for {tool_name} (contains shell operators)")
                _agent_debug_log(
                    "tools/tool_manager.py:ensure_installed",
                    "Rejected unsafe install command",
                    {"tool": tool_name,
                     "install_cmd_preview": install_cmd[:300]},
                    run_id="run1",
                    hypothesis_id="H4",
                )
            else:
                max_vps_attempts = 3
                vps_attempt = 0
                current_install_cmd = install_cmd
                
                while vps_attempt < max_vps_attempts:
                    vps_attempt += 1
                    log.info(f"VPS install attempt {vps_attempt}/{max_vps_attempts} for '{tool_name}'...")
                    
                    # Accept only canonical apt / pip installs and transform into safe operations
                    apt_match = re.search(r'(?:apt-get|apt)\s+(?:-y\s+)?install\s+(.+)$', current_install_cmd, re.IGNORECASE)
                    pip_match = re.search(r'(?:python3?\s+-m\s+)?pip(?:3)?\s+install\s+(.+)$', current_install_cmd, re.IGNORECASE)
                    
                    exit_code = -1
                    err_out = ""
                    
                    if apt_match:
                        pkgs = apt_match.group(1).strip()
                        if not re.match(r'^[A-Za-z0-9+_.:=\s-]+$', pkgs):
                            log.warning(f"Rejected AI apt install for {tool_name} (invalid package names): {pkgs}")
                            err_out = f"Rejected invalid packages: {pkgs}"
                        else:
                            # Simulate install first to ensure packages resolved
                            sim_cmd = f"DEBIAN_FRONTEND=noninteractive apt-get -s install {pkgs}"
                            sim_exit, sim_out, sim_err = self.remote.execute(sim_cmd, timeout=60)
                            if sim_exit == 0:
                                if not AUTO_APPROVE_INSTALLS:
                                    log.info(f"AI-suggested apt install for '{tool_name}' requires operator approval (AUTO_APPROVE_INSTALLS=false)")
                                    break
                                else:
                                    upd_exit, upd_out, upd_err = self.remote.execute("DEBIAN_FRONTEND=noninteractive apt-get update -qq", timeout=120)
                                    if upd_exit != 0:
                                        log.warning(f"apt-get update failed for {tool_name}: {upd_err}")
                                    exit_code, out, err_out = self.remote.execute(f"DEBIAN_FRONTEND=noninteractive apt-get -y install {pkgs}", timeout=tool_info.get("install_timeout", 300))
                            else:
                                log.warning(f"Simulated apt install failed/resolved for {tool_name}: {sim_err or sim_out}")
                                exit_code = sim_exit
                                err_out = sim_err or sim_out
                    elif pip_match:
                        pkgs = pip_match.group(1).strip()
                        if not re.match(r'^[A-Za-z0-9+_.:=\s-]+$', pkgs):
                            log.warning(f"Rejected AI pip install for {tool_name} (invalid package names): {pkgs}")
                            err_out = f"Rejected invalid packages: {pkgs}"
                        else:
                            if not AUTO_APPROVE_INSTALLS:
                                log.info(f"AI-suggested pip install for '{tool_name}' requires operator approval (AUTO_APPROVE_INSTALLS=false)")
                                break
                            else:
                                exit_code, out, err_out = self.remote.execute(f"python3 -m pip install --no-input {pkgs}", timeout=tool_info.get("install_timeout", 300))
                    else:
                        log.warning(f"AI install command for '{tool_name}' not recognized as safe (only apt/pip supported): {current_install_cmd[:200]}")
                        err_out = f"Command {current_install_cmd[:50]} not recognized as safe apt/pip format"
                    
                    if exit_code == 0:
                        # ── VPS PATH LOCATOR ──
                        check_exit, _, _ = self.remote.execute(check_cmd)
                        if check_exit == 0:
                            install_success = True
                            log.info(f"[+] VPS install succeeded for '{tool_name}' and is in PATH.")
                            break
                        else:
                            log.warning(f"VPS install returned 0 but '{binary}' not in PATH. Executing PATH locator...")
                            find_cmd = f"find / -type f -name '{binary}' -executable 2>/dev/null | grep -v 'Permission denied' | head -n 1"
                            find_exit, find_out, _ = self.remote.execute(find_cmd, timeout=60)
                            found_path = find_out.strip()
                            if found_path:
                                log.info(f"Locator found '{binary}' at {found_path}. Symlinking to /usr/local/bin...")
                                link_cmd = f"ln -sf '{found_path}' '/usr/local/bin/{binary}'"
                                self.remote.execute(link_cmd, timeout=15)
                                check_exit, _, _ = self.remote.execute(check_cmd)
                                if check_exit == 0:
                                    install_success = True
                                    log.info(f"[+] Symlink successful. '{tool_name}' is now accessible.")
                                    break
                                else:
                                    log.error(f"Symlink failed for '{binary}'.")
                                    break
                            else:
                                log.error(f"Locator could not find '{binary}' anywhere on the VPS filesystem.")
                                break
                    else:
                        log.error(f"VPS Install attempt {vps_attempt} failed for {tool_name}: {err_out[:300]}")
                        if vps_attempt < max_vps_attempts and self.ai:
                            log.info(f"Invoking AI Repair for VPS '{tool_name}' installation...")
                            repair_prompt = (
                                f"I tried to install '{tool_name}' on the VPS using:\n`{current_install_cmd}`\n\n"
                                f"It failed with this error:\n{err_out[:1000]}\n\n"
                                f"Provide ONLY the raw JSON block for an alternative installation command (must be a valid apt-get or pip install). "
                                f"The JSON must have this structure:\n{{\"install\": \"<exact_alternative_command>\"}}"
                            )
                            try:
                                repair_res = self.ai.query("You are a Linux sysadmin.", repair_prompt)
                                repair_data = FragileParseFixer.safe_split_json_extraction(repair_res, default={})
                                new_cmd = repair_data.get("install", "")
                                if new_cmd and new_cmd != current_install_cmd:
                                    current_install_cmd = new_cmd
                                    continue
                            except Exception as e:
                                log.error(f"AI Repair failed: {e}")
                                break
                        break
        else:
            try:
                _agent_debug_log(
                    "tools/tool_manager.py:local_install_attempt",
                    "Running local WSL install",
                    {"tool": tool_name,
                     "install_cmd_preview": install_cmd[:200]},
                    run_id="run1",
                    hypothesis_id="H4",
                )
                if not AUTO_APPROVE_INSTALLS:
                    log.info(
                        f"AI-suggested local install for '{tool_name}' requires operator approval (AUTO_APPROVE_INSTALLS=false)")
                else:
                    # Run install inside WSL — apt-get/pip commands don't exist on Windows.
                    # Prefix with sudo -n to avoid interactive password
                    # prompts.
                    safe_cmd = install_cmd.strip()
                    # Prepend DEBIAN_FRONTEND for apt installs
                    if "apt" in safe_cmd:
                        safe_cmd = f"DEBIAN_FRONTEND=noninteractive {safe_cmd}"
                    # ── AI REPAIR LOOP FOR WSL INSTALLATION ──
                    max_attempts = 3
                    attempt = 0
                    current_install_cmd = safe_cmd
                    
                    while attempt < max_attempts:
                        attempt += 1
                        log.info(f"Running WSL install attempt {attempt}/{max_attempts} for '{tool_name}': {current_install_cmd[:120]}")
                        
                        result = subprocess.run(
                            ["wsl", "-u", "root", "-e", "bash", "-c", current_install_cmd],
                            capture_output=True, text=True, timeout=300,
                        )
                        
                        if result.returncode == 0:
                            # ── AUTOMATED BINARY LOCATOR (PATH RESILIENCE) ──
                            if _wsl_which(binary):
                                install_success = True
                                log.info(f"[+] WSL install succeeded for '{tool_name}' and is in PATH.")
                                break
                            else:
                                log.warning(f"WSL install returned 0 but '{binary}' not in PATH. Executing PATH locator...")
                                # This locator only runs AFTER a PATH lookup already failed, so a
                                # full `find /` is both pointless (PATH dirs are already covered)
                                # and catastrophic under WSL: it descends into /mnt/{c,d,...} (the
                                # mounted Windows drives) and reliably blows the 60s timeout below,
                                # leaving tools installed off-PATH (gau -> /root/go/bin,
                                # searchsploit -> /opt) unregistered and unusable. Instead probe
                                # the known non-PATH install bin dirs directly (~15ms), then fall
                                # back to a depth-bounded search over just the dirs where clones
                                # land (never /mnt) — ~2s worst case vs a 60s hang.
                                find_cmd = (
                                    f"for d in /usr/local/bin /root/go/bin /root/.local/bin "
                                    f"/opt/bin /snap/bin /usr/bin /bin /usr/sbin; do "
                                    f"[ -x \"$d/{binary}\" ] && {{ echo \"$d/{binary}\"; exit 0; }}; done; "
                                    f"find /opt /root/go /usr/local /usr/share -maxdepth 5 "
                                    f"-type f -name '{binary}' -executable 2>/dev/null "
                                    f"| grep -v 'Permission denied' | head -n 1")
                                find_res = subprocess.run(
                                    ["wsl", "-u", "root", "-e", "bash", "-c", find_cmd],
                                    capture_output=True, text=True, timeout=60,
                                )
                                found_path = find_res.stdout.strip()
                                if found_path:
                                    log.info(f"Locator found '{binary}' at {found_path}. Symlinking to /usr/local/bin...")
                                    link_cmd = f"ln -sf '{found_path}' '/usr/local/bin/{binary}'"
                                    subprocess.run(["wsl", "-u", "root", "-e", "bash", "-c", link_cmd], timeout=15)
                                    if _wsl_which(binary):
                                        install_success = True
                                        log.info(f"[+] Symlink successful. '{tool_name}' is now accessible.")
                                        break
                                    else:
                                        log.error(f"Symlink failed for '{binary}'.")
                                        break
                                else:
                                    log.error(f"Locator could not find '{binary}' anywhere on the WSL filesystem.")
                                    break
                        else:
                            err_out = (result.stderr or "").strip()
                            log.error(f"WSL Install attempt {attempt} failed for {tool_name}: {err_out[:300]}")
                            
                            if attempt < max_attempts and self.ai:
                                log.info(f"Invoking AI Repair for '{tool_name}' installation...")
                                repair_prompt = (
                                    f"I tried to install '{tool_name}' via this command:\n`{current_install_cmd}`\n\n"
                                    f"It failed with this error:\n{err_out[:1000]}\n\n"
                                    f"Provide ONLY the raw JSON block for an alternative installation command (e.g., using pip3, wget/tar, go install, or git clone). "
                                    f"The JSON must have this structure:\n{{\"install\": \"<exact_alternative_command>\"}}"
                                )
                                try:
                                    repair_res = self.ai.query("You are a Linux sysadmin.", repair_prompt)
                                    repair_data = FragileParseFixer.safe_split_json_extraction(repair_res, default={})
                                    new_cmd = repair_data.get("install", "")
                                    if new_cmd and new_cmd != current_install_cmd:
                                        current_install_cmd = new_cmd
                                        if "apt" in current_install_cmd and not "DEBIAN_FRONTEND" in current_install_cmd:
                                             current_install_cmd = f"DEBIAN_FRONTEND=noninteractive {current_install_cmd}"
                                        # Mirror the primary discovery path (see AI-discovery
                                        # normalization): on Debian/PEP-668 a bare `pip3 install`
                                        # fails with "externally-managed-environment", so the
                                        # AI-repair fallback must inject --break-system-packages
                                        # too — without this, pip3 repairs are guaranteed to fail
                                        # (observed: commix repair chain died here, tool unusable).
                                        if "pip3 install" in current_install_cmd and "--break-system-packages" not in current_install_cmd:
                                            current_install_cmd = current_install_cmd.replace(
                                                "pip3 install", "pip3 install --break-system-packages", 1)
                                        elif "pip install" in current_install_cmd and "--break-system-packages" not in current_install_cmd:
                                            current_install_cmd = current_install_cmd.replace(
                                                "pip install", "pip install --break-system-packages", 1)
                                        continue
                                except Exception as e:
                                    log.error(f"AI Repair failed: {e}")
                                    break
                            break

            except Exception as e:
                _agent_debug_log(
                    "tools/tool_manager.py:local_install_exception",
                    "Exception during local install execution",
                    {"tool": tool_name, "error": str(e)[:200]},
                    run_id="run1",
                    hypothesis_id="H4",
                )
                log.error(f"Local Install exception for {tool_name}: {e}")

        if install_success:
            self._installed_cache.add(tool_name)
            return True
        else:
            log.warning(
                f"Installation validation failed for '{tool_name}'. Will attempt fallback on execution.")
            # Don't cache as failed if it was a network error (so it can be
            # retried immediately)
            err_msg = str(result.stderr).lower() if 'result' in locals() and result else ""
            if get_config().vps.use_remote_vps and any(x in err_msg for x in ["ssh", "connection failed", "banner"]):
                log.info(
                    f"Retrying installation for '{tool_name}' next time (transient network error).")
            else:
                self._failed_cache[tool_name] = time.time()
            return False

    def get_fallback_tool(self, tool_name: str) -> str | None:
        """Get a fallback tool when primary tool is unavailable."""
        tool_name = tool_name.lower()
        fallbacks = TOOL_FALLBACKS.get(tool_name, [])
        for fallback in fallbacks:
            if self.ensure_installed(fallback):
                log.warning(
                    f"Using fallback tool '{fallback}' for '{tool_name}'")
                return fallback
        return None

    def _translate_command_for_fallback(
            self, original_tool: str, fallback_tool: str, command: str) -> str:
        """Translate a command from original tool to fallback tool syntax."""
        # Simple command translation for common fallbacks
        if original_tool == "nuclei" and fallback_tool == "nikto":
            # nuclei -u <url> -> nikto -h <url>
            match = re.search(r'-u\s+([^\s]+)', command)
            if match:
                url = match.group(1)
                return f"nikto -h {url} -maxtime 120"
            return command
        elif original_tool == "nuclei" and fallback_tool == "curl":
            # nuclei -u <url> -> curl <url>
            match = re.search(r'-u\s+([^\s]+)', command)
            if match:
                url = match.group(1)
                return f"curl -sL {url}"
            return command
        elif original_tool == "nikto" and fallback_tool == "gobuster":
            # nikto -h <url> -> gobuster dir -u <url>
            match = re.search(r'-h\s+([^\s]+)', command)
            if match:
                url = match.group(1)
                return f"gobuster dir -u {url} -q"
            return command
        elif original_tool == "gobuster" and fallback_tool == "ffuf":
            # gobuster dir -u <url> -> ffuf -u <url>/FUZZ
            match = re.search(r'-u\s+([^\s]+)', command)
            if match:
                url = match.group(1).rstrip('/')
                return f"ffuf -u {url}/FUZZ -w {config_paths.VPS_TEMP_DIR}/ai_wordlist.txt -q"
            return command
        elif original_tool in ("sqlmap", "gobuster", "nikto") and fallback_tool == "curl":
            # Any tool falls back to curl for basic HTTP requests
            match = re.search(r'(?:-u|-h)\s+([^\s]+)', command)
            if match:
                url = match.group(1)
                return f"curl -sL -i {url}"
            return command
        else:
            # For unknown translations, just use the fallback tool name
            pass
        return re.sub(r'\b' + re.escape(original_tool) +
                      r'\b', fallback_tool, command)

    def discover_tool(self, tool_name: str) -> dict | None:
        """Use AI to research how to install an unknown tool."""
        tool_name = tool_name.lower()
        if not self.ai:
            log.warning(
                f"Cannot discover tool '{tool_name}': AI backend not available")
            return None
        warning(
            f"AI RESEARCH: Discovering installation metadata for '{tool_name}'...")
        prompt = (
            f"I need to use a tool called '{tool_name}' on a Debian-based Linux VPS via SSH.\n"
            f"Provide a JSON object with:\n"
            f"1. 'binary': the exact binary name\n"
            f"2. 'install': the exact apt-get/pip/wget command to install it silently.\n"
            f"3. 'timeout': integer execution timeout in seconds.\n"
            f"Return ONLY the raw JSON block."
        )
        try:
            response = self.ai.query(
                "You are an expert Linux sysadmin.", prompt)
            data = FragileParseFixer.safe_split_json_extraction(
                response, default={})
            if "binary" in data and "install" in data:
                # Validate install command against a conservative allowlist
                install_cmd = data.get("install", "")
                safe_prefixes = (
                    "apt-get ",
                    "apt ",
                    "pip ",
                    "pip3 ",
                    "yum ",
                    "dnf ",
                    "wget ",
                    "curl ")
                normalized = install_cmd.strip().lower()
                if any(normalized.startswith(p) for p in safe_prefixes):
                    if normalized.startswith(
                            "pip3 install") and "--break-system-packages" not in normalized:
                        install_cmd = install_cmd.replace(
                            "pip3 install", "pip3 install --break-system-packages", 1)
                        data["install"] = install_cmd
                    log.info(
                        f"AI discovered '{tool_name}': binary={
                            data['binary']}")
                    return data
                else:
                    log.warning(
                        f"AI-suggested install command for '{tool_name}' rejected by allowlist: {install_cmd[:200]}")
                    _agent_debug_log(
                        "tools/tool_manager.py:discover_tool:unsafe",
                        "AI-suggested install rejected",
                        {"tool": tool_name,
                         "suggested_install": install_cmd[:500]},
                        run_id="run1",
                        hypothesis_id="H4",
                    )
                    return None
        except Exception as e:
            log.error(f"AI Tool Discovery failed for '{tool_name}': {e}")
        return None

    def learn_tool_syntax(self, tool_name: str) -> str | None:
        """Dynamically learn tool syntax by reading its help menu and caching the AI distillation."""
        cache_key = f"tool_syntax_{tool_name}"
        cached = self.store.get(cache_key)
        if cached:
            return cached

        if not self.ai:
            return None

        warning(f"AI LEARNING: Distilling syntax rules for '{tool_name}'...")

        # Fast non-blocking help execution
        res = self._execute(
            tool_name,
            f"{tool_name} -h",
            timeout=15,
            silent=True)
        help_text = (res.stdout or "") + (res.stderr or "")

        if not help_text or len(help_text.strip()) < 20:
            # Try --help if -h fails or is too short
            res = self._execute(
                tool_name,
                f"{tool_name} --help",
                timeout=15,
                silent=True)
            help_text = (res.stdout or "") + (res.stderr or "")

        if not help_text or len(help_text.strip()) < 20:
            log.warning(f"Could not retrieve help text for '{tool_name}'.")
            return None

        # Truncate to save tokens (first 8000 chars is usually enough for
        # syntax)
        help_text = help_text[:8000]

        prompt = (
            f"You are a command-line expert. Read the following help menu for '{tool_name}'.\n"
            f"Extract the absolute most critical, robust syntax required to run this tool correctly.\n"
            f"If it's a web fuzzer, mention where to place 'FUZZ'. If it's a login brute forcer (like hydra), provide the exact string structure for post forms (e.g. 'http-post-form \"/path:params:fail\"').\n"
            f"Also explicitly list the exact flag used for rate-limiting, concurrency, or threads (e.g., -rate, -t, -c).\n"
            f"Keep your response strictly under 2 sentences. Start your response with 'CRITICAL CONSTRAINT:'\n\n"
            f"--- HELP MENU ---\n{help_text}"
        )

        try:
            syntax_rule = self.ai.query(
                "You are a syntax extraction bot.", prompt).strip()
            if syntax_rule:
                self.store.set(cache_key, syntax_rule)
                success(f"Learned syntax for {tool_name}: {syntax_rule}")
                return syntax_rule
        except Exception as e:
            log.error(f"Failed to learn syntax for {tool_name}: {e}")

        return None

    def _print_vps_console(self, command: str, status: str, duration: float,
                           out: str, err: str) -> None:
        """Print a compact VPS result panel for failures."""
        node_label = "VPS" if get_config().vps.use_remote_vps else "WSL"
        console = Console()
        status_colors = {
            "success": "bright_green",
            "timeout": "yellow",
            "fallback": "bright_yellow",
            "fallback_success": "bright_cyan",
        }
        color = status_colors.get(status, "bright_red")
        content = Text()
        content.append("    [ CMD ] ", style="bold cyan")
        # Show full command up to 1500 chars (enough for any nuclei/gobuster
        # cmd)
        truncated_cmd = command[:1500] + ("..." if len(command) > 1500 else "")
        content.append(f"{truncated_cmd}\n", style="dim white")
        content.append("    [ STS ] ", style="bold cyan")
        content.append(f"{status.upper()} ({duration:.1f}s)\n",
                       style=f"bold {color}")
        if out.strip():
            content.append("\n" + "─" * 60 + "\n", style="dim cyan")
            lines = out.strip().splitlines()

            # Nuclei JSONL can contain very large fields like template-encoded/request/response.
            # Render concise finding lines so terminal output stays readable.
            if "nuclei " in command.lower():
                concise_lines = []
                for line in lines:
                    s = line.strip()
                    if not s:
                        continue
                    if s.startswith("{") and s.endswith("}"):
                        try:
                            obj = json.loads(s)
                            tid = obj.get("template-id", "unknown")
                            sev = obj.get("info", {}).get("severity", "info")
                            matched = obj.get(
                                "matched-at") or obj.get("host") or obj.get("url") or ""
                            concise_lines.append(
                                f"[{sev}] {tid} {matched}".strip())
                            continue
                        except Exception as e:
                            import logging as __logging_tmp
                            __logging_tmp.getLogger(__name__).error(
                                f"Unhandled exception: {e}", exc_info=True)
                            # Some Nuclei lines include massive encoded fields;
                            # skip noisy payload lines.
                            lower_s = s.lower()
                            if any(k in lower_s for k in [
                                   "template-encoded", "curl-command", "\"request\"", "\"response\""]):
                                continue
                            m_tid = re.search(
                                r'"template-id"\s*:\s*"([^"]+)"', s)
                            m_sev = re.search(r'"severity"\s*:\s*"([^"]+)"', s)
                            m_match = re.search(
                                r'"matched-at"\s*:\s*"([^"]+)"', s)
                            if m_tid:
                                tid = m_tid.group(1)
                                sev = m_sev.group(1) if m_sev else "info"
                                matched = m_match.group(1) if m_match else ""
                                concise_lines.append(
                                    f"[{sev}] {tid} {matched}".strip())
                                continue
                    concise_lines.append(s)
                lines = concise_lines

            # Show as much output as possible while protecting CMD scrollback buffer.
            # Full uncut output is always saved to the VPS results file.
            MAX_DISPLAY_LINES = 300
            if len(lines) > MAX_DISPLAY_LINES:
                HEAD_LINES = 200
                TAIL_LINES = 30
                omitted = len(lines) - HEAD_LINES - TAIL_LINES
                display_lines = [
                    line[:2000] +
                    (" ...[line truncated]" if len(line) > 2000 else "")
                    for line in lines[:HEAD_LINES]
                ]
                content.append("\n".join(display_lines), style="dim white")
                content.append(
                    f"\n\n  ─── [ {omitted} lines omitted · full output saved to {node_label} results ] ───\n\n",
                    style="bold yellow"
                )
                display_lines_tail = [
                    line[:2000] +
                    (" ...[line truncated]" if len(line) > 2000 else "")
                    for line in lines[-TAIL_LINES:]
                ]
                content.append(
                    "\n".join(display_lines_tail),
                    style="dim white")
            else:
                display_lines = [
                    line[:2000] +
                    (" ...[line truncated]" if len(line) > 2000 else "")
                    for line in lines
                ]
                content.append("\n".join(display_lines), style="dim white")
        elif status == "success":
            content.append("\n" + "─" * 60 + "\n", style="dim cyan")
            content.append(
                "    (No results/output returned from tool)",
                style="dim italic white")

        if err.strip():
            content.append(
                "\n\n" + "[!] " * 30 + "\n",
                style="bold bright_red")
            content.append(err.strip()[:1000], style="bright_red")
        label = f"{node_label} TARGET MODULE"
        console.print(
            Panel(
                content,
                title=f"[bold {color}]▰▰▰ {label} ▰▰▰[/]",
                border_style=color,
                padding=(
                    1,
                    2)))

    def get_tool_valid_flags(self, tool_name: str, command: str = "") -> set:
        """Execute --help and cache the valid flags for a tool/subcommand."""
        tool_name = tool_name.lower()
        subcmd = ""
        # Identify subcommand for gobuster
        if tool_name == "gobuster":
            for s in ["dir", "dns", "vhost", "fuzz", "s3", "gcs", "tftp"]:
                if f"gobuster {s}" in command:
                    subcmd = s
                    break

        cache_key = f"{tool_name}_{subcmd}" if subcmd else tool_name
        if cache_key in self._valid_flags_cache:
            return self._valid_flags_cache[cache_key]

        help_cmd = f"{tool_name} --help 2>&1 || {tool_name} -h 2>&1"
        if subcmd:
            help_cmd = f"{tool_name} {subcmd} --help 2>&1 || {help_cmd}"

        h_exit, help_out, _h_err = self.remote.execute(
            help_cmd, timeout=15) if self.remote else (1, "", "")
        if not help_out.strip() and getattr(_h_err, "strip", lambda: "")():
            help_out = _h_err

        import re
        valid_flags = set(
            re.findall(
                r'(?:(?<=\s)|(?<=,)|^)(-{1,2}[a-zA-Z0-9][a-zA-Z0-9\-]*)',
                help_out,
                re.MULTILINE)
        )
        # Safety guard
        if len(valid_flags) < 5:
            log.warning(
                f"Dynamic Flag Corrector: Only {
                    len(valid_flags)} flags extracted from '{help_cmd}' — returning empty set to avoid stripping.")
            valid_flags = set()

        self._valid_flags_cache[cache_key] = valid_flags
        return valid_flags

    def get_tool_help_brief(self, tool_name: str, command: str = "",
                            max_chars: int = 1100) -> str:
        """Return a compact, cached slice of a tool's REAL `--help` output, for
        PROACTIVE grounding of command generation (so the AI writes correct
        syntax up front instead of failing and entering the repair loop).

        Ground truth on purpose: we fetch the tool's own help rather than
        trusting remembered/learned syntax, because a command that "worked
        before" may still have been subtly wrong. Fetched once per tool (per
        subcommand) per engagement and cached, so it is token/-latency bounded.
        Returns "" if help can't be obtained.
        """
        tool_name = (tool_name or "").lower().strip()
        if not tool_name or not self.remote:
            return ""
        subcmd = ""
        if tool_name == "gobuster":
            for s in ["dir", "dns", "vhost", "fuzz", "s3", "gcs", "tftp"]:
                if f"gobuster {s}" in command:
                    subcmd = s
                    break
        cache_key = f"{tool_name}_{subcmd}" if subcmd else tool_name
        if cache_key in self._help_brief_cache:
            return self._help_brief_cache[cache_key]

        help_cmd = f"{tool_name} --help 2>&1 || {tool_name} -h 2>&1"
        if subcmd:
            help_cmd = f"{tool_name} {subcmd} --help 2>&1 || {help_cmd}"
        try:
            _ec, help_out, _err = self.remote.execute(help_cmd, timeout=15)
        except Exception as e:
            log.debug(f"help-brief fetch failed for {tool_name}: {e}")
            self._help_brief_cache[cache_key] = ""
            return ""
        if not (help_out or "").strip() and getattr(_err, "strip", lambda: "")():
            help_out = _err
        # CRITICAL: tools auto-install on first USE, but grounding fetches help
        # BEFORE that — so a not-yet-installed tool returns a shell error
        # ("command not found", "no such file", a one-line usage stub) rather
        # than real help. Feeding THAT to the grounding AI as "authoritative
        # --help" makes it rewrite a sound command to "match" an error message →
        # a wrong command. Treat error/empty output as NO help (return "") so
        # grounding leaves the draft unchanged and the tool auto-installs on run.
        _ho = (help_out or "")
        _hol = _ho.lower()
        _is_error = (
            not _ho.strip()
            or "command not found" in _hol
            or "not found" in _hol[:160]
            or "no such file" in _hol
            or "is not recognized" in _hol
            or "cannot find" in _hol[:160]
            # a genuine --help dump has a usage line and/or many flag rows; a
            # bare error stub does not.
            or (len(_ho.strip()) < 60 and "usage" not in _hol and _ho.count("-") < 3))
        if _is_error:
            self._help_brief_cache[cache_key] = ""
            return ""
        brief = self._compact_help_text(help_out or "", max_chars)
        self._help_brief_cache[cache_key] = brief
        return brief

    @staticmethod
    def _compact_help_text(text: str, max_chars: int) -> str:
        """Keep the highest-signal lines of a --help dump (usage line + flag
        rows) and drop prose, so grounding stays token-bounded."""
        text = (text or "").strip()
        if not text:
            return ""
        if len(text) <= max_chars:
            return text
        lines = [ln.rstrip() for ln in text.splitlines()]
        usage, flags, other = [], [], []
        for ln in lines:
            low = ln.strip().lower()
            if low.startswith("usage") or low.startswith("syntax"):
                usage.append(ln)
            elif ln.strip().startswith("-"):
                flags.append(ln)
            elif ln.strip():
                other.append(ln)
        kept = usage + flags + other
        out = "\n".join(kept)
        if len(out) > max_chars:
            out = out[:max_chars] + "\n...[help truncated]"
        return out

    def validate_and_filter_flags(self, command: str, tool_name: str) -> str:
        """Return the command unchanged.

        DISABLED (was the "Proactive Flag Corrector"): the previous
        implementation ran `<tool> --help`, regex-extracted a set of "valid"
        flags from the help text, and silently DROPPED any flag in the command
        that wasn't in that set. The help parser is unreliable — many tools
        document flags in ways the regex misses (e.g. nmap lists scan types
        slash-separated as `-sS/-sT/-sA`, so only `-sS` was captured and the AI's
        `-sT`, `-p`, `-oN` were stripped). The result was silent corruption: the
        AI believed it ran `nmap -p 80,443 -oN out` but the engine actually ran
        bare `nmap`, producing wrong/unbounded scans the AI never sees and can't
        learn from.

        Correct behaviour for a fully-autonomous engine: run the AI's command as
        written. If a flag really is wrong, the tool errors with a usage message,
        which `safe_run_tool` detects and feeds — together with the tool's real
        `--help` output — to `_ai_repair_tool`, which fixes the *specific* flag
        the tool actually rejected. That AI-driven repair is strictly more
        accurate than a regex guess and keeps the AI in the loop.
        """
        return command

    def _canonical_hosts_file(self) -> str | None:
        """Materialize ALL currently-known hosts (primary target + every
        subdomain/host finding) to a stable file in the WSL workspace, returning
        its path. Universal input for ANY tool that needs a host list. Cached and
        refreshed per call so it always reflects the latest findings.
        """
        if not self.remote:
            return None
        try:
            import posixpath
            import config_paths
            eid = getattr(self.session, "engagement_id", "global")
            hosts = set()
            try:
                primary = getattr(self.session, "target", "") or ""
                ph = re.sub(r"^https?://", "", primary).split("/")[0].split(":")[0]
                if ph:
                    hosts.add(ph.lower())
            except Exception:
                pass
            try:
                for f in (self.store.get_all_findings(eid) or []):
                    ft = str(f.get("type", "") or f.get("finding_type", "")).lower()
                    if "subdomain" in ft or ft in (
                            "live_host", "discovered_host", "new_host", "discovered_endpoint"):
                        for m in re.findall(
                                r'([a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})',
                                str(f.get("detail", ""))):
                            hosts.add(m.lower().rstrip("."))
            except Exception:
                pass
            hosts = sorted(h for h in hosts if h and "." in h)
            if not hosts:
                return None
            # Resolve to an ABSOLUTE path — a quoted '~' does not expand in the
            # shell, so a tool given '~/…/recon_hosts.txt' would not find it.
            base_dir = config_paths.WSL_TEMP_DIR
            if base_dir.startswith("~"):
                if not getattr(self, "_remote_home_dir", None):
                    ec, out, _ = self.remote.execute("echo $HOME", timeout=5)
                    self._remote_home_dir = out.strip() if ec == 0 and out.strip() else "/root"
                base_dir = base_dir.replace("~", self._remote_home_dir, 1)
            path = posixpath.join(base_dir, "recon_hosts.txt")
            self.remote.execute(f"mkdir -p {posixpath.dirname(path)}", timeout=5)
            self.remote.execute(f"rm -f {path}", timeout=5)
            for i in range(0, len(hosts), 40):
                chunk = "\n".join(hosts[i:i + 40])
                self.remote.execute(f"echo -n {shlex.quote(chunk + chr(10))} >> {path}", timeout=10)
            return path
        except Exception as e:
            log.debug(f"canonical hosts file materialization failed: {e}")
            return None

    def _canonical_wordlist(self) -> str | None:
        """Return a real wordlist path that EXISTS in WSL, for any tool whose
        wordlist argument points at a missing/placeholder file or the literal
        {WORDLIST} token.

        Order: (1) the engine's AI-provisioned, tech-stack-targeted micro-wordlist
        (preferred); (2) standard installed lists; (3) a tiny generic fallback we
        WRITE on the spot so dir-busting can always run instead of crashing on a
        missing file. (3) is last-resort infrastructure, not attack logic — the
        AI's targeted list always wins above it. Never returns None when a real
        list can be found or written."""
        if not self.remote:
            return None
        if getattr(self, "_cached_wordlist", None):
            return self._cached_wordlist
        import config_paths as _cp
        _wd = str(_cp.WSL_TEMP_DIR).rstrip("/")
        candidates = [
            f"{_wd}/ai_wordlist.txt",   # AI-provisioned micro-wordlist (preferred)
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
        ]
        for c in candidates:
            try:
                ec, _, _ = self.remote.execute(f'test -e "{c}"', timeout=5)
                if ec == 0:
                    self._cached_wordlist = c
                    return c
            except Exception:
                continue
        # LAST RESORT: nothing installed and the AI list wasn't provisioned —
        # write a tiny generic fallback so the tool RUNS rather than dying on a
        # missing file. The AI's targeted list is always preferred above.
        try:
            fb = f"{_wd}/fallback_wordlist.txt"
            words = ("admin api login dashboard config backup .env .git/HEAD "
                     "robots.txt sitemap.xml wp-admin wp-login.php phpinfo.php "
                     "test dev staging uploads static assets js css images v1 v2 "
                     "graphql swagger api-docs actuator health debug console "
                     "server-status info status .well-known .htaccess admin.php")
            self.remote.execute(
                f"mkdir -p {_wd} 2>/dev/null; printf '%s\\n' {words} > {fb}",
                timeout=10)
            ec, _, _ = self.remote.execute(f'test -s "{fb}"', timeout=5)
            if ec == 0:
                self._cached_wordlist = fb
                log.info(
                    f"[WORDLIST] No installed/AI wordlist found — wrote generic "
                    f"fallback so dir-busting can run: {fb}")
                return fb
        except Exception as _e:
            log.debug(f"fallback wordlist write failed: {_e}")
        return None

    def _canonical_substitute(self, missing_path: str, preceding_flag: str) -> str | None:
        """Universal classifier: a referenced INPUT file doesn't exist anywhere.
        Decide whether it's a host-list or a wordlist (from the preceding flag or
        the filename) and return a canonical file we actually have. Tool-agnostic
        — keys off STANDARD flag names + filename keywords, not per-tool logic.
        Returns None when it can't classify (caller leaves the path as-is)."""
        pf = (preceding_flag or "").lower().lstrip("-").split("=")[0]
        base = missing_path.rsplit("/", 1)[-1].lower()
        HOST_FLAGS = {"l", "list", "il", "input-file", "hosts", "host", "targets", "target"}
        WORD_FLAGS = {"w", "wordlist", "wordlists", "d"}
        host_kw = ("host", "sub", "target", "live", "domain", "scope", "url")
        word_kw = ("word", "list", "dirb", "common", "dict", "raft", "seclist", "fuzz")
        is_host = pf in HOST_FLAGS or any(k in base for k in host_kw)
        is_word = pf in WORD_FLAGS or any(k in base for k in word_kw)
        # host classification wins ties only when a host flag is explicit
        if pf in HOST_FLAGS:
            is_word = False
        if pf in WORD_FLAGS:
            is_host = False
        if is_host and not is_word:
            return self._canonical_hosts_file()
        if is_word and not is_host:
            return self._canonical_wordlist()
        # ambiguous → prefer hosts (most common missing-input case in recon)
        if is_host:
            return self._canonical_hosts_file()
        return None

    def _fix_glued_path_flags(self, command: str) -> str:
        """Handle `--flag=<path>` / `-flag=<path>` forms (e.g. whatweb
        `--input-file=hosts.txt`). These are a single shlex token starting with
        '-', so the path detector below skips them — handle the glued value here.
        Missing input files are redirected to a canonical resource universally."""
        _EXTS = (".txt", ".lst", ".list", ".wordlist", ".json", ".csv", ".conf")

        def _repl(m):
            flag, val = m.group(1), m.group(2)
            if "://" in val or "{" in val or "FUZZ" in val:
                return m.group(0)
            if not (val.startswith("/") or val.startswith("~")
                    or any(val.endswith(e) for e in _EXTS)):
                return m.group(0)
            try:
                ec, _, _ = self.remote.execute(f'test -e "{val}"', timeout=5)
            except Exception:
                return m.group(0)
            if ec == 0:
                return m.group(0)  # file exists — leave it
            canonical = self._canonical_substitute(val, flag.rstrip("="))
            if canonical:
                log.info(
                    f"[UNIVERSAL INPUT REPAIR] Missing input '{val}' "
                    f"(via '{flag}') → canonical '{canonical}'")
                return flag + canonical
            return m.group(0)

        try:
            return re.sub(r'(-{1,2}[\w-]+=)(\S+)', _repl, command)
        except Exception:
            return command

    def _validate_and_fix_command(self, command: str, tool_name: str) -> str:
        """Dynamic validation and auto-correction of file paths in commands."""
        if not self.remote:
            return command

        # 1. Proactive flag validation
        command = self.validate_and_filter_flags(command, tool_name)
        # 1b. Universal glued-flag input-file repair (`--input-file=missing.txt`)
        command = self._fix_glued_path_flags(command)

        # 1c. Universal {WORDLIST} resolution. The literal token (and bare/quoted
        # forms) can slip past the agent-level substitution because commands also
        # come from the grounding / repair / make-lighter paths. Resolve it HERE,
        # which every command passes through, so a fuzzing tool never receives a
        # literal '{WORDLIST}' and dies on a missing file.
        if "{WORDLIST}" in command:
            _wl = self._canonical_wordlist()
            if _wl:
                command = command.replace("{WORDLIST}", _wl)

        # 1d. A -w/--wordlist value that does NOT exist (a placeholder like
        # '/path/to/wordlist', or a standard list that isn't installed) →
        # canonical wordlist. This catches values the generic path-detector
        # below skips (no extension / not a system dir) — the single biggest
        # cause of ffuf/gobuster failures.
        def _fix_wordlist_arg(m):
            flag, val = m.group(1), m.group(2)
            if "{" in val or "://" in val or "FUZZ" in val:
                return m.group(0)
            try:
                ec, _, _ = self.remote.execute(f'test -e "{val}"', timeout=5)
            except Exception:
                return m.group(0)
            if ec == 0:
                return m.group(0)  # exists — leave it
            wl = self._canonical_wordlist()
            if wl:
                log.info(f"[WORDLIST] missing '{val}' → canonical '{wl}'")
                return f"{flag}{wl}"
            return m.group(0)
        try:
            command = re.sub(
                r'(-w[= ]|--wordlist[= ])([^\s]+)', _fix_wordlist_arg, command)
        except Exception:
            pass

        import shlex
        try:
            parts = shlex.split(command)
        except ValueError as e:
            # Unbalanced quotes etc. — a malformed (usually AI-repaired)
            # command. This is expected and handled by the repair loop, so log
            # it quietly rather than dumping a full traceback that looks like a
            # crash. Fall back to a naive split so path-fixing can still run.
            log.debug(
                f"shlex could not parse command for {tool_name} "
                f"({e}); using naive split.")
            parts = command.split()

        def is_likely_file_path(part: str) -> bool:
            if not part:
                return False
            # Ignore options/flags and URLs
            if part.startswith(
                    "-") or part.startswith("http://") or part.startswith("https://"):
                return False
            # Ignore strings containing characters that indicate query params,
            # templates, or options
            if any(c in part for c in [
                   "?", "&", "=", "^", ":", "{", "}", "FUZZ"]):
                return False

            # If it starts with / but has only 1 slash and no extension, it's
            # likely a URL route
            if part.startswith("/") and part.count("/") == 1:
                if not any(part.endswith(ext) for ext in [
                           ".txt", ".lst", ".wordlist", ".git", ".db", ".conf", ".json", ".py", ".sh"]):
                    return False

            # Check if it starts with / or ~
            if part.startswith("/") or part.startswith("~"):
                # Only check paths starting with common linux system dirs, user
                # homes, or having typical extensions
                common_dirs = [
                    "/usr",
                    "/opt",
                    "/tmp",
                    "/root",
                    "/var",
                    "/etc",
                    "/home",
                    "/bin",
                    "/sbin",
                    "/lib",
                    "/mnt",
                    "/dev",
                    "~/"]
                if not any(part.startswith(d) for d in common_dirs):
                    if not any(part.endswith(ext) for ext in [
                               ".txt", ".lst", ".wordlist", ".git", ".db", ".conf", ".json", ".py", ".sh"]):
                        return False
                return True

            # If it doesn't start with / or ~ but has a file extension
            if any(part.endswith(ext) for ext in [
                   ".txt", ".lst", ".wordlist", ".git", ".db", ".conf", ".json", ".py", ".sh"]):
                return True

            return False

        fixed_parts = []
        for _idx, part in enumerate(parts):
            if not is_likely_file_path(part):
                fixed_parts.append(part)
                continue
            _preceding_flag = parts[_idx - 1] if _idx > 0 else ""
            # OUTPUT destinations (-o/-oN/-oX/-oG/-oA/--output/...) do NOT exist
            # yet by design. Treating them like a missing INPUT file ran the
            # existence check and then a full-filesystem `find` (30s timeout) on
            # EVERY command that writes to a fresh output file — pure wasted time
            # that never helped (the file legitimately isn't there yet) and could
            # even substitute a canonical input over the output path. Skip them.
            # Universal output-flag convention, not per-tool logic.
            _OUTPUT_FLAGS = {"-o", "-on", "-ox", "-og", "-oa", "-oj", "-os",
                             "--output", "--output-dir", "--out", "-of"}
            if (_preceding_flag or "").lower() in _OUTPUT_FLAGS:
                fixed_parts.append(part)
                continue
            # Replace ~ with the actual absolute home directory to avoid issues
            # with shlex.join quoting $HOME
            if part.startswith("~"):
                if not hasattr(self, "_remote_home_dir"):
                    ec, out, _ = self.remote.execute("echo $HOME", timeout=5)
                    self._remote_home_dir = out.strip() if ec == 0 else "/root"
                test_path = part.replace("~", self._remote_home_dir, 1)
            else:
                test_path = part
            # Do not attempt to fix paths that look like output locations (in
            # results dir) — UNLESS this path is the value of a known INPUT flag
            # (then it MUST exist, even if the AI dropped it in a results/ path,
            # e.g. the hallucinated `…/results/live_subdomains.txt` for `-iL`).
            _INPUT_FLAGS = {
                "-il", "-l", "-list", "--input-file", "-w", "--wordlist", "-d"}
            _is_input_arg = (_preceding_flag or "").lower() in _INPUT_FLAGS
            if "results/" in test_path and not _is_input_arg:
                fixed_parts.append(test_path)
                continue

            # Test if path exists remotely (use double quotes to allow $HOME
            # expansion)
            exit_code, _, _ = self.remote.execute(
                f'test -e "{test_path}"', timeout=5)
            if exit_code != 0:
                basename = part.split('/')[-1]
                # If basename is extremely common or empty, it's risky to
                # auto-resolve
                if not basename or basename in [
                        "home", "tmp", "var", "etc", "usr"]:
                    fixed_parts.append(test_path)
                    continue

                # Path is broken. Try to find the real file dynamically.
                # Added `-type f` to avoid matching directories as files, but
                # if original path ends in / we shouldn't replace it with a
                # file
                if part.endswith('/'):
                    fixed_parts.append(test_path)
                    continue

                find_cmd = f"find / -not -path '*/\\.*' -not -path '/proc/*' -not -path '/sys/*' -not -path '/snap/*' -name '{basename}' -type f 2>/dev/null | head -n 1"
                f_exit, stdout, stderr = self.remote.execute(
                    find_cmd, timeout=30)
                real_path = stdout.strip()
                if f_exit == 0 and real_path:
                    log.info(
                        f"Dynamic Path Resolver: Fixed broken path '{part}' -> '{real_path}'")
                    fixed_parts.append(real_path)
                else:
                    # UNIVERSAL recovery: the file exists NOWHERE (a hallucinated
                    # input like `live_subdomains.txt`). `find` can't help. Before
                    # letting the tool fail on a missing file, substitute a
                    # canonical resource we actually materialized (host list or
                    # wordlist), classified from the preceding flag / filename.
                    # Works for ANY tool — no per-tool logic.
                    canonical = self._canonical_substitute(part, _preceding_flag)
                    if canonical:
                        log.info(
                            f"[UNIVERSAL INPUT REPAIR] Missing input '{part}' "
                            f"(via '{_preceding_flag}') → canonical '{canonical}'")
                        fixed_parts.append(canonical)
                    else:
                        fixed_parts.append(test_path)
            else:
                fixed_parts.append(test_path)

        try:
            return shlex.join(fixed_parts)
        except AttributeError:
            # Fallback for Python < 3.8
            return " ".join([f"'{p}'" if " " in p else p for p in fixed_parts])

    def run(self, tool_name: str, command: str, phase: str,
            timeout: int = None, save_raw: bool = True,
            output_path: str | Path = None, silent: bool = False) -> ToolResult:
        """Primary method to run any tool with full visibility."""
        tool_name = tool_name.lower()
        from tools.tool_registry import TOOL_TIMEOUTS
        start = time.time()
        timeout = timeout or TOOL_TIMEOUTS.get(tool_name, TOOL_DEFAULT_TIMEOUT)

        if get_config().vps.use_remote_vps:
            remote_raw_dir = self.vps_path(self.session.results_dir / "raw")
            self.remote.remote_mkdir(remote_raw_dir)

        # Try primary tool first
        original_tool = tool_name
        if not self.ensure_installed(tool_name):
            # Try fallback tool before failing
            fallback = self.get_fallback_tool(tool_name)
            if fallback:
                log.info(
                    f"Primary tool '{tool_name}' unavailable. Using fallback '{fallback}'.")
                tool_name = fallback  # Use fallback for actual execution
                # Translate command to use fallback tool syntax (if needed)
                command = self._translate_command_for_fallback(
                    original_tool, fallback, command)
            else:
                duration = time.time() - start
                result = ToolResult(
                    tool=original_tool, command=command, stdout="", stderr="",
                    exit_code=-1, duration_seconds=duration, status=ResultStatus.BLOCKED
                )
                self._log_result(result, phase)
                return result

        # Determine retry count based on tool type
        retry_count = 1 if tool_name in FAST_TOOLS else TOOL_RETRY_COUNT

        command = self._validate_and_fix_command(command, tool_name)

        result = None
        evasion_level = 1

        for attempt in range(retry_count):
            if attempt > 0:
                delay = min(2 ** (attempt - 1), 10)
                log.info(
                    f"Retrying '{tool_name}' (attempt {
                        attempt + 1}/{retry_count})... waiting {delay}s")
                time.sleep(delay)

                # If the last failure was a WAF block, apply WafGhostEngine
                # evasion
                if result and result.status == "waf_blocked":
                    evasion_level += 1
                    log.warning(
                        f"WAF Block evasion escalated to Level {evasion_level} for {tool_name}")
                    try:
                        from core.waf_ghost_engine import WafGhostEngine
                        ghost = WafGhostEngine(remote_executor=self.remote)
                        # force=True: a real WAF block just occurred, so evasion
                        # is warranted even though this fresh engine has no
                        # accumulated block-rate feedback.
                        command = ghost.transform(
                            command, tool_name, level=evasion_level, force=True)
                    except Exception as e:
                        log.error(f"Failed to apply WafGhostEngine: {e}")

            result = self._execute(tool_name, command, timeout, silent=silent)

            # RC-2 FIX: Masscan raw-socket permission error recovery.
            # masscan requires CAP_NET_RAW for -sS (raw SYN). The sudo-stripping logic
            # in _execute() removes sudo before WSL execution, so prepending sudo doesn't
            # help. Instead, apply setcap to grant the capability permanently,
            # then retry.
            if tool_name == "masscan" and not result.success and attempt < retry_count - 1:
                combined_perm = (result.stdout + result.stderr).lower()
                if "permission denied" in combined_perm or "if:eth0:init: failed" in combined_perm:
                    log.warning(
                        "[RC-2] Masscan permission denied (raw socket). Attempting setcap fix...")
                    if self.remote:
                        masscan_bin_ec, masscan_bin_out, _ = self.remote.execute(
                            "which masscan 2>/dev/null", timeout=5
                        )
                        masscan_bin = masscan_bin_out.strip() if masscan_bin_ec == 0 else "/usr/bin/masscan"
                        # Try setcap — grants raw-socket capability without
                        # needing sudo at runtime
                        setcap_ec, _, setcap_err = self.remote.execute(
                            f"setcap cap_net_raw+eip {masscan_bin} 2>&1 || "
                            f"sudo setcap cap_net_raw+eip {masscan_bin} 2>&1",
                            timeout=10
                        )
                        if setcap_ec == 0:
                            log.info(
                                f"[RC-2] setcap applied to {masscan_bin}. Retrying masscan without sudo...")
                            # Remove any sudo prefix from command since setcap
                            # makes it unnecessary
                            command = re.sub(r'^sudo\s+', '', command.strip())
                        else:
                            log.warning(
                                f"[RC-2] setcap failed ({setcap_err[:100]}). Falling back to nmap -sT (no raw socket required).")
                            # Translate masscan command to unprivileged nmap
                            # -sT
                            port_match = re.search(
                                r'-p\s*([0-9,\-]+)', command)
                            host_match = re.search(
                                r'(?:masscan\s+)(\S+)', command)
                            port_range = port_match.group(
                                1) if port_match else "1-1000"
                            scan_host = host_match.group(
                                1) if host_match else ""
                            if scan_host and not scan_host.startswith("-"):
                                host_to_m = max(1, min(int(timeout / 4 / 60) if timeout else 5, 10))
                                command = f"nmap -sT -T4 -p {port_range} --open {scan_host} --host-timeout {host_to_m}m -n"
                                tool_name = "nmap"
                                log.info(
                                    f"[RC-2] Switched to nmap fallback: {command}")
                    continue  # Force a retry with fixed command

            # nmap raw-socket recovery: -sS/-sU/-sA/-O and --privileged need
            # CAP_NET_RAW / root, which an unprivileged WSL shell does not have
            # ("Couldn't open a raw socket. Operation not permitted" /
            # "dnet: failed to open device"). nmap PRINTS its banner then QUITS,
            # so it can even be mis-scored as success. Detect the raw-socket
            # error regardless of status and fall back to -sT (TCP connect scan,
            # no privileges required) for the retry.
            if tool_name == "nmap" and attempt < retry_count - 1:
                _np = (result.stdout + result.stderr).lower()
                if ("couldn't open a raw socket" in _np
                        or "operation not permitted" in _np
                        or "failed to open device" in _np
                        or "requires root privileges" in _np
                        or "quitting" in _np):
                    _new_cmd = re.sub(r'-s[SUAFNX]\b', '-sT', command)
                    _new_cmd = re.sub(r'\s--privileged\b', ' --unprivileged', _new_cmd)
                    _new_cmd = re.sub(r'\s-O\b', '', _new_cmd)   # OS detection needs root
                    if '-sT' not in _new_cmd and '-sn' not in _new_cmd:
                        _new_cmd = _new_cmd.replace('nmap ', 'nmap -sT ', 1)
                    if _new_cmd != command:
                        log.warning(
                            "[NMAP] Raw-socket scan needs root (unavailable in WSL). "
                            f"Falling back to TCP connect scan: {_new_cmd[:90]}")
                        command = _new_cmd
                        result.status = ResultStatus.FAILURE  # don't let the QUITTING banner score as success
                        continue

            # WAF Block Detection (403/429/CAPTCHA) - MUST happen inside loop
            # for evasion to trigger
            _WAF_EXEMPT_TOOLS = {
                "nmap",
                "sslscan",
                "masscan",
                "dig",
                "naabu",
                "subfinder"}
            if result.success and tool_name not in _WAF_EXEMPT_TOOLS:
                combined = (result.stdout + result.stderr).lower()
                waf_markers = [
                    "403 forbidden", "429 too many requests", "cloudflare ray id",
                    "please verify you are human", "access denied", "waf block",
                    "security challenge", "attention required! | cloudflare",
                    "error 1020"
                ]
                if any(marker in combined for marker in waf_markers):
                    if tool_name == "whatweb" and any(u in combined for u in [
                                                      "httpserver[", "title[", "ip["]):
                        log.info(
                            "whatweb got WAF response but extracted useful tech fingerprint. Keeping as partial_success.")
                        result.status = "partial_success"
                    elif tool_name == "curl" and "-sI" in command:
                        log.info(
                            "curl header probe received WAF response. Keeping as success to parse headers.")
                        result.status = ResultStatus.SUCCESS
                    else:
                        log.warning(
                            f"WAF Block Detected for {tool_name}. Escaping to failed state.")
                        result.success = False
                        result.status = "waf_blocked"
                        result.exit_code = 1

            # Handle silent failures for curl/dig/nuclei: try with more verbose
            # output
            if not result.success and not result.stdout.strip() and not result.stderr.strip():
                if attempt < retry_count - 1:
                    log.warning(
                        f"'{tool_name}' failed silently. Adjusting for retry...")
                    if tool_name == "dig":
                        command = command.replace(
                            "+short", "") + " +noall +answer"
                    elif tool_name == "curl":
                        command = command.replace(
                            "-s", "").replace("--silent", "")
                        if "--verbose" not in command and "-v" not in command:
                            command += " --verbose"
                    elif tool_name == "nuclei":
                        if "-v" not in command and "-debug" not in command:
                            command += " -v"

            # Syntax / Invalid Flag Error Detection & Auto-Correction
            combined = (result.stdout + result.stderr).lower()
            syntax_errors = [
                "usage:", "syntax error", "unrecognized argument", "invalid option",
                "unrecognized option", "only 1 -p option allowed", "quitting!",
                "not recognized", "command not found", "invalid parameter", "invalid command",
                "unknown flag", "flag provided but not defined", "incorrect usage:"
            ]
            is_successful_gobuster = tool_name == "gobuster" and "found: " in result.stdout.lower()
            # A tool that exits 0 AND printed substantial real results is a
            # SUCCESS even if its output happens to contain a marker substring
            # (e.g. whatweb prints its fingerprint to stdout while a benign
            # "Unknown option" warning lands in stderr; nmap/nikto banners can
            # contain "usage"). Only override to FAILED when the output is
            # genuinely just a usage/error dump — otherwise we throw away good
            # data and burn the whole repair/token budget chasing a phantom
            # failure. See _produced_real_output().
            if not is_successful_gobuster and any(
                    err in combined for err in syntax_errors):
                if result.success and not _produced_real_output(result.stdout):
                    log.warning(
                        f"Tool {tool_name} exited 0 but emitted syntax error. Overriding to FAILED.")
                    result.success = False
                    result.status = ResultStatus.FAILURE
                    result.exit_code = 1
                elif result.success:
                    log.debug(
                        f"Tool {tool_name} output contains an error-marker substring but also "
                        f"substantial real output — trusting the exit-0 success.")

                # Dynamic correction moved to proactive `validate_and_filter_flags` step
                # before the execution loop. If syntax error still occurs, we
                # leave it to AI repair.

            # UNIVERSAL no-retry guard: some failures are DETERMINISTIC — an
            # identical retry will produce the identical failure, so retrying
            # just burns wall-clock (the nmap-on-a-non-resolving-host case wasted
            # 5s+25s+25s). Break immediately on these for ANY tool. (Missing
            # input files are already repaired before execution; this also backs
            # that up.)
            _det = (result.stdout + result.stderr).lower()
            _DETERMINISTIC_FAIL = (
                "failed to resolve", "could not resolve", "name or service not known",
                "no targets were specified", "name does not resolve", "unable to resolve",
                "no such host", "no such file or directory", "cannot find the file",
                "invalid target", "no route to host",
                # Transport-level: the target PORT cannot be reached (closed /
                # filtered). No flag change opens a closed port — e.g. SSH brute
                # force against a Vercel/CDN IP that has no port 22.
                "could not connect", "timeout connecting", "connection timed out",
                "connection refused", "network is unreachable", "host is down",
            )
            if not result.success and any(m in _det for m in _DETERMINISTIC_FAIL):
                _why = next(m for m in _DETERMINISTIC_FAIL if m in _det)
                log.info(
                    f"[NO-RETRY] {tool_name}: deterministic failure ('{_why}') — "
                    "an identical retry cannot change this, moving on.")
                break

            if result.success or result.status in {
                    "timeout", "blocked", "scope_blocked", "not_installed", "partial_success", "partial"}:
                break

        # Universal False-Success Detection
        # Some tools exit 0 while the transport layer or target clearly failed.
        # Only apply this to tools where a fatal transport error means the run
        # did not complete usefully.
        if result.success and tool_name != "grep":
            combined = (result.stdout + result.stderr).lower()

            # Smart exception: if gobuster found paths/subdomains despite some network errors, don't fail it
            # BUG-07: Gobuster writes "Found: " with capital F - must use
            # case-insensitive check
            is_successful_gobuster = tool_name == "gobuster" and "found: " in result.stdout.lower()

            # Transport failures mean the run produced nothing useful no matter
            # what — always honour them.
            transport_errors = [
                "unable to connect", "error on running gobuster",
                "connection refused", "network is unreachable",
                "the server returns a status code that matches",
                "fatal exception:",
            ]
            # Syntax/usage markers only mean failure when the tool produced no
            # real output (see block above) — otherwise the marker is incidental.
            syntax_markers = [
                "usage:", "syntax error", "unrecognized argument", "invalid option",
                "unrecognized option", "only 1 -p option allowed", "quitting!",
                "not recognized", "command not found",
                "too many arguments", "invalid parameter", "invalid command",
            ]
            _transport_failed = any(err in combined for err in transport_errors)
            _syntax_failed = (
                any(err in combined for err in syntax_markers)
                and not _produced_real_output(result.stdout)
            )
            if not is_successful_gobuster and (_transport_failed or _syntax_failed):
                log.warning(
                    f"Tool {tool_name} exited 0 but emitted network/wildcard/syntax error. Overriding to FAILED.")
                result.success = False
                result.status = ResultStatus.FAILURE
                result.exit_code = 1

        if result.status == "success" and not result.stdout.strip() and result.stderr.strip(
        ) and tool_name in {"curl", "wget", "gobuster", "ffuf", "nikto", "nuclei", "whatweb"}:
            # Strip "errors: 0" from ffuf progress bar to prevent false
            # positive failure triggers
            combined = result.stderr.lower().replace("errors: 0", "")
            if any(marker in combined for marker in (
                    "error", "tls", "unable to connect", "connection refused", "timeout", "empty reply")):
                result.success = False
                result.status = ResultStatus.FAILURE
                result.exit_code = 1

        # Console output for VPS / WSL
        if self.remote and not silent:
            # For STREAMING_TOOLS: the live feed already printed all stdout.
            # Only show a compact status header + stderr (if any) to avoid
            # duplication.
            if tool_name in STREAMING_TOOLS:
                if result.status not in ("success",):
                    # Always show non-success outcomes with full output for
                    # debugging
                    self._print_vps_console(command, result.status, result.duration,
                                            result.stdout, result.stderr)
                else:
                    # Success + streaming: already shown live - just print
                    # compact footer
                    from rich.console import Console
                    from rich.text import Text
                    console = Console()
                    footer = Text()
                    footer.append("    [ CMD ] ", style="bold cyan")
                    footer.append(
                        f"{command[:120]}{'...' if len(command) > 120 else ''}\n", style="dim white")
                    footer.append("    [ STS ] ", style="bold cyan")
                    footer.append(
                        f"SUCCESS ({
                            result.duration:.1f}s)\n",
                        style="bold bright_green")
                    if result.stderr.strip():
                        footer.append(
                            "\n[!] STDERR:\n", style="bold bright_red")
                        footer.append(
                            result.stderr.strip()[
                                :500], style="bright_red")
                    from rich.panel import Panel
                    label = "VPS TOOL COMPLETE" if get_config(
                    ).vps.use_remote_vps else "WSL TOOL COMPLETE"
                    console.print(Panel(footer, title=f"[bold bright_green]▰▰▰ {label} ▰▰▰[/]",
                                        border_style="bright_green", padding=(0, 2)))
            elif result.status in ("failed", "timeout", "not_installed", "waf_blocked", "success",
                                   "fallback", "fallback_success", "tls_blocked", "captcha_blocked"):
                self._print_vps_console(command, result.status, result.duration,
                                        result.stdout, result.stderr)
            else:
                # Surface WHY it failed — a bare "[FAILURE] httpx done in 5.2s"
                # hides the actual error (bad flag vs missing input file vs
                # connection refused vs empty output), which makes a repair loop
                # spin blindly. Show the stderr/stdout tail + exit code.
                _reason = (result.stderr or "").strip() or (result.stdout or "").strip()
                _reason = _reason.replace("\n", " ")[:240]
                _ec = getattr(result, "exit_code", "?")
                if _reason:
                    log.info(
                        f"[{result.status.upper()}] {tool_name} done in {result.duration:.1f}s "
                        f"(exit={_ec}): {_reason}")
                else:
                    log.info(
                        f"[{result.status.upper()}] {tool_name} done in {result.duration:.1f}s "
                        f"(exit={_ec}, NO OUTPUT — tool ran but returned nothing)")

        # Save raw output
        if save_raw and result.stdout:
            raw_path = self.session.results_dir / "raw" / \
                f"{phase}_{tool_name}_{int(start)}.txt"
            clean_stdout = clean_text(result.stdout)
            raw_path.write_text(
                clean_stdout,
                encoding="utf-8",
                errors="replace")
            result.stdout = clean_stdout

        # Parse output
        result.parsed = self.parser.parse(
            tool_name, result.stdout, result.stderr)

        # Automated Readback for VPS file output
        # For tools that write to -o file (nuclei, nmap, nikto), ALWAYS prefer
        # the file content over stdout - stdout is polluted with banners/stats/progress
        # that the parser will misinterpret. The file is the authoritative
        # output.
        FILE_OUTPUT_TOOLS = {"nuclei", "nmap", "nikto", "masscan", "gobuster"}
        if get_config().vps.use_remote_vps and output_path:
            vps_out = self.vps_path(output_path)
            log.debug(f"Reading back VPS file: {vps_out}")
            exit_code, content, _ = self.remote.execute(f'cat "{vps_out}"')
            if exit_code == 0 and content.strip():
                # Always use file for file-output tools; for others only if
                # file is longer
                if tool_name in FILE_OUTPUT_TOOLS or not result.stdout.strip() or len(
                        content) > len(result.stdout):
                    result.stdout = content
                    result.parsed = self.parser.parse(
                        tool_name, result.stdout, result.stderr)
                    # If file output is meaningful, don't classify as hard
                    # failure.
                    if result.status == "failed" and tool_name in FILE_OUTPUT_TOOLS:
                        parsed = result.parsed if isinstance(
                            result.parsed, dict) else {}
                        has_structured_data = any([
                            bool(parsed.get("findings")),
                            bool(parsed.get("open_ports")),
                            bool(parsed.get("discovered_paths")),
                            bool(parsed.get("services")),
                            int(parsed.get("count", 0)) > 0,
                        ])
                        if has_structured_data or len(content.strip()) > 120:
                            result.status = "fallback_success"
                try:
                    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
                    Path(output_path).write_text(
                        content, encoding="utf-8", errors="replace")
                except Exception as e:
                    log.error(f"Failed to write synced file: {e}")

        self._log_result(result, phase)
        return result

    def _execute(self, tool_name: str, command: str, timeout: int,
                 silent: bool = False) -> ToolResult:
        start = time.time()

        # Handle virtual AI tools with Guardian validation
        if tool_name in VIRTUAL_AI_TOOLS:
            from utils.guardian import block_or_repair
            repaired_cmd, decision = block_or_repair(
                command, self.session.target)

            if not repaired_cmd:
                log.warning(f"Guardian BLOCKED: {decision}")
                duration = time.time() - start
                return ToolResult(
                    tool=tool_name, command=command,
                    stdout="", stderr=f"Guardian blocked: {decision}",
                    exit_code=126, duration_seconds=duration, status=ResultStatus.BLOCKED
                )

            command = repaired_cmd
            log.info(f"Guardian approved: {decision} - {command[:80]}")
            # Continue to normal execution with repaired command

        if self.remote:
            node_label = "VPS" if get_config().vps.use_remote_vps else "WSL"

            # Detect and handle sudo commands safely by running them natively
            # as root
            as_root = False
            if command.strip().startswith("sudo"):
                try:
                    parts = shlex.split(command)
                    if parts and parts[0] == "sudo":
                        as_root = True
                        parts_to_keep = parts[1:]
                        # Strip sudo flags: -n, -S, -E, -H, -P, -v, -k, etc.
                        # and options like -u user, -g group, -p prompt
                        while parts_to_keep and parts_to_keep[0].startswith(
                                "-"):
                            flag = parts_to_keep[0]
                            if flag in ("-u", "-g", "-p", "-C",
                                        "-D", "-R", "-T"):
                                parts_to_keep = parts_to_keep[2:]
                            else:
                                parts_to_keep = parts_to_keep[1:]
                        command = shlex.join(parts_to_keep)
                except Exception as e:
                    import logging as __logging_tmp
                    __logging_tmp.getLogger(__name__).error(
                        f"Unhandled exception: {e}", exc_info=True)
                    as_root = True
                    command = re.sub(
                        r'^sudo\s*(?:-[a-zA-Z0-9_-]+\s*)*', '', command)

            use_streaming = tool_name in STREAMING_TOOLS
            if use_streaming:
                from rich.console import Console
                console = Console()
                if not silent:
                    label = "WSL LIVE FEED" if not get_config().vps.use_remote_vps else "VPS LIVE FEED"
                    console.print(
                        f"\n[bold bright_magenta]▰▰▰ {label} ›[/bold bright_magenta] [dim]{command[:180]}[/dim]")
                printed_lines = []

                MAX_LIVE_LINES = 500
                seen_live_lines = set()  # Dedup guard for live feed output

                def on_line(line: str) -> None:
                    if silent or len(printed_lines) >= MAX_LIVE_LINES:
                        return
                    clean = clean_text(line)
                    if clean:
                        # Dedup: skip exact duplicate lines in live feed
                        if clean in seen_live_lines:
                            return
                        seen_live_lines.add(clean)
                        ll = clean.lower()
                        # Smart filtering: only print meaningful lines
                        if any(kw in ll for kw in [
                            "found:", "open", "discovered", "/tcp", "/udp",
                            "[info]", "[warn]", "error", "vuln",
                            "running", "starting", "scanning", "done",
                            "rate:", "harvester", "emails", "hosts", "ips",
                            "status:", "size:", "-->", "[+]"
                        ]):
                            printed_lines.append(clean)
                            console.print(f"  [dim]{clean}[/dim]")
                            if len(printed_lines) == MAX_LIVE_LINES:
                                console.print(
                                    f"  [bold yellow]! Live feed capped at {MAX_LIVE_LINES} lines (full output saved to {node_label} results)[/bold yellow]")

                # Use the new resilient tailing mode for long-running tools
                exit_code, stdout, stderr = self.remote.execute_resilient(
                    command, timeout=timeout, on_line=on_line, as_root=as_root
                )
                if not silent and printed_lines:
                    console.print(
                        f"  [bold cyan]► {tool_name}: {
                            len(printed_lines)} total lines captured[/bold cyan]")
            else:
                exit_code, stdout, stderr = self.remote.execute(
                    command, timeout=timeout, as_root=as_root)

            duration = time.time() - start
            fatal_error_markers = (
                "unable to connect",
                "error on running gobuster",
                "tls: internal error",
                "tlsv1 alert internal error",
                "connection refused",
                "network is unreachable",
                "host maximum execution time",
                "empty reply from server",
                "\": eof\"",
            )
            combined_output = f"{stdout}\n{stderr}".lower()
            has_fatal_error = any(
                marker in combined_output for marker in fatal_error_markers)

            if exit_code == -2 or exit_code == 124:
                status = ResultStatus.TIMEOUT
            elif exit_code == 0 or has_fatal_error:
                # A fatal-error MARKER (e.g. "connection refused", "empty reply")
                # means "blocked/failed" for a SINGLE-request tool (curl/wget/
                # sslscan/whatweb) — one request, it didn't get through. But a
                # multi-request SCANNER (gobuster/ffuf/nikto/nuclei) routinely
                # prints such a line for SOME of its many sub-requests while the
                # scan as a whole succeeds (exit 0) with real findings. Marking
                # that whole run BLOCKED discarded the findings and fired need-
                # less evasion. So a scanner only counts as blocked-by-marker if
                # it ALSO exited non-zero (the scan itself failed). Genuine full
                # blocks of an exit-0 scanner are caught by the baseline-
                # differential WAF check and the AI outcome triage downstream.
                _single_req_block_tools = {"curl", "wget", "sslscan", "whatweb"}
                _scanner_tools = {"gobuster", "ffuf", "nikto", "nuclei"}
                if has_fatal_error and (
                        tool_name in _single_req_block_tools
                        or (tool_name in _scanner_tools and exit_code != 0)):
                    status = ResultStatus.BLOCKED
                    exit_code = 1
                elif exit_code == 0:
                    empty_markers = (
                        "0 items checked",
                        "[inf] no results found",
                        "0 hosts up",
                        "no subdomains found")
                    if (not stdout.strip() and not stderr.strip()) or any(
                            m in combined_output for m in empty_markers):
                        status = ResultStatus.NO_FINDINGS
                    else:
                        status = ResultStatus.SUCCESS
                else:
                    status = ResultStatus.FAILURE
            else:
                # Some tools exit non-zero but produce valid output (e.g. nmap
                # on filtered ports)
                known_partial_success = {
                    "nmap", "masscan", "nikto", "nuclei", "gobuster", "ffuf"}
                if tool_name in known_partial_success and stdout and len(
                        stdout.strip()) > 50 and not has_fatal_error:
                    status = ResultStatus.SUCCESS
                else:
                    status = ResultStatus.FAILURE

            return ToolResult(
                tool=tool_name, command=command,
                stdout=stdout, stderr=stderr,
                exit_code=exit_code, duration_seconds=duration, status=status
            )

        # Local execution path
        process = None
        try:
            # shlex is imported at module level - do NOT re-import
            # Split the command string into a list for safe execution without a shell
            # This prevents command injection vulnerabilities from unsanitized
            # input
            args = shlex.split(command)
            process = subprocess.Popen(
                args, shell=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace",
                preexec_fn=getattr(os, "setsid", None)
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                duration = time.time() - start
                fatal_error_markers = (
                    "unable to connect",
                    "error on running gobuster",
                    "tls: internal error",
                    "tlsv1 alert internal error",
                    "connection refused",
                    "network is unreachable",
                    "host maximum execution time",
                    "certificate verify failed",
                    "empty reply from server",
                    "\": eof",
                )
                combined_output = f"{stdout}\n{stderr}".lower()
                has_fatal_error = any(
                    marker in combined_output for marker in fatal_error_markers)

                exit_code = process.returncode
                if exit_code == 124:
                    status = ResultStatus.TIMEOUT
                elif exit_code == 0 or has_fatal_error:
                    # Same single-request-vs-scanner distinction as the remote
                    # path: a scanner that completed (exit 0) is NOT "blocked"
                    # just because one of its many sub-requests errored, and a
                    # non-zero exit WITH a fatal error is a FAILURE (the old
                    # `else: SUCCESS` here wrongly marked such runs successful).
                    _single_req_block_tools = {"curl", "wget", "sslscan", "whatweb"}
                    _scanner_tools = {"gobuster", "ffuf", "nikto", "nuclei"}
                    if has_fatal_error and (
                            tool_name in _single_req_block_tools
                            or (tool_name in _scanner_tools and exit_code != 0)):
                        status = ResultStatus.BLOCKED
                        exit_code = 1
                    elif exit_code == 0:
                        status = ResultStatus.SUCCESS
                    else:
                        status = ResultStatus.FAILURE
                else:
                    known_partial_success = {
                        "nmap", "masscan", "nikto", "nuclei", "gobuster", "ffuf"}
                    if tool_name in known_partial_success and stdout and len(
                            stdout.strip()) > 50 and not has_fatal_error:
                        status = ResultStatus.SUCCESS
                    else:
                        status = ResultStatus.FAILURE

                return ToolResult(
                    tool=tool_name, command=command,
                    stdout=stdout, stderr=stderr,
                    exit_code=exit_code, duration_seconds=duration, status=status
                )
            except subprocess.TimeoutExpired:
                try:
                    if hasattr(os, "killpg"):
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                        time.sleep(1)
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    else:
                        process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except Exception as e:
                    import logging as __logging_tmp
                    __logging_tmp.getLogger(__name__).error(
                        f"Unhandled exception: {e}", exc_info=True)
                    stdout, stderr = "", ""
                duration = time.time() - start
                return ToolResult(
                    tool=tool_name, command=command,
                    stdout=stdout, stderr=stderr,
                    exit_code=-1, duration_seconds=duration, status=ResultStatus.TIMEOUT
                )
        except FileNotFoundError:
            duration = time.time() - start
            return ToolResult(
                tool=tool_name, command=command,
                stdout="", stderr=f"Binary not found: {tool_name}",
                exit_code=-1, duration_seconds=duration, status=ResultStatus.BLOCKED
            )
        except KeyboardInterrupt:
            raise
        except Exception as e:
            duration = time.time() - start
            return ToolResult(
                tool=tool_name, command=command,
                stdout="", stderr=str(e),
                exit_code=-1, duration_seconds=duration, status=ResultStatus.FAILURE
            )

    def _log_result(self, result: ToolResult, phase: str) -> None:
        self.store.log_tool_run(
            engagement_id=self.session.engagement_id,
            phase=phase,
            tool=result.tool,
            command=result.command,
            status=result.status.value if hasattr(
                result.status, "value") else str(
                result.status),
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            duration=result.duration
        )
