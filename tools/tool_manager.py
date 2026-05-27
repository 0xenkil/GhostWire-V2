import subprocess
import shutil
import time
import os
import signal
import json
import re
import shlex
from pathlib import Path
from typing import TYPE_CHECKING
from tools.tool_registry import TOOL_REGISTRY
from tools.output_parser import OutputParser
from core.ssh_executor import SSHExecutor
from core.result_contracts import FragileParseFixer
from utils.logger import get_logger
from utils.display import warning
from utils.sanitizer import clean_text
from core.config_manager import get_config
import config_paths
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Load config
config = get_config()
TOOL_DEFAULT_TIMEOUT = config.timeout.tool_default
TOOL_RETRY_COUNT = 3  # Default retry count
USE_REMOTE_VPS = config.vps.use_remote_vps
AUTO_APPROVE_INSTALLS = False  # Default for safety


if TYPE_CHECKING:
    from core.session import EngagementSession
    from core.state_store import StateStore
    from core.ai_backend import AIBackend

log = get_logger("tool_manager")


def _agent_debug_log(location: str, message: str, data: dict, run_id: str = "run1", hypothesis_id: str = "H4") -> None:
    # Use centralized debug file from config_paths; include session/run metadata when available
    try:
        session_id = data.get("sessionId") if isinstance(data, dict) and data.get("sessionId") else run_id
        log_path = config_paths.DEBUG_LOG_FILE if hasattr(config_paths, "DEBUG_LOG_FILE") else Path("debug.log")
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
    except Exception:
        # Avoid raising from debug logging
        pass

# Tools that benefit from real-time streaming (long-running)
STREAMING_TOOLS = {"nmap", "nuclei", "gobuster", "nikto", "masscan", "ffuf",
                   "hydra", "sqlmap", "theharvester", "enum4linux"}

# Tools with fast execution - only 1 retry needed
FAST_TOOLS = {"dig", "curl", "whois", "nc"}

# Virtual tools (internal meta-tools) always 'installed'
VIRTUAL_TOOLS = {"ai_dynamic_recon", "ai_dynamic_exploit", "react_payload", "python_payload"}
VIRTUAL_AI_TOOLS = {"ai_dynamic_recon", "ai_dynamic_exploit", "react_payload", "python_payload"}

# Tool fallback mappings: if primary tool unavailable, use alternatives
TOOL_FALLBACKS = {
    "nuclei": ["nikto", "curl"],  # If nuclei missing, fall back to nikto or curl probes
    "nikto": ["gobuster", "curl"],  # If nikto missing, try gobuster or curl
    "gobuster": ["ffuf", "curl"],  # If gobuster missing, try ffuf or curl
    "ffuf": ["gobuster", "curl"],
    "nmap": ["curl"],  # If nmap missing, use curl for port probing
    "masscan": ["nmap", "curl"],
    "sqlmap": ["curl"],  # If sqlmap missing, use curl with payloads
    "theharvester": ["curl"],  # If theharvester missing, use curl for OSINT
}


class ToolResult:
    def __init__(self, tool: str, command: str, stdout: str, stderr: str,
                 exit_code: int, duration: float, status: str, parsed: dict = None) -> None:
        self.tool = tool
        self.command = command
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.duration = duration
        self.status = status
        self.parsed = parsed or {}

    @property
    def success(self) -> bool:
        """Derived from status - always consistent even after status is mutated."""
        return self.status in ("success", "fallback_success")

    @success.setter
    def success(self, value: bool) -> None:
        """Allow callers to override success (e.g. false-success detection)."""
        # When explicitly set to False, demote status if it was success
        if not value and self.status in ("success", "fallback_success"):
            self.status = "failed"
        # When explicitly set to True, promote to success (legacy compat)
        elif value and self.status not in ("success", "fallback_success"):
            self.status = "success"

    def __repr__(self):
        return f"<ToolResult tool={self.tool} status={self.status} duration={self.duration:.1f}s>"


class ToolManager:
    def __init__(self, session: "EngagementSession", state_store: "StateStore", ai_backend: "AIBackend" = None) -> None:
        self.session = session
        self.store = state_store
        self.ai = ai_backend
        self.parser = OutputParser()
        self._installed_cache: set = set()
        self._failed_cache: dict = {} # tool -> timestamp
        self.remote = None
        
        if USE_REMOTE_VPS:
            self.remote = SSHExecutor()
            if not self.remote.connect():
                import sys
                warning("FATAL: USE_REMOTE_VPS is enabled but SSH connection failed.")
                sys.exit(1)

    def vps_path(self, local_path: str | Path) -> str:
        """Translate a local path to the VPS results tree."""
        if not USE_REMOTE_VPS:
            return str(local_path)
        posix = Path(local_path).as_posix()
        if "results/" in posix:
            rel = posix.split("results/")[-1]
        else:
            rel = posix.replace(":", "").replace("\\", "/").lstrip("/")
        return f"{config_paths.VPS_RESULTS_DIR.rstrip('/')}/{rel}"

    def ensure_installed(self, tool_name: str, force_install: bool = False) -> bool:
        """Check if a tool is installed; attempt installation if not."""
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
        if not USE_REMOTE_VPS:
            if shutil.which(tool_name) or shutil.which(tool_name.lower()):
                self._installed_cache.add(tool_name)
                return True
        else:
            path_prefix = f"export PATH={config_paths.VPS_TOOL_PATH}:$PATH && "
            check_cmd = f"{path_prefix}which {tool_name} 2>/dev/null || which {tool_name.lower()} 2>/dev/null"
            if self.remote:
                exit_code, out, _ = self.remote.execute(check_cmd)
                if exit_code == 0 and out.strip():
                    self._installed_cache.add(tool_name)
                    return True

        tool_info = TOOL_REGISTRY.get(tool_name)
        if not tool_info:
            log.info(f"Tool '{tool_name}' not in registry. Invoking AI Discovery...")
            tool_info = self.discover_tool(tool_name)
            if not tool_info:
                self._failed_cache[tool_name] = time.time()
                return False

        binary = tool_info.get("binary") or tool_name

        # 2. Check if already installed (using canonical binary name from registry)
        if binary != tool_name:
            if not USE_REMOTE_VPS:
                found = shutil.which(binary) or shutil.which(binary.lower())
                if found:
                    self._installed_cache.add(tool_name)
                    return True
            else:
                path_prefix = f"export PATH={config_paths.VPS_TOOL_PATH}:$PATH && "
                check_cmd = f"{path_prefix}which {binary} 2>/dev/null || which {binary.lower()} 2>/dev/null"
                if tool_name == "theharvester":
                    check_cmd += " || ls /root/theHarvester/theHarvester.py 2>/dev/null"
                if self.remote:
                    exit_code, out, _ = self.remote.execute(check_cmd)
                    if exit_code == 0 and out.strip():
                        self._installed_cache.add(tool_name)
                        return True

        # 2. Attempt installation
        log.info(f"Tool '{tool_name}' not found. Installing...")
        install_cmd = tool_info.get("install", "")
        install_success = False

        if USE_REMOTE_VPS:
            # Sanitize AI-provided install commands: reject complex shell constructs
            forbidden_ops = ["&&", ";", "|", ">", "<", "`", "$(`", "\n"]
            if any(op in install_cmd for op in forbidden_ops):
                log.warning(f"Rejected unsafe AI install for {tool_name} (contains shell operators)")
                _agent_debug_log(
                    "tools/tool_manager.py:ensure_installed",
                    "Rejected unsafe install command",
                    {"tool": tool_name, "install_cmd_preview": install_cmd[:300]},
                    run_id="run1",
                    hypothesis_id="H4",
                )
            else:
                # Accept only canonical apt / pip installs and transform into safe operations
                apt_match = re.search(r'(?:apt-get|apt)\s+(?:-y\s+)?install\s+(.+)$', install_cmd, re.IGNORECASE)
                pip_match = re.search(r'(?:python3?\s+-m\s+)?pip(?:3)?\s+install\s+(.+)$', install_cmd, re.IGNORECASE)
                if apt_match:
                    pkgs = apt_match.group(1).strip()
                    # Basic package name safety: alphanum, +, -, ., :, spaces
                    if not re.match(r'^[A-Za-z0-9+_.:=\s-]+$', pkgs):
                        log.warning(f"Rejected AI apt install for {tool_name} (invalid package names): {pkgs}")
                    else:
                        # Simulate install first to ensure packages resolved
                        sim_cmd = f"DEBIAN_FRONTEND=noninteractive apt-get -s install {pkgs}"
                        sim_exit, sim_out, sim_err = self.remote.execute(sim_cmd, timeout=60)
                        if sim_exit == 0:
                            if not AUTO_APPROVE_INSTALLS:
                                log.info(f"AI-suggested apt install for '{tool_name}' requires operator approval (AUTO_APPROVE_INSTALLS=false)")
                            else:
                                # Perform update then install as separate commands (no shell operators)
                                upd_exit, upd_out, upd_err = self.remote.execute("DEBIAN_FRONTEND=noninteractive apt-get update -qq", timeout=120)
                                if upd_exit != 0:
                                    log.warning(f"apt-get update failed for {tool_name}: {upd_err}")
                                exit_code, out, err = self.remote.execute(f"DEBIAN_FRONTEND=noninteractive apt-get -y install {pkgs}", timeout=tool_info.get("install_timeout", 300))
                                if exit_code == 0:
                                    check_exit, _, _ = self.remote.execute(check_cmd)
                                    if check_exit == 0:
                                        install_success = True
                                else:
                                    log.error(f"VPS apt install failed for {tool_name}: {err}")
                        else:
                            log.warning(f"Simulated apt install failed/resolved for {tool_name}: {sim_err or sim_out}")
                elif pip_match:
                    pkgs = pip_match.group(1).strip()
                    if not re.match(r'^[A-Za-z0-9+_.:=\s-]+$', pkgs):
                        log.warning(f"Rejected AI pip install for {tool_name} (invalid package names): {pkgs}")
                    else:
                        if not AUTO_APPROVE_INSTALLS:
                            log.info(f"AI-suggested pip install for '{tool_name}' requires operator approval (AUTO_APPROVE_INSTALLS=false)")
                        else:
                            exit_code, out, err = self.remote.execute(f"python3 -m pip install --no-input {pkgs}", timeout=tool_info.get("install_timeout", 300))
                            if exit_code == 0:
                                check_exit, _, _ = self.remote.execute(check_cmd)
                                if check_exit == 0:
                                    install_success = True
                            else:
                                log.error(f"VPS pip install failed for {tool_name}: {err}")
                else:
                    log.warning(f"AI install command for '{tool_name}' not recognized as safe (only apt/pip supported): {install_cmd[:200]}")
                    _agent_debug_log(
                        "tools/tool_manager.py:ensure_installed",
                        "AI install unsupported type",
                        {"tool": tool_name, "install_cmd_preview": install_cmd[:300]},
                        run_id="run1",
                        hypothesis_id="H4",
                    )
        else:
            try:
                # shlex is imported at module level - do NOT re-import
                # Split the command into a list for safe non-shell execution
                args = shlex.split(install_cmd)
                _agent_debug_log(
                    "tools/tool_manager.py:local_install_attempt",
                    "Running local install with shell=False",
                    {"tool": tool_name, "arg_count": len(args), "args_preview": args[:8]},
                    run_id="run1",
                    hypothesis_id="H4",
                )
                if not AUTO_APPROVE_INSTALLS:
                    log.info(f"AI-suggested local install for '{tool_name}' requires operator approval (AUTO_APPROVE_INSTALLS=false)")
                else:
                    result = subprocess.run(
                        args, shell=False, capture_output=True, text=True,
                        timeout=180, env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
                    )
                    if result.returncode == 0:
                        if shutil.which(binary):
                            install_success = True
                    else:
                        _agent_debug_log(
                            "tools/tool_manager.py:local_install_failure",
                            "Local install returned non-zero",
                            {"tool": tool_name, "returncode": result.returncode, "stderr_preview": (result.stderr or "")[:200]},
                            run_id="run1",
                            hypothesis_id="H4",
                        )
                        log.error(f"Local Install failed for {tool_name}: {result.stderr}")
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
            log.warning(f"Installation validation failed for '{tool_name}'. Will attempt fallback on execution.")
            # Don't cache as failed if it was a network error (so it can be retried immediately)
            if USE_REMOTE_VPS and any(x in str(locals().get("err", "")).lower() for x in ["ssh", "connection failed", "banner"]):
                log.info(f"Retrying installation for '{tool_name}' next time (transient network error).")
            else:
                self._failed_cache[tool_name] = time.time()
            return False

    def get_fallback_tool(self, tool_name: str) -> str | None:
        """Get a fallback tool when primary tool is unavailable."""
        fallbacks = TOOL_FALLBACKS.get(tool_name, [])
        for fallback in fallbacks:
            if self.ensure_installed(fallback):
                log.warning(f"Using fallback tool '{fallback}' for '{tool_name}'")
                return fallback
        return None

    def _translate_command_for_fallback(self, original_tool: str, fallback_tool: str, command: str) -> str:
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
                url = match.group(1)
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
        return re.sub(r'(^|\s)' + re.escape(original_tool) + r'(\s|$)', r'\1' + fallback_tool + r'\2', command, 1)

    def discover_tool(self, tool_name: str) -> dict | None:
        """Use AI to research how to install an unknown tool."""
        if not self.ai:
            log.warning(f"Cannot discover tool '{tool_name}': AI backend not available")
            return None
        warning(f"AI RESEARCH: Discovering installation metadata for '{tool_name}'...")
        prompt = (
            f"I need to use a tool called '{tool_name}' on a Debian-based Linux VPS via SSH.\n"
            f"Provide a JSON object with:\n"
            f"1. 'binary': the exact binary name\n"
            f"2. 'install': the exact apt-get/pip/wget command to install it silently.\n"
            f"3. 'timeout': integer execution timeout in seconds.\n"
            f"Return ONLY the raw JSON block."
        )
        try:
            response = self.ai.query("You are an expert Linux sysadmin.", prompt)
            data = FragileParseFixer.safe_split_json_extraction(response, default={})
            if "binary" in data and "install" in data:
                # Validate install command against a conservative allowlist
                install_cmd = data.get("install", "")
                safe_prefixes = ("apt-get ", "apt ", "pip ", "pip3 ", "yum ", "dnf ", "wget ", "curl ")
                normalized = install_cmd.strip().lower()
                if any(normalized.startswith(p) for p in safe_prefixes):
                    log.info(f"AI discovered '{tool_name}': binary={data['binary']}")
                    return data
                else:
                    log.warning(f"AI-suggested install command for '{tool_name}' rejected by allowlist: {install_cmd[:200]}")
                    _agent_debug_log(
                        "tools/tool_manager.py:discover_tool:unsafe",
                        "AI-suggested install rejected",
                        {"tool": tool_name, "suggested_install": install_cmd[:500]},
                        run_id="run1",
                        hypothesis_id="H4",
                    )
                    return None
        except Exception as e:
            log.error(f"AI Tool Discovery failed for '{tool_name}': {e}")
        return None

    def _print_vps_console(self, command: str, status: str, duration: float,
                            out: str, err: str) -> None:
        """Print a compact VPS result panel for failures."""
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
        # Show full command up to 1500 chars (enough for any nuclei/gobuster cmd)
        truncated_cmd = command[:1500] + ("..." if len(command) > 1500 else "")
        content.append(f"{truncated_cmd}\n", style="dim white")
        content.append("    [ STS ] ", style="bold cyan")
        content.append(f"{status.upper()} ({duration:.1f}s)\n", style=f"bold {color}")
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
                            matched = obj.get("matched-at") or obj.get("host") or obj.get("url") or ""
                            concise_lines.append(f"[{sev}] {tid} {matched}".strip())
                            continue
                        except Exception:
                            # Some Nuclei lines include massive encoded fields; skip noisy payload lines.
                            lower_s = s.lower()
                            if any(k in lower_s for k in ["template-encoded", "curl-command", "\"request\"", "\"response\""]):
                                continue
                            m_tid = re.search(r'"template-id"\s*:\s*"([^"]+)"', s)
                            m_sev = re.search(r'"severity"\s*:\s*"([^"]+)"', s)
                            m_match = re.search(r'"matched-at"\s*:\s*"([^"]+)"', s)
                            if m_tid:
                                tid = m_tid.group(1)
                                sev = m_sev.group(1) if m_sev else "info"
                                matched = m_match.group(1) if m_match else ""
                                concise_lines.append(f"[{sev}] {tid} {matched}".strip())
                                continue
                    concise_lines.append(s)
                lines = concise_lines

            # Cap individual lines at 2000 chars (handles nuclei base64 encoded fields)
            # No line count cap - show all output so findings are never silently hidden
            # Actually, user complained about "cli rates of characters", so let's cap it
            # but mention the full log is available.
            MAX_DISPLAY_LINES = 100
            if len(lines) > MAX_DISPLAY_LINES:
                display_lines = [
                    line[:2000] + (" ...[line truncated]" if len(line) > 2000 else "")
                    for line in lines[:80]
                ]
                content.append("\n".join(display_lines), style="dim white")
                content.append(f"\n\n... [ {len(lines) - 90} lines omitted for brevity ] ...\n\n", style="bold yellow")
                display_lines_tail = [
                    line[:2000] + (" ...[line truncated]" if len(line) > 2000 else "")
                    for line in lines[-10:]
                ]
                content.append("\n".join(display_lines_tail), style="dim white")
            else:
                display_lines = [
                    line[:2000] + (" ...[line truncated]" if len(line) > 2000 else "")
                    for line in lines
                ]
                content.append("\n".join(display_lines), style="dim white")
        elif status == "success":
            content.append("\n" + "─" * 60 + "\n", style="dim cyan")
            content.append("    (No results/output returned from tool)", style="dim italic white")

        if err.strip():
            content.append("\n\n" + "[!] " * 30 + "\n", style="bold bright_red")
            content.append(err.strip()[:1000], style="bright_red")
        console.print(Panel(content, title=f"[bold {color}]▰▰▰ VPS TARGET MODULE ▰▰▰[/]", border_style=color, padding=(1, 2)))

    def run(self, tool_name: str, command: str, phase: str,
            timeout: int = None, save_raw: bool = True,
            output_path: str | Path = None, silent: bool = False) -> ToolResult:
        """Primary method to run any tool with full visibility."""
        from tools.tool_registry import TOOL_TIMEOUTS
        start = time.time()
        timeout = timeout or TOOL_TIMEOUTS.get(tool_name, TOOL_DEFAULT_TIMEOUT)

        if USE_REMOTE_VPS:
            remote_raw_dir = self.vps_path(self.session.results_dir / "raw")
            self.remote.remote_mkdir(remote_raw_dir)

        # Try primary tool first
        original_tool = tool_name
        if not self.ensure_installed(tool_name):
            # Try fallback tool before failing
            fallback = self.get_fallback_tool(tool_name)
            if fallback:
                log.info(f"Primary tool '{tool_name}' unavailable. Using fallback '{fallback}'.")
                tool_name = fallback  # Use fallback for actual execution
                # Translate command to use fallback tool syntax (if needed)
                command = self._translate_command_for_fallback(original_tool, fallback, command)
            else:
                duration = time.time() - start
                result = ToolResult(
                    tool=original_tool, command=command, stdout="", stderr="",
                    exit_code=-1, duration=duration, status="not_installed"
                )
                self._log_result(result, phase)
                return result

        # Determine retry count based on tool type
        retry_count = 1 if tool_name in FAST_TOOLS else TOOL_RETRY_COUNT

        result = None
        for attempt in range(retry_count):
            if attempt > 0:
                delay = min(2 ** (attempt - 1), 10)
                log.info(f"Retrying '{tool_name}' (attempt {attempt + 1}/{retry_count})... waiting {delay}s")
                time.sleep(delay)

            result = self._execute(tool_name, command, timeout, silent=silent)

            # Handle silent failures for curl/dig: try with more verbose output
            if not result.success and not result.stdout.strip() and not result.stderr.strip():
                if attempt < retry_count - 1:
                    log.warning(f"'{tool_name}' failed silently. Adjusting for retry...")
                    if tool_name == "dig":
                        command = command.replace("+short", "") + " +noall +answer"
                    elif tool_name == "curl":
                        command = command.replace("-s", "").replace("--silent", "")
                        if "--verbose" not in command and "-v" not in command:
                            command += " --verbose"

            if result.success or result.status in {"timeout", "blocked", "scope_blocked", "not_installed"}:
                break

        # Universal False-Success Detection
        # Some tools exit 0 while the transport layer or target clearly failed.
        # Only apply this to tools where a fatal transport error means the run did not complete usefully.
        SCANNER_TOOLS = {"nuclei", "nmap", "nikto", "masscan", "sqlmap", "john", "hydra", "ffuf"}
        if result.success and tool_name != "grep":
            combined = (result.stdout + result.stderr).lower()
            
            # Smart exception: if gobuster found paths/subdomains despite some network errors, don't fail it
            # BUG-07: Gobuster writes "Found: " with capital F - must use case-insensitive check
            is_successful_gobuster = tool_name == "gobuster" and "found: " in result.stdout.lower()
            
            if not is_successful_gobuster and any(err in combined for err in [
                "unable to connect", "error on running gobuster",
                "connection refused", "network is unreachable",
                "the server returns a status code that matches",
                "usage:", "syntax error", "unrecognized argument", "invalid option",
                "unrecognized option", "only 1 -p option allowed", "quitting!", 
                "fatal exception:", "not recognized", "command not found", 
                "too many arguments", "invalid parameter", "invalid command"
            ]):
                log.warning(f"Tool {tool_name} exited 0 but emitted network/wildcard/syntax error. Overriding to FAILED.")
                result.success = False
                result.status = "failed"
                result.exit_code = 1

        if result.status == "success" and not result.stdout.strip() and result.stderr.strip() and tool_name in {"curl", "wget", "gobuster", "ffuf", "nikto", "nuclei"}:
            combined = result.stderr.lower()
            if any(marker in combined for marker in ("error", "tls", "unable to connect", "connection refused", "timeout", "empty reply")):
                result.success = False
                result.status = "failed"
                result.exit_code = 1

        # VPS Console output
        if USE_REMOTE_VPS and not silent:
            # For STREAMING_TOOLS: the live feed already printed all stdout.
            # Only show a compact status header + stderr (if any) to avoid duplication.
            if tool_name in STREAMING_TOOLS:
                if result.status not in ("success",):
                    # Always show non-success outcomes with full output for debugging
                    self._print_vps_console(command, result.status, result.duration,
                                             result.stdout, result.stderr)
                else:
                    # Success + streaming: already shown live - just print compact footer
                    from rich.console import Console
                    from rich.text import Text
                    console = Console()
                    footer = Text()
                    footer.append("    [ CMD ] ", style="bold cyan")
                    footer.append(f"{command[:120]}{'...' if len(command) > 120 else ''}\n", style="dim white")
                    footer.append("    [ STS ] ", style="bold cyan")
                    footer.append(f"SUCCESS ({result.duration:.1f}s)\n", style="bold bright_green")
                    if result.stderr.strip():
                        footer.append("\n[!] STDERR:\n", style="bold bright_red")
                        footer.append(result.stderr.strip()[:500], style="bright_red")
                    from rich.panel import Panel
                    console.print(Panel(footer, title="[bold bright_green]▰▰▰ VPS TOOL COMPLETE ▰▰▰[/]",
                                        border_style="bright_green", padding=(0, 2)))
            elif result.status in ("failed", "timeout", "not_installed", "waf_blocked", "success",
                                   "fallback", "fallback_success", "tls_blocked", "captcha_blocked"):
                self._print_vps_console(command, result.status, result.duration,
                                         result.stdout, result.stderr)
            else:
                log.info(f"[{result.status.upper()}] {tool_name} done in {result.duration:.1f}s")

        # Save raw output
        if save_raw and result.stdout:
            raw_path = self.session.results_dir / "raw" / f"{phase}_{tool_name}_{int(start)}.txt"
            clean_stdout = clean_text(result.stdout)
            raw_path.write_text(clean_stdout, encoding="utf-8", errors="replace")
            result.stdout = clean_stdout

        # Parse output
        result.parsed = self.parser.parse(tool_name, result.stdout, result.stderr)

        # Automated Readback for VPS file output
        # For tools that write to -o file (nuclei, nmap, nikto), ALWAYS prefer
        # the file content over stdout - stdout is polluted with banners/stats/progress
        # that the parser will misinterpret. The file is the authoritative output.
        FILE_OUTPUT_TOOLS = {"nuclei", "nmap", "nikto", "masscan", "gobuster"}
        if USE_REMOTE_VPS and output_path:
            vps_out = self.vps_path(output_path)
            log.debug(f"Reading back VPS file: {vps_out}")
            exit_code, content, _ = self.remote.execute(f'cat "{vps_out}"')
            if exit_code == 0 and content.strip():
                # Always use file for file-output tools; for others only if file is longer
                if tool_name in FILE_OUTPUT_TOOLS or not result.stdout.strip() or len(content) > len(result.stdout):
                    result.stdout = content
                    result.parsed = self.parser.parse(tool_name, result.stdout, result.stderr)
                    # If file output is meaningful, don't classify as hard failure.
                    if result.status == "failed" and tool_name in FILE_OUTPUT_TOOLS:
                        parsed = result.parsed if isinstance(result.parsed, dict) else {}
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
                    Path(output_path).write_text(content, encoding="utf-8", errors="replace")
                except Exception as e:
                    log.error(f"Failed to write synced file: {e}")

        self._log_result(result, phase)
        return result

    def _execute(self, tool_name: str, command: str, timeout: int, silent: bool = False) -> ToolResult:
        start = time.time()

        # Handle virtual AI tools with Guardian validation
        if tool_name in VIRTUAL_AI_TOOLS:
            from utils.guardian import block_or_repair
            repaired_cmd, decision = block_or_repair(command, self.session.target)
            
            if not repaired_cmd:
                log.warning(f"Guardian BLOCKED: {decision}")
                duration = time.time() - start
                return ToolResult(
                    tool=tool_name, command=command,
                    stdout="", stderr=f"Guardian blocked: {decision}",
                    exit_code=126, duration=duration, status="blocked"
                )
            
            command = repaired_cmd
            log.info(f"Guardian approved: {decision} - {command[:80]}")
            # Continue to normal execution with repaired command

        if USE_REMOTE_VPS:
            use_streaming = tool_name in STREAMING_TOOLS
            if use_streaming:
                from rich.console import Console
                # Use default Console so Rich auto-detects terminal width
                console = Console()
                if not silent:
                    console.print(f"\n[bold bright_magenta]▰▰▰ VPS LIVE FEED ›[/bold bright_magenta] [dim]{command[:180]}[/dim]")
                printed_lines = []

                MAX_LIVE_LINES = 200
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
                                console.print(f"  [bold yellow]! Live feed capped at {MAX_LIVE_LINES} lines (see logs for full output)[/bold yellow]")

                # Use the new resilient tailing mode for long-running tools
                exit_code, stdout, stderr = self.remote.execute_resilient(
                    command, timeout=timeout, on_line=on_line
                )
                if not silent and printed_lines:
                    console.print(f"  [bold cyan]► {tool_name}: {len(printed_lines)} total lines captured[/bold cyan]")
            else:
                exit_code, stdout, stderr = self.remote.execute(command, timeout=timeout)

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
            has_fatal_error = any(marker in combined_output for marker in fatal_error_markers)

            if exit_code == -2:
                status = "timeout"
            elif exit_code == 0 or has_fatal_error:
                if has_fatal_error and tool_name in {"curl", "wget", "gobuster", "ffuf", "nikto", "nuclei", "sslscan", "whatweb"}:
                    status = "blocked"
                    exit_code = 1
                elif exit_code == 0:
                    status = "success"
                else:
                    status = "failed"
            else:
                # Some tools exit non-zero but produce valid output (e.g. nmap on filtered ports)
                known_partial_success = {"nmap", "masscan", "nikto", "nuclei", "gobuster", "ffuf"}
                if tool_name in known_partial_success and stdout and len(stdout.strip()) > 50 and not has_fatal_error:
                    status = "success"
                else:
                    status = "failed"

            return ToolResult(
                tool=tool_name, command=command,
                stdout=stdout, stderr=stderr,
                exit_code=exit_code, duration=duration, status=status
            )

        # Local execution path
        process = None
        try:
            # shlex is imported at module level - do NOT re-import
            # Split the command string into a list for safe execution without a shell
            # This prevents command injection vulnerabilities from unsanitized input
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
                exit_code = process.returncode
                status = "success" if exit_code == 0 else "failed"
                return ToolResult(
                    tool=tool_name, command=command,
                    stdout=stdout, stderr=stderr,
                    exit_code=exit_code, duration=duration, status=status
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
                except Exception:
                    stdout, stderr = "", ""
                duration = time.time() - start
                return ToolResult(
                    tool=tool_name, command=command,
                    stdout=stdout, stderr=stderr,
                    exit_code=-1, duration=duration, status="timeout"
                )
        except FileNotFoundError:
            duration = time.time() - start
            return ToolResult(
                tool=tool_name, command=command,
                stdout="", stderr=f"Binary not found: {tool_name}",
                exit_code=-1, duration=duration, status="not_installed"
            )
        except KeyboardInterrupt:
            raise
        except Exception as e:
            duration = time.time() - start
            return ToolResult(
                tool=tool_name, command=command,
                stdout="", stderr=str(e),
                exit_code=-1, duration=duration, status="failed"
            )

    def _log_result(self, result: ToolResult, phase: str) -> None:
        self.store.log_tool_run(
            engagement_id=self.session.engagement_id,
            phase=phase,
            tool=result.tool,
            command=result.command,
            status=result.status,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            duration=result.duration
        )


