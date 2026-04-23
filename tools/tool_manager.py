import subprocess
import shutil
import time
import os
import signal
from pathlib import Path
from tools.tool_registry import TOOL_REGISTRY
from tools.output_parser import OutputParser
from core.ssh_executor import SSHExecutor
from utils.logger import get_logger
from utils.display import warning
from utils.sanitizer import clean_text
from config import (
    TOOL_DEFAULT_TIMEOUT, TOOL_RETRY_COUNT,
    USE_REMOTE_VPS
)

log = get_logger("tool_manager")

# Tools that benefit from real-time streaming (long-running)
STREAMING_TOOLS = {"nmap", "nuclei", "gobuster", "nikto", "masscan", "ffuf",
                   "hydra", "sqlmap", "theharvester", "enum4linux"}

# Tools with fast execution — only 1 retry needed
FAST_TOOLS = {"dig", "curl", "whois", "nc"}


class ToolResult:
    def __init__(self, tool: str, command: str, stdout: str, stderr: str,
                 exit_code: int, duration: float, status: str, parsed: dict = None):
        self.tool = tool
        self.command = command
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.duration = duration
        self.status = status
        self.parsed = parsed or {}
        self.success = status == "success"

    def __repr__(self):
        return f"<ToolResult tool={self.tool} status={self.status} duration={self.duration:.1f}s>"


class ToolManager:
    def __init__(self, session, state_store, ai_backend=None):
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
        """Translate a local path to a VPS-safe /tmp path."""
        if not USE_REMOTE_VPS:
            return str(local_path)
        rel = str(local_path).replace("\\", "/").split("results/")[-1]
        return f"/tmp/antigravity/results/{rel}"

    def ensure_installed(self, tool_name: str, force_install: bool = False) -> bool:
        """Check if a tool is installed; attempt installation if not."""
        if not force_install and tool_name in self._installed_cache:
            return True
            
        # Failed cache expires after 5 mins to allow retries
        if tool_name in self._failed_cache:
            if time.time() - self._failed_cache[tool_name] < 300:
                return False
            else:
                del self._failed_cache[tool_name]

        tool_info = TOOL_REGISTRY.get(tool_name)
        if not tool_info:
            log.info(f"Tool '{tool_name}' not in registry. Invoking AI Discovery...")
            tool_info = self.discover_tool(tool_name)
            if not tool_info:
                self._failed_cache[tool_name] = time.time()
                return False

        binary = tool_info["binary"]

        # 1. Check if already installed
        if not USE_REMOTE_VPS:
            found = shutil.which(binary) or shutil.which(binary.lower())
            if found:
                self._installed_cache.add(tool_name)
                return True
        else:
            vps_path = "export PATH=$HOME/.local/bin:/root/.local/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/root/theHarvester:$PATH && "
            check_cmd = f"{vps_path}which {binary} 2>/dev/null || which {binary.lower()} 2>/dev/null"
            if tool_name == "theharvester":
                check_cmd += " || ls /root/theHarvester/theHarvester.py 2>/dev/null"
            exit_code, out, _ = self.remote.execute(check_cmd)
            if exit_code == 0 and out.strip():
                self._installed_cache.add(tool_name)
                return True

        # 2. Attempt installation
        log.info(f"Tool '{tool_name}' not found. Installing...")
        install_cmd = tool_info["install"]
        install_success = False

        if USE_REMOTE_VPS:
            exit_code, out, err = self.remote.execute(
                f"export DEBIAN_FRONTEND=noninteractive && {install_cmd}",
                timeout=tool_info.get("install_timeout", 300)
            )
            if exit_code == 0:
                # Validate after install using the same check command
                check_exit, _, _ = self.remote.execute(check_cmd)
                if check_exit == 0:
                    install_success = True
            else:
                log.error(f"VPS Install failed for {tool_name}: {err}")
        else:
            try:
                import shlex
                # Split the command into a list for safe non-shell execution
                args = shlex.split(install_cmd)
                result = subprocess.run(
                    args, shell=False, capture_output=True, text=True,
                    timeout=180, env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
                )
                if result.returncode == 0:
                    if shutil.which(binary):
                        install_success = True
                else:
                    log.error(f"Local Install failed for {tool_name}: {result.stderr}")
            except Exception as e:
                log.error(f"Local Install exception for {tool_name}: {e}")

        if install_success:
            self._installed_cache.add(tool_name)
            return True
        else:
            log.error(f"Final installation validation failed for '{tool_name}'.")
            self._failed_cache[tool_name] = time.time()
            return False

    def discover_tool(self, tool_name: str) -> dict | None:
        """Use AI to research how to install an unknown tool."""
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
            import json as pyjson
            response = self.ai.query("You are an expert Linux sysadmin.", prompt)
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0].strip()
            elif "{" in response:
                import re
                match = re.search(r'\{.*\}', response, re.DOTALL)
                if match:
                    response = match.group(0)
            data = pyjson.loads(response)
            if "binary" in data and "install" in data:
                log.info(f"AI discovered '{tool_name}': binary={data['binary']}")
                return data
        except Exception as e:
            log.error(f"AI Tool Discovery failed for '{tool_name}': {e}")
        return None

    def _print_vps_console(self, command: str, status: str, duration: float,
                            out: str, err: str):
        """Print a compact VPS result panel for failures."""
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text
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
        truncated_cmd = command[:500] + ("..." if len(command) > 500 else "")
        content.append(f"{truncated_cmd}\n", style="dim white")
        content.append("    [ STS ] ", style="bold cyan")
        content.append(f"{status.upper()} ({duration:.1f}s)\n", style=f"bold {color}")
        if out.strip():
            content.append("\n" + "─" * 60 + "\n", style="dim cyan")
            lines = out.strip().splitlines()
            truncated_lines = [line[:300] + ("... [truncated]" if len(line) > 300 else "") for line in lines]
            snippet = truncated_lines[:5] + (["... [snip] ..."] + truncated_lines[-3:] if len(truncated_lines) > 8 else [])
            content.append("\n".join(snippet), style="dim white")
        elif status == "success":
            content.append("\n" + "─" * 60 + "\n", style="dim cyan")
            content.append("    (No results/output returned from tool)", style="dim italic white")

        if err.strip():
            content.append("\n\n" + "⚠ " * 30 + "\n", style="bold bright_red")
            content.append(err.strip()[:300], style="bright_red")
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

        if not self.ensure_installed(tool_name):
            duration = time.time() - start
            result = ToolResult(
                tool=tool_name, command=command, stdout="", stderr="",
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

            if result.success or result.status == "timeout":
                break

        # Universal False-Success Detection
        # Only applies to connection-centric tools (curl, gobuster, ffuf, hydra).
        # Long-running scanners (nuclei, nmap, nikto, masscan) have their own
        # error tracking and exit codes — they naturally emit partial errors
        # (e.g., 227/13619 template timeouts) which is normal behavior.
        SCANNER_TOOLS = {"nuclei", "nmap", "nikto", "masscan", "sqlmap", "john", "hydra"}
        if result.success and tool_name not in SCANNER_TOOLS and tool_name != "grep":
            combined = (result.stdout + result.stderr).lower()
            
            # Smart exception: if gobuster found subdomains despite some network errors, don't fail it
            is_successful_gobuster = tool_name == "gobuster" and "found: " in result.stdout.lower()
            
            if not is_successful_gobuster and any(err in combined for err in [
                "unable to connect", "error on running gobuster",
                "connection refused", "network is unreachable",
                "the server returns a status code that matches"
            ]):
                log.warning(f"Tool {tool_name} exited 0 but emitted network/wildcard error. Overriding to FAILED.")
                result.success = False
                result.status = "failed"
                result.exit_code = 1

        # VPS Console output
        if USE_REMOTE_VPS and not silent:
            if result.status in ("failed", "timeout", "not_installed", "waf_blocked", "success", "fallback", "fallback_success"):
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
        if USE_REMOTE_VPS and output_path:
            vps_out = self.vps_path(output_path)
            log.debug(f"Reading back VPS file: {vps_out}")
            exit_code, content, _ = self.remote.execute(f'cat "{vps_out}"')
            if exit_code == 0 and content.strip():
                if not result.stdout.strip() or len(content) > len(result.stdout):
                    result.stdout = content
                    result.parsed = self.parser.parse(tool_name, result.stdout, result.stderr)
                try:
                    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
                    Path(output_path).write_text(content, encoding="utf-8", errors="replace")
                except Exception as e:
                    log.error(f"Failed to write synced file: {e}")

        self._log_result(result, phase)
        return result

    def _execute(self, tool_name: str, command: str, timeout: int, silent: bool = False) -> ToolResult:
        start = time.time()

        if USE_REMOTE_VPS:
            use_streaming = tool_name in STREAMING_TOOLS
            if use_streaming:
                from rich.console import Console
                console = Console()
                if not silent:
                    console.print(f"\n[bold bright_magenta]▰▰▰ VPS LIVE FEED ›[/bold bright_magenta] [dim]{command[:180]}[/dim]")
                printed_lines = []

                def on_line(line: str):
                    if silent:
                        return
                    clean = clean_text(line)
                    if clean:
                        printed_lines.append(clean)
                        ll = clean.lower()
                        # Smart filtering: only print meaningful lines
                        if any(kw in ll for kw in [
                            "found:", "open", "discovered", "/tcp", "/udp",
                            "[info]", "[warn]", "error", "vuln",
                            "running", "starting", "scanning", "done",
                            "rate:", "harvester", "emails", "hosts", "ips",
                        ]) or len(printed_lines) % 20 == 0:
                            console.print(f"  [dim]{clean[:200]}[/dim]")

                # Use the new resilient tailing mode for long-running tools
                exit_code, stdout, stderr = self.remote.execute_resilient(
                    command, timeout=timeout, on_line=on_line
                )
                if not silent and printed_lines:
                    console.print(f"  [bold cyan]► {tool_name}: {len(printed_lines)} total lines captured[/bold cyan]")
            else:
                exit_code, stdout, stderr = self.remote.execute(command, timeout=timeout)

            duration = time.time() - start
            if exit_code == -2:
                status = "timeout"
            elif exit_code == 0:
                status = "success"
            else:
                # Some tools exit non-zero but produce valid output (e.g. nmap on filtered ports)
                known_partial_success = {"nmap", "masscan", "nikto", "nuclei", "gobuster"}
                if tool_name in known_partial_success and stdout and len(stdout.strip()) > 50:
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
            import shlex
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

    def _log_result(self, result: ToolResult, phase: str):
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

    def run_msf_module(self, module: str, options: dict, phase: str) -> ToolResult:
        """Run a Metasploit module via msfconsole resource script."""
        rc_content = "spool /tmp/msf_output.txt\n"
        rc_content += f"use {module}\n"
        for k, v in options.items():
            rc_content += f"set {k} {v}\n"
        rc_content += "run\nexit -y\n"

        local_rc_path = self.session.results_dir / "raw" / f"msf_{int(time.time())}.rc"
        local_rc_path.write_text(rc_content, encoding="utf-8")

        if USE_REMOTE_VPS:
            remote_rc_path = f"/tmp/antigravity_msf_{int(time.time())}.rc"
            self.remote.upload_content(rc_content, remote_rc_path)
            exec_rc_path = remote_rc_path
        else:
            exec_rc_path = str(local_rc_path)

        return self.run("msfconsole", f"msfconsole -q -r {exec_rc_path} 2>&1", phase, timeout=300)
