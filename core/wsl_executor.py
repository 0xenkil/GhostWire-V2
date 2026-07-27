import os
import time
import threading
import uuid
import shlex
import subprocess
from utils.logger import get_logger
from utils.sanitizer import clean_text


from config_thresholds import (
    TOOL_DEFAULT_TIMEOUT
)

log = get_logger("wsl_executor")


class WSLExecutor:
    def __init__(self):
        # Try importing from config_backends, fall back to environment
        # variables
        try:
            from config_backends import WSL_DISTRO, WSL_USER
            self.distro = WSL_DISTRO
            self.wsl_user = WSL_USER
        except ImportError:
            self.distro = os.getenv("WSL_DISTRO", "")
            self.wsl_user = os.getenv("WSL_USER", "")

        self._wsl_active = False
        self._lock = threading.RLock()          # General-purpose lock
        self._connect_lock = threading.Lock()   # Connect-only lock

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def _build_wsl_command(self, cmd: str, timeout: int = 0) -> list[str]:
        """Build command list for wsl execution."""
        from config_paths import WSL_TOOL_PATH
        cmd_with_path = f"export PATH={WSL_TOOL_PATH}:$PATH && {cmd}"

        if timeout > 0:
            cmd_with_path = f"timeout -k 5s {timeout}s bash -c {
                shlex.quote(cmd_with_path)}"
        wsl_args = ["wsl"]
        if self.distro:
            wsl_args.extend(["-d", self.distro])
        elif os.getenv("WSL_DISTRO"):
            wsl_args.extend(["-d", os.getenv("WSL_DISTRO")])

        if self.wsl_user:
            wsl_args.extend(["-u", self.wsl_user])
        elif os.getenv("WSL_USER"):
            wsl_args.extend(["-u", os.getenv("WSL_USER")])

        wsl_args.extend(["-e", "bash", "-c", cmd_with_path])
        return wsl_args

    def _build_wsl_command_root(self, cmd: str, timeout: int = 0) -> list[str]:
        """Build command list for wsl execution as root."""
        from config_paths import WSL_TOOL_PATH
        cmd_with_path = f"export PATH={WSL_TOOL_PATH}:$PATH && {cmd}"

        if timeout > 0:
            cmd_with_path = f"timeout -k 5s {timeout}s bash -c {
                shlex.quote(cmd_with_path)}"
        wsl_args = ["wsl"]
        if self.distro:
            wsl_args.extend(["-d", self.distro])
        elif os.getenv("WSL_DISTRO"):
            wsl_args.extend(["-d", os.getenv("WSL_DISTRO")])

        wsl_args.extend(["-u", "root", "-e", "bash", "-c", cmd_with_path])
        return wsl_args

    def to_wsl_path(self, win_path: str) -> str:
        """Translate a Windows path to WSL path /mnt/drive/..."""
        if not win_path:
            return ""
        # If it looks like a Linux path, return it directly
        if win_path.startswith(
                "/") or win_path.startswith("$") or win_path.startswith("~"):
            return win_path
        abs_path = os.path.abspath(win_path)
        path = abs_path.replace("\\", "/")
        if len(path) >= 2 and path[1] == ":":
            drive = path[0].lower()
            path = f"/mnt/{drive}{path[2:]}"
        return path

    def resolve_home_paths(self):
        """Query WSL to expand ~ in VPS_TEMP_DIR and VPS_RESULTS_DIR to absolute path."""
        try:
            wsl_cmd = self._build_wsl_command("echo $HOME")
            res = subprocess.run(
                wsl_cmd,
                capture_output=True,
                text=True,
                timeout=5,
                errors="replace")
            if res.returncode == 0:
                wsl_home = res.stdout.strip()
                if wsl_home:
                    import config_paths
                    # Update config_paths attributes ONLY (avoid mutating local
                    # globals directly)
                    for attr in ['WSL_TEMP_DIR', 'WSL_RESULTS_DIR',
                                 'VPS_TEMP_DIR', 'VPS_RESULTS_DIR']:
                        if hasattr(config_paths, attr):
                            val = getattr(config_paths, attr)
                            if isinstance(val, str) and val.startswith("~"):
                                new_val = val.replace("~", wsl_home, 1)
                                setattr(config_paths, attr, new_val)

                    log.info(
                        f"Resolved WSL home paths dynamically: Temp={
                            config_paths.WSL_TEMP_DIR}, Results={
                            config_paths.WSL_RESULTS_DIR}")
        except Exception as e:
            log.error(f"Failed to resolve home paths: {e}")

    def ensure_workspace(self):
        """Ensure that the workspace directories exist on WSL."""
        try:
            import config_paths
            # Create the workspace directories directly using config_paths
            self.execute(
                f"mkdir -p {config_paths.WSL_RESULTS_DIR} {config_paths.WSL_TEMP_DIR}/buffers")
            log.info("WSL workspace directories created/verified.")
        except Exception as e:
            log.error(f"Failed to create WSL workspace: {e}")

    def connect(self) -> bool:
        """Verify WSL environment is responsive."""
        with self._connect_lock:
            if self._wsl_active:
                return True
            try:
                wsl_cmd = self._build_wsl_command("echo READY")
                res = subprocess.run(
                    wsl_cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    errors="replace")
                if res.returncode == 0 and "READY" in res.stdout:
                    self._wsl_active = True
                    log.info("WSL environment is ready and active.")
                    self.resolve_home_paths()
                    self.ensure_workspace()
                    return True
            except Exception as e:
                log.error(
                    f"WSL environment is not responsive or not installed: {e}")
            self._wsl_active = False
            return False

    def is_active(self) -> bool:
        """Check if WSL executor is active."""
        return self._wsl_active

    def ensure_connected(self) -> bool:
        """Ensure WSL is responsive, checking connection status."""
        with self._lock:
            if self._wsl_active:
                return True
            return self.connect()

    def execute(self, command: str, timeout: int = TOOL_DEFAULT_TIMEOUT,
                as_root: bool = False) -> tuple[int, str, str]:
        """
        Execute a command in WSL - blocking, returns (exit_code, stdout, stderr).
        """
        if not self.ensure_connected():
            return -1, "", "WSL environment failed to initialize"

        log.debug(f"Executing in WSL (root={as_root}): {command[:120]}")
        wsl_cmd = self._build_wsl_command_root(
            command, timeout) if as_root else self._build_wsl_command(
            command, timeout)
        try:
            py_timeout = (timeout + 5) if timeout else None
            res = subprocess.run(
                wsl_cmd,
                capture_output=True,
                text=True,
                timeout=py_timeout,
                errors="replace")
            out_str = clean_text(res.stdout)
            err_str = clean_text(res.stderr)
            exit_code = res.returncode
            if exit_code == 124:
                return -2, out_str, err_str + "\nTIMEOUT: GNU timeout 124"
            if exit_code != 0:
                log.debug(f"WSL command exited {exit_code}: {command[:60]}")
            return exit_code, out_str, err_str
        except subprocess.TimeoutExpired as e:
            log.error(
                f"WSL command timeout after {py_timeout}s: {command[:120]}")
            out_str = clean_text(
                e.stdout.decode(
                    "utf-8",
                    errors="replace") if isinstance(
                    e.stdout,
                    bytes) else e.stdout) if e.stdout else ""
            err_str = clean_text(
                e.stderr.decode(
                    "utf-8",
                    errors="replace") if isinstance(
                    e.stderr,
                    bytes) else e.stderr) if e.stderr else ""
            return -2, out_str, f"TIMEOUT: {e}"
        except Exception as e:
            log.error(f"Unexpected WSL error running command: {e}")
            return -1, "", str(e)

    def _workload_active(self) -> bool:
        """Generic liveness probe for the stall detector: is the box actually
        doing work right now?

        A scanner (nmap -p-, nikto, nuclei) can be SILENT for minutes while it
        probes filtered ports or rate-limits, yet it is busy — non-idle CPU
        advances and/or the TCP socket set churns. A genuinely hung command
        (blocked on a single read, a dead proxy) shows neither. We sample twice
        ~0.5s apart and treat non-idle CPU movement OR a change in the open-TCP
        count as 'working'. No per-tool knowledge — pure infrastructure signal.
        On ANY uncertainty we return True (assume alive) so the hard timeout,
        not this probe, stays the real backstop."""
        # Non-idle CPU jiffies = user+nice+system+irq+softirq+steal
        # ($2+$3+$4+$7+$8+$9), deliberately excluding idle ($5) and iowait ($6)
        # so the delta is ~0 on an idle box and only rises under real work.
        probe = (
            "b1=$(awk '/^cpu /{print $2+$3+$4+$7+$8+$9; exit}' /proc/stat 2>/dev/null); "
            "n1=$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | wc -l); "
            "sleep 0.5; "
            "b2=$(awk '/^cpu /{print $2+$3+$4+$7+$8+$9; exit}' /proc/stat 2>/dev/null); "
            "n2=$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | wc -l); "
            "echo \"$b1 $b2 $n1 $n2\""
        )
        try:
            ec, out, _ = self.execute(probe, timeout=8)
            parts = (out or "").split()
            if len(parts) != 4:
                return True
            b1, b2, n1, n2 = (int(x) for x in parts)
            cpu_busy_delta = b2 - b1   # non-idle jiffies over ~0.5s
            sockets_changed = n1 != n2
            return cpu_busy_delta > 10 or sockets_changed
        except Exception as e:
            log.debug(f"workload-active probe failed (assuming alive): {e}")
            return True

    def execute_streaming(self, command: str, timeout: int = TOOL_DEFAULT_TIMEOUT,
                          on_line=None, as_root: bool = False) -> tuple[int, str, str]:
        """
        Execute a command in WSL with REAL-TIME streaming output.
        Calls on_line(line: str) for each stdout line as it arrives.
        Returns (exit_code, full_stdout, full_stderr) when done.
        """
        if not self.ensure_connected():
            return -1, "", "WSL environment failed to initialize"

        log.debug(f"Streaming in WSL (root={as_root}): {command[:120]}")
        wsl_cmd = self._build_wsl_command_root(
            command, timeout) if as_root else self._build_wsl_command(
            command, timeout)

        try:
            p = subprocess.Popen(
                wsl_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                bufsize=1
            )

            stdout_lines = []
            stderr_data = []
            # UNIVERSAL stall detection: track the wall-clock of the last byte of
            # output. A tool that streams NOTHING for a long window is hung (the
            # nmap `--script=http-enum` case printed its banner then went silent
            # for the full 900s). Killing on stall bounds wasted time for ANY
            # tool without per-tool knowledge.
            _last_output = [time.monotonic()]

            # Read stdout in a background thread to prevent blocking the
            # timeout check
            def read_stdout():
                try:
                    for line in p.stdout:
                        line_clean = line.rstrip("\r\n")
                        stdout_lines.append(line_clean)
                        _last_output[0] = time.monotonic()
                        if on_line:
                            on_line(line_clean)
                except Exception as e:
                    log.debug(f"Error reading stdout: {e}")

            stdout_thread = threading.Thread(target=read_stdout, daemon=True)
            stdout_thread.start()

            # Read stderr in a background thread to prevent deadlocks
            def read_stderr():
                try:
                    for line in p.stderr:
                        line_clean = line.rstrip("\r\n")
                        stderr_data.append(line_clean + "\n")
                        _last_output[0] = time.monotonic()
                        if on_line:
                            on_line(line_clean)
                except Exception as e:
                    log.debug(f"Error reading stderr: {e}")

            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stderr_thread.start()

            start_time = time.monotonic()
            py_timeout = (timeout + 5) if timeout else 0
            # No-output window before we declare a stall. Generous so a normally
            # progressing tool is never killed, but well under the full timeout.
            # Override via TOOL_STALL_TIMEOUT; 0 disables stall detection.
            try:
                import os as _os
                _stall_window = int(_os.getenv("TOOL_STALL_TIMEOUT", "0")) or (
                    min(int(timeout * 0.4), 240) if timeout and timeout > 120 else 0)
            except Exception:
                _stall_window = 0
            while True:
                elapsed = time.monotonic() - start_time
                if py_timeout > 0 and elapsed > py_timeout:
                    log.error(
                        f"Streaming command exceeded timeout of {py_timeout}s")
                    p.kill()
                    p.wait()
                    stdout_thread.join(timeout=1)
                    stderr_thread.join(timeout=1)
                    return - \
                        2, "\n".join(
                            stdout_lines), f"TIMEOUT after {elapsed:.1f}s"

                # Stall: no output for the whole window AND past a 30s grace.
                if _stall_window and elapsed > 30:
                    _idle = time.monotonic() - _last_output[0]
                    if _idle > _stall_window:
                        # A quiet command is only HUNG if it is also doing no
                        # work. Scanners go silent for minutes while probing
                        # filtered / rate-limited hosts — killing them as 'hung'
                        # was the #1 cause of tool failures (nmap/nikto/nuclei
                        # all banned this way). Defer to the hard timeout when
                        # the box is still working.
                        if self._workload_active():
                            log.debug(
                                f"No output for {_idle:.0f}s but workload is active "
                                f"(CPU/socket churn) — not killing; deferring to timeout.")
                            _last_output[0] = time.monotonic()  # re-arm window
                        else:
                            log.warning(
                                f"Stall detected: no output for {_idle:.0f}s "
                                f"(window {_stall_window}s) and no CPU/network "
                                f"activity — killing hung command.")
                            p.kill()
                            p.wait()
                            stdout_thread.join(timeout=1)
                            stderr_thread.join(timeout=1)
                            return -2, "\n".join(stdout_lines), (
                                f"STALLED: no output for {_idle:.0f}s, killed as hung")

                if p.poll() is not None:
                    break

                time.sleep(0.1)

            # Wait for threads to finish consuming any final buffered output
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)

            exit_code = p.returncode
            if exit_code == 124:
                return -2, clean_text("\n".join(stdout_lines)), clean_text(
                    "".join(stderr_data)) + "\nTIMEOUT: GNU timeout 124"
            return exit_code, clean_text(
                "\n".join(stdout_lines)), clean_text("".join(stderr_data))

        except Exception as e:
            log.error(f"Streaming execute error in WSL: {e}")
            return -1, "", str(e)

    def execute_tmux(self, command: str, session_name: str,
                     timeout: int = TOOL_DEFAULT_TIMEOUT) -> tuple[int, str, str]:
        """
        Execute a command in WSL. In VPS mode this used tmux to survive disconnects,
        but for local WSL we can just use execute_streaming.
        """
        log.info(
            f"Executing directly in WSL (bypassing tmux '{session_name}'): {command[:50]}")
        return self.execute_streaming(command, timeout)

    def execute_resilient(self, command: str, timeout: int = TOOL_DEFAULT_TIMEOUT,
                          on_line=None, as_root: bool = False) -> tuple[int, str, str]:
        """
        Execute a command in WSL with resilient tailing. In VPS mode this used
        background setsid tasks. In WSL we directly stream the process synchronously.
        """
        log.info(
            f"Executing resilient command natively via WSL stream (root={as_root})...")
        return self.execute_streaming(command, timeout, on_line, as_root)
        """
        Execute a command in WSL with resilient tailing and background persistence.
        """
        # Implementation replaced with direct stream above

    def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload a file from Windows to WSL filesystem."""
        try:
            remote_dir = os.path.dirname(remote_path)
            if remote_dir:
                self.remote_mkdir(remote_dir)
            wsl_local = self.to_wsl_path(local_path)
            cmd = f"cp {shlex.quote(wsl_local)} {shlex.quote(remote_path)}"
            ec, _, err = self.execute(cmd)
            return ec == 0
        except Exception as e:
            log.error(f"Upload failed: {e}")
            return False

    def download(self, remote_path: str, local_path: str) -> bool:
        """Download a file from WSL filesystem to Windows."""
        try:
            local_dir = os.path.dirname(local_path)
            if local_dir:
                os.makedirs(local_dir, exist_ok=True)
            wsl_local = self.to_wsl_path(local_path)
            cmd = f"cp {shlex.quote(remote_path)} {shlex.quote(wsl_local)}"
            ec, _, err = self.execute(cmd)
            return ec == 0
        except Exception as e:
            log.error(f"Download failed: {e}")
            return False

    def remote_mkdir(self, path: str):
        """Ensure a directory structure exists in WSL."""
        self.execute(f'mkdir -p "{path}"')

    def upload_content(self, content: str, remote_path: str) -> bool:
        """Upload a raw string as a file to WSL."""
        temp_local = os.path.join(
            os.environ.get(
                "TEMP", "."), f"wsl_temp_{
                uuid.uuid4().hex}.tmp")
        try:
            with open(temp_local, "w", encoding="utf-8", errors="replace") as f:
                f.write(content)
            return self.upload(temp_local, remote_path)
        except Exception as e:
            log.error(f"Upload content failed: {e}")
            return False
        finally:
            if os.path.exists(temp_local):
                try:
                    os.remove(temp_local)
                except Exception as _e:
                    import logging
                    logging.getLogger(__name__).debug(
                        f'Swallowed exception in wsl_executor.py: {_e}')

    def check_vps_health(self) -> dict:
        """
        Pre-flight health check for WSL.
        Returns metrics corresponding to old VPS settings but calculated for local WSL.
        """
        import config_paths
        try:
            from config import VPS_DISK_WARN_PCT, VPS_DISK_ABORT_PCT, VPS_MEM_LOW_MB
        except ImportError:
            VPS_DISK_WARN_PCT, VPS_DISK_ABORT_PCT, VPS_MEM_LOW_MB = 85, 95, 512

        health = {
            "disk_pct": 0,
            "mem_avail_mb": 9999,
            "cpu_load": 0.0,
            "services": {"tor": True},
            "healthy": True,
            "issues": []
        }

        # 1. Disk check
        _, disk_out, _ = self.execute(
            f"df {config_paths.VPS_TEMP_DIR} 2>/dev/null | awk 'NR==2{{print $5}}' | tr -d '%'"
        )
        try:
            health["disk_pct"] = int(disk_out.strip())
        except (ValueError, TypeError) as e:
            log.debug(f"Disk check parsing failed: {e}")

        if health["disk_pct"] >= VPS_DISK_ABORT_PCT:
            health["healthy"] = False
            health["issues"].append(
                f"CRITICAL: {config_paths.VPS_TEMP_DIR} is {
                    health['disk_pct']}% full (abort threshold: {VPS_DISK_ABORT_PCT}%)"
            )
        elif health["disk_pct"] >= VPS_DISK_WARN_PCT:
            health["issues"].append(
                f"WARNING: {config_paths.VPS_TEMP_DIR} is {
                    health['disk_pct']}% full (warn threshold: {VPS_DISK_WARN_PCT}%)"
            )

        # 2. Memory check
        _, mem_out, _ = self.execute(
            "free -m 2>/dev/null | awk '/^Mem:/{print $7}'"
        )
        try:
            health["mem_avail_mb"] = int(mem_out.strip())
        except (ValueError, TypeError) as e:
            log.debug(f"Memory check parsing failed: {e}")

        if health["mem_avail_mb"] < VPS_MEM_LOW_MB:
            health["issues"].append(
                f"WARNING: Only {
                    health['mem_avail_mb']}MB RAM available (threshold: {VPS_MEM_LOW_MB}MB)"
            )

        # 3. CPU Load check (1-minute average)
        _, cpu_out, _ = self.execute(
            "uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1")
        try:
            health["cpu_load"] = float(cpu_out.strip())
            if health["cpu_load"] > 10.0:
                health["issues"].append(
                    f"WARNING: High CPU load: {
                        health['cpu_load']}")
        except (ValueError, TypeError) as e:
            log.debug(f"CPU load parsing failed: {e}")

        # 4. Service status checks
        # In WSL mode, sshd is not required. Only check tor.
        services_to_check = ["tor"]
        for svc in services_to_check:
            exit_code, _, _ = self.execute(
                f"systemctl is-active {svc} --quiet 2>/dev/null || ps aux | grep -v grep | grep -q {svc}")
            is_active = (exit_code == 0)
            health["services"][svc] = is_active
            if not is_active:
                try:
                    from config_backends import TOR_ENABLED
                except ImportError:
                    TOR_ENABLED = False
                if svc == "tor" and TOR_ENABLED:
                    health["healthy"] = False
                    health["issues"].append(
                        f"CRITICAL: Service '{svc}' is DOWN but TOR_ENABLED=true")
                else:
                    health["issues"].append(
                        f"WARNING: Service '{svc}' is DOWN")

        log.debug(
            f"WSL Health: disk={
                health['disk_pct']}% mem={
                health['mem_avail_mb']}MB "
            f"cpu={health['cpu_load']} healthy={health['healthy']}"
        )
        return health

    def cleanup_stale_sessions(self):
        """
        Kill orphaned processes from previous engagements inside WSL.
        """
        import config_paths
        try:
            from config import VPS_ZOMBIE_AGE_MINUTES
        except ImportError:
            VPS_ZOMBIE_AGE_MINUTES = 60
        log.info("Cleaning up stale WSL sessions from previous engagements...")

        cleanup_cmd = (
            f"find {config_paths.VPS_TEMP_DIR}/buffers/ -name '*.pid' -mmin +{VPS_ZOMBIE_AGE_MINUTES} "
            f"-exec sh -c 'kill -9 $(cat \"$1\" 2>/dev/null) 2>/dev/null; "
            f"rm -f \"$1\" \"$(echo $1 | sed s/.pid/.log/)\"' _ {{}} \\; 2>/dev/null; "
            f"echo 'cleanup_done'"
        )
        exit_code, out, _ = self.execute(
            cleanup_cmd, timeout=TOOL_DEFAULT_TIMEOUT)

        self.execute(
            f"find {config_paths.VPS_TEMP_DIR}/buffers/ -name '*.log' -mmin +{VPS_ZOMBIE_AGE_MINUTES} "
            f"-delete 2>/dev/null; true",
            timeout=TOOL_DEFAULT_TIMEOUT
        )

        if "cleanup_done" in out:
            log.info("Stale WSL session cleanup complete.")
        else:
            log.warning("Stale WSL session cleanup may have failed.")

    def cleanup_tmp(self):
        """Emergency disk cleanup in WSL temp dir."""
        import config_paths
        log.warning(f"Running emergency disk cleanup on WSL {config_paths.VPS_TEMP_DIR}...")
        self.execute(
            f"rm -rf {config_paths.VPS_TEMP_DIR}/buffers/*.log {config_paths.VPS_TEMP_DIR}/buffers/*.pid "
            f"{config_paths.VPS_TEMP_DIR}/nuclei*.zip {config_paths.VPS_TEMP_DIR}/ffuf*.tar.gz {config_paths.VPS_TEMP_DIR}/*.tmp 2>/dev/null; "
            f"find {config_paths.VPS_RESULTS_DIR}/ -name '*.json' -size +50M -delete 2>/dev/null; "
            f"echo 'emergency_cleanup_done'",
            timeout=TOOL_DEFAULT_TIMEOUT
        )

    def close(self):
        """Close WSL resources properly."""
        with self._lock:
            self._wsl_active = False
            log.debug("WSL executor resources closed")

# aliases for module level compatibility
