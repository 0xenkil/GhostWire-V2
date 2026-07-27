import os
import time
import threading
import shlex
import subprocess
from utils.logger import get_logger
from utils.sanitizer import clean_text
from config_thresholds import TOOL_DEFAULT_TIMEOUT

log = get_logger("ssh_executor")


class SSHExecutor:
    def __init__(self):
        try:
            from config_backends import VPS_HOST, VPS_PORT, VPS_USERNAME, VPS_KEY_FILE, VPS_PASSWORD
            self.host = VPS_HOST
            self.port = VPS_PORT
            self.user = VPS_USERNAME
            self.key_file = VPS_KEY_FILE
            self.password = VPS_PASSWORD
        except ImportError:
            self.host = os.getenv("VPS_HOST", "")
            self.port = int(os.getenv("VPS_PORT", "22"))
            self.user = os.getenv("VPS_USERNAME", "root")
            self.key_file = os.getenv("VPS_KEY_FILE", "")
            self.password = os.getenv("VPS_PASSWORD", "")

        self._active = False
        self._lock = threading.RLock()
        self._connect_lock = threading.Lock()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def _build_ssh_command(self, cmd: str, timeout: int = 0,
                           as_root: bool = False) -> list[str]:
        if timeout > 0:
            cmd = f"timeout {timeout}s bash -c {shlex.quote(cmd)}"

        if as_root and self.user != "root":
            cmd = f"sudo -n bash -c {shlex.quote(cmd)}"

        ssh_args = ["ssh", "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes", "-p", str(self.port)]
        if self.key_file:
            ssh_args.extend(["-i", self.key_file])

        ssh_args.append(f"{self.user}@{self.host}")
        ssh_args.append(cmd)
        return ssh_args

    def to_wsl_path(self, win_path: str) -> str:
        if not win_path:
            return ""
        if win_path.startswith(
                "/") or win_path.startswith("$") or win_path.startswith("~"):
            return win_path
        abs_path = os.path.abspath(win_path)
        path = abs_path.replace("\\", "/")
        if len(path) >= 2 and path[1] == ":":
            drive = path[0].lower()
            path = f"/mnt/{drive}{path[2:]}"
        return path

    def connect(self) -> bool:
        with self._connect_lock:
            if self._active:
                return True
            if not self.host:
                log.error("VPS_HOST not configured for SSHExecutor")
                return False

            try:
                ssh_cmd = self._build_ssh_command("echo READY")
                res = subprocess.run(
                    ssh_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    errors="replace")
                if res.returncode == 0 and "READY" in res.stdout:
                    self._active = True
                    log.info(f"SSH connection to {self.host} is active.")
                    return True
                else:
                    log.error(f"SSH connect failed: {res.stderr}")
            except Exception as e:
                log.error(f"SSH environment is not responsive: {e}")
            self._active = False
            return False

    def is_active(self) -> bool:
        return self._active

    def ensure_connected(self) -> bool:
        with self._lock:
            if self._active:
                return True
            return self.connect()

    def execute(self, command: str, timeout: int = TOOL_DEFAULT_TIMEOUT,
                as_root: bool = False) -> tuple[int, str, str]:
        if not self.ensure_connected():
            return -1, "", "SSH environment failed to initialize"

        log.debug(f"Executing over SSH (root={as_root}): {command[:120]}")
        ssh_cmd = self._build_ssh_command(command, timeout, as_root)
        try:
            # Adding a 5s buffer to python's timeout to let the remote
            # 'timeout' trigger first
            py_timeout = (timeout + 5) if timeout else None
            res = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=py_timeout,
                errors="replace")
            out_str = clean_text(res.stdout)
            err_str = clean_text(res.stderr)
            exit_code = res.returncode
            if exit_code != 0:
                log.debug(f"SSH command exited {exit_code}: {command[:60]}")
            return exit_code, out_str, err_str
        except subprocess.TimeoutExpired as e:
            log.error(
                f"SSH command timeout after {py_timeout}s: {command[:120]}")
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
            log.error(f"Unexpected SSH error running command: {e}")
            return -1, "", str(e)

    def _workload_active(self) -> bool:
        """Generic liveness probe for the stall detector (parity with
        WSLExecutor): is the remote box doing work right now? A scanner can be
        silent for minutes while probing filtered/rate-limited hosts yet be busy
        — non-idle CPU advances and/or the TCP socket set churns. A hung command
        shows neither. Sample twice ~0.5s apart; CPU movement OR socket-count
        change == working. No per-tool knowledge. On uncertainty return True so
        the hard timeout stays the real backstop."""
        probe = (
            "b1=$(awk '/^cpu /{print $2+$3+$4+$7+$8+$9; exit}' /proc/stat 2>/dev/null); "
            "n1=$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | wc -l); "
            "sleep 0.5; "
            "b2=$(awk '/^cpu /{print $2+$3+$4+$7+$8+$9; exit}' /proc/stat 2>/dev/null); "
            "n2=$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | wc -l); "
            "echo \"$b1 $b2 $n1 $n2\""
        )
        try:
            ec, out, _ = self.execute(probe, timeout=12)
            parts = (out or "").split()
            if len(parts) != 4:
                return True
            b1, b2, n1, n2 = (int(x) for x in parts)
            return (b2 - b1) > 10 or n1 != n2
        except Exception as e:
            log.debug(f"workload-active probe failed (assuming alive): {e}")
            return True

    def execute_streaming(self, command: str, timeout: int = TOOL_DEFAULT_TIMEOUT,
                          on_line=None, as_root: bool = False) -> tuple[int, str, str]:
        if not self.ensure_connected():
            return -1, "", "SSH environment failed to initialize"

        log.debug(f"Streaming over SSH (root={as_root}): {command[:120]}")
        ssh_cmd = self._build_ssh_command(command, timeout, as_root)

        try:
            p = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                bufsize=1
            )

            stdout_lines = []
            stderr_data = []
            # UNIVERSAL stall detection (parity with WSLExecutor): kill a command
            # that streams NO output for a long window — it is hung.
            _last_output = [time.monotonic()]

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

            def read_stderr():
                try:
                    for line in p.stderr:
                        stderr_data.append(line)
                        _last_output[0] = time.monotonic()
                except Exception as e:
                    log.debug(f"Error reading stderr: {e}")

            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stderr_thread.start()

            start_time = time.monotonic()
            # Adding a 5s buffer to python's timeout to let the remote
            # 'timeout' trigger first
            py_timeout = (timeout + 5) if timeout else 0
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
                    return -2, clean_text("\n".join(stdout_lines)
                                          ), "TIMEOUT: Process killed by Python due to timeout"

                if _stall_window and elapsed > 30:
                    _idle = time.monotonic() - _last_output[0]
                    if _idle > _stall_window:
                        # Only kill a quiet command if it is also doing no work
                        # (no CPU / no socket churn). Scanners are legitimately
                        # silent for minutes — deferring to the hard timeout when
                        # the box is busy stops them being banned as 'hung'.
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
                            return -2, clean_text("\n".join(stdout_lines)), (
                                f"STALLED: no output for {_idle:.0f}s, killed as hung")

                if p.poll() is not None:
                    break
                time.sleep(0.1)

            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)

            full_out = clean_text("\n".join(stdout_lines))
            full_err = clean_text("".join(stderr_data))
            return p.returncode, full_out, full_err

        except Exception as e:
            log.error(f"Streaming execution error: {e}")
            return -1, "", str(e)

    def execute_resilient(self, command: str, timeout: int = TOOL_DEFAULT_TIMEOUT,
                          on_line=None, as_root: bool = False) -> tuple[int, str, str]:
        """
        Execute a command over SSH with resilient tailing.
        """
        log.info(
            f"Executing resilient command natively via SSH stream (root={as_root})...")
        return self.execute_streaming(command, timeout, on_line, as_root)

    def cleanup_stale_sessions(self):
        self.execute("pkill -u $USER -f '(nmap|sqlmap|ffuf|gobuster)'")

    def cleanup_tmp(self):
        import config_paths
        if config_paths.VPS_TEMP_DIR and len(config_paths.VPS_TEMP_DIR) > 2 and config_paths.VPS_TEMP_DIR != "/":
            self.execute(f"rm -rf {config_paths.VPS_TEMP_DIR}/*")
        else:
            log.warning("Skipped cleanup_tmp: VPS_TEMP_DIR is unsafe or unset")

    def check_vps_health(self):
        issues = []
        disk_pct = 0
        cpu_load = 0.0

        if not self.ensure_connected():
            return {"healthy": False, "disk_pct": 0,
                    "cpu_load": 0.0, "issues": ["SSH not connected"]}

        # Check disk space
        ec_disk, out_disk, _ = self.execute(
            "df -hP / | tail -1 | awk '{print $5}' | tr -d '%'")
        if ec_disk == 0 and out_disk.strip().isdigit():
            disk_pct = int(out_disk.strip())
            if disk_pct > 90:
                issues.append(f"Disk usage critical: {disk_pct}%")

        # Check CPU load (1 minute average)
        ec_cpu, out_cpu, _ = self.execute(
            "uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1")
        if ec_cpu == 0 and out_cpu.strip():
            try:
                cpu_load = float(out_cpu.strip())
                if cpu_load > 5.0:
                    issues.append(f"High CPU load: {cpu_load}")
            except ValueError:
                pass

        return {
            "healthy": len(issues) == 0,
            "disk_pct": disk_pct,
            "cpu_load": cpu_load,
            "issues": issues
        }
