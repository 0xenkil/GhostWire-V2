import paramiko
import socket
import os
import time
import threading
import uuid
from utils.logger import get_logger
from utils.sanitizer import clean_text
from config import VPS_HOST, VPS_USER, VPS_KEY_PATH

log = get_logger("ssh_executor")


class SSHExecutor:
    def __init__(self):
        self.host = VPS_HOST
        self.user = VPS_USER
        self.key_path = VPS_KEY_PATH
        self.client = None
        self._lock = threading.RLock()          # General-purpose lock
        self._connect_lock = threading.Lock()   # Auth-only lock (parallel execute is lock-free)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def connect(self):
        """Establish SSH connection to the VPS."""
        with self._connect_lock:
            try:
                log.info(f"Connecting to {self.user}@{self.host}...")
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                key = None
                for cls_name in ['Ed25519Key', 'RSAKey', 'ECDSAKey', 'DSSKey']:
                    if hasattr(paramiko, cls_name):
                        try:
                            key = getattr(paramiko, cls_name).from_private_key_file(self.key_path)
                            log.debug(f"Loaded key using {cls_name}")
                            break
                        except Exception:
                            continue

                if not key:
                    raise ValueError(f"File at {self.key_path} is not a valid or supported private key.")

                self.client.connect(
                    hostname=self.host,
                    username=self.user,
                    pkey=key,
                    timeout=20
                )
                transport = self.client.get_transport()
                if transport:
                    transport.set_keepalive(15) # Hardened keep-alive

                log.info("SSH connection established.")
                return True
            except Exception as e:
                log.error(f"Failed to connect to VPS: {e}")
                self.client = None
                return False

    def is_active(self) -> bool:
        """Check if the SSH session is still alive."""
        if not self.client:
            return False
        transport = self.client.get_transport()
        if not transport or not transport.is_active():
            return False
        try:
            # Send a keepalive-style probe
            transport.send_ignore()
            return True
        except Exception:
            return False

    def ensure_connected(self) -> bool:
        """Ensure SSH is connected, reconnecting if necessary."""
        with self._lock:
            if self.is_active():
                return True
            log.info("SSH connection lost or not established. Re-connecting...")
            return self.connect()

    def execute(self, command: str, timeout: int = 120) -> tuple[int, str, str]:
        """
        Execute a command on the VPS — blocking, returns (exit_code, stdout, stderr).
        Lock-free for parallel execution. Only reconnects use _connect_lock.
        Includes single retry on channel loss.
        """
        if not self.ensure_connected():
            return -1, "", "SSH connection failed"

        for attempt in range(2):  # 1 retry on channel loss
            try:
                self.last_command = command
                log.debug(f"Executing: {command[:120]}")
                stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)

                out_str = clean_text(stdout.read().decode("utf-8", errors="replace"))
                err_str = clean_text(stderr.read().decode("utf-8", errors="replace"))
                exit_code = stdout.channel.recv_exit_status()

                if exit_code != 0:
                    log.debug(f"Command exited {exit_code}: {command[:60]}")
                return exit_code, out_str, err_str

            except (AttributeError, EOFError, paramiko.SSHException) as e:
                log.warning(f"SSH channel error (attempt {attempt + 1}/2): {e}")
                if attempt == 0:
                    # Single retry: reconnect and try again
                    time.sleep(1)
                    if not self.connect():
                        return -1, "", "SSH channel failed after reconnect attempt"
                else:
                    return -1, "", f"SSH channel failed after reconnect attempt: {e}"

            except (socket.timeout,) as e:
                if "timeout" in str(e).lower() or isinstance(e, socket.timeout):
                    return -2, "", f"TIMEOUT: {e}"
                return -1, "", str(e)
            except Exception as e:
                log.error(f"Unexpected SSH error: {e}")
                return -1, "", str(e)

        return -1, "", "SSH execute exhausted retries"

    def execute_streaming(self, command: str, timeout: int = 120,
                           on_line=None) -> tuple[int, str, str]:
        """
        Execute a command with REAL-TIME streaming output.
        Calls on_line(line: str) for each stdout line as it arrives.
        Returns (exit_code, full_stdout, full_stderr) when done.

        V2: Lock-free — only uses _connect_lock for auth, allowing parallel
        streaming sessions (e.g., multiple exploit vectors running simultaneously).
        Each call uses its own local buffer to prevent cross-thread contamination.
        """
        if not self.ensure_connected():
            return -1, "", "SSH connection failed"

        for attempt in range(2):  # Single retry on channel loss
            try:
                transport = self.client.get_transport()
                if not transport or not transport.is_active():
                    if attempt == 0:
                        time.sleep(1)
                        if not self.connect():
                            return -1, "", "SSH transport dead, reconnect failed"
                        continue
                    return -1, "", "SSH transport not active"

                channel = transport.open_session()
                channel.settimeout(timeout)
                channel.exec_command(command)

                # Thread-local buffers (no shared state)
                stdout_lines = []
                stderr_data = []
                buf = ""
                start = time.time()
                max_iterations = 100000
                iterations = 0

                while iterations < max_iterations:
                    iterations += 1

                    elapsed = time.time() - start
                    if elapsed > timeout:
                        log.error(f"Command exceeded timeout of {timeout}s")
                        channel.close()
                        return -2, "\n".join(stdout_lines), f"TIMEOUT after {elapsed:.1f}s"

                    if not transport.is_active():
                        log.error("SSH transport lost during streaming.")
                        break

                    try:
                        if channel.recv_ready():
                            chunk = channel.recv(4096).decode("utf-8", errors="replace")
                            buf += chunk
                            while "\n" in buf:
                                line, buf = buf.split("\n", 1)
                                line = line.rstrip("\r")
                                stdout_lines.append(line)
                                if on_line:
                                    on_line(line)

                        if channel.recv_stderr_ready():
                            chunk = channel.recv_stderr(4096).decode("utf-8", errors="replace")
                            stderr_data.append(chunk)

                        if channel.exit_status_ready():
                            # Final drain
                            while channel.recv_ready():
                                chunk = channel.recv(4096).decode("utf-8", errors="replace")
                                buf += chunk
                            if buf.strip():
                                stdout_lines.append(buf.rstrip("\r"))
                                if on_line:
                                    on_line(buf.rstrip("\r"))
                            break
                    except socket.timeout:
                        pass
                    except Exception as e:
                        log.error(f"Stream error: {e}")
                        break

                    time.sleep(0.05)

                if iterations >= max_iterations:
                    log.error("Command hit max iteration safety limit")
                    channel.close()
                    return -1, "\n".join(stdout_lines), "Max iterations reached"

                exit_code = channel.recv_exit_status()
                channel.close()
                return exit_code, clean_text("\n".join(stdout_lines)), clean_text("".join(stderr_data))

            except (AttributeError, EOFError, paramiko.SSHException) as e:
                log.warning(f"SSH streaming channel error (attempt {attempt + 1}/2): {e}")
                if attempt == 0:
                    time.sleep(1)
                    if not self.connect():
                        return -1, "", "SSH channel failed after reconnect attempt"
                else:
                    return -1, "", f"SSH streaming failed after retry: {e}"
            except Exception as e:
                log.error(f"Streaming execute error: {e}")
                return -1, "", str(e)

        return -1, "", "SSH streaming exhausted retries"

    def execute_resilient(self, command: str, timeout: int = 120, on_line=None) -> tuple[int, str, str]:
        """
        Execute a command with autonomous reconnection and persistence.
        Writes output to a VPS buffer and tails it. Survives SSH resets (10054).
        """
        cmd_id = str(uuid.uuid4())[:8]
        buffer_file = f"/tmp/antigravity/buffers/{cmd_id}.log"
        pid_file = f"/tmp/antigravity/buffers/{cmd_id}.pid"
        

        
        # Re-using the logic but being careful with quoting
        import shlex
        wrapped_cmd = f"mkdir -p /tmp/antigravity/buffers && setsid bash -c {shlex.quote(command)} > {buffer_file} 2>&1 & echo $! > {pid_file}"
        
        self.execute(wrapped_cmd)
        log.info(f"Resilient session started: {cmd_id}")
        
        full_stdout = []
        last_offset = 0
        start_time = time.time()
        line_buffer = ""
        
        while time.time() - start_time < timeout:
            try:
                if not self.ensure_connected():
                    time.sleep(2)
                    continue
                
                # Check if process is still alive
                exit_code, pid_exists, _ = self.execute(f"kill -0 $(cat {pid_file} 2>/dev/null) 2>/dev/null && echo 'alive'")
                is_alive = "alive" in pid_exists
                
                # Fetch new lines from buffer starting at last_offset (byte-based)
                fetch_cmd = f"tail -c +{last_offset + 1} {buffer_file}"
                _, chunk, _ = self.execute(fetch_cmd)
                
                if chunk:
                    # Update offset by byte length
                    last_offset += len(chunk.encode("utf-8", errors="replace"))
                    line_buffer += chunk
                    while "\n" in line_buffer:
                        line, line_buffer = line_buffer.split("\n", 1)
                        line = line.rstrip("\r")
                        full_stdout.append(line)
                        if on_line:
                            on_line(line)
                
                if not is_alive:
                    # Final drain
                    _, final_chunk, _ = self.execute(f"tail -c +{last_offset + 1} {buffer_file}")
                    if final_chunk:
                        line_buffer += final_chunk
                        while "\n" in line_buffer:
                            line, line_buffer = line_buffer.split("\n", 1)
                            line = line.rstrip("\r")
                            full_stdout.append(line)
                            if on_line:
                                on_line(line)
                    if line_buffer:
                        # Print any remaining trailing data as a line
                        line = line_buffer.rstrip("\r")
                        full_stdout.append(line)
                        if on_line:
                            on_line(line)
                    break
                    
                time.sleep(2) # Polling interval for reconnection safety
                
            except Exception as e:
                log.warning(f"Resilient tailing flicker for {cmd_id}: {e}")
                time.sleep(3)
                
        # Success exit
        self.execute(f"rm -f {buffer_file} {pid_file}")
        return 0, "\n".join(full_stdout), ""

    def upload(self, local_path: str, remote_path: str):
        """Upload a file to the VPS."""
        if not self.client:
            self.connect()
        try:
            sftp = self.client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            return True
        except Exception as e:
            log.error(f"Upload failed: {e}")
            return False

    def download(self, remote_path: str, local_path: str):
        """Download a file from the VPS."""
        if not self.client:
            self.connect()
        try:
            sftp = self.client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            return True
        except Exception as e:
            log.error(f"Download failed: {e}")
            return False

    def remote_mkdir(self, path: str):
        """Ensure a directory structure exists on the VPS."""
        self.execute(f'mkdir -p "{path}"')

    def upload_content(self, content: str, remote_path: str):
        """Upload a raw string as a file to the VPS."""
        if not self.client:
            self.connect()
        try:
            dirname = os.path.dirname(remote_path)
            if dirname:
                self.remote_mkdir(dirname)
            sftp = self.client.open_sftp()
            with sftp.file(remote_path, 'w') as f:
                f.write(content)
            sftp.close()
            return True
        except Exception as e:
            log.error(f"Upload content failed: {e}")
            return False

    def check_vps_health(self) -> dict:
        """
        Pre-flight health check for the VPS.
        Returns: {"disk_pct": int, "mem_avail_mb": int, "healthy": bool, "issues": [str]}
        """
        from config import VPS_DISK_WARN_PCT, VPS_DISK_ABORT_PCT, VPS_MEM_LOW_MB

        health = {"disk_pct": 0, "mem_avail_mb": 9999, "healthy": True, "issues": []}

        # Disk check
        _, disk_out, _ = self.execute(
            "df /tmp 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%'"
        )
        try:
            health["disk_pct"] = int(disk_out.strip())
        except (ValueError, TypeError):
            pass

        if health["disk_pct"] >= VPS_DISK_ABORT_PCT:
            health["healthy"] = False
            health["issues"].append(
                f"CRITICAL: /tmp is {health['disk_pct']}% full (abort threshold: {VPS_DISK_ABORT_PCT}%)"
            )
        elif health["disk_pct"] >= VPS_DISK_WARN_PCT:
            health["issues"].append(
                f"WARNING: /tmp is {health['disk_pct']}% full (warn threshold: {VPS_DISK_WARN_PCT}%)"
            )

        # Memory check
        _, mem_out, _ = self.execute(
            "free -m 2>/dev/null | awk '/^Mem:/{print $7}'"
        )
        try:
            health["mem_avail_mb"] = int(mem_out.strip())
        except (ValueError, TypeError):
            pass

        if health["mem_avail_mb"] < VPS_MEM_LOW_MB:
            health["issues"].append(
                f"WARNING: Only {health['mem_avail_mb']}MB RAM available (threshold: {VPS_MEM_LOW_MB}MB)"
            )

        log.info(
            f"VPS Health: disk={health['disk_pct']}% mem={health['mem_avail_mb']}MB "
            f"{'HEALTHY' if health['healthy'] else 'UNHEALTHY'}"
        )
        return health

    def cleanup_stale_sessions(self):
        """
        Kill orphaned processes from previous crashed engagements.
        Removes zombie setsid processes and stale buffer files.
        """
        from config import VPS_ZOMBIE_AGE_MINUTES
        log.info("Cleaning up stale sessions from previous engagements...")

        # Kill processes with stale PID files
        cleanup_cmd = (
            f"find /tmp/antigravity/buffers/ -name '*.pid' -mmin +{VPS_ZOMBIE_AGE_MINUTES} "
            f"-exec sh -c 'kill -9 $(cat \"$1\" 2>/dev/null) 2>/dev/null; "
            f"rm -f \"$1\" \"$(echo $1 | sed s/.pid/.log/)\"' _ {{}} \\; 2>/dev/null; "
            f"echo 'cleanup_done'"
        )
        exit_code, out, _ = self.execute(cleanup_cmd, timeout=30)

        # Also remove any stale buffer logs older than the threshold
        self.execute(
            f"find /tmp/antigravity/buffers/ -name '*.log' -mmin +{VPS_ZOMBIE_AGE_MINUTES} "
            f"-delete 2>/dev/null; true",
            timeout=15
        )

        if "cleanup_done" in out:
            log.info("Stale session cleanup complete.")
        else:
            log.warning("Stale session cleanup may have failed.")

    def cleanup_tmp(self):
        """Emergency disk cleanup when /tmp is near full."""
        log.warning("Running emergency disk cleanup on VPS /tmp...")
        self.execute(
            "rm -rf /tmp/antigravity/buffers/*.log /tmp/antigravity/buffers/*.pid "
            "/tmp/nuclei*.zip /tmp/ffuf*.tar.gz /tmp/*.tmp 2>/dev/null; "
            "find /tmp/antigravity/results/ -name '*.json' -size +50M -delete 2>/dev/null; "
            "echo 'emergency_cleanup_done'",
            timeout=30
        )

    def close(self):
        if self.client:
            self.client.close()
            self.client = None
