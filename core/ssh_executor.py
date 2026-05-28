import paramiko
import socket
import os
import time
import threading
import uuid
import shlex
from utils.logger import get_logger
from utils.sanitizer import clean_text
from config import VPS_HOST, VPS_USER, VPS_KEY_PATH
from config_paths import VPS_TEMP_DIR, VPS_RESULTS_DIR
from config_thresholds import (
    TOOL_DEFAULT_TIMEOUT, 
    SSH_CONNECT_TIMEOUT, 
    SSH_BANNER_TIMEOUT, 
    SSH_AUTH_TIMEOUT,
    MAX_COMMAND_RETRIES,
    VPS_HEALTH_CHECK_TIMEOUT,
    SSH_RECONNECT_DELAY,
    SSH_STREAM_POLL_DELAY,
    SSH_RESILIENT_PID_WAIT,
    SSH_RESILIENT_POLL_INTERVAL,
    SSH_RESILIENT_ERROR_WAIT
)
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
        """Establish SSH connection to the VPS (reuses if active).
        FIX #3.3: Added explicit socket timeout to prevent indefinite hangs.
        """
        with self._connect_lock:
            # OPTIMIZATION: Reuse existing connection if still active (avoid recreating)
            if self.is_active():
                log.debug("SSH connection already active, reusing...")
                return True
            
            try:
                log.info(f"Connecting to {self.user}@{self.host}...")
                if self.client:
                    try:
                        self.client.close()
                    except Exception as e:
                        log.debug(f"Error closing client: {e}")
                
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # FIX #3.3: Set socket timeout to prevent indefinite hangs on network issues
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(SSH_CONNECT_TIMEOUT)  # Socket-level timeout
                
                try:
                    sock.connect((self.host, 22))  # SSH default port
                    log.debug(f"Socket connection established to {self.host}:22 within {SSH_CONNECT_TIMEOUT}s")
                except socket.timeout:
                    sock.close()
                    log.error(f"Socket timeout connecting to {self.host}:22 after {SSH_CONNECT_TIMEOUT}s")
                    raise socket.timeout(f"SSH socket timeout after {SSH_CONNECT_TIMEOUT}s")
                except socket.error as e:
                    sock.close()
                    log.error(f"Socket connection failed to {self.host}:22: {e}")
                    raise e

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
                    sock.close()
                    raise ValueError(f"File at {self.key_path} is not a valid or supported private key.")

                for retry in range(MAX_COMMAND_RETRIES):
                    try:
                        # FIX #3.3: Use sock_extra parameter if available, otherwise create fresh connection
                        self.client.connect(
                            hostname=self.host,
                            username=self.user,
                            pkey=key,
                            sock=sock if retry == 0 else None,  # Use socket for first attempt
                            timeout=SSH_CONNECT_TIMEOUT,  # Connection timeout
                            banner_timeout=SSH_BANNER_TIMEOUT,  # Banner timeout
                            allow_agent=False,
                            look_for_keys=False,
                            auth_timeout=SSH_AUTH_TIMEOUT  # Auth timeout
                        )
                        break
                    except (paramiko.ssh_exception.SSHException, socket.error, EOFError) as e:
                        if any(x in str(e).lower() for x in ["banner", "eof", "reset", "timeout"]) or isinstance(e, EOFError):
                            if retry < MAX_COMMAND_RETRIES - 1:
                                wait = 2 ** retry
                                log.warning(f"SSH banner/protocol error (attempt {retry+1}/{MAX_COMMAND_RETRIES}). Retrying in {wait}s...")
                                time.sleep(wait)
                                if retry > 0:  # Create new socket for retry
                                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                    sock.settimeout(SSH_CONNECT_TIMEOUT)
                                continue
                        # FIX #3.3: Close socket on error
                        try:
                            sock.close()
                        except Exception as e:
                            log.debug(f"Error closing socket: {e}")
                        raise e

                transport = self.client.get_transport()
                if transport:
                    transport.set_keepalive(15) # Hardened keep-alive

                log.info("SSH connection established.")
                return True
            except socket.timeout as e:
                log.error(f"SSH connection timeout after {SSH_CONNECT_TIMEOUT}s: {e}")
                self.client = None
                return False
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

    def execute(self, command: str, timeout: int = TOOL_DEFAULT_TIMEOUT) -> tuple[int, str, str]:
        """
        Execute a command on the VPS - blocking, returns (exit_code, stdout, stderr).
        Lock-free for parallel execution. Only reconnects use _connect_lock.
        Includes single retry on channel loss.
        CRITICAL: Sets socket timeout on channel to respect long-running operations (nuclei, masscan).
        """
        if not self.ensure_connected():
            return -1, "", "SSH connection failed"

        for attempt in range(2):  # 1 retry on channel loss
            try:
                self.last_command = command
                log.debug(f"Executing: {command[:120]}")
                stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
                
                # CRITICAL FIX: Set socket timeout on channels to allow long-running commands
                # Without this, Paramiko defaults to shorter timeout, causing nuclei/masscan to fail
                stdout.channel.settimeout(timeout)
                stderr.channel.settimeout(timeout)

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
                    time.sleep(SSH_RECONNECT_DELAY)
                    if not self.connect():
                        return -1, "", "SSH channel failed after reconnect attempt"
                else:
                    return -1, "", f"SSH channel failed after reconnect attempt: {e}"

            except socket.timeout as e:
                # socket.timeout always means timeout - no need to re-check isinstance
                return -2, "", f"TIMEOUT: {e}"
            except Exception as e:
                log.error(f"Unexpected SSH error: {e}")
                return -1, "", str(e)

        return -1, "", "SSH execute exhausted retries"

    def execute_streaming(self, command: str, timeout: int = TOOL_DEFAULT_TIMEOUT,
                           on_line=None) -> tuple[int, str, str]:
        """
        Execute a command with REAL-TIME streaming output.
        Calls on_line(line: str) for each stdout line as it arrives.
        Returns (exit_code, full_stdout, full_stderr) when done.

        V2: Lock-free - only uses _connect_lock for auth, allowing parallel
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
                        time.sleep(SSH_RECONNECT_DELAY)
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
                        if hasattr(self, "log"):
                            self.log.error("Exception caught", exc_info=True)
                        else:
                            import logging
                            logging.error("Exception caught", exc_info=True)
                        raise
                    except Exception as e:
                        log.error(f"Stream error: {e}")
                        break

                    time.sleep(SSH_STREAM_POLL_DELAY)

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
                    time.sleep(SSH_RECONNECT_DELAY)
                    if not self.connect():
                        return -1, "", "SSH channel failed after reconnect attempt"
                else:
                    return -1, "", f"SSH streaming failed after retry: {e}"
            except Exception as e:
                log.error(f"Streaming execute error: {e}")
                return -1, "", str(e)

        return -1, "", "SSH streaming exhausted retries"

    def execute_tmux(self, command: str, session_name: str, timeout: int = TOOL_DEFAULT_TIMEOUT) -> tuple[int, str, str]:
        """
        Execute a command within a detached Tmux session for interactive sandbox support.
        """
        if not self.ensure_connected():
            return -1, "", "SSH connection failed"

        # Check if tmux is installed
        exit_code, _, _ = self.execute("which tmux")
        if exit_code != 0:
            log.warning("tmux is not installed on the VPS, falling back to execute_resilient")
            return self.execute_resilient(command, timeout)

        # Kill existing session if it exists
        self.execute(f"tmux kill-session -t {session_name} 2>/dev/null", timeout=10)

        # Start a new detached tmux session running the command and saving the output
        log.info(f"Starting Tmux session '{session_name}' for command: {command[:50]}")
        cmd_id = str(uuid.uuid4())[:8]
        buffer_file = f"{VPS_TEMP_DIR}/buffers/tmux_{cmd_id}.log"
        status_file = f"{VPS_TEMP_DIR}/buffers/tmux_{cmd_id}.status"

        self.execute(f"mkdir -p {VPS_TEMP_DIR}/buffers", timeout=10)
        
        # Wrapped command saves exit code and outputs to buffer
        wrapped = f"{command} | tee {buffer_file}; echo $? > {status_file}"
        tmux_cmd = f"tmux new-session -d -s {session_name} {shlex.quote(wrapped)}"
        
        ec, out, err = self.execute(tmux_cmd, timeout=10)
        if ec != 0:
            return ec, out, f"Tmux launch failed: {err}"
            
        start_time = time.time()
        while time.time() - start_time < timeout:
            # Check if tmux session is still alive
            alive_code, _, _ = self.execute(f"tmux has-session -t {session_name} 2>/dev/null", timeout=10)
            if alive_code != 0:
                # Session ended
                _, out_data, _ = self.execute(f"cat {buffer_file} 2>/dev/null", timeout=10)
                stat_code, stat_data, _ = self.execute(f"cat {status_file} 2>/dev/null", timeout=10)
                final_ec = int(stat_data.strip()) if stat_code == 0 and stat_data.strip().isdigit() else 0
                self.execute(f"rm -f {buffer_file} {status_file}", timeout=10)
                return final_ec, out_data, ""
            time.sleep(SSH_RESILIENT_POLL_INTERVAL)
            
        # Timeout reached, kill session
        self.execute(f"tmux kill-session -t {session_name} 2>/dev/null", timeout=10)
        _, out_data, _ = self.execute(f"cat {buffer_file} 2>/dev/null", timeout=10)
        self.execute(f"rm -f {buffer_file} {status_file}", timeout=10)
        return -2, out_data, "Timeout reached"

    def execute_resilient(self, command: str, timeout: int = TOOL_DEFAULT_TIMEOUT, on_line=None) -> tuple[int, str, str]:
        """
        Execute a command with autonomous reconnection and persistence.
        Writes output to a VPS buffer and tails it. Survives SSH resets (10054).
        
        FIXES APPLIED:
        - Kill-on-timeout cleanup (prevents zombie processes)
        - PID file wait loop (prevents race condition)
        - Line-number tracking (prevents UTF-8 corruption)
        - Short timeouts on child execute() calls (prevents cascade hangs)
        """
        cmd_id = str(uuid.uuid4())[:8]
        buffer_file = f"{VPS_TEMP_DIR}/buffers/{cmd_id}.log"
        pid_file = f"{VPS_TEMP_DIR}/buffers/{cmd_id}.pid"
        status_file = f"{VPS_TEMP_DIR}/buffers/{cmd_id}.status"
        
        # Pre-allocate buffer files (avoids race condition on first poll)
        # NOTE: shlex is imported at module level - do NOT re-import here
        prealloc_cmd = (
            f"mkdir -p {VPS_TEMP_DIR}/buffers && "
            f"touch {buffer_file} {pid_file} {status_file} && "
            f"chmod 666 {buffer_file} {pid_file} {status_file}"
        )
        exit_code, _, _ = self.execute(prealloc_cmd, timeout=TOOL_DEFAULT_TIMEOUT)
        if exit_code != 0:
            log.warning(f"Failed to pre-allocate buffer for {cmd_id}, continuing anyway...")
        
        # Spawn timeout: use 30% of total timeout for spawn phase, but at least 30s
        spawn_timeout = max(30, int(timeout * 0.30))
        
        # Wrapped command with explicit output redirection and persisted exit code.
        wrapped_inner = f"{command}; ec=$?; echo $ec > {status_file}; exit $ec"
        wrapped_cmd = f"setsid bash -c {shlex.quote(wrapped_inner)} >{buffer_file} 2>&1 & echo $! >{pid_file}"
        
        # Retry spawn with exponential backoff
        spawn_pid = None
        for spawn_attempt in range(3):
            exit_code, _, err = self.execute(wrapped_cmd, timeout=spawn_timeout)
            if exit_code == 0:
                log.info(f"Resilient session {cmd_id} spawned (attempt {spawn_attempt + 1}/3)")
                break
            else:
                if spawn_attempt < 2:
                    backoff_time = 2 ** spawn_attempt
                    log.warning(f"Resilient spawn failed (attempt {spawn_attempt + 1}/3): {err[:100]}. Retrying in {backoff_time}s...")
                    time.sleep(backoff_time)
                else:
                    log.error(f"Failed to start resilient session {cmd_id} after 3 attempts: {err[:200]}")
                    return -1, "", f"Failed to spawn resilient command: {err}"
        
        # FIX #1: Wait for PID file to be written (race condition prevention)
        pid_wait_attempts = 0
        while pid_wait_attempts < 10:
            try:
                exit_code, pid_content, _ = self.execute(f"cat {pid_file}", timeout=VPS_HEALTH_CHECK_TIMEOUT)
                spawn_pid = pid_content.strip()
                if spawn_pid and spawn_pid.isdigit():
                    log.info(f"Resilient session {cmd_id} confirmed with PID {spawn_pid}")
                    break
            except Exception as e:
                log.debug(f"Failed to check PID: {e}")
            pid_wait_attempts += 1
            time.sleep(SSH_RESILIENT_PID_WAIT)
        
        if not spawn_pid:
            log.error(f"Could not retrieve PID for {cmd_id}, aborting")
            return -1, "", "Failed to retrieve process PID"
        
        log.info(f"Resilient session {cmd_id} launched, tailing output...")
        
        full_stdout = []
        last_line_num = 0
        start_time = time.time()
        line_buffer = ""
        final_exit_code = -1
        
        # FIX #3: Short timeouts on child execute() calls prevent cascade hangs
        CHILD_TIMEOUT = VPS_HEALTH_CHECK_TIMEOUT
        
        while time.time() - start_time < timeout:
            try:
                if not self.ensure_connected():
                    time.sleep(SSH_RESILIENT_ERROR_WAIT)
                    continue
                
                # FIX #2: Line-number tracking instead of byte offsets (UTF-8 safe)
                # Check if process is still alive using PID
                exit_code, _, _ = self.execute(f"kill -0 {spawn_pid} 2>/dev/null && echo 'alive'", timeout=CHILD_TIMEOUT)
                is_alive = exit_code == 0
                
                # FIX #2: Use line-based tail instead of byte-based
                if last_line_num == 0:
                    # First read: use cat below to get all lines
                    pass
                if last_line_num > 0:
                    fetch_cmd = f"sed -n '{last_line_num + 1},$p' {buffer_file}"
                else:
                    fetch_cmd = f"cat {buffer_file}"
                
                exit_code, chunk, _ = self.execute(fetch_cmd, timeout=CHILD_TIMEOUT)
                
                if chunk:
                    lines = chunk.split("\n")
                    # All but the last segment are "complete" lines (ended with \n in the file)
                    for i, line in enumerate(lines[:-1]):
                        if "\r" in line:
                            line = line.split("\r")[-1]
                        
                        line = line.strip()
                        if not line:
                            last_line_num += 1
                            continue
                            
                        full_stdout.append(line)
                        if on_line:
                            on_line(line)
                        last_line_num += 1
                    
                    # Handle the last segment (could be partial or a progress update without \n)
                    last_segment = lines[-1]
                    if last_segment:
                        display_segment = last_segment.split("\r")[-1] if "\r" in last_segment else last_segment
                        display_str = display_segment.strip()
                        
                        if on_line and display_str:
                            # Avoid printing the exact same progress string repeatedly
                            if not hasattr(self, "_last_printed_progress"):
                                self._last_printed_progress = ""
                            if display_str != self._last_printed_progress:
                                on_line(display_str)
                                self._last_printed_progress = display_str
                
                if not is_alive:
                    # Final drain: get any remaining lines
                    fetch_cmd = f"sed -n '{last_line_num + 1},$p' {buffer_file}"
                    _, final_chunk, _ = self.execute(fetch_cmd, timeout=CHILD_TIMEOUT)
                    
                    if final_chunk:
                        for line in final_chunk.split("\n"):
                            if "\r" in line:
                                line = line.split("\r")[-1]
                            line = line.rstrip("\r").strip()
                            if line:
                                full_stdout.append(line)
                                if on_line:
                                    on_line(line)
                    
                    log.info(f"Resilient session {cmd_id} completed, {len(full_stdout)} lines captured")
                    code_exit, code_out, _ = self.execute(f"cat {status_file} 2>/dev/null", timeout=CHILD_TIMEOUT)
                    if code_exit == 0 and code_out.strip().lstrip("-").isdigit():
                        final_exit_code = int(code_out.strip())
                    else:
                        final_exit_code = -1
                    break
                
                time.sleep(SSH_RESILIENT_POLL_INTERVAL)  # Polling interval
                
            except Exception as e:
                log.warning(f"Resilient tailing flicker for {cmd_id}: {e}")
                time.sleep(SSH_RESILIENT_ERROR_WAIT)
        
        else:
            # FIX #4: Kill-on-timeout cleanup (prevents zombie accumulation)
            log.warning(f"Resilient session {cmd_id} exceeded timeout of {timeout}s, killing process group {spawn_pid}")
            try:
                # Use kill -9 -PID to kill the entire process group created by setsid, preventing orphaned tools.
                self.execute(f"kill -9 -{spawn_pid} 2>/dev/null || kill -9 {spawn_pid} 2>/dev/null", timeout=CHILD_TIMEOUT)
                time.sleep(SSH_RESILIENT_PID_WAIT)
                # Verify kill
                exit_code, _, _ = self.execute(f"kill -0 {spawn_pid} 2>/dev/null", timeout=CHILD_TIMEOUT)
                if exit_code != 0:
                    log.info(f"Process group {spawn_pid} successfully terminated")
            except Exception as e:
                log.error(f"Failed to kill process {spawn_pid}: {e}")
            final_exit_code = -2
        
        # Cleanup buffer files
        try:
            self.execute(f"rm -f {buffer_file} {pid_file} {status_file}", timeout=CHILD_TIMEOUT)
        except Exception as e:
            log.debug(f"Cleanup buffer files failed: {e}")
        
        return final_exit_code, "\n".join(full_stdout), ""

    def upload(self, local_path: str, remote_path: str):
        """Upload a file to the VPS."""
        if not self.client:
            self.connect()
        sftp = None
        try:
            sftp = self.client.open_sftp()
            sftp.put(local_path, remote_path)
            return True
        except Exception as e:
            log.error(f"Upload failed: {e}")
            return False
        finally:
            if sftp:
                try:
                    sftp.close()
                except Exception as e:
                    log.warning(f"SFTP close error (non-fatal): {e}")

    def download(self, remote_path: str, local_path: str):
        """Download a file from the VPS."""
        if not self.client:
            self.connect()
        sftp = None
        try:
            sftp = self.client.open_sftp()
            sftp.get(remote_path, local_path)
            return True
        except Exception as e:
            log.error(f"Download failed: {e}")
            return False
        finally:
            if sftp:
                try:
                    sftp.close()
                except Exception as e:
                    log.warning(f"SFTP close error (non-fatal): {e}")

    def remote_mkdir(self, path: str):
        """Ensure a directory structure exists on the VPS."""
        self.execute(f'mkdir -p "{path}"')

    def upload_content(self, content: str, remote_path: str):
        """Upload a raw string as a file to the VPS."""
        if not self.client:
            self.connect()
        sftp = None
        try:
            dirname = os.path.dirname(remote_path)
            if dirname:
                self.remote_mkdir(dirname)
            sftp = self.client.open_sftp()
            with sftp.file(remote_path, 'w') as f:
                f.write(content)
            return True
        except Exception as e:
            log.error(f"Upload content failed: {e}")
            return False
        finally:
            if sftp:
                try:
                    sftp.close()
                except Exception as e:
                    log.warning(f"SFTP close error (non-fatal): {e}")

    def check_vps_health(self) -> dict:
        """
        Pre-flight health check for the VPS.
        Returns: {"disk_pct": int, "mem_avail_mb": int, "cpu_load": float, "services": dict, "healthy": bool, "issues": [str]}
        """
        from config import VPS_DISK_WARN_PCT, VPS_DISK_ABORT_PCT, VPS_MEM_LOW_MB

        health = {
            "disk_pct": 0, 
            "mem_avail_mb": 9999, 
            "cpu_load": 0.0,
            "services": {"sshd": True, "tor": True},
            "healthy": True, 
            "issues": []
        }

        # 1. Disk check
        _, disk_out, _ = self.execute(
            f"df {VPS_TEMP_DIR} 2>/dev/null | awk 'NR==2{{print $5}}' | tr -d '%'"
        )
        try:
            health["disk_pct"] = int(disk_out.strip())
        except (ValueError, TypeError) as e:
            log.debug(f"Disk check parsing failed: {e}")

        if health["disk_pct"] >= VPS_DISK_ABORT_PCT:
            health["healthy"] = False
            health["issues"].append(
                f"CRITICAL: {VPS_TEMP_DIR} is {health['disk_pct']}% full (abort threshold: {VPS_DISK_ABORT_PCT}%)"
            )
        elif health["disk_pct"] >= VPS_DISK_WARN_PCT:
            health["issues"].append(
                f"WARNING: {VPS_TEMP_DIR} is {health['disk_pct']}% full (warn threshold: {VPS_DISK_WARN_PCT}%)"
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
                f"WARNING: Only {health['mem_avail_mb']}MB RAM available (threshold: {VPS_MEM_LOW_MB}MB)"
            )

        # 3. CPU Load check (1-minute average)
        _, cpu_out, _ = self.execute("uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1")
        try:
            health["cpu_load"] = float(cpu_out.strip())
            if health["cpu_load"] > 10.0:  # Arbitrary high load threshold
                 health["issues"].append(f"WARNING: High CPU load: {health['cpu_load']}")
        except (ValueError, TypeError) as e:
            log.debug(f"CPU load parsing failed: {e}")

        # 4. Service status checks
        for svc in ["sshd", "tor"]:
            exit_code, _, _ = self.execute(f"systemctl is-active {svc} --quiet 2>/dev/null || ps aux | grep -v grep | grep -q {svc}")
            is_active = (exit_code == 0)
            health["services"][svc] = is_active
            if not is_active:
                # Tor failure is critical if TOR_ENABLED is true
                from config_backends import TOR_ENABLED
                if svc == "tor" and TOR_ENABLED:
                    health["healthy"] = False
                    health["issues"].append(f"CRITICAL: Service '{svc}' is DOWN but TOR_ENABLED=true")
                else:
                    health["issues"].append(f"WARNING: Service '{svc}' is DOWN")

        log.debug(
            f"VPS Health: disk={health['disk_pct']}% mem={health['mem_avail_mb']}MB "
            f"cpu={health['cpu_load']} healthy={health['healthy']}"
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
            f"find {VPS_TEMP_DIR}/buffers/ -name '*.pid' -mmin +{VPS_ZOMBIE_AGE_MINUTES} "
            f"-exec sh -c 'kill -9 $(cat \"$1\" 2>/dev/null) 2>/dev/null; "
            f"rm -f \"$1\" \"$(echo $1 | sed s/.pid/.log/)\"' _ {{}} \\; 2>/dev/null; "
            f"echo 'cleanup_done'"
        )
        exit_code, out, _ = self.execute(cleanup_cmd, timeout=TOOL_DEFAULT_TIMEOUT)

        # Also remove any stale buffer logs older than the threshold
        self.execute(
            f"find {VPS_TEMP_DIR}/buffers/ -name '*.log' -mmin +{VPS_ZOMBIE_AGE_MINUTES} "
            f"-delete 2>/dev/null; true",
            timeout=TOOL_DEFAULT_TIMEOUT
        )

        if "cleanup_done" in out:
            log.info("Stale session cleanup complete.")
        else:
            log.warning("Stale session cleanup may have failed.")

    def cleanup_tmp(self):
        """Emergency disk cleanup when temp dir is near full."""
        log.warning(f"Running emergency disk cleanup on VPS {VPS_TEMP_DIR}...")
        self.execute(
            f"rm -rf {VPS_TEMP_DIR}/buffers/*.log {VPS_TEMP_DIR}/buffers/*.pid "
            f"{VPS_TEMP_DIR}/nuclei*.zip {VPS_TEMP_DIR}/ffuf*.tar.gz {VPS_TEMP_DIR}/*.tmp 2>/dev/null; "
            f"find {VPS_RESULTS_DIR}/ -name '*.json' -size +50M -delete 2>/dev/null; "
            f"echo 'emergency_cleanup_done'",
            timeout=TOOL_DEFAULT_TIMEOUT
        )

    def close(self):
        """Close SSH connection and clean up resources properly."""
        with self._lock:
            try:
                if self.client:
                    transport = self.client.get_transport()
                    if transport:
                        # Properly close all channels before closing transport
                        pass
                    try:
                        self.client.close()
                    except Exception as e:
                        log.debug(f"Error closing client: {e}")
                    log.debug("SSH connection closed and resources freed")
            except Exception as e:
                log.debug(f"Error closing SSH: {e}")
            finally:
                self.client = None
