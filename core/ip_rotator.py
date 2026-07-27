"""
core/ip_rotator.py

Manages Tor IP rotation and WAF-evasion proxying on the remote VPS.

Design:
- Sends NEWNYM to Tor's ControlPort to request a new circuit/exit IP.
- Verifies the new exit IP actually changed before proceeding.
- Tracks per-command request counts and auto-rotates when the threshold
  (from config or rules/infrastructure.json) is hit.
- Provides a `build_proxychains_cmd(tool_cmd)` helper that correctly wraps
  compound shell commands so only the tool binary is routed through proxychains4.
- All thresholds and timeouts are read from environment, config, or rules.
"""

import re
import time
import shlex
from pathlib import Path
from utils.logger import get_logger
from config_backends import TOR_SOCKS_PORT, TOR_CONTROL_PORT

log = get_logger("ip_rotator")


class IpRotator:
    """
    Manages Tor circuit rotation and proxychains injection on the remote VPS.
    All config (thresholds, ports, timeouts) comes from environment/config or rules.
    """

    def __init__(self, remote_executor, rules: dict | None = None):
        """
        Args:
            remote_executor: WSLExecutor instance with an active connection.
            rules: Pre-loaded infrastructure rules dict. If None, loaded from disk.
        """
        self._ssh = remote_executor
        self._rules = rules or self._load_rules()
        self._request_count = 0
        self._last_rotation_time = 0.0
        self._current_exit_ip: str | None = None
        self._tor_verified = False
        self._tor_disabled = False
        self._rotation_errors = 0
        import threading
        self._lock = threading.Lock()

    # ── Config ──────────────────────────────────────────────────────────────

    def _load_rules(self) -> dict:
        p = Path("rules/infrastructure.json")
        if p.exists():
            import json
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f'Swallowed exception in ip_rotator.py: {_e}')
        return {}

    @property
    def _rotate_every(self) -> int:
        return self._rules.get("ip_rotation_every_n_requests", 5)

    @property
    def _control_port(self) -> int:
        # Prefer environment/config values, then fall back to rules
        return TOR_CONTROL_PORT

    @property
    def _socks_port(self) -> int:
        # Prefer environment/config values, then fall back to rules
        return TOR_SOCKS_PORT

    @property
    def _rotation_timeout(self) -> int:
        return self._rules.get("ip_rotation_timeout_secs", 20)

    @property
    def _max_rotation_errors(self) -> int:
        return self._rules.get("ip_rotation_max_errors", 3)

    @property
    def _verify_ip_change(self) -> bool:
        return self._rules.get("ip_rotation_verify_change", True)

    # ── Core ────────────────────────────────────────────────────────────────

    def ensure_tor_ready(self) -> bool:
        """
        Verify Tor is installed, running, and listening on socks_port.
        Sets self._tor_verified = True on success.
        """
        if self._tor_verified:
            return True

        # Fail-fast: once we have determined Tor is unreachable/unroutable in
        # this engagement, never re-run the full ~50s probe (ss check + 4×10s
        # curl exit-IP checks). Without this, every caller that asks for Tor
        # readiness re-pays the whole timeout because _tor_verified stays False
        # — that was burning minutes at startup when Tor is down. Generic
        # short-circuit, not target-specific.
        if getattr(self, "_tor_disabled", False):
            return False

        # 1. Check socks port is listening
        import shlex
        quoted_socks_port = shlex.quote(str(self._socks_port))
        check_cmd = (
            f"ss -tlnp 2>/dev/null | grep -q ':{quoted_socks_port}' && echo SOCKS_OK || "
            f"nc -z 127.0.0.1 {quoted_socks_port} 2>/dev/null && echo SOCKS_OK || echo SOCKS_FAIL"
        )
        try:
            exit_code, out, _ = self._ssh.execute(check_cmd, timeout=10)
            if "SOCKS_OK" not in (out or ""):
                log.warning(
                    f"[IP-ROTATE] Tor SOCKS port {self._socks_port} not listening - trying to start...")
                self._ssh.execute(
                    "sudo systemctl restart tor || sudo service tor restart || (sudo killall tor; (sudo -u debian-tor tor || sudo -u tor tor || sudo -u toranon tor || tor) > /dev/null 2>&1 &)",
                    timeout=15
                )
                time.sleep(5)
                exit_code2, out2, _ = self._ssh.execute(check_cmd, timeout=10)
                if "SOCKS_OK" not in (out2 or ""):
                    log.error(
                        "[IP-ROTATE] Tor SOCKS port still not listening after start attempt.")
                    return False
        except Exception as e:
            log.error(f"[IP-ROTATE] Tor readiness check failed: {e}")
            return False

        # 2. Grab baseline exit IP
        self._current_exit_ip = self._get_exit_ip()
        if not self._current_exit_ip:
            log.warning(
                "[IP-ROTATE] Tor SOCKS port is listening, but we cannot route traffic (Tor likely blocked). Bypassing Tor.")
            self._tor_disabled = True
            self._tor_verified = False
            return False

        log.info(
            f"[IP-ROTATE] Tor ready. Current exit IP: {self._current_exit_ip}")
        self._tor_verified = True
        return True

    def should_rotate(self) -> bool:
        """Returns True when it's time to request a new circuit."""
        with self._lock:
            if self._rotation_errors >= self._max_rotation_errors:
                return False  # Too many failures - stop trying
            if self._rotate_every <= 0:
                return False  # Disabled
            self._request_count += 1
            return (self._request_count % self._rotate_every) == 0

    def rotate(self) -> bool:
        """
        Send NEWNYM to Tor's ControlPort to request a new exit circuit.
        Optionally verifies that the exit IP actually changed.
        Returns True on successful rotation.
        """
        if not self._tor_verified:
            if not self.ensure_tor_ready():
                return False

        log.info(
            f"[IP-ROTATE] Requesting new Tor circuit (request #{self._request_count})...")

        # Fallback: if we failed multiple times recently, try restarting tor
        # entirely
        with self._lock:
            rotation_errors = self._rotation_errors

        if rotation_errors >= 2:
            log.warning(
                f"[IP-ROTATE] Multiple rotation failures ({rotation_errors}). Restarting Tor service...")
            self._ssh.execute(
                "sudo systemctl restart tor || sudo service tor restart || (sudo killall tor; (sudo -u debian-tor tor || sudo -u tor tor || sudo -u toranon tor || tor) > /dev/null 2>&1 &)",
                timeout=15)
            time.sleep(5)
            with self._lock:
                self._rotation_errors = 0
                self._tor_verified = False  # force re-verify
            if not self.ensure_tor_ready():
                return False

        # Send NEWNYM via python script to be completely shell-agnostic and
        # avoid echo/printf parsing issues
        py_script = (
            f"import socket; "
            f"s = socket.socket(); "
            f"s.settimeout(5); "
            f"s.connect(('127.0.0.1', {shlex.quote(str(self._control_port))})); "
            f"s.sendall(b'AUTHENTICATE \\\"\\\"\\r\\nSIGNAL NEWNYM\\r\\nQUIT\\r\\n'); "
            f"print(s.recv(1024).decode())"
        )
        newnym_cmd = f"python3 -c \"{py_script}\" 2>/dev/null"

        try:
            exit_code, out, _ = self._ssh.execute(
                newnym_cmd, timeout=self._rotation_timeout)
            out_lower = (out or "").lower()

            if "250 ok" not in out_lower and "250-ok" not in out_lower:
                log.warning(
                    f"[IP-ROTATE] NEWNYM response unexpected: {(out or '').strip()[:80]}")
                with self._lock:
                    self._rotation_errors += 1
                return False

            # Tor needs a few seconds to build the new circuit
            time.sleep(self._rules.get("ip_rotation_settle_secs", 4))

            if self._verify_ip_change:
                new_ip = self._get_exit_ip()
                if new_ip and new_ip == self._current_exit_ip:
                    log.warning(
                        f"[IP-ROTATE] Exit IP unchanged after NEWNYM ({new_ip}). Circuit may be slow.")
                elif new_ip:
                    log.info(
                        f"[IP-ROTATE] [+] Exit IP rotated: {self._current_exit_ip} -> {new_ip}")
                    self._current_exit_ip = new_ip
                else:
                    log.warning(
                        "[IP-ROTATE] Could not verify new exit IP (connectivity issue).")

            with self._lock:
                self._last_rotation_time = time.time()
                self._rotation_errors = 0
            return True

        except Exception as e:
            log.error(f"[IP-ROTATE] Circuit rotation failed: {e}")
            with self._lock:
                self._rotation_errors += 1
            return False

    def rotate_if_due(self) -> None:
        """Convenience: check and rotate in one call. Silently skips on error."""
        if self.should_rotate():
            self.rotate()

    # ── proxychains command builder ─────────────────────────────────────────

    def build_proxychains_cmd(self, command: str) -> str:
        """
        Wrap the tool portion of a compound shell command with proxychains4.

        Correctly handles compound commands like:
            export PATH=... && export A=b && nuclei -u https://target.com

        Only the actual tool invocation is proxied, not the env exports.
        If proxychains4 is already present, returns command unchanged.
        """
        if getattr(self, '_tor_disabled', False):
            return command  # Tor is non-functional, bypass wrapping

        if "proxychains4 " in command:
            return command  # Already wrapped

        segments = [s.strip() for s in re.split(r'\s*&&\s*', command)]
        env_segments: list[str] = []
        tool_segments: list[str] = []
        in_env = True

        for seg in segments:
            if in_env and (
                seg.startswith("export ") or
                re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', seg)
            ):
                env_segments.append(seg)
            else:
                in_env = False

                # Split a pipeline so EACH process is proxied — but ONLY on a
                # GENUINE shell pipe. A literal '|' inside an argument (a git
                # --pretty=format:"%h | %s", an awk/sed script, a regex) must NOT
                # be split: doing so inserted `proxychains4 -q` mid-argument and
                # corrupted the command (e.g. git: unknown option
                # 'pretty=format:%h %ad | proxychains4 -q %s'). A real pipeline
                # stage starts with a command word; a literal pipe is followed by
                # non-command text (%s, a quote, a bracket) — glue those back.
                _local = {"grep", "awk", "cut", "tee", "jq", "cat", "echo", "sed",
                          "sort", "uniq", "tr", "wc", "xargs", "head", "tail", "ls", "find"}
                pipe_segments: list[str] = []
                for idx, p_seg in enumerate(seg.split('|')):
                    p_seg = p_seg.strip()
                    if not p_seg:
                        continue
                    bin_name = p_seg.split()[0]
                    looks_like_cmd = bool(re.match(r'^[a-zA-Z][\w./-]*$', bin_name))
                    if idx > 0 and not looks_like_cmd:
                        # literal pipe inside an argument — re-join, do not wrap
                        if pipe_segments:
                            pipe_segments[-1] = pipe_segments[-1] + " | " + p_seg
                        else:
                            pipe_segments.append(p_seg)
                        continue
                    if bin_name in _local:
                        pipe_segments.append(p_seg)
                    else:
                        pipe_segments.append(f"proxychains4 -q {p_seg}")

                tool_segments.append(" | ".join(pipe_segments))

        all_segs = env_segments + tool_segments
        return " && ".join(
            all_segs) if all_segs else f"proxychains4 -q {command}"

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _get_exit_ip(self) -> str | None:
        """Query current Tor exit IP using a fast API endpoint via raw SOCKS proxy."""
        ip_sources = [
            "https://api.ipify.org",
            "https://icanhazip.com",
            "https://ifconfig.me/ip",
            "https://ident.me",
        ]
        for src in ip_sources:
            try:
                # Bypass proxychains completely to avoid external config issues,
                # and run a direct curl through Tor SOCKS port.
                import shlex
                quoted_socks_port = shlex.quote(str(self._socks_port))
                quoted_src = shlex.quote(src)
                curl_cmd = f"curl -s --socks5-hostname 127.0.0.1:{quoted_socks_port} --max-time 10 {quoted_src} 2>/dev/null"
                exit_code, out, _ = self._ssh.execute(curl_cmd, timeout=15)

                if exit_code == 0 and out:
                    ip = out.strip()
                    # Basic IP validation (IPv4 regex)
                    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
                        return ip
            except Exception as e:
                log.debug(
                    f"[IP-ROTATE] Failed to fetch IP from {src} via Tor SOCKS: {e}")
                continue
        return None

    @property
    def exit_ip(self) -> str | None:
        """Current known exit IP (may be stale if rotation wasn't verified)."""
        with self._lock:
            return self._current_exit_ip

    @property
    def request_count(self) -> int:
        with self._lock:
            return self._request_count

    @property
    def rotation_errors(self) -> int:
        with self._lock:
            return self._rotation_errors
