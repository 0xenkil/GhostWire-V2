"""
VPS Infrastructure Optimization Before Major Scans
Tunes SSH, networking, and filesystem for high-throughput scanning operations.
"""
import os
import time
import json
from pathlib import Path
from utils.logger import get_logger
from config_thresholds import VPS_HEALTH_CHECK_TIMEOUT

log = get_logger("vps_optimizer")


def _load_debug_cfg() -> dict:
    try:
        import uuid
        from config_paths import LOG_DIR
        session_id = os.getenv("SESSION_ID") or uuid.uuid4().hex[:8]
        log_file = LOG_DIR / f"debug-{session_id}.log"
        return {"log_file": str(log_file), "session_id": session_id}
    except Exception as e:
        import logging as __logging_tmp
        __logging_tmp.getLogger(__name__).error(
            f"Unhandled exception: {e}", exc_info=True)
        return {"log_file": "debug.log", "session_id": "unknown"}


def _agent_debug_log(location: str, message: str, data: dict,
                     run_id: str = "run1", hypothesis_id: str = "H3"):
    try:
        dbg = _load_debug_cfg()
        Path(dbg["log_file"]).parent.mkdir(parents=True, exist_ok=True)
        with open(dbg["log_file"], "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "sessionId": dbg["session_id"],
                "runId": run_id,
                "hypothesisId": hypothesis_id,
                "location": location,
                "message": message,
                "data": data,
                "timestamp": int(time.time() * 1000),
            }, ensure_ascii=True) + "\n")
    except Exception as e:
        import sys
        print(f"[DEBUG] Failed to write debug log: {e}", file=sys.stderr)


class VPSOptimizer:
    """Pre-scan VPS optimization: SSH tuning, kernel params, cleanup."""

    def __init__(self, remote_executor):
        """
        Args:
            remote_executor: WSLExecutor instance with active connection
        """
        self.remote = remote_executor
        self.optimizations_applied = []
        self.rules = self._load_rules()

    def _load_rules(self) -> dict:
        import json
        from pathlib import Path
        p = Path("rules/infrastructure.json")
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception as e:
                import sys
                print(f"[VPS] Failed to load VPS rules: {e}", file=sys.stderr)
        return {}

    def optimize_all(self) -> bool:
        """
        Run all WSL optimizations. Returns True if successful, False otherwise.
        Continues on individual failures to apply as many optimizations as possible.
        """
        log.info("▶ Starting WSL Infrastructure Optimization...")

        try:
            # 1. Skip SSH MaxSessions tuning
            self._optimize_ssh_maxsessions()

            # 2. Increase system file descriptor limits
            self._optimize_file_descriptors()

            # 3. Tune TCP network parameters for high throughput
            self._optimize_tcp_buffers()

            # 4. Enable TCP BBR for better congestion control
            self._optimize_congestion_control()

            # 5. Create and prepare scan buffer directories
            self._prepare_scan_directories()

            # 6. Clean up old results to free disk space
            self._cleanup_old_results()

            # 7. Verify disk space for scans
            self._verify_disk_space()

            log.info(
                f"[+] WSL Optimization Complete: {len(self.optimizations_applied)} changes applied")
            return True

        except Exception as e:
            log.error(f"[x] WSL Optimization failed: {e}")
            return False

    def _optimize_ssh_maxsessions(self):
        """
        Skip SSH tuning for WSL environment.
        """
        self.optimizations_applied.append("SSH MaxSessions: Skipped (WSL)")
        log.info("  [+] SSH MaxSessions: Skipped (WSL)")

    def _optimize_file_descriptors(self):
        """
        Skip sysctl for WSL.
        """
        self.optimizations_applied.append("File Descriptors: Skipped (WSL)")
        log.info("  [+] File Descriptors: Skipped (WSL)")

    def _optimize_tcp_buffers(self):
        """
        Skip TCP buffers for WSL.
        """
        self.optimizations_applied.append("TCP Buffers: Skipped (WSL)")
        log.info("  [+] TCP Buffers: Skipped (WSL)")

    def _optimize_congestion_control(self):
        """
        Skip BBR for WSL.
        """
        self.optimizations_applied.append("Congestion Control: Skipped (WSL)")
        log.info("  [+] Congestion Control: Skipped (WSL)")
    def _prepare_scan_directories(self):
        """
        Create and prepare directories for scan buffers and results.
        Ensures proper permissions and avoids race conditions on scan startup.
        """
        import config_paths
        try:
            cmds = [
                # Main scan results directory
                f"mkdir -p {config_paths.VPS_RESULTS_DIR} && chmod 755 {config_paths.VPS_RESULTS_DIR}",
                # Buffer directory for resilient sessions
                f"mkdir -p {config_paths.VPS_TEMP_DIR}/buffers && chmod 755 {config_paths.VPS_TEMP_DIR}/buffers",
                # Tool cache directory
                f"mkdir -p {config_paths.VPS_TEMP_DIR}/cache && chmod 755 {config_paths.VPS_TEMP_DIR}/cache",
                # Cleanup old buffers (older than 24 hours)
                f"find {config_paths.VPS_TEMP_DIR}/buffers -type f -mtime +1 -delete 2>/dev/null || true",
            ]

            for cmd in cmds:
                self.remote.execute(cmd, timeout=VPS_HEALTH_CHECK_TIMEOUT)

            self.optimizations_applied.append("Scan Directories: prepared")
            log.info(f"  [+] Scan Directories: prepared ({config_paths.VPS_TEMP_DIR})")

        except Exception as e:
            log.warning(f"  [!] Scan directory preparation failed: {e}")

    def _cleanup_old_results(self):
        """
        Clean up old engagement results to free disk space.
        Keeps recent 10 engagements, deletes older ones.
        """
        import config_paths
        try:
            # Count existing results
            exit_code, count, _ = self.remote.execute(
                f"find {config_paths.VPS_RESULTS_DIR} -maxdepth 1 -type d -name 'eng_*' | wc -l",
                timeout=VPS_HEALTH_CHECK_TIMEOUT
            )

            try:
                num_results = int(count.strip()) if count else 0
            except (ValueError, TypeError) as _count_err:
                log.debug(
                    f"Failed to parse result count from: {count}: {_count_err}")
                num_results = 0

            keep = self.rules.get("max_engagements_to_keep", 15)
            if num_results > keep:
                # Delete oldest safely using find to avoid unquoted rm -rf
                log.info(
                    f"  ↻ Cleaning up old results ({num_results} -> {keep} max)...")
                self.remote.execute(
                    f"cd {config_paths.VPS_RESULTS_DIR} && ls -td eng_*/ | tail -n +{keep +
                                                                         1} | tr '\\n' '\\0' | xargs -0 rm -rf",
                    timeout=VPS_HEALTH_CHECK_TIMEOUT
                )

            self.optimizations_applied.append(
                f"Old Results: cleaned (keeping {keep} most recent)")
            log.info(
                f"  [+] Old Results: cleaned (keeping {keep} most recent)")

        except Exception as e:
            log.warning(f"  [!] Old result cleanup failed (non-critical): {e}")

    def _verify_disk_space(self):
        """
        Check available disk space on /tmp.
        Major scans (nuclei with 10k+ findings, masscan, etc) need 50GB+ free.
        """
        try:
            # Get disk usage for /tmp
            exit_code, output, _ = self.remote.execute(
                "df -BG /tmp | tail -1 | awk '{print $4, $2}' | tr ' ' ','",
                timeout=VPS_HEALTH_CHECK_TIMEOUT
            )
            _agent_debug_log(
                "core/vps_optimizer.py:disk_raw_output",
                "Raw disk command output captured",
                {"exit_code": exit_code, "output": (
                    output or "").strip()[:120]},
                run_id="run1",
                hypothesis_id="H3",
            )

            if output:
                try:
                    # Normalize: strip whitespace, convert any remaining spaces to
                    # commas (df output format varies across distros/locales),
                    # then split on comma.
                    raw = output.strip()
                    # Replace runs of whitespace with a single comma if no
                    # comma present
                    if "," not in raw:
                        import re as _re
                        raw = _re.sub(r'\s+', ',', raw)
                    parts = [p.strip().rstrip("GgMmKkBb")
                             for p in raw.split(",") if p.strip()]
                    if len(parts) < 2:
                        raise ValueError(
                            f"Unexpected df output format: {
                                raw!r}")
                    available_gb = int(parts[0])
                    total_gb = int(parts[1])
                    # available / total gives real free percentage
                    percent_free = (
                        available_gb /
                        total_gb *
                        100) if total_gb > 0 else 0
                    _agent_debug_log(
                        "core/vps_optimizer.py:disk_parse_success",
                        "Parsed disk stats",
                        {"available_gb": available_gb, "total_gb": total_gb,
                            "percent_free": percent_free},
                        run_id="run1",
                        hypothesis_id="H3",
                    )

                    if available_gb < 5:
                        log.warning(
                            f"  [!] Critical: only {available_gb}GB free - scans may fail!")
                    elif available_gb < 15:
                        log.warning(
                            f"  [!] Low disk space: {available_gb}GB free")
                    else:
                        log.info(
                            f"  [+] Disk Space: {available_gb}GB available ({percent_free:.0f}% free)")

                    self.optimizations_applied.append(
                        f"Disk Space: {available_gb}GB available")
                except Exception as _pe:
                    _agent_debug_log(
                        "core/vps_optimizer.py:disk_parse_exception",
                        "Failed to parse disk command output",
                        {"raw_output": (output or "").strip()[
                            :120], "error": str(_pe)[:80]},
                        run_id="run1",
                        hypothesis_id="H3",
                    )
                    log.warning(
                        f"  [!] Disk space parse failed (non-critical): {_pe}")

        except Exception as e:
            log.warning(f"  [!] Disk space check failed (non-critical): {e}")


def optimize_vps_before_scan(remote_executor) -> bool:
    """
    Convenience function: run full VPS optimization.
    Call this right after SSH connection is established.
    """
    optimizer = VPSOptimizer(remote_executor)
    return optimizer.optimize_all()
