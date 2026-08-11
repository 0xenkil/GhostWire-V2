"""
VPS Infrastructure Optimization Before Major Scans
Tunes SSH, networking, and filesystem for high-throughput scanning operations.
"""
from utils.logger import get_logger
from config_thresholds import VPS_HEALTH_CHECK_TIMEOUT

log = get_logger("vps_optimizer")

# P5-3 (D-VPS-1, VPS-OPT-STUBBED): the _load_debug_cfg / _agent_debug_log pair
# (a hardcoded run1/H3 debug side-channel that wrote JSON lines to a separate
# debug-<session>.log) was removed — diagnostics now go through the normal
# logger. The four no-op "_optimize_*" WSL methods that only appended
# "Skipped (WSL)" strings were also deleted; optimize_all() keeps only the
# three that do real remote work (dirs / cleanup / disk check).


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
            # Create and prepare scan buffer directories
            self._prepare_scan_directories()

            # Clean up old results to free disk space
            self._cleanup_old_results()

            # Verify disk space for scans
            self._verify_disk_space()

            log.info(
                f"[+] WSL Optimization Complete: {len(self.optimizations_applied)} changes applied")
            return True

        except Exception as e:
            log.error(f"[x] WSL Optimization failed: {e}")
            return False

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
            log.debug(
                f"disk raw output: exit={exit_code} "
                f"out={(output or '').strip()[:120]!r}")

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
                    log.debug(
                        f"parsed disk stats: available={available_gb}GB "
                        f"total={total_gb}GB free={percent_free:.0f}%")

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
                    log.warning(
                        f"  [!] Disk space parse failed (non-critical): {_pe} "
                        f"(raw={(output or '').strip()[:120]!r})")

        except Exception as e:
            log.warning(f"  [!] Disk space check failed (non-critical): {e}")


def optimize_vps_before_scan(remote_executor) -> bool:
    """
    Convenience function: run full VPS optimization.
    Call this right after SSH connection is established.
    """
    optimizer = VPSOptimizer(remote_executor)
    return optimizer.optimize_all()
