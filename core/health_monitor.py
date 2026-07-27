import threading
from utils.logger import get_logger

log = get_logger("health_monitor")


class HealthMonitor:
    def __init__(self, remote=None, store=None, engagement_id: str = "global"):
        self.remote = remote
        self.store = store
        self.engagement_id = engagement_id
        self._stop_event = threading.Event()
        self._thread = None
        self._health_status = {
            "healthy": True,
            "disk_pct": 0,
            "cpu_load": 0.0,
            "issues": []}
        self._abort_flag = False

    def start(self):
        if not self._thread:
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._monitor_loop, daemon=True)
            self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            if self.remote and getattr(
                    self.remote, 'is_active', lambda: False)():
                try:
                    # Check disk usage
                    code, out, _ = self.remote.execute(
                        "df -h / | awk 'NR==2 {print $5}' | sed 's/%//'", timeout=10)
                    if code == 0 and out.strip().isdigit():
                        pct = int(out.strip())
                        self._health_status["disk_pct"] = pct
                        if pct > 95:
                            self._abort_flag = True
                            self._health_status["issues"].append(
                                f"CRITICAL: Disk full ({pct}%)")
                            log.error(
                                f"Health Monitor: Disk at {pct}%. Triggering abort.")

                    # Check load
                    code, out, _ = self.remote.execute(
                        "cat /proc/loadavg | awk '{print $1}'", timeout=10)
                    if code == 0:
                        try:
                            self._health_status["cpu_load"] = float(
                                out.strip())
                        except ValueError:
                            pass
                except Exception as e:
                    log.debug(f"Health monitor loop error: {e}")

            # Sleep for 60 seconds
            self._stop_event.wait(60.0)

    def should_abort(self) -> bool:
        return self._abort_flag

    def get_latest_health(self) -> dict:
        return self._health_status
