from core.health_monitor import HealthMonitor
import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestHealthMonitor(unittest.TestCase):
    def setUp(self):
        self.mock_ssh = MagicMock()
        self.mock_store = MagicMock()
        self.monitor = HealthMonitor(self.mock_ssh, self.mock_store)

    def test_monitor_loop_healthy(self):
        # Setup healthy metrics
        self.mock_ssh.check_vps_health.return_value = {
            "disk_pct": 50,
            "mem_avail_mb": 2000,
            "cpu_load": 0.5,
            "services": {"sshd": True, "tor": True},
            "healthy": True,
            "issues": []
        }

        # We need to stop the loop after one iteration
        # Patching time.sleep to return immediately
        with patch('time.sleep', side_effect=[None, Exception("Stop loop")]):
            try:
                self.monitor._monitor_loop()
            except Exception as e:
                if str(e) != "Stop loop":
                    raise e

        self.mock_store.save_global_data.assert_called_with(
            "vps_health", self.mock_ssh.check_vps_health.return_value)
        self.mock_ssh.cleanup_tmp.assert_not_called()

    def test_monitor_loop_unhealthy_disk_warn(self):
        # Setup disk warn metrics
        warn_pct = 86
        self.mock_ssh.check_vps_health.side_effect = [
            {
                "disk_pct": warn_pct,
                "mem_avail_mb": 2000,
                "cpu_load": 0.5,
                "healthy": True,
                "issues": [f"WARNING: disk {warn_pct}%"]
            },
            {
                "disk_pct": 50,  # After cleanup
                "mem_avail_mb": 2000,
                "cpu_load": 0.5,
                "healthy": True,
                "issues": []
            }
        ]

        with patch('time.sleep', side_effect=[None, Exception("Stop loop")]):
            # Patch config to ensure threshold is met
            with patch('config.VPS_DISK_WARN_PCT', 85):
                try:
                    self.monitor._monitor_loop()
                except Exception as e:
                    if str(e) != "Stop loop":
                        raise e

        self.mock_ssh.cleanup_tmp.assert_called_once()
        # Should have saved twice: once before cleanup, once after
        self.assertEqual(self.mock_store.save_global_data.call_count, 2)

    def test_should_abort(self):
        # Mock state store response
        self.mock_store.get_global_data.return_value = {"healthy": False}
        self.assertTrue(self.monitor.should_abort())

        self.mock_store.get_global_data.return_value = {"healthy": True}
        self.assertFalse(self.monitor.should_abort())


if __name__ == '__main__':
    unittest.main()
