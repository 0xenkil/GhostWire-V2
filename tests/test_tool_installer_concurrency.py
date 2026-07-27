import threading
import time
import unittest
from unittest.mock import MagicMock, patch
from core.tool_installer import get_installer, SESSION_INSTALL_LIMIT


class MockWSLExecutor:
    def __init__(self):
        self.installed_tools = set()
        self.lock = threading.Lock()

    def execute(self, cmd, timeout=None):
        # Simulate some work
        time.sleep(0.01)
        # Mock df -m output
        if "df -m" in cmd:
            return 0, "5000", ""
        # Mock memory info
        if "/proc/meminfo" in cmd:
            return 0, "2048", ""
        # Mock load average
        if "/proc/loadavg" in cmd:
            return 0, "0.5", ""
        # Mock dependency checks
        if "apt-cache search" in cmd or "which" in cmd:
            return 0, "dependency_ok", ""

        # Parse commands
        if "apt install" in cmd or "apt-get install" in cmd:
            parts = cmd.split()
            tool = parts[-1]
            with self.lock:
                self.installed_tools.add(tool.lower())
            return 0, "success", ""

        if cmd.startswith("command -v"):
            binary = cmd.split()[-1].lower()
            with self.lock:
                if binary in self.installed_tools:
                    return 0, f"/usr/bin/{binary}", ""
                else:
                    return 1, "", ""

        if cmd.startswith("[ -x"):
            path = cmd.split()[2]
            binary = path.split("/")[-1].lower()
            with self.lock:
                if binary in self.installed_tools:
                    return 0, "", ""
                else:
                    return 1, "", ""

        with self.lock:
            for tool in self.installed_tools:
                if tool in cmd:
                    return 0, f"{tool} version 1.0", ""

        return 1, "not found", ""


class TestToolInstallerConcurrency(unittest.TestCase):
    def setUp(self):
        self.installer = get_installer()
        # Reset singleton state for testing
        self.installer._session_install_count = 0
        self.installer._runtime_allowlist = set()
        self.installer._install_failure_counts = {}
        self.installer._install_failure_details = {}
        self.installer._install_timestamps = {}

    @patch('core.tool_installer.log')
    def test_concurrent_installs(self, mock_log):
        executor = MockWSLExecutor()
        threads = []
        results = []

        def worker(tool_name):
            # Mock registry tool
            mock_registry_tool = MagicMock()
            mock_registry_tool.name = tool_name
            mock_registry_tool.binary = tool_name
            mock_registry_tool.can_auto_install = True
            mock_registry_tool.sha256 = None
            # Avoid MagicMock TypeError during iteration
            mock_registry_tool.dependencies = []

            # We need to mock core.capability_registry.ALL_TOOLS too because
            # request_install imports it
            with patch('core.capability_registry.ALL_TOOLS', [mock_registry_tool]):
                approved, reason = self.installer.request_install(
                    tool_name=tool_name,
                    install_script=f"apt install {tool_name}",
                    remote_executor=executor,
                    target="1.2.3.4",
                    registry_tool=mock_registry_tool
                )
                results.append((tool_name, approved, reason))

        # Launch more threads than the limit
        num_threads = SESSION_INSTALL_LIMIT + 5
        for i in range(num_threads):
            t = threading.Thread(target=worker, args=(f"tool_{i}",))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Check total installs
        approved_count = sum(1 for _, approved, _ in results if approved)
        self.assertLessEqual(approved_count, SESSION_INSTALL_LIMIT)
        self.assertEqual(self.installer._session_install_count, approved_count)

        print(f"\n[TEST] Total approved: {approved_count}/{num_threads}")
        print(
            f"[TEST] Final session count: {
                self.installer._session_install_count}")
        print(
            f"[TEST] Allowlist size: {len(self.installer._runtime_allowlist)}")

    @patch('core.tool_installer.log')
    def test_session_summary_no_error(self, mock_log):
        # Trigger a failure to populate failure dicts
        self.installer._install_failure_counts["broken_tool"] = 1

        try:
            summary = self.installer.session_summary()
            self.assertIn("install_failures", summary)
            self.assertEqual(summary["install_failures"]["broken_tool"], 1)
            print("[TEST] session_summary executed without AttributeError")
        except AttributeError as e:
            self.fail(f"session_summary raised AttributeError: {e}")


if __name__ == "__main__":
    unittest.main()
