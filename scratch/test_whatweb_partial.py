import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, ".")


class TestWhatwebPartialSuccess(unittest.TestCase):
    @patch('core.wsl_executor.WSLExecutor')
    def test_whatweb_partial_success_loop_break(self, mock_wsl):
        # We want to test that when whatweb returns a WAF blocked response (e.g. 403 Forbidden)
        # but has successfully extracted some stack details (e.g. "httpserver[nginx]"),
        # the status is set to "partial_success" and the execution retry loop is immediately
        # broken rather than retrying 3 times.

        # Setup mock executor response
        executor_mock = MagicMock()
        # Mock whatweb exit code 0, with a WAF block marker but containing
        # valid metadata
        executor_mock.execute.return_value = (
            0, "httpserver[nginx] Title[Novalink] IP[216.198.79.1] 403 Forbidden", "")

        # Instantiate ToolManager
        from tools.tool_manager import ToolManager
        mock_session = MagicMock()
        mock_session.results_dir = MagicMock()

        with patch('tools.tool_manager.get_config') as mock_config:
            # Setup configuration values
            cfg = MagicMock()
            cfg.timeout.tool_default = 60
            cfg.vps.use_remote_vps = False
            mock_config.return_value = cfg

            tm = ToolManager(mock_session, MagicMock(), MagicMock())
            tm.remote = executor_mock
            tm.ensure_installed = lambda x: True  # Bypass installation checks

            # Execute whatweb command
            result = tm.run("whatweb", "whatweb https://novalink.lk", "recon")

            # Assertions
            # 1. Status should be normalized to partial_success
            self.assertEqual(result.status, "partial_success")

            # 2. execute should have been called exactly once (no retries)
            self.assertEqual(executor_mock.execute.call_count, 1)


if __name__ == '__main__':
    unittest.main()
