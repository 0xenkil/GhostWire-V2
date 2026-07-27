import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, ".")


class TestToolManagerFixes(unittest.TestCase):
    def test_nuclei_template_folder_dedup(self):
        # Instantiate a mock agent
        from agents.base_agent import BaseAgent
        mock_session = MagicMock()
        mock_session.engagement_id = "test_eng"

        # Create a subclass of BaseAgent to test
        class DummyAgent(BaseAgent):
            def run(self): pass

        # Patch __init__ of BaseAgent to avoid database initialization or setup
        with patch.object(BaseAgent, '__init__', lambda self, *args, **kwargs: None):
            agent = DummyAgent()
            agent.log = MagicMock()

            # Setup template path resolver mock
            agent._nuclei_templates_path = lambda: "/home/user/nuclei-templates/"

            # Test duplicate nesting cleanup logic
            broken_cmd = "nuclei -u http://127.0.0.1 -t http/http/http/http/http/cves/"
            repaired = agent._repair_common_tool_flags("nuclei", broken_cmd)

            # Should repair http/http/.../cves/ to http/cves/
            self.assertIn("http/cves/", repaired)
            self.assertNotIn("http/http/", repaired)

    @patch('core.wsl_executor.WSLExecutor')
    def test_gobuster_subcommand_help(self, mock_wsl):
        executor_mock = MagicMock()
        # Mock what gobuster dir --help outputs
        executor_mock.execute.return_value = (
            0,
            "  -u, --url string  URL\n  -w, --wordlist string Wordlist\n  --wildcard wildcard check",
            "")
        # Mock execute_resilient to return exit code 1 with unrecognized flag
        # error
        executor_mock.execute_resilient.return_value = (
            1, "", "flag provided but not defined: -wildcard")

        from tools.tool_manager import ToolManager
        mock_session = MagicMock()
        mock_session.results_dir = MagicMock()

        with patch('tools.tool_manager.get_config') as mock_config:
            cfg = MagicMock()
            cfg.timeout.tool_default = 60
            cfg.vps.use_remote_vps = False
            mock_config.return_value = cfg

            tm = ToolManager(mock_session, MagicMock(), MagicMock())
            tm.remote = executor_mock
            tm.ensure_installed = lambda x: True

            # Run command with unrecognized flag to trigger dynamic correction
            result = tm.run(
                "gobuster",
                "gobuster dir -u http://127.0.0.1 -w /tmp/w -wildcard",
                "recon")

            # Check what help command was constructed and executed
            called_cmds = [call[0][0]
                           for call in executor_mock.execute.call_args_list]
            self.assertTrue(any("gobuster dir --help" in cmd for cmd in called_cmds),
                            f"gobuster dir --help not found in executed commands: {called_cmds}")


if __name__ == '__main__':
    unittest.main()
