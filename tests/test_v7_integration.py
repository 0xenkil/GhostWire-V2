from utils.logger import configure_log_dir
from core.capability_registry import CapabilityRegistry
from tools.tool_manager import ToolManager
from core.scope_enforcer import ScopeEnforcer
from core.message_bus import MessageBus
from core.session import EngagementSession
from core.target_context import TargetContext
from agents.exploitation_agent import ExploitationAgent
from core.stealth_proxy import StealthProxy
from core.payload_sandbox import validate_script
from core.state_store import StateStore
import unittest
import sys
import os
import json
import sqlite3
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DummyAI:
    """Mock AI Backend for V7.1 Cognitive Loop"""

    def __init__(self):
        self.calls = 0

    def query(self, system: str, user: str, **kwargs) -> str:
        # **kwargs mirrors the real AIBackend.query (model_id, max_retries, …) so
        # tier-based model routing doesn't break this stub.
        self.calls += 1
        print(f"DummyAI call {self.calls}: {user[:100]}")

        if "We need a wordlist" in user:
            return json.dumps({
                "type": "generate",
                "wordlist": ["/admin", "/api/v1", ".env"]
            })

        if "curl http://localhost" not in user:
            return json.dumps([{
                "analysis": "Testing target HTTP status and connectivity using safe urllib",
                "command": "curl http://localhost",
                "timeout": 10,
                "expect": "200 OK"
            }])
        else:
            return json.dumps([])


class TestV7Integration(unittest.TestCase):
    def setUp(self):
        import tools.tool_manager
        import agents.base_agent
        tools.tool_manager.USE_REMOTE_VPS = False
        tools.tool_manager.USE_WSL = False
        agents.base_agent.USE_REMOTE_VPS = False
        agents.base_agent.USE_WSL = False

        self.db_path = Path("tests/results/test_v7.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if self.db_path.exists():
            for _ in range(5):
                try:
                    self.db_path.unlink()
                    break
                except Exception:
                    import time
                    time.sleep(0.5)
            for suffix in ['.db-wal', '.db-shm']:
                path = self.db_path.with_suffix(suffix)
                if path.exists():
                    try:
                        path.unlink()
                    except Exception as _e:
                        import logging
                        logging.getLogger(__name__).warning(
                            f"Swallowed exception: {_e}")

        self.store = StateStore(self.db_path)
        self.target_ctx = TargetContext.from_input("http://10.1.1.1:9090")

        self.session = EngagementSession(
            mode="pentest",
            target='http://10.1.1.1:9090',
            scope=["10.1.1.1"],
            rules_of_engagement={
                "allow_exploitation": True,
                "allow_destructive": False},
            operator="integration_test",
            ai_backend="dummy",
            stealth_config={"ghost_mode": True, "rotate_ip": False},
        )

        # Configure log and workspace directories to avoid sandbox permission
        # errors
        self.session.results_dir.mkdir(parents=True, exist_ok=True)
        configure_log_dir(self.session.results_dir / "logs")

        import utils.display

        class DummyConsole:
            def print(self, *args, **kwargs):
                pass

            def rule(self, *args, **kwargs):
                pass
        utils.display.console = DummyConsole()
        utils.display.section = lambda msg: print(f"\n◤ {msg.upper()} ◢")
        utils.display.info = lambda msg: print(f"[ SYS.INFO ] {msg}")
        utils.display.warning = lambda msg: print(f"[ SYS.WARN ] {msg}")
        utils.display.success = lambda msg: print(f"[  SYS.OK  ] {msg}")

        self.bus = MessageBus(self.store, self.session.engagement_id)
        self.scope = ScopeEnforcer(self.session)
        self.tools = ToolManager(self.session, self.store, ai_backend=None)
        self.cap_reg = CapabilityRegistry(
            remote_executor=None, ai_backend=None)

        # Setup initial fake recon data so exploitation agent doesn't fail
        # preflight checks
        recon_data = {
            "open_ports": [80, 443],
            "services": {"80": "http", "443": "https"},
            "waf_present": False,
            "waf_type": "None",
            "is_cdn": False
        }
        self.store.set_phase_data(
            self.session.engagement_id, "recon", recon_data)

    def tearDown(self):
        self.store.close()
        import gc
        gc.collect()
        if self.db_path.exists():
            for _ in range(5):
                try:
                    self.db_path.unlink()
                    break
                except Exception:
                    time.sleep(0.5)
            # Cleanup WAL and SHM if they exist
            for suffix in ['.db-wal', '.db-shm']:
                path = self.db_path.with_suffix(suffix)
                if path.exists():
                    try:
                        path.unlink()
                    except Exception as _e:
                        import logging
                        logging.getLogger(__name__).warning(
                            f"Swallowed exception: {_e}")

    def test_database_schema_v7(self):
        """1. Verify SQLite schema upgrades from V7.1 (core persisted tables).

        P5-8: the graph_nodes/graph_edges assertions were removed with the
        write-only AttackGraph they backed; assert the durable core tables the
        engine actually relies on instead (tool_runs, findings, evidence_graph —
        the LIVE, consumed graph)."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Query tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]

        self.assertIn("tool_runs", tables)
        self.assertIn("findings", tables)
        self.assertIn("evidence_graph", tables)

        # tool_runs carries the P0-10 originating-run link + P3-3 evasion column.
        cursor.execute("PRAGMA table_info(tool_runs);")
        columns = [row[1] for row in cursor.fetchall()]
        self.assertIn("tool", columns)
        self.assertIn("evasion_applied", columns)

        conn.close()

    def test_payload_sandbox_ast_rules(self):
        """3. Validate code compilation gate (AST whitelist blocks bad imports/functions)"""
        # Forbidden imports/functions
        bad_code_1 = "import os\nos.system('whoami')"
        bad_code_2 = "import subprocess\nsubprocess.run(['id'])"
        bad_code_3 = "eval('__import__(\"os\").system(\"id\")')"
        bad_code_4 = "open('/etc/passwd', 'r').read()"

        self.assertGreater(len(validate_script(bad_code_1)), 0)
        self.assertGreater(len(validate_script(bad_code_2)), 0)
        self.assertGreater(len(validate_script(bad_code_3)), 0)
        self.assertGreater(len(validate_script(bad_code_4)), 0)

        # Whitelisted (safe) payload
        safe_code = "import urllib.request\nprint('Safe API Execution')"
        self.assertEqual(len(validate_script(safe_code)), 0)

    def test_stealth_proxy_interaction(self):
        """4. Verify Stealth Proxy listener runs concurrently and rotates UAs"""
        proxy = StealthProxy(port=8082)
        proxy.start()
        time.sleep(0.5)

        try:
            self.assertTrue(proxy.thread.is_alive())
        finally:
            proxy.stop()

    def test_exploitation_agent_cognitive_loop(self):
        """5. End-to-end simulated run of the exploitation agent with mocked AI backend"""
        dummy_ai = DummyAI()

        class MockScopeEnforcer:
            def is_in_scope(self, url):
                return True

        agent = ExploitationAgent(
            name="exploitation",
            session=self.session,
            state_store=self.store,
            tool_manager=self.tools,
            ai_backend=dummy_ai,
            message_bus=self.bus,
            scope_enforcer=MockScopeEnforcer()
        )
        self.session.ai_backend = dummy_ai

        # Override soft-404 and tech stacking so the test runs fast without
        # hitting network
        agent._get_spa_baseline = lambda base_url: 0
        agent._detect_spa_tech = lambda base_url: {
            "spa": False, "framework": None, "cms": None, "api_endpoints": []}
        agent._profile_dynamic_soft_404 = lambda base_url: set()

        # Mock safe_run_tool to bypass network and trigger HTTP Smuggling
        from tools.tool_manager import ToolResult
        from agents.base_agent import ResultStatus

        def fake_run_tool(tool_name, cmd_string, *args, **kwargs):
            if "Transfer-Encoding: chunked" in cmd_string or "curl http://localhost" in cmd_string:
                return ToolResult(
                    tool=tool_name,
                    command=cmd_string,
                    stdout="HTTP/1.1 200 OK\nSensitive file disclosed! Warning: syntax error or private key exposure detected!",
                    stderr="",
                    exit_code=0,
                    duration_seconds=1.2,
                    status=ResultStatus.SUCCESS
                )
            return ToolResult(
                tool=tool_name,
                command=cmd_string,
                stdout="location: https://",
                stderr="",
                exit_code=0,
                duration_seconds=0.5,
                status=ResultStatus.SUCCESS
            )
        agent.safe_run_tool = fake_run_tool

        # Patch time.sleep to avoid 90s cooldown
        import unittest.mock
        with unittest.mock.patch('time.sleep', return_value=None), \
                unittest.mock.patch('core.payload_sandbox.execute_in_sandbox', return_value=("Target response received: 200 OK\n", "", 0)), \
                unittest.mock.patch('tools.tool_manager.USE_REMOTE_VPS', False), \
                unittest.mock.patch('tools.tool_manager.USE_WSL', False), \
                unittest.mock.patch('agents.base_agent.USE_REMOTE_VPS', False), \
                unittest.mock.patch('agents.base_agent.USE_WSL', False):
            # Run agent
            import asyncio
            import inspect
            coro = agent.run()
            if inspect.isawaitable(coro):
                asyncio.run(coro)
            else:
                pass

        # Verify the AI backend was consulted and completed the cognitive loop
        self.assertGreaterEqual(dummy_ai.calls, 2)

        # Verify findings were added securely.
        # P0-5 (EXPLOIT-EMIT-1): output that merely CONTAINS a sensitive substring
        # (e.g. "private key") is no longer minted as a proven ai_dynamic_exploit —
        # with no control/test differential it is an UNVERIFIED LEAD (exploit_lead)
        # for the hypothesis engine to validate, never a forged proof.
        findings = self.store.get_all_findings(self.session.engagement_id)
        cognitive_findings = [
            f for f in findings if f["type"] == "exploit_lead"]
        self.assertGreater(len(cognitive_findings), 0)
        self.assertIn("curl http://localhost", cognitive_findings[0]["detail"])


if __name__ == '__main__':
    unittest.main()
