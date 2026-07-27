#!/usr/bin/env python3
"""
REAL INTEGRATION TEST - Actually runs agents against realistic scenarios
Unlike stress_test_realistic.py, this ACTUALLY executes agents with real phase data
"""

from tools.tool_manager import ToolManager
from core.message_bus import MessageBus
from core.state_store import StateStore
from core.session import EngagementSession
from agents.weaponization_agent import WeaponizationAgent
from agents.validation_agent import ValidationAgent
from agents.reporting_agent import ReportingAgent
from agents.objectives_agent import ObjectivesAgent
from agents.persistence_agent import PersistenceAgent
from agents.exploitation_agent import ExploitationAgent
from agents.recon_agent import ReconAgent
from agents.planning_agent import PlanningAgent
import sys
import os
import io
import json
import time
import logging
from datetime import datetime
from pathlib import Path

# ── Force UTF-8 output on Windows CMD
if sys.platform == "win32":
    try:
        import io
        if hasattr(sys.stdout, 'detach') and getattr(
                sys.stdout, 'encoding', '').lower() not in ('utf-8', 'utf8'):
            sys.stdout.flush()
            sys.stdout = io.TextIOWrapper(
                sys.stdout.detach(), encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, 'detach') and getattr(
                sys.stderr, 'encoding', '').lower() not in ('utf-8', 'utf8'):
            sys.stderr.flush()
            sys.stderr = io.TextIOWrapper(
                sys.stderr.detach(), encoding="utf-8", errors="replace")
        os.environ["PYTHONIOENCODING"] = "utf-8"
    except Exception as _e:
        import logging
        logging.getLogger(__name__).debug(
            f'Swallowed exception in real_integration_test.py: {_e}')

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s][%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("real_integration_test.log", encoding="utf-8")
    ]
)
log = logging.getLogger("real_int_test")

# Import agents


# Test scenarios with local/mock targets
REAL_TEST_SCENARIOS = [
    {
        "name": "Simple HTTP localhost (pentest)",
        "target": "http://127.0.0.1:8080",
        "mode": "pentest",
        "expected_phases": ["planning", "recon", "exploitation", "reporting"],
    },
    {
        "name": "HTTPS localhost (pentest)",
        "target": "https://127.0.0.1:8443",
        "mode": "pentest",
        "expected_phases": ["planning", "recon", "exploitation", "reporting"],
    },
]


class RealIntegrationTester:
    """Actually runs agents, not simulated."""

    def __init__(self):
        self.results = {
            "test_start": datetime.now().isoformat(),
            "scenarios": [],
            "summary": {}
        }
        self.results_dir = Path("integration_test_results")
        self.results_dir.mkdir(exist_ok=True)

    def setup_session(self, scenario: dict) -> EngagementSession:
        """Create a real engagement session."""
        from core.target_context import TargetContext
        target_ctx = TargetContext.from_input(scenario["target"])
        session = EngagementSession(
            mode=scenario["mode"],
            target_context=target_ctx,
            scope_strs=[scenario["target"]],
            rules_of_engagement={
                "allow_exploitation": True,
                "allow_destructive": False,
            },
            operator="test_operator",
            ai_backend="ollama",  # Mock
            stealth_config={}
        )
        return session

    def run_phase(self, phase_name: str, agent_class,
                  session: EngagementSession, store: StateStore) -> dict:
        """Run a single agent phase and return results."""
        phase_start = time.time()

        try:
            log.info(f"    Starting {phase_name} phase...")

            # Create agent instance
            tools = ToolManager(session, store, ai_backend=None)
            agent = agent_class(
                name=phase_name,
                session=session,
                state_store=store,
                tool_manager=tools,
                ai_backend=None,
                message_bus=MessageBus(store, session.engagement_id),
                scope_enforcer=None,
                capability_registry=None
            )

            # Run agent
            result = agent.run()
            elapsed = time.time() - phase_start

            log.info(f"    {phase_name} PASS ({elapsed:.2f}s)")
            return {
                "status": "pass",
                "duration": elapsed,
                "error": None,
                "result": result
            }

        except Exception as e:
            elapsed = time.time() - phase_start
            log.error(f"    {phase_name} FAIL ({elapsed:.2f}s): {e}")
            return {
                "status": "fail",
                "duration": elapsed,
                "error": str(e),
                "result": None
            }

    def run_scenario(self, scenario: dict) -> dict:
        """Run all phases for a scenario."""
        log.info(f"\nScenario: {scenario['name']}")
        log.info(f"Target: {scenario['target']}")

        scenario_start = time.time()
        scenario_result = {
            "name": scenario["name"],
            "target": scenario["target"],
            "phases": {},
            "overall_status": "pass",
            "total_duration": 0.0
        }

        # Setup session and store
        session = self.setup_session(scenario)
        store = StateStore(self.results_dir / f"{scenario['name']}.db")

        # Map phase names to agent classes
        phase_agents = {
            "planning": PlanningAgent,
            "recon": ReconAgent,
            "exploitation": ExploitationAgent,
            "persistence": PersistenceAgent,
            "objectives": ObjectivesAgent,
            "reporting": ReportingAgent,
            "validation": ValidationAgent,
            "weaponization": WeaponizationAgent,
        }

        # Run each phase in order
        for phase_name in scenario["expected_phases"]:
            if phase_name not in phase_agents:
                log.warning(f"Unknown phase: {phase_name}")
                continue

            agent_class = phase_agents[phase_name]
            result = self.run_phase(phase_name, agent_class, session, store)
            scenario_result["phases"][phase_name] = result

            # If phase fails, stop here (unless it's optional)
            if result["status"] == "fail":
                scenario_result["overall_status"] = "fail"
                # Continue to next phase anyway to see all failures

        scenario_result["total_duration"] = time.time() - scenario_start
        return scenario_result

    def run_all(self):
        """Run all scenarios."""
        log.info("\n" + "=" * 70)
        log.info("REAL INTEGRATION TEST - ACTUAL AGENT EXECUTION")
        log.info("=" * 70)

        for scenario in REAL_TEST_SCENARIOS:
            try:
                result = self.run_scenario(scenario)
                self.results["scenarios"].append(result)
            except Exception as e:
                log.error(f"Scenario setup failed: {e}", exc_info=True)
                self.results["scenarios"].append({
                    "name": scenario["name"],
                    "status": "error",
                    "error": str(e)
                })

        # Calculate summary
        passed = sum(
            1 for s in self.results["scenarios"] if s["overall_status"] == "pass")
        failed = sum(
            1 for s in self.results["scenarios"] if s["overall_status"] == "fail")
        total = passed + failed

        self.results["summary"] = {
            "total": total,
            "passed": passed,
            "failed": failed,
            "success_rate_pct": (passed / total * 100) if total > 0 else 0
        }

        self.print_summary()
        self.save_results()

    def print_summary(self):
        """Print test summary."""
        summary = self.results["summary"]
        log.info("\n" + "=" * 70)
        log.info("TEST SUMMARY")
        log.info("=" * 70)
        log.info(f"Total: {summary['total']}")
        log.info(f"Passed: {summary['passed']}")
        log.info(f"Failed: {summary['failed']}")
        log.info(f"Success Rate: {summary['success_rate_pct']:.1f}%")

    def save_results(self):
        """Save results to JSON."""
        results_file = self.results_dir / f"results_{int(time.time())}.json"
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        log.info(f"\nResults saved to: {results_file}")


if __name__ == "__main__":
    tester = RealIntegrationTester()
    tester.run_all()
