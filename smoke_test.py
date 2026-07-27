#!/usr/bin/env python3
"""
SMOKE TEST - Verify all agents can be instantiated and basic methods exist
This is a quick sanity check before running full integration tests
"""

import sys
import logging
from pathlib import Path
from types import SimpleNamespace

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger("smoke_test")


def main():
    # Test 1: Import all agents
    log.info("TEST 1: Importing all agents...")
    try:
        from agents.planning_agent import PlanningAgent
        from agents.recon_agent import ReconAgent
        from agents.exploitation_agent import ExploitationAgent
        from agents.persistence_agent import PersistenceAgent
        from agents.objectives_agent import ObjectivesAgent
        from agents.reporting_agent import ReportingAgent
        from agents.validation_agent import ValidationAgent
        from agents.weaponization_agent import WeaponizationAgent
        log.info("[+] All agents imported successfully")
    except ImportError as e:
        log.error(f"[-] Import failed: {e}")
        sys.exit(1)

    # Test 2: Check core dependencies
    log.info("\nTEST 2: Checking core dependencies...")
    try:
        from core.state_store import StateStore
        log.info("[+] Core dependencies available")
    except ImportError as e:
        log.error(f"[-] Dependency import failed: {e}")
        sys.exit(1)

    # Test 3: Create mock session
    log.info("\nTEST 3: Creating mock session...")
    try:
        session = SimpleNamespace(
            engagement_id="test_001",
            target="http://localhost:8080",
            scope=["localhost"],
            mode="pentest",
            rules_of_engagement={"allow_exploitation": True},
            results_dir=Path("/tmp/test_results"),
            db_path=Path("/tmp/test.db"),
            normalized_target=lambda: "localhost",
            ai_backend="mock"
        )
        log.info("[+] Mock session created")
    except Exception as e:
        log.error(f"[-] Session creation failed: {e}")
        sys.exit(1)

    # Test 4: Create state store
    log.info("\nTEST 4: Creating state store...")
    try:
        store = StateStore(Path("/tmp/smoke_test.db"))
        log.info("[+] State store created")
    except Exception as e:
        log.error(f"[-] State store creation failed: {e}")
        sys.exit(1)

    # Test 5: Try instantiating each agent
    log.info("\nTEST 5: Instantiating all agents...")
    agents_to_test = [
        ("PlanningAgent", PlanningAgent),
        ("ReconAgent", ReconAgent),
        ("ExploitationAgent", ExploitationAgent),
        ("PersistenceAgent", PersistenceAgent),
        ("ObjectivesAgent", ObjectivesAgent),
        ("ReportingAgent", ReportingAgent),
        ("ValidationAgent", ValidationAgent),
        ("WeaponizationAgent", WeaponizationAgent),
    ]

    passed = 0
    failed = 0

    for agent_name, agent_class in agents_to_test:
        try:
            # Try to create agent with minimal dependencies
            agent = agent_class(
                name=agent_name.lower(),
                session=session,
                state_store=store,
                tool_manager=None,
                ai_backend=None,
                message_bus=SimpleNamespace(
                    publish=lambda *a, **k: None, subscribe=lambda *a, **k: None),
                scope_enforcer=None,
                capability_registry=None
            )

            # Check if agent has required methods
            if not hasattr(agent, 'run'):
                log.error(f"[-] {agent_name}: Missing 'run' method")
                failed += 1
            else:
                log.info(f"[+] {agent_name}: Instantiated successfully")
                passed += 1

        except TypeError as e:
            # Might fail due to missing parameters
            log.warning(f"[!] {agent_name}: Constructor issue: {e}")
            failed += 1
        except Exception as e:
            log.error(f"[-] {agent_name}: {e}")
            failed += 1

    log.info(f"\nResults: {passed}/{len(agents_to_test)} agents passed")

    if failed > 0:
        log.warning(
            f"[!] Smoke test detected {failed} agent issues - see above for details")
        sys.exit(1)
    else:
        log.info("[+] All smoke tests passed")
        sys.exit(0)


if __name__ == "__main__":
    main()
