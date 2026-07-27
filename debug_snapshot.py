#!/usr/bin/env python
"""
Debug: Find the exact line causing the environment snapshot error.
"""

import traceback
from types import SimpleNamespace


class DummyBus:
    def subscribe(self, *args, **kwargs):
        return None

    def publish(self, *args, **kwargs):
        return None


try:
    print("Step 1: Import BaseAgent...")
    from agents.base_agent import BaseAgent
    print("  [[+]] BaseAgent imported")

    print("Step 2: Create session object...")
    session = SimpleNamespace(
        mode='redteam',
        engagement_id='test_eng_001',
        scope=['novalink.lk'],
        rules_of_engagement={},
        target='https://novalink.lk',
        results_dir='/tmp/results'
    )
    print("  [[+]] Session created")

    print("Step 3: Create state_store...")
    store = SimpleNamespace(
        get_cross_engagement_failures=lambda limit=10: [],
        get_phase_data=lambda *a, **k: {},
        set_phase_data=lambda *a, **k: None,
        get_all_findings=lambda *a: []
    )
    print("  [[+]] Store created")

    print("Step 4: Create tool manager...")
    tools = SimpleNamespace(remote=None, ensure_installed=lambda *a, **k: True)
    print("  [[+]] Tools created")

    print("Step 5: Create DummyAgent class...")

    class DummyAgent(BaseAgent):
        pass
    print("  [[+]] DummyAgent defined")

    print("Step 6: Instantiate DummyAgent...")
    agent = DummyAgent(
        'test_agent',
        session=session,
        state_store=store,
        tool_manager=tools,
        ai_backend=None,
        message_bus=DummyBus(),
        scope_enforcer=SimpleNamespace(check_target=lambda t: True),
        capability_registry=SimpleNamespace()
    )
    print("  [[+]] Agent instantiated successfully!")

    print("Step 7: Call _get_environment_snapshot()...")
    snapshot = agent._get_environment_snapshot()
    print(f"  [[+]] Snapshot generated: {len(snapshot)} characters")
    if snapshot:
        print("  Snapshot preview:")
        print("  " + "\n  ".join(snapshot.split("\n")[:5]))

except Exception as e:
    print(f"\n[[x]] ERROR: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
