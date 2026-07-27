"""Guard for the assumption-validation loop (2026-06-18).

The agent registers tactical assumptions but never validated them — a write-only
meta-cognition gap, so its confidence model never reflected reality and it never
learned from a wrong assumption. `_validate_assumptions` closes the loop: the AI
judges each open assumption against the evidence, records SUPPORT/REFUTE, and
surfaces a refuted belief into the failure memory. These tests pin that contract
and its fail-safe behavior.
"""
import json
import logging
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.CRITICAL)


def _setup(ai):
    from agents.base_agent import BaseAgent
    from intelligence.self_awareness_module import SelfAwarenessModule
    aw = SelfAwarenessModule(state_store=None)
    aw.register_assumption("Host is a honeypot", confidence=0.8)
    aw.register_assumption("Try SQLi on /login", confidence=0.6)
    fake = types.SimpleNamespace(
        awareness=aw, ai=ai, log=logging.getLogger("t"), _recent_failures=[],
        session=types.SimpleNamespace(engagement_id="e1"),
        store=types.SimpleNamespace(
            get_all_findings=lambda eid: [{"type": "auth_endpoint", "detail": "/login"}]))
    return BaseAgent, aw, fake


def test_support_and_refute_recorded_plus_learning_signal():
    ids = ["ASSUME_0", "ASSUME_1"]

    class AI:
        def query(self, s, p):
            return json.dumps({"verdicts": [
                {"id": ids[0], "verdict": "refute", "why": "real Vercel SPA, not a honeypot"},
                {"id": ids[1], "verdict": "support", "why": "/login form present"}]})

    BaseAgent, aw, fake = _setup(AI())
    BaseAgent._validate_assumptions(fake)
    assert len(aw.validated_assumptions) == 1
    assert len(aw.failed_assumptions) == 1
    assert any("ASSUMPTION REVISED" in f for f in fake._recent_failures)


def test_no_ai_is_noop():
    BaseAgent, aw, fake = _setup(None)
    BaseAgent._validate_assumptions(fake)  # must not raise
    assert len(aw.validated_assumptions) == 0 and len(aw.failed_assumptions) == 0


def test_ai_error_is_fail_safe():
    class Boom:
        def query(self, s, p):
            raise RuntimeError("backend down")

    BaseAgent, aw, fake = _setup(Boom())
    BaseAgent._validate_assumptions(fake)  # must swallow and not raise
    assert len(aw.validated_assumptions) == 0 and len(aw.failed_assumptions) == 0
