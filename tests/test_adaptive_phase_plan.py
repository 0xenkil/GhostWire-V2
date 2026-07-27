"""Safety guard for the fenced adaptive phase plan (2026-06-18).

The orchestrator may skip an OPTIONAL phase the AI deems pointless for a target
(e.g. persistence on a serverless SPA). The non-negotiable safety property is
that this **fails OPEN**: any AI error, malformed response, or ambiguity must RUN
the phase, never skip it. These tests pin that down so a refactor can't silently
turn it into fail-closed behavior (which could starve a needed phase).
"""
import json
import logging
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.CRITICAL)


def _fake_orch(ai, findings=None):
    f = types.SimpleNamespace()
    f.session = types.SimpleNamespace(
        mode="redteam", target="https://x.vercel.app", engagement_id="e1")
    f.store = types.SimpleNamespace(
        get_all_findings=lambda eid: (findings or []))
    f.ai = ai
    return f


class _AI:
    def __init__(self, payload=None, boom=False):
        self._payload = payload
        self._boom = boom

    def query(self, system, prompt, model_id=None):
        if self._boom:
            raise RuntimeError("backend down")
        return self._payload


def test_ai_says_skip_optional_phase():
    from core.orchestrator import Orchestrator
    ai = _AI(json.dumps({"run": False, "reason": "serverless SPA, nothing to persist"}))
    run, why = Orchestrator._phase_applicable(_fake_orch(ai), "persistence")
    assert run is False and "serverless" in why


def test_ai_error_fails_open():
    from core.orchestrator import Orchestrator
    run, _ = Orchestrator._phase_applicable(_fake_orch(_AI(boom=True)), "persistence")
    assert run is True  # fail-OPEN: never skip on error


def test_malformed_response_fails_open():
    from core.orchestrator import Orchestrator
    run, _ = Orchestrator._phase_applicable(
        _fake_orch(_AI("not json at all")), "weaponization")
    assert run is True


def test_decision_is_cached():
    from core.orchestrator import Orchestrator
    fake = _fake_orch(_AI(json.dumps({"run": False, "reason": "n/a"})))
    r1, _ = Orchestrator._phase_applicable(fake, "objectives")
    # Swap in a throwing backend; a cached decision must NOT re-query.
    fake.ai = _AI(boom=True)
    r2, _ = Orchestrator._phase_applicable(fake, "objectives")
    assert r1 is False and r2 is False


def test_mandatory_phase_set_protects_core_phases():
    from core.orchestrator import Orchestrator
    # The safety floor must cover the phases that, if skipped, break the pipeline.
    for core_phase in ("planning", "recon", "exploitation", "reporting"):
        assert core_phase in Orchestrator._MANDATORY_PHASES
