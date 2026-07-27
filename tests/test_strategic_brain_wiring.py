"""Regression guard for the strategic-brain wiring (2026-06-18).

The reasoning modules (StrategicAdvisor / SelfAwarenessModule / ReasoningEngine)
were originally built but never consulted — a "write-only brain": outcomes were
fed in, but the advice was never read into the decision loop, so the agent
reasoned mechanically instead of like a human operator. Nothing TESTED that the
advice flowed, which is exactly how it rotted to dormant.

These tests lock the wiring in: if a future change stops the advisor's
recommendations / stop-signs / pivots / early-exits from reaching the decision
context, or reverts analyze_tool_failure to a non-reasoning stub, they fail.
"""
import json
import logging
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _StubAI:
    """Returns canned strategic JSON; mimics ai_backend.query(system, prompt)."""

    def __init__(self, payload):
        self._payload = payload

    def query(self, system, prompt, model_id=None):
        # advise_discovery_order asks for an "EFFICIENT order"; everything else
        # gets the tool-selection / failure payload.
        if "EFFICIENT order" in prompt or "discovery" in prompt.lower():
            return json.dumps({
                "discovery_sequence": [{"step": 1, "activity": "web fingerprint",
                                        "tools": ["httpx"]}],
                "early_exit_conditions": ["if login panel found, skip dir-busting"],
            })
        return json.dumps(self._payload)


class TestStrategicAdvisorFullAdvice:
    """advise_* must be able to surface the FULL advice (pivots/warnings), not
    just the tool list, or the decision loop can never see a pivot."""

    def _advisor(self):
        from intelligence.strategic_advisor import StrategicAdvisor
        payload = {
            "tool_recommendations": [
                {"tool": "httpx", "priority": 1, "reasoning": "fingerprint",
                 "expected_success_rate": 0.8, "avoid_because": None},
                {"tool": "nmap", "priority": 9, "reasoning": "port scan",
                 "expected_success_rate": 0.05,
                 "avoid_because": "CDN edge filters all ports"}],
            "strategic_pivot_suggestions": [
                {"from": "port scanning", "to": "web/API testing",
                 "why": "serverless edge has no host ports"}],
            "warning_signs": ["repeated nmap timeouts = filtered edge, stop"],
            "knowledge_gap": "API routes behind the SPA",
        }
        return StrategicAdvisor(state_store=None, ai_backend=_StubAI(payload))

    def test_full_returns_dict_with_pivots_and_warnings(self):
        advice = self._advisor().advise_tool_selection(
            "recon", "x.vercel.app", ["vercel"], full=True)
        assert isinstance(advice, dict)
        assert advice.get("strategic_pivot_suggestions")
        assert advice.get("warning_signs")

    def test_default_return_is_still_a_list(self):
        # Back-compat: the no-`full` call must keep returning a plain list.
        recs = self._advisor().advise_tool_selection(
            "recon", "x.vercel.app", ["vercel"])
        assert isinstance(recs, list)

    def test_discovery_order_full_exposes_early_exit(self):
        order = self._advisor().advise_discovery_order(
            "x.vercel.app", ["vercel"], full=True)
        assert isinstance(order, dict)
        assert order.get("early_exit_conditions")

    def test_should_continue_trying_runs(self):
        # The dead no-op f-string was removed; method must still decide.
        cont, why = self._advisor().should_continue_trying(
            "nmap", "x", attempts=6, failure_rate=0.9)
        assert cont is False and isinstance(why, str)


class TestAnalyzeToolFailure:
    """analyze_tool_failure must REASON (AI-driven) about whether the approach
    is wrong, not just substring-match — and degrade to a heuristic only with
    no AI backend."""

    def test_ai_path_flags_wrong_approach_and_pivot(self):
        from intelligence.reasoning_engine import ReasoningEngine
        ai = _StubAI({
            "root_cause": "CDN edge filters all ports",
            "is_approach_wrong": True,
            "suggested_pivot": "web/API + auth testing",
            "suggested_action": "stop scanning ports",
            "reduce_concurrency": False,
        })
        v = ReasoningEngine(ai_backend=ai).analyze_tool_failure(
            "nmap", "nmap -p- x.vercel.app", "", "")
        assert v["is_approach_wrong"] is True
        assert "web/API" in v["suggested_pivot"]

    def test_heuristic_fallback_without_ai(self):
        from intelligence.reasoning_engine import ReasoningEngine
        v = ReasoningEngine(ai_backend=None).analyze_tool_failure(
            "nmap", "nmap -p- x", "connection timed out", "")
        assert v["root_cause"] == "Network Timeout Detected"
        assert "is_approach_wrong" in v  # new key present on the fallback too


class TestAdviceNoteReachesDecisionContext:
    """The end-to-end guard: BaseAgent._strategic_advice_note must turn the
    brain's output into operator-style guidance the AI can act on."""

    def test_note_surfaces_operator_signals(self):
        logging.disable(logging.CRITICAL)
        from agents.base_agent import BaseAgent
        from intelligence.strategic_advisor import StrategicAdvisor
        from intelligence.self_awareness_module import SelfAwarenessModule

        payload = {
            "tool_recommendations": [
                {"tool": "httpx", "priority": 1, "reasoning": "fingerprint",
                 "expected_success_rate": 0.8, "avoid_because": None},
                {"tool": "nmap", "priority": 9, "reasoning": "port scan",
                 "expected_success_rate": 0.05,
                 "avoid_because": "CDN edge filters all ports"}],
            "strategic_pivot_suggestions": [
                {"from": "port scan", "to": "web/API", "why": "CDN edge"}],
            "warning_signs": ["nmap timeouts = filtered edge"],
            "knowledge_gap": "API routes",
        }
        fake = types.SimpleNamespace()
        fake.log = logging.getLogger("t")
        fake.session = types.SimpleNamespace(target="https://x.vercel.app")
        fake._situation_summary = lambda: (["vercel"], {"tech_stack": 1})
        fake.advisor = StrategicAdvisor(state_store=None, ai_backend=_StubAI(payload))
        fake.awareness = SelfAwarenessModule(state_store=None)
        fake.awareness.knowledge_state["unknown_unknowns"].append(
            {"gap": "hidden API routes", "how_to_find_out": "fuzz /api",
             "why_it_matters": "real attack surface"})

        note = BaseAgent._strategic_advice_note(fake, "recon")
        for marker in ("RECOMMENDED", "AVOID", "STOP-SIGN", "PIVOT",
                       "EARLY-EXIT", "COLLECT-NEXT"):
            assert marker in note, f"missing {marker} in advice note"
