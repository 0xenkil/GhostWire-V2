"""Phase 5 — P5-7 LLMBackend Protocol + one shared token-budget resolver (D-FUT-3).

A new LLM backend is any class satisfying the LLMBackend Protocol (name + query +
the three budget methods). token_budget() and the Phase-4 budget authority
(base_agent._phase_token_budget) BOTH resolve through phase_token_budget(), so a
backend's view of the budget can never drift from the agent's.
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.llm_backend import LLMBackend, phase_token_budget  # noqa: E402


def test_shared_resolver_matches_config_thresholds():
    from config_thresholds import (
        PHASE_TOKEN_BUDGET_RECON, PHASE_TOKEN_BUDGET_EXPLOITATION,
        PHASE_TOKEN_BUDGET_DEFAULT,
    )
    assert phase_token_budget("recon") == PHASE_TOKEN_BUDGET_RECON
    assert phase_token_budget("exploitation") == PHASE_TOKEN_BUDGET_EXPLOITATION
    assert phase_token_budget("weaponization") == PHASE_TOKEN_BUDGET_DEFAULT
    assert phase_token_budget("") == PHASE_TOKEN_BUDGET_DEFAULT


def test_base_agent_phase_budget_delegates_to_resolver():
    # The Phase-4 authority and the shared resolver return the SAME value —
    # proving they are one authority, not two that can drift.
    from agents.base_agent import BaseAgent
    for phase in ("recon", "exploitation", "reporting"):
        f = types.SimpleNamespace(name=phase)
        assert BaseAgent._phase_token_budget(f) == phase_token_budget(phase)


class _ConformingBackend:
    name = "dummy"

    def query(self, system_prompt, user_message, **kwargs):
        return "ok"

    def token_budget(self, phase=""):
        return phase_token_budget(phase)

    def is_phase_budget_exceeded(self, phase, max_tokens):
        return False

    def get_usage_stats(self, phase=""):
        return {"phase_approx_tokens": 0}


class _MissingBudgetMethods:
    name = "partial"

    def query(self, system_prompt, user_message, **kwargs):
        return "ok"


def test_protocol_conformance_is_structural():
    assert isinstance(_ConformingBackend(), LLMBackend)
    assert not isinstance(_MissingBudgetMethods(), LLMBackend)


def test_conforming_backend_token_budget_aligns():
    b = _ConformingBackend()
    assert b.token_budget("recon") == phase_token_budget("recon")


def test_real_ai_backend_satisfies_protocol_surface():
    # The production AIBackend must expose the full contract (name + token_budget
    # added in P5-7). Assert the surface without constructing it (init needs keys).
    from core.ai_backend import AIBackend
    for attr in ("name", "query", "token_budget",
                 "is_phase_budget_exceeded", "get_usage_stats"):
        assert hasattr(AIBackend, attr), f"AIBackend missing {attr}"
    assert AIBackend.name  # class-level identifier is set
