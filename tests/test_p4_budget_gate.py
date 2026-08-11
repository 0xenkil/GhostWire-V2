"""Phase 4 — P4-2 budget-gated self-correction stack (RC-4 / DEEP-3 / DEEP-10).

`_afford_llm(kind)` is the ONE authority deciding whether the engine may spend a
live LLM call on self-correction (triage / repair / grounding / mentor). It is
built ON TOP of the existing is_phase_budget_exhausted() and keys on the TOKEN
budget (_phase_token_budget), never wall-clock seconds. As the phase token
budget drains, the lowest-value kinds shed first (grounding/mentor, then repair)
while triage rides to full exhaustion — because triage's accept/abandon verdict
is what curbs further spend. When it sheds, the caller falls through to the
loop's deterministic classifiers instead of paying for an LLM it can't afford.
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.base_agent import BaseAgent  # noqa: E402


class _AI:
    """Minimal AI backend exposing the same budget surface the real one does."""

    def __init__(self, used_tokens):
        self._used = used_tokens

    def get_usage_stats(self, phase=""):
        return {"phase_approx_tokens": self._used}

    def is_phase_budget_exceeded(self, phase, max_tokens):
        return self._used >= max_tokens


def _fake(used_tokens=0, budget=1000, ai=None):
    """A minimal `self` carrying only what _afford_llm touches, with the REAL
    is_phase_budget_exhausted bound so the single-authority ceiling is exercised."""
    f = types.SimpleNamespace(
        name="recon",
        ai=_AI(used_tokens) if ai is None else ai,
        _LLM_SHED_FRACTIONS=BaseAgent._LLM_SHED_FRACTIONS,
        log=types.SimpleNamespace(info=lambda *a, **k: None,
                                  debug=lambda *a, **k: None,
                                  warning=lambda *a, **k: None),
    )
    # Fixed budget so the fraction math is trivial and config-independent.
    f._phase_token_budget = lambda: budget
    f.is_phase_budget_exhausted = types.MethodType(
        BaseAgent.is_phase_budget_exhausted, f)
    f._afford_llm = types.MethodType(BaseAgent._afford_llm, f)
    return f


def _afford(f):
    return {k: f._afford_llm(k)
            for k in ("triage", "repair", "grounding", "mentor")}


def test_fresh_budget_affords_everything():
    a = _afford(_fake(used_tokens=0))
    assert a == {"triage": True, "repair": True, "grounding": True, "mentor": True}


def test_70pct_sheds_grounding_and_mentor_only():
    # 700/1000 = 0.70 → grounding/mentor shed (>= 0.70); repair/triage still on.
    a = _afford(_fake(used_tokens=700))
    assert a["grounding"] is False and a["mentor"] is False
    assert a["repair"] is True and a["triage"] is True


def test_85pct_sheds_repair_too_triage_survives():
    # 900/1000 = 0.90 → repair shed (>= 0.85); triage rides on until exhaustion.
    a = _afford(_fake(used_tokens=900))
    assert a["grounding"] is False and a["mentor"] is False
    assert a["repair"] is False
    assert a["triage"] is True


def test_full_exhaustion_sheds_every_kind_including_triage():
    # used >= budget → is_phase_budget_exhausted() True → the ceiling sheds all.
    a = _afford(_fake(used_tokens=1000))
    assert a == {"triage": False, "repair": False, "grounding": False, "mentor": False}


def test_just_under_shed_points_are_inclusive_boundaries():
    # 699/1000 = 0.699 < 0.70 → grounding/mentor still affordable.
    a = _afford(_fake(used_tokens=699))
    assert a["grounding"] is True and a["mentor"] is True
    # 849/1000 = 0.849 < 0.85 → repair still affordable.
    b = _afford(_fake(used_tokens=849))
    assert b["repair"] is True


def test_fail_open_when_no_token_budget():
    # budget 0 = unlimited/unset → never gate, regardless of (nonsense) usage.
    f = _fake(used_tokens=10_000, budget=0)
    assert _afford(f) == {"triage": True, "repair": True,
                          "grounding": True, "mentor": True}


def test_fail_open_when_backend_has_no_usage_tracking():
    # A backend that can't report usage must never cause a self-correction to be
    # shed — same fail-open contract as is_phase_budget_exhausted().
    ai = types.SimpleNamespace()  # no get_usage_stats / is_phase_budget_exceeded
    f = _fake(budget=1000, ai=ai)
    assert _afford(f) == {"triage": True, "repair": True,
                          "grounding": True, "mentor": True}


def test_uses_token_budget_not_wallclock():
    # _phase_token_budget for a recon agent is the TOKEN constant (400k), proving
    # the gate reads tokens, not _phase_budget_total (wall-clock seconds).
    from config_thresholds import PHASE_TOKEN_BUDGET_RECON
    f = types.SimpleNamespace(name="recon")
    assert BaseAgent._phase_token_budget(f) == PHASE_TOKEN_BUDGET_RECON
    assert PHASE_TOKEN_BUDGET_RECON > 1000  # tokens, not a seconds-scale number
