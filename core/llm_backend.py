"""P5-7 (D-FUT-3) — the LLMBackend extension contract + the ONE phase-token-budget resolver.

A new LLM backend is any class satisfying ``LLMBackend`` (name + query + the three
budget methods) — never a core edit. Crucially, ``token_budget()`` and the
Phase-4 budget authority (``base_agent._phase_token_budget`` / ``_afford_llm``)
BOTH resolve through the single ``phase_token_budget()`` function here, so the
backend's view of the budget and the agent's can never drift apart.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

# The current backend contract: query() returns the model's response TEXT. Kept as
# a named alias so the Protocol reads ``query(...) -> LLMResult`` faithfully
# without forcing a breaking wrap of the many ``-> str`` call sites; a richer
# result type can replace this alias later without changing the Protocol's shape.
LLMResult = str


def phase_token_budget(phase: str) -> int:
    """THE single resolver for a phase's TOKEN budget (0 = unlimited / unset),
    keyed on the agent/phase name. Both the Phase-4 authority
    (``base_agent._phase_token_budget`` → ``_afford_llm``) and any
    ``LLMBackend.token_budget()`` resolve HERE so the two never diverge. Reads the
    ``config_thresholds`` constants (env > YAML > default already applied there);
    any import failure yields 0 (unlimited) — never a crash."""
    try:
        from config_thresholds import (
            PHASE_TOKEN_BUDGET_RECON,
            PHASE_TOKEN_BUDGET_EXPLOITATION,
            PHASE_TOKEN_BUDGET_DEFAULT,
        )
    except Exception:
        return 0
    name = (phase or "").lower()
    if name == "recon":
        return PHASE_TOKEN_BUDGET_RECON
    if name == "exploitation":
        return PHASE_TOKEN_BUDGET_EXPLOITATION
    return PHASE_TOKEN_BUDGET_DEFAULT


@runtime_checkable
class LLMBackend(Protocol):
    """Structural contract for an LLM backend.

    - ``name``                       — identifier for logging/telemetry.
    - ``query(system, user, ...)``   — returns the model response (``LLMResult``).
    - ``token_budget(phase)``        — the phase TOKEN budget via
      ``phase_token_budget`` (aligns with the Phase-4 authority).
    - ``is_phase_budget_exceeded`` / ``get_usage_stats`` — what ``_afford_llm``
      (P4-2) reads to shed self-correction under budget pressure.

    ``@runtime_checkable`` so ``isinstance(backend, LLMBackend)`` verifies the
    surface a new backend must provide.
    """
    name: str

    def query(self, system_prompt: str, user_message: str, **kwargs) -> LLMResult:
        ...

    def token_budget(self, phase: str = "") -> int:
        ...

    def is_phase_budget_exceeded(self, phase: str, max_tokens: int) -> bool:
        ...

    def get_usage_stats(self, phase: str = "") -> dict:
        ...
