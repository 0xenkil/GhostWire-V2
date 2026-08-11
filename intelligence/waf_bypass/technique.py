"""P5-5 (D-FUT-2) — the WafTechnique extension contract + the Evidence-or-lead gate.

A WAF-bypass technique is anything with a ``name`` and a
``run(target, ctx) -> Evidence | None``. This is the extension SEAM: a new
technique is a class satisfying this Protocol, never a core edit. The engine
treats a technique's result as a CONFIRMED bypass ONLY when it returned an
``Evidence`` that RE-MEASURES ``is_proven()`` True (``confirmed_bypass``); a
``None`` or an unproven ``Evidence`` is a LEAD, not a confirmation — which is how
non-differential techniques (request-smuggling heuristics, credential greps,
origin guesses) demote to leads instead of forging a ``waf_bypassed:True``.
Closes SMUGGLER-FALSEPOS / OOB-STUB / CREDFINDER-NO-VALUE / ORIGIN-STUBS at the
verdict boundary.
"""
from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from core.result_contracts import Evidence


@runtime_checkable
class WafTechnique(Protocol):
    """Structural contract for a WAF-bypass technique.

    Implementors expose a ``name`` and ``run(target, ctx) -> Evidence | None``.
    ``run`` MEASURES an attempt and returns an ``Evidence`` (which the ledger will
    re-verify) or ``None``. It must never return a bare "success" bool — the only
    confirmation currency is a provable ``Evidence``.
    """
    name: str

    def run(self, target: str, ctx) -> Optional[Evidence]:
        ...


def confirmed_bypass(evidence: Optional[Evidence]) -> bool:
    """THE gate a WAF technique's result passes through to become a confirmed
    bypass: True iff it produced an ``Evidence`` that re-measures as proven.
    ``None`` (nothing measured) or an unproven ``Evidence`` (a lead) is never a
    confirmation, so a technique cannot assert its own success."""
    return bool(evidence is not None and evidence.is_proven())
