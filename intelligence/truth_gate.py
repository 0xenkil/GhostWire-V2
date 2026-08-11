"""TruthGate (P3-5, §3.5) — admit a persistent self-upgrade ONLY when real proof
backs it.

A self-modifying engine that rewrites its own tool metrics / generation rules on
a *schema* check (or on unproven "it ran" signals) drifts itself into garbage.
TruthGate is the one predicate the apply paths (auto_upgrader, rule_generator)
must pass before persisting a change: the change must be supported by at least
`min_proven` PROOF-BACKED outcomes whose proven success-rate on a held-out slice
does not regress. If it cannot be evaluated, it returns False — fail-closed to
dry-run, never fail-open.
"""

from __future__ import annotations

from typing import List

from intelligence.learning_signal import LearningOutcome


class TruthGate:
    def __init__(self, proven_outcomes: List[LearningOutcome] | None = None):
        # Keep ONLY genuinely proof-backed outcomes — the clean-execution
        # fallback (Tier 2) is not strong enough to justify a permanent
        # self-modification.
        self._outcomes = [
            o for o in (proven_outcomes or [])
            if getattr(o, "is_proof_backed", False)
        ]

    def supports(self, change: dict, min_proven: int = 3,
                 holdout: float = 0.3) -> bool:
        """A persistent self-upgrade is admitted ONLY if backed by >= min_proven
        proof-backed outcomes whose proven success-rate on a held-out slice does
        not regress vs the training slice. Unevaluable → False (stay dry-run)."""
        if not isinstance(change, dict) or min_proven <= 0:
            return False
        outcomes = self._relevant(change)
        if len(outcomes) < min_proven:
            return False

        # Deterministic split (no RNG — must be reproducible across resume):
        # the tail `holdout` fraction is the held-out slice.
        n = len(outcomes)
        cut = max(1, int(round(n * (1.0 - holdout))))
        if cut >= n:  # too few to hold anything out → cannot evaluate
            return False
        train, held = outcomes[:cut], outcomes[cut:]

        train_rate = self._proven_rate(train)
        held_rate = self._proven_rate(held)
        if train_rate is None or held_rate is None:
            return False
        # Non-regressing: the held-out proven-rate must not fall materially below
        # the training rate (small tolerance for split noise).
        return held_rate >= (train_rate - 0.10)

    # ── helpers ──────────────────────────────────────────────────────────────
    def _relevant(self, change: dict) -> List[LearningOutcome]:
        """Outcomes this change is about. A change may scope to a tool / tactic;
        an unscoped change is judged against all proof-backed outcomes."""
        tool = str(change.get("tool", "")).strip().lower()
        tactic = change.get("evasion_tactic") or change.get("tactic")
        out = self._outcomes
        if tool:
            out = [o for o in out if (o.tool or "").lower() == tool]
        if tactic:
            out = [o for o in out if (o.evasion_tactic or "") == tactic]
        return out

    @staticmethod
    def _proven_rate(outcomes: List[LearningOutcome]):
        if not outcomes:
            return None
        return sum(1 for o in outcomes if o.proven) / len(outcomes)
