"""Learning-from-proof signal (P3-1, §3.5).

The SINGLE contract every learner reads to decide "did this actually work?".

Two honest tiers, in priority order:
  1. **Proven** — a real re-measured `Evidence` object (`proof.is_proven()`). This
     is the only tier the engine may call "proven" to the user.
  2. **Clean-execution fallback** — used where no proof object exists (e.g. a
     recon tool that can't produce an Evidence): the run executed cleanly AND
     produced an actionable result (`_produced_result`, the P0-9 signal) AND was
     not WAF-blocked AND shows no generic process-failure marker. This is a
     signal-cleaned execution verdict, NOT "proven" — labelled as such.

The classification **authority is `produced_result` + process/exit semantics** —
never a per-tool substring table. `HARD_FAIL_MARKERS` is a NARROW, tool-agnostic
*process*-failure set used only as a fast-path hint that `_produced_result` can
override (a run that genuinely produced parsed results is not a failure even if
its noise happens to contain one of these). This is the invariant that keeps the
plan from condemning substring-classification-as-authority in Phase 0 and then
re-enshrining it here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.result_contracts import Evidence


# NARROW, tool-agnostic PROCESS-failure markers. NOT per-tool, NOT syntax-level —
# these mean the OS/process itself failed to run the tool usefully. A fast-path
# hint only: `_produced_result` overrides it. Kept as the single shared source
# (syntax_learner imports it and adds its own syntax-validity markers on top).
HARD_FAIL_MARKERS: tuple[str, ...] = (
    "command not found",
    "permission denied",
    "operation not permitted",
    "segmentation fault",
    "no space left",
    "cannot allocate memory",
    "killed",
    "core dumped",
)

# Clean-execution statuses (string form, matching ResultStatus values / aliases).
_CLEAN_STATUSES = frozenset({
    "success", "partial", "partial_success", "fallback_success",
})


def looks_like_failure(text: str) -> bool:
    """True iff the output carries a generic PROCESS-failure marker. A fast-path
    hint, not an authority — callers combine it with `_produced_result` (which
    wins) and exit semantics."""
    if not text:
        return False
    low = text.lower()
    return any(m in low for m in HARD_FAIL_MARKERS)


@dataclass(frozen=True)
class LearningOutcome:
    """One tool run reduced to what a learner may safely learn from.

    Build it from a proof (`from_confirmed_hypothesis`) when one exists, or from a
    cleaned execution verdict (`from_result`) otherwise. Read `.proven`.
    """
    tool: str
    target_type: str = "generic"
    evasion_tactic: Optional[str] = None
    duration: float = 0.0
    waf_blocked: bool = False
    proof: Optional[Evidence] = None
    tool_run_id: Optional[int] = None  # P0-10 exact originating-run link, if known
    _raw_status: str = ""
    _output: str = ""
    _produced_result: bool = True

    @property
    def proven(self) -> bool:
        # Tier 1 — a real, re-measured proof.
        if self.proof is not None:
            try:
                return bool(self.proof.is_proven())
            except Exception:
                return False
        # Tier 2 — honest clean-execution fallback (NOT called "proven" to the
        # user). Authority = produced_result + status; the marker is a hint only.
        return (
            self._raw_status in _CLEAN_STATUSES
            and self._produced_result
            and not self.waf_blocked
            and not looks_like_failure(self._output)
        )

    @property
    def is_proof_backed(self) -> bool:
        """True only for Tier-1 (a real Evidence). Lets a consumer that must NOT
        accept the clean-execution fallback (e.g. TruthGate) demand real proof."""
        return self.proof is not None and self.proven

    @classmethod
    def from_confirmed_hypothesis(cls, tool: str, proof: Evidence, **kw) -> "LearningOutcome":
        """Carry the Evidence and let `.proven` call `is_proven()` directly — never
        trust a `status == 'confirmed'` label."""
        return cls(tool=tool, proof=proof, **kw)

    @classmethod
    def from_result(cls, tool: str, result, *, evasion_tactic: str = None,
                    target_type: str = "generic",
                    capability: str = "") -> "LearningOutcome":
        """Build the clean-execution fallback from a ToolResult. Reuses the P0-9
        `produced_result` signal so "ran clean, proved nothing" (nmap host-up /
        no-ports, gobuster all-404, sqlmap not-injectable) does NOT score proven."""
        status = getattr(result, "status", "")
        status = str(getattr(status, "value", status)).lower()
        out = ((getattr(result, "stdout", "") or "") + "\n"
               + (getattr(result, "stderr", "") or "")).strip()
        try:
            produced = bool(result.produced_result(capability))
        except Exception:
            produced = False
        waf = status in {"waf_blocked", "blocked", "captcha_blocked"}
        return cls(
            tool=tool, target_type=target_type, evasion_tactic=evasion_tactic,
            duration=float(getattr(result, "duration_seconds", 0.0) or 0.0),
            waf_blocked=waf,
            tool_run_id=getattr(result, "tool_run_id", None),
            _raw_status=status, _output=out, _produced_result=produced,
        )
