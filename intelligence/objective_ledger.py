"""
WS5 — Objective-Driven Orchestration.

The engine was a tool-centric waterfall driven by loop counters: it ran
planning→recon→exploitation→… and stopped at MIN/MAX loops regardless of whether
it had actually achieved anything. A real red team is objective-centric: it
knows what "win" means (get access, read another tenant's data, prove RCE, reach
admin) and stops when those are met or genuinely exhausted.

`ObjectiveLedger` makes the engagement's goals explicit, maps findings to
objective progress, drives momentum/abandon decisions, and provides real stop
conditions. It is evidence-driven (an objective only advances on a finding that
demonstrates it), so it cannot be fooled into "done" by activity alone.
"""

from dataclasses import dataclass
from typing import Optional


# Default objective set. NOT hardcoded target logic — these are generic
# red-team goals; which are *relevant* is refined from mode + Target Model.
PRIMARY = "primary"
SECONDARY = "secondary"

_DEFAULT_OBJECTIVES = [
    # key, label, weight, markers that (in a confirmed finding) demonstrate it
    ("authenticated_access", "Gain authenticated access", PRIMARY,
     ("valid_credential", "shell_access", "initial_access", "login successful",
      "authenticated session", "session acquired")),
    ("object_authz_bug", "Prove object/function-level authz bug (IDOR/BOLA)", PRIMARY,
     ("idor", "bola", "object-level authorization", "broken object",
      "broken function level")),
    ("sensitive_data", "Extract sensitive data", PRIMARY,
     ("data extraction", "dumped", "extracted", "/etc/passwd", "password",
      "credential", "api key", "secret", "token leak", "pii")),
    ("rce", "Achieve remote code execution", PRIMARY,
     ("rce", "remote code execution", "reverse shell", "command execution",
      "code execution")),
    ("admin_access", "Reach admin / management", SECONDARY,
     ("admin access", "administrative", "privilege escalation", "admin panel")),
]


@dataclass
class Objective:
    key: str
    label: str
    tier: str
    markers: tuple
    status: str = "pending"        # pending | in_progress | achieved | abandoned
    evidence: str = ""
    attempts: int = 0

    def to_dict(self) -> dict:
        return {"key": self.key, "label": self.label, "tier": self.tier,
                "status": self.status, "evidence": self.evidence[:200],
                "attempts": self.attempts}


class ObjectiveLedger:
    """Tracks objectives, scores progress, and drives stop/abandon decisions."""

    def __init__(self, mode: str = "pentest", target_model: Optional[dict] = None):
        self.mode = mode
        self.objectives = {
            o[0]: Objective(key=o[0], label=o[1], tier=o[2], markers=o[3])
            for o in _DEFAULT_OBJECTIVES
        }
        self._idle_streak = 0
        self._last_progress_count = 0
        if target_model:
            self._tailor_to_target(target_model)

    def _tailor_to_target(self, tm: dict) -> None:
        """Mark objectives that are implausible on this target as abandoned up
        front (evidence-driven relevance), e.g. RCE on a static SPA apex."""
        implausible = " ".join(tm.get("implausible_vuln_classes", []) or []).lower()
        ttype = (tm.get("target_type", "") or "").lower()
        if ttype in ("spa", "api", "static") and ("rce" in implausible or "command" in implausible):
            self.objectives["rce"].status = "abandoned"
            self.objectives["rce"].evidence = "implausible on this target type per Target Model"
        # An api/spa elevates the object-authz objective (its core surface).
        if ttype in ("api", "spa"):
            self.objectives["object_authz_bug"].tier = PRIMARY

    # ── progress ──────────────────────────────────────────────────────────────

    def update_from_findings(self, findings: list) -> list:
        """Advance objectives from confirmed findings. Returns newly-achieved keys."""
        newly = []
        confirmed = [
            f for f in (findings or [])
            if (f.get("type", "") or "").lower() in (
                "confirmed_vulnerability", "valid_credential", "shell_access",
                "initial_access", "rce_confirmed")
            or (f.get("severity", "") or "").lower() in ("high", "critical")
        ]
        for obj in self.objectives.values():
            if obj.status in ("achieved", "abandoned"):
                continue
            for f in confirmed:
                blob = (str(f.get("type", "")) + " " + str(f.get("detail", ""))).lower()
                if any(m in blob for m in obj.markers):
                    obj.status = "achieved"
                    obj.evidence = str(f.get("detail", ""))[:200]
                    newly.append(obj.key)
                    break
        # momentum bookkeeping
        progressed = len(confirmed)
        if progressed > self._last_progress_count or newly:
            self._idle_streak = 0
        else:
            self._idle_streak += 1
        self._last_progress_count = progressed
        return newly

    def mark_in_progress(self, key: str) -> None:
        o = self.objectives.get(key)
        if o and o.status == "pending":
            o.status = "in_progress"
        if o:
            o.attempts += 1

    # ── controller signals (W5.3 momentum/abandon, W5.4 stop) ─────────────────

    @property
    def idle_streak(self) -> int:
        return self._idle_streak

    def primary_objectives(self) -> list:
        return [o for o in self.objectives.values() if o.tier == PRIMARY]

    def active_primaries(self) -> list:
        return [o for o in self.primary_objectives()
                if o.status not in ("achieved", "abandoned")]

    def achieved(self) -> list:
        return [o for o in self.objectives.values() if o.status == "achieved"]

    def should_stop(self, idle_limit: int = 6) -> tuple[bool, str]:
        """W5.4 — stop on objective completion or genuine exhaustion, not loops."""
        if not self.active_primaries():
            done = [o.label for o in self.achieved()]
            return True, (f"All primary objectives resolved (achieved: {done or 'none achievable'})."
                          if done else "No primary objectives remain achievable.")
        if self._idle_streak >= idle_limit:
            return True, (f"Genuine exhaustion: {self._idle_streak} consecutive loops with no "
                          "objective progress across all active threads.")
        return False, ""

    def momentum(self, produced_findings: bool) -> str:
        """W5.3 — promote the momentum hint to an objective-aware directive."""
        if produced_findings:
            return ("HIGH — last actions advanced an objective; press THIS thread deeper")
        if self._idle_streak == 0:
            return ("MEDIUM — actions running but no objective progress; vary technique/parameter")
        active = ", ".join(o.label for o in self.active_primaries()[:3]) or "none"
        return (f"LOW — {self._idle_streak} idle loop(s); ABANDON this approach and pivot toward "
                f"an unmet objective: {active}")

    def format_for_prompt(self, produced_findings: bool = False) -> str:
        lines = ["### 🎯 OBJECTIVE LEDGER (win conditions — drive toward these)"]
        for o in self.objectives.values():
            icon = {"achieved": "✅", "abandoned": "⬛", "in_progress": "🔄",
                    "pending": "⬜"}.get(o.status, "⬜")
            tier = "P" if o.tier == PRIMARY else "S"
            line = f"{icon} [{tier}] {o.label} — {o.status}"
            if o.status == "achieved" and o.evidence:
                line += f" ({o.evidence[:80]})"
            lines.append(line)
        lines.append(f"Momentum: {self.momentum(produced_findings)}")
        return "\n".join(lines) + "\n"

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "objectives": [o.to_dict() for o in self.objectives.values()],
            "idle_streak": self._idle_streak,
        }
