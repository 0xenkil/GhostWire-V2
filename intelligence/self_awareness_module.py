"""
Self-Awareness Module: Tracks system's own knowledge boundaries and confidence.

The problem it solves:
- System doesn't know what it doesn't know
- Makes overconfident decisions based on incomplete information
- Solution: Track knowledge boundaries and inform AI of gaps

This enables:
1. "I'm not sure about this, need more recon"
2. "We've already tried this tool on this tech, it failed"
3. "This finding contradicts previous findings, which do we trust?"
4. "We're operating with <50% confidence, suggest more data collection"
"""

import json
import logging
from typing import Dict, List, Any
from datetime import datetime, timezone
from collections import defaultdict

log = logging.getLogger(__name__)


class SelfAwarenessModule:
    """Tracks system's knowledge state and confidence boundaries."""

    def __init__(self, state_store=None):
        """
        Initialize self-awareness tracking.

        Args:
            state_store: StateStore for persistent knowledge tracking
        """
        self.store = state_store

        # Knowledge tracking
        self.knowledge_state = {
            "known_facts": [],  # High-confidence findings
            "uncertain_facts": [],  # Medium-confidence findings
            "contradictions": [],  # Conflicting findings
            "unknown_unknowns": [],  # Gaps we've identified
        }

        # Confidence tracking per finding type
        self.confidence_by_type = defaultdict(
            lambda: {"high": 0, "medium": 0, "low": 0})

        # Tool effectiveness history
        self.tool_outcomes = defaultdict(
            lambda: {
                "success": 0,
                "failure": 0,
                "inconclusive": 0})

        # Tactical assumptions
        self.active_assumptions = []  # Assumptions guiding current tactics
        self.validated_assumptions = []  # Assumptions proven correct
        self.failed_assumptions = []  # Assumptions proven wrong

    def register_finding(self, finding: Dict[str, Any]) -> None:
        """
        Register a finding and track its confidence level.

        Args:
            finding: Finding dict with type, confidence, etc
        """
        confidence = finding.get("confidence", 0.5)
        finding_type = finding.get("type", "unknown")

        # Categorize by confidence
        if confidence >= 0.8:
            self.knowledge_state["known_facts"].append(finding)
            self.confidence_by_type[finding_type]["high"] += 1
        elif confidence >= 0.5:
            self.knowledge_state["uncertain_facts"].append(finding)
            self.confidence_by_type[finding_type]["medium"] += 1
        else:
            self.confidence_by_type[finding_type]["low"] += 1

        # Detect contradictions
        self._check_for_contradictions(finding)

    def _check_for_contradictions(self, new_finding: Dict[str, Any]) -> None:
        """
        Check if new finding contradicts existing knowledge.
        """
        new_target = new_finding.get("target", "")
        new_detail = new_finding.get("detail", "").lower()

        for existing in self.knowledge_state["known_facts"]:
            if existing.get("target") == new_target:
                # Same target, different finding - potential contradiction
                existing_detail = existing.get("detail", "").lower()

                # Simple contradiction detection
                if "not" in new_detail and "not" not in existing_detail:
                    self.knowledge_state["contradictions"].append({
                        "finding_1": existing.get("detail"),
                        "finding_2": new_finding.get("detail"),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "resolution": "unresolved"
                    })

    def register_knowledge_gap(self, gap: Dict[str, Any]) -> None:
        """
        Register an identified knowledge gap.

        Args:
            gap: Gap dict with description, why_it_matters, how_to_find_out
        """
        self.knowledge_state["unknown_unknowns"].append({
            "gap": gap.get("gap", ""),
            "why_it_matters": gap.get("why_it_matters", ""),
            "how_to_find_out": gap.get("how_to_find_out", ""),
            "identified_at": datetime.now(timezone.utc).isoformat(),
            "resolved": False
        })

    def register_assumption(self, assumption: str,
                            confidence: float = 0.5) -> str:
        """
        Register a tactical assumption we're making.
        Returns assumption ID for later validation.
        """
        assumption_id = f"ASSUME_{len(self.active_assumptions)}"

        self.active_assumptions.append({
            "id": assumption_id,
            "assumption": assumption,
            "confidence": confidence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "validated": False,
            "outcome": None
        })

        return assumption_id

    def validate_assumption(self, assumption_id: str, was_correct: bool,
                            evidence: str = None) -> None:
        """
        Record outcome of an assumption.
        """
        for assumption in self.active_assumptions:
            if assumption["id"] == assumption_id:
                assumption["validated"] = True
                assumption["outcome"] = was_correct
                assumption["evidence"] = evidence

                if was_correct:
                    self.validated_assumptions.append(assumption)
                else:
                    self.failed_assumptions.append(assumption)

                # Learn: if high-confidence assumption failed, note it
                if not was_correct and assumption["confidence"] >= 0.7:
                    log.warning(
                        f"High-confidence assumption failed: {assumption['assumption']}")

                break

    def register_tool_outcome(self, tool: str, target_type: str, success: bool,
                              output_size: int = 0) -> None:
        """
        Register outcome of tool execution.
        """
        outcome_type = "success" if success else "failure"
        self.tool_outcomes[f"{tool}_{target_type}"][outcome_type] += 1

        # Detect patterns: tool always fails on certain tech?
        stats = self.tool_outcomes[f"{tool}_{target_type}"]
        total = sum(stats.values())
        success_rate = stats["success"] / total if total > 0 else 0

        if total >= 3 and success_rate < 0.2:
            print(
                f"[!] PATTERN: {tool} has low success rate on {target_type} ({
                    success_rate:.0%})")

    def get_current_knowledge_state(self) -> Dict[str, Any]:
        """
        Return current system knowledge state for AI context.
        Useful for AI to understand what it knows vs doesn't know.
        """
        return {
            "known_facts_count": len(self.knowledge_state["known_facts"]),
            "uncertain_facts_count": len(self.knowledge_state["uncertain_facts"]),
            "contradictions_count": len(self.knowledge_state["contradictions"]),
            "knowledge_gaps_count": len(self.knowledge_state["unknown_unknowns"]),
            "high_confidence_by_type": dict(
                (t, stats["high"]) for t, stats in self.confidence_by_type.items()
            ),
            "medium_confidence_by_type": dict(
                (t, stats["medium"]) for t, stats in self.confidence_by_type.items()
            ),
            "active_assumptions": len([a for a in self.active_assumptions if not a["validated"]]),
            "validated_assumptions": len(self.validated_assumptions),
            "failed_assumptions": len(self.failed_assumptions),
            "overall_confidence": self._calculate_overall_confidence()
        }

    def _calculate_overall_confidence(self) -> str:
        """
        Calculate overall system confidence in its knowledge.
        """
        known = len(self.knowledge_state["known_facts"])
        uncertain = len(self.knowledge_state["uncertain_facts"])
        contradictions = len(self.knowledge_state["contradictions"])
        gaps = len(self.knowledge_state["unknown_unknowns"])

        total_facts = known + uncertain

        if total_facts == 0:
            return "insufficient_data"

        confidence_score = (known / total_facts) if total_facts > 0 else 0

        # Penalize contradictions and gaps
        if contradictions > 0:
            confidence_score *= 0.8
        if gaps > 0:
            confidence_score *= 0.9

        if confidence_score >= 0.7:
            return "high"
        elif confidence_score >= 0.4:
            return "medium"
        else:
            return "low"

    def suggest_data_collection(self) -> List[Dict[str, Any]]:
        """
        AI-friendly suggestion: what data should we collect next?
        Based on knowledge gaps and low-confidence areas.
        """
        suggestions = []

        # Suggest addressing knowledge gaps
        for gap in self.knowledge_state["unknown_unknowns"][:3]:
            if not gap.get("resolved"):
                suggestions.append({
                    "priority": "high",
                    "type": "knowledge_gap",
                    "description": gap.get("gap"),
                    "method": gap.get("how_to_find_out"),
                    "why": gap.get("why_it_matters")
                })

        # Suggest validating uncertain findings
        uncertain_by_type = defaultdict(list)
        for fact in self.knowledge_state["uncertain_facts"][:5]:
            uncertain_by_type[fact.get("type", "unknown")].append(fact)

        for finding_type, facts in uncertain_by_type.items():
            suggestions.append({
                "priority": "medium",
                "type": "validate_uncertain",
                "description": f"Validate {len(facts)} uncertain {finding_type} findings",
                "method": "additional_recon",
                "why": "Increase confidence in exploitation tactics"
            })

        return suggestions

    def get_confidence_report(self) -> str:
        """
        Human-readable confidence report for system self-awareness.
        """
        state = self.get_current_knowledge_state()

        # Don't emit a MISLEADING "0 facts / INSUFFICIENT_DATA" report when this
        # instance was never populated. register_finding is recon-only and each
        # agent owns its own awareness instance, so exploitation's was always
        # empty — injecting a fake "you know nothing" nudges the brain to over-
        # cautiously re-recon when recon already found plenty. Empty = silent.
        if (state["known_facts_count"] == 0
                and state["uncertain_facts_count"] == 0
                and state["knowledge_gaps_count"] == 0
                and state["active_assumptions"] == 0
                and state["validated_assumptions"] == 0
                and state["failed_assumptions"] == 0):
            return ""

        report = f"""
SYSTEM SELF-AWARENESS REPORT
=============================

Knowledge State:
  - Known facts: {state['known_facts_count']}
  - Uncertain facts: {state['uncertain_facts_count']}
  - Contradictions: {state['contradictions_count']}
  - Knowledge gaps: {state['knowledge_gaps_count']}

Confidence Level: {state['overall_confidence'].upper()}

Tactical Assumptions:
  - Active: {state['active_assumptions']}
  - Validated: {state['validated_assumptions']}
  - Failed: {state['failed_assumptions']}

High-Confidence Finding Types: {dict(state.get('high_confidence_by_type', {}))}

Next Steps:
{json.dumps(self.suggest_data_collection(), indent=2)}
"""
        return report

    # ── W8.1: OPS SANITY LAYER ──────────────────────────────────────────────
    # The engine has repeatedly fooled itself with conclusions that contradict
    # its own operational plumbing (a Tor connect-scan reporting all 65535 ports
    # "open" → "honeypot"; a 200 identical to baseline → "WAF bypass PROVEN";
    # `crontab -l` on the local scanner box → "target has crontab access"). This
    # layer cross-checks an exotic conclusion against known operational context
    # BEFORE it is trusted, and returns a plausibility verdict the AI must weigh.

    def ops_sanity_check(self, conclusion: str,
                         ops_context: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Reality-check an exotic conclusion against operational context.

        Args:
            conclusion: the asserted finding/claim text (e.g. "all ports open").
            ops_context: live ops facts that can explain-away the conclusion,
                e.g. {"proxy_active": True, "scan_type": "connect",
                      "open_port_count": 65535, "response_vs_baseline_similarity": 0.99,
                      "ran_on_target": False, "has_target_foothold": False}.

        Returns a dict:
            {"plausible": bool, "confidence_cap": float, "reasons": [str, ...]}
        The caller (agent) injects `reasons` into the AI prompt and treats
        `confidence_cap` as a ceiling so a self-fooling artifact cannot be
        promoted to a confirmed finding. This is advisory, not a hard block —
        the AI can still pursue a lead, it just cannot CONFIRM it on artifact.
        """
        ctx = ops_context or {}
        text = (conclusion or "").lower()
        reasons: List[str] = []
        confidence_cap = 1.0

        # 1. "Everything open" through a proxy/connect-scan is an artifact.
        port_count = ctx.get("open_port_count", 0)
        proxy_active = ctx.get("proxy_active", False)
        scan_type = (ctx.get("scan_type", "") or "").lower()
        if isinstance(port_count, (int, float)) and port_count >= 1000:
            if proxy_active or scan_type in ("connect", "st", "-st"):
                reasons.append(
                    f"{int(port_count)} 'open' ports via a "
                    f"{'proxy' if proxy_active else 'connect'}-scan is almost "
                    "certainly a CONNECT artifact, not real services.")
                confidence_cap = min(confidence_cap, 0.1)

        # 2. A 'bypass'/'vuln'/'confirmed' that matches baseline proves nothing.
        sim = ctx.get("response_vs_baseline_similarity")
        if sim is not None and isinstance(sim, (int, float)) and sim >= 0.97:
            if any(k in text for k in (
                    "bypass", "vuln", "confirmed", "proven", "exploit", "injection")):
                reasons.append(
                    f"Response is {sim:.0%} identical to the control baseline — "
                    "no observable differential, so this cannot be a confirmed "
                    "bypass/vuln. Downgrade to lead.")
                confidence_cap = min(confidence_cap, 0.1)

        # 3. Host-level claims when the command ran locally, not on the target.
        host_markers = (
            "crontab", "shell access", "user has", "we have access",
            "root", "sudo", "persistence", "foothold", "/etc/", "ssh key")
        if any(m in text for m in host_markers):
            if ctx.get("ran_on_target") is False or ctx.get("has_target_foothold") is False:
                reasons.append(
                    "Host-level claim, but the command ran on the local scanner "
                    "box (no confirmed target foothold). It describes OUR host, "
                    "not the target.")
                confidence_cap = min(confidence_cap, 0.1)

        plausible = confidence_cap >= 0.5
        if reasons:
            self.knowledge_state["contradictions"].append({
                "finding_1": conclusion,
                "finding_2": "ops_sanity: " + "; ".join(reasons),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "resolution": "ops_artifact_suspected",
            })

        return {
            "plausible": plausible,
            "confidence_cap": confidence_cap,
            "reasons": reasons,
        }
