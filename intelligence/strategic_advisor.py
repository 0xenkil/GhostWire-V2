"""
Strategic Advisor: AI-driven autonomous decision layer

Learns from every engagement and scan to make intelligent decisions about:
- What tools to use based on tech stack and history
- What WAF evasion tactics work best per target type
- What NOT to do (avoid failed patterns)
- When to pivot strategies
- Risk/reward of different approaches

Zero hardcoding: All decisions driven by accumulated knowledge from previous engagements.
"""

import json
import os
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from collections import defaultdict


class StrategicAdvisor:
    """AI-driven strategic advisor that learns from every engagement."""

    # P3-4 (ADVISOR-NONATOMIC-SAVE): every agent builds its own StrategicAdvisor
    # pointing at the SAME strategic_knowledge.json, so concurrent saves raced and
    # a non-atomic write could truncate the file. One process-wide lock serializes
    # writers; the write itself is atomic (temp + os.replace).
    _save_lock = threading.Lock()

    def __init__(self, state_store=None, ai_backend=None,
                 knowledge_dir: str = None):
        self.store = state_store
        self.ai = ai_backend
        if knowledge_dir is None:
            from config_paths import INTEL_DIR
            self.knowledge_dir = INTEL_DIR
        else:
            self.knowledge_dir = Path(knowledge_dir)
        self.knowledge_dir.mkdir(exist_ok=True)

        # Load or initialize knowledge base
        self.knowledge_base = self._load_knowledge_base()
        self.current_engagement_id = None

    def _load_knowledge_base(self) -> Dict[str, Any]:
        """Load accumulated knowledge from disk."""
        kb_file = self.knowledge_dir / "strategic_knowledge.json"
        if kb_file.exists():
            try:
                return json.loads(kb_file.read_text())
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f'Swallowed exception in strategic_advisor.py: {_e}')

        return {
            "tool_effectiveness": defaultdict(lambda: {"success": 0, "failure": 0, "avg_time": 0}),
            "tech_stack_patterns": {},  # tech -> [tools that work]
            "waf_bypass_tactics": {},  # waf_type -> [tactics that work]
            "failed_approaches": [],  # approaches to avoid
            "successful_pivots": [],  # when we switched strategy and won
            "discovery_patterns": {},  # discovery order that works best
            "engagement_summaries": [],  # high-level summaries of engagements
        }

    def _save_knowledge_base(self):
        """Persist knowledge to disk ATOMICALLY (P3-4). Convert defaultdicts to
        regular dicts, serialize once, then temp-write + os.replace under a
        process-wide lock so concurrent agent writers can never truncate or
        interleave into a corrupt strategic_knowledge.json."""
        kb_file = self.knowledge_dir / "strategic_knowledge.json"
        kb_serializable = {
            "tool_effectiveness": dict(self.knowledge_base["tool_effectiveness"]),
            "tech_stack_patterns": self.knowledge_base["tech_stack_patterns"],
            "waf_bypass_tactics": self.knowledge_base["waf_bypass_tactics"],
            "failed_approaches": self.knowledge_base["failed_approaches"],
            "successful_pivots": self.knowledge_base["successful_pivots"],
            "discovery_patterns": self.knowledge_base["discovery_patterns"],
            "engagement_summaries": self.knowledge_base["engagement_summaries"],
        }
        payload = json.dumps(kb_serializable, indent=2)
        with StrategicAdvisor._save_lock:
            tmp = str(kb_file) + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(payload)
            os.replace(tmp, str(kb_file))

    def set_engagement_context(
            self, engagement_id: str, target: str, tech_stack: List[str] = None):
        """Set current engagement context for strategic decisions."""
        self.current_engagement_id = engagement_id
        self.current_target = target
        self.current_tech_stack = tech_stack or []

    def _tool_entry(self, tool: str) -> Dict[str, Any]:
        """Get or create tool entry in knowledge base."""
        key = (tool or "unknown").lower()
        if key not in self.knowledge_base["tool_effectiveness"]:
            self.knowledge_base["tool_effectiveness"][key] = {
                "success": 0, "failure": 0, "avg_time": 0}
        return self.knowledge_base["tool_effectiveness"][key]

    def record_tool_outcome(self, tool: str, target: str,
                            success: bool, duration: float = 0.0, phase: str = None):
        """Record whether a tool worked so future scans can prefer or avoid it."""
        entry = self._tool_entry(tool)
        if success:
            entry["success"] += 1
        else:
            entry["failure"] += 1

        total = entry["success"] + entry["failure"]
        if duration and total > 0:
            previous = float(entry.get("avg_time", 0) or 0)
            entry["avg_time"] = (
                (previous * (total - 1)) + float(duration)) / total

        if not success:
            failed_approach = {
                "approach": tool,
                "target": target,
                "phase": phase,
                "reason": "tool_failure",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.knowledge_base["failed_approaches"].append(failed_approach)

        self._save_knowledge_base()

    def record_finding(self, finding_type: str, target: str,
                       detail: str, severity: str = "info", confidence: float = 0.5):
        """Record a finding so future prompts can reuse what was learned."""
        summary_key = f"{finding_type}:{severity}".lower()
        tech_patterns = self.knowledge_base.setdefault("finding_patterns", {})
        if summary_key not in tech_patterns:
            tech_patterns[summary_key] = []
        tech_patterns[summary_key].append({
            "target": target,
            "detail": detail[:250],
            "confidence": confidence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self._save_knowledge_base()

    def record_waf_detection(self, waf_type: str, tactics: List[str] = None):
        """Record WAF type and the tactics that were attempted or worked."""
        waf_key = (waf_type or "unknown").lower()
        tactics = tactics or []
        if waf_key not in self.knowledge_base["waf_bypass_tactics"]:
            self.knowledge_base["waf_bypass_tactics"][waf_key] = []
        for tactic in tactics:
            if tactic not in self.knowledge_base["waf_bypass_tactics"][waf_key]:
                self.knowledge_base["waf_bypass_tactics"][waf_key].append({
                    "tactic": tactic,
                    "success": None,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        self._save_knowledge_base()

    def record_tech_discovery(self, tech: str, target: str = None):
        """Track tech stack discoveries for future tool selection."""
        tech_key = (tech or "unknown").lower()
        if tech_key not in self.knowledge_base["tech_stack_patterns"]:
            self.knowledge_base["tech_stack_patterns"][tech_key] = {
                "successful_tools": [],
                "failed_tools": [],
                "best_discovery_order": [],
                "typical_findings": [],
            }
        if target:
            self.knowledge_base["tech_stack_patterns"][tech_key].setdefault(
                "targets", [])
            if target not in self.knowledge_base["tech_stack_patterns"][tech_key]["targets"]:
                self.knowledge_base["tech_stack_patterns"][tech_key]["targets"].append(
                    target)
        self._save_knowledge_base()

    def advise_tool_selection(self, phase: str, target: str, tech_stack: List[str],
                              discovered: Dict[str, Any] = None, model_id: str = None,
                              full: bool = False):
        """
        AI-driven tool recommendation based on:
        - Tech stack discovered
        - What's worked before on similar stacks
        - What hasn't worked
        - Current phase in engagement

        Returns list of recommended tools with reasoning. When ``full=True``,
        returns the entire advice dict (tool_recommendations +
        strategic_pivot_suggestions + warning_signs + knowledge_gap) so callers
        can surface the strategic pivots/stop-signs to the decision loop, not
        just the tool list.
        """
        discovered = discovered or {}

        # Query knowledge base for this tech stack
        kb_tactics = self._query_knowledge_for_tech(tech_stack)

        if not self.ai:
            fb = self._default_tool_advice(phase, tech_stack, kb_tactics)
            return {"tool_recommendations": fb} if full else fb

        try:
            prompt = f"""You are a strategic penetration test advisor. Based on accumulated knowledge from previous engagements,
recommend the BEST tools and tactics for this target.

Phase: {phase}
Target: {target}
Tech Stack: {', '.join(tech_stack) if tech_stack else 'Unknown'}
Previously Discovered: {json.dumps(discovered, indent=2)}

Historical Knowledge Base:
{json.dumps(kb_tactics, indent=2)}

Output JSON with tool recommendations:
{{
  "tool_recommendations": [
    {{
      "tool": "tool_name",
      "priority": 1,
      "reasoning": "why this tool",
      "expected_success_rate": 0.0-1.0,
      "estimated_time": 60,
      "prerequisites": ["what must be true"],
      "avoid_because": null or "reason to avoid",
      "knowledge_based_on": "previous engagement where this worked"
    }}
  ],
  "strategic_pivot_suggestions": [
    {{"from": "current_approach", "to": "better_approach", "why": "reason"}}
  ],
  "warning_signs": [
    "pattern that indicates we should stop trying X"
  ],
  "knowledge_gap": "what we don't know that would help"
}}

Be guided by historical data, not hardcoded rules. If something hasn't worked before, don't recommend it."""

            response = self.ai.query(
                "You are a strategic security advisor analyzing historical engagement data.",
                prompt,
                model_id=model_id
            )

            import re
            match = re.search(r'\{[\s\S]*\}', response)
            if match:
                advice = json.loads(match.group(0))

                # Learn: track what advice was given
                self._record_advice_given(phase, tech_stack, advice)

                return advice if full else advice.get("tool_recommendations", [])
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in strategic_advisor.py: {_e}')

        fb = self._default_tool_advice(phase, tech_stack, kb_tactics)
        return {"tool_recommendations": fb} if full else fb

    def advise_waf_evasion(self, waf_type: str, current_approach: str, failures_so_far: List[str],
                           model_id: str = None) -> Dict[str, Any]:
        """
        Get strategic WAF evasion advice based on what we've learned about this WAF type.
        Draws from previous successful evasion patterns.
        """
        waf_key = waf_type.lower()
        known_tactics = self.knowledge_base["waf_bypass_tactics"].get(
            waf_key, [])

        if not self.ai:
            return self._default_waf_advice(waf_type, known_tactics)

        try:
            prompt = f"""You are a WAF evasion specialist. Analyze this WAF and recommend evasion tactics
based on what's worked before against this WAF.

WAF Type: {waf_type}
Current Approach: {current_approach}
Failures So Far: {json.dumps(failures_so_far, indent=2)}

Known Working Tactics Against This WAF:
{json.dumps(known_tactics, indent=2)}

Output JSON:
{{
  "next_tactic": {{
    "name": "tactic_name",
    "technique": "how to apply it",
    "applies_to_tools": ["tool1", "tool2"],
    "confidence": 0.0-1.0,
    "reasoning": "why this should work based on WAF nature",
    "estimated_attempts": 1-5
  }},
  "alternative_tactics": [
    {{"name": "tactic", "reasoning": "why", "confidence": 0.5}}
  ],
  "when_to_stop": "condition when we should pivot to different strategy",
  "learning_note": "what we should remember about this WAF"
}}"""

            response = self.ai.query(
                "You are an expert in WAF evasion and bypass techniques.",
                prompt,
                model_id=model_id
            )

            import re
            match = re.search(r'\{[\s\S]*\}', response)
            if match:
                advice = json.loads(match.group(0))

                # Learn: record this tactic attempt
                if waf_key not in self.knowledge_base["waf_bypass_tactics"]:
                    self.knowledge_base["waf_bypass_tactics"][waf_key] = []

                return advice
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in strategic_advisor.py: {_e}')

        return self._default_waf_advice(waf_type, known_tactics)

    def advise_discovery_order(self, target: str, tech_stack: List[str],
                               phase: str = "recon", model_id: str = None,
                               full: bool = False):
        """
        Get AI recommendation on what order to perform discovery activities.
        Based on what's been most efficient in previous engagements.

        With ``full=True`` returns the whole advice dict (discovery_sequence +
        early_exit_conditions + efficiency_notes) so callers can surface the
        human-operator "if you find X, skip to Y" early-exit conditions, not
        just the ordered sequence.
        """
        # Look up best discovery order for this tech stack from history
        pattern_key = "_".join(sorted(tech_stack)) if tech_stack else "generic"
        known_pattern = self.knowledge_base["discovery_patterns"].get(
            pattern_key, {})

        if not self.ai:
            fb = self._default_discovery_order(tech_stack, known_pattern)
            return {"discovery_sequence": fb} if full else fb

        try:
            prompt = f"""You are optimizing reconnaissance activities. Based on previous engagements,
what's the MOST EFFICIENT order to discover vulnerabilities?

Target: {target}
Tech Stack: {', '.join(tech_stack) if tech_stack else 'Unknown'}
Phase: {phase}

Historical Successful Discovery Order:
{json.dumps(known_pattern, indent=2)}

Output JSON:
{{
  "discovery_sequence": [
    {{
      "step": 1,
      "activity": "discovery activity",
      "tools": ["tool1", "tool2"],
      "reasoning": "why this first",
      "estimated_time": 300,
      "likely_findings": ["finding_type1", "finding_type2"],
      "feeds_into": "next_step"
    }}
  ],
  "efficiency_notes": "how this order is better than alternatives",
  "prerequisites": ["what must be true first"],
  "early_exit_conditions": ["if we find X, skip to Y"]
}}"""

            response = self.ai.query(
                "You are a penetration test optimization specialist.",
                prompt,
                model_id=model_id
            )

            import re
            match = re.search(r'\{[\s\S]*\}', response)
            if match:
                advice = json.loads(match.group(0))
                return advice if full else advice.get("discovery_sequence", [])
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in strategic_advisor.py: {_e}')

        fb = self._default_discovery_order(tech_stack, known_pattern)
        return {"discovery_sequence": fb} if full else fb

    def should_continue_trying(self, tool: str, target: str, attempts: int,
                               failure_rate: float,
                               no_progress: bool = False) -> tuple[bool, str]:
        """
        Intelligent decision: should we keep trying this tool or pivot?
        Based on historical success rates and current failure pattern.

        P4-3: ``no_progress`` is the AUTHORITATIVE convergence signal from the
        base_agent intent ledger (the intent burned its attempt budget without
        producing a single finding for its own host). When set with >=3 attempts
        it returns False unconditionally — the loop breaks with NO LLM, ending the
        403→rotate→403 cascade regardless of historical rates.
        """
        if no_progress and attempts >= 3:
            return False, (
                f"No intent-local progress after {attempts} attempts — "
                "converged to failure; pivot.")
        tool_history = self.knowledge_base["tool_effectiveness"].get(tool, {})

        # Query knowledge base
        total_attempts = tool_history.get(
            "success", 0) + tool_history.get("failure", 0)
        historical_success_rate = (
            tool_history.get("success", 0) / total_attempts
            if total_attempts > 0 else 0.5
        )

        # Decision logic based on learning

        # If current failure rate exceeds historical by 2x, pivot
        if failure_rate > historical_success_rate * 2:
            return False, f"Failure rate {failure_rate:.1%} exceeds historical {historical_success_rate:.1%}"

        # If we've tried >5 times and not succeeding, pivot
        if attempts > 5 and failure_rate > 0.6:
            return False, f"Too many attempts ({attempts}) with failure rate {failure_rate:.1%}"

        # If historical data says this tool never worked for this tech, don't
        # keep trying
        if historical_success_rate < 0.1 and attempts > 2:
            return False, "Tool has 0% historical success rate on this tech stack"

        return True, f"Continue: {historical_success_rate:.1%} historical success rate"

    def record_engagement_outcome(self, engagement_id: str, target: str,
                                  findings: List[Dict], tech_stack: List[str],
                                  waf_detected: Optional[str] = None,
                                  tool_performance: Dict = None,
                                  waf_tactics_used: List[str] = None):
        """
        Learn from completed engagement and update knowledge base.
        This is called at the end of each engagement to feed the learning loop.
        """
        tool_performance = tool_performance or {}
        waf_tactics_used = waf_tactics_used or []

        # 1. Update tool effectiveness scores
        for tool, perf in tool_performance.items():
            key = tool.lower()
            if key not in self.knowledge_base["tool_effectiveness"]:
                self.knowledge_base["tool_effectiveness"][key] = {
                    "success": 0, "failure": 0, "avg_time": 0
                }

            if perf.get("success"):
                self.knowledge_base["tool_effectiveness"][key]["success"] += 1
            else:
                self.knowledge_base["tool_effectiveness"][key]["failure"] += 1

            # Update average time
            if perf.get("time_taken"):
                entry = self.knowledge_base["tool_effectiveness"][key]
                total = entry["success"] + entry["failure"]
                entry["avg_time"] = (
                    (entry["avg_time"] * (total - 1) +
                     perf["time_taken"]) / total
                )

        # 2. Update tech stack patterns
        pattern_key = "_".join(sorted(tech_stack)) if tech_stack else "generic"
        if pattern_key not in self.knowledge_base["tech_stack_patterns"]:
            self.knowledge_base["tech_stack_patterns"][pattern_key] = {
                "successful_tools": [],
                "failed_tools": [],
                "best_discovery_order": [],
                "typical_findings": []
            }

        pattern = self.knowledge_base["tech_stack_patterns"][pattern_key]
        for tool, perf in tool_performance.items():
            if perf.get("success") and tool not in pattern["successful_tools"]:
                pattern["successful_tools"].append(tool)
            elif not perf.get("success") and tool not in pattern["failed_tools"]:
                pattern["failed_tools"].append(tool)

        # 3. Update WAF knowledge
        if waf_detected:
            waf_key = waf_detected.lower()
            if waf_key not in self.knowledge_base["waf_bypass_tactics"]:
                self.knowledge_base["waf_bypass_tactics"][waf_key] = []

            _known = {t.get("tactic") for t in
                      self.knowledge_base["waf_bypass_tactics"][waf_key]
                      if isinstance(t, dict)}
            for tactic in waf_tactics_used:
                # P3-4 (ADVISOR-WAF-ALLTRUE): a tactic being USED is not a tactic
                # that WORKED. The old code hardcoded success:True for every used
                # tactic, fabricating a 100% success rate. Record attempted-UNKNOWN
                # (None, matching record_waf_detection); the real per-tactic outcome
                # is computed by the WafLearner batch path (P3-3) from measured
                # tool runs, never asserted here. (Dedup also fixed: the old
                # `tactic not in [list-of-dicts]` never matched, duplicating rows.)
                if tactic not in _known:
                    _known.add(tactic)
                    self.knowledge_base["waf_bypass_tactics"][waf_key].append({
                        "tactic": tactic,
                        "success": None,  # attempted; resolved by the WafLearner
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })

        # 4. Record engagement summary
        summary = {
            "engagement_id": engagement_id,
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tech_stack": tech_stack,
            "waf_detected": waf_detected,
            "findings_count": len(findings),
            "critical_findings": len([f for f in findings if f.get("severity") == "critical"]),
            "tool_performance": tool_performance
        }
        self.knowledge_base["engagement_summaries"].append(summary)

        # Keep only last 100 engagement summaries
        if len(self.knowledge_base["engagement_summaries"]) > 100:
            self.knowledge_base["engagement_summaries"] = (
                self.knowledge_base["engagement_summaries"][-100:]
            )

        # Persist updated knowledge
        self._save_knowledge_base()

    def get_confidence_report(self) -> str:
        """Generate a report on what we're confident about vs. what we're guessing."""
        report = ["=== KNOWLEDGE BASE CONFIDENCE REPORT ===\n"]

        # Tool confidence
        report.append("Tool Effectiveness (based on history):")
        for tool, stats in list(
                self.knowledge_base["tool_effectiveness"].items())[:10]:
            total = stats["success"] + stats["failure"]
            if total > 0:
                rate = stats["success"] / total
                confidence = "HIGH" if rate > 0.7 else "MEDIUM" if rate > 0.4 else "LOW"
                report.append(
                    f"  {tool}: {
                        rate:.1%} ({
                        stats['success']}/{total}) [{confidence}]"
                )

        # Tech stack knowledge
        report.append("\nTech Stack Patterns Known:")
        for pattern, data in list(
                self.knowledge_base["tech_stack_patterns"].items())[:5]:
            report.append(
                f"  {pattern}: {len(data.get('successful_tools', []))} tools work"
            )

        # WAF knowledge
        report.append("\nWAF Types Encountered:")
        for waf_type, tactics in list(
                self.knowledge_base["waf_bypass_tactics"].items())[:5]:
            report.append(f"  {waf_type}: {len(tactics)} known tactics")

        # Failed approaches (what NOT to do)
        if self.knowledge_base["failed_approaches"]:
            report.append("\nApproaches to AVOID:")
            for failed in self.knowledge_base["failed_approaches"][:5]:
                report.append(
                    f"  - {failed.get('approach', '?')}: {failed.get('reason', '?')}")

        return "\n".join(report)

    # ── Defaults (used when AI unavailable) ──

    def _query_knowledge_for_tech(
            self, tech_stack: List[str]) -> Dict[str, Any]:
        """Query knowledge base for this tech stack."""
        pattern_key = "_".join(sorted(tech_stack)) if tech_stack else "generic"
        return self.knowledge_base["tech_stack_patterns"].get(
            pattern_key,
            {"successful_tools": [], "failed_tools": []}
        )

    def _default_tool_advice(self, phase: str, tech_stack: List[str],
                             kb_tactics: Dict) -> List[Dict[str, Any]]:
        """Fallback: recommend tools based on knowledge base only (no AI)."""
        recommendations = []

        for tool in kb_tactics.get("successful_tools", [])[:3]:
            recommendations.append({
                "tool": tool,
                "priority": len(recommendations) + 1,
                "reasoning": f"Worked in previous engagements on {len(tech_stack)} tech stack",
                "expected_success_rate": 0.7,
                "knowledge_based_on": "historical data"
            })

        return recommendations

    def _default_waf_advice(self, waf_type: str,
                            known_tactics: List) -> Dict[str, Any]:
        """Fallback WAF advice from knowledge base."""
        return {
            "next_tactic": {
                "name": known_tactics[0].get("tactic", "header_mutation") if known_tactics else "header_mutation",
                "confidence": 0.6,
                "reasoning": "based on previous encounters"
            },
            "when_to_stop": "after 3 failed attempts"
        }

    def _default_discovery_order(self, tech_stack: List[str],
                                 pattern: Dict) -> List[Dict[str, Any]]:
        """Fallback: default discovery order."""
        return [
            {
                "step": 1,
                "activity": "technology identification",
                "tools": ["curl", "whatweb"],
                "estimated_time": 60
            },
            {
                "step": 2,
                "activity": "subdomain enumeration",
                "tools": ["subfinder", "assetfinder"],
                "estimated_time": 120
            },
            {
                "step": 3,
                "activity": "port scanning",
                "tools": ["nmap", "masscan"],
                "estimated_time": 300
            }
        ]

    def _record_advice_given(self, phase: str, tech_stack: List[str],
                             advice: Dict):
        """Track advice given so we can validate it later."""
        # This helps the system learn if its own advice was good
