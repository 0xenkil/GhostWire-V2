"""
Reasoning Engine: AI-driven decision layer that reasons about findings and generates tactics.

The problem it solves:
- AI sees raw findings but has no framework for reasoning about them
- No self-awareness about confidence levels or knowledge gaps
- Solution: Structured reasoning with confidence tracking and dynamic rule application

Architecture:
1. Input: Structured findings with confidence scores
2. Reasoning: AI reasons about what's exploitable, what's not, what we need to know
3. Tactics: Generate specific exploitation tactics with rationale
4. Self-awareness: Track what we know vs. what we need to know
"""

import json
from typing import Dict, Any
from datetime import datetime, timezone


class ReasoningEngine:
    """AI-driven reasoning layer for tactical decision-making."""

    def __init__(self, ai_backend=None, state_store=None):
        """
        Initialize reasoning engine.

        Args:
            ai_backend: AIBackend for AI-driven reasoning
            state_store: StateStore for persistent reasoning state
        """
        self.ai = ai_backend
        self.store = state_store
        self.reasoning_history = []  # Track reasoning decisions over time
        self.knowledge_gaps = {}  # Track what we don't know
        # Learn our own confidence accuracy — persisted ACROSS engagements so it
        # actually accumulates enough samples to be meaningful (a single run
        # rarely sees >=3 of the same tactic).
        self.confidence_calibration = self._load_calibration()

    def _calibration_path(self):
        try:
            from config_paths import INTEL_DIR
            from pathlib import Path
            return Path(INTEL_DIR) / "calibration_memory.json"
        except Exception:
            return None

    def _load_calibration(self) -> dict:
        p = self._calibration_path()
        if p and p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
            except Exception:
                return {}
        return {}

    def _save_calibration(self) -> None:
        p = self._calibration_path()
        if not p:
            return
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(
                json.dumps(self.confidence_calibration, indent=2),
                encoding="utf-8")
        except Exception:
            pass

    def calibration_summary_for_prompt(self, max_items: int = 5) -> str:
        """Short, AI-consumable note on how well this engine's success
        PREDICTIONS have matched reality, so the decision loop can correct its
        own over-/under-confidence instead of repeating mis-calibrated bets.
        Returns '' until a tactic has >=3 outcomes (not enough signal yet)."""
        lines = []
        for name, c in (self.confidence_calibration or {}).items():
            preds = c.get("predictions", []) or []
            outs = c.get("outcomes", []) or []
            if len(preds) < 3 or len(outs) < 3:
                continue
            avg_pred = sum(preds) / len(preds)
            avg_out = sum(outs) / len(outs)
            err = avg_pred - avg_out
            if abs(err) < 0.15:
                tag = f"well-calibrated (~{avg_out:.0%} succeed)"
            elif err > 0:
                tag = (f"OVERCONFIDENT — predicted {avg_pred:.0%} but only "
                       f"{avg_out:.0%} actually succeed; demand stronger proof")
            else:
                tag = (f"UNDERCONFIDENT — predicted {avg_pred:.0%} but "
                       f"{avg_out:.0%} succeed; pursue these more aggressively")
            lines.append((abs(err), f"- {name}: {tag} (n={len(outs)})"))
        if not lines:
            return ""
        lines.sort(reverse=True)  # surface the most mis-calibrated first
        body = "\n".join(t for _, t in lines[:max_items])
        return ("### PREDICTION CALIBRATION (learned from past outcomes — adjust "
                "confidence accordingly)\n" + body + "\n")

    def reason_about_findings(self, structured_findings: Dict[str, Any],
                              target: str, mode: str = "pentest") -> Dict[str, Any]:
        """
        Apply AI reasoning to structured findings to generate tactical recommendations.

        Args:
            structured_findings: Output from StructuredAnalyzer
            target: Target being tested
            mode: "pentest" or "redteam" affecting risk tolerance

        Returns:
            Reasoning output with tactics, confidence, and knowledge gaps
        """
        findings_json = json.dumps(
            structured_findings.get(
                "all_findings", []), indent=2)
        tech_stack = json.dumps(
            structured_findings.get(
                "technology_stack", {}), indent=2)

        risk_tolerance = "high" if mode == "redteam" else "medium"

        prompt = f"""You are an expert penetration tester. Reason about these findings.

Target: {target}
Mode: {mode} (risk tolerance: {risk_tolerance})
Findings:
{findings_json}

Technology Stack:
{tech_stack}

Your reasoning should output JSON:
{{
  "reasoning_steps": [
    {{"step": "number", "analysis": "what did you observe", "confidence": 0.0-1.0}}
  ],
  "exploitation_tactics": [
    {{
      "tactic": "specific technique",
      "target": "what to exploit",
      "probability_of_success": 0.0-1.0,
      "tools_needed": ["tool1", "tool2"],
      "reasoning": "why this should work based on findings",
      "prerequisites": ["what must be true for this to work"],
      "risk_level": "critical|high|medium|low"
    }}
  ],
  "knowledge_gaps": [
    {{"gap": "what we don't know", "why_it_matters": "reason", "how_to_find_out": "tool/method"}}
  ],
  "high_confidence_vs_speculation": {{
    "high_confidence": ["what we're sure about"],
    "medium_confidence": ["what we think but aren't sure"],
    "low_confidence": ["wild guesses"],
    "false_positive_risks": ["what could be tricking us"]
  }},
  "recommended_next_steps": [
    {{"priority": 1, "step": "do this first", "why": "reasoning"}}
  ]
}}

Be honest about confidence. Flag assumptions. Identify blind spots."""

        if not self.ai:
            return self._default_reasoning(structured_findings)

        try:
            response = self.ai.query(
                "You are a penetration tester reasoning about findings.",
                prompt
            )

            from core.result_contracts import FragileParseFixer
            reasoning = FragileParseFixer.safe_split_json_extraction(response)
            if reasoning:

                # Track reasoning for learning
                self.reasoning_history.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "target": target,
                    "reasoning": reasoning
                })

                # Extract and track knowledge gaps
                for gap in reasoning.get("knowledge_gaps", []):
                    gap_key = gap.get("gap", "unknown")
                    self.knowledge_gaps[gap_key] = gap

                return reasoning
        except Exception as e:
            return self._default_reasoning(structured_findings, error=str(e))

        return self._default_reasoning(structured_findings)

    def _default_reasoning(
            self, findings: Dict[str, Any], error: str = None) -> Dict[str, Any]:
        """Fallback reasoning when AI is unavailable."""
        tactics = []

        # Basic rule-guided reasoning (rules guide, don't enforce)
        for finding in findings.get("all_findings", []):
            conf = finding.get("confidence", 0.5)
            if conf >= 0.7:  # Only reason about high-confidence findings
                finding_type = finding.get("type", "unknown")

                # Simple rules to guide tactics (not hardcoded tactics)
                if finding_type == "vulnerability" and conf >= 0.8:
                    tactics.append({
                        "tactic": f"Exploit {finding_type}",
                        "target": finding.get("target", "unknown"),
                        "probability_of_success": conf,
                        "tools_needed": ["custom_exploit"],
                        "reasoning": f"High confidence {finding_type} found"
                    })

        return {
            "reasoning_steps": [],
            "exploitation_tactics": tactics,
            "knowledge_gaps": ["Unavailable without AI"],
            "high_confidence_vs_speculation": {
                "high_confidence": [],
                "medium_confidence": [str(f) for f in findings.get("all_findings", [])[:5]],
                "low_confidence": [],
                "false_positive_risks": findings.get("false_positives", [])
            },
            "recommended_next_steps": [],
            "error": error if error else "Fallback reasoning (AI unavailable)"
        }

    def assess_confidence_calibration(self, tactic: Dict[str, Any],
                                      actual_result: Dict[str, Any]) -> None:
        """
        Learn from actual outcomes: Did our probability estimates match reality?
        Updates confidence calibration over time.
        """
        predicted_prob = tactic.get("probability_of_success", 0.5)
        actual_success = actual_result.get("success", False)

        tactic_name = tactic.get("tactic", "unknown")

        if tactic_name not in self.confidence_calibration:
            self.confidence_calibration[tactic_name] = {
                "predictions": [],
                "outcomes": [],
                "calibration_error": 0
            }

        self.confidence_calibration[tactic_name]["predictions"].append(
            float(predicted_prob))
        self.confidence_calibration[tactic_name]["outcomes"].append(
            1 if actual_success else 0)

        # Bound memory: keep the most recent 50 samples per tactic so the
        # calibration tracks recent behaviour and the file can't grow forever.
        for _k in ("predictions", "outcomes"):
            self.confidence_calibration[tactic_name][_k] = \
                self.confidence_calibration[tactic_name][_k][-50:]

        # Recalculate calibration error (we should improve over time)
        predictions = self.confidence_calibration[tactic_name]["predictions"]
        outcomes = self.confidence_calibration[tactic_name]["outcomes"]

        if len(predictions) >= 3:
            # Simple calibration: average prediction vs. average outcome
            avg_pred = sum(predictions) / len(predictions)
            avg_outcome = sum(outcomes) / len(outcomes)
            self.confidence_calibration[tactic_name]["calibration_error"] = abs(
                avg_pred - avg_outcome)

        # Persist across engagements (this is where calibration becomes useful).
        self._save_calibration()

    def get_reasoning_quality_metrics(self) -> Dict[str, Any]:
        """
        Return metrics on how well our reasoning is performing.
        Used for self-awareness and continuous improvement.
        """
        metrics = {
            "total_reasoning_decisions": len(self.reasoning_history),
            "knowledge_gaps_identified": len(self.knowledge_gaps),
            "confidence_calibration": self.confidence_calibration,
            "recent_reasoning": self.reasoning_history[-5:] if self.reasoning_history else [],
        }

        # Calculate overall calibration quality
        all_calibrations = self.confidence_calibration.values()
        if all_calibrations:
            avg_error = sum(c.get("calibration_error", 0)
                            for c in all_calibrations) / len(all_calibrations)
            metrics["overall_calibration_error"] = avg_error
            metrics["calibration_quality"] = "good" if avg_error < 0.15 else (
                "fair" if avg_error < 0.3 else "poor")

        return metrics

    def analyze_tool_failure(
            self, tool_name: str, command: str, stderr: str, stdout: str) -> Dict[str, Any]:
        """
        Analyze a repeated tool failure: is this a fixable TACTICAL problem
        (syntax / concurrency / timeout) or is the whole APPROACH wrong for this
        target (e.g. port-scanning a CDN edge that filters everything)? The
        latter is the human-operator instinct to abandon a dead end and pivot.

        AI-driven when a backend is available (the substring heuristic below is
        only the no-AI fallback, so this never silently degrades to hardcoded
        signature matching when the AI could reason properly).
        """
        combined_output = ((stderr or "") + (stdout or "")).lower()

        if self.ai:
            try:
                prompt = f"""A tool has failed repeatedly. Decide, like a senior operator, whether to
keep adjusting it or abandon the approach entirely.

Tool: {tool_name}
Command: {command}
Error output (truncated):
{(stderr or '')[:600]}
{(stdout or '')[:300]}

Output STRICT JSON only:
{{
  "root_cause": "one-line plain-language cause",
  "is_approach_wrong": true or false,
  "suggested_pivot": "what to do instead (only if the approach is wrong, else null)",
  "suggested_action": "concrete next action",
  "reduce_concurrency": true or false
}}

is_approach_wrong = true ONLY when no flag/parameter change could fix it (wrong
tool or wrong strategy for this target), e.g. scanning ports on a serverless/CDN
edge, brute-forcing a service that isn't exposed."""
                response = self.ai.query(
                    "You are a senior penetration tester triaging a repeated tool failure.",
                    prompt)
                from core.result_contracts import FragileParseFixer
                parsed = FragileParseFixer.safe_split_json_extraction(response)
                if isinstance(parsed, dict) and parsed.get("root_cause"):
                    parsed.setdefault("is_approach_wrong", False)
                    parsed.setdefault("suggested_pivot", None)
                    parsed.setdefault("reduce_concurrency", False)
                    parsed.setdefault(
                        "suggested_action", "Retry with different parameters")
                    return parsed
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f"analyze_tool_failure AI path failed, using heuristic: {_e}")

        # ── Heuristic fallback (no AI backend available) ──────────────────
        result = {
            "root_cause": "Unknown",
            "is_approach_wrong": False,
            "suggested_pivot": None,
            "reduce_concurrency": False,
            "suggested_action": "Retry with different parameters",
        }
        if "timed out" in combined_output or "timeout" in combined_output:
            result["root_cause"] = "Network Timeout Detected"
            result["reduce_concurrency"] = True
            result["suggested_action"] = "Reduce concurrency, increase timeout"
        elif ("waf" in combined_output or "blocked" in combined_output
              or "access denied" in combined_output or "403 forbidden" in combined_output):
            result["root_cause"] = "WAF / Rate Limit Block Detected"
            result["reduce_concurrency"] = True
            result["suggested_action"] = "Use evasion techniques, rotate IP, slow down"
        return result
