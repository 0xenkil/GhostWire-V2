"""
Heuristic Optimizer - Updates system configuration based on learnings

Adjusts:
- Tool success rates and priorities
- Finding confidence scores
- Timeout values based on observed durations
- WAF-specific tool filtering
- Technology-specific exploit sequences
"""

import json
import os
from typing import Dict, List, Any


class HeuristicOptimizer:
    """Optimizes system parameters based on engagement insights"""

    def __init__(self, config_dir: str = None):
        """Initialize optimizer"""
        self.config_dir = config_dir or os.path.join(
            os.path.dirname(__file__), ".."
        )
        self.changes = []

    def optimize_from_insights(
            self, insights: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply heuristic optimizations based on insights

        Args:
            insights: Dictionary from engagement_analyzer

        Returns:
            Dict of optimization changes to apply
        """
        optimizations = {
            "timestamp": insights.get("timestamp"),
            "engagement_id": insights.get("engagement_id"),
            "changes": {},
            "recommendations": [],
            "rollback_data": {}
        }

        # Optimize tool effectiveness scores
        optimizations["changes"]["tool_effectiveness"] = self._optimize_tool_scores(
            insights)

        # Optimize finding confidence scores
        optimizations["changes"]["finding_confidence"] = self._optimize_confidence_scores(
            insights)

        # Optimize timeouts
        optimizations["changes"]["timeouts"] = self._optimize_timeouts(
            insights)

        # Optimize WAF handling
        optimizations["changes"]["waf_handling"] = self._optimize_waf_handling(
            insights)

        # Generate recommendations for json rules
        optimizations["recommendations"] = self._generate_rule_recommendations(
            insights)

        return optimizations

    def _optimize_tool_scores(
            self, insights: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize tool success rates"""
        changes = {
            "tool_rates_adjusted": {},
            "tool_order_changed": False,
            "reasoning": []
        }

        tool_effectiveness = insights.get("tool_effectiveness", {})
        tool_rates = tool_effectiveness.get("tool_rates", {})

        if not tool_rates:
            return changes

        for tool, rates in tool_rates.items():
            success_rate = rates.get("success_rate", 0)
            total_runs = rates.get("total_runs", 0)

            # Only adjust if we have multiple data points
            if total_runs < 2:
                continue

            # Calculate new priority (higher success = higher priority)
            new_priority = success_rate

            # Penalties for high average duration
            avg_duration = rates.get("avg_duration", 0)
            if avg_duration > 300:  # > 5 minutes
                new_priority *= 0.6  # 40% penalty
            elif avg_duration > 120:  # > 2 minutes
                new_priority *= 0.8  # 20% penalty

            changes["tool_rates_adjusted"][tool] = {
                "success_rate": success_rate,
                "priority": new_priority,
                "total_runs": total_runs,
                "avg_duration": avg_duration,
                "recommendation": self._get_tool_recommendation(success_rate, total_runs, avg_duration)
            }

            if new_priority == 0.0 and total_runs > 2:
                changes["reasoning"].append(
                    f"Tool '{tool}' has 0% success rate after {total_runs} runs - consider removing")
            elif new_priority >= 0.8:
                changes["reasoning"].append(
                    f"Tool '{tool}' highly effective ({
                        success_rate:.0%} success) - prioritize")

        return changes

    def _optimize_confidence_scores(
            self, insights: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize finding confidence thresholds"""
        changes = {
            "confidence_adjustments": {},
            "high_confidence_techs": [],
            "reasoning": []
        }

        tech_patterns = insights.get(
            "technology_patterns", {}).get(
            "detected_technologies", {})

        for tech, info in tech_patterns.items():
            if not isinstance(info, dict):
                continue

            occurrences = info.get("occurrences", 0)
            confirmed = info.get("confirmed", False)

            # Increase confidence for technologies found multiple times
            if occurrences >= 3:
                new_confidence = 0.95
                changes["high_confidence_techs"].append({
                    "technology": tech,
                    "confidence": new_confidence,
                    "reasoning": f"Found {occurrences} times in engagement"
                })
                changes["reasoning"].append(
                    f"Technology '{tech}' appears reliably ({occurrences} times)")
            elif confirmed and occurrences >= 1:
                new_confidence = 0.90
                changes["high_confidence_techs"].append({
                    "technology": tech,
                    "confidence": new_confidence,
                    "reasoning": "Confirmed by multiple sources"
                })

        return changes

    def _optimize_timeouts(self, insights: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize timeout values based on observed durations"""
        changes = {
            "timeout_adjustments": {},
            "reasoning": []
        }

        phase_metrics = insights.get("phase_metrics", {})

        for phase, metrics in phase_metrics.items():
            if not isinstance(metrics, dict):
                continue

            duration = metrics.get("duration", 0)

            if duration == 0:
                continue

            # Set timeout to 1.5x observed duration (with buffer)
            suggested_timeout = int(duration * 1.5) + 30  # +30s buffer

            changes["timeout_adjustments"][phase] = {
                "observed_duration": duration,
                "suggested_timeout": suggested_timeout,
                "buffer_seconds": 30
            }

            if duration > 300:  # > 5 minutes
                changes["reasoning"].append(
                    f"Phase '{phase}' takes {duration}s - increase timeout to {suggested_timeout}s")

        return changes

    def _optimize_waf_handling(
            self, insights: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize WAF-specific tool handling"""
        changes = {
            "waf_rules": {},
            "blocked_tools": {},
            "effective_tools": {},
            "reasoning": []
        }

        waf_patterns = insights.get("waf_patterns", {})
        waf_type = waf_patterns.get("waf_type")

        if not waf_type:
            return changes

        tools_blocked = waf_patterns.get("tools_blocked", [])
        tools_effective = waf_patterns.get("tools_effective", [])
        recommended_order = waf_patterns.get("recommended_tool_order", [])

        changes["waf_rules"][waf_type] = {
            "tools_to_avoid": tools_blocked,
            "tools_to_use": tools_effective,
            "recommended_order": recommended_order
        }

        if tools_blocked:
            changes["reasoning"].append(
                f"WAF '{waf_type}' blocks: {', '.join(tools_blocked[:3])} - skip these tools")

        if tools_effective:
            changes["reasoning"].append(
                f"Against {waf_type}, use: {', '.join(tools_effective[:3])}")

        return changes

    def _generate_rule_recommendations(
            self, insights: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations for new JSON rules"""
        recommendations = []

        tech_patterns = insights.get(
            "technology_patterns", {}).get(
            "detected_technologies", {})
        tool_rates = insights.get(
            "tool_effectiveness", {}).get(
            "tool_rates", {})
        waf_type = insights.get("waf_patterns", {}).get("waf_type")
        findings = insights.get("findings_confirmed", [])

        # Rule 1: Tech-specific tool recommendations
        for tech, info in tech_patterns.items():
            if not isinstance(info, dict):
                continue

            if info.get("confirmed") and info.get("occurrences", 0) >= 2:
                # Find most effective tools
                best_tools = sorted(
                    [(t, r.get("success_rate", 0))
                     for t, r in tool_rates.items()],
                    key=lambda x: x[1],
                    reverse=True
                )[:2]

                best_tool_names = [t[0] for t in best_tools]

                recommendations.append({
                    "type": "tech_tool_mapping",
                    "technology": tech,
                    "recommended_tools": best_tool_names,
                    "priority": "high",
                    "reasoning": f"Confirmed {tech} detection - use best-performing tools"
                })

        # Rule 2: WAF bypass strategies
        if waf_type:
            effective_against_waf = [
                t for t, r in tool_rates.items() if r.get(
                    "success_rate", 0) >= 0.7]

            if effective_against_waf:
                recommendations.append({
                    "type": "waf_bypass_strategy",
                    "waf": waf_type,
                    "tools_to_use": effective_against_waf,
                    "tools_to_avoid": insights.get("waf_patterns", {}).get("tools_blocked", []),
                    "priority": "high",
                    "reasoning": f"Against {waf_type}, prioritize {', '.join(effective_against_waf)}"
                })

        # Rule 3: High-confidence exploitation sequences
        if len(findings) >= 3:
            confirmed_vulns = [
                f for f in findings if f.get("type") == "nuclei_finding"]
            if confirmed_vulns:
                recommendations.append({
                    "type": "exploitation_sequence",
                    "vulnerabilities_found": len(confirmed_vulns),
                    "priority": "high",
                    "reasoning": f"Found {len(confirmed_vulns)} confirmed vulnerabilities - create specific exploit sequence"
                })

        # Rule 4: Tool skip rules for ineffective tools
        ineffective = [
            t for t,
            r in tool_rates.items() if r.get(
                "success_rate",
                0) == 0.0 and r.get(
                "total_runs",
                0) > 2]
        if ineffective:
            recommendations.append({
                "type": "skip_ineffective_tools",
                "tools": ineffective,
                "priority": "medium",
                "reasoning": f"Tools {ineffective} never succeeded - consider skipping on similar targets"
            })

        return recommendations

    def _get_tool_recommendation(
            self, success_rate: float, total_runs: int, avg_duration: float) -> str:
        """Get recommendation for a tool"""
        if total_runs < 2:
            return "insufficient_data"

        if success_rate >= 0.9:
            return "highly_effective"
        elif success_rate >= 0.7:
            return "effective"
        elif success_rate >= 0.5:
            return "moderate"
        elif success_rate == 0.0:
            return "never_works"
        else:
            return "unreliable"

    def apply_optimizations(
            self, optimizations: Dict[str, Any], backup_dir: str = None) -> Dict[str, Any]:
        """
        Apply optimizations to system files

        Returns tracking of what was changed
        """
        results = {
            "timestamp": optimizations.get("timestamp"),
            "applied_changes": [],
            "backups_created": [],
            "errors": []
        }

        if not backup_dir:
            backup_dir = os.path.join(
                self.config_dir,
                "intelligence",
                ".upgrades_backup")

        os.makedirs(backup_dir, exist_ok=True)

        # Store optimization record
        record_file = os.path.join(
            backup_dir, f"optimization_{
                optimizations.get('engagement_id')}.json")
        with open(record_file, "w") as f:
            json.dump(optimizations, f, indent=2)

        results["backups_created"].append(record_file)
        results["applied_changes"].append(
            "Optimization record saved for rollback capability")

        return results

    def get_rollback_data(self, engagement_id: str,
                          backup_dir: str = None) -> Dict[str, Any]:
        """Get data needed to rollback an optimization"""
        if not backup_dir:
            backup_dir = os.path.join(
                self.config_dir,
                "intelligence",
                ".upgrades_backup")

        record_file = os.path.join(
            backup_dir, f"optimization_{engagement_id}.json")

        if not os.path.exists(record_file):
            return {"error": "No optimization record found"}

        with open(record_file, "r") as f:
            return json.load(f)
