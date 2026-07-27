"""
Engagement Analyzer - Extracts learnings from completed engagements

Analyzes engagement results to identify:
- What tools worked vs didn't work
- Time patterns (how long phases take)
- Technology-specific patterns
- WAF-specific behaviors
- Tool effectiveness per target type
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict


class EngagementAnalyzer:
    """Analyzes engagement results to extract learnings"""

    def __init__(self, store=None):
        """Initialize analyzer with state store reference"""
        self.store = store
        self.insights = {}

    def analyze_engagement(self, engagement_id: str) -> Dict[str, Any]:
        """
        Analyze a completed engagement and extract insights

        Args:
            engagement_id: ID of the engagement to analyze

        Returns:
            Dict containing insights about what worked
        """
        if not self.store:
            return {"error": "No state store available"}

        insights = {
            "engagement_id": engagement_id,
            "timestamp": datetime.now().isoformat(),
            "tool_effectiveness": {},
            "phase_metrics": {},
            "technology_patterns": {},
            "waf_patterns": {},
            "target_profile": {},
            "findings_confirmed": [],
            "patterns_discovered": [],
            "optimization_opportunities": []
        }

        # Analyze tool effectiveness
        insights["tool_effectiveness"] = self._analyze_tool_effectiveness(
            engagement_id)

        # Analyze phase metrics
        insights["phase_metrics"] = self._analyze_phase_metrics(engagement_id)

        # Analyze technology patterns
        insights["technology_patterns"] = self._analyze_technology_patterns(
            engagement_id)

        # Analyze WAF patterns
        insights["waf_patterns"] = self._analyze_waf_patterns(engagement_id)

        # Get target profile
        insights["target_profile"] = self._extract_target_profile(
            engagement_id)

        # Extract confirmed findings
        insights["findings_confirmed"] = self._extract_confirmed_findings(
            engagement_id)

        # Discover patterns
        insights["patterns_discovered"] = self._discover_patterns(
            engagement_id, insights)

        # Identify optimization opportunities
        insights["optimization_opportunities"] = self._identify_optimizations(
            engagement_id, insights)

        return insights

    def _analyze_tool_effectiveness(
            self, engagement_id: str) -> Dict[str, Any]:
        """Analyze which tools worked and which didn't"""
        effectiveness = {
            "successful_tools": [],
            "failed_tools": [],
            "tool_timings": {},
            "tool_rates": {}
        }

        try:
            # Get tool runs from centralized database
            tool_runs = self.store.get_tool_runs(engagement_id)

            success_count = defaultdict(int)
            fail_count = defaultdict(int)
            total_time = defaultdict(float)
            run_count = defaultdict(int)

            for run in tool_runs:
                tool_name = run.get("tool", "unknown")
                status = run.get("status", "failed")
                success = status == "success"
                duration = run.get("duration", 0)

                if success:
                    success_count[tool_name] += 1
                    effectiveness["successful_tools"].append({
                        "tool": tool_name,
                        "duration": duration,
                        # Use stdout field, first 100 chars
                        "output": run.get("stdout", "")[:100]
                    })
                else:
                    fail_count[tool_name] += 1
                    effectiveness["failed_tools"].append({
                        "tool": tool_name,
                        # Use stderr field for error details
                        "reason": run.get("stderr", "unknown"),
                        "duration": duration
                    })

                total_time[tool_name] += duration
                run_count[tool_name] += 1

            # Calculate success rates
            for tool in set(list(success_count.keys()) +
                            list(fail_count.keys())):
                total = success_count[tool] + fail_count[tool]
                rate = success_count[tool] / total if total > 0 else 0

                effectiveness["tool_rates"][tool] = {
                    "success_rate": rate,
                    "successes": success_count[tool],
                    "failures": fail_count[tool],
                    "total_runs": total,
                    "avg_duration": total_time[tool] / run_count[tool] if run_count[tool] > 0 else 0
                }

        except Exception as e:
            effectiveness["error"] = str(e)

        return effectiveness

    def _analyze_phase_metrics(self, engagement_id: str) -> Dict[str, Any]:
        """Analyze timing and metrics per phase"""
        metrics = {}

        try:
            phases = [
                "planning",
                "recon",
                "weaponization",
                "exploitation",
                "persistence",
                "objectives",
                "reporting"]

            for phase in phases:
                phase_data = self.store.get_phase_data(engagement_id, phase)
                if not phase_data:
                    continue

                if isinstance(phase_data, str):
                    try:
                        phase_data = json.loads(phase_data)
                    except Exception as _e:
                        import logging
                        logging.getLogger(__name__).debug(
                            f'Swallowed exception in engagement_analyzer.py: {_e}')
                        continue

                metrics[phase] = {
                    "completed": phase_data.get("status") == "completed" if isinstance(phase_data, dict) else False,
                    "duration": phase_data.get("duration", 0) if isinstance(phase_data, dict) else 0,
                    "findings": phase_data.get("findings_count", 0) if isinstance(phase_data, dict) else 0,
                    "commands_run": phase_data.get("commands_run", 0) if isinstance(phase_data, dict) else 0
                }

        except Exception as e:
            metrics["error"] = str(e)

        return metrics

    def _analyze_technology_patterns(
            self, engagement_id: str) -> Dict[str, Any]:
        """Identify technology stack from findings"""
        patterns = {
            "detected_technologies": {},
            "tech_tool_mapping": {}
        }

        try:
            findings = self.store.get_all_findings(engagement_id)
            if not findings:
                return patterns

            for finding in findings:
                detail = finding.get("detail", "")
                finding_type = finding.get("type", "")

                # Extract technology names
                techs = self._extract_technologies_from_finding(
                    detail, finding_type)

                for tech in techs:
                    if tech not in patterns["detected_technologies"]:
                        patterns["detected_technologies"][tech] = {
                            "occurrences": 0,
                            "finding_types": [],
                            "confirmed": False
                        }

                    patterns["detected_technologies"][tech]["occurrences"] += 1
                    patterns["detected_technologies"][tech]["finding_types"].append(
                        finding_type)

                    # Mark as confirmed if high confidence
                    if finding_type in ["nuclei_finding",
                                        "tool_result", "header_analysis"]:
                        patterns["detected_technologies"][tech]["confirmed"] = True

        except Exception as e:
            patterns["error"] = str(e)

        return patterns

    def _analyze_waf_patterns(self, engagement_id: str) -> Dict[str, Any]:
        """Analyze WAF behaviors and tool effectiveness against WAF"""
        patterns = {
            "waf_type": None,
            "waf_detected_on": [],
            "tools_blocked": [],
            "tools_effective": [],
            "recommended_tool_order": []
        }

        try:
            findings = self.store.get_all_findings(engagement_id)
            if not findings:
                return patterns

            blocked_tools = defaultdict(int)
            successful_tools = defaultdict(int)

            for finding in findings:
                detail = finding.get("detail", "")

                # Detect WAF type
                if "cloudflare" in detail.lower():
                    patterns["waf_type"] = "cloudflare"
                elif "waf" in detail.lower() or "403" in detail:
                    patterns["waf_type"] = "generic_waf"

                # Track blocked tools
                if "blocked" in detail.lower() or "timeout" in detail.lower():
                    tool = self._extract_tool_from_finding(detail)
                    if tool:
                        blocked_tools[tool] += 1
                        if tool not in patterns["tools_blocked"]:
                            patterns["tools_blocked"].append(tool)

            # Get tool runs to see what succeeded and which evasion worked
            tool_runs = self.store.get_tool_runs(engagement_id)
            evasion_stats = defaultdict(int)

            for run in tool_runs:
                tool = run.get("tool", "")
                status = run.get("status", "")
                evasion = run.get("evasion_applied", "none")

                if status == "success":
                    if tool:
                        successful_tools[tool] += 1
                        if tool not in patterns["tools_effective"]:
                            patterns["tools_effective"].append(tool)

                    # Track effective evasion vectors
                    if evasion and evasion != "none":
                        for vector in evasion.split(","):
                            evasion_stats[vector] += 1

                elif "403" in str(run.get("stdout", "")) or "blocked" in str(run.get("stdout", "")).lower():
                    if tool:
                        blocked_tools[tool] += 1
                        if tool not in patterns["tools_blocked"]:
                            patterns["tools_blocked"].append(tool)

            # Map successful evasion vectors
            patterns["successful_evasion_vectors"] = dict(evasion_stats)

            # Recommend tool order (effective first)
            patterns["recommended_tool_order"] = sorted(
                successful_tools.keys(),
                key=lambda t: successful_tools[t],
                reverse=True
            )

        except Exception as e:
            patterns["error"] = str(e)

        return patterns

    def _extract_target_profile(self, engagement_id: str) -> Dict[str, Any]:
        """Extract target characteristics"""
        profile = {
            "technologies": [],
            "waf_presence": False,
            "waf_type": None,
            "open_ports": [],
            "services": [],
            "difficulty_estimate": "unknown"
        }

        try:
            # Get recon data
            recon_data = self.store.get_phase_data(engagement_id, "recon")
            if recon_data and isinstance(recon_data, str):
                recon_data = json.loads(recon_data)

            if isinstance(recon_data, dict):
                profile["open_ports"] = recon_data.get("open_ports", [])
                profile["services"] = recon_data.get("services", [])
                profile["waf_type"] = recon_data.get("waf_type")
                if profile["waf_type"]:
                    profile["waf_presence"] = True

            # Get exploitations data
            expl_data = self.store.get_phase_data(
                engagement_id, "exploitation")
            if expl_data and isinstance(expl_data, str):
                expl_data = json.loads(expl_data)

            if isinstance(expl_data, dict):
                # Infer difficulty from number of vulnerabilities found
                vuln_count = expl_data.get("vulnerabilities_found", 0)
                if vuln_count >= 5:
                    profile["difficulty_estimate"] = "easy"
                elif vuln_count >= 2:
                    profile["difficulty_estimate"] = "medium"
                else:
                    profile["difficulty_estimate"] = "hard"

        except Exception as e:
            profile["error"] = str(e)

        return profile

    def _extract_confirmed_findings(
            self, engagement_id: str) -> List[Dict[str, Any]]:
        """Extract all confirmed findings"""
        findings = []

        try:
            all_findings = self.store.get_all_findings(engagement_id)
            if not all_findings:
                return findings

            for finding in all_findings:
                if finding.get("type") in [
                        "nuclei_finding", "confirmed_vulnerability", "exploitation_result"]:
                    findings.append({
                        "type": finding.get("type"),
                        "detail": finding.get("detail", "")[:100],
                        "severity": finding.get("severity", "unknown")
                    })

        except Exception as e:
            findings.append({"error": str(e)})

        return findings

    def _discover_patterns(self, engagement_id: str,
                           insights: Dict[str, Any]) -> List[str]:
        """Discover actionable patterns"""
        patterns = []

        try:
            tool_rates = insights.get(
                "tool_effectiveness", {}).get(
                "tool_rates", {})
            waf_patterns = insights.get("waf_patterns", {})
            phase_metrics = insights.get("phase_metrics", {})

            # Pattern: Tools with 100% success rate on this target
            perfect_tools = [
                t for t, r in tool_rates.items() if r.get("success_rate") == 1.0]
            if perfect_tools:
                patterns.append(
                    f"Perfect tools (100% success): {
                        ', '.join(perfect_tools)}")

            # Pattern: Tools completely ineffective
            useless_tools = [
                t for t, r in tool_rates.items() if r.get("success_rate") == 0.0]
            if useless_tools:
                patterns.append(
                    f"Never-successful tools: {', '.join(useless_tools)}")

            # Pattern: WAF blocking specific tools
            if waf_patterns.get("waf_type") and waf_patterns.get(
                    "tools_blocked"):
                patterns.append(
                    f"{waf_patterns['waf_type']} blocks: {', '.join(waf_patterns['tools_blocked'][:3])}")

            # Pattern: Phases that take unusually long
            for phase, metrics in phase_metrics.items():
                if isinstance(metrics, dict) and metrics.get(
                        "duration", 0) > 300:  # > 5 minutes
                    patterns.append(
                        f"{phase} phase is slow ({
                            metrics['duration']}s)")

            # Pattern: Technology-specific vulnerabilities
            techs = insights.get(
                "technology_patterns", {}).get(
                "detected_technologies", {})
            confirmed_techs = [
                t for t, info in techs.items() if info.get("confirmed")]
            if confirmed_techs:
                patterns.append(
                    f"Confirmed technologies: {
                        ', '.join(confirmed_techs)}")

        except Exception as e:
            patterns.append(f"Pattern discovery error: {str(e)}")

        return patterns

    def _identify_optimizations(
            self, engagement_id: str, insights: Dict[str, Any]) -> List[Dict[str, str]]:
        """Identify optimization opportunities"""
        optimizations = []

        try:
            tool_rates = insights.get(
                "tool_effectiveness", {}).get(
                "tool_rates", {})
            phase_metrics = insights.get("phase_metrics", {})
            waf_patterns = insights.get("waf_patterns", {})

            # Optimization: Remove tools that never work
            for tool, rates in tool_rates.items():
                if rates.get("success_rate", 0) == 0.0 and rates.get(
                        "total_runs", 0) > 2:
                    optimizations.append({
                        "type": "remove_tool",
                        "tool": tool,
                        "reason": f"Never succeeded ({rates['total_runs']} runs)",
                        "priority": "high"
                    })

            # Optimization: Prioritize high-success tools
            for tool, rates in tool_rates.items():
                if rates.get("success_rate", 0) >= 0.80:
                    optimizations.append({
                        "type": "prioritize_tool",
                        "tool": tool,
                        "reason": f"High success rate ({rates['success_rate']:.1%})",
                        "priority": "high"
                    })

            # Optimization: Skip blocked tools on this WAF
            if waf_patterns.get("waf_type") and waf_patterns.get(
                    "tools_blocked"):
                for tool in waf_patterns["tools_blocked"][:2]:
                    optimizations.append({
                        "type": "skip_on_waf",
                        "tool": tool,
                        "waf": waf_patterns["waf_type"],
                        "reason": "Consistently blocked by WAF",
                        "priority": "high"
                    })

            # Optimization: Increase timeouts for slow phases
            for phase, metrics in phase_metrics.items():
                if isinstance(metrics, dict) and metrics.get(
                        "duration", 0) > 300:
                    optimizations.append({
                        "type": "increase_timeout",
                        "phase": phase,
                        "current": metrics["duration"],
                        "reason": "Phase consistently takes long",
                        "priority": "medium"
                    })

        except Exception as e:
            optimizations.append({
                "error": str(e)
            })

        return optimizations

    def _extract_technologies_from_finding(
            self, detail: str, finding_type: str) -> List[str]:
        """Extract technology names from finding detail"""
        techs = []
        detail_lower = detail.lower()

        # Tech keywords
        tech_keywords = {
            "wordpress": ["wordpress", "wp-", "wp_"],
            "apache": ["apache", "apache/"],
            "nginx": ["nginx"],
            "php": ["php", "php/"],
            "python": ["python", "django", "flask"],
            "nodejs": ["node.js", "node", "express", "next.js"],
            "java": ["java", "tomcat", "spring"],
            "mysql": ["mysql", "mariadb"],
            "postgresql": ["postgresql", "postgres"],
            "mongodb": ["mongodb", "mongo"],
            "cloudflare": ["cloudflare"],
            "aws": ["aws", "amazon", "s3"],
            "azure": ["azure", "microsoft"],
            "gcp": ["google cloud", "gcp"]
        }

        for tech, keywords in tech_keywords.items():
            for keyword in keywords:
                if keyword in detail_lower:
                    techs.append(tech)
                    break

        return list(set(techs))

    def _extract_tool_from_finding(self, detail: str) -> str:
        """Extract tool name from finding detail"""
        detail_lower = detail.lower()

        tools = [
            "nuclei",
            "nikto",
            "sqlmap",
            "curl",
            "gobuster",
            "dalfox",
            "commix",
            "ffuf"]
        for tool in tools:
            if tool in detail_lower:
                return tool

        return None

    def save_insights(
            self, insights: Dict[str, Any], filepath: str = None) -> str:
        """Save insights to file"""
        if not filepath:
            from config_paths import LOCAL_RESULTS_DIR
            filepath = os.path.join(
                LOCAL_RESULTS_DIR,
                f"engagement_insights_{insights['engagement_id']}.json"
            )

        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, "w") as f:
            json.dump(insights, f, indent=2)

        return filepath
