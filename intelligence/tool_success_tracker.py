"""
Tool Success Tracker: Learns which tools work best on which target types.
Enables intelligent tool selection based on past experience.
"""

import json
from pathlib import Path
from datetime import datetime, timezone


class ToolSuccessTracker:
    """
    Tracks tool effectiveness across engagements.
    Learns: "Tool X works 80% on CDN targets, 40% on regular targets"
    """

    def __init__(self, db_path: Path = None):
        """
        Initialize tracker with optional persistent storage.

        Args:
            db_path: Path to JSON file for persisting metrics across runs
        """
        self.db_path = db_path or Path("./tool_metrics.json")
        self.metrics = self._load_metrics()

    def _load_metrics(self) -> dict:
        """Load metrics from disk if available."""
        default_metrics = {
            "tool_stats": {},  # {tool: {target_type: {success_count, fail_count, total_time}}}
            "target_profiles": {},  # {target_type: {tech_stack, waf_type, typical_tools}}
            "engagement_results": [],  # List of engagement summaries
        }
        if self.db_path.exists():
            try:
                with open(self.db_path) as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict):
                        for k, v in loaded.items():
                            default_metrics[k] = v
                        return default_metrics
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f'Swallowed exception in tool_success_tracker.py: {_e}')

        return default_metrics

    def _save_metrics(self):
        """Persist metrics to disk."""
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            # Atomic write: temp file + replace so an interrupted or concurrent
            # write can't truncate/corrupt the metrics file.
            _tmp = self.db_path.with_name(self.db_path.name + '.tmp')
            with open(_tmp, 'w') as f:
                json.dump(self.metrics, f, indent=2)
            _tmp.replace(self.db_path)
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in tool_success_tracker.py: {_e}')

    def log_tool_result(self, tool: str, target_type: str, success: bool,
                        duration: float = 0, waf_blocked: bool = False):
        """
        Log the result of a tool execution.

        Args:
            tool: Tool name (e.g., "sqlmap")
            target_type: Target classification (e.g., "wordpress", "apache", "cdn")
            success: Whether the tool found something
            duration: Execution duration in seconds
            waf_blocked: Whether the execution failed purely due to a WAF block
        """
        if tool not in self.metrics["tool_stats"]:
            self.metrics["tool_stats"][tool] = {}

        if target_type not in self.metrics["tool_stats"][tool]:
            self.metrics["tool_stats"][tool][target_type] = {
                "success_count": 0,
                "fail_count": 0,
                "waf_blocked_count": 0,
                "total_time": 0.0,
                "total_runs": 0,
            }

        stats = self.metrics["tool_stats"][tool][target_type]
        stats["total_runs"] += 1
        stats["total_time"] += duration

        if waf_blocked:
            stats.setdefault("waf_blocked_count", 0)
            stats["waf_blocked_count"] += 1
        elif success:
            stats["success_count"] += 1
        else:
            stats["fail_count"] += 1

        self._save_metrics()

    def get_tool_effectiveness(self, tool: str, target_type: str) -> dict:
        """
        Get effectiveness metrics for a tool on a target type.

        Returns:
            {
                "success_rate": 0.0-1.0,
                "total_runs": int,
                "avg_duration": float,
                "recommendation": str,
            }
        """
        if tool not in self.metrics["tool_stats"]:
            return {
                "success_rate": 0.5,  # Unknown, default to neutral
                "total_runs": 0,
                "avg_duration": 0.0,
                "recommendation": "insufficient_data",
            }

        if target_type not in self.metrics["tool_stats"][tool]:
            return {
                "success_rate": 0.5,  # Unknown
                "total_runs": 0,
                "avg_duration": 0.0,
                "recommendation": "not_tested_on_this_type",
            }

        stats = self.metrics["tool_stats"][tool][target_type]
        total = stats["total_runs"]
        waf_blocks = stats.get("waf_blocked_count", 0)
        valid_runs = total - waf_blocks
        success_rate = stats["success_count"] / \
            valid_runs if valid_runs > 0 else 0.5
        avg_duration = stats["total_time"] / total if total > 0 else 0.0

        # Generate recommendation based on effectiveness
        if total < 3:
            recommendation = "insufficient_data"
        elif success_rate > 0.7:
            recommendation = "highly_effective"
        elif success_rate > 0.4:
            recommendation = "moderately_effective"
        elif success_rate > 0.1:
            recommendation = "rarely_effective"
        else:
            recommendation = "ineffective_skip"

        return {
            "success_rate": round(success_rate, 2),
            "total_runs": total,
            "avg_duration": round(avg_duration, 1),
            "recommendation": recommendation,
        }

    def rank_tools_for_target(self, tools: list, target_type: str) -> list:
        """
        Rank tools by predicted effectiveness on a target type.

        Args:
            tools: List of tool names
            target_type: Target classification (e.g., "wordpress", "cdn")

        Returns:
            Sorted list of tools (highest priority first)
        """
        ranked = []

        for tool in tools:
            metrics = self.get_tool_effectiveness(tool, target_type)
            rank_score = (
                metrics["success_rate"] * 0.6 +  # Success rate: 60% weight
                # Speed: 30% weight
                (1.0 - min(metrics["avg_duration"] / 300, 1.0)) * 0.3 +
                # Data reliability: 10% weight
                (metrics["total_runs"] / 20) * 0.1
            )
            ranked.append((rank_score, tool, metrics))

        ranked.sort(reverse=True, key=lambda x: x[0])
        return [(tool, metrics) for _, tool, metrics in ranked]

    def profile_target(self, target_url: str, tech_stack: list,
                       waf_type: str = None) -> dict:
        """
        Build a profile of a target for future reference.

        Args:
            target_url: The target URL
            tech_stack: Detected technologies
            waf_type: Detected WAF type if any

        Returns:
            Target profile dict
        """
        # Classify target type based on tech stack
        target_type = self._classify_target(tech_stack, waf_type)

        profile = {
            "url": target_url,
            "tech_stack": tech_stack,
            "waf_type": waf_type,
            "target_type": target_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "recommended_tools": self._get_recommended_tools_for_target(target_type),
        }

        if target_type not in self.metrics["target_profiles"]:
            self.metrics["target_profiles"][target_type] = profile

        return profile

    def _classify_target(self, tech_stack: list, waf_type: str = None) -> str:
        """Classify target into a category based on tech stack."""
        tech_str = " ".join(tech_stack).lower()

        if waf_type:
            return f"{waf_type.lower()}_protected"

        if "wordpress" in tech_str:
            return "wordpress"
        elif "php" in tech_str:
            return "php"
        elif "apache" in tech_str:
            return "apache"
        elif "nginx" in tech_str:
            return "nginx"
        elif "node" in tech_str or "express" in tech_str:
            return "nodejs"
        else:
            return "generic"

    def _get_recommended_tools_for_target(self, target_type: str) -> list:
        """Get best tools for a target type based on history."""
        # Default tool recommendations per target type
        defaults = {
            "wordpress": ["curl", "sqlmap", "dalfox", "gobuster"],
            "php": ["dalfox", "commix", "sqlmap", "curl"],
            "apache": ["curl", "nmap"],
            "nginx": ["curl", "ffuf"],
            "nodejs": ["dalfox", "sqlmap", "curl"],
            "generic": ["curl", "nmap", "sqlmap"],
            "cloudflare_protected": ["curl"],  # Most tools blocked
            "akamai_protected": ["curl"],
        }

        if target_type not in defaults:
            return defaults["generic"]

        return defaults[target_type]

    def summarize_effectiveness(self) -> dict:
        """Generate a summary of tool effectiveness across all target types."""
        summary = {}

        for tool, target_stats in self.metrics["tool_stats"].items():
            summary[tool] = {}
            for target_type, stats in target_stats.items():
                success_rate = (stats["success_count"] / stats["total_runs"]
                                if stats["total_runs"] > 0 else 0)
                summary[tool][target_type] = {
                    "success_count": stats["success_count"],
                    "total_runs": stats["total_runs"],
                    "success_rate": success_rate,
                    "avg_duration": stats["total_time"] / stats["total_runs"] if stats["total_runs"] > 0 else 0
                }

        return summary
