"""
Engagement Recorder: Captures engagement outcomes and feeds learning to StrategicAdvisor

Records:
- Tool performance and effectiveness
- Tech stack patterns and what worked
- WAF types and successful evasion tactics
- Failure patterns and what to avoid
- Discovery order efficiency
"""

import json
from typing import Dict, Any
from datetime import datetime, timezone
from pathlib import Path


class EngagementRecorder:
    """Records engagement data and feeds it to the learning system."""

    def __init__(self, advisor=None, state_store=None):
        self.advisor = advisor
        self.store = state_store
        self.current_engagement_data = {
            "engagement_id": None,
            "target": None,
            "tech_stack": [],
            "waf_detected": None,
            "tools_used": {},  # tool -> {"success": bool, "time": float, "attempts": int}
            "findings": [],
            "waf_tactics_used": [],
            "discovery_order": [],  # order tools were executed
            "phase_durations": {},  # phase -> duration_seconds
        }

    def start_engagement(self, engagement_id: str, target: str):
        """Start recording a new engagement."""
        self.current_engagement_data = {
            "engagement_id": engagement_id,
            "target": target,
            "tech_stack": [],
            "waf_detected": None,
            "tools_used": {},
            "findings": [],
            "waf_tactics_used": [],
            "discovery_order": [],
            "phase_durations": {},
            "start_time": datetime.now(timezone.utc).isoformat(),
        }

    def record_tool_usage(self, tool: str, success: bool,
                          duration: float = 0, attempts: int = 1):
        """Record that a tool was used and whether it succeeded."""
        tool_key = tool.lower()
        if tool_key not in self.current_engagement_data["tools_used"]:
            self.current_engagement_data["tools_used"][tool_key] = {
                "success": False, "time": 0, "attempts": 0
            }

        record = self.current_engagement_data["tools_used"][tool_key]
        # Success if ANY attempt succeeded
        record["success"] = success or record["success"]
        record["time"] += duration
        record["attempts"] += attempts

        # Track discovery order
        if tool_key not in self.current_engagement_data["discovery_order"]:
            self.current_engagement_data["discovery_order"].append(tool_key)

    def record_tech_stack_discovery(self, tech: str):
        """Record discovery of a technology."""
        if tech not in self.current_engagement_data["tech_stack"]:
            self.current_engagement_data["tech_stack"].append(tech)

    def record_waf_detection(self, waf_type: str, fingerprint: Dict = None):
        """Record WAF detection."""
        self.current_engagement_data["waf_detected"] = waf_type
        if fingerprint:
            self.current_engagement_data["waf_fingerprint"] = fingerprint

    def record_waf_tactic_used(self, tactic: str):
        """Record WAF evasion tactic used."""
        if tactic not in self.current_engagement_data["waf_tactics_used"]:
            self.current_engagement_data["waf_tactics_used"].append(tactic)

    def record_finding(self, finding_type: str, detail: str, severity: str):
        """Record a finding."""
        self.current_engagement_data["findings"].append({
            "type": finding_type,
            "detail": detail,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    def record_phase_duration(self, phase: str, duration_seconds: float):
        """Record how long a phase took."""
        self.current_engagement_data["phase_durations"][phase] = duration_seconds

    def finalize_and_learn(self):
        """Finalize engagement recording and feed to advisor for learning."""
        if not self.advisor:
            return

        self.current_engagement_data["end_time"] = datetime.now(
            timezone.utc).isoformat()

        # Call advisor's learning method
        try:
            self.advisor.record_engagement_outcome(
                engagement_id=self.current_engagement_data.get(
                    "engagement_id"),
                target=self.current_engagement_data.get("target"),
                findings=self.current_engagement_data.get("findings", []),
                tech_stack=self.current_engagement_data.get("tech_stack", []),
                waf_detected=self.current_engagement_data.get("waf_detected"),
                tool_performance=self.current_engagement_data.get(
                    "tools_used", {}),
                waf_tactics_used=self.current_engagement_data.get(
                    "waf_tactics_used", [])
            )
        except Exception as e:
            print(f"Failed to record engagement outcome: {e}")

        # Persist engagement record
        try:
            from config_paths import LOCAL_RESULTS_DIR
            records_dir = Path(
                LOCAL_RESULTS_DIR) / self.current_engagement_data.get("engagement_id", "unknown")
            records_dir.mkdir(parents=True, exist_ok=True)
            record_file = records_dir / "engagement_record.json"
            record_file.write_text(
                json.dumps(
                    self.current_engagement_data,
                    indent=2))
        except Exception as e:
            print(f"Failed to persist engagement record: {e}")

    def get_current_engagement_summary(self) -> Dict[str, Any]:
        """Get a summary of the current engagement for reporting."""
        data = self.current_engagement_data

        successful_tools = [
            t for t, r in data.get("tools_used", {}).items()
            if r.get("success")
        ]
        failed_tools = [
            t for t, r in data.get("tools_used", {}).items()
            if not r.get("success")
        ]

        summary = {
            "target": data.get("target"),
            "tech_stack": data.get("tech_stack", []),
            "waf_detected": data.get("waf_detected"),
            "successful_tools": successful_tools,
            "failed_tools": failed_tools,
            "total_findings": len(data.get("findings", [])),
            "critical_findings": len([f for f in data.get("findings", []) if f.get("severity") == "critical"]),
            "discovery_order": data.get("discovery_order", []),
            "phase_durations": data.get("phase_durations", {}),
        }

        return summary
