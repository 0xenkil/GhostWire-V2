import json
from agents.base_agent import BaseAgent
from utils.display import section, info, success, warning

class ObjectivesAgent(BaseAgent):
    """
    Phase 6: Actions on Objectives
    Executes the final goal: data exfiltration simulation, critical system access
    WITHOUT causing actual damage.
    """
    async def run(self) -> dict:
        section("PHASE 6 - Actions on Objectives")
        self.store.set_phase_status(self.session.engagement_id, "objectives", "running")

        roe = self.session.rules_of_engagement
        target = self.session.target
        results = {}

        findings = self.store.get_all_findings(self.session.engagement_id)
        critical = [f for f in findings if f.get("severity", "") in ["critical", "high"]]

        # AI summary of what objectives are achievable
        info("Asking AI to assess achievable objectives...")
        obj_prompt = (
            f"Target: {target}. Engagement mode: {self.session.mode}.\n"
            f"High/critical findings: {json.dumps(critical[:10], default=str)[:2000]}\n"
            f"What objectives could realistically be achieved? "
            f"Provide 3 search patterns for sensitive data (e.g. *.conf)."
        )
        ai_objectives = self.think(obj_prompt)
        results["achievable_objectives"] = ai_objectives
        
        # Architectural 4: Run actual data discovery commands
        if roe.get("allow_exploitation"):
            # Architectural check: 'ssh_cmd' currently only runs on the scanner box.
            # We must explicitly separate this from target-bound execution.
            creds = [f for f in findings if (f.get("type") or f.get("finding_type", "")) == "valid_credential"]
            if creds:
                # FUTURE: Implement TargetSSHExecutor for real target interaction.
                # For now, we block this to prevent scanner-box pollution.
                warning("System credentials found, but direct target SSH execution is not yet isolated from scanner box. Skipping automated verification to prevent data pollution of scanner box.")
            else:
                info("No valid system credentials found. Objective assessment limited to theoretical impact.")

        # Severity for the objectives_assessment finding: use the highest severity
        # found in actual critical/high findings - never auto-escalate to CRITICAL
        # just because the findings list is non-empty.
        # Additionally, exclude known Nikto structural noise lines that may have
        # been miscategorised as CRITICAL by an earlier pipeline run.
        _NOISE_PATTERNS = [
            "no cgi directories found", "items checked", "host(s) tested",
            "no web server found", "host maximum execution time",
        ]
        real_critical = [
            f for f in findings
            if f.get("severity", "") == "critical"
            and not any(p in (f.get("detail") or "").lower() for p in _NOISE_PATTERNS)
        ]
        obj_severity = "critical" if real_critical else ("high" if critical else "medium")

        self.add_finding(
            "objectives_assessment", target,
            ai_objectives[:500], obj_severity
        )

        self.bus.publish("objectives", "reporting", {
            "event": "objectives_complete",
            "critical_count": len(critical),
            "ai_assessment": ai_objectives
        })

        success("Objectives phase complete.")
        return self.finish_phase(results, message=f"Assessed {len(critical)} critical findings.")
