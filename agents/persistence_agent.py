import json
import re
from agents.base_agent import BaseAgent
from utils.display import section, info, warning, success

class PersistenceAgent(BaseAgent):
    """
    Phase 5: Persistence and Lateral Movement
    In pentest mode: identifies and documents persistence mechanisms found
    In redteam mode: attempts non-destructive persistence verification
    """
    async def run(self) -> dict:
        section("PHASE 5 - Persistence & Lateral Movement")
        self.store.set_phase_status(self.session.engagement_id, "persistence", "running")

        roe = self.session.rules_of_engagement
        target = self.session.target
        results = {}

        # SMB lateral movement check
        findings = self.store.get_all_findings(self.session.engagement_id)

        # AI analysis of persistence opportunities
        info("Asking AI to identify persistence and lateral movement opportunities...")
        persist_prompt = (
            f"Target: {target}. Mode: {self.session.mode}.\n"
            f"Findings so far: {json.dumps(findings[:15], default=str)[:2000]}\n"
            f"What persistence mechanisms should be checked? "
            f"What lateral movement paths are possible? "
            f"Provide at most 3 commands to verify these (e.g. crontab -l). "
            f"Return ONLY a valid JSON array of strings. "
            f"Example: [\"crontab -l\", \"ls -la /etc/cron.d\"]"
        )
        ai_analysis_raw = self.think(persist_prompt)
        ai_analysis = ai_analysis_raw
        
        # Parse commands from AI response
        from core.robust_parser import extract_json_list
        try:
            # Use robust_parser to safely extract JSON arrays
            commands = extract_json_list(ai_analysis_raw, ai_backend=self.ai)
        except Exception as e:
            self.log.error(f"Failed to parse AI persistence plan: {e}")
            self.log.debug(f"Raw AI response: {ai_analysis_raw}")
            commands = []

        # Architectural 4: Run actual validation commands
        if roe.get("allow_exploitation"):
            # Architectural check: 'ssh_cmd' currently only runs on the scanner box.
            # We must explicitly separate this from target-bound execution.
            creds = [f for f in findings if f["type"] == "valid_credential"]
            if creds:
                # FUTURE: Implement TargetSSHExecutor for real target interaction.
                # For now, we block this to prevent scanner-box pollution.
                warning("System credentials found, but direct target SSH execution is not yet isolated from scanner box. Skipping automated validation to prevent self-infection.")
            elif commands:
                info(f"Executing {len(commands)} persistence verification commands...")
                for cmd in commands:
                    info(f"Running: {cmd}")
                    primary_tool = self._extract_primary_tool(cmd)
                    if not primary_tool:
                        primary_tool = "unknown"
                    r = self.safe_run_tool(primary_tool, cmd, target)
                    if r.success:
                        self.add_finding("persistence_verified", target, f"Verified: {cmd}", "info")
                        success(f"Successfully verified: {cmd}")
                    else:
                        self.log.debug(f"Command failed: {cmd} - {r.stderr}")
            else:
                info("No specific persistence commands suggested by AI. Passive analysis only.")

        self.bus.publish("persistence", "objectives", {
            "event": "persistence_complete",
            "findings": findings,
            "ai_analysis": ai_analysis
        })

        self.store.set_phase_status(
            self.session.engagement_id, "persistence", "complete",
            (ai_analysis or "")[:200]
        )

        success("Persistence phase complete.")
        return self.finish_phase({
            "ai_analysis": ai_analysis,
            "findings": findings
        })
