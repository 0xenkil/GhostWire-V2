from agents.base_agent import BaseAgent
from utils.display import section, info, warning, success
from core.result_contracts import ResultStatus


class PlanningAgent(BaseAgent):
    async def run(self) -> dict:
        section("PHASE 1 - Planning & Preparation")
        self.store.set_phase_status(
            self.session.engagement_id, "planning", "running")

        # Validate scope
        if not self.session.scope:
            warning("No scope defined. Defaulting to primary target only.")
            self.session.scope = [self.session.target]

        # Log consent acknowledgment
        info(f"Target: {self.session.normalized_target()}")
        info(f"Scope: {', '.join(self.session.scope)}")
        info(f"Mode: {self.session.mode}")
        info(f"ROE: {self.session.rules_of_engagement}")

        # AI-driven goal analysis with schema-validated planning
        from core.robust_parser import extract_json_object
        prompt = (
            f"We are beginning a {
                self.session.mode} engagement against target: {
                self.session.normalized_target()}. "
            f"Scope: {self.session.scope}. "
            f"Rules of engagement: {self.session.rules_of_engagement}. "
            f"Generate a structured Concept of Operations (ConOps) and Rules of Engagement (RoE). "
            f"You MUST return valid JSON in exactly this format:\n"
            f"{{\n"
            f"  \"ConOps\": \"Detailed concept of operations plan\",\n"
            f"  \"RoE\": \"Specific rules of engagement constraints\",\n"
            f"  \"phases\": [\"phase1\", \"phase2\"]\n"
            f"}}\n"
        )
        raw_analysis = self.think(prompt)
        try:
            analysis = extract_json_object(raw_analysis)
        except Exception as e:
            import logging as __logging_tmp
            __logging_tmp.getLogger(__name__).debug(f"Silenced exception: {e}")
            analysis = {
                "ConOps": "Fallback plan",
                "RoE": self.session.rules_of_engagement,
                "phases": []}

        # Format the plan nicely instead of a raw JSON dump
        analysis_lower = {k.lower(): v for k, v in analysis.items()}

        plan_ui = "\n" + "=" * 60 + "\n"
        plan_ui += " TACTICAL ENGAGEMENT PLAN\n"
        plan_ui += "=" * 60 + "\n\n"
        
        conops_val = analysis_lower.get('conops', analysis_lower.get('concept_of_operations', 'None'))
        plan_ui += f" [CONOPS] Concept of Operations:\n {conops_val}\n\n"
        
        roe_val = analysis_lower.get('roe', analysis_lower.get('rules_of_engagement', 'None'))
        plan_ui += f" [RoE] Rules of Engagement:\n {roe_val}\n\n"

        phases = analysis_lower.get('phases', [])
        if phases:
            plan_ui += " [PHASES] Execution Pipeline:\n"
            for i, p in enumerate(phases, 1):
                plan_ui += f"   {i}. {p}\n"

        plan_ui += "=" * 60
        info(plan_ui)

        self.add_finding(
            "engagement_plan", self.session.normalized_target(),
            f"Mode={
                self.session.mode}, Scope={
                self.session.scope}, ROE={
                self.session.rules_of_engagement}",
            "info"
        )

        # Publish plan to all other agents via their respective channels
        # Each agent subscribes to its own name, so we send individual messages
        plan_message = {
            "event": "plan_ready",
            "target": self.session.normalized_target(),
            "scope": self.session.scope,
            "roe": self.session.rules_of_engagement,
            "ai_analysis": analysis
        }
        for agent_name in ["recon", "exploitation", "weaponization",
                           "persistence", "objectives", "reporting"]:
            self.bus.publish("planning", agent_name, plan_message)

        success("Planning phase complete.")
        return self.finish_phase(
            {"target": self.session.normalized_target(),
             "scope": self.session.scope,
             "analysis": analysis},
            status=ResultStatus.SUCCESS,
            message=f"Scope confirmed: {self.session.scope}"
        )
