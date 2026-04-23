from agents.base_agent import BaseAgent
from utils.display import section, info, warning, success

class PlanningAgent(BaseAgent):
    def run(self) -> dict:
        section("PHASE 1 — Planning & Preparation")
        self.store.set_phase_status(self.session.engagement_id, "planning", "running")

        # Validate scope
        if not self.session.scope:
            warning("No scope defined. Defaulting to primary target only.")
            self.session.scope = [self.session.target]

        # Log consent acknowledgment
        info(f"Target: {self.session.target}")
        info(f"Scope: {', '.join(self.session.scope)}")
        info(f"Mode: {self.session.mode}")
        info(f"ROE: {self.session.rules_of_engagement}")

        # AI-driven goal analysis
        prompt = (
            f"We are beginning a {self.session.mode} engagement against target: {self.session.target}. "
            f"Scope: {self.session.scope}. "
            f"Rules of engagement: {self.session.rules_of_engagement}. "
            f"List the 5 most important reconnaissance steps for this target, "
            f"and identify any risks we should be aware of."
        )
        analysis = self.think(prompt)
        info(f"AI Planning Analysis:\n{analysis}")

        self.add_finding(
            "engagement_plan", self.session.target,
            f"Mode={self.session.mode}, Scope={self.session.scope}, ROE={self.session.rules_of_engagement}",
            "info"
        )

        # Publish plan to all other agents
        self.bus.publish("planning", "all_agents", {
            "event": "plan_ready",
            "target": self.session.target,
            "scope": self.session.scope,
            "roe": self.session.rules_of_engagement,
            "ai_analysis": analysis
        })

        self.store.set_phase_status(
            self.session.engagement_id, "planning", "complete",
            f"Scope confirmed: {self.session.scope}"
        )
        success("Planning phase complete.")
        return {"target": self.session.target, "scope": self.session.scope, "analysis": analysis}
