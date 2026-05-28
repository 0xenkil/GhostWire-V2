from agents.base_agent import BaseAgent
from utils.display import section, info, warning, success
from intelligence.waf_bypass_orchestrator import WafBypassOrchestrator

class PlanningAgent(BaseAgent):
    async def run(self) -> dict:
        section("PHASE 1 - Planning & Preparation")
        self.store.set_phase_status(self.session.engagement_id, "planning", "running")

        # Validate scope
        if not self.session.scope:
            warning("No scope defined. Defaulting to primary target only.")
            self.session.scope = [self.session.target]

        # Log consent acknowledgment
        info(f"Target: {self.session.normalized_target()}")
        info(f"Scope: {', '.join(self.session.scope)}")
        info(f"Mode: {self.session.mode}")
        info(f"ROE: {self.session.rules_of_engagement}")

        # ===== WAF BYPASS ORCHESTRATION =====
        info("\n[GHOST-PROTOCOL] Initializing active WAF bypass orchestration...")
        try:
            orchestrator = WafBypassOrchestrator(state_store=self.store)
            bypass_analysis = orchestrator.analyze_target(self.session.engagement_id, self.session.target)
            
            # Store WAF policy posture for use by other agents
            import json
            self.store.set(
                f"{self.session.engagement_id}:waf_bypass_analysis",
                json.dumps(bypass_analysis)
            )
            
            # Display findings
            rec_bypass = bypass_analysis.get("recommended_bypass")
            priority_order = bypass_analysis.get("bypass_priority_order", [])
            risk_level = bypass_analysis.get("risk_profile", {}).get("risk_level", "unknown")
            
            if rec_bypass:
                success(f"WAF bypass strategy: {rec_bypass.upper()}")
                info(f"  Priority order: {' -> '.join(priority_order[:5])}")
                info(f"  Risk level: {risk_level}")
                
                # Show viability scores
                viability = bypass_analysis.get("viability_scores", {})
                viable_layers = sorted([(k, v) for k, v in viability.items() if v > 0.3], 
                                      key=lambda x: x[1], reverse=True)
                if viable_layers:
                    info(f"  Policy layers:")
                    for layer, score in viable_layers[:5]:
                        info(f"    - {layer}: {score:.0%} viable")
            else:
                info("  Direct probing active: target appears to have minimal WAF filtering")
            
        except Exception as e:
            warning(f"WAF defense policy analysis error (non-fatal): {e}")

        # AI-driven goal analysis with schema-validated planning
        from core.robust_parser import extract_json_object
        prompt = (
            f"We are beginning a {self.session.mode} engagement against target: {self.session.normalized_target()}. "
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
        except Exception:
            analysis = {"ConOps": "Fallback plan", "RoE": self.session.rules_of_engagement, "phases": []}
            
        info(f"\nAI Planning Analysis (Schema Validated):\n{json.dumps(analysis, indent=2)}")

        self.add_finding(
            "engagement_plan", self.session.normalized_target(),
            f"Mode={self.session.mode}, Scope={self.session.scope}, ROE={self.session.rules_of_engagement}",
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
        for agent_name in ["recon", "exploitation", "weaponization", "persistence", "objectives", "reporting"]:
            self.bus.publish("planning", agent_name, plan_message)

        self.store.set_phase_status(
            self.session.engagement_id, "planning", "complete",
            f"Scope confirmed: {self.session.scope}"
        )
        success("Planning phase complete.")
        return {"target": self.session.normalized_target(), "scope": self.session.scope, "analysis": analysis}
