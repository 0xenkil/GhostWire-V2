from agents.base_agent import BaseAgent
from utils.logger import get_logger


class StrategicMentor(BaseAgent):
    def __init__(self, name: str = "strategic_mentor", **kwargs):
        super().__init__(name, **kwargs)
        self.log = get_logger("agent.mentor")

    def advise(self, transcript: str, objective: str,
               guardian_logs: str) -> dict:
        """
        Analyze the failed transcript and provide strategic recommendations to pivot.
        """
        prompt = (
            "You are the GHOSTWIRE Strategic Mentor. A specialist offensive agent has got stuck in a failure loop.\n"
            "Analyze the following context and prescribe a pivot strategy:\n\n"
            f"### CURRENT OBJECTIVE\n{objective}\n\n"
            f"### RECENT ATTEMPTS & OBSERVATIONS (TRANSCRIPT)\n{transcript}\n\n"
            f"### GUARDIAN & SYSTEM LOGS\n{guardian_logs}\n\n"
            "Assess the progress, identify structural flaws in their approach (e.g., trying to exploit a patched service, "
            "triggering WAF blocks, using invalid syntax, or scanning in-scope targets with wrong assumptions), "
            "and suggest a concrete pivot path.\n\n"
            "Return a strictly formatted JSON object with the following keys:\n"
            "{\n"
            "  \"assessment\": \"Brief summary of what went wrong and progress made so far\",\n"
            "  \"flaws\": \"Identify the specific flaws in the previous attempts\",\n"
            "  \"pivot_recommendation\": \"A concrete, step-by-step recommendation on what the agent should do next (e.g., try another port, use a different tool, search for specific files, etc.)\"\n"
            "}\n"
            "Return ONLY the raw JSON object, without any markdown formatting or ticks."
        )

        try:
            ai_resp = self.think(prompt, mode="nano")
            # Clean potential markdown formatting
            ai_resp = ai_resp.strip()
            if ai_resp.startswith("```json"):
                ai_resp = ai_resp[7:]
            if ai_resp.startswith("```"):
                ai_resp = ai_resp[3:]
            if ai_resp.endswith("```"):
                ai_resp = ai_resp[:-3]
            ai_resp = ai_resp.strip()

            from core.robust_parser import extract_json_object
            data = extract_json_object(ai_resp)
            return data
        except Exception as e:
            self.log.error(f"Failed to query Strategic Mentor: {e}")
            return {
                "assessment": "Failures detected, mentor query failed.",
                "flaws": "Repeated failures on the current vector.",
                "pivot_recommendation": "Abandon current tool and target. Attempt a different port or check local files."
            }

    async def run(self) -> dict:
        # Standalone run not required for mentor
        return {"status": "mentor_idle"}
