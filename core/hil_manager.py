"""
Human-in-the-Loop (HIL) Escalation Manager
Allows the autonomous engine to pause execution and prompt the operator for critical decisions.
"""
from rich.prompt import Confirm
from utils.display import warning


class HILManager:
    @staticmethod
    def request_override(reason: str, prompt: str,
                         default: bool = False) -> bool:
        """
        Escalates a decision to the operator.
        Returns True if the operator approves, False otherwise.
        """
        warning(f"HIL ESCALATION TRIGGERED: {reason}")
        return Confirm.ask(
            f"[bold yellow]{prompt}[/bold yellow]", default=default)


# Global singleton
hil_manager = HILManager()
