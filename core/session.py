import uuid
import threading
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, List
from config_paths import RESULTS_DIR


@dataclass
class EngagementSession:
    mode: str                          # "pentest" or "redteam"
    target: str = ""                   # Primary target (IP, domain, or CIDR)
    # All in-scope targets/ranges
    scope: List[str] = field(default_factory=list)
    rules_of_engagement: dict = field(
        default_factory=dict)  # What's allowed and what isn't
    operator: str = "operator"         # Who is running this
    ai_backend: str = "ollama"         # Preferred AI Backend
    stealth_config: dict = field(default_factory=dict)  # WAF policy/settings
    guardian_enabled: bool = True      # Whether Validation Agent is active
    engagement_id: str = field(
        default_factory=lambda: f"eng_{uuid.uuid4().hex[:8]}")

    # Compatibility attributes for V6/V7 and main.py / real_integration_test.py
    target_context: Any = None
    scope_strs: Any = None
    destructive_mode: bool = False

    # WS3 — authenticated testing. Operator may supply test credentials
    # ({"login_url","mode","fields"/"payload","success_markers"}) and an
    # interactive HITL approver callable(action_name, description) -> bool.
    credentials: dict = field(default_factory=dict)
    hitl_approver: Any = None

    started_at: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc).isoformat())
    results_dir: Path = None
    db_path: Path = None
    shutdown: threading.Event = field(default_factory=threading.Event)

    def __post_init__(self):
        if self.target_context is not None and not self.target:
            self.target = getattr(
                self.target_context, 'full_url', str(
                    self.target_context))
        if self.scope_strs is not None and not self.scope:
            self.scope = list(self.scope_strs)

        self.results_dir = RESULTS_DIR / self.engagement_id
        self.db_path = self.results_dir / "state.db"
        (self.results_dir / "raw").mkdir(parents=True, exist_ok=True)
        (self.results_dir / "parsed").mkdir(parents=True, exist_ok=True)
        (self.results_dir / "logs").mkdir(parents=True, exist_ok=True)
        (self.results_dir / "report").mkdir(parents=True, exist_ok=True)

        import config_paths
        # Dynamically append engagement_id to remote/WSL paths to ensure segregation per engagement
        if hasattr(config_paths, "WSL_TEMP_DIR") and self.engagement_id not in config_paths.WSL_TEMP_DIR:
            config_paths.WSL_TEMP_DIR = f"{config_paths.WSL_TEMP_DIR.rstrip('/')}/{self.engagement_id}"
            config_paths.VPS_TEMP_DIR = config_paths.WSL_TEMP_DIR
        if hasattr(config_paths, "WSL_RESULTS_DIR") and self.engagement_id not in config_paths.WSL_RESULTS_DIR:
            config_paths.WSL_RESULTS_DIR = f"{config_paths.WSL_TEMP_DIR}/results"
            config_paths.VPS_RESULTS_DIR = config_paths.WSL_RESULTS_DIR

    def normalized_target(self) -> str:
        """Return a canonical host-only form of the session target (no scheme/path)."""
        t = str(self.target or "").strip()
        # Remove scheme if present
        if t.startswith("http://") or t.startswith("https://"):
            t = t.split("://", 1)[1]
        # Strip path
        t = t.split("/")[0]
        return t

    def clear_transient_context(self):
        """Clears transient short-term memory to prevent LLM hallucination between phases."""
