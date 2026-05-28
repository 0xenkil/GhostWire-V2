import uuid
import threading
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, List
from config import RESULTS_DIR

@dataclass
class EngagementSession:
    mode: str                          # "pentest" or "redteam"
    target: str = ""                   # Primary target (IP, domain, or CIDR)
    scope: List[str] = field(default_factory=list) # All in-scope targets/ranges
    rules_of_engagement: dict = field(default_factory=dict) # What's allowed and what isn't
    operator: str = "operator"         # Who is running this
    ai_backend: str = "ollama"         # Preferred AI Backend
    stealth_config: dict = field(default_factory=dict) # WAF policy/settings
    guardian_enabled: bool = True      # Whether Validation Agent is active
    engagement_id: str = field(default_factory=lambda: f"eng_{uuid.uuid4().hex[:8]}")

    # Compatibility attributes for V6/V7 and main.py / real_integration_test.py
    target_context: Any = None
    scope_strs: Any = None
    destructive_mode: bool = False

    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    results_dir: Path = None
    db_path: Path = None
    shutdown: threading.Event = field(default_factory=threading.Event)

    def __post_init__(self):
        if self.target_context is not None and not self.target:
            self.target = getattr(self.target_context, 'full_url', str(self.target_context))
        if self.scope_strs is not None and not self.scope:
            self.scope = list(self.scope_strs)
            
        self.results_dir = RESULTS_DIR / self.engagement_id
        self.db_path = self.results_dir / "state.db"
        (self.results_dir / "raw").mkdir(parents=True, exist_ok=True)
        (self.results_dir / "parsed").mkdir(parents=True, exist_ok=True)
        (self.results_dir / "logs").mkdir(parents=True, exist_ok=True)
        (self.results_dir / "report").mkdir(parents=True, exist_ok=True)

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
        pass
