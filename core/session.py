import uuid
import threading
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from config import RESULTS_DIR

@dataclass
class EngagementSession:
    mode: str                          # "pentest" or "redteam"
    target: str                        # Primary target (IP, domain, or CIDR)
    scope: list[str]                   # All in-scope targets/ranges
    rules_of_engagement: dict          # What's allowed and what isn't
    operator: str = "operator"         # Who is running this
    ai_backend: str = "ollama"         # Preferred AI Backend
    engagement_id: str = field(default_factory=lambda: f"eng_{uuid.uuid4().hex[:8]}")

    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    results_dir: Path = None
    db_path: Path = None
    shutdown: threading.Event = field(default_factory=threading.Event)

    def __post_init__(self):
        self.results_dir = RESULTS_DIR / self.engagement_id
        self.db_path = self.results_dir / "state.db"
        (self.results_dir / "raw").mkdir(parents=True, exist_ok=True)
        (self.results_dir / "parsed").mkdir(parents=True, exist_ok=True)
        (self.results_dir / "logs").mkdir(parents=True, exist_ok=True)
        (self.results_dir / "report").mkdir(parents=True, exist_ok=True)
