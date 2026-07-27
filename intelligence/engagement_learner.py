import json
from datetime import datetime, timezone
from core.state_store import StateStore


class EngagementLearner:
    """Tracks tool success rates and WAF evasion tactics across engagements."""

    def __init__(self, store: StateStore):
        self.store = store

    def log_tool_outcome(self, engagement_id: str,
                         tool_name: str, success: bool, tactics: dict = None):
        with self.store._lock:
            existing = self.store.conn.execute(
                "SELECT id, success, failure FROM learning WHERE engagement_id=? AND tool_name=?",
                (engagement_id, tool_name)
            ).fetchone()

            tactics_str = json.dumps(tactics) if tactics else "{}"
            now = datetime.now(timezone.utc).isoformat()

            if existing:
                s_count = existing[1] + (1 if success else 0)
                f_count = existing[2] + (0 if success else 1)
                self.store.conn.execute(
                    "UPDATE learning SET success=?, failure=?, tactics=?, last_updated=? WHERE id=?",
                    (s_count, f_count, tactics_str, now, existing[0])
                )
            else:
                self.store.conn.execute(
                    "INSERT INTO learning (engagement_id, tool_name, success, failure, tactics, last_updated) VALUES (?, ?, ?, ?, ?, ?)",
                    (engagement_id, tool_name, 1 if success else 0,
                     0 if success else 1, tactics_str, now)
                )
            self.store.conn.commit()

    def get_tool_stats(self, engagement_id: str, tool_name: str) -> dict:
        with self.store._lock:
            row = self.store.conn.execute(
                "SELECT success, failure, tactics FROM learning WHERE engagement_id=? AND tool_name=?",
                (engagement_id, tool_name)
            ).fetchone()
            if row:
                return {
                    "success": row[0],
                    "failure": row[1],
                    "tactics": json.loads(row[2])
                }
            return {"success": 0, "failure": 0, "tactics": {}}
