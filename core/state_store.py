import sqlite3
import json
import threading
from datetime import datetime
from pathlib import Path
from utils.logger import get_logger

log = get_logger("state_store")

class StateStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=15)
        self._lock = threading.Lock()
        self._init_schema()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _init_schema(self):
        with self._lock:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS phases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    started_at TEXT,
                    finished_at TEXT,
                    summary TEXT
                );
                CREATE TABLE IF NOT EXISTS tool_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    command TEXT NOT NULL,
                    status TEXT,
                    stdout TEXT,
                    stderr TEXT,
                    exit_code INTEGER,
                    duration_sec REAL,
                    timestamp TEXT
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT NOT NULL,
                    agent_id TEXT,
                    phase TEXT NOT NULL,
                    finding_type TEXT,
                    target TEXT,
                    detail TEXT,
                    severity TEXT DEFAULT 'info',
                    timestamp TEXT
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT NOT NULL,
                    from_agent TEXT,
                    to_agent TEXT,
                    content TEXT,
                    timestamp TEXT
                );
                CREATE TABLE IF NOT EXISTS phase_data (
                    engagement_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    data TEXT,
                    PRIMARY KEY(engagement_id, phase)
                );
            """)
            self.conn.commit()

    def set_phase_status(self, engagement_id: str, phase: str, status: str, summary: str = ""):
        now = datetime.utcnow().isoformat()
        with self._lock:
            existing = self.conn.execute(
                "SELECT id FROM phases WHERE engagement_id=? AND phase=?",
                (engagement_id, phase)
            ).fetchone()
            if existing:
                self.conn.execute(
                    "UPDATE phases SET status=?, finished_at=?, summary=? WHERE engagement_id=? AND phase=?",
                    (status, now, summary, engagement_id, phase)
                )
            else:
                self.conn.execute(
                    "INSERT INTO phases (engagement_id, phase, status, started_at, summary) VALUES (?,?,?,?,?)",
                    (engagement_id, phase, status, now, summary)
                )
            self.conn.commit()

    def log_tool_run(self, engagement_id: str, phase: str, tool: str,
                     command: str, status: str, stdout: str, stderr: str,
                     exit_code: int, duration: float):
        with self._lock:
            self.conn.execute(
                """INSERT INTO tool_runs
                   (engagement_id, phase, tool, command, status, stdout, stderr, exit_code, duration_sec, timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (engagement_id, phase, tool, command, status,
                 stdout[:50000], stderr[:10000], exit_code, duration,
                 datetime.utcnow().isoformat())
            )
            self.conn.commit()

    def add_finding(self, engagement_id: str, phase: str, finding_type: str,
                    target: str, detail: str, severity: str = "info", agent_id: str = "unknown"):
        with self._lock:
            self.conn.execute(
                """INSERT INTO findings
                   (engagement_id, agent_id, phase, finding_type, target, detail, severity, timestamp)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (engagement_id, agent_id, phase, finding_type, target, detail, severity,
                 datetime.utcnow().isoformat())
            )
            self.conn.commit()

    def get_all_findings(self, engagement_id: str) -> list:
        with self._lock:
            rows = self.conn.execute(
                "SELECT phase, finding_type, target, detail, severity, timestamp FROM findings WHERE engagement_id=? ORDER BY timestamp",
                (engagement_id,)
            ).fetchall()
            return [
                dict(phase=r[0], type=r[1], target=r[2], detail=r[3], severity=r[4], timestamp=r[5])
                for r in rows
            ]

    def log_message(self, engagement_id: str, from_agent: str, to_agent: str, content: str):
        with self._lock:
            self.conn.execute(
                "INSERT INTO messages (engagement_id, from_agent, to_agent, content, timestamp) VALUES (?,?,?,?,?)",
                (engagement_id, from_agent, to_agent, content, datetime.utcnow().isoformat())
            )
            self.conn.commit()

    def set_phase_data(self, engagement_id: str, phase: str, data: dict):
        """Persist structured results from a phase with thread-safe merging."""
        with self._lock:
            # 1. Fetch existing data
            row = self.conn.execute(
                "SELECT data FROM phase_data WHERE engagement_id=? AND phase=?",
                (engagement_id, phase)
            ).fetchone()
            
            merged_data = data
            if row:
                try:
                    existing = json.loads(row[0])
                    if isinstance(existing, dict) and isinstance(data, dict):
                        # Merge dicts
                        merged_data = {**existing, **data}
                except Exception:
                    pass

            # 2. Save merged data
            self.conn.execute(
                "INSERT OR REPLACE INTO phase_data (engagement_id, phase, data) VALUES (?, ?, ?)",
                (engagement_id, phase, json.dumps(merged_data, default=str))
            )
            self.conn.commit()

    def get_phase_data(self, engagement_id: str, phase: str) -> dict:
        """Retrieve persisted results from a specific phase."""
        with self._lock:
            row = self.conn.execute(
                "SELECT data FROM phase_data WHERE engagement_id=? AND phase=?",
                (engagement_id, phase)
            ).fetchone()
            return json.loads(row[0]) if row else None

    def get_phase_status(self, engagement_id: str, phase: str) -> str | None:
        """Get the status of a specific phase. Returns None if phase hasn't started."""
        with self._lock:
            row = self.conn.execute(
                "SELECT status FROM phases WHERE engagement_id=? AND phase=?",
                (engagement_id, phase)
            ).fetchone()
            return row[0] if row else None

    def get_phase_summary(self, engagement_id: str) -> dict:
        with self._lock:
            rows = self.conn.execute(
                "SELECT phase, status, summary FROM phases WHERE engagement_id=?",
                (engagement_id,)
            ).fetchall()
            return {r[0]: {"status": r[1], "summary": r[2]} for r in rows}

    def close(self):
        with self._lock:
            if self.conn:
                self.conn.close()
                self.conn = None
