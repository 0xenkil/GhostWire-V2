import sqlite3
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from config_thresholds import DB_TIMEOUT
from utils.logger import get_logger

log = get_logger("state_store")


class StateStore:
    def __init__(self, db_path):
        if str(db_path) != ":memory:":
            db_path = Path(db_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(
            str(db_path),
            check_same_thread=False,
            timeout=DB_TIMEOUT)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        # FIX #3.5: Thread safety - initialization event to prevent access
        # before schema is ready
        self._initialized = threading.Event()
        self._init_schema()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in scratch_state_store.py: {_e}')

    def _wait_for_init(self, timeout: int = 30):
        """FIX #3.5: Wait for database initialization before proceeding."""
        if not self._initialized.wait(timeout=timeout):
            log.error(
                f"[FIX 3.5] StateStore initialization timeout after {timeout}s")
            raise RuntimeError(
                "StateStore initialization timeout - database schema not ready")

    def _init_schema(self):
        with self._lock:
            # Enable WAL mode for better concurrency
            self.conn.execute("PRAGMA journal_mode=WAL;")
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
                    evasion_applied TEXT,
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
                    timestamp TEXT,
                    UNIQUE(engagement_id, finding_type, target, detail)
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
                CREATE TABLE IF NOT EXISTS failure_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    tool TEXT,
                    error_type TEXT,
                    command TEXT,
                    stderr TEXT,
                    root_cause TEXT,
                    severity TEXT,
                    avoid_next TEXT,
                    retry_count INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT
                );
                CREATE TABLE IF NOT EXISTS evidence_graph (
                    engagement_id TEXT NOT NULL,
                    node_type TEXT NOT NULL,
                    node_key TEXT NOT NULL,
                    attributes TEXT,
                    updated_at TEXT,
                    PRIMARY KEY(engagement_id, node_type, node_key)
                );
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    engagement_id TEXT NOT NULL,
                    key TEXT NOT NULL,
                    type TEXT NOT NULL,
                    attributes TEXT NOT NULL,
                    PRIMARY KEY(engagement_id, key)
                );
                CREATE TABLE IF NOT EXISTS graph_edges (
                    engagement_id TEXT NOT NULL,
                    source TEXT,
                    target TEXT,
                    rel_type TEXT,
                    PRIMARY KEY (engagement_id, source, target, rel_type),
                    FOREIGN KEY(engagement_id, source) REFERENCES graph_nodes(engagement_id, key),
                    FOREIGN KEY(engagement_id, target) REFERENCES graph_nodes(engagement_id, key)
                );
                CREATE TABLE IF NOT EXISTS learning (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    success INTEGER DEFAULT 0,
                    failure INTEGER DEFAULT 0,
                    tactics TEXT,
                    last_updated TEXT
                );
            """)
            self.conn.commit()
            # FIX #3.5: Signal that initialization is complete
            self._initialized.set()

    def set_phase_status(self, engagement_id: str,
                         phase: str, status: str, summary: str = ""):
        # FIX #3.5: Ensure database is initialized before accessing
        self._wait_for_init()
        now = datetime.now(timezone.utc).isoformat()
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
                     exit_code: int, duration: float, evasion_applied: str = None):
        self._wait_for_init()
        with self._lock:
            self.conn.execute(
                """INSERT INTO tool_runs
                   (engagement_id, phase, tool, command, status, stdout, stderr, exit_code, duration_sec, evasion_applied, timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (engagement_id, phase, tool, command, status,
                 stdout[:50000], stderr[:10000], exit_code, duration, evasion_applied,
                 datetime.now(timezone.utc).isoformat())
            )
            self.conn.commit()

    def get_tool_runs(self, engagement_id: str) -> list:
        self._wait_for_init()
        with self._lock:
            rows = self.conn.execute(
                """SELECT phase, tool, command, status, stdout, stderr, exit_code, duration_sec, evasion_applied, timestamp
                   FROM tool_runs WHERE engagement_id=? ORDER BY timestamp""",
                (engagement_id,)
            ).fetchall()
            return [
                dict(phase=r[0], tool=r[1], command=r[2], status=r[3],
                     stdout=r[4], stderr=r[5], exit_code=r[6],
                     duration=r[7], evasion_applied=r[8], timestamp=r[9])
                for r in rows
            ]

    def add_finding(self, engagement_id: str, phase: str, finding_type: str,
                    target: str, detail: str, severity: str = "info", agent_id: str = "unknown"):
        # Schema validation/sanitization to prevent pipeline crashes
        if not detail or not str(detail).strip():
            log.warning(
                f"Dropping malformed finding: empty detail for {finding_type} on {target}")
            return
        detail = str(detail).strip()
        self._wait_for_init()
        with self._lock:
            # DB-level duplicate guard: check first 120 chars of detail to match
            # in-memory dedup logic in BaseAgent. Prevents duplicates from cross-agent
            # calls that bypass the per-agent in-memory dedup set.
            detail_key = detail[:120]
            existing = self.conn.execute(
                """SELECT id FROM findings
                   WHERE engagement_id=? AND finding_type=? AND target=?
                   AND SUBSTR(detail, 1, 120)=?""",
                (engagement_id, finding_type, target, detail_key)
            ).fetchone()
            if existing:
                log.debug(
                    f"DB dedup: skipping duplicate finding [{finding_type}] {detail_key[:50]}")
                return
            self.conn.execute(
                """INSERT OR IGNORE INTO findings
                   (engagement_id, agent_id, phase, finding_type, target, detail, severity, timestamp)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (engagement_id, agent_id, phase, finding_type, target, detail, severity,
                 datetime.now(timezone.utc).isoformat())
            )
            self.conn.commit()

    def get_all_findings(self, engagement_id: str) -> list:
        self._wait_for_init()
        with self._lock:
            rows = self.conn.execute(
                "SELECT phase, finding_type, target, detail, severity, timestamp FROM findings WHERE engagement_id=? ORDER BY timestamp",
                (engagement_id,)
            ).fetchall()

            # Sanitize findings before returning to agents to prevent
            # IndexError crashes
            valid_findings = []
            for r in rows:
                detail = r[3]
                if not detail or not isinstance(
                        detail, str) or not detail.strip():
                    continue
                valid_findings.append(
                    dict(
                        phase=r[0],
                        type=r[1],
                        target=r[2],
                        detail=detail.strip(),
                        severity=r[4],
                        timestamp=r[5]))
            return valid_findings

    def has_findings(self, engagement_id: str, phase: str) -> bool:
        """Check if a specific phase has produced any findings."""
        self._wait_for_init()
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM findings WHERE engagement_id=? AND phase=? LIMIT 1",
                (engagement_id, phase)
            ).fetchone()
            return bool(row)

    def log_message(self, engagement_id: str, from_agent: str,
                    to_agent: str, content: str):
        self._wait_for_init()
        with self._lock:
            self.conn.execute(
                "INSERT INTO messages (engagement_id, from_agent, to_agent, content, timestamp) VALUES (?,?,?,?,?)",
                (engagement_id, from_agent, to_agent, content,
                 datetime.now(timezone.utc).isoformat())
            )
            self.conn.commit()

    def set_phase_data(self, engagement_id: str, phase: str, data: dict):
        """Persist structured results from a phase with thread-safe merging and validation.
        FIX #3.5: Ensure database is initialized before accessing.
        """
        # FIX #3.5: Ensure database is initialized before accessing
        self._wait_for_init()

        # ── INPUT VALIDATION ──
        if not isinstance(data, dict):
            log.error(
                f"[VALIDATION] set_phase_data({engagement_id}, {phase}): Expected dict, got {
                    type(data).__name__}")
            raise TypeError(
                f"State data must be dict, got {
                    type(data).__name__}")

        if not engagement_id or not phase:
            log.error(
                "[VALIDATION] set_phase_data: engagement_id or phase is empty")
            raise ValueError("engagement_id and phase must not be empty")

        if not data:
            log.warning(
                f"[VALIDATION] set_phase_data({engagement_id}, {phase}): Storing empty dict")

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
                except Exception as e:
                    log.warning(
                        f"[VALIDATION] Failed to merge existing phase data: {e}, using new data only")

            # 2. Validate merged data is serializable
            try:
                serialized = json.dumps(merged_data, default=str)
            except Exception as e:
                log.error(f"[VALIDATION] Failed to serialize phase data: {e}")
                raise ValueError(f"State data is not JSON-serializable: {e}")

            # 3. Save merged data
            self.conn.execute(
                "INSERT OR REPLACE INTO phase_data (engagement_id, phase, data) VALUES (?, ?, ?)",
                (engagement_id, phase, serialized)
            )
            self.conn.commit()
            log.debug(
                f"[VALIDATION] Stored phase data: {engagement_id}:{phase} ({
                    len(serialized)} bytes)")

    def get_phase_data(self, engagement_id: str, phase: str) -> dict | None:
        """Retrieve persisted results from a specific phase with validation.
        FIX #3.5: Ensure database is initialized before accessing.
        """
        # FIX #3.5: Ensure database is initialized before accessing
        self._wait_for_init()

        if not engagement_id or not phase:
            log.error(
                "[VALIDATION] get_phase_data: engagement_id or phase is empty")
            return None

        with self._lock:
            row = self.conn.execute(
                "SELECT data FROM phase_data WHERE engagement_id=? AND phase=?",
                (engagement_id, phase)
            ).fetchone()

            if row is None:
                log.debug(
                    f"[VALIDATION] No data found for {engagement_id}:{phase}")
                return None

            try:
                data = json.loads(row[0])

                # Validate it's a dict
                if not isinstance(data, dict):
                    log.error(
                        f"[VALIDATION] Phase data corrupted for {engagement_id}:{phase}: got {
                            type(data).__name__} instead of dict")
                    return None

                # Warn if empty
                if not data:
                    log.warning(
                        f"[VALIDATION] Phase data for {engagement_id}:{phase} is empty dict")

                return data

            except json.JSONDecodeError as e:
                log.error(
                    f"[VALIDATION] Failed to parse phase data JSON for {engagement_id}:{phase}: {e}")
                return None
            except Exception as e:
                log.error(
                    f"[VALIDATION] Unexpected error reading phase data for {engagement_id}:{phase}: {e}")
                return None

    def get_phase_status(self, engagement_id: str, phase: str) -> str | None:
        """Get the status of a specific phase. Returns None if phase hasn't started."""
        self._wait_for_init()
        with self._lock:
            row = self.conn.execute(
                "SELECT status FROM phases WHERE engagement_id=? AND phase=?",
                (engagement_id, phase)
            ).fetchone()
            return row[0] if row else None

    def get_phase_summary(self, engagement_id: str) -> dict:
        self._wait_for_init()
        with self._lock:
            rows = self.conn.execute(
                "SELECT phase, status, summary FROM phases WHERE engagement_id=?",
                (engagement_id,)
            ).fetchall()
            return {r[0]: {"status": r[1], "summary": r[2]} for r in rows}

    def check_negative_outcome(
            self, engagement_id: str, target: str, tool: str) -> bool:
        """Check if a specific tool + target combination has already returned a negative result."""
        self._wait_for_init()
        with self._lock:
            # We look for findings of type 'negative_outcome' associated with this tool and target.
            # We match on the tool name being present in the detail.
            row = self.conn.execute(
                """SELECT 1 FROM findings
                   WHERE engagement_id=? AND target=?
                   AND finding_type='negative_outcome'
                   AND detail LIKE ? LIMIT 1""",
                (engagement_id, target, f"%[{tool}]%")
            ).fetchone()
            return bool(row)

    def record_failure_pattern(self, engagement_id: str, agent_id: str, tool: str = None,
                               error_type: str = None, command: str = None, stderr: str = None,
                               root_cause: str = None, severity: str = "warning",
                               avoid_next: str = None):
        """
        Persistently record a failure for future reference.
        Enables the system to learn: "When tool X fails with error_type Y, avoid doing Z next."
        """
        self._wait_for_init()
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            # Check if this exact pattern exists; if so, increment retry_count
            # and update last_seen
            existing = self.conn.execute(
                """SELECT id, retry_count FROM failure_patterns
                   WHERE engagement_id=? AND agent_id=? AND tool=? AND error_type=?
                   LIMIT 1""",
                (engagement_id, agent_id, tool, error_type)
            ).fetchone()

            if existing:
                pattern_id, retry_count = existing
                self.conn.execute(
                    """UPDATE failure_patterns
                       SET retry_count=?, last_seen=?, stderr=?, root_cause=?
                       WHERE id=?""",
                    (retry_count + 1, now, stderr[:1000] if stderr else None,
                     root_cause, pattern_id)
                )
            else:
                # Record new failure pattern
                self.conn.execute(
                    """INSERT INTO failure_patterns
                       (engagement_id, agent_id, tool, error_type, command, stderr,
                        root_cause, severity, avoid_next, first_seen, last_seen)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (engagement_id, agent_id, tool, error_type,
                     command[:500] if command else None,
                     stderr[:1000] if stderr else None,
                     root_cause, severity, avoid_next, now, now)
                )
            self.conn.commit()

    def get_failure_patterns(self, engagement_id: str,
                             agent_id: str = None) -> list:
        """
        Retrieve persistent failure patterns to inform future decisions.
        Returns list of failures with root_cause and avoid_next guidance.
        """
        self._wait_for_init()
        with self._lock:
            if agent_id:
                rows = self.conn.execute(
                    """SELECT agent_id, tool, error_type, root_cause, severity,
                              avoid_next, retry_count, last_seen
                       FROM failure_patterns
                       WHERE engagement_id=? AND agent_id=?
                       ORDER BY last_seen DESC LIMIT 50""",
                    (engagement_id, agent_id)
                ).fetchall()
            else:
                rows = self.conn.execute(
                    """SELECT agent_id, tool, error_type, root_cause, severity,
                              avoid_next, retry_count, last_seen
                       FROM failure_patterns
                       WHERE engagement_id=?
                       ORDER BY last_seen DESC LIMIT 100""",
                    (engagement_id,)
                ).fetchall()

            return [dict(agent=r[0], tool=r[1], error_type=r[2], root_cause=r[3],
                         severity=r[4], avoid_next=r[5], retry_count=r[6], last_seen=r[7])
                    for r in rows]

    def save_global_data(self, key: str, data: dict):
        """Save global configuration or state data."""
        self.set_phase_data("global", key, data)

    def get_global_data(self, key: str) -> dict | None:
        """Retrieve global configuration or state data."""
        return self.get_phase_data("global", key)

    def set(self, key: str, value: str):
        """Simple KV store for agents using global phase."""
        self.save_global_data(key, {"value": value})

    def get(self, key: str) -> str | None:
        """Simple KV retrieve for agents."""
        data = self.get_global_data(key)
        return data.get("value") if data else None

    def get_config(self, key: str) -> dict | None:
        """
        Loads configuration from the rules directory.
        Used by the orchestrator for phase-level parameters.
        """
        config_path = Path(__file__).parent.parent / "rules" / f"{key}.json"
        if not config_path.exists():
            log.warning(f"Config file not found: {config_path}")
            return None
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            log.error(f"Failed to load config {key}: {e}")
            return None

    def store_evidence_graph(self, engagement_id: str, nodes: list[dict]):
        """
        Persist a structured evidence graph produced by ReconAgent.

        Each node dict must contain: ``node_type`` (str), ``node_key`` (str),
        and optionally ``attributes`` (dict).  Examples::

            {"node_type": "open_port", "node_key": "443", "attributes": {"service": "https"}}
            {"node_type": "tech",      "node_key": "WordPress 6.4", "attributes": {"confidence": 0.9}}
            {"node_type": "waf",       "node_key": "Cloudflare",    "attributes": {"confidence": 0.8}}
        """
        self._wait_for_init()
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            for node in nodes:
                ntype = str(node.get("node_type", "unknown"))
                nkey = str(node.get("node_key", "unknown"))
                attrs = json.dumps(node.get("attributes", {}), default=str)
                self.conn.execute(
                    """INSERT OR REPLACE INTO evidence_graph
                       (engagement_id, node_type, node_key, attributes, updated_at)
                       VALUES (?,?,?,?,?)""",
                    (engagement_id, ntype, nkey, attrs, now),
                )
            self.conn.commit()

    def get_evidence_graph(self, engagement_id: str,
                           node_type: str | None = None) -> list[dict]:
        """
        Retrieve evidence graph nodes for an engagement, optionally filtered
        by ``node_type``.  Returns a list of dicts with keys:
        ``node_type``, ``node_key``, ``attributes``, ``updated_at``.
        """
        self._wait_for_init()
        with self._lock:
            if node_type:
                rows = self.conn.execute(
                    """SELECT node_type, node_key, attributes, updated_at
                       FROM evidence_graph
                       WHERE engagement_id=? AND node_type=?
                       ORDER BY updated_at""",
                    (engagement_id, node_type),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    """SELECT node_type, node_key, attributes, updated_at
                       FROM evidence_graph
                       WHERE engagement_id=?
                       ORDER BY node_type, updated_at""",
                    (engagement_id,),
                ).fetchall()
        result = []
        for r in rows:
            try:
                attrs = json.loads(r[2]) if r[2] else {}
            except Exception as e:
                log.error(
                    f"Failed to parse attributes for evidence graph node {
                        r[1]}: {e}", exc_info=True)
                attrs = {}
            result.append(dict(node_type=r[0], node_key=r[1],
                               attributes=attrs, updated_at=r[3]))
        return result

    def add_graph_node(self, engagement_id: str, key: str,
                       node_type: str, attributes: dict):
        """Add or update a node in the attack graph."""
        self._wait_for_init()
        with self._lock:
            attrs = json.dumps(attributes, default=str)
            self.conn.execute(
                """INSERT OR REPLACE INTO graph_nodes (engagement_id, key, type, attributes)
                   VALUES (?, ?, ?, ?)""",
                (engagement_id, key, node_type, attrs)
            )
            self.conn.commit()

    def add_graph_edge(self, engagement_id: str, source: str,
                       target: str, rel_type: str):
        """Add an edge between two nodes in the attack graph."""
        self._wait_for_init()
        with self._lock:
            self.conn.execute(
                """INSERT OR IGNORE INTO graph_edges (engagement_id, source, target, rel_type)
                   VALUES (?, ?, ?, ?)""",
                (engagement_id, source, target, rel_type)
            )
            self.conn.commit()

    def get_graph_node(self, engagement_id: str, key: str) -> dict | None:
        """Retrieve a specific node from the attack graph."""
        self._wait_for_init()
        with self._lock:
            row = self.conn.execute(
                "SELECT type, attributes FROM graph_nodes WHERE engagement_id=? AND key=?",
                (engagement_id, key)
            ).fetchone()
            if row:
                try:
                    attrs = json.loads(row[1]) if row[1] else {}
                except Exception as e:
                    log.error(
                        f"Failed to parse attributes for graph node {key}: {e}",
                        exc_info=True)
                    attrs = {}
                return {"key": key, "type": row[0], "attributes": attrs}
            return None

    def get_graph_neighbors(self, engagement_id: str,
                            node_key: str) -> list[tuple[str, str]]:
        """Retrieve all neighbors (and relationship types) for a given node in the attack graph."""
        self._wait_for_init()
        with self._lock:
            rows = self.conn.execute(
                """SELECT target, rel_type FROM graph_edges WHERE engagement_id=? AND source=?
                   UNION
                   SELECT source, rel_type FROM graph_edges WHERE engagement_id=? AND target=?""",
                (engagement_id, node_key, engagement_id, node_key)
            ).fetchall()
            return [(r[0], r[1]) for r in rows]

    def get_cross_engagement_failures(self, tool: str | None = None,
                                      limit: int = 100) -> list[dict]:
        """
        Retrieve persistent failure patterns *across all engagements* so that
        long-term behavioral intelligence survives process restarts.

        Optionally filter by ``tool``.  Results are ordered by most-recent
        ``last_seen`` first.
        """
        self._wait_for_init()
        with self._lock:
            if tool:
                rows = self.conn.execute(
                    """SELECT engagement_id, agent_id, tool, error_type,
                              root_cause, severity, avoid_next, retry_count, last_seen
                       FROM failure_patterns
                       WHERE tool=?
                       ORDER BY last_seen DESC LIMIT ?""",
                    (tool, limit),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    """SELECT engagement_id, agent_id, tool, error_type,
                              root_cause, severity, avoid_next, retry_count, last_seen
                       FROM failure_patterns
                       ORDER BY last_seen DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
        return [
            dict(engagement_id=r[0], agent=r[1], tool=r[2], error_type=r[3],
                 root_cause=r[4], severity=r[5], avoid_next=r[6],
                 retry_count=r[7], last_seen=r[8])
            for r in rows
        ]

    def close(self):
        with self._lock:
            if self.conn:
                self.conn.close()
                self.conn = None
