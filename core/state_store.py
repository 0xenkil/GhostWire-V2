import sqlite3
import json
import threading
import queue
import time
from datetime import datetime, timezone
from pathlib import Path
from config_thresholds import DB_CONNECTION_TIMEOUT as DB_TIMEOUT
from utils.logger import get_logger

log = get_logger("state_store")

# ── STATE-1 (P0-0a): durable, *acknowledged* write guarantees ───────────────
# ProofLedger.stamp() and every learning write route through the single-writer
# queue below. A silent drop here would demote a genuinely-proven finding (a
# safe direction) but — worse — a *false* acknowledgement would let a caller
# believe a row failed to land while it lands later, corrupting the trust
# guarantee the whole Evidence spine depends on. These constants + the typed
# error make the ack path the durability boundary: a write either commits and
# _submit_write returns True, or it raises StateWriteError. It NEVER returns
# success on an uncommitted write.
#
# The ack wait must outlive a worst-case SQLite busy-timeout so a slow-but-
# succeeding write is not falsely reported as failed; a genuinely wedged/dead
# writer is caught immediately by the liveness guard instead.
WRITE_ACK_TIMEOUT = max(45.0, DB_TIMEOUT + 15.0)   # ≥ busy-timeout + margin
WRITE_MAX_RETRIES = 3                               # bounded retry on transient locks
WRITE_RETRY_BACKOFF = 0.2                           # seconds, linear per attempt


class StateWriteError(RuntimeError):
    """Raised when a state-store write could not be durably acknowledged.

    Subclasses RuntimeError so existing ``except RuntimeError`` callers still
    catch what used to be a bare RuntimeError timeout."""


class StateStore:
    def __init__(self, db_path):
        if str(db_path) != ":memory:":
            db_path = Path(db_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self.db_path = str(db_path)
            self.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=DB_TIMEOUT,
                isolation_level=None)
        else:
            self.db_path = "file::memory:?cache=shared"
            self.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=DB_TIMEOUT,
                uri=True,
                isolation_level=None)

        self.conn.execute("PRAGMA journal_mode=WAL")

        # P5-12 (CONCURRENCY-1): the SINGLE read connection `self.conn` is used by
        # many agent threads. sqlite3 connections are not safe for truly-concurrent
        # use (check_same_thread=False only disables the CHECK), so all direct reads
        # serialize through this lock. Writes already serialize via the queue.
        import threading as _threading
        self._read_lock = _threading.RLock()

        # Setup background writer thread
        self.write_queue = queue.Queue()
        self.writer_thread = threading.Thread(
            target=self._writer_loop, daemon=True)
        self.writer_thread.start()

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
            logging.getLogger(__name__).warning(
                f"Failed to close state store: {_e}")

    def _wait_for_init(self, timeout: int = 30):
        """FIX #3.5: Wait for database initialization before proceeding."""
        if not self._initialized.wait(timeout=timeout):
            log.error(
                f"[FIX 3.5] StateStore initialization timeout after {timeout}s")
            raise RuntimeError(
                "StateStore initialization timeout - database schema not ready")

    def _writer_loop(self):
        is_uri = str(self.db_path).startswith("file:")
        write_conn = sqlite3.connect(
            str(self.db_path), check_same_thread=False, timeout=DB_TIMEOUT, uri=is_uri)
        write_conn.execute("PRAGMA journal_mode=WAL")
        while True:
            try:
                task = self.write_queue.get()
                if task is None:
                    # STATE-1: checkpoint the WAL on the writer connection (the
                    # one that actually appended the frames) before shutting it
                    # down, so a clean close leaves no committed-but-unflushed
                    # data stranded in the -wal sidecar.
                    try:
                        write_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    except Exception as _ce:
                        log.debug(f"Shutdown WAL checkpoint skipped: {_ce}")
                    write_conn.close()
                    self.write_queue.task_done()
                    break
                try:
                    self._run_write(write_conn, task)
                except Exception as e:
                    # STATE-1: record the failure FIRST, then attempt rollback
                    # defensively. If rollback itself raises, the caller must
                    # still see the original error — never a false "landed".
                    task['error'] = e
                    try:
                        write_conn.rollback()
                    except Exception as _re:
                        log.error(f"Rollback failed after write error: {_re}")
                finally:
                    task['event'].set()
                    self.write_queue.task_done()
            except Exception as e:
                log.error(f"Writer loop error: {e}")

    def _run_write(self, write_conn, task):
        """Execute one queued write, committing atomically, with a bounded
        retry on transient SQLite lock/busy errors.

        STATE-1: either the write commits (``task['error']`` stays None) or this
        raises — the writer never reports a partial/uncommitted write as done.
        Every queued statement is idempotent (INSERT OR IGNORE / OR REPLACE /
        UPSERT / CREATE IF NOT EXISTS), so re-running after a rolled-back
        transient failure cannot create a phantom or duplicate row."""
        attempt = 0
        while True:
            try:
                payload = task['payload']
                if task.get('is_script'):
                    write_conn.executescript(payload)
                elif isinstance(payload, list):
                    cur = None
                    for q, p in payload:
                        cur = write_conn.execute(q, p)
                    if cur is not None:
                        task['lastrowid'] = cur.lastrowid
                else:
                    q, p = payload
                    cur = write_conn.execute(q, p)
                    # P0-10: expose the AUTOINCREMENT rowid so an acknowledged
                    # INSERT can hand its id back to the caller (tool_run linkage).
                    task['lastrowid'] = cur.lastrowid
                write_conn.commit()
                return
            except sqlite3.OperationalError as e:
                msg = str(e).lower()
                transient = ('locked' in msg) or ('busy' in msg)
                attempt += 1
                if not transient or attempt > WRITE_MAX_RETRIES:
                    raise
                try:
                    write_conn.rollback()
                except Exception:
                    pass
                backoff = WRITE_RETRY_BACKOFF * attempt
                log.warning(
                    f"Transient write lock ({e}); retry {attempt}/{WRITE_MAX_RETRIES} "
                    f"in {backoff:.2f}s")
                time.sleep(backoff)

    def _submit_write(self, payload, is_script=False, return_id=False):
        # STATE-1: dead-writer guard — if the single writer thread is not
        # running, the row can never land; fail loudly instead of enqueuing
        # into a void and blocking the caller for the full ack timeout.
        if not (getattr(self, 'writer_thread', None) and self.writer_thread.is_alive()):
            raise StateWriteError(
                "state store writer thread is not running; write cannot be acknowledged")
        task = {
            'payload': payload,
            'is_script': is_script,
            'event': threading.Event(),
            'error': None,
            'lastrowid': None,
        }
        self.write_queue.put(task)
        if not task['event'].wait(timeout=WRITE_ACK_TIMEOUT):
            # NOT acknowledged within budget: callers must treat the row as
            # un-landed. Because every queued statement is idempotent, a late
            # replay cannot create a phantom/duplicate — the ledger's proof id
            # is content-addressed for exactly this reason.
            raise StateWriteError(
                f"state store write not acknowledged within {WRITE_ACK_TIMEOUT}s")
        if task['error']:
            raise task['error']
        # P0-10: return_id lets an acknowledged single-INSERT hand back its
        # AUTOINCREMENT rowid; the default keeps the historical `True` contract.
        return task['lastrowid'] if return_id else True

    def _init_schema(self):
        self._submit_write("""
            CREATE TABLE IF NOT EXISTS phases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                finished_at TEXT,
                summary TEXT,
                -- Without this, `INSERT OR REPLACE INTO phases` (set_phase_status)
                -- has no unique key to conflict on (id is autoincrement), so every
                -- status update INSERTS A DUPLICATE ROW instead of updating, and
                -- get_phase_status (no ORDER BY) then returns a stale row. Mirror
                -- the phase_data PRIMARY KEY(engagement_id, phase).
                UNIQUE(engagement_id, phase)
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
                -- P0-10: the tool_runs.id whose output produced this finding, so
                -- Phase-3 learning can join a finding to its exact originating run
                -- (not a target-fuzzy guess). NULL when the finding has no single
                -- originating tool run (e.g. an AI-reasoned or cross-run finding).
                tool_run_id INTEGER,
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
                last_seen TEXT,
                UNIQUE(engagement_id, agent_id, tool, error_type)
            );
            CREATE TABLE IF NOT EXISTS evidence_graph (
                engagement_id TEXT NOT NULL,
                node_type TEXT NOT NULL,
                node_key TEXT NOT NULL,
                attributes TEXT,
                updated_at TEXT,
                PRIMARY KEY(engagement_id, node_type, node_key)
            );
            -- P5-8 (D-WIRE-1): graph_nodes/graph_edges tables removed. They backed
            -- the write-only AttackGraph (populated per finding, never read in
            -- production) which is deleted. The live evidence_graph table above is
            -- a SEPARATE, consumed system and stays.
            CREATE TABLE IF NOT EXISTS learning (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                success INTEGER DEFAULT 0,
                failure INTEGER DEFAULT 0,
                tactics TEXT,
                last_updated TEXT
            );
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                target TEXT,
                service TEXT,
                username TEXT,
                password TEXT,
                auth_type TEXT,
                source_tool TEXT,
                timestamp TEXT,
                UNIQUE(engagement_id, target, service, username, password)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_failure_patterns_unique ON failure_patterns(engagement_id, agent_id, tool, error_type);
            CREATE TABLE IF NOT EXISTS proof_ledger (
                engagement_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                proof_type TEXT,
                evidence_json TEXT NOT NULL,
                vuln_class TEXT,
                title TEXT,
                severity TEXT,
                created_at TEXT,
                PRIMARY KEY(engagement_id, evidence_id)
            );
        """, is_script=True)
        # P0-10 migration: older DBs predate the findings.tool_run_id column.
        # ADD COLUMN is a no-op-safe forward migration (nullable, no default
        # rewrite); guard on PRAGMA table_info so a re-run doesn't error.
        try:
            cols = {
                r[1] for r in self.conn.execute(
                    "PRAGMA table_info(findings)").fetchall()}
            if "tool_run_id" not in cols:
                self._submit_write(
                    ("ALTER TABLE findings ADD COLUMN tool_run_id INTEGER", ()))
        except Exception as _mig_err:
            log.warning(f"[P0-10] findings.tool_run_id migration skipped: {_mig_err}")
        self._initialized.set()

    def set_phase_status(self, engagement_id: str,
                         phase: str, status: str, summary: str = ""):
        self._wait_for_init()
        now = datetime.now(timezone.utc).isoformat()

        # FIX P0-4: Convert SELECT-then-INSERT/UPDATE to INSERT OR REPLACE to
        # prevent race conditions
        self._submit_write(
            ("""INSERT OR REPLACE INTO phases (engagement_id, phase, status, started_at, finished_at, summary)
                VALUES (?, ?, ?,
                        COALESCE((SELECT started_at FROM phases WHERE engagement_id=? AND phase=?), ?),
                        ?, ?)""",
             (engagement_id, phase, status, engagement_id, phase, now, now if status != 'pending' else None, summary))
        )

    def log_tool_run(self, engagement_id: str, phase: str, tool: str,
                     command: str, status: str, stdout: str, stderr: str,
                     exit_code: int, duration: float, evasion_applied: str = None):
        """Persist one tool run and return its AUTOINCREMENT ``id`` (P0-10), so
        the caller can stamp findings produced from this run with an EXACT
        originating-run link. Returns None only if the acknowledged write could
        not report a rowid."""
        self._wait_for_init()
        return self._submit_write(
            ("""INSERT INTO tool_runs
               (engagement_id, phase, tool, command, status, stdout, stderr, exit_code, duration_sec, evasion_applied, timestamp)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
             (engagement_id, phase, tool, command, status,
              (stdout or "")[:50000], (stderr or "")[:10000], exit_code, duration, evasion_applied,
              datetime.now(timezone.utc).isoformat())),
            return_id=True
        )

    def get_tool_runs(self, engagement_id: str) -> list:
        self._wait_for_init()
        rows = self.conn.execute(
            """SELECT id, phase, tool, command, status, stdout, stderr, exit_code, duration_sec, evasion_applied, timestamp
               FROM tool_runs WHERE engagement_id=? ORDER BY timestamp""",
            (engagement_id,)
        ).fetchall()
        return [
            dict(id=r[0], phase=r[1], tool=r[2], command=r[3], status=r[4],
                 stdout=r[5], stderr=r[6], exit_code=r[7],
                 duration=r[8], evasion_applied=r[9], timestamp=r[10])
            for r in rows
        ]

    def add_finding(self, engagement_id: str, phase: str, finding_type: str,
                    target: str, detail: str, severity: str = "info", agent_id: str = "unknown",
                    tool_run_id: int = None):
        if not detail or not str(detail).strip():
            log.warning(
                f"Dropping malformed finding: empty detail for {finding_type} on {target}")
            return
        detail = str(detail).strip()

        # Enforce severity whitelist
        severity = str(severity).strip().lower()
        if severity not in {"info", "low", "medium", "high", "critical"}:
            severity = "info"

        self._wait_for_init()
        detail_key = detail[:120]
        # P5-12: serialize the dedup read on the shared connection AND make it
        # FAIL-SAFE — a transient lock/read error must never DROP the finding
        # (the old code let the exception propagate and lost the write entirely).
        # On any read failure we skip dedup and proceed to the queued INSERT OR
        # IGNORE, so correctness = the write is never silently lost.
        existing = None
        try:
            with self._read_lock:
                existing = self.conn.execute(
                    """SELECT id FROM findings
                       WHERE engagement_id=? AND finding_type=? AND target=?
                       AND SUBSTR(detail, 1, 120)=?""",
                    (engagement_id, finding_type, target, detail_key)
                ).fetchone()
        except Exception as _dedup_err:
            log.debug(
                f"finding dedup read failed (proceeding to write, not dropping): {_dedup_err}")
        if existing:
            log.debug(
                f"DB dedup: skipping duplicate finding [{finding_type}] {detail_key[:50]}")
            return
        # P0-10: tool_run_id links this finding to the exact tool run that
        # produced it (NULL when there is no single originating run).
        self._submit_write(
            ("""INSERT OR IGNORE INTO findings
               (engagement_id, agent_id, phase, finding_type, target, detail, severity, timestamp, tool_run_id)
               VALUES (?,?,?,?,?,?,?,?,?)""",
             (engagement_id, agent_id, phase, finding_type, target, detail, severity,
              datetime.now(timezone.utc).isoformat(), tool_run_id))
        )

    def stamp_proof(self, engagement_id: str, evidence_id: str, proof_type: str,
                    evidence_json: str, vuln_class: str = "", title: str = "",
                    severity: str = ""):
        """P0-2: persist one ProofLedger row. INSERT OR IGNORE on
        (engagement_id, evidence_id) makes it idempotent — the id is
        content-addressed, so a re-stamp or a STATE-1 late-write replay of the
        SAME measured evidence is a no-op, never a duplicate. Routed through the
        single-writer queue (no KV read-modify-write lost updates)."""
        self._wait_for_init()
        self._submit_write(
            ("""INSERT OR IGNORE INTO proof_ledger
                (engagement_id, evidence_id, proof_type, evidence_json, vuln_class, title, severity, created_at)
                VALUES (?,?,?,?,?,?,?,?)""",
             (engagement_id, evidence_id, proof_type, evidence_json,
              vuln_class, title, severity,
              datetime.now(timezone.utc).isoformat()))
        )

    def get_proof(self, engagement_id: str, evidence_id: str) -> dict | None:
        """P0-2: resolve a persisted Evidence dict by its content-addressed id."""
        self._wait_for_init()
        row = self.conn.execute(
            "SELECT evidence_json FROM proof_ledger WHERE engagement_id=? AND evidence_id=?",
            (engagement_id, evidence_id)
        ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except Exception as e:
            log.error(f"Failed to parse proof_ledger row {evidence_id}: {e}")
            return None

    def get_evidence_objects(self, engagement_id: str) -> list:
        """P0-2: reporting-format evidence list read ATOMICALLY from the ledger
        table (no KV read-modify-write). Mirrors the legacy
        {vuln_class,title,severity,evidence} shape reporting._export_pocs wants."""
        self._wait_for_init()
        rows = self.conn.execute(
            """SELECT vuln_class, title, severity, evidence_json
               FROM proof_ledger WHERE engagement_id=? ORDER BY created_at""",
            (engagement_id,)
        ).fetchall()
        out = []
        for r in rows:
            try:
                ev = json.loads(r[3]) if r[3] else {}
            except Exception:
                ev = {}
            out.append({"vuln_class": r[0], "title": r[1],
                        "severity": r[2], "evidence": ev})
        return out

    def get_all_findings(self, engagement_id: str) -> list:
        self._wait_for_init()
        rows = self.conn.execute(
            "SELECT phase, finding_type, target, detail, severity, timestamp, tool_run_id FROM findings WHERE engagement_id=? ORDER BY timestamp",
            (engagement_id,)
        ).fetchall()

        valid_findings = []
        for r in rows:
            detail = r[3]
            if not detail or not isinstance(detail, str) or not detail.strip():
                continue
            valid_findings.append(
                dict(
                    phase=r[0],
                    type=r[1],
                    target=r[2],
                    detail=detail.strip(),
                    severity=r[4],
                    timestamp=r[5],
                    tool_run_id=r[6]))  # P0-10: exact originating-run link (may be None)
        return valid_findings

    def has_findings(self, engagement_id: str, phase: str) -> bool:
        self._wait_for_init()
        row = self.conn.execute(
            "SELECT 1 FROM findings WHERE engagement_id=? AND phase=? LIMIT 1",
            (engagement_id, phase)
        ).fetchone()
        return bool(row)

    def log_message(self, engagement_id: str, from_agent: str,
                    to_agent: str, content: str):
        self._wait_for_init()
        self._submit_write(
            ("INSERT INTO messages (engagement_id, from_agent, to_agent, content, timestamp) VALUES (?,?,?,?,?)",
             (engagement_id, from_agent, to_agent, content, datetime.now(timezone.utc).isoformat()))
        )

    def set_phase_data(self, engagement_id: str, phase: str, data: dict):
        self._wait_for_init()

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

        row = self.conn.execute(
            "SELECT data FROM phase_data WHERE engagement_id=? AND phase=?",
            (engagement_id, phase)
        ).fetchone()

        merged_data = data
        if row:
            try:
                existing = json.loads(row[0])
                if isinstance(existing, dict) and isinstance(data, dict):
                    merged_data = {}
                    for k in set(existing.keys()) | set(data.keys()):
                        if k in data:
                            if data[k] is None and k in existing and existing[k] is not None:
                                merged_data[k] = existing[k]
                            else:
                                merged_data[k] = data[k]
                        else:
                            merged_data[k] = existing[k]
            except Exception as e:
                log.warning(
                    f"[VALIDATION] Failed to merge existing phase data: {e}, using new data only")

        try:
            serialized = json.dumps(merged_data, default=str)
        except Exception as e:
            log.error(f"[VALIDATION] Failed to serialize phase data: {e}")
            raise ValueError(f"State data is not JSON-serializable: {e}")

        self._submit_write(
            ("INSERT OR REPLACE INTO phase_data (engagement_id, phase, data) VALUES (?, ?, ?)",
             (engagement_id, phase, serialized))
        )
        log.debug(
            f"[VALIDATION] Stored phase data: {engagement_id}:{phase} ({
                len(serialized)} bytes)")

    def get_phase_data(self, engagement_id: str, phase: str) -> dict | None:
        self._wait_for_init()

        if not engagement_id or not phase:
            log.error(
                "[VALIDATION] get_phase_data: engagement_id or phase is empty")
            return None

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

            if not isinstance(data, dict):
                log.error(
                    f"[VALIDATION] Phase data corrupted for {engagement_id}:{phase}: got {
                        type(data).__name__} instead of dict")
                return None

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
        self._wait_for_init()
        row = self.conn.execute(
            "SELECT status FROM phases WHERE engagement_id=? AND phase=?",
            (engagement_id, phase)
        ).fetchone()
        return row[0] if row else None

    def get_phase_summary(self, engagement_id: str) -> dict:
        self._wait_for_init()
        rows = self.conn.execute(
            "SELECT phase, status, summary FROM phases WHERE engagement_id=?",
            (engagement_id,)
        ).fetchall()
        return {r[0]: {"status": r[1], "summary": r[2]} for r in rows}

    def check_negative_outcome(
            self, engagement_id: str, target: str, tool: str) -> bool:
        self._wait_for_init()
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
        self._wait_for_init()
        now = datetime.now(timezone.utc).isoformat()

        # Convert to INSERT OR REPLACE or UPSERT (SQLite 3.24+) to avoid race
        # condition
        self._submit_write(
            ("""INSERT INTO failure_patterns
                (engagement_id, agent_id, tool, error_type, command, stderr, root_cause, severity, avoid_next, first_seen, last_seen, retry_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                ON CONFLICT(engagement_id, agent_id, tool, error_type) DO UPDATE SET
                retry_count = retry_count + 1,
                last_seen = excluded.last_seen,
                stderr = excluded.stderr,
                root_cause = excluded.root_cause
             """,
             (engagement_id, agent_id, tool, error_type,
              command[:500] if command else None,
              stderr[:1000] if stderr else None,
              root_cause, severity, avoid_next, now, now))
        )

    def get_failure_patterns(self, engagement_id: str,
                             agent_id: str = None) -> list:
        self._wait_for_init()
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

    def save_global_data(self, key: str, data: dict,
                         engagement_id: str = "global"):
        self.set_phase_data(engagement_id, key, data)

    def get_global_data(self, key: str,
                        engagement_id: str = "global") -> dict | None:
        return self.get_phase_data(engagement_id, key)

    def set(self, key: str, value: str):
        if ":" in key:
            engagement_id, real_key = key.split(":", 1)
            self.save_global_data(real_key, {"value": value}, engagement_id)
        else:
            self.save_global_data(key, {"value": value})

    def get(self, key: str) -> str | None:
        if ":" in key:
            engagement_id, real_key = key.split(":", 1)
            data = self.get_global_data(real_key, engagement_id)
        else:
            data = self.get_global_data(key)
        return data.get("value") if data else None

    def get_config(self, key: str) -> dict | None:
        import re
        safe_key = re.sub(r'[^A-Za-z0-9_-]', '', key)[:64]
        if not safe_key:
            return None
        config_path = Path(__file__).parent.parent / \
            "rules" / f"{safe_key}.json"
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
        self._wait_for_init()
        now = datetime.now(timezone.utc).isoformat()
        writes = []
        for node in nodes:
            ntype = str(node.get("node_type", "unknown"))
            nkey = str(node.get("node_key", "unknown"))
            attrs = json.dumps(node.get("attributes", {}), default=str)
            writes.append(
                ("INSERT OR REPLACE INTO evidence_graph (engagement_id, node_type, node_key, attributes, updated_at) VALUES (?,?,?,?,?)",
                 (engagement_id, ntype, nkey, attrs, now))
            )
        if writes:
            self._submit_write(writes)

    def get_evidence_graph(self, engagement_id: str,
                           node_type: str | None = None) -> list[dict]:
        self._wait_for_init()
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

    # P5-8 (D-WIRE-1): add_graph_node/add_graph_edge/get_graph_node/
    # get_graph_neighbors removed — they backed the write-only AttackGraph
    # (deleted). The live evidence_graph accessors (store_evidence_graph/
    # get_evidence_graph, above) are a SEPARATE, consumed system and remain.

    def get_cross_engagement_failures(
            self, tool: str | None = None, limit: int = 100) -> list[dict]:
        self._wait_for_init()
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

    def store_credential(self, engagement_id: str, target: str, service: str,
                         username: str, password: str, auth_type: str = "password",
                         source_tool: str = "unknown"):
        self._wait_for_init()
        now = datetime.now(timezone.utc).isoformat()
        self._submit_write(
            ("""INSERT OR IGNORE INTO credentials
               (engagement_id, target, service, username, password, auth_type, source_tool, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
             (engagement_id, target, service, username, password, auth_type, source_tool, now))
        )

    def get_credentials(self, engagement_id: str,
                        target: str | None = None) -> list[dict]:
        self._wait_for_init()
        if target:
            rows = self.conn.execute(
                """SELECT target, service, username, password, auth_type, source_tool, timestamp
                   FROM credentials WHERE engagement_id=? AND target=? ORDER BY timestamp DESC""",
                (engagement_id, target)
            ).fetchall()
        else:
            rows = self.conn.execute(
                """SELECT target, service, username, password, auth_type, source_tool, timestamp
                   FROM credentials WHERE engagement_id=? ORDER BY timestamp DESC""",
                (engagement_id,)
            ).fetchall()

        return [
            dict(target=r[0], service=r[1], username=r[2], password=r[3],
                 auth_type=r[4], source_tool=r[5], timestamp=r[6])
            for r in rows
        ]

    def close(self):
        if hasattr(self, 'write_queue') and self.write_queue:
            self.write_queue.put(None)
            if hasattr(self, 'writer_thread') and self.writer_thread.is_alive():
                self.writer_thread.join(timeout=2.0)

        if getattr(self, 'conn', None):
            try:
                try:
                    self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except Exception as e:
                    import logging as __logging_tmp
                    __logging_tmp.getLogger(__name__).debug(
                        f"Ignored error: {e}")
                self.conn.close()
            except Exception as _e:
                log.warning(f"Failed to close connection: {_e}")
            self.conn = None
