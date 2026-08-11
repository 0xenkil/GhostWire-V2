"""P5-4 (D-OBS-1, NEW-5) — structured observability for swallowed failures.

Turns a silent ``except Exception: pass`` / ``log.debug(...)`` swallow into a
STRUCTURED, queryable record folded into the EXISTING ``failure_patterns`` table
(via ``StateStore.record_failure_pattern``) — NOT a parallel store. Anything the
engine already reads from ``get_cross_engagement_failures`` /
``get_failure_patterns`` (the plausibility gates, the tool/WAF learners) now also
sees the failures that used to vanish.

Two invariants:
  1. **Self-safe recorder** — ``record_failure`` / ``observe`` NEVER raise into
     the wrapped operation. A telemetry write must not convert a swallowed error
     into a crash. Any error inside the recorder is itself swallowed (logged if a
     logger is supplied).
  2. **Per-engagement cap** — an in-memory, process-local set of distinct failure
     signatures per engagement bounds how many NEW distinct rows one run may
     write (repeats of a known signature still upsert, incrementing retry_count).
     The table's ``UNIQUE(engagement_id, agent_id, tool, error_type)`` upsert is
     the DB-level dedup; this cap is the belt against a pathological run inventing
     unbounded distinct signatures.
"""
from __future__ import annotations

import contextlib
import threading
from dataclasses import dataclass
from typing import Optional

# Process-local per-engagement distinct-signature ledger (the cap).
_MAX_DISTINCT_PER_ENGAGEMENT = 200
_recorded_lock = threading.Lock()
_recorded: dict[str, set] = {}


def _cap_allows(engagement_id: str, signature: str,
                cap: int = _MAX_DISTINCT_PER_ENGAGEMENT) -> bool:
    """True if this signature may be written. A known signature always may (it
    upserts); a NEW one may only while the engagement is under the distinct cap."""
    with _recorded_lock:
        seen = _recorded.setdefault(engagement_id, set())
        if signature in seen:
            return True
        if len(seen) >= cap:
            return False
        seen.add(signature)
        return True


def reset_failure_cap(engagement_id: str = None) -> None:
    """Clear the in-memory distinct-signature ledger (test hook / new run)."""
    with _recorded_lock:
        if engagement_id is None:
            _recorded.clear()
        else:
            _recorded.pop(engagement_id, None)


@dataclass
class FailureRecord:
    """One swallowed failure, structured for the failure_patterns table."""
    agent_id: str
    location: str                      # WHERE it was swallowed, e.g. "base_agent.advisor_record"
    error_type: str = "error"          # exception class name
    tool: Optional[str] = None
    command: Optional[str] = None
    stderr: Optional[str] = None       # exception message / detail
    root_cause: Optional[str] = None
    severity: str = "warning"
    avoid_next: Optional[str] = None

    def signature(self) -> str:
        return f"{self.agent_id}|{self.tool}|{self.location}:{self.error_type}"


def record_failure(store, engagement_id: str, record: FailureRecord,
                   logger=None, cap: int = _MAX_DISTINCT_PER_ENGAGEMENT) -> bool:
    """Persist a FailureRecord into the existing failure_patterns table.

    Self-safe: returns False (never raises) on any problem — missing store,
    empty engagement, cap reached, or a write error. ``location`` is folded into
    ``error_type`` so distinct swallow sites do not collapse onto one row."""
    try:
        if store is None or not engagement_id:
            return False
        if not _cap_allows(engagement_id, record.signature(), cap):
            return False
        store.record_failure_pattern(
            engagement_id=engagement_id,
            agent_id=record.agent_id or "unknown",
            tool=record.tool,
            error_type=(f"{record.location}:{record.error_type}"
                        if record.location else (record.error_type or "error")),
            command=record.command,
            stderr=record.stderr,
            root_cause=record.root_cause,
            severity=record.severity,
            avoid_next=record.avoid_next,
        )
        return True
    except Exception as e:  # recorder must never raise into the wrapped op
        if logger is not None:
            try:
                logger.debug(f"[observe] failure record swallowed: {e}")
            except Exception:
                pass
        return False


@contextlib.contextmanager
def observe(store, engagement_id: str, agent_id: str, location: str, *,
            tool: str = None, command: str = None, severity: str = "warning",
            root_cause: str = None, avoid_next: str = None, logger=None,
            suppress: bool = True):
    """Context manager: record any exception raised in the block into the
    failure_patterns table, then — by default — SUPPRESS it. This is the
    structured replacement for a silent ``except Exception: pass``.

    ``suppress=False`` records-and-re-raises (use where the caller still needs
    the exception to propagate). The recorder itself never raises."""
    try:
        yield
    except Exception as e:
        rec = FailureRecord(
            agent_id=agent_id, location=location,
            error_type=type(e).__name__, tool=tool, command=command,
            stderr=str(e)[:1000], root_cause=root_cause, severity=severity,
            avoid_next=avoid_next,
        )
        record_failure(store, engagement_id, rec, logger=logger)
        if logger is not None:
            try:
                logger.debug(f"[{location}] swallowed {type(e).__name__}: {e}")
            except Exception:
                pass
        if not suppress:
            raise
