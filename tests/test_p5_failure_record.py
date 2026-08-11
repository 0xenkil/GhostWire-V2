"""Phase 5 — P5-4 structured FailureRecord + observe() (D-OBS-1 / NEW-5).

observe() replaces a silent `except Exception: pass` with a structured record
folded into the EXISTING failure_patterns table. Invariants:
  - the recorder is SELF-SAFE (never raises into the wrapped op),
  - observe() suppresses by default (record-and-swallow) but can re-raise,
  - distinct swallow sites map to distinct rows (location folded into error_type),
  - a per-engagement in-memory cap bounds NEW distinct signatures per run.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.failure_record import (  # noqa: E402
    FailureRecord, observe, record_failure, reset_failure_cap,
)


class _FakeStore:
    def __init__(self, raises=False):
        self.writes = []
        self._raises = raises

    def record_failure_pattern(self, **kw):
        if self._raises:
            raise RuntimeError("db down")
        self.writes.append(kw)


@pytest.fixture(autouse=True)
def _clear_cap():
    reset_failure_cap()
    yield
    reset_failure_cap()


def test_observe_records_and_suppresses():
    store = _FakeStore()
    ran_after = False
    with observe(store, "eng1", "recon", "advisor.record", tool="nmap"):
        raise ValueError("boom")
    ran_after = True  # reached only because observe suppressed the exception
    assert ran_after
    assert len(store.writes) == 1
    w = store.writes[0]
    assert w["engagement_id"] == "eng1"
    assert w["agent_id"] == "recon"
    assert w["tool"] == "nmap"
    # location folded into error_type; message captured in stderr.
    assert w["error_type"] == "advisor.record:ValueError"
    assert "boom" in w["stderr"]


def test_observe_no_exception_writes_nothing():
    store = _FakeStore()
    with observe(store, "eng1", "recon", "loc"):
        pass
    assert store.writes == []


def test_observe_can_reraise_but_still_records():
    store = _FakeStore()
    with pytest.raises(KeyError):
        with observe(store, "eng1", "recon", "loc", suppress=False):
            raise KeyError("k")
    assert len(store.writes) == 1


def test_recorder_is_self_safe_when_store_raises():
    # A store whose write raises must NOT turn into a crash in the wrapped op.
    store = _FakeStore(raises=True)
    reached_after = False
    with observe(store, "eng1", "recon", "loc"):
        raise ValueError("boom")
    reached_after = True
    assert reached_after  # self-safe: original exception suppressed, recorder swallowed its own


def test_record_failure_noop_without_store_or_engagement():
    assert record_failure(None, "eng1", FailureRecord("recon", "loc")) is False
    assert record_failure(_FakeStore(), "", FailureRecord("recon", "loc")) is False


def test_distinct_locations_are_distinct_rows():
    store = _FakeStore()
    for loc in ("a", "b", "a"):
        with observe(store, "eng1", "recon", loc):
            raise ValueError("x")
    etypes = [w["error_type"] for w in store.writes]
    # 'a' and 'b' both written; the repeat of 'a' still writes (upsert bumps retry_count).
    assert etypes == ["a:ValueError", "b:ValueError", "a:ValueError"]


def test_per_engagement_cap_blocks_new_signatures_only():
    store = _FakeStore()
    # cap=2 distinct signatures for this engagement.
    for i in range(5):
        assert record_failure(store, "engX",
                              FailureRecord("recon", f"loc{i}"), cap=2) is (i < 2)
    # A repeat of an already-recorded signature still writes (it upserts).
    assert record_failure(store, "engX", FailureRecord("recon", "loc0"), cap=2) is True
    # Different engagement has its own budget.
    assert record_failure(store, "engY", FailureRecord("recon", "loc9"), cap=2) is True
