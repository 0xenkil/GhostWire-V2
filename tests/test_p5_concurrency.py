"""Phase 5 — P5-12 systematic shared-cache concurrency (CONCURRENCY-1).

Audit of shared MUTABLE state touched by multiple threads and its sync strategy:
  - state_store            → single-writer queue serializes all writes (P0-0a)
  - _outcome_interp_cache  → threading.Lock (P1-5)
  - failure_record._recorded ledger → threading.Lock (P5-4)
  - ProofRegistry._methods → populated at import; read-only at runtime
  - per-agent caches (_command_history etc.) → per-instance; single set/get is
    GIL-atomic; the one read-modify-write (outcome cache) is locked above.
The regression test below stress-tests the primary shared durable store: 10
threads writing concurrently must lose ZERO rows.
"""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.state_store import StateStore  # noqa: E402
from core.failure_record import record_failure, FailureRecord, reset_failure_cap  # noqa: E402


def test_state_store_no_lost_writes_under_10_threads():
    store = StateStore(":memory:")
    eng = "p5_12_concurrency"
    N_THREADS, PER = 10, 20

    def worker(tid):
        for i in range(PER):
            store.add_finding(eng, "recon", "web_vulnerability",
                              f"host{tid}", f"finding t{tid} i{i}", "info",
                              agent_id=f"t{tid}")

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(N_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    findings = store.get_all_findings(eng)
    assert len(findings) == N_THREADS * PER, \
        f"lost writes: {len(findings)} != {N_THREADS * PER}"


def test_failure_record_ledger_is_lock_guarded_under_threads():
    # The P5-4 in-memory distinct-signature ledger must not tear under threads.
    reset_failure_cap()

    class _S:
        def __init__(self):
            self.n = 0
            self._lk = threading.Lock()

        def record_failure_pattern(self, **kw):
            with self._lk:
                self.n += 1

    store = _S()
    eng = "p5_12_frl"

    def worker(tid):
        for i in range(25):
            record_failure(store, eng, FailureRecord(f"agent{tid}", f"loc{tid}_{i}"),
                           cap=10_000)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # 10 threads * 25 distinct signatures each = 250 distinct → all written once.
    assert store.n == 250
    reset_failure_cap()
