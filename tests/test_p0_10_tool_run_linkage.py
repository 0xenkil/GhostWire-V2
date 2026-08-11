"""P0-10 — tool-run → finding linkage.

The originating ``tool_runs.id`` is persisted on each finding row and both
accessors expose it, so Phase-3 learning can join a finding to the EXACT run
that produced it (not a target-fuzzy guess). Findings with no single
originating run keep a NULL link.

NOTE: ``StateStore(":memory:")`` opens ``file::memory:?cache=shared`` — a single
shared in-memory DB for the whole process — so every test here uses a UNIQUE
engagement id to stay isolated (all accessors are engagement-scoped, mirroring
production isolation).
"""

import sqlite3
import pytest

from core.state_store import StateStore


@pytest.fixture
def store():
    s = StateStore(":memory:")
    yield s
    s.close()


def test_log_tool_run_returns_rowid(store):
    rid = store.log_tool_run("e_rowid", "recon", "nmap", "nmap -p- t",
                             "success", "80/tcp open", "", 0, 1.2)
    assert isinstance(rid, int) and rid > 0


def test_get_tool_runs_exposes_id(store):
    rid = store.log_tool_run("e_gtr", "recon", "nmap", "nmap t", "success", "x", "", 0, 1.0)
    runs = store.get_tool_runs("e_gtr")
    assert len(runs) == 1 and runs[0]["id"] == rid


def test_finding_persists_and_exposes_link(store):
    eng = "e_link"
    rid = store.log_tool_run(eng, "recon", "nmap", "nmap t", "success", "80 open", "", 0, 1.0)
    store.add_finding(eng, "recon", "open_port", "t", "80/tcp open", "medium", tool_run_id=rid)
    store.add_finding(eng, "recon", "note", "t", "ai-reasoned note", "info")  # no run
    by_type = {f["type"]: f for f in store.get_all_findings(eng)}
    assert by_type["open_port"]["tool_run_id"] == rid
    assert by_type["note"]["tool_run_id"] is None


def test_exact_join_finding_to_run(store):
    eng = "e_join"
    rid = store.log_tool_run(eng, "recon", "nikto", "nikto -h t", "success", "hit", "", 0, 2.0)
    store.add_finding(eng, "recon", "misconfig", "t", "server banner leak", "low", tool_run_id=rid)
    finding = store.get_all_findings(eng)[0]
    run = {r["id"]: r for r in store.get_tool_runs(eng)}[finding["tool_run_id"]]
    assert run["tool"] == "nikto" and run["command"] == "nikto -h t"


def test_legacy_db_is_migrated(tmp_path):
    p = tmp_path / "legacy.db"
    c = sqlite3.connect(str(p))
    c.execute(
        "CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "engagement_id TEXT NOT NULL, agent_id TEXT, phase TEXT NOT NULL, "
        "finding_type TEXT, target TEXT, detail TEXT, severity TEXT DEFAULT 'info', "
        "timestamp TEXT, UNIQUE(engagement_id, finding_type, target, detail))")
    c.execute("INSERT INTO findings(engagement_id,phase,finding_type,target,detail,severity,timestamp) "
              "VALUES('e','recon','open_port','t','80 open','medium','2026-01-01')")
    c.commit()
    c.close()

    s = StateStore(str(p))
    try:
        cols = {r[1] for r in s.conn.execute("PRAGMA table_info(findings)").fetchall()}
        assert "tool_run_id" in cols
        # legacy row survives with a NULL link
        assert s.get_all_findings("e")[0]["tool_run_id"] is None
        # and new linked writes work on the migrated table
        rid = s.log_tool_run("e", "recon", "nmap", "nmap t", "success", "x", "", 0, 1.0)
        s.add_finding("e", "recon", "svc", "t", "ssh", "low", tool_run_id=rid)
        got = {f["type"]: f["tool_run_id"] for f in s.get_all_findings("e")}
        assert got["svc"] == rid
    finally:
        s.close()
