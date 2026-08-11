"""Phase 3 — P3-3 (BATCH-DEAD enabler): persist the applied WAF-evasion tactic
per tool_run.

The batch WAF learner was dead because it read tactic data from a phase_data key
that was never populated. The durable fix threads the applied tactic:
    base_agent evasion loop  →  tools.run(evasion_applied=...)
    →  ToolManager._log_result  →  state_store.log_tool_run(evasion_applied=...)
    →  get_tool_runs() returns it.
These tests pin that persistence chain end-to-end at the store + _log_result
seams (running real tools is out of scope). The batch CONSUMPTION in reporting
is deliberately still deferred — reviving it would double-count against the live
per-block path, which is the cumulative cross-engagement authority.
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.result_contracts import ToolResult, ResultStatus  # noqa: E402
from core.state_store import StateStore  # noqa: E402
from tools.tool_manager import ToolManager  # noqa: E402


def test_toolresult_has_evasion_field_default_none():
    r = ToolResult(tool="curl", command="curl x", stdout="", stderr="",
                   exit_code=0, duration_seconds=0.0, status=ResultStatus.SUCCESS)
    assert r.evasion_applied is None


def test_state_store_round_trips_evasion_applied():
    store = StateStore(":memory:")
    eng = "e_evasion_rt"  # unique id — shared :memory: DB across instances (P0-10 lesson)
    rid = store.log_tool_run(
        engagement_id=eng, phase="exploitation", tool="nuclei",
        command="proxychains4 -q nuclei -u http://t", status="success",
        stdout="found", stderr="", exit_code=0, duration=1.0,
        evasion_applied="header_mutation")
    assert rid is not None
    runs = store.get_tool_runs(eng)
    assert len(runs) == 1
    assert runs[0]["evasion_applied"] == "header_mutation"
    # A run with no evasion stays NULL (the common case) — not "" or a fabricated tactic.
    store.log_tool_run(
        engagement_id=eng, phase="recon", tool="curl", command="curl http://t",
        status="success", stdout="ok", stderr="", exit_code=0, duration=0.1)
    runs = store.get_tool_runs(eng)
    assert runs[1]["evasion_applied"] is None


class _CapturingStore:
    def __init__(self):
        self.kwargs = None

    def log_tool_run(self, **kwargs):
        self.kwargs = kwargs
        return 42


def _log_result_self(pending):
    """A minimal `self` carrying only what ToolManager._log_result touches."""
    return types.SimpleNamespace(
        store=_CapturingStore(),
        session=types.SimpleNamespace(engagement_id="e"),
        _pending_evasion=pending,
    )


def test_log_result_threads_pending_evasion_onto_run_and_result():
    f = _log_result_self("ip_rotation")
    r = ToolResult(tool="nmap", command="nmap t", stdout="", stderr="",
                   exit_code=0, duration_seconds=0.0, status=ResultStatus.SUCCESS)
    ToolManager._log_result(f, r, "recon")
    # Stamped on the result AND forwarded to the durable write.
    assert r.evasion_applied == "ip_rotation"
    assert f.store.kwargs["evasion_applied"] == "ip_rotation"
    assert r.tool_run_id == 42  # P0-10 link still captured


def test_log_result_no_evasion_persists_none():
    f = _log_result_self(None)
    r = ToolResult(tool="curl", command="curl t", stdout="ok", stderr="",
                   exit_code=0, duration_seconds=0.0, status=ResultStatus.SUCCESS)
    ToolManager._log_result(f, r, "recon")
    assert r.evasion_applied is None
    assert f.store.kwargs["evasion_applied"] is None


def test_log_result_does_not_overwrite_preexisting_evasion():
    # If the result already carries a tactic, the pending value must not clobber it.
    f = _log_result_self("ip_rotation")
    r = ToolResult(tool="nmap", command="nmap t", stdout="", stderr="",
                   exit_code=0, duration_seconds=0.0, status=ResultStatus.SUCCESS,
                   evasion_applied="header_mutation")
    ToolManager._log_result(f, r, "recon")
    assert r.evasion_applied == "header_mutation"
    assert f.store.kwargs["evasion_applied"] == "header_mutation"
