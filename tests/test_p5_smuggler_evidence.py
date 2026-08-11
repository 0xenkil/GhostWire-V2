"""Phase 5 — P5-5 arsenal conformance: request_smuggler Evidence-or-lead (SMUGGLER-FALSEPOS).

The old detector asserted `bypassed_waf = "403" not in response`, so ANY live host
that returned a non-403 response fabricated a CL.TE/TE.CL/TE.TE "vulnerability".
Now:
  - a benign (non-hung) response yields NO vector (the false positive is dead),
  - a candidate desync is a socket HANG (front/back-end length disagreement),
  - a CONFIRMED bypass requires run()'s control-vs-test timing differential to
    re-measure is_proven() — otherwise it is a lead.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.waf_bypass.request_smuggler import RequestSmuggler  # noqa: E402
from intelligence.waf_bypass.technique import WafTechnique, confirmed_bypass  # noqa: E402


def _smuggler_with(exec_returns):
    """A RequestSmuggler whose network call is replaced by a scripted result (or a
    list of results consumed in order)."""
    s = RequestSmuggler()
    if isinstance(exec_returns, list):
        seq = list(exec_returns)
        s.execute_smuggling_attack = lambda t, p: seq.pop(0)
    else:
        s.execute_smuggling_attack = lambda t, p: dict(exec_returns)
    return s


def test_conforms_to_waf_technique_protocol():
    assert isinstance(RequestSmuggler(), WafTechnique)
    assert RequestSmuggler().name == "request_smuggler"


def test_benign_response_no_longer_fabricates_a_vector():
    # A normal 200 (no hang) must NOT be reported as smuggling-vulnerable.
    s = _smuggler_with({"success": True, "hung": False,
                        "response": "HTTP/1.1 200 OK\r\n\r\nhello", "elapsed": 0.1})
    vuln = s.detect_smuggling_vulnerability("example.com")
    assert vuln["vulnerable_to"] == []
    assert vuln["confidence"] == 0.0


def test_hang_is_a_candidate_desync_lead():
    # A socket hang (capped read) is the real single-request desync signal.
    s = _smuggler_with({"success": True, "hung": True, "response": "", "elapsed": 10.0})
    vuln = s.detect_smuggling_vulnerability("example.com")
    assert "CL.TE" in vuln["vulnerable_to"]


def test_run_confirms_only_on_convincing_timing_differential():
    # control fast, test materially slower (>=2s and >=2x) → proven desync.
    s = _smuggler_with([{"elapsed": 0.1, "hung": False},   # control baseline
                        {"elapsed": 5.0, "hung": True}])    # smuggling payload hangs
    ev = s.run("example.com")
    assert ev is not None
    assert confirmed_bypass(ev) is True


def test_run_returns_lead_when_no_timing_differential():
    # Both fast → no convincing delay → Evidence exists but is NOT proven (a lead).
    s = _smuggler_with([{"elapsed": 0.10, "hung": False},
                        {"elapsed": 0.15, "hung": False}])
    ev = s.run("example.com")
    assert ev is not None
    assert confirmed_bypass(ev) is False


def test_run_returns_none_when_timings_unmeasurable():
    s = _smuggler_with([{"elapsed": -1.0}, {"elapsed": -1.0}])
    assert s.run("example.com") is None
