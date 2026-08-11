"""Phase 5 — P5-5 WafTechnique Protocol + Evidence-or-lead gate (D-FUT-2).

A WAF-bypass technique returns Evidence|None; it becomes a CONFIRMED bypass only
when confirmed_bypass() sees an Evidence that re-measures is_proven() True. A
None (nothing measured) or an unproven Evidence (a lead) never confirms — the
demote-to-lead rule that closes SMUGGLER-FALSEPOS / ORIGIN-STUBS. The orchestrator
confirmation gate now routes its verdict through this same is_proven check.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.result_contracts import Evidence  # noqa: E402
from intelligence.waf_bypass.technique import WafTechnique, confirmed_bypass  # noqa: E402


def _proven_evidence():
    # A status-differential-style proof: low similarity + a differential note.
    return Evidence(proof_type="differential", differential="control blocked, test allowed",
                    similarity_to_baseline=0.0, reproducible_command="curl ...")


def _unproven_evidence():
    return Evidence(proof_type="differential", differential="same both sides",
                    similarity_to_baseline=0.99)


def test_confirmed_bypass_requires_proven_evidence():
    assert confirmed_bypass(_proven_evidence()) is True
    assert confirmed_bypass(_unproven_evidence()) is False
    assert confirmed_bypass(None) is False


class _GoodTechnique:
    name = "origin_direct"

    def run(self, target, ctx):
        return _proven_evidence()


class _LeadOnlyTechnique:
    name = "smuggler_heuristic"

    def run(self, target, ctx):
        return None  # a heuristic hit is a LEAD, not a confirmation


class _NotATechnique:
    name = "missing_run"  # no run() → does not satisfy the contract


def test_protocol_conformance_is_structural():
    assert isinstance(_GoodTechnique(), WafTechnique)
    assert isinstance(_LeadOnlyTechnique(), WafTechnique)
    assert not isinstance(_NotATechnique(), WafTechnique)


def test_lead_only_technique_does_not_confirm():
    t = _LeadOnlyTechnique()
    assert confirmed_bypass(t.run("t", {})) is False


def test_good_technique_confirms():
    t = _GoodTechnique()
    assert confirmed_bypass(t.run("t", {})) is True


def test_orchestrator_validation_still_keys_on_status_differential(monkeypatch):
    # The confirmation gate now builds an Evidence and gates on is_proven, but the
    # observable (verified, note) contract is unchanged: control BLOCKED + test
    # ALLOWED => confirmed; both allowed => no differential.
    from intelligence.waf_bypass_orchestrator import WafBypassOrchestrator
    import requests

    o = WafBypassOrchestrator()

    class _R:
        def __init__(self, code):
            self.status_code = code
            self.text = "identical-body"  # bodies match; only status differs

    seq = [_R(403), _R(200)]  # control blocked, test allowed
    monkeypatch.setattr(requests, "get", lambda url, **kw: seq.pop(0))
    verified, note = o._validate_bypass_differential("example.com", "https://1.2.3.4/")
    assert verified is True and "differential confirmed" in note

    seq2 = [_R(200), _R(200)]  # neither blocked
    monkeypatch.setattr(requests, "get", lambda url, **kw: seq2.pop(0))
    verified2, note2 = o._validate_bypass_differential("example.com", "https://1.2.3.4/")
    assert verified2 is False and "no differential" in note2
