"""Phase 5 — P5-5 arsenal conformance: oob_exfil_engine Evidence-or-lead (OOB-STUB).

Old behavior: the DNS vector hardcoded `waf_bypassed: True`, and monitor_oob_channel
always returned exfil_successful=False (a stub). Now an OOB exfil is CONFIRMED only
by a real out-of-band callback carrying the planted canary (the oob_callback proof
through is_proven); the emitted vectors are leads, not confirmations.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.waf_bypass.oob_exfil_engine import OOBExfilEngine  # noqa: E402
from intelligence.waf_bypass.technique import WafTechnique, confirmed_bypass  # noqa: E402


def test_conforms_to_waf_technique_protocol():
    assert isinstance(OOBExfilEngine(), WafTechnique)
    assert OOBExfilEngine().name == "oob_exfil"


def test_dns_vector_no_longer_hardcodes_bypassed_true():
    eng = OOBExfilEngine()
    dns = eng._create_dns_exfil_vector("t")
    assert dns["waf_bypassed"] is not True
    assert dns.get("confirmed") is False


def test_discovered_vectors_are_leads_not_confirmations():
    eng = OOBExfilEngine()
    out = eng.discover_oob_vectors("target.com")
    # vectors exist (payload leads) but none asserts a confirmed bypass.
    assert out["oob_vectors"]
    assert all(v.get("waf_bypassed") is not True for v in out["oob_vectors"])


def test_run_confirms_only_on_callback_with_canary():
    eng = OOBExfilEngine()
    canary = "exfil-canary-8b21"
    # A real callback carrying the canary → proven exfil.
    ev = eng.run("target.com", {"canary": canary,
                                "oob_events": [f"{canary}.collaborator.oob A?"]})
    assert ev is not None and confirmed_bypass(ev) is True


def test_run_none_without_callback():
    eng = OOBExfilEngine()
    assert eng.run("target.com", {"canary": "c", "oob_events": []}) is None
    # Events present but none carry the canary → not confirmed.
    assert eng.run("target.com", {"canary": "exfil-canary-8b21",
                                  "oob_events": ["unrelated.lookup.example A?"]}) is None
    assert eng.run("target.com", None) is None


def test_monitor_channel_confirms_on_canary_callback():
    eng = OOBExfilEngine()
    canary = "exfil-canary-8b21"
    res = eng.monitor_oob_channel(
        "dns", observed_events=[f"data.{canary}.collaborator.oob"], canary=canary)
    assert res["exfil_successful"] is True
    assert res["data_received"]


def test_monitor_channel_stub_call_still_false():
    # Backward compatible: the old zero-arg call still returns not-successful.
    res = OOBExfilEngine().monitor_oob_channel("dns")
    assert res["exfil_successful"] is False
