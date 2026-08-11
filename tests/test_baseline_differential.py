"""Guard: the differential proof gate diffs against the baseline BODY, not its size (2026-06-21).

Purpose-vs-reality bug: `HypothesisEngine.validate_result` treats `baseline` as a
RESPONSE BODY — it goes into the AI prompt as "normal response" and into
`_response_similarity(stdout, baseline)`, whose value must be < 0.97 for a
differential to count as proof. But the caller passed `waf_baseline_size` (a
number like "4521"), so similarity was ~0 for every real response and the
"identical to baseline" rejection could NEVER fire — every claimed differential
auto-confirmed (a false-positive engine). Fix: recon persists the homepage body
as `waf_baseline_body`; exploitation feeds that to the gate. Empty body degrades
to the documented no-baseline path (sentinel -1.0 → trust the described delta).

LIMITATION (documented, not a bug): the body is a GLOBAL (homepage) baseline, not
per-endpoint. It is strongest exactly where false positives cluster — SPA/catch-all
targets that serve index.html for every route, and WAF block-pages returned as the
response: an attack "differential" that is really just the homepage now correctly
fails the gate. A per-endpoint clean baseline would be the ideal refinement (an
extra request per hypothesis) but is left out to keep the proof core stable.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_similarity_separates_identical_from_different():
    from intelligence.hypothesis_engine import HypothesisEngine
    he = HypothesisEngine.__new__(HypothesisEngine)
    base = "Welcome to ACME shop. Home page content. " * 40
    assert he._response_similarity(base, base) >= 0.97
    diff = "you have an error in your SQL syntax near LINE 1 " * 5
    assert he._response_similarity(diff, base) < 0.97


def test_differential_gate_rejects_identical_to_baseline():
    from core.result_contracts import Evidence
    # A "differential" whose response is ~identical to normal proves nothing.
    e = Evidence(proof_type="differential", differential="claims a delta",
                 similarity_to_baseline=1.0)
    assert e.is_proven() is False
    # A real delta passes.
    e2 = Evidence(proof_type="differential", differential="SQL error vs normal",
                  similarity_to_baseline=0.16)
    assert e2.is_proven() is True


def test_artifact_and_oob_require_measurement():
    from core.result_contracts import Evidence
    # P0-1: self-proving artifact/OOB confirm even when the response equals the
    # baseline — but ONLY when the measurement is present (control-absent +
    # test-present for artifacts, a real observed token for OOB). proof_type
    # alone is not enough — that was the forgery hole.
    assert Evidence(proof_type="artifact", similarity_to_baseline=1.0,
                    control_absent=True, test_present=True).is_proven() is True
    assert Evidence(proof_type="artifact").is_proven() is False
    assert Evidence(proof_type="oob", similarity_to_baseline=1.0,
                    oob_token="uniq.oob.example").is_proven() is True
    assert Evidence(proof_type="oob").is_proven() is False


def test_unmeasured_differential_is_a_lead_not_proof():
    from core.result_contracts import Evidence
    # P0-1 (deliberate contract change): when recon captured no baseline body,
    # similarity is the -1.0 sentinel and the differential is UNMEASURED. The old
    # behaviour trusted the AI-described delta ("proven") — a forgery hole — so an
    # unmeasured differential is now a LEAD, not proof. Proof requires a real
    # 0.0 <= similarity < 0.97 measurement.
    e = Evidence(proof_type="differential", differential="described delta",
                 similarity_to_baseline=-1.0)
    assert e.is_proven() is False
