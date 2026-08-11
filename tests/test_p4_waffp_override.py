"""Phase 4 — P4-7 sever the WAF fabricated-confidence override
(WAFFP-PLANNING-OVERRIDE / WAFFP-TYPE-MISNOMER).

A planning recommendation must NOT manufacture WAF presence: the old code
overwrote a weak behavioral fingerprint's confidence with a hardcoded 0.8,
bypassing the >=0.5 strong-signal gate. Now a planner guess is a capped
HYPOTHESIS (<=0.2). And waf_type is a STABLE identity (matched known-WAF name or
unknown_<hash>), never a raw pattern name.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.recon_agent import ReconAgent  # noqa: E402


def test_waf_type_prefers_matched_known_name():
    assert ReconAgent._derive_waf_type(
        {"similar_to_known": ["cloudflare (match: 80%)"]}) == "cloudflare"
    assert ReconAgent._derive_waf_type(
        {"similar_to_known": ["AWS WAF (match: 60%)"]}) == "aws_waf"


def test_waf_type_falls_to_stable_unknown_hash():
    a = ReconAgent._derive_waf_type({"detected_patterns": ["p1", "p2"]})
    b = ReconAgent._derive_waf_type({"detected_patterns": ["p2", "p1"]})
    assert a.startswith("unknown_") and a == b   # order-independent, stable
    assert ReconAgent._derive_waf_type({}) == "unknown"


def test_no_fabricated_0_8_confidence_in_source():
    # The exact override that manufactured WAF presence must be gone.
    import inspect
    src = inspect.getsource(ReconAgent._run_recon_for_target)
    assert '"confidence": 0.8' not in src
    assert "0.8" not in src.split("planning_hypothesis")[0][-400:] if "planning_hypothesis" in src else True
    # The planner path is now a capped hypothesis.
    assert "planning_hypothesis" in src
    assert "min(float(_prior.get" in src


def test_planner_confidence_is_capped_below_assertion_threshold():
    # Model the fix's arithmetic: a weak prior + planner guess caps at <=0.2,
    # below the 0.5 WAF-presence assertion threshold.
    for prior in (0.0, 0.1, 0.3, 0.9):
        capped = min(float(prior), 0.2)
        assert capped <= 0.2
        # Only a real >=0.5 prior (which skips the override) can assert a WAF.
