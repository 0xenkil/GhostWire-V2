"""Phase 3 — P3-4 tail: ADVISOR-WAF-ALLTRUE severed.

record_engagement_outcome used to record success:True for every WAF tactic that
was merely USED, fabricating a 100% success rate. A used tactic is now recorded
attempted-UNKNOWN (None); real outcomes come from the WafLearner batch path.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.strategic_advisor import StrategicAdvisor  # noqa: E402


def _advisor():
    return StrategicAdvisor(knowledge_dir=tempfile.mkdtemp())


def test_used_tactics_are_not_recorded_as_successful():
    adv = _advisor()
    adv.record_engagement_outcome(
        "eng1", "t.com", findings=[], tech_stack=["nginx"],
        waf_detected="cloudflare",
        waf_tactics_used=["header_mutation", "ip_rotation"])
    tactics = adv.knowledge_base["waf_bypass_tactics"].get("cloudflare", [])
    assert tactics, "tactics should be recorded (as attempted)"
    assert all(t["success"] is None for t in tactics)   # never fabricated True
    assert {t["tactic"] for t in tactics} == {"header_mutation", "ip_rotation"}


def test_no_hardcoded_true_in_source():
    import inspect
    src = inspect.getsource(StrategicAdvisor.record_engagement_outcome)
    assert '"success": True' not in src


def test_dedup_no_longer_duplicates_used_tactics():
    adv = _advisor()
    for _ in range(3):
        adv.record_engagement_outcome(
            "eng1", "t.com", findings=[], tech_stack=[],
            waf_detected="akamai", waf_tactics_used=["header_mutation"])
    tactics = adv.knowledge_base["waf_bypass_tactics"].get("akamai", [])
    assert len([t for t in tactics if t["tactic"] == "header_mutation"]) == 1
