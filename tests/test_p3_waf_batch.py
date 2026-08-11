"""Phase 3 — P3-3 revived WAF-learner batch consumption (WAFLEARN-BATCH-DEAD).

The batch pass (_analyze_tactic_effectiveness) keys on each tool run's
`evasion_applied`. Fed runs that carry that key (now sourced from the tool_runs
TABLE, not the key-less phase blob), it credits the ACTUAL tactic that got
through — not a single "none" bucket.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.waf_learner import WafLearner  # noqa: E402


def _learner():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    return WafLearner(database_file=path)


def test_batch_credits_the_applied_tactic_not_none():
    learner = _learner()
    runs = [
        {"evasion_applied": "header_mutation", "success": True},
        {"evasion_applied": "header_mutation", "success": True},
        {"evasion_applied": "header_mutation", "success": False},
        {"evasion_applied": "none", "success": True},   # skip sentinel — not credited
    ]
    updates = learner._analyze_tactic_effectiveness(runs, {"id": "cloudflare"})
    by_tactic = {u["tactic"]: u for u in updates}
    assert "none" not in by_tactic                       # the skip sentinel is excluded
    assert "header_mutation" in by_tactic                # the real tactic IS credited
    hm = by_tactic["header_mutation"]
    assert hm["successes"] == 2 and hm["failures"] == 1
    assert abs(hm["success_rate"] - (2 / 3)) < 1e-6
    assert hm["waf_id"] == "cloudflare"


def test_batch_normalizes_tactic_keys():
    learner = _learner()
    # Differently-cased/formatted evasion labels normalize to one entry.
    runs = [
        {"evasion_applied": "Header_Mutation", "success": True},
        {"evasion_applied": "header_mutation", "success": True},
    ]
    updates = learner._analyze_tactic_effectiveness(runs, {"id": "w"})
    tactics = [u["tactic"] for u in updates]
    assert len(tactics) == 1  # normalized onto the same bucket


def test_empty_runs_produce_no_updates():
    learner = _learner()
    assert learner._analyze_tactic_effectiveness([], {"id": "w"}) == []
