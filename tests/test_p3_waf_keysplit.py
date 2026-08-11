"""Phase 3 — P3-3 WafLearner key unification + proven-gated record_outcome.

WAFLEARN-KEYSPLIT: the live loop debited the block path with `str(tactic)` — the
stringified DICT `"{'name': 'header_mutation'}"` — while crediting the success
path with the hardcoded literal `"header_mutation"`. The two keys never matched,
so every tactic's per-WAF success_rate was computed over a split, meaningless
denominator. P3-3 routes both sides through ONE `record_outcome` that normalizes
the tactic name, and gates the credit on a real proof / clean-execution signal.

(The batch-path revival — WAFLEARN-BATCH-DEAD — is deferred: it needs the
execute path to persist `evasion_applied` per tool_run row first, which the
schema is ready for but `_log_result` does not yet populate.)
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.waf_learner import WafLearner  # noqa: E402
from intelligence.learning_signal import LearningOutcome  # noqa: E402


def _learner(tmp_path):
    return WafLearner(database_file=str(tmp_path / "waf_db.json"))


def _tactics(learner):
    return learner._load_database().get("tactics", {})


# ── the normalizer ────────────────────────────────────────────────────────────

def test_normalize_dict_and_string_collapse_to_one_key():
    n = WafLearner._normalize_tactic
    assert n({"name": "header_mutation"}) == "header_mutation"
    assert n("header_mutation") == "header_mutation"
    assert n("Header Mutation") == "header_mutation"
    assert n({"tactic": "IP Rotation"}) == "ip_rotation"


def test_normalize_empty_is_unknown_sentinel():
    n = WafLearner._normalize_tactic
    assert n("") == "unknown"
    assert n(None) == "unknown"
    assert n({}) == "unknown"


# ── the KEYSPLIT itself ───────────────────────────────────────────────────────

def test_dict_debit_and_string_credit_land_on_one_entry(tmp_path):
    """The exact production bug: block side passes a dict, success side a string.
    Post-fix they MUST accumulate under a single 'header_mutation' key."""
    learner = _learner(tmp_path)
    # Success side (string), then block side (dict) — as the live sites now call it.
    learner.record_outcome(True, "header_mutation", waf_id="cloudflare")
    learner.record_outcome(False, {"name": "header_mutation"}, waf_id="cloudflare")

    tactics = _tactics(learner)
    assert list(tactics.keys()) == ["header_mutation"]  # ONE key, not two
    per_waf = tactics["header_mutation"]["per_waf"]["cloudflare"]
    assert per_waf["successes"] == 1
    assert per_waf["failures"] == 1
    assert per_waf["total_runs"] == 2
    assert abs(per_waf["success_rate"] - 0.5) < 1e-9


def test_direct_update_also_normalizes(tmp_path):
    """A caller that bypasses record_outcome and hits update_tactic_effectiveness
    with a raw dict still normalizes onto the same key."""
    learner = _learner(tmp_path)
    learner.update_tactic_effectiveness({"name": "header_mutation"}, True, waf_id="akamai")
    learner.update_tactic_effectiveness("header_mutation", True, waf_id="akamai")
    tactics = _tactics(learner)
    assert list(tactics.keys()) == ["header_mutation"]
    assert tactics["header_mutation"]["per_waf"]["akamai"]["total_runs"] == 2


# ── proven-gating via LearningOutcome ─────────────────────────────────────────

def test_learning_outcome_proven_credits_blocked_debits(tmp_path):
    learner = _learner(tmp_path)
    got_past = LearningOutcome(
        tool="curl", _raw_status="success", _produced_result=True, waf_blocked=False)
    still_blocked = LearningOutcome(
        tool="curl", _raw_status="blocked", _produced_result=False, waf_blocked=True)
    assert got_past.proven is True and still_blocked.proven is False

    learner.record_outcome(got_past, "header_mutation", waf_id="cloudflare")
    learner.record_outcome(still_blocked, {"name": "header_mutation"}, waf_id="cloudflare")

    per_waf = _tactics(learner)["header_mutation"]["per_waf"]["cloudflare"]
    assert per_waf["successes"] == 1 and per_waf["failures"] == 1


def test_clean_run_that_produced_nothing_is_not_a_win(tmp_path):
    """A tactic whose run 'succeeded' but produced no result must NOT be credited
    as beating the WAF (P0-9 honesty carried into WAF learning)."""
    learner = _learner(tmp_path)
    empty = LearningOutcome(
        tool="curl", _raw_status="success", _produced_result=False, waf_blocked=False)
    assert empty.proven is False
    learner.record_outcome(empty, "header_mutation", waf_id="generic")
    per_waf = _tactics(learner)["header_mutation"]["per_waf"]["generic"]
    assert per_waf["successes"] == 0 and per_waf["failures"] == 1


def test_tactic_taken_from_outcome_when_not_passed(tmp_path):
    learner = _learner(tmp_path)
    o = LearningOutcome(
        tool="curl", evasion_tactic="ip_rotation",
        _raw_status="success", _produced_result=True)
    learner.record_outcome(o, waf_id="generic")  # tactic omitted → uses outcome
    assert "ip_rotation" in _tactics(learner)


def test_unknown_tactic_is_noop(tmp_path):
    learner = _learner(tmp_path)
    assert learner.record_outcome(True, "", waf_id="generic") is False
    assert learner.record_outcome(True, None, waf_id="generic") is False
    assert _tactics(learner) == {}
