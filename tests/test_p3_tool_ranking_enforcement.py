"""§9.7(a): the tool_success_tracker ranking is ENFORCED into selection — the
environment snapshot turns per-target-type effectiveness into an obeyed
PREFER/AVOID directive (not just a numeric display). This pins the contract that
directive keys on: highly_effective ⇒ PREFER, ineffective/rarely ⇒ AVOID,
insufficient data ⇒ neutral (no directive).
"""
import os
import tempfile
from pathlib import Path

from intelligence.tool_success_tracker import ToolSuccessTracker


def _tracker():
    d = tempfile.mkdtemp()
    return ToolSuccessTracker(db_path=Path(os.path.join(d, "metrics.json")))


def _verdict(rec):
    # exact mapping used by base_agent._get_environment_snapshot (§9.7a)
    if rec == "highly_effective":
        return "PREFER"
    if rec in ("ineffective_skip", "rarely_effective"):
        return "AVOID"
    return ""


def test_ranking_drives_prefer_and_avoid():
    t = _tracker()
    for _ in range(4):                       # proven effective on this target type
        t.log_tool_result("nuclei", "api", True, 1.0)
    for _ in range(4):                       # proven to fail on this target type
        t.log_tool_result("gobuster", "api", False, 1.0)

    assert t.get_tool_effectiveness("nuclei", "api")["recommendation"] == "highly_effective"
    assert t.get_tool_effectiveness("gobuster", "api")["recommendation"] == "ineffective_skip"
    assert _verdict(t.get_tool_effectiveness("nuclei", "api")["recommendation"]) == "PREFER"
    assert _verdict(t.get_tool_effectiveness("gobuster", "api")["recommendation"]) == "AVOID"


def test_insufficient_data_stays_neutral():
    t = _tracker()
    t.log_tool_result("ffuf", "api", True, 1.0)          # a single run
    rec = t.get_tool_effectiveness("ffuf", "api")["recommendation"]
    assert rec == "insufficient_data" and _verdict(rec) == ""   # no directive fired


def test_ranking_is_per_target_type():
    t = _tracker()
    for _ in range(4):
        t.log_tool_result("sqlmap", "api", True, 1.0)    # effective on api...
    # ...but never run on 'static' — must not carry the verdict across types
    assert t.get_tool_effectiveness("sqlmap", "api")["recommendation"] == "highly_effective"
    assert t.get_tool_effectiveness("sqlmap", "static")["recommendation"] == "not_tested_on_this_type"
