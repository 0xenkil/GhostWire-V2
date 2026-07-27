"""Guard: the self-awareness lobe is populated in every phase, and an empty
instance stays SILENT instead of injecting a misleading report (2026-06-21).

Bug: `register_finding` was called only in recon, and each agent owns its own
SelfAwarenessModule instance — so exploitation's knowledge_state was always empty,
yet `think()` injected its `get_confidence_report()` ("Known facts: 0 / Confidence:
INSUFFICIENT_DATA") into the exploitation prompt, nudging the brain to act like it
knew nothing right when recon had found the most. Fix: feed awareness from
base_agent.add_finding (every phase, severity->confidence), and return "" from
get_confidence_report when truly unpopulated so think() injects nothing.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.self_awareness_module import SelfAwarenessModule  # noqa: E402


def test_empty_instance_is_silent():
    a = SelfAwarenessModule()
    assert a.get_confidence_report() == ""


def test_populated_instance_reports():
    a = SelfAwarenessModule()
    a.register_finding({"type": "open_port", "target": "x", "detail": "80",
                        "confidence": 0.85})   # high -> known_facts
    a.register_finding({"type": "tech", "target": "x", "detail": "nginx",
                        "confidence": 0.6})    # medium -> uncertain_facts
    r = a.get_confidence_report()
    assert r and "Known facts: 1" in r and "Uncertain facts: 1" in r


def test_assumptions_alone_are_not_silent():
    a = SelfAwarenessModule()
    a.register_assumption("Try SQLi on /login", confidence=0.6)
    # an open assumption is real awareness state -> report should not be silent
    assert a.get_confidence_report() != ""
