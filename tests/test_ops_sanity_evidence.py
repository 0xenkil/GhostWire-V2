"""Guard: the ops-sanity backstop must never hide a PROVEN vulnerability (2026-06-18).

`_ops_sanity_backstop` downgrades exotic high/critical findings to "info leads"
when a hardcoded heuristic deems them implausible (e.g. host-level claim with no
foothold). It ran on ALL findings — including the hypothesis engine's
`confirmed_vulnerability`, which already carries differential Proof[...]. So a
proven LFI/RCE whose proof mentions host terms (/etc/, root, shell), and which IS
the first foothold (so has_target_foothold is still False), got silently demoted
— the system hiding its own proven vuln. The fix: a hardcoded signature must never
override real evidence. These tests pin both directions.
"""
import logging
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.CRITICAL)


def _fake():
    from intelligence.self_awareness_module import SelfAwarenessModule
    f = types.SimpleNamespace()
    f.awareness = SelfAwarenessModule(state_store=None)
    f.log = logging.getLogger("t")
    f._ip_rotator = None
    f._has_target_foothold_generic = lambda: False  # no prior foothold (the trap)
    return f


def test_proven_vuln_with_host_terms_is_not_downgraded():
    from agents.base_agent import BaseAgent
    f = _fake()
    sev, _ = BaseAgent._ops_sanity_backstop(
        f, "confirmed_vulnerability",
        "VULN_PROVEN [LFI] arbitrary file read | PoC: curl ... | "
        "Proof[differential]: retrieved /etc/passwd root:x:0:0 | Impact: file read",
        "critical")
    assert sev == "critical"


def test_proven_marker_in_detail_also_protected():
    from agents.base_agent import BaseAgent
    f = _fake()
    sev, _ = BaseAgent._ops_sanity_backstop(
        f, "exploit_lead",
        "RCE confirmed | Proof[oob]: DNS callback received from target with root uid",
        "high")
    assert sev == "high"


def test_unproven_host_claim_still_downgraded():
    from agents.base_agent import BaseAgent
    f = _fake()
    sev, det = BaseAgent._ops_sanity_backstop(
        f, "exploit_lead",
        "We have root shell access and persistence on the target", "critical")
    assert sev == "info"
    assert "UNVERIFIED LEAD" in det
