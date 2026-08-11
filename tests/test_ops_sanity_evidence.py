"""Guard: the ops-sanity backstop must never hide a PROVEN vulnerability — where
"proven" is a re-measured ProofLedger token (P0-3), NOT a VULN_PROVEN/Proof[
substring or the finding TYPE (either of which an emitter forges). This closes
SELFAWARE-OPSSANITY-BYPASS: previously any `confirmed_vulnerability` type or
`VULN_PROVEN`/`Proof[` substring exempted a finding from the sanity backstop, so
a fabricated "root shell on target" rode through untouched.
"""
import logging
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.CRITICAL)


def _ledger():
    from core.state_store import StateStore
    from core.proof import ProofLedger
    store = StateStore(":memory:")
    return ProofLedger(store, "eng_ops"), store


def _fake(ledger=None):
    from intelligence.self_awareness_module import SelfAwarenessModule
    f = types.SimpleNamespace()
    f.awareness = SelfAwarenessModule(state_store=None)
    f.log = logging.getLogger("t")
    f._ip_rotator = None
    f._has_target_foothold_generic = lambda: False  # no prior foothold (the trap)
    f._proof_ledger = ledger
    return f


def _proven_detail(ledger, base_detail):
    """Stamp a REAL artifact proof and return the token-prefixed detail."""
    from core.proof import ProofContext
    eid = ledger.stamp("artifact_reflection", ProofContext(
        control_response="normal page",
        test_response="leaked root:x:0:0:root:/root:/bin/bash",
        canary="root:x:0:0:root", command="curl x"))
    assert eid, "expected a real proof token"
    return f"[proof:{eid}] {base_detail}"


def test_proven_vuln_with_host_terms_is_not_downgraded():
    from agents.base_agent import BaseAgent
    ledger, store = _ledger()
    try:
        f = _fake(ledger)
        detail = _proven_detail(
            ledger,
            "VULN_PROVEN [LFI] arbitrary file read | PoC: curl ... | "
            "Proof[differential]: retrieved /etc/passwd root:x:0:0 | Impact: file read")
        sev, _ = BaseAgent._ops_sanity_backstop(
            f, "confirmed_vulnerability", detail, "critical")
        assert sev == "critical"
    finally:
        store.close()


def test_proven_marker_in_detail_also_protected():
    from agents.base_agent import BaseAgent
    ledger, store = _ledger()
    try:
        f = _fake(ledger)
        detail = _proven_detail(ledger, "RCE confirmed with root uid on target")
        sev, _ = BaseAgent._ops_sanity_backstop(f, "exploit_lead", detail, "high")
        assert sev == "high"
    finally:
        store.close()


def test_unproven_host_claim_still_downgraded():
    from agents.base_agent import BaseAgent
    ledger, store = _ledger()
    try:
        f = _fake(ledger)
        sev, det = BaseAgent._ops_sanity_backstop(
            f, "exploit_lead",
            "We have root shell access and persistence on the target", "critical")
        assert sev == "info"
        assert "UNVERIFIED LEAD" in det
    finally:
        store.close()


def test_substring_alone_no_longer_exempts():
    """The forgery P0-3 closes: a VULN_PROVEN/Proof[ substring (or the
    confirmed_vulnerability type) with NO resolvable proof token must NOT exempt
    an implausible host claim from the sanity backstop."""
    from agents.base_agent import BaseAgent
    ledger, store = _ledger()
    try:
        f = _fake(ledger)
        sev, det = BaseAgent._ops_sanity_backstop(
            f, "confirmed_vulnerability",
            "VULN_PROVEN [RCE] We have root shell access and persistence on the "
            "target | Proof[oob]: trust me", "critical")
        assert sev == "info"
        assert "UNVERIFIED LEAD" in det
    finally:
        store.close()
