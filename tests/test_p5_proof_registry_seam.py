"""Phase 5 — P5-6 proof-method registry as the vuln-class extension seam (D-FUT-1).

The P0-2 ProofRegistry is now populated with three more reference methods —
cache_deception, authz_tester, test_origin_connection — each backing an existing
arsenal detector. A registered method proves a class ONLY through the hardened
Evidence.is_proven(): a positive differential/leak re-measures True, and a
control-less or non-matching case re-measures False (no forged proof).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.proof import ProofRegistry, ProofContext  # noqa: E402


def _build(method, **ctx_kw):
    return ProofRegistry.build(method, ProofContext(**ctx_kw))


def test_all_three_methods_are_registered():
    for name in ("cache_deception", "authz_tester", "test_origin_connection"):
        assert name in ProofRegistry.methods()
        assert ProofRegistry.get(name) is not None


def test_cache_deception_positive_is_proven():
    ev = _build("cache_deception",
                canary="SECRET-CANARY-7f3a",
                test_response="<html>hello SECRET-CANARY-7f3a cached</html>",
                control_response="<html>public page, no secret</html>",
                command="curl https://t/account.css")
    assert ev is not None and ev.proof_type == "artifact"
    assert ev.is_proven() is True


def test_cache_deception_without_control_is_not_proven():
    # No control captured → 'absent' is unverifiable → must NOT forge a proof.
    ev = _build("cache_deception",
                canary="SECRET-CANARY-7f3a",
                test_response="SECRET-CANARY-7f3a",
                control_response="")
    assert ev is None


def test_cache_deception_token_in_control_is_not_proven():
    # The datum is ALSO in the control (it was public) → not a leak.
    ev = _build("cache_deception",
                canary="SECRET-CANARY-7f3a",
                test_response="SECRET-CANARY-7f3a here",
                control_response="also SECRET-CANARY-7f3a here")
    assert ev is not None
    assert ev.is_proven() is False  # control_absent is False


def test_authz_tester_high_similarity_leak_is_proven():
    body = "PRIVATE ORDER #4471 for alice, total $980, ship 22 Elm St " * 3
    ev = _build("authz_tester",
                control_response=body,
                test_response=body,  # attacker got the owner's exact object
                command="curl -H 'id: attacker' https://t/api/orders/4471")
    assert ev is not None and ev.is_proven() is True


def test_authz_tester_different_body_is_not_proven():
    ev = _build("authz_tester",
                control_response="PRIVATE ORDER #4471 for alice " * 5,
                test_response="403 Forbidden: you do not own this resource",
                command="curl https://t/api/orders/4471")
    # Low similarity → below the 0.9 gate → no Evidence built.
    assert ev is None


def test_origin_connection_same_app_is_proven():
    app = "<html><title>ACME Portal</title><body>login form ...</body></html>" * 4
    ev = _build("test_origin_connection",
                control_response=app,             # via the WAF-fronted host
                test_response=app,                # direct to the origin IP
                command="curl --resolve t:443:203.0.113.9 https://t/")
    assert ev is not None and ev.is_proven() is True


def test_origin_connection_waf_block_page_is_not_proven():
    ev = _build("test_origin_connection",
                control_response="<html><title>ACME Portal</title>...</html>" * 4,
                test_response="Access denied by security policy (request blocked)",
                command="curl --resolve t:443:203.0.113.9 https://t/")
    assert ev is None  # not the same app → not a reachable origin
