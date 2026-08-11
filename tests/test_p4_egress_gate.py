"""Phase 4 — P4-4 evasion-trigger gate in base_agent (RC-1/RC-2/DEEP-1/DEEP-7).

Before firing TARGET WAF-evasion, the engine attributes the block:
  - real target WAF / direct-IP block → 'evade' (fire evasion),
  - our own burned Tor exit           → 'rotate' (rotate exit once, don't hammer target),
  - unknown cause                     → 'abandon' (don't waste budget).
Critically: with Tor OFF, a block attributes to the target with NO network probe,
so direct engagements behave exactly as before (the whole suite is unaffected).
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.base_agent import BaseAgent  # noqa: E402
from core.egress_probe import EgressProbe  # noqa: E402


def _res(stdout="", stderr=""):
    return types.SimpleNamespace(stdout=stdout, stderr=stderr)


def _agent(tor_verified=False, egress_probe=None, rotator=True):
    f = types.SimpleNamespace(
        log=types.SimpleNamespace(debug=lambda *a, **k: None,
                                  warning=lambda *a, **k: None,
                                  info=lambda *a, **k: None),
        _egress_probe=egress_probe,
        _egress_fingerprint=None,
    )
    if rotator:
        f._ip_rotator = types.SimpleNamespace(_tor_verified=tor_verified)
    else:
        f._ip_rotator = None
    f._extract_host = types.MethodType(BaseAgent._extract_host, f)
    f._went_through_tor = types.MethodType(BaseAgent._went_through_tor, f)
    f._egress_gate = types.MethodType(BaseAgent._egress_gate, f)
    return f


def test_direct_block_attributes_to_target_evade():
    # No Tor → a real 403 is the target blocking our real IP → evade (no network).
    a = _agent(tor_verified=False)
    assert a._egress_gate("curl", "curl https://t/", _res(stdout="HTTP/1.1 403 Forbidden")) == "evade"


def test_non_block_or_non_target_without_tor_falls_through_to_evade():
    # A non-block output, or any non-'target' attribution WITHOUT Tor, must fall
    # through to the existing logic ('evade') — the gate only diverts on a
    # positively-attributed Tor-routed self_egress/unknown, so direct engagements
    # are 100% unchanged.
    a = _agent(tor_verified=False)
    assert a._egress_gate("curl", "curl https://t/", _res(stdout="just some text")) == "evade"
    assert a._egress_gate("curl", "curl https://t/", _res(stdout="HTTP/1.1 403")) == "evade"


def test_went_through_tor_requires_verified_and_proxychains():
    a = _agent(tor_verified=True)
    assert a._went_through_tor("proxychains4 -q curl https://t/") is True
    assert a._went_through_tor("curl https://t/") is False          # not proxied
    b = _agent(tor_verified=False)
    assert b._went_through_tor("proxychains4 -q curl https://t/") is False  # tor not verified


def test_tor_burned_exit_rotates():
    # Proxied request + a burned exit (controls all blocked) → rotate once.
    burned = EgressProbe(controls=("a", "b", "c"), fetcher=lambda u: 403)
    a = _agent(tor_verified=True, egress_probe=burned)
    action = a._egress_gate("curl", "proxychains4 -q curl https://t/",
                            _res(stdout="HTTP/1.1 403 Forbidden"))
    assert action == "rotate"


def test_tor_clean_exit_evades_real_target_waf():
    # Proxied request but controls are clean → the target specifically blocked us.
    clean = EgressProbe(controls=("a", "b", "c"), fetcher=lambda u: 200)
    a = _agent(tor_verified=True, egress_probe=clean)
    action = a._egress_gate("curl", "proxychains4 -q curl https://t/",
                            _res(stdout="HTTP/1.1 403 Forbidden"))
    assert action == "evade"


def test_tor_unknown_abandons():
    # Proxied request, controls unprobeable (majority None) → unknown → abandon.
    unk = EgressProbe(controls=("a", "b", "c"), fetcher=lambda u: None)
    a = _agent(tor_verified=True, egress_probe=unk)
    action = a._egress_gate("curl", "proxychains4 -q curl https://t/",
                            _res(stdout="HTTP/1.1 403 Forbidden"))
    assert action == "abandon"
