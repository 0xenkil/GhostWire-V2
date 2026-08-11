"""Phase 5 — P5-5 arsenal conformance: origin_discovery Evidence-or-lead (ORIGIN-STUBS).

Old behavior: `test_origin_connection` set bypass_viable=True the moment ANY bytes
came back from the candidate IP — so a random server / default page / the CDN
itself "confirmed" an origin, and recon_agent then adopted that IP as the bypass
URL, ADDED IT TO SCOPE, and retargeted exploitation. Now an IP is a confirmed
origin ONLY when its direct response matches the WAF-fronted app (high-similarity
proof via is_proven); merely reachable is a lead.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.waf_bypass.origin_discovery import OriginDiscovery  # noqa: E402
from intelligence.waf_bypass.technique import WafTechnique, confirmed_bypass  # noqa: E402

_APP = "<html><head><title>ACME Portal</title></head><body>login form here ...</body></html>" * 5
_OTHER = "<html><body>default nginx welcome page, unrelated host</body></html>" * 5


def test_conforms_to_waf_technique_protocol():
    assert isinstance(OriginDiscovery(), WafTechnique)
    assert OriginDiscovery().name == "origin_discovery"


def test_same_app_body_proves_origin():
    od = OriginDiscovery()
    ev = od._origin_bypass_evidence(_APP, _APP, "203.0.113.9", "acme.com")
    assert ev is not None and confirmed_bypass(ev) is True


def test_different_body_is_not_a_confirmed_origin():
    od = OriginDiscovery()
    ev = od._origin_bypass_evidence(_APP, _OTHER, "203.0.113.9", "acme.com")
    # <0.9 similarity → the proof method builds no Evidence → not a bypass.
    assert confirmed_bypass(ev) is False


def test_bytes_back_alone_no_longer_confirms(monkeypatch):
    # Reachable IP that serves a DIFFERENT app must be reachable=True but NOT viable.
    od = OriginDiscovery()

    def fake_origin(ip, domain, port, result):
        result["reachable"] = True
        return _OTHER

    monkeypatch.setattr(od, "_fetch_origin_response", fake_origin)
    monkeypatch.setattr(od, "_fetch_fronted_response", lambda d: _APP)
    res = od.test_origin_connection("203.0.113.9", "acme.com")
    assert res["reachable"] is True
    assert res["bypass_viable"] is False


def test_matching_app_confirms_viable(monkeypatch):
    od = OriginDiscovery()
    monkeypatch.setattr(od, "_fetch_origin_response",
                        lambda ip, domain, port, result: (result.__setitem__("reachable", True) or _APP))
    monkeypatch.setattr(od, "_fetch_fronted_response", lambda d: _APP)
    res = od.test_origin_connection("203.0.113.9", "acme.com")
    assert res["bypass_viable"] is True


def test_unreachable_origin_is_not_viable(monkeypatch):
    od = OriginDiscovery()
    monkeypatch.setattr(od, "_fetch_origin_response",
                        lambda ip, domain, port, result: "")
    res = od.test_origin_connection("203.0.113.9", "acme.com")
    assert res["reachable"] is False and res["bypass_viable"] is False


def test_run_returns_proven_origin_only(monkeypatch):
    od = OriginDiscovery()
    monkeypatch.setattr(od, "_fetch_fronted_response", lambda d: _APP)
    monkeypatch.setattr(od, "discover_origin_ips",
                        lambda domain, aggressive=False: {"origin_candidates": [
                            {"ip": "198.51.100.1"}, {"ip": "203.0.113.9"}]})

    # First candidate serves a different app (lead), second matches (proven).
    bodies = {"198.51.100.1": _OTHER, "203.0.113.9": _APP}

    def fake_origin(ip, domain, port, result):
        result["reachable"] = True
        return bodies[ip]

    monkeypatch.setattr(od, "_fetch_origin_response", fake_origin)
    ev = od.run("https://acme.com/")
    assert ev is not None and confirmed_bypass(ev) is True


def test_run_none_when_no_candidate_matches(monkeypatch):
    od = OriginDiscovery()
    monkeypatch.setattr(od, "_fetch_fronted_response", lambda d: _APP)
    monkeypatch.setattr(od, "discover_origin_ips",
                        lambda domain, aggressive=False: {"origin_candidates": [{"ip": "198.51.100.1"}]})
    monkeypatch.setattr(od, "_fetch_origin_response",
                        lambda ip, domain, port, result: _OTHER)
    assert od.run("https://acme.com/") is None
