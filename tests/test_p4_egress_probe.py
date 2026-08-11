"""Phase 4 — P4-4 egress causality classifier (RC-1/RC-2/DEEP-1/DEEP-7).

EgressProbe attributes a target WAF block by probing a diverse control set (incl.
a CDN/WAF-fronted endpoint) from the same egress:
  - controls also blocked → self_egress (our exit is burned; don't rotate at target)
  - controls clean        → target      (real target WAF; evasion warranted)
  - can't reach a majority / drift → unknown (fail-safe: no evasion)
Deterministic via an injected fetcher — no network.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.egress_probe import (  # noqa: E402
    EgressProbe, should_fire_evasion, DEFAULT_CONTROLS,
    looks_like_http_block, attribute_block,
)


def _probe(status_map, fingerprint_provider=None):
    controls = tuple(status_map.keys())
    return EgressProbe(controls=controls,
                       fetcher=lambda u: status_map[u],
                       fingerprint_provider=fingerprint_provider)


def test_controls_clean_means_target():
    p = _probe({"a": 200, "b": 200, "c": 301})
    assert p.classify("victim.com") == "target"
    assert should_fire_evasion("target") is True


def test_controls_blocked_means_self_egress():
    # Our exit is blocked across diverse endpoints → the target 403 is really us.
    p = _probe({"a": 403, "b": 429, "c": 200})
    assert p.classify("victim.com") == "self_egress"
    assert should_fire_evasion("self_egress") is False


def test_majority_unreachable_is_unknown():
    # Only one of three controls answered → cannot attribute.
    p = _probe({"a": None, "b": None, "c": 200})
    assert p.classify("victim.com") == "unknown"
    assert should_fire_evasion("unknown") is False


def test_tie_is_unknown():
    # 1 blocked, 1 clean of 2 probed → no majority → unknown (fail-safe).
    p = _probe({"a": 403, "b": 200})
    assert p.classify("victim.com") == "unknown"


def test_egress_drift_forces_unknown():
    # Fingerprint captured at block time no longer matches current egress
    # (a mid-flight Tor rotation) → cannot attribute the original block.
    p = _probe({"a": 200, "b": 200, "c": 200},
               fingerprint_provider=lambda: "exit-NODE-B")
    assert p.classify("victim.com", egress_fingerprint="exit-NODE-A") == "unknown"


def test_matching_fingerprint_allows_classification():
    p = _probe({"a": 200, "b": 200, "c": 200},
               fingerprint_provider=lambda: "exit-NODE-A")
    assert p.classify("victim.com", egress_fingerprint="exit-NODE-A") == "target"


def test_default_controls_include_a_cdn_fronted_endpoint():
    # The control set must include at least one CDN/WAF-fronted endpoint.
    assert any("cloudflare" in c for c in DEFAULT_CONTROLS)
    assert len(DEFAULT_CONTROLS) >= 3


# ── looks_like_http_block: real block vs 403-as-data ─────────────────────────

def test_status_line_403_is_a_block():
    assert looks_like_http_block("HTTP/1.1 403 Forbidden\r\nServer: cloudflare") is True
    assert looks_like_http_block("HTTP/2 429\ncontent-type: text/html") is True


def test_status_tag_block_is_a_block():
    # nuclei/httpx-style status tag.
    assert looks_like_http_block("https://t/login [403] [title]") is True


def test_challenge_body_marker_is_a_block():
    assert looks_like_http_block("<h1>Attention Required! | Cloudflare</h1>") is True


def test_403_as_scan_data_is_not_a_block():
    # subfinder/nmap listing that merely mentions 403 as DATA — must NOT trip.
    assert looks_like_http_block("admin.t.com\napi.t.com  # returned 403 last week") is False
    assert looks_like_http_block("PORT     STATE  SERVICE\n403/tcp  open   unknown") is False


def test_attribute_block_not_blocked_passes_through():
    assert attribute_block("PORT 403/tcp open", "t.com") == "not_blocked"


def test_attribute_block_direct_is_target():
    # Real block, direct egress → the target blocked our real IP.
    assert attribute_block("HTTP/1.1 403 Forbidden", "t.com",
                           went_through_tor=False) == "target"


def test_attribute_block_tor_uses_egress_probe():
    clean = EgressProbe(controls=("a", "b"), fetcher=lambda u: 200)
    assert attribute_block("HTTP/1.1 403", "t.com", went_through_tor=True,
                           egress_probe=clean) == "target"
    burned = EgressProbe(controls=("a", "b"), fetcher=lambda u: 403)
    assert attribute_block("HTTP/1.1 403", "t.com", went_through_tor=True,
                           egress_probe=burned) == "self_egress"
