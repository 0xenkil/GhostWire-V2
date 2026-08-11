"""Guard: stealth fail-closed — never run a network tool DIRECT when anonymity
was requested but Tor isn't verified (GAP-2 opsec leak fix, 2026-06-21).

If the operator asked for Tor (stealth rotate_ip) but Tor can't be verified, a
network tool used to run DIRECT and silently leak the real IP. `_stealth_leak_guard`
now blocks leak-prone tools (returns a BLOCKED ToolResult) unless they explicitly
opt into allow_direct_on_tor_fail. Local/util tools and --help probes are exempt
(no network request).
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.base_agent import BaseAgent  # noqa: E402
from core.result_contracts import ResultStatus  # noqa: E402


def _fake(stealth, tor_verified=None):
    rot = None
    if tor_verified is not None:
        rot = types.SimpleNamespace(_tor_verified=tor_verified)
    f = types.SimpleNamespace(
        _stealth=stealth,
        _ip_rotator=rot,
        # P4-5: the guard now reads these shared class constants + the widened
        # _stealth_requested() trigger; supply them on the minimal fake `self`.
        _STEALTH_LOCAL_TOOLS=BaseAgent._STEALTH_LOCAL_TOOLS,
        _STEALTH_RAW_SOCKET_TOOLS=BaseAgent._STEALTH_RAW_SOCKET_TOOLS,
        _STEALTH_ANONYMITY_KEYS=BaseAgent._STEALTH_ANONYMITY_KEYS,
        log=types.SimpleNamespace(error=lambda *a, **k: None,
                                  debug=lambda *a, **k: None),
    )
    f._stealth_requested = types.MethodType(BaseAgent._stealth_requested, f)
    # P2-1: the raw-socket check now consults the ToolCatalog tag (bind the real
    # method; it falls back to _STEALTH_RAW_SOCKET_TOOLS supplied above).
    f._is_raw_socket_tool = types.MethodType(BaseAgent._is_raw_socket_tool, f)
    return f


def test_no_anonymity_requested_allows():
    f = _fake({"rotate_ip": False})
    assert BaseAgent._stealth_leak_guard(f, "nuclei", "nuclei -u http://x") is None


def test_tor_verified_allows():
    f = _fake({"rotate_ip": True}, tor_verified=True)
    assert BaseAgent._stealth_leak_guard(f, "nuclei", "nuclei -u http://x") is None


def test_requested_but_tor_unverified_blocks_network_tool():
    f = _fake({"rotate_ip": True}, tor_verified=False)
    res = BaseAgent._stealth_leak_guard(f, "nuclei", "nuclei -u http://x")
    assert res is not None and res.status == ResultStatus.BLOCKED
    # no rotator at all (tor install failed) -> also blocks
    f2 = _fake({"rotate_ip": True}, tor_verified=None)
    assert BaseAgent._stealth_leak_guard(f2, "ffuf", "ffuf -u http://x").status == ResultStatus.BLOCKED


def test_local_tools_and_help_probes_exempt():
    f = _fake({"rotate_ip": True}, tor_verified=False)
    assert BaseAgent._stealth_leak_guard(f, "grep", "grep foo bar.txt") is None
    assert BaseAgent._stealth_leak_guard(f, "nuclei", "nuclei --help") is None


def test_explicit_opt_out_allows_direct():
    f = _fake({"rotate_ip": True, "allow_direct_on_tor_fail": True}, tor_verified=False)
    assert BaseAgent._stealth_leak_guard(f, "nuclei", "nuclei -u http://x") is None
