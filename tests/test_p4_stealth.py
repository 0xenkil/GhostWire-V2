"""Phase 4 — P4-5 fail-closed stealth (STEALTH-DEGRADE-1, both halves).

If IP anonymity was requested, a run that would still reach the target from the
operator's REAL IP must be blocked, not silently de-anonymized:
  1. a proxiable tool when Tor is not verified working, and
  2. (higher severity) a RAW-SOCKET tool even under VERIFIED Tor — SOCKS can't
     carry raw packets so nmap/masscan/dig run DIRECT regardless of Tor state.
"""

import logging

import pytest

from agents.exploitation_agent import ExploitationAgent
from core.result_contracts import ResultStatus


def _agent(stealth, tor_verified=None):
    a = ExploitationAgent.__new__(ExploitationAgent)
    a.log = logging.getLogger("test")
    a._ssh = None
    a._stealth = stealth

    class _Rot:
        _tor_verified = tor_verified

        def ensure_tor_ready(self):
            return False

    a._ip_rotator = _Rot() if tor_verified is not None else None
    return a


def _blocked(res):
    return res is not None and res.status == ResultStatus.BLOCKED


class TestRawSocketHalf:
    def test_raw_socket_blocks_even_under_verified_tor(self):
        a = _agent({"rotate_ip": True}, tor_verified=True)
        assert _blocked(a._stealth_leak_guard("nmap", "nmap -sS t"))

    def test_manual_proxychains_is_operator_owned(self):
        a = _agent({"rotate_ip": True}, tor_verified=True)
        assert a._stealth_leak_guard("nmap", "proxychains nmap -sT t") is None

    def test_allow_direct_opt_out(self):
        a = _agent({"rotate_ip": True, "allow_direct_on_tor_fail": True}, tor_verified=True)
        assert a._stealth_leak_guard("nmap", "nmap -sS t") is None


class TestTorNotVerifiedHalf:
    def test_proxiable_tool_blocks_when_tor_down(self):
        a = _agent({"rotate_ip": True}, tor_verified=False)
        assert _blocked(a._stealth_leak_guard("curl", "curl https://t/"))

    def test_proxiable_tool_ok_when_tor_verified(self):
        a = _agent({"rotate_ip": True}, tor_verified=True)
        assert a._stealth_leak_guard("curl", "curl https://t/") is None


class TestTrigger:
    def test_widened_trigger_use_tor(self):
        a = _agent({"use_tor": True}, tor_verified=False)
        assert _blocked(a._stealth_leak_guard("curl", "curl https://t/"))

    def test_ghost_mode_is_not_ip_anonymity(self):
        # ghost_mode is WAF header/JA3 evasion — it legitimately uses the real IP.
        a = _agent({"ghost_mode": True}, tor_verified=None)
        assert a._stealth_leak_guard("nmap", "nmap -sS t") is None

    def test_no_stealth_allows_everything(self):
        a = _agent({}, tor_verified=None)
        assert a._stealth_leak_guard("nmap", "nmap -sS t") is None

    def test_help_probe_exempt(self):
        a = _agent({"rotate_ip": True}, tor_verified=False)
        assert a._stealth_leak_guard("nmap", "nmap --help") is None
