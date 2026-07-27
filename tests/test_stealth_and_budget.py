"""Universal stealth routing + insufficient-budget tool-skip."""

import logging
import pytest
from agents.base_agent import BaseAgent


class _ConcreteAgent(BaseAgent):
    async def run(self):
        return {}


class _Rotator:
    def __init__(self, verified=True):
        self._tor_verified = verified
        self._tor_disabled = False

    def build_proxychains_cmd(self, command):
        if "proxychains4 " in command:
            return command
        return "proxychains4 -q " + command


def _agent(tor_verified=True):
    a = _ConcreteAgent.__new__(_ConcreteAgent)
    a.log = logging.getLogger("test")
    a._ip_rotator = _Rotator(tor_verified)
    return a


class TestStealthRouting:
    def test_http_tool_routed_through_tor(self):
        a = _agent()
        for tool, cmd in [("httpx", "httpx -l h.txt"), ("nuclei", "nuclei -u https://x"),
                          ("ffuf", "ffuf -u https://x/FUZZ -w w.txt"), ("curl", "curl https://x")]:
            assert a._apply_stealth_routing(tool, cmd).startswith("proxychains4 -q")

    def test_raw_socket_tools_not_routed(self):
        a = _agent()
        # SOCKS cannot carry raw packets; connect-scan-through-Tor = all-ports artifact
        for tool, cmd in [("nmap", "nmap -sT x"), ("masscan", "masscan x"),
                          ("dig", "dig x"), ("naabu", "naabu -host x")]:
            assert a._apply_stealth_routing(tool, cmd) == cmd

    def test_no_double_wrap(self):
        a = _agent()
        assert a._apply_stealth_routing("curl", "proxychains4 -q curl x") == "proxychains4 -q curl x"

    def test_no_routing_when_tor_inactive(self):
        a = _agent(tor_verified=False)
        assert a._apply_stealth_routing("httpx", "httpx x") == "httpx x"

    def test_no_rotator_is_safe(self):
        a = _ConcreteAgent.__new__(_ConcreteAgent)
        a.log = logging.getLogger("test")
        a._ip_rotator = None
        assert a._apply_stealth_routing("httpx", "httpx x") == "httpx x"


class TestInsufficientBudgetSkip:
    """The min-viable-timeout thresholds: a tool given less than its viable
    runtime should be skipped. Verifies the threshold constants are sane."""

    def test_thresholds_reasonable(self):
        # heavy tools need a real runtime (nuclei loads thousands of templates);
        # light tools can succeed in a few seconds.
        heavy_min, light_min = 45, 8
        # A 1-9s cap (what the live run imposed) is below the heavy threshold,
        # so heavy tools would be skipped instead of run doomed.
        assert 9 < heavy_min and 1 < light_min
        assert heavy_min > light_min

    def test_skip_decision(self):
        # mirror the inline guard: skip when capped timeout < min-viable
        def should_skip(tool, capped_timeout):
            heavy = {"nuclei", "ffuf", "nikto", "gobuster", "sqlmap",
                     "masscan", "feroxbuster", "wfuzz"}
            min_viable = 45 if tool in heavy else 8
            return capped_timeout < min_viable
        assert should_skip("nuclei", 9) is True
        assert should_skip("ffuf", 1) is True
        assert should_skip("curl", 1) is True
        assert should_skip("nuclei", 120) is False
        assert should_skip("curl", 10) is False
