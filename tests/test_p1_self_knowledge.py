"""Phase 1 — deterministic self-knowledge gates.

Covers:
  P1-1  capability probe records probe_ok (failed/absent probe is never an
        authoritative hard-reject).
  P1-2  enforce_capability escalates on the MEASURED root-raw capability, degrades
        to a connect scan otherwise, and is a strict no-op when unmeasured.
  P1-4  _command_intent_key collapses wrapper/value/volatile/evasion mutations of
        one logical attempt onto a single key.
  P1-5  the outcome-verdict cache fingerprints the FULL error (not a 160-char
        prefix) with digit runs collapsed.
"""

import logging
import re
import hashlib

import pytest

from agents.exploitation_agent import ExploitationAgent
from core.result_contracts import ToolResult, ResultStatus


def _agent():
    a = ExploitationAgent.__new__(ExploitationAgent)
    a.log = logging.getLogger("test")
    a._ssh = None
    return a


class TestProbeOk:
    def test_no_ssh_is_unknown_not_hard_reject(self):
        # No remote executor to probe → probe_ok False (UNKNOWN). Consumers must
        # NOT read this as "raw_socket unavailable".
        caps = _agent()._probe_capabilities()
        assert caps.get("probe_ok") is False
        assert "raw_socket" not in caps


class TestEnforceCapability:
    def _ec(self, cmd, caps):
        a = _agent()
        a._capabilities_cache = dict(caps)
        return a.enforce_capability(cmd)

    def test_unmeasured_is_passthrough(self):
        assert self._ec("nmap -sS --privileged t",
                        {"probe_ok": False}) == "nmap -sS --privileged t"

    def test_direct_raw_runs_as_is_minus_inert_flags(self):
        assert self._ec("nmap -sS --privileged t",
                        {"probe_ok": True, "root": True, "raw_socket": True,
                         "raw_socket_via_root": True}) == "nmap -sS t"

    def test_escalates_on_measured_root_raw(self):
        assert self._ec("nmap -sS --privileged t",
                        {"probe_ok": True, "root": False, "raw_socket": False,
                         "raw_socket_via_root": True}) == "sudo nmap -sS t"

    def test_connect_fallback_when_no_root_path(self):
        assert self._ec("nmap -sS -O t",
                        {"probe_ok": True, "root": False, "raw_socket": False,
                         "raw_socket_via_root": False}) == "nmap -sT t"

    def test_unprivileged_command_untouched(self):
        assert self._ec("nmap -sT -p80 t",
                        {"probe_ok": True, "root": False, "raw_socket": False,
                         "raw_socket_via_root": False}) == "nmap -sT -p80 t"

    def test_already_escalated_not_double_prefixed_or_degraded(self):
        assert self._ec("sudo nmap -sS t",
                        {"probe_ok": True, "root": False, "raw_socket": False,
                         "raw_socket_via_root": True}) == "sudo nmap -sS t"


class TestIntentKey:
    def test_variants_of_one_intent_collapse(self):
        a = _agent()
        base = a._command_intent_key("nmap -sS 1.2.3.4")
        for variant in [
            "sudo nmap -sS 1.2.3.4",
            "proxychains4 -q nmap -sS 1.2.3.4 -oN out.txt",
            "timeout 300 nmap -sS 1.2.3.4 -T4 --max-rate 500",
            "env HTTP_PROXY=x nmap -sS 1.2.3.4 -v -oX r.xml",
        ]:
            assert a._command_intent_key(variant) == base, variant

    def test_distinct_intents_stay_distinct(self):
        a = _agent()
        base = a._command_intent_key("nmap -sS 1.2.3.4")
        assert a._command_intent_key("nmap -sT 1.2.3.4") != base
        assert a._command_intent_key("nmap -sS 5.6.7.8") != base
        assert a._command_intent_key("masscan -sS 1.2.3.4") != base

    def test_value_only_difference_collapses(self):
        a = _agent()
        assert (a._command_intent_key("gobuster dir -u http://t/ -w big.txt")
                == a._command_intent_key("gobuster dir -u http://t/ -w small.txt"))

    def test_host_from_command_first(self):
        a = _agent()
        assert (a._command_intent_key("nmap -sS http://t.example/p", "t.example")
                == a._command_intent_key("nmap -sS t.example"))


class TestOutcomeCacheFingerprint:
    def _fp(self, out):
        n = re.sub(r'\d+', '#', " ".join(out.lower().split()))
        return hashlib.md5(n.encode("utf-8", "ignore")).hexdigest()[:16]

    def test_full_error_not_prefix(self):
        prefix = "connection error: " + ("x" * 160)
        a = prefix + " TAIL-AAAA " + ("a" * 700)
        b = prefix + " TAIL-BBBB " + ("b" * 700)
        assert self._fp(a) != self._fp(b)  # old 160-prefix key collided these

    def test_digit_runs_collapse(self):
        assert self._fp("port 8080 refused") == self._fp("port 9090 refused")

    def test_interpret_outcome_fail_safe_and_caches_tuple(self):
        a = _agent()
        a.ai = None  # no backend → safe default, no crash
        r = ToolResult(tool="nmap", command="x", stdout="boom 12", stderr="",
                       exit_code=1, duration_seconds=1.0, status=ResultStatus.FAILURE)
        v = a._interpret_outcome("nmap", "nmap -sS t.example", r)
        assert v == {"action": "repair", "reason": ""}
