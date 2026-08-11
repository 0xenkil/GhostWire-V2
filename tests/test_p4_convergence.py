"""Phase 4 — P4-3 enforced convergence breaker (intent-ledgered, no LLM).

A doomed intent (403→rotate-Tor→403, or any tool that keeps failing to move the
needle) must be abandoned deterministically once it has burned its attempt budget
without producing a single finding for its OWN host. Keyed on the P1-4 intent key
(so every evasion mutation shares one ledger entry — the reason the old per-full-
hash breaker never tripped) with INTENT-LOCAL progress (not global).
"""

import logging
import tempfile

import pytest

from agents.exploitation_agent import ExploitationAgent
from intelligence.strategic_advisor import StrategicAdvisor


def _agent(advisor=None):
    a = ExploitationAgent.__new__(ExploitationAgent)
    a.log = logging.getLogger("test")
    a._ssh = None
    a._findings_seen = set()
    a._intent_ledger = {}
    a.advisor = advisor
    return a


class TestIntentLocalProgress:
    def test_counts_only_this_host(self):
        a = _agent()
        assert a._intent_local_progress("t.example") == 0
        a._findings_seen.add("open_port::t.example::abc::80 open")
        a._findings_seen.add("note::other.host::def::x")
        assert a._intent_local_progress("t.example") == 1
        assert a._intent_local_progress("other.host") == 1


class TestConvergenceBreaker:
    def test_doomed_intent_abandoned_on_budget(self):
        a = _agent()
        key = "nmap|t.example|-ss"
        results = [a._convergence_breaker(key, "t.example", "nmap", False)[0]
                   for _ in range(4)]
        assert results == [False, False, False, True]

    def test_continuously_productive_intent_never_abandoned(self):
        # A genuinely productive intent — one that keeps surfacing NEW findings —
        # is never abandoned: every fresh finding resets the stale streak.
        a = _agent()
        key = "gobuster|t.example|dir"
        for i in range(8):
            a._findings_seen.add(f"path::t.example::e{i}::/dir{i}")  # new finding each round
            abandon, _ = a._convergence_breaker(key, "t.example", "gobuster", False)
            assert abandon is False

    def test_early_progress_then_stale_is_abandoned(self):
        # REGRESSION (live novalink.lk run): the OLD breaker measured progress
        # since the intent STARTED, so a single early finding gave permanent
        # immunity and a WAF-blocked nmap loop spun ~90 min. Now: one finding at
        # attempt 2, then MAX consecutive stale attempts => abandoned.
        a = _agent()
        key = "nmap|t.example|--script,-sv"
        abandons = []
        for i in range(6):
            if i == 1:
                a._findings_seen.add("http_title::t.example::e1::title")  # one early win
            abandons.append(a._convergence_breaker(key, "t.example", "nmap", False)[0])
        assert abandons[-1] is True          # doomed loop IS abandoned despite the early win
        assert abandons.count(True) >= 1

    def test_repair_fetches_never_count(self):
        a = _agent()
        key = "nmap|t.example|-ss"
        for _ in range(10):
            assert a._convergence_breaker(key, "t.example", "nmap", True)[0] is False
        assert key not in a._intent_ledger

    def test_advisor_can_veto_abandon(self):
        class _Adv:
            def should_continue_trying(self, tool, target, attempts,
                                       failure_rate, no_progress=False):
                return True, "keep going"
        a = _agent(advisor=_Adv())
        key = "x|h|-a"
        abandon = False
        for _ in range(5):
            abandon, _ = a._convergence_breaker(key, "h", "x", False)
        assert abandon is False


class TestAdvisorSignature:
    def _advisor(self):
        return StrategicAdvisor(knowledge_dir=tempfile.mkdtemp())

    def test_legacy_signature_still_decides(self):
        cont, why = self._advisor().should_continue_trying(
            "nmap", "x", attempts=6, failure_rate=0.9)
        assert cont is False and isinstance(why, str)

    def test_no_progress_is_authoritative(self):
        cont, why = self._advisor().should_continue_trying(
            "nmap", "x", attempts=4, failure_rate=0.0, no_progress=True)
        assert cont is False

    def test_no_progress_below_threshold_not_forced(self):
        cont, _ = self._advisor().should_continue_trying(
            "nmap", "x", attempts=2, failure_rate=0.0, no_progress=True)
        assert cont is True
