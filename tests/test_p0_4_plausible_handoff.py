"""P0-4 — pre-exploit plausibility / result-quality gate.

Empty or garbage recon must NOT hand off to exploitation (RC-6, DEEP-5). When a
honeypot/tarpit port-flood is present, the honeypot pruner may only LOWER
CONFIDENCE (flag needs_confirmation) — it must never hard-drop a reported port,
because the Evidence differential is the final arbiter (TRIPWIRE-1 bound).
"""

import logging
import pytest

from agents.exploitation_agent import ExploitationAgent


class _Store:
    def __init__(self, findings=None, phase=None):
        self._f = findings or []
        self._phase = phase

    def get_all_findings(self, eng):
        return self._f

    def get_phase_data(self, eng, phase):
        return self._phase


class _Session:
    def __init__(self, target="https://t.example", eng="eng_x"):
        self.target = target
        self.engagement_id = eng


def _agent(findings=None, phase=None, target="https://t.example"):
    a = ExploitationAgent.__new__(ExploitationAgent)
    a.log = logging.getLogger("test")
    a.store = _Store(findings, phase)
    a.session = _Session(target=target)
    a._ssh = None
    a.tools = None
    return a


class TestPlausibleHandoff:
    def test_no_ports_no_findings_is_garbage(self):
        ok, reason, ann = _agent()._plausible_handoff({"open_ports": []})
        assert ok is False
        assert "no plausible target" in reason.lower()

    def test_open_ports_make_it_plausible(self):
        ok, reason, ann = _agent()._plausible_handoff({"open_ports": [80, 443]})
        assert ok is True and reason == ""

    def test_findings_alone_make_it_plausible(self):
        a = _agent(findings=[{"type": "open_port"}])
        ok, reason, ann = a._plausible_handoff({"open_ports": []})
        assert ok is True

    def test_non_dict_recon_with_findings(self):
        a = _agent(findings=[{"type": "x"}])
        ok, reason, ann = a._plausible_handoff(None)
        assert ok is True

    def test_honeypot_flood_flags_never_drops(self, monkeypatch):
        import core.tripwire_detector as td
        # Pretend only 80/443 verify as live web services.
        monkeypatch.setattr(td.TripwireDetector, "prune_honeypot_ports",
                            lambda self, host, ports: [80, 443])
        flood = [80, 443] + list(range(1000, 1060))  # 62 ports >= threshold 50
        ok, reason, ann = _agent()._plausible_handoff({"open_ports": flood})
        assert ok is True
        assert set(ann["verified_live_ports"]) == {80, 443}
        # every unverified port is FLAGGED for confirmation, not removed
        assert set(ann["needs_confirmation_ports"]) == set(flood) - {80, 443}

    def test_small_port_set_does_not_probe(self, monkeypatch):
        import core.tripwire_detector as td
        called = {"n": 0}

        def _spy(self, host, ports):
            called["n"] += 1
            return [80]

        monkeypatch.setattr(td.TripwireDetector, "prune_honeypot_ports", _spy)
        ok, reason, ann = _agent()._plausible_handoff({"open_ports": [80, 443, 22]})
        assert ok is True
        assert called["n"] == 0          # under threshold → pruner never consulted
        assert ann["needs_confirmation_ports"] == []


class TestPreflightWiring:
    def test_no_recon_data(self):
        ok, reason = _agent(phase=None)._preflight()
        assert ok is False and "no data" in reason.lower()

    def test_garbage_recon_blocks_handoff(self):
        ok, reason = _agent(phase={"open_ports": []})._preflight()
        assert ok is False

    def test_good_recon_passes_and_stashes_annotations(self):
        a = _agent(phase={"open_ports": [80, 443]})
        ok, reason = a._preflight()
        assert ok is True and reason == ""
        assert hasattr(a, "_handoff_annotations")
        assert "needs_confirmation_ports" in a._handoff_annotations
