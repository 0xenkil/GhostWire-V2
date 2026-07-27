"""W6.3 / W6.6 (TLS, smuggling, cache) / W5.2 (phase revisit) tests."""

import json
import pytest


# ── W6.6a — TLS/JA3 fingerprint ──────────────────────────────────────────────

class TestTlsFingerprint:
    def _t(self):
        from intelligence.waf_bypass.tls_fingerprint import TlsFingerprintEvasion
        return TlsFingerprintEvasion()

    def test_graceful_without_tooling(self):
        t = self._t()
        cmd, note = t.rewrite_curl_for_impersonation("curl -s https://x.com/")
        # No impersonate tooling in dev → command unchanged + explanatory note.
        if not t.available:
            assert cmd == "curl -s https://x.com/"
            assert "no curl-impersonate" in note

    def test_profiles_listed(self):
        t = self._t()
        assert "chrome120" in t.profiles()

    def test_non_curl_command_untouched(self):
        t = self._t()
        cmd, note = t.rewrite_curl_for_impersonation("nmap -sV x.com")
        assert cmd == "nmap -sV x.com"


# ── W6.6c — cache deception signal logic (offline) ───────────────────────────

class TestCacheSignals:
    def test_looks_cached(self):
        from intelligence.waf_bypass.cache_deception import _looks_cached
        assert _looks_cached({"x-cache": "HIT"})
        assert _looks_cached({"cf-cache-status": "HIT"})
        assert _looks_cached({"age": "10"})
        assert _looks_cached({"cache-control": "public, max-age=600"})
        assert not _looks_cached({"cache-control": "private, no-store"})
        assert not _looks_cached({"age": "0"})

    def test_probe_degrades_without_requests(self, monkeypatch):
        import intelligence.waf_bypass.cache_deception as cd
        monkeypatch.setattr(cd, "_requests", lambda: None)
        probe = cd.CacheDeceptionProbe()
        r = probe.probe_deception("https://x.com", "/account")
        assert r["vulnerable"] is False
        assert "unavailable" in r["evidence"]


# ── W6.6b — smuggling HITL gate ──────────────────────────────────────────────

class TestSmugglingHitl:
    def _orch(self):
        from intelligence.waf_bypass_orchestrator import WafBypassOrchestrator
        return WafBypassOrchestrator()

    def test_detection_within_roe_no_vector(self, monkeypatch):
        from intelligence.waf_bypass_orchestrator import WafBypassOrchestrator
        o = self._orch()
        o.request_smuggler.detect_smuggling_vulnerability = lambda t: {"vulnerable_to": []}
        res = o._execute_smuggling_bypass("x.com", {"details": {}}, authorized_attack=False)
        assert res["success"] is False  # nothing detected, no escalation

    def test_destructive_escalates_when_unauthorized(self, monkeypatch):
        from intelligence.waf_bypass_orchestrator import (
            WafBypassOrchestrator, WafAttackAuthorizationRequired)
        o = self._orch()
        o.request_smuggler.detect_smuggling_vulnerability = lambda t: {"vulnerable_to": ["CL.TE"]}
        with pytest.raises(WafAttackAuthorizationRequired):
            o._execute_smuggling_bypass("x.com", {"details": {}}, authorized_attack=False)

    def test_authorized_executes(self, monkeypatch):
        o = self._orch()
        o.request_smuggler.detect_smuggling_vulnerability = lambda t: {"vulnerable_to": ["CL.TE"]}
        o.request_smuggler.create_smuggling_payload = lambda v, t, s: "payload"
        o.request_smuggler.execute_smuggling_attack = lambda t, p: {"success": True}
        res = o._execute_smuggling_bypass("x.com", {"details": {}}, authorized_attack=True)
        assert res["success"] is True
        assert res["detected_vectors"] == ["CL.TE"]


# ── W5.2 — phase revisit ─────────────────────────────────────────────────────

class _Store:
    def __init__(self):
        self._kv = {}

    def get(self, k):
        return self._kv.get(k)

    def set(self, k, v):
        self._kv[k] = v


class TestPhaseRevisit:
    def _agent(self):
        from agents.base_agent import BaseAgent

        class _A(BaseAgent):
            async def run(self):
                return {}

        a = _A.__new__(_A)
        import logging
        a.log = logging.getLogger("test")
        a.store = _Store()

        class _S:
            engagement_id = "eng1"
        a.session = _S()
        return a

    def test_producer_sets_signal(self):
        a = self._agent()
        a.request_phase_revisit("recon", "found 3 new hosts")
        raw = a.store.get("eng1:revisit_request")
        assert raw
        req = json.loads(raw)
        assert req["phase"] == "recon"
        assert "new hosts" in req["reason"]

    def _orch(self, store):
        from core.orchestrator import Orchestrator
        import threading
        o = Orchestrator.__new__(Orchestrator)
        o.store = store
        o._lock = threading.Lock()
        o.task_queue = ["reporting"]
        o._current_phase_order = ["recon", "exploitation", "reporting"]

        class _Sess:
            engagement_id = "eng1"
        o.session = _Sess()
        # minimal agent registry
        o.agents = {"recon": object(), "exploitation": object(), "reporting": object()}
        return o

    def test_consumer_requeues_and_caps(self, monkeypatch):
        monkeypatch.setenv("MAX_PHASE_REVISITS", "1")
        store = _Store()
        store.set("eng1:revisit_request",
                  json.dumps({"phase": "recon", "reason": "new hosts"}))
        o = self._orch(store)
        o._maybe_requeue_for_revisit("exploitation")
        # recon + exploitation re-queued ahead of reporting (reporting excluded
        # from requeue set but already present)
        assert o.task_queue[0] == "recon"
        assert "exploitation" in o.task_queue
        # signal consumed
        assert not store.get("eng1:revisit_request")
        # second request beyond cap is ignored
        store.set("eng1:revisit_request",
                  json.dumps({"phase": "recon", "reason": "again"}))
        o._maybe_requeue_for_revisit("exploitation")
        assert o._revisit_count == 1

    def test_consumer_noop_without_signal(self):
        store = _Store()
        o = self._orch(store)
        before = list(o.task_queue)
        o._maybe_requeue_for_revisit("exploitation")
        assert o.task_queue == before
