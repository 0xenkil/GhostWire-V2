"""WS6 remainder — shell-valid mutation guard + real bypass differential validation."""

import pytest


class TestShellValidGuard:
    def _engine(self):
        from core.waf_ghost_engine import WafGhostEngine
        return WafGhostEngine(rules={"waf_ghost_use_parasitism": True})

    def test_mutation_stays_shell_parseable(self):
        import shlex
        e = self._engine()
        for _ in range(3):
            e.feedback("t.com", "curl", blocked=True)
        out = e.transform('curl -s "https://t.com/"', "curl", level=3, force=True)
        # must not raise
        shlex.split(out)

    def test_unparseable_mutation_falls_back(self, monkeypatch):
        """If mutation injects an unbalanced quote, guard returns the original."""
        e = self._engine()
        for _ in range(3):
            e.feedback("t.com", "curl", blocked=True)
        orig = 'curl -s https://t.com/'

        # Force the header generator to inject a value with an unbalanced quote.
        monkeypatch.setattr(
            e, "_generate_stealth_headers",
            lambda *a, **k: {"X-Bad": 'a"b'})  # unbalanced double-quote
        out = e.transform(orig, "curl", level=2, force=True)
        # Either it fell back to orig, or it produced something parseable.
        import shlex
        try:
            shlex.split(out)
            parseable = True
        except ValueError:
            parseable = False
        assert parseable
        # When mutation would have broken parsing, we expect the original back.
        if not parseable:
            assert out == orig


class TestBypassDifferential:
    def _orch(self):
        from intelligence.waf_bypass_orchestrator import WafBypassOrchestrator
        return WafBypassOrchestrator()

    def _resp(self, code):
        class _R:
            status_code = code
            text = "x"
        return _R()

    def test_differential_confirmed(self, monkeypatch):
        import intelligence.waf_bypass_orchestrator as m
        o = self._orch()
        calls = {"n": 0}

        def fake_get(url, **kw):
            calls["n"] += 1
            # first call = control (blocked 403), second = test (allowed 200)
            return self._resp(403) if calls["n"] == 1 else self._resp(200)

        import requests
        monkeypatch.setattr(requests, "get", fake_get)
        verified, note = o._validate_bypass_differential("example.com", "https://1.2.3.4/")
        assert verified is True
        assert "differential confirmed" in note

    def test_no_differential_downgrades(self, monkeypatch):
        o = self._orch()

        def fake_get(url, **kw):
            return self._resp(200)  # both allowed — no differential

        import requests
        monkeypatch.setattr(requests, "get", fake_get)
        verified, note = o._validate_bypass_differential("example.com", "https://1.2.3.4/")
        assert verified is False
        assert "no differential" in note

    def test_execute_bypass_downgrades_unverified(self, monkeypatch):
        """A 'successful' strategy with no differential is downgraded to failure."""
        o = self._orch()
        monkeypatch.setattr(
            o, "_validate_bypass_differential",
            lambda target, url: (False, "no differential: control=200, test=200"))

        # Stub a strategy that claims success.
        def fake_origin(target, result):
            result["success"] = True
            result["bypass_url"] = "https://1.2.3.4/"
            return result

        monkeypatch.setattr(o, "_execute_origin_bypass", fake_origin)
        res = o.execute_bypass("eng1", "example.com", bypass_strategy="origin")
        assert res["success"] is False
        assert res.get("bypass_verified") is False
        assert "unverified_reason" in res
