"""WS3 — Authenticated & app-aware testing: AppSession, AuthzTester, HITL gate."""

import pytest

from core.app_session import AppSession
from intelligence.authz_tester import AuthzTester, AuthzResult


# ── fake responses / sessions (no real network) ──────────────────────────────

class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self.text = body


class _FakeSession(AppSession):
    """AppSession whose .get returns canned responses keyed by URL."""

    def __init__(self, routes, label="user"):
        super().__init__(base_url="https://t.lk")
        self._routes = routes
        self.identity_label = label
        self.authenticated = True

    def get(self, url, **kw):
        body = self._routes.get(url)
        if body is None:
            return _Resp(404, "not found")
        return _Resp(200, body)


class TestAppSessionIdentity:
    def test_bearer_and_jwt_decode(self):
        s = AppSession(base_url="https://t.lk")
        # jwt with payload {"sub":"42","role":"user"}
        jwt = ("eyJhbGciOiJIUzI1NiJ9."
               "eyJzdWIiOiI0MiIsInJvbGUiOiJ1c2VyIn0."
               "sig")
        s.set_bearer(jwt)
        assert s.authenticated
        assert s._s.headers["Authorization"].startswith("Bearer ")
        claims = s.current_jwt_claims
        assert claims.get("sub") == "42"
        assert claims.get("role") == "user"

    def test_clear_and_clone(self):
        s = AppSession(base_url="https://t.lk")
        s.set_bearer("abcdefghijklmnop")
        s.set_cookie("session", "xyz")
        clone = s.clone_anonymous()
        assert clone.authenticated is False
        assert "Authorization" not in clone._s.headers
        s.clear_identity()
        assert s.authenticated is False


class TestBola:
    def test_bola_confirmed_when_anon_gets_same_object(self):
        obj = '{"order_id":123,"owner":"alice","total":"$99","card":"****1111"}'
        auth = _FakeSession({"/api/orders/123": obj}, label="alice")
        # anonymous clone returns the SAME object → BOLA
        anon = _FakeSession({"/api/orders/123": obj}, label="anonymous")
        anon.authenticated = False
        t = AuthzTester(auth)
        res = t.test_bola("/api/orders/123", other_session=anon)
        assert res.confirmed
        assert res.vuln_class == "BOLA"
        assert res.proof_type == "differential"
        assert res.severity == "high"

    def test_bola_safe_when_other_identity_blocked(self):
        obj = '{"order_id":123,"owner":"alice"}'
        auth = _FakeSession({"/api/orders/123": obj}, label="alice")
        other = _FakeSession({}, label="bob")  # 404 for the object → authz holds
        t = AuthzTester(auth)
        res = t.test_bola("/api/orders/123", other_session=other)
        assert not res.confirmed


class TestIdor:
    def test_idor_confirmed_on_neighbor_object(self):
        own = '{"order_id":123,"owner":"me","item":"book"}'
        other = '{"order_id":124,"owner":"someone_else","item":"laptop"}'
        auth = _FakeSession({"/api/orders/123": own, "/api/orders/124": other})
        t = AuthzTester(auth)
        res = t.test_idor("/api/orders/123")
        assert res.confirmed
        assert res.vuln_class == "IDOR"
        assert "124" in res.url

    def test_idor_safe_when_neighbors_404(self):
        own = '{"order_id":123,"owner":"me"}'
        auth = _FakeSession({"/api/orders/123": own})  # neighbors → 404
        t = AuthzTester(auth)
        res = t.test_idor("/api/orders/123")
        assert not res.confirmed

    def test_neighbor_url_derivation(self):
        urls = AuthzTester._neighbor_urls("/api/orders/123", None)
        assert "/api/orders/124" in urls
        assert "/api/orders/122" in urls
        # query-style ids too
        q = AuthzTester._neighbor_urls("/api/get?user_id=50", [51])
        assert "/api/get?user_id=51" in q


class TestHitlGate:
    """The HITL authorization decision logic (no real prompt)."""

    class _Sess:
        def __init__(self, roe, approver=None):
            self.rules_of_engagement = roe
            if approver is not None:
                self.hitl_approver = approver

    def _agent(self, roe, approver=None):
        from agents.base_agent import BaseAgent

        class _ConcreteAgent(BaseAgent):
            async def run(self):  # satisfy the abstract method
                return {}

        a = _ConcreteAgent.__new__(_ConcreteAgent)
        import logging
        a.log = logging.getLogger("test")
        a.session = self._Sess(roe, approver)
        return a

    def test_within_roe_autonomous(self):
        a = self._agent({"allow_exploitation": True})
        assert a.request_hitl_authorization(
            "authenticate", "login", ["allow_exploitation"]) is True

    def test_beyond_roe_batch_denies(self):
        a = self._agent({"allow_exploitation": False})
        assert a.request_hitl_authorization(
            "authenticate", "login", ["allow_exploitation"]) is False

    def test_beyond_roe_approver_grants(self):
        a = self._agent({}, approver=lambda name, desc: True)
        assert a.request_hitl_authorization(
            "authenticate", "login", ["allow_exploitation"]) is True

    def test_beyond_roe_approver_denies(self):
        a = self._agent({}, approver=lambda name, desc: False)
        assert a.request_hitl_authorization(
            "authenticate", "login", ["allow_exploitation"]) is False


class TestBrowserDriverGraceful:
    def test_noop_when_playwright_unavailable(self):
        from core.browser_driver import BrowserDriver, playwright_available
        d = BrowserDriver()
        if not playwright_available():
            out = d.render("https://example.com")
            assert out["ok"] is False
            assert out["error"] == "playwright_unavailable"
            assert out["api_endpoints"] == []
