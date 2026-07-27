"""
WS3 / W3.1 — Authenticated HTTP session manager.

The entire modern attack surface (IDOR, BOLA, broken object/function-level
authorization, tenant isolation) lives *behind auth*. Before this, the engine
could not hold a session, so it could never reach those bugs. `AppSession` is a
real session: it carries cookies, a bearer/JWT token, captures CSRF tokens, and
injects all of that into every request — so a tool/probe can run "as an
authenticated user" and then "as another user" for the differential that proves
object-level authz bugs.

Dependency-light (requests + stdlib). No hardcoded target logic — the caller (an
AI-driven agent) decides *what* to request; this class only handles *carrying
the identity*.
"""

import base64
import json
import re
import time
from typing import Optional

import requests


class AppSession:
    """A persistent authenticated HTTP session for app-aware testing."""

    def __init__(self, base_url: str = "", verify_tls: bool = False,
                 timeout: int = 20, user_agent: Optional[str] = None,
                 proxies: Optional[dict] = None):
        self.base_url = (base_url or "").rstrip("/")
        self.timeout = timeout
        self._s = requests.Session()
        self._s.verify = verify_tls
        if proxies:
            self._s.proxies.update(proxies)
        self._s.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        })
        self._bearer: Optional[str] = None
        self._csrf_token: Optional[str] = None
        self._csrf_header: str = "X-CSRF-Token"
        self.authenticated: bool = False
        self.identity_label: str = "anonymous"

    # ── identity management ──────────────────────────────────────────────────

    def set_bearer(self, token: str, label: str = "user") -> None:
        """Attach a bearer/JWT token to all subsequent requests."""
        token = (token or "").strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        self._bearer = token
        if token:
            self._s.headers["Authorization"] = f"Bearer {token}"
            self.authenticated = True
            self.identity_label = label

    def set_cookie(self, name: str, value: str, domain: Optional[str] = None) -> None:
        if domain:
            self._s.cookies.set(name, value, domain=domain)
        else:
            self._s.cookies.set(name, value)
        self.authenticated = True

    def set_csrf(self, token: str, header: str = "X-CSRF-Token") -> None:
        self._csrf_token = token
        self._csrf_header = header

    def clear_identity(self) -> None:
        """Drop all auth context (back to anonymous) — used for control requests."""
        self._bearer = None
        self._csrf_token = None
        self.authenticated = False
        self.identity_label = "anonymous"
        self._s.headers.pop("Authorization", None)
        self._s.cookies.clear()

    def clone_anonymous(self) -> "AppSession":
        """A fresh anonymous session against the same base — the control arm of
        an authz differential (request the same object with no identity)."""
        return AppSession(base_url=self.base_url, verify_tls=self._s.verify,
                          timeout=self.timeout,
                          user_agent=self._s.headers.get("User-Agent"),
                          proxies=dict(self._s.proxies))

    # ── requests ─────────────────────────────────────────────────────────────

    def _full(self, url: str) -> str:
        if url.startswith("http"):
            return url
        if not url.startswith("/"):
            url = "/" + url
        return self.base_url + url

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Perform a request carrying the current identity + CSRF. Returns the
        Response, or None on a transport error (never raises)."""
        full = self._full(url)
        headers = dict(kwargs.pop("headers", {}) or {})
        if self._csrf_token and method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
            headers.setdefault(self._csrf_header, self._csrf_token)
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        try:
            resp = self._s.request(method.upper(), full, headers=headers, **kwargs)
            self._capture_csrf(resp)
            return resp
        except requests.RequestException:
            return None

    def get(self, url: str, **kw) -> Optional[requests.Response]:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> Optional[requests.Response]:
        return self.request("POST", url, **kw)

    # ── auth acquisition (mechanism only; policy/HITL is the caller's job) ────

    def login_form(self, login_url: str, data: dict,
                   success_markers: Optional[list] = None) -> bool:
        """Submit a login form and detect success. AI supplies login_url + the
        field map; this carries the resulting cookies. Returns True on apparent
        success (2xx/3xx + optional success markers, or a new session cookie)."""
        pre_cookies = set(self._s.cookies.keys())
        resp = self.post(login_url, data=data)
        if resp is None:
            return False
        ok = resp.status_code < 400
        gained_cookie = bool(set(self._s.cookies.keys()) - pre_cookies)
        body_lc = (resp.text or "").lower()
        marker_ok = True
        if success_markers:
            marker_ok = any(m.lower() in body_lc for m in success_markers)
        # Try to lift a bearer token from a JSON login response.
        self._maybe_lift_token(resp)
        if (ok and marker_ok and (gained_cookie or self._bearer)) or (
                ok and self._bearer):
            self.authenticated = True
            self.identity_label = "user"
            return True
        return self.authenticated

    def login_json(self, login_url: str, payload: dict,
                   token_fields: Optional[list] = None) -> bool:
        """POST JSON credentials to an API login endpoint and lift the token."""
        resp = self.post(login_url, json=payload)
        if resp is None:
            return False
        self._maybe_lift_token(resp, token_fields=token_fields)
        if resp.status_code < 400 and (self._bearer or self._s.cookies):
            self.authenticated = True
            self.identity_label = "user"
            return True
        return False

    # ── helpers ───────────────────────────────────────────────────────────────

    def _maybe_lift_token(self, resp: requests.Response,
                          token_fields: Optional[list] = None) -> None:
        fields = token_fields or [
            "access_token", "accessToken", "token", "jwt", "id_token", "idToken",
            "authToken", "auth_token", "session_token"]
        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        # search top-level then one level into "data"/"result"
        candidates = [data]
        for nest in ("data", "result", "tokens", "auth"):
            if isinstance(data.get(nest), dict):
                candidates.append(data[nest])
        for blob in candidates:
            for f in fields:
                v = blob.get(f)
                if isinstance(v, str) and len(v) > 10:
                    self.set_bearer(v)
                    return

    def _capture_csrf(self, resp: requests.Response) -> None:
        """Best-effort CSRF capture from common locations (cookie, meta, hidden input)."""
        try:
            for cname in ("csrftoken", "csrf_token", "XSRF-TOKEN", "_csrf"):
                if cname in resp.cookies:
                    self._csrf_token = resp.cookies.get(cname)
                    if cname == "XSRF-TOKEN":
                        self._csrf_header = "X-XSRF-TOKEN"
                    return
            ctype = resp.headers.get("Content-Type", "")
            if "html" in ctype.lower() and resp.text:
                m = re.search(
                    r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)',
                    resp.text, re.IGNORECASE)
                if not m:
                    m = re.search(
                        r'<input[^>]+name=["\'](?:_csrf|csrf_token|authenticity_token)["\']'
                        r'[^>]+value=["\']([^"\']+)', resp.text, re.IGNORECASE)
                if m:
                    self._csrf_token = m.group(1)
        except Exception:
            pass

    @staticmethod
    def decode_jwt_claims(token: str) -> dict:
        """Decode a JWT payload (no signature verification) so an AI can reason
        about which claim holds the user/object id to manipulate for IDOR."""
        try:
            token = (token or "").strip()
            if token.lower().startswith("bearer "):
                token = token[7:].strip()
            parts = token.split(".")
            if len(parts) < 2:
                return {}
            payload = parts[1]
            payload += "=" * (-len(payload) % 4)  # pad base64
            decoded = base64.urlsafe_b64decode(payload.encode())
            return json.loads(decoded)
        except Exception:
            return {}

    @property
    def current_jwt_claims(self) -> dict:
        return self.decode_jwt_claims(self._bearer or "")

    def snapshot(self) -> dict:
        """Serializable view of the session identity for logging/evidence."""
        return {
            "base_url": self.base_url,
            "authenticated": self.authenticated,
            "identity": self.identity_label,
            "has_bearer": bool(self._bearer),
            "cookies": list(self._s.cookies.keys()),
            "jwt_claims": self.current_jwt_claims if self._bearer else {},
            "ts": time.time(),
        }
