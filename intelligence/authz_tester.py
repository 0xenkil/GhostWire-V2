"""
WS3 / W3.4 — Object-level & function-level authorization testing (IDOR / BOLA).

These are the bug classes that actually exist on modern SaaS and that the engine
previously could not reach. They are inherently *differential* (ties to WS4): a
finding requires a control vs. test comparison across identities, never a lone
200. This module operates on `AppSession` objects so the same object can be
requested as the authenticated user, as another user, and anonymously.

No hardcoded targets: the AI supplies candidate object-URLs (mined from the JS
bundle / captured XHR by WS2). This module only runs the differential and judges
it by observable response deltas.
"""

import re
from dataclasses import dataclass, field
from typing import Optional

from core.app_session import AppSession

# id-bearing path/query segments, e.g. /api/orders/123, ?user_id=42, /users/42
_ID_IN_PATH_RE = re.compile(r'(/[a-zA-Z0-9_\-]+/)(\d{1,12})(/|$|\?)')
_ID_IN_QUERY_RE = re.compile(r'([?&][a-zA-Z0-9_\-]*id[a-zA-Z0-9_\-]*=)(\d{1,12})', re.IGNORECASE)


@dataclass
class AuthzResult:
    vuln_class: str               # "BOLA" | "IDOR"
    url: str
    confirmed: bool
    severity: str = "info"
    differential: str = ""
    proof_type: str = "none"      # "differential" when proven
    control: dict = field(default_factory=dict)
    test: dict = field(default_factory=dict)
    # P0-5: the measured control/test bodies (truncated) so the ProofLedger can
    # RE-MEASURE the cross-identity differential and stamp a real proof token,
    # rather than the emitter asserting "VULN_PROVEN".
    control_body: str = ""
    test_body: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "vuln_class": self.vuln_class, "url": self.url,
            "confirmed": self.confirmed, "severity": self.severity,
            "differential": self.differential, "proof_type": self.proof_type,
            "control": self.control, "test": self.test, "notes": self.notes,
        }


def _resp_view(resp) -> dict:
    if resp is None:
        return {"status": 0, "len": 0, "body": ""}
    body = resp.text or ""
    return {"status": resp.status_code, "len": len(body), "body": body[:4000]}


def _similar(a: str, b: str) -> float:
    a, b = (a or "").strip(), (b or "").strip()
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    import difflib
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).quick_ratio()


def _looks_protected(view: dict) -> bool:
    """A non-trivial 2xx body that plausibly contains object data."""
    return view.get("status", 0) and 200 <= view["status"] < 300 and view.get("len", 0) >= 40


class AuthzTester:
    """Runs IDOR / BOLA differentials across identities."""

    def __init__(self, auth_session: AppSession, logger=None):
        self.auth = auth_session
        self.log = logger

    # ── BOLA: can an unauthorized identity read a protected object? ───────────

    def test_bola(self, object_url: str,
                  other_session: Optional[AppSession] = None) -> AuthzResult:
        """Broken Object-Level Authorization.

        Control: the authenticated owner fetches `object_url` → protected object.
        Test:    a *different* identity (another user, or anonymous) fetches the
                 SAME url. If it returns the same protected object (2xx + similar
                 body), object-level authz is broken.
        """
        control = _resp_view(self.auth.get(object_url))
        res = AuthzResult(vuln_class="BOLA", url=object_url, confirmed=False,
                          control={k: control[k] for k in ("status", "len")})

        if not _looks_protected(control):
            res.notes = "control did not return a protected object (2xx, body≥40B)"
            return res

        tester = other_session or self.auth.clone_anonymous()
        test = _resp_view(tester.get(object_url))
        res.test = {k: test[k] for k in ("status", "len")}

        if not (test.get("status", 0) and 200 <= test["status"] < 300):
            res.notes = f"unauthorized identity got {test.get('status')} (authz holds)"
            return res

        sim = _similar(control["body"], test["body"])
        # Same protected object served to a different identity → BOLA.
        if sim >= 0.9 and test["len"] >= 40:
            res.confirmed = True
            res.proof_type = "differential"
            res.severity = "high"
            res.control_body = control["body"]
            res.test_body = test["body"]
            who = other_session.identity_label if other_session else "anonymous"
            res.differential = (
                f"{who} identity received the SAME protected object as the owner "
                f"(status {test['status']}, body {test['len']}B, {sim:.0%} identical). "
                "Object-level authorization is not enforced.")
        else:
            res.notes = f"different/empty body for other identity (sim {sim:.0%}) — authz likely holds"
        return res

    # ── IDOR: can the user reach a neighbour object that isn't theirs? ────────

    def test_idor(self, object_url: str, neighbor_ids: Optional[list] = None) -> AuthzResult:
        """Insecure Direct Object Reference.

        Control: the user fetches their own object at `object_url`.
        Test:    the user fetches a NEIGHBOUR id (123 → 124/122/1). If that
                 returns a *different but valid* protected object (2xx, body
                 differs from the user's own and from a 404/empty), the user can
                 read objects that aren't theirs → IDOR.
        """
        control = _resp_view(self.auth.get(object_url))
        res = AuthzResult(vuln_class="IDOR", url=object_url, confirmed=False,
                          control={k: control[k] for k in ("status", "len")})
        if not _looks_protected(control):
            res.notes = "control did not return a protected object"
            return res

        candidates = self._neighbor_urls(object_url, neighbor_ids)
        if not candidates:
            res.notes = "no id found in url to pivot"
            return res

        for nurl in candidates:
            test = _resp_view(self.auth.get(nurl))
            if not (test.get("status", 0) and 200 <= test["status"] < 300):
                continue
            if test["len"] < 40:
                continue
            sim = _similar(control["body"], test["body"])
            # A neighbour that returns a DIFFERENT valid object = someone else's data.
            if sim < 0.97:
                res.confirmed = True
                res.url = nurl
                res.proof_type = "differential"
                res.severity = "high"
                res.control_body = control["body"]
                res.test_body = test["body"]
                res.test = {k: test[k] for k in ("status", "len")}
                res.differential = (
                    f"Neighbour id {nurl} returned a different valid protected object "
                    f"(status {test['status']}, body {test['len']}B, only {sim:.0%} "
                    "similar to the user's own) — direct object reference is not "
                    "scoped to the owner.")
                return res
        res.notes = "neighbour ids returned 4xx/empty/identical — IDOR not demonstrated"
        return res

    @staticmethod
    def _neighbor_urls(object_url: str, neighbor_ids: Optional[list]) -> list:
        """Derive neighbour-object URLs by perturbing the numeric id in the url."""
        out = []
        m = _ID_IN_PATH_RE.search(object_url) or _ID_IN_QUERY_RE.search(object_url)
        if not m:
            return out
        cur = int(m.group(2))
        ids = neighbor_ids or [cur + 1, cur - 1, 1, cur + 2]
        for nid in ids:
            if nid == cur or nid < 0:
                continue
            new_url = object_url[:m.start(2)] + str(nid) + object_url[m.end(2):]
            if new_url not in out:
                out.append(new_url)
        return out[:5]
