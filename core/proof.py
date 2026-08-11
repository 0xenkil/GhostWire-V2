"""core/proof.py — the one deterministic proof seam (P0-2).

Every trust decision in the engine keys on a single fact: does a finding carry a
``[proof:<16hex>]`` token that resolves, in the ProofLedger, to an Evidence
object whose ``is_proven()`` RE-COMPUTES True? Proof is therefore *measured*,
never asserted by an emitter substring like ``"VULN_PROVEN"``.

- ``ProofContext``  — the measured inputs a proof method reasons over.
- ``ProofRegistry`` — ``name -> ProofMethod``; runtime-extensible (zero-hardcode).
- ``ProofLedger``   — the SOLE writer/reader of proof state. ``stamp()`` is the
  only way to obtain an evidence id, and only AFTER a re-measured ``is_proven()``
  returns True.
- ``finding_is_proven(finding, ledger)`` — THE one gate every consumer calls.

Design invariants:
- ``stamp()`` never accepts a pre-built Evidence (closes the hand-forge hole).
- The evidence id is CONTENT-ADDRESSED (sha256 of the canonical Evidence), so an
  idempotent ``INSERT OR IGNORE`` plus a late-write replay can never create a
  phantom or duplicate row (see STATE-1 / P0-0a).
- Persistence is a dedicated table written through state_store's single-writer
  queue — never a KV read-modify-write map (which lost updates under a 10-way
  ThreadPoolExecutor).

Autonomy / no-hardcode: every method keys on capability + measurement and is
runtime-extensible via ``ProofRegistry.register()``. ``artifact_reflection``
works for ANY leaked string (absent-in-control vs present-in-test), never a fixed
marker list. Zero new LLM passes — the seam only *measures*.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from core.result_contracts import Evidence


@dataclass
class ProofContext:
    """The measured inputs a proof method reasons over. A method receives ONLY
    this — never emitter prose, a tool name, or a claimed verdict."""
    control_response: str = ""
    test_response: str = ""
    control_latency: float = -1.0
    test_latency: float = -1.0
    oob_events: list = field(default_factory=list)
    canary: str = ""
    command: str = ""
    notes: str = ""


ProofMethod = Callable[[ProofContext], Optional[Evidence]]


def _similarity(a: str, b: str) -> float:
    """Reuse the engine's single similarity definition so 'differs from baseline'
    means the same thing everywhere (plan §3.1: reuse hypothesis_engine)."""
    try:
        from intelligence.hypothesis_engine import HypothesisEngine
        return float(HypothesisEngine._response_similarity(a or "", b or ""))
    except Exception:
        # Deterministic fallback so proof never silently succeeds because the
        # similarity import failed.
        a = (a or "").strip()
        b = (b or "").strip()
        if not a or not b:
            return 0.0
        if a == b:
            return 1.0
        import difflib
        return difflib.SequenceMatcher(None, a[:4000], b[:4000]).quick_ratio()


# ── built-in proof methods ──────────────────────────────────────────────────

def _differential(ctx: ProofContext) -> Optional[Evidence]:
    """Impact proven by a MEASURED control-vs-test response differential."""
    if not (ctx.control_response and ctx.test_response):
        return None
    sim = _similarity(ctx.control_response, ctx.test_response)
    return Evidence(
        proof_type="differential",
        reproducible_command=ctx.command,
        request=ctx.command,
        response_excerpt=ctx.test_response[:2000],
        baseline_excerpt=ctx.control_response[:1000],
        differential=(ctx.notes or f"control vs test differ (similarity={sim:.3f})"),
        similarity_to_baseline=sim,
        notes=ctx.notes,
    )


def _artifact_reflection(ctx: ProofContext) -> Optional[Evidence]:
    """Impact proven by a self-proving artifact (a leaked string / canary) that
    is PRESENT in the test response and ABSENT from the control. Works for ANY
    string — never a fixed list of markers."""
    token = (ctx.canary or "").strip()
    if len(token) < 4:
        return None
    # A real control MUST have been captured: with an empty control we cannot
    # claim the artifact was ABSENT there, so "absent" would be trivially true
    # and any string in the test response would forge a proof. Require it.
    if not (ctx.control_response or "").strip():
        return None
    present = token in (ctx.test_response or "")
    absent = token not in (ctx.control_response or "")
    return Evidence(
        proof_type="artifact",
        reproducible_command=ctx.command,
        request=ctx.command,
        response_excerpt=(ctx.test_response or "")[:2000],
        baseline_excerpt=(ctx.control_response or "")[:1000],
        control_absent=absent,
        test_present=present,
        notes=ctx.notes,
    )


def _oob_callback(ctx: ProofContext) -> Optional[Evidence]:
    """Impact proven by an out-of-band callback carrying the planted canary."""
    token = (ctx.canary or "").strip()
    matched = ""
    if token:
        for ev in (ctx.oob_events or []):
            if token in str(ev):
                matched = token
                break
    # A callback observed with no canary planted to bind it is not attributable
    # proof; a token with no matching callback is likewise unproven.
    return Evidence(
        proof_type="oob",
        reproducible_command=ctx.command,
        request=ctx.command,
        oob_token=matched,
        notes=ctx.notes,
    )


def _time_delta(ctx: ProofContext) -> Optional[Evidence]:
    """Impact proven by a MEASURED timing differential (blind/time-based). The
    test arm must be materially slower than control by a real margin; encoded as
    a differential Evidence whose similarity reflects whether the delay is
    convincing (so it flows through the one hardened is_proven threshold)."""
    if ctx.control_latency < 0 or ctx.test_latency < 0:
        return None
    convincing = (ctx.test_latency >= 2.0
                  and ctx.test_latency >= 2.0 * max(ctx.control_latency, 1e-6))
    sim = 0.0 if convincing else 0.99
    return Evidence(
        proof_type="differential",
        reproducible_command=ctx.command,
        request=ctx.command,
        differential=(ctx.notes or
                      f"time-based: control={ctx.control_latency:.2f}s "
                      f"test={ctx.test_latency:.2f}s"),
        similarity_to_baseline=sim,
        notes=ctx.notes,
    )


class ProofRegistry:
    """Registry of proof methods, keyed by capability name. Runtime-extensible so
    a new vuln class = one ``register()`` call, never a core edit."""
    _methods: dict = {}

    @classmethod
    def register(cls, name: str, fn: ProofMethod) -> None:
        if not name or not callable(fn):
            raise ValueError("register(name, fn): a name and a callable are required")
        cls._methods[name] = fn

    @classmethod
    def get(cls, name: str) -> Optional[ProofMethod]:
        return cls._methods.get(name)

    @classmethod
    def build(cls, method: str, ctx: ProofContext) -> Optional[Evidence]:
        fn = cls._methods.get(method)
        if fn is None:
            return None
        try:
            ev = fn(ctx)
        except Exception:
            return None
        return ev if isinstance(ev, Evidence) else None

    @classmethod
    def methods(cls) -> list:
        return sorted(cls._methods.keys())


def _authz_shared_object(ctx: ProofContext) -> Optional[Evidence]:
    """Cross-identity object leak (BOLA-style): an identity that must NOT see a
    protected object (test_response) received the SAME object as the legitimate
    owner (control_response). Unlike a generic differential, the PROOF is HIGH
    similarity — the same protected body was served across a trust boundary.

    This is the measured inverse of _differential and is kept a distinct method
    so the two never get conflated. Re-measures similarity from the two bodies
    the caller passed; a caller cannot forge the verdict by asserting it."""
    control = ctx.control_response or ""
    test = ctx.test_response or ""
    if not control or len(test.strip()) < 40:
        return None
    sim = _similarity(control, test)
    if sim < 0.9:
        return None
    # Modelled as an artifact: the protected object (present in the test
    # response) reached an identity for which it must be absent. control_absent /
    # test_present are DERIVED from the re-measured leak condition, exactly as
    # _artifact_reflection derives them from a canary.
    return Evidence(
        proof_type="artifact",
        reproducible_command=ctx.command,
        request=ctx.command,
        response_excerpt=test[:2000],
        baseline_excerpt=control[:1000],
        control_absent=True,
        test_present=True,
        notes=(ctx.notes or f"cross-identity object leak (similarity {sim:.0%})"),
    )


# ── P5-6 (D-FUT-1): reference proof methods for three more vuln classes ───────
# The ProofRegistry is the vuln-class EXTENSION SEAM: a new class = one register()
# call whose method returns an Evidence that flows through the hardened is_proven,
# never a bespoke `waf_bypassed:True` assert. These three back the existing
# arsenal detectors (CacheDeceptionProbe / AuthzTester / origin_discovery) so a
# detection becomes a MEASURED proof, not a claimed one.

def _cache_deception(ctx: ProofContext) -> Optional[Evidence]:
    """Web cache deception: a PRIVATE datum (the planted canary) that must never
    be cached appears in the edge-CACHED response (test) and is ABSENT from a
    clean control fetch — the private data leaked into a shared cache. Artifact-
    style with the same rigor as _artifact_reflection: a real control MUST exist
    (else 'absent' is trivially true and any string would forge the proof)."""
    token = (ctx.canary or "").strip()
    if len(token) < 4:
        return None
    if not (ctx.control_response or "").strip():
        return None
    present = token in (ctx.test_response or "")
    absent = token not in (ctx.control_response or "")
    return Evidence(
        proof_type="artifact",
        reproducible_command=ctx.command,
        request=ctx.command,
        response_excerpt=(ctx.test_response or "")[:2000],
        baseline_excerpt=(ctx.control_response or "")[:1000],
        control_absent=absent,
        test_present=present,
        notes=(ctx.notes or "web cache deception: private datum served from a shared/edge cache"),
    )


def _origin_reachable(ctx: ProofContext) -> Optional[Evidence]:
    """WAF bypass via origin discovery: a DIRECT connection to the candidate
    origin (test_response) serves the SAME application as the WAF-fronted host
    (control_response). HIGH similarity proves the discovered IP is the true
    origin and the WAF can be bypassed by talking to it directly. Same measured-
    inverse-of-differential shape as _authz_shared_object — similarity is
    RE-MEASURED from the two bodies so the caller cannot assert the verdict."""
    control = ctx.control_response or ""
    test = ctx.test_response or ""
    if len(control.strip()) < 40 or len(test.strip()) < 40:
        return None
    sim = _similarity(control, test)
    if sim < 0.9:
        return None
    return Evidence(
        proof_type="artifact",
        reproducible_command=ctx.command,
        request=ctx.command,
        response_excerpt=test[:2000],
        baseline_excerpt=control[:1000],
        control_absent=True,
        test_present=True,
        notes=(ctx.notes or f"origin reachable directly behind the WAF (similarity {sim:.0%})"),
    )


# Built-ins registered at import (still runtime-extensible via register()).
ProofRegistry.register("differential", _differential)
ProofRegistry.register("artifact_reflection", _artifact_reflection)
ProofRegistry.register("oob_callback", _oob_callback)
ProofRegistry.register("time_delta", _time_delta)
ProofRegistry.register("authz_shared_object", _authz_shared_object)
# P5-6 reference methods (authz_tester aliases the existing shared-object proof).
ProofRegistry.register("cache_deception", _cache_deception)
ProofRegistry.register("authz_tester", _authz_shared_object)
ProofRegistry.register("test_origin_connection", _origin_reachable)


PROOF_TOKEN_RE = re.compile(r'\[proof:([0-9a-f]{16})\]')


def extract_proof_id(detail: Optional[str]) -> str:
    """None-safe extraction of the first ``[proof:<16hex>]`` token, or ''."""
    if not detail:
        return ""
    m = PROOF_TOKEN_RE.search(str(detail))
    return m.group(1) if m else ""


def _evidence_id(evidence: Evidence) -> str:
    """Content-addressed 16-hex id: the same measured evidence => the same id,
    so INSERT OR IGNORE + a late-write replay are idempotent."""
    payload = json.dumps(evidence.to_dict(), sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:16]


class ProofLedger:
    """The SOLE writer/reader of proof state for one engagement."""

    def __init__(self, store, engagement_id: str):
        self.store = store
        self.engagement_id = engagement_id

    def stamp(self, method: str, ctx: ProofContext, *,
              vuln_class: str = "", title: str = "", severity: str = "") -> str:
        """Build Evidence via ProofRegistry, RE-MEASURE ``is_proven()``, and
        persist + return a 16-hex id ONLY if proven; else ''. This is the ONLY
        way to obtain an evidence id — no caller may hand in a pre-built
        Evidence, so proof cannot be forged upstream of the ledger."""
        evidence = ProofRegistry.build(method, ctx)
        if evidence is None or not evidence.is_proven():
            return ""
        eid = _evidence_id(evidence)
        try:
            self.store.stamp_proof(
                self.engagement_id, eid, evidence.proof_type,
                json.dumps(evidence.to_dict(), default=str),
                vuln_class=vuln_class, title=title, severity=severity)
        except Exception:
            # A durable-write failure must NOT yield a usable id the caller would
            # treat as proven (STATE-1 safe direction: demote, never fabricate).
            return ""
        return eid

    def get(self, evidence_id: str) -> Optional[Evidence]:
        if not evidence_id:
            return None
        try:
            d = self.store.get_proof(self.engagement_id, evidence_id)
        except Exception:
            return None
        return Evidence.from_dict(d) if d else None

    def is_proven(self, evidence_id: str) -> bool:
        """Resolve the id and RE-COMPUTE ``is_proven()`` from the persisted
        measurement — never trust the id's mere existence."""
        ev = self.get(evidence_id)
        return bool(ev and ev.is_proven())


def finding_is_proven(finding: dict, ledger: Optional[ProofLedger]) -> bool:
    """THE one gate every trust consumer calls. Extract the finding's proof
    token, resolve it in the ledger, and RE-COMPUTE ``is_proven()``. A missing
    ledger, a missing token, an unresolved token, or evidence that no longer
    re-measures as proven ALL => False. It never trusts a substring."""
    if not finding or ledger is None:
        return False
    detail = finding.get("detail") if isinstance(finding, dict) else None
    eid = extract_proof_id(detail)
    if not eid:
        return False
    return ledger.is_proven(eid)
