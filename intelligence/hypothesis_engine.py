"""
Hypothesis Engine: the "security researcher" brain of the engine.

Philosophy (per operator directive): this is NOT a CVE-lookup bot. We do not
want "tech == WordPress 5.8 -> run CVE-2021-39200". Instead the engine reasons
about the SPECIFIC observed behaviour of THIS target (its endpoints, parameters,
forms, headers, response anomalies, auth flows, object references, etc.) and
proposes NOVEL, concrete, testable vulnerability hypotheses — the way a human
researcher hunting for a fresh bug or a zero-day would. Known CVEs are passed in
only as ONE cheap seed signal ("low-hanging fruit"), never as the core.

The loop this enables:  observe -> hypothesise -> test -> validate -> refine.

- generate_hypotheses(): AI proposes ranked, testable hypotheses from evidence.
- validate_result():     AI rigorously judges a tool result against a
                         hypothesis's expected-if-vulnerable signal, producing a
                         confirmed / refuted / inconclusive verdict so we emit
                         VERIFIED findings (real PoCs) — not "a command ran".

Everything here is AI-driven. There are no hardcoded vulnerability tables or
exploit playbooks; the only static content is the reasoning scaffold that tells
the model HOW to think like a researcher.
"""

import json
import uuid
from typing import Any, Dict, List, Optional


# Vulnerability classes used purely to *prompt breadth* of thinking — they are
# hints to widen the AI's search, NOT a checklist it must follow and NOT mapped
# to any canned exploit. The model is explicitly told it may go beyond them.
_VULN_CLASS_HINTS = [
    "broken access control (IDOR / BOLA / forced browsing / privilege escalation)",
    "authentication & session flaws (auth bypass, weak/forgeable tokens, JWT confusion)",
    "injection into DISCOVERED parameters (SQLi, NoSQLi, command, template/SSTI, LDAP)",
    "server-side request forgery (SSRF) and its blind/OOB variants",
    "business-logic & workflow abuse (price/quantity tampering, state skipping, race conditions)",
    "insecure deserialization / object injection",
    "file handling (path traversal, arbitrary upload, LFI/RFI, XXE)",
    "secrets / sensitive data exposure (keys, configs, backups, source, debug endpoints)",
    "HTTP request smuggling / desync, cache poisoning/deception",
    "client-side (stored/reflected/DOM XSS, prototype pollution) where it crosses a trust boundary",
    "misconfiguration & exposed admin/management interfaces and APIs",
    "novel / target-specific logic that does not fit a standard class",
]


class HypothesisEngine:
    """AI-driven novel-vulnerability hypothesis generation and PoC validation."""

    def __init__(self, ai_backend=None, state_store=None, logger=None):
        self.ai = ai_backend
        self.store = state_store
        self.log = logger
        self.history: List[Dict[str, Any]] = []

    # ──────────────────────────────────────────────────────────────────
    #  HYPOTHESIS GENERATION
    # ──────────────────────────────────────────────────────────────────

    def generate_hypotheses(
        self,
        evidence: Dict[str, Any],
        target: str,
        mode: str = "pentest",
        known_cve_seeds: Optional[List[Dict[str, Any]]] = None,
        prior_results: Optional[List[Dict[str, Any]]] = None,
        max_hypotheses: int = 8,
    ) -> List[Dict[str, Any]]:
        """Reason over observed evidence and propose novel, testable hypotheses.

        Args:
            evidence: structured observations about the target. Recognised keys
                (all optional): tech_stack, services, endpoints, parameters,
                forms, interesting_headers, response_anomalies, auth, subdomains,
                object_refs, notes.
            target: the target URL/host (for context only).
            mode: "pentest" | "redteam" (affects aggressiveness).
            known_cve_seeds: optional list of known-CVE hints (one cheap signal).
            prior_results: optional list of {hypothesis, verdict, evidence} from
                earlier loops so the AI refines instead of repeating.
            max_hypotheses: soft cap on how many to return.

        Returns:
            List of hypothesis dicts (see _normalise_hypothesis for schema).
            Empty list if the AI backend is unavailable or returns nothing usable.
        """
        if not self.ai:
            return []

        evidence_json = json.dumps(evidence, indent=2, default=str)[:8000]
        seeds_json = json.dumps(known_cve_seeds or [], default=str)[:2000]
        prior_json = json.dumps(prior_results or [], default=str)[:2500]
        aggressiveness = (
            "Assume an authorised red-team engagement: prefer high-impact, "
            "chained, multi-step hypotheses."
            if mode == "redteam"
            else "Authorised pentest: favour clearly demonstrable, lower-blast-radius proofs."
        )
        class_hints = "\n".join(f"  - {c}" for c in _VULN_CLASS_HINTS)

        prompt = f"""You are an elite offensive security researcher hunting for REAL, \
target-specific vulnerabilities on an authorised engagement. You are NOT a \
vulnerability-scanner that matches versions to a CVE list. Your value is finding \
the bug a scanner would MISS by reasoning about how THIS application actually behaves.

Target: {target}
Mode: {mode}. {aggressiveness}

### OBSERVED EVIDENCE (what we have actually seen on this target)
{evidence_json}

### KNOWN-CVE SEEDS (one cheap signal — treat as low-hanging fruit, do NOT let it dominate)
{seeds_json}

### PRIOR TEST RESULTS THIS ENGAGEMENT (refine; never repeat a refuted idea verbatim)
{prior_json}

### HOW TO THINK
Reason like a researcher, not a checklist:
1. Look at the SPECIFIC endpoints, parameters, object references, headers and \
response anomalies above. What does the app's behaviour imply about its trust \
boundaries, data model, and assumptions?
2. Form hypotheses about where those assumptions BREAK — including NOVEL or \
target-specific logic flaws that have no CVE. Aim for at least half of your \
hypotheses to be discovery of new issues rather than known-CVE checks.
3. Widen your search across (but do not limit yourself to) these classes:
{class_hints}
4. Every hypothesis MUST be concretely TESTABLE now with command-line tools and \
MUST state the exact observable signal that would CONFIRM it (so a later step can \
validate the PoC objectively). Vague hypotheses are useless.

### OUTPUT — strict JSON array, at most {max_hypotheses} items, ranked best-first:
[
  {{
    "vuln_class": "short class label, e.g. 'IDOR' or 'novel-logic'",
    "title": "one-line specific claim, e.g. 'order_id in /api/orders is a direct object reference'",
    "location": "exact endpoint / parameter / header this targets",
    "rationale": "WHY this target's observed behaviour suggests this bug",
    "novelty": "novel | variant | known_cve",
    "test_plan": [
      {{"tool": "curl|sqlmap|ffuf|...", "command": "exact command to run, use {{target}} for base URL", "expected_if_vulnerable": "the precise observable that proves it (status/body/diff/timing/OOB)"}}
    ],
    "confidence": 0.0-1.0,
    "impact": "what an attacker gains if confirmed"
  }}
]
Output ONLY the JSON array. No prose."""

        try:
            resp = self.ai.query(
                "You are an elite, rigorous offensive security researcher. "
                "You prize novel, testable findings and you never invent results.",
                prompt,
            )
        except Exception as e:
            if self.log:
                self.log.warning(f"HypothesisEngine generation failed: {e}")
            return []

        hyps = self._extract_json_array(resp)
        out: List[Dict[str, Any]] = []
        for h in hyps[:max_hypotheses]:
            norm = self._normalise_hypothesis(h)
            if norm:
                out.append(norm)
        # Rank by confidence (desc); stable for ties.
        out.sort(key=lambda x: x.get("confidence", 0.0), reverse=True)
        self.history.append({"target": target, "count": len(out)})
        return out

    # ──────────────────────────────────────────────────────────────────
    #  POC VALIDATION
    # ──────────────────────────────────────────────────────────────────

    def validate_result(
        self,
        hypothesis: Dict[str, Any],
        command: str,
        stdout: str,
        stderr: str = "",
        status: str = "",
        baseline: str = "",
    ) -> Dict[str, Any]:
        """Rigorously judge whether a tool result confirms a hypothesis.

        Returns a dict:
            {
              "verdict": "confirmed" | "refuted" | "inconclusive",
              "confidence": 0.0-1.0,
              "evidence": "the concrete bytes/behaviour that justify the verdict",
              "severity": "critical|high|medium|low|info",
              "refinement": optional next command to disambiguate (str or None),
            }
        Fails closed to "inconclusive" so we never fabricate a confirmation.
        """
        if not self.ai:
            return {"verdict": "inconclusive", "confidence": 0.0,
                    "evidence": "No AI backend to validate.", "severity": "info",
                    "refinement": None}

        expected = "; ".join(
            step.get("expected_if_vulnerable", "")
            for step in hypothesis.get("test_plan", [])
            if isinstance(step, dict)
        ) or hypothesis.get("title", "")

        out_blob = ((stdout or "")[:4000] + "\n--STDERR--\n" + (stderr or "")[:800])
        baseline_blob = (baseline or "")[:1500]

        prompt = f"""You are validating a vulnerability PoC on an authorised engagement. \
Be a skeptical reviewer: confirm ONLY when the evidence objectively matches the \
expected proof. False positives are worse than misses.

### HYPOTHESIS
Class: {hypothesis.get('vuln_class', '?')}
Claim: {hypothesis.get('title', '?')}
Location: {hypothesis.get('location', '?')}
Expected-if-vulnerable signal: {expected}

### COMMAND RUN
{command}

### BASELINE (normal response for comparison, may be empty)
{baseline_blob}

### ACTUAL RESULT (stdout + stderr, truncated)
{out_blob}
Exit/status: {status}

### DECIDE
- "confirmed": the actual result clearly exhibits the expected proof signal AND you can name the
  PROOF: either (a) a concrete DIFFERENTIAL — what is observably different from the baseline/normal
  response — or (b) a self-proving ARTIFACT (e.g. /etc/passwd contents, a data dump, an OOB callback).
- "refuted": the result clearly does NOT exhibit it (e.g. 403/blocked, identical to baseline, error).
- "inconclusive": ambiguous, WAF-blocked, or needs another probe.
Do not confirm on a tool merely running, a generic 200, or reflected input without impact.
A "confirmed" with proof_type "none" is INVALID — if you cannot name the proof, it is not confirmed.

### PROOF TYPE
- "differential": you can describe a concrete delta vs the baseline (status, length, content, timing).
- "artifact": the response contains self-proving content that a normal response never would.
- "oob": an out-of-band signal (DNS/HTTP callback) fired.
- "none": no proof — must NOT be paired with "confirmed".

### OUTPUT — strict JSON object only:
{{"verdict": "confirmed|refuted|inconclusive", "confidence": 0.0-1.0, "evidence": "the specific bytes/behaviour that decide it", "proof_type": "differential|artifact|oob|none", "differential": "what is observably different from normal (or empty)", "severity": "critical|high|medium|low|info", "refinement": "a single next command to disambiguate, or null"}}"""

        try:
            resp = self.ai.query(
                "You are a rigorous PoC validator. You never confirm without proof.",
                prompt,
            )
        except Exception as e:
            if self.log:
                self.log.warning(f"HypothesisEngine validation failed: {e}")
            return {"verdict": "inconclusive", "confidence": 0.0,
                    "evidence": f"validation error: {e}", "severity": "info",
                    "refinement": None}

        verdict = self._extract_json_object(resp)
        if not isinstance(verdict, dict) or "verdict" not in verdict:
            return {"verdict": "inconclusive", "confidence": 0.0,
                    "evidence": "Validator returned no parseable verdict.",
                    "severity": "info", "refinement": None}

        v = str(verdict.get("verdict", "inconclusive")).lower().strip()
        if v not in ("confirmed", "refuted", "inconclusive"):
            v = "inconclusive"
        try:
            conf = float(verdict.get("confidence", 0.0))
        except (TypeError, ValueError):
            conf = 0.0
        sev = str(verdict.get("severity", "info")).lower().strip()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"
        refinement = verdict.get("refinement")
        if isinstance(refinement, str) and refinement.strip().lower() in ("", "null", "none"):
            refinement = None

        proof_type = str(verdict.get("proof_type", "none")).lower().strip()
        if proof_type not in ("differential", "artifact", "oob", "none"):
            proof_type = "none"
        differential = str(verdict.get("differential", "")).strip()

        # NOTE: a previous pre-filter here downgraded ANY "confirmed" whose
        # response was ~identical to the baseline — REGARDLESS of proof_type. That
        # silently DISCARDED valid vulns proven by an ARTIFACT (a SQL error,
        # reflected XSS payload, leaked /etc/passwd, or stack trace IN the
        # response — which can sit inside an otherwise-identical page) or by an
        # OOB callback (whose proof is out-of-band, so response similarity is
        # irrelevant). It was a real driver of "0 proven". The proof_type-AWARE
        # MANDATORY EVIDENCE GATE below (Evidence.is_proven) is the correct check:
        # it accepts artifact/oob proofs and validates a differential against the
        # baseline (requires similarity < 0.97). So the buggy pre-filter is gone.

        # ── WS4: MANDATORY DIFFERENTIAL / EVIDENCE GATE ──────────────────────
        # A "confirmed" verdict must carry real proof. If the AI confirmed but
        # named proof_type "none" (or a "differential" with no described delta),
        # there is nothing to stand on — fail closed to a lead. This is the
        # generalization of the differential guard to the no-baseline case.
        if v == "confirmed":
            measured_sim = (
                self._response_similarity(stdout or "", baseline or "")
                if (baseline or "").strip() else -1.0)
            evidence_obj = self._build_evidence(
                proof_type, command, stdout, baseline, differential, measured_sim, verdict)
            if not evidence_obj.is_proven():
                if self.log:
                    self.log.info(
                        "HypothesisEngine: downgrading 'confirmed' -> 'inconclusive' — "
                        f"no demonstrable proof (proof_type={proof_type}, "
                        f"differential={'yes' if differential else 'no'}).")
                return {"verdict": "inconclusive", "confidence": min(conf, 0.4),
                        "evidence": ("[evidence gate] Confirmed without a demonstrable "
                                     "differential or self-proving artifact — treated as a "
                                     "lead. " + str(verdict.get("evidence", "")))[:600],
                        "severity": "info", "proof_type": "none",
                        "evidence_obj": evidence_obj.to_dict(),
                        "refinement": refinement}
            # W4.3 — severity from impact, not keywords: cap the AI's claimed
            # severity by what the proof actually demonstrates.
            sev = self._cap_severity_by_proof(sev, proof_type, differential, hypothesis)
            return {"verdict": v, "confidence": max(0.0, min(1.0, conf)),
                    "evidence": str(verdict.get("evidence", ""))[:600],
                    "severity": sev, "proof_type": proof_type,
                    "evidence_obj": evidence_obj.to_dict(),
                    "refinement": refinement}

        return {"verdict": v, "confidence": max(0.0, min(1.0, conf)),
                "evidence": str(verdict.get("evidence", ""))[:600],
                "severity": sev, "proof_type": proof_type, "refinement": refinement}

    def _build_evidence(self, proof_type: str, command: str, stdout: str,
                        baseline: str, differential: str, similarity: float,
                        verdict: dict | None = None):
        """Assemble the structured Evidence object for a verdict (WS4).

        P0-1: for artifact/oob the proof must be MEASURED, not merely asserted by
        the AI's ``proof_type``. Artifact reflection is measured against the
        response/baseline the gate already holds — the proving excerpt must be
        PRESENT in the test response and ABSENT from the control — and OOB carries
        the unique token that was actually observed. An AI that only *claims*
        proof_type='artifact'/'oob' with no such measurement fails is_proven and
        is downgraded to a lead, closing the assertion-as-proof forgery.
        """
        from core.result_contracts import Evidence
        verdict = verdict or {}
        art_absent = False
        art_present = False
        oob_token = ""
        if proof_type == "artifact":
            excerpt = str(
                verdict.get("artifact_excerpt")
                or verdict.get("artifact_locator")
                or verdict.get("evidence") or "").strip()
            # Require a non-trivial excerpt so a proof can't ride on empty/short
            # noise that would coincidentally match.
            if len(excerpt) >= 6:
                art_present = excerpt in (stdout or "")
                art_absent = excerpt not in (baseline or "")
        elif proof_type == "oob":
            oob_token = str(
                verdict.get("oob_token") or verdict.get("oob_interaction") or "").strip()
        return Evidence(
            proof_type=proof_type,
            reproducible_command=command or "",
            request=command or "",
            response_excerpt=(stdout or "")[:2000],
            baseline_excerpt=(baseline or "")[:1000],
            differential=differential or "",
            similarity_to_baseline=similarity,
            control_absent=art_absent,
            test_present=art_present,
            oob_token=oob_token,
            notes="",
        )

    @staticmethod
    def _cap_severity_by_proof(claimed: str, proof_type: str,
                               differential: str, hypothesis: dict) -> str:
        """W4.3 — severity reflects demonstrated impact, not the vuln-class name.

        The AI may label a reflected-input differential 'critical' because the
        class is 'XSS'; but if all we proved is a reflection (not execution /
        data access / control), the demonstrated impact is lower. We cap the
        claimed severity by the strength of the proof so the report's severity
        tables mean something.
        """
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        claimed_rank = order.get(claimed, 0)
        impact_text = (str(hypothesis.get("impact", "")) + " " + differential).lower()

        # Self-proving artifacts / OOB demonstrate real impact → allow as-is.
        if proof_type in ("artifact", "oob"):
            cap = 4
        else:  # differential only
            # A differential that demonstrates data access / code exec / auth
            # bypass keeps high; a bare reflection/length-delta is capped.
            strong_markers = (
                "extracted", "dumped", "rows", "password", "credential", "token",
                "/etc/passwd", "code execution", "rce", "shell", "auth bypass",
                "authentication bypass", "admin access", "privilege", "ssrf to",
                "read file", "arbitrary file")
            if any(m in impact_text for m in strong_markers):
                cap = 4
            else:
                cap = 2  # medium — a real but lower-impact differential
        capped_rank = min(claimed_rank, cap)
        inv = {v: k for k, v in order.items()}
        return inv[capped_rank]

    @staticmethod
    def _response_similarity(a: str, b: str) -> float:
        """Cheap similarity in [0,1] between two tool/HTTP responses, used to
        detect 'the bypass returned the same page as baseline'. Compares a
        capped prefix so large bodies stay fast."""
        a = (a or "").strip()
        b = (b or "").strip()
        if not a or not b:
            return 0.0
        if a == b:
            return 1.0
        import difflib
        cap = 4000
        return difflib.SequenceMatcher(None, a[:cap], b[:cap]).quick_ratio()

    # ──────────────────────────────────────────────────────────────────
    #  helpers
    # ──────────────────────────────────────────────────────────────────

    def _normalise_hypothesis(self, h: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(h, dict):
            return None
        title = str(h.get("title") or h.get("vuln_class") or "").strip()
        if not title:
            return None
        plan_in = h.get("test_plan") or []
        plan: List[Dict[str, Any]] = []
        if isinstance(plan_in, list):
            for step in plan_in:
                if isinstance(step, dict) and step.get("command"):
                    plan.append({
                        "tool": str(step.get("tool", "")).strip(),
                        "command": str(step.get("command", "")).strip(),
                        "expected_if_vulnerable": str(step.get("expected_if_vulnerable", "")).strip(),
                    })
        if not plan:
            return None  # untestable hypotheses are useless
        try:
            conf = float(h.get("confidence", 0.5))
        except (TypeError, ValueError):
            conf = 0.5
        return {
            "id": uuid.uuid4().hex[:10],
            "vuln_class": str(h.get("vuln_class", "unknown")).strip()[:60],
            "title": title[:200],
            "location": str(h.get("location", "")).strip()[:200],
            "rationale": str(h.get("rationale", "")).strip()[:500],
            "novelty": str(h.get("novelty", "novel")).strip().lower()[:20],
            "test_plan": plan[:4],
            "confidence": max(0.0, min(1.0, conf)),
            "impact": str(h.get("impact", "")).strip()[:300],
            "status": "untested",
        }

    @staticmethod
    def _extract_json_array(text: str) -> List[Any]:
        if not text:
            return []
        try:
            from core.robust_parser import extract_json_list
            data = extract_json_list(text)
            if isinstance(data, list):
                return data
        except Exception:
            pass
        try:
            from core.result_contracts import FragileParseFixer
            data = FragileParseFixer.safe_split_json_extraction(text, default=[])
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return [data]
        except Exception:
            pass
        return []

    @staticmethod
    def _extract_json_object(text: str) -> Dict[str, Any]:
        if not text:
            return {}
        try:
            from core.robust_parser import extract_json_object
            data = extract_json_object(text)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        try:
            from core.result_contracts import FragileParseFixer
            data = FragileParseFixer.safe_split_json_extraction(text, default={})
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {}
