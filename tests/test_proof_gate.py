"""Guard: the validation core must confirm ARTIFACT/OOB proofs (2026-06-20).

The hypothesis engine had a pre-filter that downgraded ANY "confirmed" verdict
whose response was ~identical to the baseline — regardless of proof_type. That
silently discarded vulns proven by an ARTIFACT (a SQL error / reflected payload /
leaked file content IN the response, which can sit inside an otherwise-identical
page) or by an OOB callback (proof is out-of-band, so response similarity is
irrelevant). A real driver of "0 proven". The proof_type-aware MANDATORY EVIDENCE
GATE (Evidence.is_proven) is the correct check; the buggy pre-filter was removed.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_BASE = "<html>normal page content here</html>"
_H = {"title": "SQLi", "vuln_class": "sqli", "expected_if_vulnerable": "SQL error"}


def _engine(payload):
    from intelligence.hypothesis_engine import HypothesisEngine

    class AI:
        def query(self, system, prompt, model_id=None):
            return json.dumps(payload)
    return HypothesisEngine(ai_backend=AI())


def _verdict(payload, stdout=_BASE, baseline=_BASE):
    return _engine(payload).validate_result(
        _H, "tool -u x", stdout=stdout, stderr="", status="success",
        baseline=baseline)["verdict"]


def test_artifact_proof_confirms_even_if_response_matches_baseline():
    assert _verdict({"verdict": "confirmed", "proof_type": "artifact",
                     "evidence": "SQL syntax error near ...", "differential": "",
                     "severity": "high", "confidence": 0.9}) == "confirmed"


def test_oob_proof_confirms_even_if_response_matches_baseline():
    assert _verdict({"verdict": "confirmed", "proof_type": "oob",
                     "evidence": "DNS callback received on collaborator",
                     "differential": "", "severity": "critical",
                     "confidence": 0.95}) == "confirmed"


def test_differential_without_real_delta_is_downgraded():
    # response identical to baseline -> a 'differential' proof is not real
    assert _verdict({"verdict": "confirmed", "proof_type": "differential",
                     "differential": "status 200 vs 403", "evidence": "x",
                     "severity": "high", "confidence": 0.8}) == "inconclusive"


def test_no_proof_is_downgraded():
    assert _verdict({"verdict": "confirmed", "proof_type": "none",
                     "evidence": "i think so", "differential": "",
                     "severity": "high", "confidence": 0.7},
                    stdout="<html>totally different</html>") == "inconclusive"
