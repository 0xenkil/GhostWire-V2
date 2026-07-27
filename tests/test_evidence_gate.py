"""WS4 — Evidence & Differential Integrity tests."""

import json
import pytest

from intelligence.hypothesis_engine import HypothesisEngine
from core.result_contracts import Evidence


class _AI:
    """Mock AI returning a scripted verdict JSON."""

    def __init__(self, payload):
        self._payload = payload

    def query(self, system, user):
        return json.dumps(self._payload)


def _engine(payload):
    return HypothesisEngine(ai_backend=_AI(payload))


_HYP = {"vuln_class": "sqli", "title": "blind sqli in id", "location": "/api?id=",
        "impact": "data extraction", "test_plan": [{"expected_if_vulnerable": "db error"}]}


class TestEvidenceContract:
    def test_is_proven_semantics(self):
        assert not Evidence(proof_type="none").is_proven()
        assert Evidence(proof_type="artifact").is_proven()
        assert Evidence(proof_type="oob").is_proven()
        assert Evidence(proof_type="differential", differential="500 vs 200",
                        similarity_to_baseline=0.3).is_proven()
        assert not Evidence(proof_type="differential", differential="x",
                            similarity_to_baseline=0.99).is_proven()
        assert not Evidence(proof_type="differential", differential="").is_proven()


class TestMandatoryDifferential:
    def test_confirmed_without_proof_downgraded(self):
        """A 'confirmed' with proof_type none must fail closed to a lead."""
        v = _engine({"verdict": "confirmed", "confidence": 0.9,
                     "evidence": "the tool ran", "proof_type": "none",
                     "differential": "", "severity": "critical"}).validate_result(
            _HYP, "sqlmap -u x", stdout="some output", baseline="")
        assert v["verdict"] == "inconclusive"
        assert v["severity"] == "info"
        assert v["proof_type"] == "none"

    def test_confirmed_with_real_differential_kept(self):
        v = _engine({"verdict": "confirmed", "confidence": 0.9,
                     "evidence": "db error leaked", "proof_type": "differential",
                     "differential": "baseline 200/1kb, payload 500 with SQL syntax error and dumped rows",
                     "severity": "high"}).validate_result(
            _HYP, "sqlmap -u x", stdout="SQL syntax error near...50 rows", baseline="normal page")
        assert v["verdict"] == "confirmed"
        assert v["evidence_obj"]["proof_type"] == "differential"

    def test_confirmed_identical_to_baseline_downgraded(self):
        """The original differential guard still fires on ~identical responses."""
        same = "the exact same page body here " * 20
        v = _engine({"verdict": "confirmed", "confidence": 0.8,
                     "evidence": "got 200", "proof_type": "differential",
                     "differential": "claims bypass", "severity": "high"}).validate_result(
            _HYP, "curl x", stdout=same, baseline=same)
        assert v["verdict"] == "inconclusive"


class TestSeverityFromImpact:
    def test_reflection_only_capped(self):
        assert HypothesisEngine._cap_severity_by_proof(
            "critical", "differential", "input reflected", {"impact": "reflected"}) == "medium"

    def test_data_extraction_stays_critical(self):
        assert HypothesisEngine._cap_severity_by_proof(
            "critical", "differential", "dumped 50 rows with password hashes",
            {"impact": "data extracted"}) == "critical"

    def test_artifact_kept(self):
        assert HypothesisEngine._cap_severity_by_proof(
            "high", "artifact", "", {"impact": "/etc/passwd"}) == "high"
