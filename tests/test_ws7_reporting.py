"""WS7 — Evidence & Reporting Integrity: two-tier findings, honest verdict, PoC export."""

import json
import pytest
from pathlib import Path

from agents.reporting_agent import ReportingAgent


class _Store:
    def __init__(self, kv=None):
        self._kv = kv or {}

    def get(self, key):
        return self._kv.get(key)


class _Session:
    def __init__(self, tmp):
        self.engagement_id = "eng_test"
        self.target = "https://t.lk"
        self.results_dir = tmp


def _agent(tmp_path, kv=None):
    a = ReportingAgent.__new__(ReportingAgent)
    import logging
    a.log = logging.getLogger("test")
    a.store = _Store(kv)
    a.session = _Session(tmp_path)
    return a


class TestTwoTier:
    def test_split_proven_vs_leads(self, tmp_path):
        # P0-8: proven = a resolvable ProofLedger token, NOT a finding type or a
        # "VULN_PROVEN" substring (that was REPORT-SPLIT-SUBSTR).
        from core.state_store import StateStore
        from core.proof import ProofLedger, ProofContext
        store = StateStore(":memory:")
        try:
            ledger = ProofLedger(store, "eng_test")
            eid = ledger.stamp("differential", ProofContext(
                control_response="the owner's own order page body",
                test_response="a DIFFERENT user's order 124 body",
                command="GET /api/orders/124"))
            assert eid
            a = _agent(tmp_path)
            a._proof_ledger = ledger
            findings = [
                {"type": "confirmed_vulnerability", "severity": "high",
                 "detail": f"[proof:{eid}] VULN_PROVEN [IDOR] /api/orders/124"},
                {"type": "exploit_lead", "severity": "info", "detail": "generic db keyword"},
                {"type": "waf_detected", "severity": "high",
                 "detail": "[UNVERIFIED LEAD — ops-sanity: ...] maybe waf"},
                {"type": "open_port", "severity": "medium", "detail": "443 open"},
                # substring-only "proof" with NO token must now be a LEAD
                {"type": "confirmed_vulnerability", "severity": "critical",
                 "detail": "VULN_PROVEN [RCE] trust me — no proof token"},
            ]
            proven, leads = a._split_two_tier(findings)
            assert len(proven) == 1
            assert "[proof:" in proven[0]["detail"]
            assert all("unverified lead" not in str(p.get("detail", "")).lower() for p in proven)
            assert len(leads) == 4
        finally:
            store.close()


class TestVerdict:
    def test_compromised_when_high_proven(self, tmp_path):
        a = _agent(tmp_path)
        v = a._engagement_verdict([{"severity": "high", "type": "confirmed_vulnerability"}])
        assert v["verdict"] == "COMPROMISED"

    def test_not_compromised_when_none(self, tmp_path):
        a = _agent(tmp_path)
        v = a._engagement_verdict([])
        assert v["verdict"] == "NOT COMPROMISED"

    def test_partial_when_only_low(self, tmp_path):
        a = _agent(tmp_path)
        v = a._engagement_verdict([{"severity": "low", "type": "confirmed_vulnerability"}])
        assert v["verdict"] == "PARTIAL"

    def test_verdict_cites_objectives(self, tmp_path):
        led = {"objectives": [
            {"label": "Prove object/function-level authz bug (IDOR/BOLA)", "status": "achieved"},
            {"label": "Achieve remote code execution", "status": "abandoned"},
        ]}
        a = _agent(tmp_path, kv={"eng_test:objective_ledger": json.dumps(led)})
        v = a._engagement_verdict([{"severity": "high", "type": "confirmed_vulnerability"}])
        assert "Objectives achieved" in v["rationale"]
        assert "IDOR/BOLA" in v["rationale"]


class TestPocExport:
    def test_export_writes_files(self, tmp_path):
        evidence = [{
            "vuln_class": "IDOR", "title": "IDOR at /api/orders/124", "severity": "high",
            "evidence": {
                "proof_type": "differential",
                "reproducible_command": "GET /api/orders/124 (cross-identity differential)",
                "request": "GET /api/orders/124", "response_excerpt": "{...other user...}",
                "baseline_excerpt": "{...own...}", "differential": "neighbour id returns other user's order",
            }}]
        a = _agent(tmp_path, kv={"eng_test:evidence_objects": json.dumps(evidence)})
        proven = [{"type": "confirmed_vulnerability", "severity": "high",
                   "detail": "VULN_PROVEN [IDOR]"}]
        a._export_pocs(proven, a._load_evidence_objects())
        jp = tmp_path / "poc_export.json"
        mp = tmp_path / "poc_export.md"
        assert jp.exists() and mp.exists()
        data = json.loads(jp.read_text(encoding="utf-8"))
        assert data["proven_vulnerabilities"] == 1
        assert data["pocs"][0]["proof_type"] == "differential"
        md = mp.read_text(encoding="utf-8")
        assert "Reproduce" in md and "IDOR" in md

    def test_export_fallback_without_evidence(self, tmp_path):
        a = _agent(tmp_path)
        proven = [{"type": "confirmed_vulnerability", "severity": "high",
                   "detail": "VULN_PROVEN [SQLi]", "command": "sqlmap -u x"}]
        a._export_pocs(proven, [])
        data = json.loads((tmp_path / "poc_export.json").read_text(encoding="utf-8"))
        assert len(data["pocs"]) == 1
        assert data["pocs"][0]["reproducible_command"] == "sqlmap -u x"
