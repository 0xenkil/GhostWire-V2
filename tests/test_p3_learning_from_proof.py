"""Phase 3 — learning-from-proof.

  P3-1  LearningOutcome: real proof (Tier 1) vs honest clean-execution fallback
        (Tier 2, reuses P0-9 produced_result); TruthGate admits only proof-backed,
        non-regressing change sets.
  P3-2  engagement_analyzer effectiveness is proof-anchored via the P0-10 exact
        join (findings.tool_run_id → tool_runs.id).
  P3-5  auto_upgrader apply path fails closed behind TruthGate; the inert
        corrupting _update_tool_metrics write is gone.
  P3-6  rule merge preserves file shape, id-dedups, writes atomically, and merges
        nothing without a TruthGate.
"""

import json
import os
import tempfile

import pytest

from core.state_store import StateStore
from core.result_contracts import ToolResult, ResultStatus, Evidence
from core.proof import ProofLedger, ProofContext
from intelligence.learning_signal import LearningOutcome, looks_like_failure
from intelligence.truth_gate import TruthGate
from intelligence.engagement_analyzer import EngagementAnalyzer
from intelligence.auto_upgrader import AutoUpgrader
from intelligence.rule_generator import RuleGenerator


def _proven_ev():
    return Evidence(proof_type="differential", similarity_to_baseline=0.3,
                    differential="neighbour id returns another user's order")


class TestLearningOutcome:
    def test_proof_backed_is_proven(self):
        o = LearningOutcome.from_confirmed_hypothesis("idor", _proven_ev())
        assert o.proven and o.is_proof_backed

    def test_unmeasured_proof_not_proven(self):
        ev = Evidence(proof_type="differential", similarity_to_baseline=-1.0,
                      differential="described but unmeasured")
        o = LearningOutcome.from_confirmed_hypothesis("x", ev)
        assert not o.proven and not o.is_proof_backed

    def test_clean_execution_fallback_needs_produced_result(self):
        r = ToolResult(tool="nmap", command="x", stdout="80/tcp open", stderr="",
                       exit_code=0, duration_seconds=1.0, status=ResultStatus.SUCCESS)
        r.parsed = {"open_ports": [80], "services": {"80": {}}}
        o = LearningOutcome.from_result("nmap", r, capability="port_scan")
        assert o.proven and not o.is_proof_backed  # Tier 2, not proof-backed

    def test_ran_clean_but_produced_nothing_is_not_proven(self):
        r = ToolResult(tool="nmap", command="x", stdout="0 hosts up", stderr="",
                       exit_code=0, duration_seconds=1.0, status=ResultStatus.SUCCESS)
        r.parsed = {"open_ports": [], "services": {}}
        assert not LearningOutcome.from_result("nmap", r, capability="port_scan").proven

    def test_marker_helper(self):
        assert looks_like_failure("bash: x: command not found")
        assert not looks_like_failure("all good")


class TestTruthGate:
    def test_admits_proof_backed_nonregressing(self):
        proven = [LearningOutcome.from_confirmed_hypothesis("nmap", _proven_ev())
                  for _ in range(10)]
        assert TruthGate(proven).supports({"tool": "nmap"}, min_proven=3)

    def test_rejects_too_few(self):
        proven = [LearningOutcome.from_confirmed_hypothesis("nmap", _proven_ev())
                  for _ in range(2)]
        assert not TruthGate(proven).supports({"tool": "nmap"}, min_proven=3)

    def test_ignores_clean_execution_outcomes(self):
        r = ToolResult(tool="nmap", command="x", stdout="80 open", stderr="",
                       exit_code=0, duration_seconds=1.0, status=ResultStatus.SUCCESS)
        r.parsed = {"open_ports": [80]}
        clean = [LearningOutcome.from_result("nmap", r, capability="port_scan")
                 for _ in range(10)]
        assert not TruthGate(clean).supports({"tool": "nmap"}, min_proven=3)


class TestEngagementAnalyzerProofAnchored:
    def test_effectiveness_and_waf_use_exact_join(self):
        s = StateStore(":memory:")
        try:
            eng = "eng_p3_join"
            rid = s.log_tool_run(eng, "recon", "nmap", "nmap -sV t", "success", "80 open", "", 0, 2.0)
            led = ProofLedger(s, eng)
            eid = led.stamp("differential", ProofContext(
                control_response="own", test_response="other user order", command="GET /o/124"))
            s.add_finding(eng, "exploit", "idor", "t", f"[proof:{eid}] IDOR", "high", tool_run_id=rid)
            # a run that is 'no_findings' (P0-9 honest) → counts as a failure
            s.log_tool_run(eng, "recon", "curl", "curl t", "no_findings", "", "", 0, 1.0)

            a = EngagementAnalyzer(s)
            eff = a._analyze_tool_effectiveness(eng)
            assert "nmap" in eff["proven_tools"]
            assert eff["tool_rates"]["nmap"]["proven"] == 1
            assert eff["tool_rates"]["curl"]["success_rate"] == 0.0

            waf = a._analyze_waf_patterns(eng)
            assert "nmap" in waf["tools_effective"] and "curl" not in waf["tools_effective"]
        finally:
            s.close()


class TestAutoUpgraderFailsClosed:
    def test_no_proof_zeroes_valid_changes(self):
        s = StateStore(":memory:")
        try:
            up = AutoUpgrader(store=s)
            opt = {"changes": {"tool_effectiveness": {"tool_rates_adjusted": {
                "gobuster": {"recommendation": "never_works"}}}}}
            rules = {"rules": {"exploitation": [{"id": "r1"}], "recon": [{"id": "r2"}]}}
            v = up._validate_changes(opt, rules, "eng_no_proof")
            assert v["truth_gated"] and v["valid_changes"] == 0
            assert not hasattr(up, "_update_tool_metrics")
        finally:
            s.close()


class TestRuleMergeDisarmed:
    def test_shape_preserved_iddedup_atomic(self):
        d = tempfile.mkdtemp()
        cfg = {"web_ports": [80, 443], "max_web_ports_to_test": 5,
               "rules": [{"id": "r1", "v": 1}]}
        with open(os.path.join(d, "exploitation.json"), "w") as f:
            json.dump(cfg, f)
        rg = RuleGenerator(d)
        rg._append_to_rule_file("exploitation", [{"id": "r2", "v": 2}, {"id": "r1", "v": 99}])
        out = json.load(open(os.path.join(d, "exploitation.json")))
        assert isinstance(out, dict) and out["web_ports"] == [80, 443]
        assert [r["id"] for r in out["rules"]] == ["r1", "r2"]
        assert [r for r in out["rules"] if r["id"] == "r1"][0]["v"] == 99
        assert not os.path.exists(os.path.join(d, "exploitation.json.tmp"))

    def test_merge_without_gate_merges_nothing(self):
        d = tempfile.mkdtemp()
        rg = RuleGenerator(d)
        cnt = rg.merge_rules_to_system(
            {"rules": {"exploitation": [{"id": "x", "confidence": 0.99}]}})
        assert all(v == 0 for v in cnt.values())
