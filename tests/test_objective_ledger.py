"""WS5 — Objective-Driven Orchestration tests."""

import pytest
from intelligence.objective_ledger import ObjectiveLedger


class TestTailoring:
    def test_spa_abandons_rce(self):
        tm = {"target_type": "spa",
              "implausible_vuln_classes": ["apex SQLi", "RCE", "command execution"]}
        L = ObjectiveLedger(target_model=tm)
        assert L.objectives["rce"].status == "abandoned"
        assert L.objectives["object_authz_bug"].tier == "primary"

    def test_no_model_keeps_all_pending(self):
        L = ObjectiveLedger()
        assert all(o.status == "pending" for o in L.objectives.values())


class TestProgress:
    def test_confirmed_idor_achieves_objective(self):
        L = ObjectiveLedger()
        newly = L.update_from_findings([
            {"type": "confirmed_vulnerability", "severity": "high",
             "detail": "VULN_PROVEN [IDOR] /api/orders/124 differential"}])
        assert "object_authz_bug" in newly
        assert L.objectives["object_authz_bug"].status == "achieved"

    def test_idle_streak_increments_without_progress(self):
        L = ObjectiveLedger()
        L.update_from_findings([])
        L.update_from_findings([])
        assert L.idle_streak == 2

    def test_progress_resets_idle(self):
        L = ObjectiveLedger()
        L.update_from_findings([])
        assert L.idle_streak == 1
        L.update_from_findings([
            {"type": "confirmed_vulnerability", "severity": "critical",
             "detail": "dumped rows password data extraction"}])
        assert L.idle_streak == 0


class TestStopConditions:
    def test_stop_when_primaries_resolved(self):
        tm = {"target_type": "spa", "implausible_vuln_classes": ["RCE"]}
        L = ObjectiveLedger(target_model=tm)  # rce abandoned
        L.update_from_findings([
            {"type": "confirmed_vulnerability", "severity": "high",
             "detail": "authenticated session acquired login successful"},
            {"type": "confirmed_vulnerability", "severity": "high",
             "detail": "VULN_PROVEN [BOLA] object-level authorization broken"},
            {"type": "confirmed_vulnerability", "severity": "critical",
             "detail": "extracted password credential secret data extraction"},
        ])
        stop, why = L.should_stop()
        assert stop
        assert "primary objectives resolved" in why.lower()

    def test_stop_on_exhaustion(self):
        L = ObjectiveLedger()
        for _ in range(6):
            L.update_from_findings([])
        stop, why = L.should_stop(idle_limit=6)
        assert stop
        assert "exhaustion" in why.lower()

    def test_no_stop_while_active_and_busy(self):
        L = ObjectiveLedger()
        stop, why = L.should_stop()
        assert not stop


class TestMomentum:
    def test_high_on_findings(self):
        L = ObjectiveLedger()
        assert L.momentum(produced_findings=True).startswith("HIGH")

    def test_low_after_idle_names_objective(self):
        L = ObjectiveLedger()
        L.update_from_findings([])
        m = L.momentum(produced_findings=False)
        assert m.startswith("LOW")
        assert "objective" in m.lower()

    def test_format_for_prompt_lists_objectives(self):
        L = ObjectiveLedger()
        s = L.format_for_prompt()
        assert "OBJECTIVE LEDGER" in s
        assert "Gain authenticated access" in s
