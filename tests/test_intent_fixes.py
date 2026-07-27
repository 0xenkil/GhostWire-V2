"""Regression guards for the 2026-06-18 intent-vs-reality fixes.

Each test pins a contract that was *running fine but doing the wrong thing*:
- the syntax learner was re-teaching a discovered-hosts file as a fuzzing wordlist
- _situation_summary read per-instance findings (blank during exploitation) and
  mis-extracted the tech name from a "CMS: X" detail string
"""
import logging
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.CRITICAL)


class TestSyntaxLearnerDepoison:
    def _sl(self):
        from intelligence.syntax_learner import SyntaxLearner
        return SyntaxLearner()

    def test_workspace_file_as_wordlist_is_abstracted(self):
        sl = self._sl()
        ctx = {"workdir": "/home/en/redteam-workspace/eng_x",
               "target": "https://novalink.lk"}
        out = sl._abstract(
            "ffuf -u https://novalink.lk/FUZZ -w "
            "/home/en/redteam-workspace/eng_x/recon_hosts.txt", ctx)
        assert "{WORDLIST}" in out and "recon_hosts.txt" not in out

    def test_old_poisoned_entry_heals_on_rehydrate(self):
        sl = self._sl()
        ctx = {"workdir": "/home/en/redteam-workspace/eng_x",
               "target": "https://novalink.lk"}
        out = sl._rehydrate(
            "ffuf -u https://<TARGET>/FUZZ -w <WORKDIR>/recon_hosts.txt", ctx)
        assert "{WORDLIST}" in out and "recon_hosts.txt" not in out

    def test_any_wordlist_path_abstracted_to_token(self):
        # Updated 2026-06-20: ALL wordlist paths (even /usr/share/...) are now
        # abstracted to {WORDLIST}, because the learner kept re-teaching a path
        # that isn't installed on this box. The execution layer resolves
        # {WORDLIST} to a real list (AI-provisioned → installed → fallback).
        sl = self._sl()
        ctx = {"workdir": "/home/en/redteam-workspace/eng_x",
               "target": "https://novalink.lk"}
        out = sl._abstract(
            "ffuf -u https://novalink.lk/FUZZ -w /usr/share/wordlists/common.txt", ctx)
        assert "{WORDLIST}" in out and "/usr/share/wordlists/common.txt" not in out


class TestSituationSummary:
    def _fake(self, store_findings):
        fake = types.SimpleNamespace()
        fake.log = logging.getLogger("t")
        fake.session = types.SimpleNamespace(
            target="https://x.com", engagement_id="e1")
        fake.store = types.SimpleNamespace(
            get_all_findings=lambda eid: store_findings)
        fake._findings = []  # per-instance is empty (the bug we fixed)
        return fake

    def test_reads_cross_phase_store_and_extracts_tech_name(self):
        from agents.base_agent import BaseAgent
        fake = self._fake([{"type": "tech_stack", "detail": "CMS: WordPress"}])
        tech, discovered = BaseAgent._situation_summary(fake)
        # Must read the STORE (not the empty instance list) and pull the tech
        # NAME, not the "cms:" label.
        assert "wordpress" in tech
        assert "cms:" not in tech
        assert discovered.get("tech_stack") == 1
