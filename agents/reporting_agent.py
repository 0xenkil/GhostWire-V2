import json
from datetime import datetime, timezone
from utils.display import section, info, warning, success, console
from agents.base_agent import BaseAgent
from core.result_contracts import ResultStatus


class ReportingAgent(BaseAgent):
    async def run(self) -> dict:
        section("PHASE 7 - Reporting & Cleanup")
        self.store.set_phase_status(
            self.session.engagement_id, "reporting", "running")

        raw_findings = self.store.get_all_findings(self.session.engagement_id)
        # Filter out noisy, non-actionable findings
        noisy_types = {"tech_stack", "ssl_observation"}
        findings = [
            f for f in raw_findings
            if str(f.get("type", "")).lower() not in noisy_types
            and str(f.get("finding_type", "")).lower() not in noisy_types
        ]

        # ── WS7 — Evidence & Reporting Integrity ─────────────────────────────
        # W7.1 two-tier split, W7.2 honest verdict, W7.3 reproducible PoC export.
        proven_vulns, leads = self._split_two_tier(findings)
        engagement_verdict = self._engagement_verdict(proven_vulns)
        evidence_objects = self._load_evidence_objects()
        try:
            self._export_pocs(proven_vulns, evidence_objects)
        except Exception as _pe:
            self.log.debug(f"PoC export failed (non-fatal): {_pe}")
        info(f"[VERDICT] {engagement_verdict['verdict']} — "
             f"{len(proven_vulns)} proven vuln(s), {len(leads)} unverified lead(s)")

        # FIX E: Severity Demotion Gate
        # Downgrade High/Critical findings that lack a proven exploit
        weaponization_data = self.store.get_phase_data(
            self.session.engagement_id, "weaponization") or {}
        proven_exploits = weaponization_data.get("proven_exploits", [])
        # Extract proven finding details/types for matching
        proven_signatures = [str(p.get("proof", "")).lower()[:50]
                             for p in proven_exploits]
        proven_signatures.extend(
            [str(p.get("type", "")).lower() for p in proven_exploits])

        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in ["high", "critical"]:
                # If it's a dynamic vulnerability and we couldn't prove it,
                # demote it.
                detail = str(f.get("detail", "")).lower()
                f_type = str(f.get("type", "")).lower()

                has_proof = False
                for sig in proven_signatures:
                    if sig and (sig in detail or sig in f_type):
                        has_proof = True
                        break

                # Never demote a finding the two-tier split already classified as
                # PROVEN (confirmed_vulnerability / vuln_proven / cred / shell from
                # the WS4 evidence gate / WS3 authz differential). Those are proven
                # INDEPENDENTLY of weaponization's proven_exploits list, so demoting
                # them here would under-report their real severity in the verdict
                # and executive summary.
                if any(f is pf for pf in proven_vulns):
                    has_proof = True

                # Allow known CVE signatures and discovery findings to remain
                # high
                if not has_proof and "cve-" not in detail and "subdomain" not in f_type and "open_port" not in f_type:
                    f["severity"] = "medium"
                    f["detail"] = f"[DEMOTED: Unverified PoC] {
                        f.get(
                            'detail',
                            '')}"

        results_dir = self.session.results_dir

        # AI executive summary
        info("Generating AI executive summary...")
        crit_count = len(
            [f for f in findings if f.get('severity') == 'critical'])
        high_count = len([f for f in findings if f.get('severity') == 'high'])

        # W7.1 — headline counts reflect PROVEN vulnerabilities only; leads are
        # reported separately and never inflate the risk rating.
        proven_crit = len([f for f in proven_vulns if f.get("severity") == "critical"])
        proven_high = len([f for f in proven_vulns if f.get("severity") == "high"])
        exec_prompt = (
            f"Engagement: {
                self.session.mode} against {
                self.session.normalized_target()}.\n"
            f"ACTUAL findings only - do NOT invent or assume vulnerabilities not listed below.\n"
            f"ENGAGEMENT VERDICT (honest, objective-based): {engagement_verdict['verdict']} — "
            f"{engagement_verdict['rationale']}\n"
            f"PROVEN vulnerabilities (with reproducible evidence): {len(proven_vulns)} "
            f"(Critical: {proven_crit}, High: {proven_high}).\n"
            f"UNVERIFIED leads (NOT counted as vulnerabilities): {len(leads)}.\n"
            f"Write the summary around the PROVEN vulnerabilities. Describe leads only as "
            f"'areas warranting further manual testing' — never as confirmed risk.\n"
        )
        # Sort by severity so critical/high findings always appear in the top 30
        # (prevents nuclei CVEs from being cut off when there are many info findings)
        _sev_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4}
        top_findings = sorted(
            findings, key=lambda x: _sev_order.get(
                x.get(
                    "severity", "info").lower(), 4))[
            :30]
        exec_prompt += (
            f"Top confirmed findings (sorted by severity):\n{
                json.dumps(
                    top_findings,
                    default=str)}\n\n"
            f"Task: Write a professional executive summary for the CSO. "
            f"Use ONLY the confirmed findings above. If a vulnerability is not in the data, "
            f"do NOT mention it. Focus on identified risks and business impact. "
            f"CRITICAL: Do NOT assume a vulnerability is an XXE (XML External Entity) just because "
            f"the evidence starts with '<!DOCTYPE html' or '<html>'. That is generic HTML, not proof of XXE. "
            f"Include: overall risk rating, top 3 critical findings, "
            f"recommended immediate actions, and long-term remediation steps. "
            f"Tone: professional, clear, suitable for non-technical management."
        )
        try:
            executive_summary = self.think(exec_prompt)
        except Exception as e:
            self.log.error(f"AI query failed for executive summary: {e}")
            executive_summary = f"[AI unavailable - manual review required. Error: {e}]"

        technical_section = ""
        ai_available = not executive_summary.startswith("[AI unavailable")

        if not ai_available:
            self.log.warning(
                "AI unavailable - generating static report from tool output")
            executive_summary = f"Static Summary:\nIdentified {crit_count} Critical, {high_count} High issues."
            technical_section = "Refer to the raw findings list below for technical details."

        # Technical details generation (separate query to maximize context
        # window)
        tech_prompt = (
            f"Write a technical findings section for a penetration test report. "
            f"Top findings: {json.dumps(top_findings, default=str)}. "
            f"For each finding, include: title, severity, description, evidence (including any mentioned PoC script filenames), remediation."
        )
        try:
            # Use think() not self.ai.query() directly - think() injects system context
            # and has graceful fallback to rule-based output if AI backends are
            # down.
            technical_section = self.think(
                "You are a senior penetration tester writing a technical report. "
                "Always mention the specific PoC script filename (e.g., poc_xxe.py) in the "
                "evidence section if it is present in the data.\n\n" + tech_prompt
            )
        except Exception as e:
            self.log.error(f"AI query failed for technical section: {e}")
            if not technical_section:
                technical_section = "[AI unavailable - see findings.json for raw data.]"

        # Persist final reporting status before snapshotting phase summary for
        # output files.
        report_path = results_dir / "report" / "final_report.md"
        json_path = results_dir / "report" / "findings.json"
        final_status = "complete" if ai_available else "complete_degraded"
        self.store.set_phase_status(
            self.session.engagement_id, "reporting", final_status,
            f"Report at {report_path}"
        )
        phase_summary = self.store.get_phase_summary(
            self.session.engagement_id)

        # Build Markdown report
        awareness_report = ""
        if hasattr(self, "awareness"):
            awareness_report = self.awareness.get_confidence_report()

        # V7 Auto-Upgrade: Analyze Engagement
        try:
            from intelligence.engagement_analyzer import EngagementAnalyzer
            analyzer = EngagementAnalyzer(store=self.store)
            insights = analyzer.analyze_engagement(self.session.engagement_id)
            insights_path = analyzer.save_insights(insights, str(
                results_dir / "report" / "engagement_insights.json"))
            self.log.info(f"Engagement insights saved to: {insights_path}")

            # Format patterns for the report
            patterns = insights.get("patterns_discovered", [])
            optimizations = insights.get("optimization_opportunities", [])

            if patterns or optimizations:
                awareness_report += "\n\n### Discovered Patterns & Insights\n"
                for p in patterns:
                    awareness_report += f"- 🔍 {p}\n"

                awareness_report += "\n### Optimization Opportunities\n"
                for opt in optimizations:
                    if isinstance(opt, dict) and "reason" in opt:
                        awareness_report += f"- ⚙️ **{
                            opt.get('type')}**: {
                            opt.get(
                                'tool', opt.get(
                                    'phase', ''))} - {
                            opt.get('reason')}\n"
        except Exception as e:
            self.log.error(f"EngagementAnalyzer failed: {e}")

        try:
            report_md = self._build_markdown_report(
                executive_summary, technical_section, findings, phase_summary, awareness_report
            )
        except TypeError:
            # Backward compatibility for legacy helper signatures that do not
            # accept awareness_report.
            report_md = self._build_markdown_report(
                executive_summary, technical_section, findings, phase_summary
            )
        report_path.write_text(report_md, encoding="utf-8")

        # Build JSON findings
        json_path.write_text(
            json.dumps({
                "engagement_id": self.session.engagement_id,
                "target": self.session.normalized_target(),
                "mode": self.session.mode,
                "started_at": self.session.started_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "findings": findings,
                "phase_summary": phase_summary
            }, indent=2, default=str),
            encoding="utf-8"
        )

        # 4. Display summary in terminal (Issue 8)
        from rich.table import Table
        from rich.panel import Panel

        severity_counts = {
            s: 0 for s in [
                "critical",
                "high",
                "medium",
                "low",
                "info"]}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if sev not in severity_counts:
                sev = "info"
            severity_counts[sev] += 1

        section("ENGAGEMENT SUMMARY")

        # Severity table
        t = Table(title="Finding Severity Breakdown", border_style="red")
        t.add_column("Severity", style="bold")
        t.add_column("Count", justify="right")
        t.add_column("Visual")
        severity_colors = {
            "critical": "red",
            "high": "yellow",
            "medium": "cyan",
            "low": "blue",
            "info": "dim"}

        for sev, color in severity_colors.items():
            count = severity_counts.get(sev, 0)
            # Use solid Unicode block '█' for a cleaner look
            bar = "█" * min(count, 20)
            t.add_row(f"[{color}]{sev.upper()}[/{color}]",
                      str(count), f"[{color}]{bar}[/{color}]")
        console.print(t)

        # 4. Executive summary (Modern Markdown Rendering)
        from rich.markdown import Markdown
        from rich.rule import Rule

        console.print(Rule(style="bold yellow"))
        console.print(Markdown("# EXECUTIVE SUMMARY"))
        console.print(Markdown(executive_summary))
        console.print(Rule(style="dim yellow"))

        # 4b. Technical Report (AI Narrative)
        console.print(Markdown("# TECHNICAL ANALYSIS & REMEDIATION"))
        console.print(Markdown(technical_section))
        console.print(Rule(style="bold yellow"))
        console.print("\n")

        # 5. Key Vulnerability Findings Table
        if findings:
            f_table = Table(
                title="Key Vulnerability Findings",
                border_style="dim")
            f_table.add_column("Severity", style="bold", width=10)
            f_table.add_column("Finding", style="white")
            f_table.add_column("Location", style="dim")

            # Sort findings: Critical -> High -> Medium
            priority = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4}
            sorted_f = sorted(
                findings,
                key=lambda x: priority.get(
                    x.get(
                        'severity',
                        'info'),
                    99))

            for f in sorted_f:
                sev = f.get('severity', 'info').lower()
                if sev in ['info', 'low'] and len(findings) > 20:
                    continue  # Cap at info/low if too many for terminal

                color = severity_colors.get(sev, "white")
                f_table.add_row(
                    f"[{color}]{sev.upper()}[/{color}]",
                    f.get('detail', 'No details')[:80],
                    f.get('target', 'N/A')
                )

            console.print(
                Panel(
                    f_table,
                    border_style="red",
                    title="[bold red]VULNERABILITY DETAILS[/bold red]"))
            console.print("\n")

        # Clearly signpost the final report location
        console.print(Panel(
            f"[bold green]Full Technical Report Saved To:[/bold green]\n{report_path}\n\n"
            f"[bold cyan]Raw JSON Findings Saved To:[/bold cyan]\n{json_path}",
            title="[bold yellow]REPORT GENERATION COMPLETE[/bold yellow]",
            border_style="green"
        ))

        self.log.info(f"Report saved to: {report_path}")
        self.log.info(f"JSON findings: {json_path}")

        # Cleanup notice
        self._cleanup_guidance()

        if ai_available:
            success("Reporting & Cleanup phase complete (AI Mode).")
        else:
            warning("Reporting generated WITHOUT AI analysis - review manually.")
        success(f"Engagement ID: {self.session.engagement_id}")
        success(f"All results in: {results_dir}")

        # ===== AUTO-UPGRADE: System learns from engagement =====
        try:
            from intelligence.auto_upgrader import AutoUpgrader
            info("\n[AUTO-UPGRADE] Starting system learning phase...")

            upgrader = AutoUpgrader(store=self.store)
            upgrade_result = upgrader.run_system_upgrade(
                engagement_id=self.session.engagement_id,
                dry_run=False  # Apply changes (not dry run)
            )

            if upgrade_result.get("status") == "complete":
                success("[+] System upgraded from engagement learnings")

                # Show what changed
                stats = upgrader.get_system_evolution_stats()
                info(f"  • Tools tracked: {stats.get('tools_tracked')}")
                info(f"  • Total upgrades: {stats.get('total_upgrades')}")
                info(
                    f"  • Engagements learned from: {
                        stats.get('total_engagements_learned_from')}")

                changes_applied = upgrade_result.get("changes_applied", [])
                if changes_applied:
                    info(f"  • Changes applied: {len(changes_applied)}")
                    for change in changes_applied[:3]:
                        info(f"    - {change}")
            else:
                warning(
                    f"System upgrade incomplete: {
                        upgrade_result.get('status')}")

        except ImportError:
            # Auto-upgrade modules not available
            pass
        except Exception as e:
            self.log.warning(f"Auto-upgrade error (non-fatal): {e}")

        # ===== WAF LEARNER: Discover new WAFs and learn evasion tactics =====
        try:
            from intelligence.waf_learner import WafLearner
            info("\n[WAF-LEARNER] Starting WAF discovery and learning phase...")

            learner = WafLearner()

            # Collect engagement data for learning
            engagement_data = {
                "engagement_id": self.session.engagement_id,
                "target": self.session.target,
                "waf_fingerprint": None,
                "tool_runs": []
            }

            # Get WAF fingerprint if it was detected (prefer structured recon
            # data)
            recon_data = self.store.get_phase_data(
                self.session.engagement_id, "recon") or {}
            waf_fp = recon_data.get("waf_fingerprint")
            if waf_fp:
                engagement_data["waf_fingerprint"] = waf_fp
            else:
                waf_fp_json = self.store.get(
                    f"{self.session.engagement_id}:waf_fingerprint")
                if waf_fp_json:
                    try:
                        engagement_data["waf_fingerprint"] = json.loads(
                            waf_fp_json, strict=False)
                    except Exception as _e:
                        import logging
                        logging.getLogger(__name__).debug(
                            f'Swallowed exception in reporting_agent.py: {_e}')

            # Collect tool execution data from all phases
            for phase in ["recon", "exploitation", "persistence"]:
                phase_data = self.store.get_phase_data(
                    self.session.engagement_id, phase) or {}
                if "tool_runs" in phase_data:
                    engagement_data["tool_runs"].extend(
                        phase_data["tool_runs"])

            # Run learning if we have WAF data
            if engagement_data.get("waf_fingerprint"):
                learning_result = learner.learn_from_engagement(
                    self.session.engagement_id,
                    engagement_data
                )

                if learning_result.get("new_fingerprints"):
                    success(
                        f"[+] Discovered {len(learning_result['new_fingerprints'])} new WAF(s)")
                    for fp in learning_result["new_fingerprints"]:
                        info(f"  • New WAF ID: {fp.get('id', 'unknown')}")

                if learning_result.get("updated_tactics"):
                    success(
                        f"[+] Updated {len(learning_result['updated_tactics'])} evasion tactics")
                    for tactic in learning_result["updated_tactics"][:3]:
                        info(
                            f"  • {
                                tactic.get(
                                    'tactic',
                                    '?')}: {
                                tactic.get(
                                    'recommendation',
                                    'unknown')}")

                if learning_result.get("recommendations"):
                    info("  Recommendations for next engagement:")
                    for rec in learning_result["recommendations"][:3]:
                        info(f"  - {rec}")
            else:
                info("  No WAF detected in this engagement - skipping WAF learning")

        except ImportError:
            # WAF learner not available
            pass
        except Exception as e:
            self.log.warning(f"WAF learner error (non-fatal): {e}")

        success("Reporting & Cleanup phase complete.")
        return self.finish_phase(
            {"report_path": str(report_path), "json_path": str(json_path)},
            status=ResultStatus.SUCCESS if ai_available else ResultStatus.PARTIAL,
            message=f"Report at {report_path}"
        )

    def _build_markdown_report(
            self, exec_summary, tech_section, findings, phases, awareness_report="") -> str:
        severity_counts = {
            s: 0 for s in [
                "critical",
                "high",
                "medium",
                "low",
                "info"]}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if sev not in severity_counts:
                sev = "info"
            severity_counts[sev] += 1

        return f"""# Security Assessment Report

    **Engagement ID:** {self.session.engagement_id}
    **Target:** {self.session.normalized_target()}
    **Mode:** {self.session.mode.upper()}
    **Date:** {datetime.now(timezone.utc).strftime("%Y-%m-%d")}
    **Scope:** {', '.join(self.session.scope)}

    ---

## Executive Summary

{exec_summary}

---

## Risk Summary

| Severity | Count |
|----------|-------|
| Critical | {severity_counts['critical']} |
| High     | {severity_counts['high']} |
| Medium   | {severity_counts['medium']} |
| Low      | {severity_counts['low']} |
| Info     | {severity_counts['info']} |

---

## Phase Completion

{self._format_phases(phases)}

---

## Intelligence Confidence (Self-Awareness)

{awareness_report}

---

## Technical Findings

{tech_section}

---

## All Raw Findings

{self._format_findings(findings)}

---

## Cleanup Checklist

- [ ] Remove any test payloads from target systems
- [ ] Delete EICAR test files if deployed
- [ ] Remove any created user accounts
- [ ] Restore modified configuration files
- [ ] Revoke any temporary credentials used
- [ ] Archive this report securely

---

*This report was generated by AI Red Team Platform.*
*All activities were conducted under authorized rules of engagement.*
"""

    def _format_phases(self, phases: dict) -> str:
        lines = []
        for phase, phase_info in phases.items():
            phase_status = (phase_info.get("status") or "").lower()
            if phase_status == "complete":
                status_emoji = "✅"
            elif phase_status in ("skipped", "preflight_skipped"):
                status_emoji = "⏭️"
            else:
                status_emoji = "❌"
            lines.append(
                f"- {status_emoji} **{phase.title()}**: {phase_info.get('summary', '')[:200]}")
        return "\n".join(lines)

    def _format_findings(self, findings: list) -> str:
        lines = []
        for f in findings:
            # BUG-16: Use .get() fallbacks - dict key can be 'type' or 'finding_type'
            # depending on which code path created the finding.
            sev = (f.get("severity") or "info").upper()
            ftype = f.get("type") or f.get("finding_type") or "unknown"
            target = f.get("target") or "N/A"
            timestamp = f.get("timestamp") or ""
            detail = f.get("detail") or "No details"
            # If detail contains newlines, indent it for markdown compatibility
            if "\n" in detail:
                detail = "\n" + \
                    "\n".join(["    " + line for line in detail.split("\n")])

            lines.append(
                f"### [{sev}] {ftype}\n"
                f"- **Target:** {target}\n"
                f"- **Detail:** {detail}\n"
                f"- **Timestamp:** {timestamp}\n"
            )
        return "\n".join(lines) if lines else "No findings recorded."

    def _cleanup_guidance(self):
        self.log.warning(
            "CLEANUP REQUIRED: Review the cleanup checklist in the report.")
        self.log.warning(
            "Ensure all tools and artifacts are removed from target systems.")
        self.log.warning(
            "Revoke any temporary access credentials created during testing.")

    # ── WS7 helpers ─────────────────────────────────────────────────────────

    def _split_two_tier(self, findings: list) -> tuple[list, list]:
        """W7.1 — separate PROVEN vulnerabilities from unverified leads.

        Proven = a `confirmed_vulnerability` finding (these only exist after the
        WS4 evidence gate / WS3 authz differential). Everything else is a lead,
        regardless of the severity a scanner stamped on it.
        """
        proven, leads = [], []
        for f in findings:
            ftype = str(f.get("type", "") or f.get("finding_type", "")).lower()
            detail = str(f.get("detail", "")).lower()
            is_proven = (
                ftype == "confirmed_vulnerability"
                or "vuln_proven" in detail
                or ftype in ("valid_credential", "rce_confirmed", "shell_access"))
            # An "unverified lead" tag (from the ops-sanity backstop / evidence
            # gate) forces it to the lead tier even if mis-typed.
            if "unverified lead" in detail or "[demoted" in detail:
                is_proven = False
            (proven if is_proven else leads).append(f)
        return proven, leads

    def _engagement_verdict(self, proven_vulns: list) -> dict:
        """W7.2 — verdict reflects objective outcome, not 'tools ran'."""
        crit = [f for f in proven_vulns if f.get("severity") == "critical"]
        high = [f for f in proven_vulns if f.get("severity") == "high"]
        # Consult the objective ledger snapshot if exploitation persisted one.
        achieved = []
        try:
            import json as _json
            led_raw = self.store.get(f"{self.session.engagement_id}:objective_ledger")
            if led_raw:
                led = _json.loads(led_raw)
                achieved = [o["label"] for o in led.get("objectives", [])
                            if o.get("status") == "achieved"]
        except Exception:
            pass

        if crit or high:
            verdict = "COMPROMISED"
            rationale = (f"{len(proven_vulns)} vulnerability(ies) proven with reproducible "
                         f"evidence ({len(crit)} critical, {len(high)} high).")
        elif proven_vulns:
            verdict = "PARTIAL"
            rationale = (f"{len(proven_vulns)} lower-severity issue(s) proven; no critical/high "
                         "impact demonstrated.")
        else:
            verdict = "NOT COMPROMISED"
            rationale = ("No vulnerability could be proven with a reproducible differential or "
                         "artifact. Unverified leads may warrant manual testing.")
        if achieved:
            rationale += f" Objectives achieved: {', '.join(achieved)}."
        return {"verdict": verdict, "rationale": rationale,
                "proven_count": len(proven_vulns)}

    def _load_evidence_objects(self) -> list:
        try:
            import json as _json
            raw = self.store.get(f"{self.session.engagement_id}:evidence_objects")
            return _json.loads(raw) if raw else []
        except Exception:
            return []

    def _export_pocs(self, proven_vulns: list, evidence_objects: list) -> None:
        """W7.3 — write a reproducible PoC export (runnable command + req/resp
        + differential) for each proven vulnerability."""
        if not proven_vulns and not evidence_objects:
            return
        import json as _json
        results_dir = self.session.results_dir
        try:
            results_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        export = {
            "engagement_id": self.session.engagement_id,
            "target": getattr(self.session, "target", ""),
            "proven_vulnerabilities": len(proven_vulns),
            "pocs": [],
        }
        for eo in evidence_objects:
            ev = eo.get("evidence", {}) or {}
            export["pocs"].append({
                "vuln_class": eo.get("vuln_class"),
                "title": eo.get("title"),
                "severity": eo.get("severity"),
                "proof_type": ev.get("proof_type"),
                "reproducible_command": ev.get("reproducible_command"),
                "request": ev.get("request"),
                "response_excerpt": ev.get("response_excerpt"),
                "baseline_excerpt": ev.get("baseline_excerpt"),
                "differential": ev.get("differential"),
            })
        # Fallback: derive a minimal PoC from the finding detail when no
        # structured evidence object was persisted.
        if not export["pocs"]:
            import re as _re
            for f in proven_vulns:
                _detail = str(f.get("detail", ""))
                # DB-loaded findings don't carry the structured `command` field
                # (it isn't persisted to the findings table), but confirmed-vuln
                # details embed the trigger as "PoC: <cmd>" — recover it so the
                # fallback PoC is actually reproducible instead of blank.
                _cmd = f.get("command", "") or ""
                if not _cmd:
                    _m = _re.search(
                        r'PoC:\s*(.+?)(?:\s*\|\s*Proof|\s*\|\s*Impact|$)', _detail)
                    if _m:
                        _cmd = _m.group(1).strip()
                export["pocs"].append({
                    "title": _detail[:120],
                    "severity": f.get("severity"),
                    "reproducible_command": _cmd,
                    "differential": "see finding detail",
                })

        json_path = results_dir / "poc_export.json"
        md_path = results_dir / "poc_export.md"
        try:
            json_path.write_text(_json.dumps(export, indent=2, default=str), encoding="utf-8")
            md_path.write_text(self._pocs_to_markdown(export), encoding="utf-8")
            info(f"[POC EXPORT] {len(export['pocs'])} reproducible PoC(s) → {json_path.name}")
        except Exception as _we:
            self.log.debug(f"PoC export write failed: {_we}")

    @staticmethod
    def _pocs_to_markdown(export: dict) -> str:
        lines = [f"# Reproducible PoC Export — {export.get('target', '')}",
                 f"Proven vulnerabilities: {export.get('proven_vulnerabilities', 0)}", ""]
        for i, p in enumerate(export.get("pocs", []), 1):
            lines.append(f"## {i}. [{(p.get('severity') or 'info').upper()}] "
                         f"{p.get('vuln_class') or ''} — {p.get('title') or ''}")
            if p.get("proof_type"):
                lines.append(f"- **Proof type:** {p['proof_type']}")
            if p.get("reproducible_command"):
                lines.append(f"- **Reproduce:**\n\n```\n{p['reproducible_command']}\n```")
            if p.get("differential"):
                lines.append(f"- **Differential:** {p['differential']}")
            if p.get("request"):
                lines.append(f"- **Request:**\n\n```\n{str(p['request'])[:1000]}\n```")
            if p.get("response_excerpt"):
                lines.append(f"- **Response (excerpt):**\n\n```\n{str(p['response_excerpt'])[:800]}\n```")
            lines.append("")
        return "\n".join(lines)
