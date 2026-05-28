import json
from datetime import datetime
from utils.display import section, info, warning, success, console
from agents.base_agent import BaseAgent
from core.result_contracts import ResultStatus
class ReportingAgent(BaseAgent):
    async def run(self) -> dict:
        section("PHASE 7 - Reporting & Cleanup")
        self.store.set_phase_status(self.session.engagement_id, "reporting", "running")

        raw_findings = self.store.get_all_findings(self.session.engagement_id)
        # Filter out noisy, non-actionable findings
        noisy_types = {"tech_stack", "ssl_observation"}
        findings = [
            f for f in raw_findings 
            if str(f.get("type", "")).lower() not in noisy_types 
            and str(f.get("finding_type", "")).lower() not in noisy_types
        ]
        results_dir = self.session.results_dir

        # AI executive summary
        info("Generating AI executive summary...")
        crit_count = len([f for f in findings if f.get('severity') == 'critical'])
        high_count = len([f for f in findings if f.get('severity') == 'high'])
        
        exec_prompt = (
            f"Engagement: {self.session.mode} against {self.session.normalized_target()}.\n"
            f"ACTUAL findings only - do NOT invent or assume vulnerabilities not listed below.\n"
            f"Total findings: {len(findings)}. Critical: {crit_count}. High: {high_count}.\n"
        )
        # Sort by severity so critical/high findings always appear in the top 30
        # (prevents nuclei CVEs from being cut off when there are many info findings)
        _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        top_findings = sorted(findings, key=lambda x: _sev_order.get(x.get("severity", "info").lower(), 4))[:30]
        exec_prompt += (
            f"Top confirmed findings (sorted by severity):\n{json.dumps(top_findings, default=str)}\n\n"
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
            self.log.warning("AI unavailable - generating static report from tool output")
            executive_summary = f"Static Summary:\nIdentified {crit_count} Critical, {high_count} High issues."
            technical_section = "Refer to the raw findings list below for technical details."
        
        # Technical details generation (separate query to maximize context window)
        tech_prompt = (
            f"Write a technical findings section for a penetration test report. "
            f"Top findings: {json.dumps(top_findings, default=str)}. "
            f"For each finding, include: title, severity, description, evidence (including any mentioned PoC script filenames), remediation."
        )
        try:
            # Use think() not self.ai.query() directly - think() injects system context
            # and has graceful fallback to rule-based output if AI backends are down.
            technical_section = self.think(
                "You are a senior penetration tester writing a technical report. "
                "Always mention the specific PoC script filename (e.g., poc_xxe.py) in the "
                "evidence section if it is present in the data.\n\n" + tech_prompt
            )
        except Exception as e:
            self.log.error(f"AI query failed for technical section: {e}")
            if not technical_section:
                technical_section = "[AI unavailable - see findings.json for raw data.]"

        # Persist final reporting status before snapshotting phase summary for output files.
        report_path = results_dir / "report" / "final_report.md"
        json_path = results_dir / "report" / "findings.json"
        final_status = "complete" if ai_available else "complete_degraded"
        self.store.set_phase_status(
            self.session.engagement_id, "reporting", final_status,
            f"Report at {report_path}"
        )
        phase_summary = self.store.get_phase_summary(self.session.engagement_id)

        # Build Markdown report
        awareness_report = ""
        if hasattr(self, "awareness"):
            awareness_report = self.awareness.get_confidence_report()
            
        # V7 Auto-Upgrade: Analyze Engagement
        try:
            from intelligence.engagement_analyzer import EngagementAnalyzer
            analyzer = EngagementAnalyzer(store=self.store)
            insights = analyzer.analyze_engagement(self.session.engagement_id)
            insights_path = analyzer.save_insights(insights, str(results_dir / "report" / "engagement_insights.json"))
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
                        awareness_report += f"- ⚙️ **{opt.get('type')}**: {opt.get('tool', opt.get('phase', ''))} - {opt.get('reason')}\n"
        except Exception as e:
            self.log.error(f"EngagementAnalyzer failed: {e}")

        try:
            report_md = self._build_markdown_report(
                executive_summary, technical_section, findings, phase_summary, awareness_report
            )
        except TypeError:
            # Backward compatibility for legacy helper signatures that do not accept awareness_report.
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
                "completed_at": datetime.utcnow().isoformat(),
                "findings": findings,
                "phase_summary": phase_summary
            }, indent=2, default=str),
            encoding="utf-8"
        )

        # 4. Display summary in terminal (Issue 8)
        from rich.table import Table
        from rich.panel import Panel

        severity_counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
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
        severity_colors = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "blue", "info": "dim"}
        
        for sev, color in severity_colors.items():
            count = severity_counts.get(sev, 0)
            # Use solid Unicode block '█' for a cleaner look
            bar = "█" * min(count, 20)
            t.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count), f"[{color}]{bar}[/{color}]")
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
            f_table = Table(title="Key Vulnerability Findings", border_style="dim")
            f_table.add_column("Severity", style="bold", width=10)
            f_table.add_column("Finding", style="white")
            f_table.add_column("Location", style="dim")
            
            # Sort findings: Critical -> High -> Medium
            priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_f = sorted(findings, key=lambda x: priority.get(x.get('severity', 'info'), 99))
            
            for f in sorted_f:
                sev = f.get('severity', 'info').lower()
                if sev in ['info', 'low'] and len(findings) > 20:
                    continue # Cap at info/low if too many for terminal
                    
                color = severity_colors.get(sev, "white")
                f_table.add_row(
                    f"[{color}]{sev.upper()}[/{color}]",
                    f.get('detail', 'No details')[:80],
                    f.get('target', 'N/A')
                )
            
            console.print(Panel(f_table, border_style="red", title="[bold red]VULNERABILITY DETAILS[/bold red]"))
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
                success(f"[+] System upgraded from engagement learnings")
                
                # Show what changed
                stats = upgrader.get_system_evolution_stats()
                info(f"  • Tools tracked: {stats.get('tools_tracked')}")
                info(f"  • Total upgrades: {stats.get('total_upgrades')}")
                info(f"  • Engagements learned from: {stats.get('total_engagements_learned_from')}")
                
                changes_applied = upgrade_result.get("changes_applied", [])
                if changes_applied:
                    info(f"  • Changes applied: {len(changes_applied)}")
                    for change in changes_applied[:3]:
                        info(f"    - {change}")
            else:
                warning(f"System upgrade incomplete: {upgrade_result.get('status')}")
                
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
            
            # Get WAF fingerprint if it was detected (prefer structured recon data)
            recon_data = self.store.get_phase_data(self.session.engagement_id, "recon") or {}
            waf_fp = recon_data.get("waf_fingerprint")
            if waf_fp:
                engagement_data["waf_fingerprint"] = waf_fp
            else:
                waf_fp_json = self.store.get(f"{self.session.engagement_id}:waf_fingerprint")
                if waf_fp_json:
                    try:
                        engagement_data["waf_fingerprint"] = json.loads(waf_fp_json, strict=False)
                    except:
                        pass
            
            # Collect tool execution data from all phases
            for phase in ["recon", "exploitation", "persistence"]:
                phase_data = self.store.get_phase_data(self.session.engagement_id, phase) or {}
                if "tool_runs" in phase_data:
                    engagement_data["tool_runs"].extend(phase_data["tool_runs"])
            
            # Run learning if we have WAF data
            if engagement_data.get("waf_fingerprint"):
                learning_result = learner.learn_from_engagement(
                    self.session.engagement_id,
                    engagement_data
                )
                
                if learning_result.get("new_fingerprints"):
                    success(f"[+] Discovered {len(learning_result['new_fingerprints'])} new WAF(s)")
                    for fp in learning_result["new_fingerprints"]:
                        info(f"  • New WAF ID: {fp.get('id', 'unknown')}")
                
                if learning_result.get("updated_tactics"):
                    success(f"[+] Updated {len(learning_result['updated_tactics'])} evasion tactics")
                    for tactic in learning_result["updated_tactics"][:3]:
                        info(f"  • {tactic.get('tactic', '?')}: {tactic.get('recommendation', 'unknown')}")
                
                if learning_result.get("recommendations"):
                    info(f"  Recommendations for next engagement:")
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

    def _build_markdown_report(self, exec_summary, tech_section, findings, phases, awareness_report="") -> str:
        severity_counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if sev not in severity_counts:
                sev = "info"
            severity_counts[sev] += 1

        return f"""# Security Assessment Report

    **Engagement ID:** {self.session.engagement_id}
    **Target:** {self.session.normalized_target()}
    **Mode:** {self.session.mode.upper()}
    **Date:** {datetime.utcnow().strftime("%Y-%m-%d")}
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
            lines.append(f"- {status_emoji} **{phase.title()}**: {phase_info.get('summary', '')[:200]}")
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
                detail = "\n" + "\n".join(["    " + line for line in detail.split("\n")])

            lines.append(
                f"### [{sev}] {ftype}\n"
                f"- **Target:** {target}\n"
                f"- **Detail:** {detail}\n"
                f"- **Timestamp:** {timestamp}\n"
            )
        return "\n".join(lines) if lines else "No findings recorded."

    def _cleanup_guidance(self):
        self.log.warning("CLEANUP REQUIRED: Review the cleanup checklist in the report.")
        self.log.warning("Ensure all tools and artifacts are removed from target systems.")
        self.log.warning("Revoke any temporary access credentials created during testing.")
