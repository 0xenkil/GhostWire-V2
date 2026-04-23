import json
from datetime import datetime
from utils.display import section, info, warning, success, console
from agents.base_agent import BaseAgent
class ReportingAgent(BaseAgent):
    def run(self) -> dict:
        section("PHASE 7 — Reporting & Cleanup")
        self.store.set_phase_status(self.session.engagement_id, "reporting", "running")

        findings = self.store.get_all_findings(self.session.engagement_id)
        phase_summary = self.store.get_phase_summary(self.session.engagement_id)
        results_dir = self.session.results_dir

        # AI executive summary
        info("Generating AI executive summary...")
        crit_count = len([f for f in findings if f['severity']=='critical'])
        high_count = len([f for f in findings if f['severity']=='high'])
        
        exec_prompt = (
            f"Engagement: {self.session.mode} against {self.session.target}.\n"
            f"ACTUAL findings only — do NOT invent or assume vulnerabilities not listed below.\n"
            f"Total findings: {len(findings)}. Critical: {crit_count}. High: {high_count}.\n"
            f"ALL confirmed findings:\n{json.dumps(findings[:30], default=str)}\n\n"
            f"Task: Write a professional executive summary for the CSO. "
            f"Use ONLY the confirmed findings above. If a vulnerability is not in the data, "
            f"do NOT mention it. Focus on identified risks and business impact. "
            f"Include: overall risk rating, top 3 critical findings, "
            f"recommended immediate actions, and long-term remediation steps. "
            f"Tone: professional, clear, suitable for non-technical management."
        )
        try:
            executive_summary = self.ai.query(
                "You are a senior security consultant writing an executive summary.", exec_prompt
            )
        except Exception as e:
            self.log.error(f"AI query failed for executive summary: {e}")
            executive_summary = f"[AI unavailable — manual review required. Error: {e}]"

        technical_section = ""
        ai_available = not executive_summary.startswith("[AI unavailable")

        if not ai_available:
            self.log.warning("AI unavailable — generating static report from tool output")
            executive_summary = f"Static Summary:\nIdentified {crit_count} Critical, {high_count} High issues."
            technical_section = "Refer to the raw findings list below for technical details."
        
        # Technical details generation (separate query to maximize context window)
        tech_prompt = (
            f"Write a technical findings section for a penetration test report. "
            f"All findings: {json.dumps(findings, default=str)[:12000]}. "
            f"For each finding, include: title, severity, description, evidence, remediation."
        )
        try:
            technical_section = self.ai.query(
                "You are a senior penetration tester writing a technical report.", tech_prompt
            )
        except Exception as e:
            self.log.error(f"AI query failed for technical section: {e}")
            if not technical_section:
                technical_section = "[AI unavailable — see findings.json for raw data.]"

        # Build Markdown report
        report_md = self._build_markdown_report(
            executive_summary, technical_section, findings, phase_summary
        )
        report_path = results_dir / "report" / "final_report.md"
        report_path.write_text(report_md, encoding="utf-8")

        # Build JSON findings
        json_path = results_dir / "report" / "findings.json"
        json_path.write_text(
            json.dumps({
                "engagement_id": self.session.engagement_id,
                "target": self.session.target,
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
            severity_counts[f.get("severity", "info")] += 1

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
        from rich.panel import Panel
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
            f_table = Table(title="Key Vulnerability Findings", box=None, border_style="dim")
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

        final_status = "completed" if ai_available else "completed_degraded"
        self.store.set_phase_status(
            self.session.engagement_id, "reporting", final_status,
            f"Report at {report_path}"
        )
        if ai_available:
            success("Reporting & Cleanup phase complete (AI Mode).")
        else:
            warning("Reporting generated WITHOUT AI analysis — review manually.")
        success(f"Engagement ID: {self.session.engagement_id}")
        success(f"All results in: {results_dir}")
        return {"report_path": str(report_path), "json_path": str(json_path)}

    def _build_markdown_report(self, exec_summary, tech_section, findings, phases) -> str:
        severity_counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
        for f in findings:
            severity_counts[f.get("severity", "info")] += 1

        return f"""# Security Assessment Report

**Engagement ID:** {self.session.engagement_id}
**Target:** {self.session.target}
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
            status_emoji = "✅" if phase_info["status"] == "complete" else "⏭️" if phase_info["status"] == "skipped" else "❌"
            lines.append(f"- {status_emoji} **{phase.title()}**: {phase_info.get('summary', '')[:200]}")
        return "\n".join(lines)

    def _format_findings(self, findings: list) -> str:
        lines = []
        for f in findings:
            lines.append(
                f"### [{f['severity'].upper()}] {f['type']}\n"
                f"- **Target:** {f['target']}\n"
                f"- **Detail:** {f['detail']}\n"
                f"- **Timestamp:** {f['timestamp']}\n"
            )
        return "\n".join(lines) if lines else "No findings recorded."

    def _cleanup_guidance(self):
        self.log.warning("CLEANUP REQUIRED: Review the cleanup checklist in the report.")
        self.log.warning("Ensure all tools and artifacts are removed from target systems.")
        self.log.warning("Revoke any temporary access credentials created during testing.")
