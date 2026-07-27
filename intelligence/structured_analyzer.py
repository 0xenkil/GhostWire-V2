"""
Structured Analyzer: Converts raw tool output into structured findings with AI-driven reasoning.

The problem it solves:
- Raw recon output (nmap, gobuster, nikto) is messy, unstructured text
- AI tries to guess what it means from plain text -> poor decisions
- Solution: AI analyzes raw output and creates structured findings with reasoning

Flow:
1. Raw tool output (e.g., nmap scan results)
2. AI reads it and structures it (services, ports, versions, vulnerabilities)
3. AI assigns confidence scores (high/medium/low based on evidence)
4. AI extracts tactical recommendations (which tools to try next)
5. Reasoning engine uses structured data, not raw text
"""

import json
from typing import Dict, List, Any
from datetime import datetime, timezone


class StructuredAnalyzer:
    """Converts raw tool output to structured findings via AI reasoning."""

    def __init__(self, ai_backend=None):
        """
        Initialize analyzer with AI backend for reasoning.

        Args:
            ai_backend: AIBackend instance for AI-driven analysis
        """
        self.ai = ai_backend
        self.analysis_cache = {}  # Cache to avoid re-analyzing same output

    def analyze_raw_output(self, tool_name: str, command: str, stdout: str,
                           stderr: str = None, target: str = None) -> Dict[str, Any]:
        """
        Analyze raw tool output and structure it with reasoning.

        Args:
            tool_name: Name of tool (nmap, gobuster, nikto, etc)
            command: The command that was run
            stdout: Tool's stdout output
            stderr: Tool's stderr (if any)
            target: Target being scanned

        Returns:
            Structured analysis with findings, confidence, and tactical recommendations
        """
        if not self.ai:
            return self._basic_structure(tool_name, stdout, target)

        # Check cache first
        cache_key = f"{tool_name}:{hash(stdout[:1000])}"
        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]

        # AI-driven analysis of raw output
        prompt = f"""You are a network security analyst. Analyze this raw tool output and structure it.

Tool: {tool_name}
Command: {command}
Target: {target}

Output:
---
{stdout[:5000]}
---

{'Errors:' + stderr if stderr else 'No errors'}

Return a JSON object with:
{{
  "tool": "{tool_name}",
  "success": <bool - did the tool successfully run and find anything?>,
  "findings": [
    {{
      "type": "service|port|vulnerability|technology|path|header|redirect|...",
      "target": "specific host/port/path",
      "detail": "what was found",
      "confidence": <0.0-1.0 - how confident are you in this finding>,
      "evidence": "why you believe this (quote from output)",
      "severity": "critical|high|medium|low|info",
      "actionable": <bool - can we exploit this or use it for next step>
    }}
  ],
  "false_positives": [
    "patterns that might indicate false results (e.g., default 404 page, WAF block)"
  ],
  "next_tools_recommended": [
    "tool name that should be tried next based on these findings"
  ],
  "confidence_summary": "overall analysis confidence (high/medium/low) and why",
  "reasoning": "explain your analysis logic"
}}

Be precise. Only include findings you're confident about (confidence >= 0.5).
If the tool output looks like a WAF block or error page, mark as low confidence.
If you see generic output, indicate potential false positive."""

        try:
            response = self.ai.query(
                "You are a security analyst structuring raw tool output.",
                prompt
            )

            # Parse JSON response
            import re
            match = re.search(r'\{[\s\S]*\}', response)
            if match:
                analysis = json.loads(match.group(0))
                self.analysis_cache[cache_key] = analysis
                return analysis
        except Exception as e:
            # Fallback to basic structure if AI fails
            return self._basic_structure(
                tool_name, stdout, target, error=str(e))

        return self._basic_structure(tool_name, stdout, target)

    def _basic_structure(self, tool_name: str, stdout: str, target: str = None,
                         error: str = None) -> Dict[str, Any]:
        """Fallback: basic structure without full AI analysis."""
        return {
            "tool": tool_name,
            "success": bool(stdout and not error),
            "findings": [],
            "false_positives": [],
            "next_tools_recommended": [],
            "confidence_summary": "low - basic structure (AI analysis unavailable)",
            "reasoning": f"Fallback structure without AI: {error}" if error else "Fallback structure"
        }

    def structure_recon_phase_output(
            self, recon_tools_output: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Structure entire recon phase output (multiple tools) into unified view.

        Args:
            recon_tools_output: List of tool execution results from recon phase

        Returns:
            Unified structured analysis
        """
        structured = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools_analyzed": [],
            "all_findings": [],
            "technology_stack": {},
            "attack_surface": {
                "services": [],
                "paths": [],
                "technologies": [],
                "vulnerabilities": []
            },
            "confidence_by_finding_type": {},
            "tactical_context": {},
            "recommended_exploitation_tactics": []
        }

        # Analyze each tool's output
        for tool_result in recon_tools_output:
            tool_name = tool_result.get("tool", "unknown")

            analysis = self.analyze_raw_output(
                tool_name,
                tool_result.get("command", ""),
                tool_result.get("stdout", ""),
                tool_result.get("stderr", ""),
                tool_result.get("target", "")
            )

            structured["tools_analyzed"].append({
                "tool": tool_name,
                "confidence": analysis.get("confidence_summary", "unknown"),
                "finding_count": len(analysis.get("findings", []))
            })

            # Aggregate findings
            for finding in analysis.get("findings", []):
                structured["all_findings"].append(finding)

                # Index by type for quick access
                finding_type = finding.get("type", "unknown")
                if finding_type not in structured["attack_surface"]:
                    structured["attack_surface"][finding_type] = []
                structured["attack_surface"][finding_type].append(finding)

            # Aggregate technology stack
            if analysis.get("technology_stack"):
                structured["technology_stack"].update(
                    analysis["technology_stack"])

        # AI: Create tactical context from structured findings
        if self.ai and structured["all_findings"]:
            structured["tactical_context"] = self._build_tactical_context(
                structured)

        return structured

    def _build_tactical_context(
            self, structured_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        AI-driven tactical context: What does this attack surface mean for exploitation?
        """
        findings_summary = json.dumps(
            structured_analysis["all_findings"][:20], indent=2)

        prompt = f"""Given these structured findings from recon, create tactical exploitation context:

{findings_summary}

Return JSON:
{{
  "primary_attack_vectors": [
    {{"vector": "description", "confidence": 0.0-1.0, "why": "reasoning"}}
  ],
  "high_value_targets": [
    {{"target": "description", "why_valuable": "reason", "tools_to_try": ["tool1", "tool2"]}}
  ],
  "technology_specific_tactics": {{"tech_name": "list of specific tactics"}},
  "false_positive_risks": ["what might trick us"],
  "required_follow_up_recon": ["what we still need to know"],
  "confidence_level": "high|medium|low"
}}"""

        try:
            response = self.ai.query(
                "Create tactical exploitation context from recon.",
                prompt
            )
            import re
            match = re.search(r'\{[\s\S]*\}', response)
            if match:
                return json.loads(match.group(0))
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in structured_analyzer.py: {_e}')

        return {"error": "tactical context unavailable"}
