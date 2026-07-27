"""
Finding Scorer: Adds confidence levels and prioritization to findings.
Enables strategic decision-making about which findings to pursue.
"""

import re


class FindingScorer:
    """
    Scores findings based on confidence, exploitability, and value.
    Higher score = more actionable and likely to lead to exploitation.
    """

    # Confidence scoring: how certain are we this finding is real?
    CONFIDENCE_LEVELS = {
        "header_confirmed": 0.95,      # HTTP header directly observed
        "response_pattern": 0.85,       # Response pattern matches vulnerability signature
        "tool_confirmed": 0.80,         # Scanner tool confirmed (nuclei/nikto)
        "heuristic": 0.65,              # Educated guess from multiple sources
        "single_indicator": 0.50,       # Single weak indicator
    }

    # Exploitability: how easy is it to exploit this?
    EXPLOITABILITY_SCORES = {
        "unauthenticated_rce": 1.0,
        "authenticated_rce": 0.8,
        "unauthenticated_info_disclosure": 0.9,
        "sql_injection": 0.85,
        "xss": 0.75,
        "lfi": 0.8,
        "directory_traversal": 0.8,
        "weak_credentials": 0.7,
        "default_credentials": 0.95,
        "cors_misconfiguration": 0.6,
        "missing_security_header": 0.4,
    }

    # Priority: how urgent is this to exploit?
    PRIORITY_TYPES = {
        "credentials": 0.95,             # Leaked passwords/keys
        "rce": 0.95,                     # Remote code execution
        "file_exposure": 0.85,           # Exposed files (.env, config, .git)
        "sqli": 0.85,                    # SQL injection
        "path_traversal": 0.80,          # Path traversal / LFI / RFI
        "xss": 0.70,                     # Cross-site scripting
        "auth_bypass": 0.90,             # Authentication bypass
        "weak_tls": 0.50,                # Weak TLS config
        "missing_headers": 0.30,         # Missing security headers
    }

    @staticmethod
    def score_finding(finding: dict) -> dict:
        """
        Score a finding and return enriched version with confidence/priority/exploitability.

        Input finding dict should have:
            - type: finding type
            - detail: finding detail text
            - severity: info/low/medium/high/critical
            - source: tool/agent that found it

        Returns enriched dict with:
            - confidence: 0-1 score
            - exploitability: 0-1 score
            - priority: 0-1 score
            - overall_score: 0-1 composite score
            - reasoning: explanation of scoring
        """

        result = dict(finding)  # Copy

        # Extract base scores
        confidence = FindingScorer._score_confidence(finding)
        exploitability = FindingScorer._score_exploitability(finding)
        priority = FindingScorer._score_priority(finding)

        # Composite: confidence × exploitability, weighted by priority
        overall = (confidence * exploitability * priority)

        result.update({
            "confidence": round(confidence, 2),
            "exploitability": round(exploitability, 2),
            "priority": round(priority, 2),
            "overall_score": round(overall, 2),
            "is_high_value": overall > 0.70,  # Actionable threshold
            "should_exploit_immediately": overall > 0.85 and finding.get("severity") in ("high", "critical"),
        })

        return result

    @staticmethod
    def _score_confidence(finding: dict) -> float:
        """How certain are we this finding is real?"""
        finding_type = finding.get("type", "").lower()
        detail = finding.get("detail", "").lower()
        source = finding.get("source", "").lower()

        # Header-level findings are very confident
        if "header" in finding_type and "missing" in detail:
            return FindingScorer.CONFIDENCE_LEVELS["header_confirmed"]

        # Tool-confirmed findings (nuclei, nikto)
        if source in ("nuclei", "nikto", "nmap"):
            return FindingScorer.CONFIDENCE_LEVELS["tool_confirmed"]

        # Tech stack detection is high confidence
        if "tech_stack" in finding_type or "technology" in finding_type:
            return FindingScorer.CONFIDENCE_LEVELS["header_confirmed"]

        # Default to medium-low confidence
        return FindingScorer.CONFIDENCE_LEVELS["single_indicator"]

    @staticmethod
    def _score_exploitability(finding: dict) -> float:
        """How exploitable is this finding?"""
        finding_type = finding.get("type", "").lower()
        detail = finding.get("detail", "").lower()

        # Direct CVE matches = very exploitable
        if re.search(r"cve-\d{4}-\d{4,5}", detail):
            return FindingScorer.EXPLOITABILITY_SCORES.get(
                "unauthenticated_rce", 0.9)

        # RCE/Code execution = extremely exploitable
        if any(k in detail for k in [
               "rce", "remote code", "command injection", "shell upload"]):
            return FindingScorer.EXPLOITABILITY_SCORES.get(
                "unauthenticated_rce", 1.0)

        # SQL injection = highly exploitable
        if "sql" in detail or "sqli" in finding_type:
            return FindingScorer.EXPLOITABILITY_SCORES.get(
                "sql_injection", 0.85)

        # Credentials = extremely exploitable
        if any(k in detail for k in [
               "password", "api key", "secret", "token", "credential"]):
            return FindingScorer.EXPLOITABILITY_SCORES.get(
                "weak_credentials", 0.95)

        # Path traversal / LFI
        if any(k in detail for k in [
               "path traversal", "lfi", "rfi", "directory traversal"]):
            return FindingScorer.EXPLOITABILITY_SCORES.get(
                "path_traversal", 0.8)

        # XSS
        if "xss" in detail or "cross-site" in detail:
            return FindingScorer.EXPLOITABILITY_SCORES.get("xss", 0.75)

        # Low value findings
        if any(k in detail for k in ["missing csp",
               "missing hsts", "uncommon header"]):
            return FindingScorer.EXPLOITABILITY_SCORES.get(
                "missing_security_header", 0.4)

        return 0.5  # Default: medium exploitability

    @staticmethod
    def _score_priority(finding: dict) -> float:
        """What's the priority of this finding?"""
        finding_type = finding.get("type", "").lower()
        detail = finding.get("detail", "").lower()

        # Credentials = TOP PRIORITY
        if any(k in detail for k in [
               "password", "api_key", "secret", "token"]):
            return FindingScorer.PRIORITY_TYPES.get("credentials", 0.95)

        # RCE = TOP PRIORITY
        if any(k in detail for k in [
               "rce", "remote code", "command injection", "shell"]):
            return FindingScorer.PRIORITY_TYPES.get("rce", 0.95)

        # File exposure (.env, .git, configs) = HIGH PRIORITY
        if any(k in detail for k in ["env", ".git", ".config", "exposure"]):
            return FindingScorer.PRIORITY_TYPES.get("file_exposure", 0.85)

        # SQL Injection = HIGH PRIORITY
        if "sqli" in finding_type or "sql_injection" in finding_type:
            return FindingScorer.PRIORITY_TYPES.get("sqli", 0.85)

        # Path traversal = HIGH PRIORITY
        if "path_traversal" in finding_type or "lfi" in finding_type:
            return FindingScorer.PRIORITY_TYPES.get("path_traversal", 0.80)

        # Auth bypass = HIGH PRIORITY
        if "auth" in detail and "bypass" in detail:
            return FindingScorer.PRIORITY_TYPES.get("auth_bypass", 0.90)

        # XSS = MEDIUM PRIORITY
        if "xss" in finding_type:
            return FindingScorer.PRIORITY_TYPES.get("xss", 0.70)

        # TLS/headers = LOW PRIORITY
        if any(k in detail for k in ["tls", "ssl", "header", "hsts", "csp"]):
            return FindingScorer.PRIORITY_TYPES.get("weak_tls", 0.30)

        return 0.5  # Default: medium priority

    @staticmethod
    def score_findings_batch(findings: list) -> list:
        """Score multiple findings and return sorted by overall_score descending."""
        scored = [FindingScorer.score_finding(f) for f in findings]
        return sorted(scored, key=lambda f: f.get(
            "overall_score", 0), reverse=True)


class NegativeEvidenceTracker:
    """
    Tracks negative findings: things we TESTED and confirmed do NOT exist or are NOT vulnerable.
    Prevents wasting time retesting dead-end paths.
    """

    @staticmethod
    def create_negative_finding(
            tool: str, target: str, finding_type: str, reason: str) -> dict:
        """
        Create a negative finding record.

        Args:
            tool: Which tool was used (e.g., "sqlmap")
            target: What was tested (e.g., URL/parameter)
            finding_type: What was NOT found (e.g., "sql_injection")
            reason: Why we're confident it's not vulnerable

        Returns:
            Finding dict suitable for store.add_finding()
        """
        return {
            "type": "negative_evidence",
            "target": target,
            "detail": f"[{tool}] NOT vulnerable to {finding_type}: {reason}",
            "severity": "info",
            "meta": {
                "tool_used": tool,
                "tested_for": finding_type,
                "confidence": "high",
            }
        }

    @staticmethod
    def should_retry_exploitation(
            finding_type: str, target: str, negative_findings: list) -> bool:
        """
        Check if we should retry a specific exploitation type on a target.
        Returns False if we already confirmed it's not vulnerable.

        Args:
            finding_type: What we want to exploit (e.g., "sql_injection")
            target: What target (URL)
            negative_findings: List of negative finding dicts

        Returns:
            True if we should retry, False if we're confident it won't work
        """
        for neg in negative_findings:
            if neg.get("type") == "negative_evidence":
                detail = neg.get("detail", "").lower()
                if finding_type.lower() in detail and target in neg.get("target", ""):
                    return False  # Already tested, doesn't exist

        return True  # Safe to retry
