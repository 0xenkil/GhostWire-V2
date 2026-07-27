"""
Constraint Engine: Ensures AI decisions are grounded in evidence.
Prevents the AI from attempting exploits without supporting evidence.
"""


class ConstraintEngine:
    """
    Defines and enforces constraints on what exploitations the AI can attempt.
    Transforms soft recommendations into hard constraints.
    """

    @staticmethod
    def build_constraints_from_findings(findings: list) -> dict:
        """
        Build a constraints dict that blocks invalid exploitation attempts.

        If we DON'T have evidence for something, the AI can't try it.
        If we HAVE evidence of testing and failure, the AI won't retry.
        """

        constraints = {
            "can_attempt": {},      # {exploit_type: True/False}
            "tested_and_failed": [],  # List of (exploit_type, reason)
            # {exploit_type: [required_evidence_types]}
            "required_evidence": {},
            "blocked_tools": [],    # Tools that shouldn't be used
            "tool_priority": {},    # Tool priority rankings
        }

        tech_stack = [f for f in findings if f.get("type") == "tech_stack"]
        negative_findings = [
            f for f in findings if f.get("type") == "negative_evidence"]
        positive_findings = [f for f in findings if f.get("type") in (
            "vulnerability", "vulnerability_hint", "discovered_path", "file_exposure"
        )]

        # Build can_attempt based on evidence
        constraints["can_attempt"] = {
            "sql_injection": bool([f for f in positive_findings if "sql" in f.get("detail", "").lower()]),
            "xss": bool([f for f in positive_findings if "xss" in f.get("detail", "").lower()]),
            "rce": bool([f for f in positive_findings if "rce" in f.get("detail", "").lower()]),
            "lfi": bool([f for f in positive_findings if "lfi" in f.get("detail", "").lower()]),
            "path_traversal": bool([f for f in positive_findings if "path" in f.get("detail", "").lower()]),
            "wordpress_exploit": bool([f for f in tech_stack if "wordpress" in f.get("detail", "").lower()]),
            "apache_exploit": bool([f for f in tech_stack if "apache" in f.get("detail", "").lower()]),
        }

        # Add negative constraints from failed tests
        for neg_finding in negative_findings:
            detail = neg_finding.get("detail", "").lower()

            # Extract what was tested
            if "sql_injection" in detail:
                constraints["tested_and_failed"].append((
                    "sql_injection",
                    neg_finding.get("detail", "")
                ))
                constraints["can_attempt"]["sql_injection"] = False

            if "xss" in detail:
                constraints["tested_and_failed"].append((
                    "xss",
                    neg_finding.get("detail", "")
                ))
                constraints["can_attempt"]["xss"] = False

        # Build tool priority (prefer high-confidence tools)
        constraints["tool_priority"] = {
            "curl": 1.0,           # Always available
            "sqlmap": 0.8,         # Reliable but slow
            "dalfox": 0.8,         # Good for XSS
            "commix": 0.7,         # Command injection
            "hydra": 0.6,          # Slow, noisy
            "nmap": 0.5,           # May be blocked by WAF
            "nuclei": 0.4,         # May be blocked by WAF
            "nikto": 0.4,          # May be blocked by WAF
        }

        return constraints

    @staticmethod
    def validate_exploitation_command(command: str, constraints: dict) -> dict:
        """
        Validate if a command is allowed given constraints.

        Returns:
            {
                "allowed": bool,
                "reason": str,
                "suggested_fix": str or None,
            }
        """
        result = {
            "allowed": True,
            "reason": "Command is allowed",
            "suggested_fix": None,
        }

        command_lower = command.lower()

        # Check if attempting SQL injection without evidence
        if any(k in command_lower for k in [
               "sqlmap", "sql", "injection", "union", "sqlite"]):
            if not constraints.get("can_attempt", {}).get(
                    "sql_injection", False):
                result["allowed"] = False
                result["reason"] = "SQL injection exploit attempted without evidence of SQLi vulnerability"
                result["suggested_fix"] = "First identify a SQL-injectable parameter"
                return result

        # Check if attempting XSS without evidence
        if any(k in command_lower for k in [
               "dalfox", "xss", "alert(", "script"]):
            if not constraints.get("can_attempt", {}).get("xss", False):
                result["allowed"] = False
                result["reason"] = "XSS exploit attempted without evidence of XSS vulnerability"
                result["suggested_fix"] = "First identify XSS vectors in parameters"
                return result

        # Check if attempting RCE without evidence
        if any(k in command_lower for k in [
               "rce", "commix", "command injection", "shell", "exec"]):
            if not constraints.get("can_attempt", {}).get("rce", False):
                result["allowed"] = False
                result["reason"] = "RCE exploit attempted without evidence of RCE vulnerability"
                result["suggested_fix"] = "First check for command injection vectors"
                return result

        # Check tested_and_failed list
        tested_failed = constraints.get("tested_and_failed", [])
        for exploit_type, reason in tested_failed:
            if exploit_type.lower() in command_lower:
                result["allowed"] = False
                result["reason"] = f"Already tested {exploit_type} and it failed: {reason}"
                result["suggested_fix"] = f"Skip {exploit_type}, try different vector"
                return result

        return result

    @staticmethod
    def filter_tool_list(tools_to_try: list, constraints: dict,
                         waf_present: bool = False) -> list:
        """
        Filter and prioritize a tool list based on constraints and WAF status.

        Args:
            tools_to_try: Tools AI wants to use
            constraints: Constraint dict from build_constraints_from_findings
            waf_present: If WAF is detected, deprioritize slow/noisy tools

        Returns:
            Filtered list sorted by priority
        """
        priority_map = constraints.get("tool_priority", {})
        blocked = constraints.get("blocked_tools", [])

        filtered = []
        for tool in tools_to_try:
            if tool in blocked:
                continue

            # Deprioritize heavy tools if WAF is present
            if waf_present and tool in ("nuclei", "nikto", "nmap", "masscan"):
                continue

            priority = priority_map.get(tool, 0.5)
            filtered.append((priority, tool))

        # Sort by priority descending
        filtered.sort(reverse=True, key=lambda x: x[0])
        return [tool for _, tool in filtered]


class ExploitationPlanner:
    """
    Plans multi-stage exploitation based on findings and constraints.
    Builds exploitation narratives instead of random tool sequences.
    """

    @staticmethod
    def plan_exploitation_stages(findings: list, constraints: dict) -> list:
        """
        Create a multi-stage exploitation plan based on findings.

        Stages:
        1. Enumeration: identify more details
        2. Vulnerability testing: confirm specific vulns
        3. Exploitation: gain access
        4. Post-exploitation: maintain access, gather data

        Returns:
            List of stages, each with recommended commands
        """

        stages = []

        # Stage 1: Enumeration
        enum_stage = {
            "stage": 1,
            "name": "Deep Enumeration",
            "description": "Identify more details about the target",
            "commands": [
                "curl -sI {target} | head -20  # Get response headers",
                "whatweb {target}  # Fingerprint web technologies",
                "wfuzz -c -w /wordlist.txt {target}/FUZZ  # Fuzz for hidden paths",
            ]
        }
        stages.append(enum_stage)

        # Stage 2: Vulnerability Testing
        vuln_stage = {
            "stage": 2,
            "name": "Vulnerability Testing",
            "description": "Confirm specific vulnerabilities",
            "commands": []
        }

        # Add commands based on what we haven't tested yet
        if constraints.get("can_attempt", {}).get("sql_injection"):
            vuln_stage["commands"].append(
                "sqlmap -u {target} --batch --level=1")

        if constraints.get("can_attempt", {}).get("xss"):
            vuln_stage["commands"].append(
                "dalfox url {target} -d 'all_params'")

        if constraints.get("can_attempt", {}).get("rce"):
            vuln_stage["commands"].append("commix -u {target}")

        # Tech-specific tests
        for finding in findings:
            if finding.get("type") == "tech_stack":
                detail = finding.get("detail", "").lower()

                if "wordpress" in detail:
                    vuln_stage["commands"].append(
                        "curl -s {target}/wp-json/wp/v2/plugins/")

                if "apache" in detail:
                    vuln_stage["commands"].append("curl -s -X TRACE {target}")

        if vuln_stage["commands"]:
            stages.append(vuln_stage)

        # Stage 3: Exploitation (if we found vulnerabilities)
        vuln_findings = [f for f in findings if f.get("type") in (
            "vulnerability", "vulnerability_hint", "cve"
        )]

        if vuln_findings:
            exploit_stage = {
                "stage": 3,
                "name": "Exploitation",
                "description": "Actively exploit confirmed vulnerabilities",
                "commands": []
            }

            for vuln in vuln_findings:
                detail = vuln.get("detail", "")

                if "sql" in detail.lower():
                    exploit_stage["commands"].append(
                        "sqlmap -u {target} --batch --level=2 --risk=2 --batch"
                    )

                if "rce" in detail.lower():
                    exploit_stage["commands"].append(
                        "commix -u {target} --data='cmd' --batch"
                    )

            if exploit_stage["commands"]:
                stages.append(exploit_stage)

        return stages
