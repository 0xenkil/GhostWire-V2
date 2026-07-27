import ast
import re
from agents.base_agent import BaseAgent
import config_paths


class ValidationAgent(BaseAgent):
    """
    The GUARDIAN Agent: Validates AI-generated commands and scripts
    before execution to ensure safety, syntax correctness, and
    environment compatibility (Linux WSL).
    """

    def validate_python(self, code: str) -> tuple[bool, str, str]:
        """
        Validates Python code for syntax errors and safety.
        Returns (is_valid, fixed_code, reason).
        """
        if not code or len(code.strip()) < 10:
            return False, code, "Code is empty or too short."

        # 1. Syntax Check (using AST)
        try:
            ast.parse(code)
        except SyntaxError as e:
            self.log.warning(f"Syntax error in AI code: {e}")
            # Attempt AI-repair for minor syntax issues
            success, repaired_code, reason = self._repair_code(
                code, f"Syntax Error: {e}")
            if not success:
                return False, code, reason
            # Proceed to safety check with repaired code
            code = repaired_code

        # 2. Safety & Library Check
        # Use the centralized AST Sandbox validator for robust safety
        from core.payload_sandbox import SafePayloadValidator
        validator = SafePayloadValidator()
        validator.visit(ast.parse(code))

        if not validator.is_safe:
            return False, code, f"Forbidden operations detected: {', '.join(validator.errors)}"

        # 3. Logic Review - Replaced AI review with strict AST/Regex to save
        # tokens
        self.log.info(
            "Guardian AST and Safety checks passed. Skipping expensive AI logic review.")
        return True, code, "Passed AST and Safety review."

    def validate_bash(self, cmd: str) -> tuple[bool, str, str]:
        """
        Validates a bash command for safety and syntax.
        Returns (is_valid, fixed_cmd, reason).
        """
        if not cmd:
            return False, cmd, "Command is empty."

        # 1. Safety Filter
        infra = self._get_infra_rules()
        dangerous_patterns = infra.get("bash_dangerous_patterns", [
            r'rm\s+-rf\s+/', r'>\s+/dev/sda', r'mkfs', r'dd\s+if=',
            r'chmod\s+777\s+/', r'chown\s+root'
        ])
        for pattern in dangerous_patterns:
            if re.search(pattern, cmd):
                return False, cmd, f"Dangerous bash pattern: {pattern}"

        # 2. Syntax Repair (Ghost Protocol style)
        # Check for common AI hallucinations like 'nmap --script:script-name'
        fixed_cmd = cmd
        if "nmap " in fixed_cmd:
            fixed_cmd = re.sub(r'--script:', '--script=', fixed_cmd)

        # FIX C: Enforce AI wordlist path to prevent hallucinated dictionaries
        if "/usr/share/wordlists" in fixed_cmd:
            fixed_cmd = re.sub(
                r'/usr/share/wordlists[^\s]*',
                f'{config_paths.VPS_TEMP_DIR}/ai_wordlist.txt',
                fixed_cmd)

        # FIX D: Auto-inject concurrency limits for HTTP fuzzers
        if re.search(r'\b(ffuf|gobuster|wfuzz|dirsearch)\b', fixed_cmd):
            if "-t " not in fixed_cmd and "--threads " not in fixed_cmd:
                fixed_cmd = fixed_cmd.replace("ffuf ", "ffuf -t 10 ")
                fixed_cmd = fixed_cmd.replace(
                    "gobuster dir ", "gobuster dir -t 10 ")
                fixed_cmd = fixed_cmd.replace("wfuzz ", "wfuzz -t 10 ")
                fixed_cmd = fixed_cmd.replace("dirsearch ", "dirsearch -t 10 ")

        # Ensure timeout is present for network commands
        TOOL_TIMEOUTS = {
            "curl": 30,
            "wget": 30,
            "nikto": 900,
            "nmap": 900,
            "nuclei": 600,
            "sqlmap": 900,
            "hydra": 300,
            "gobuster": 300,
            "ffuf": 300,
            "dirsearch": 300,
            "wfuzz": 300,
        }
        for tool_name, timeout_val in TOOL_TIMEOUTS.items():
            if fixed_cmd.startswith(tool_name) or re.match(
                    rf"^\s*{tool_name}\b", fixed_cmd):
                if not re.search(r'(^|\s)timeout(\s|$)', fixed_cmd):
                    fixed_cmd = f"timeout {timeout_val} {fixed_cmd}"
                break

        return True, fixed_cmd, "Bash validation passed."

    def _repair_code(self, code: str, error_msg: str) -> tuple[bool, str, str]:
        """Attempt to fix syntax errors using the AI."""
        repair_prompt = (
            f"The following Python code has a syntax error: {error_msg}\n\n"
            f"Code:\n{code}\n\n"
            "Please fix the syntax error and return ONLY the raw corrected Python code."
        )
        try:
            fixed_code = self.think(repair_prompt).strip()
            if fixed_code.startswith("```"):
                fixed_code = re.sub(r"^```python\n?", "", fixed_code)
                fixed_code = re.sub(r"```$", "", fixed_code).strip()

            # Verify the fix
            ast.parse(fixed_code)
            return True, fixed_code, "Syntax repaired by Guardian."
        except Exception as e:
            return False, code, f"Syntax repair failed: {e}"

    async def run(self) -> dict:
        """
        ValidationAgent is a utility agent and does not have a standalone phase.
        It returns a success status by default.
        """
        return {"status": "success", "message": "Validation utility active."}

    def _handle_message(self, from_agent: str, payload: dict):
        # The ValidationAgent is mostly a utility agent called directly,
        # but could also listen for 'validation_request' events.
        if payload.get("event") == "validation_request":
            # Logic for async validation if needed
            pass
