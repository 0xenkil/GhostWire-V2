"""
AUDIT: Contract Breakage Issues and Fixes

This document lists all identified boundary failures and their fixes.
Each issue breaks the contract between stages, causing cascading failures.
"""

# ============================================================================
# ISSUE #1: Fragile JSON Extraction in tool_manager.py:310 & 535
# ============================================================================
# PROBLEM:
#   response.split("```json")[1].split("```")[0].strip()
#   Crashes with IndexError if:
#   - "```json" not in response
#   - Split result doesn't contain "```"
# 
# CONTRACT VIOLATION:
#   AI backend promises to return JSON.
#   Code assumes specific format with markdown fences.
#   If AI returns JSON without fences, or returns plain text, contract breaks.
#
# FIX:
#   Use result_contracts.FragileParseFixer.safe_split_json_extraction()

# BEFORE (tool_manager.py:310):
"""
if "```json" in response:
    response = response.split("```json")[1].split("```")[0].strip()
elif "{" in response:
    match = re.search(r'\{.*\}', response, re.DOTALL)
    if match:
        response = match.group(0)

result = pyjson.loads(response)  # Crashes if response is invalid JSON
"""

# AFTER:
"""
from core.result_contracts import FragileParseFixer

metadata = FragileParseFixer.safe_split_json_extraction(response, default={})
if not metadata:
    log.error(f"AI failed to return valid JSON for cleanup metadata. Got: {response[:100]}")
    return {
        "cleanup_paths": [],
        "keep_paths": [],
        "size_estimate_mb": 0,
        "description": "AI analysis failed - no valid JSON"
    }
result = metadata
"""

# ============================================================================
# ISSUE #2: Fragile Marker Extraction in waf_ghost_engine.py:246
# ============================================================================
# PROBLEM:
#   cookie_str = stdout.split("__SOLVED_COOKIES__=")[1].split("\\n")[0].strip()
#   Crashes with IndexError if marker not in stdout
#
# CONTRACT VIOLATION:
#   Python solver script promises to output specific marker.
#   If script fails silently, stdout is empty, crash happens.
#   Next stage (exploitation) never runs, engagement fails silently.
#
# FIX:
#   Use result_contracts.FragileParseFixer.safe_marker_extraction()

# BEFORE (waf_ghost_engine.py:246):
"""
if "__SOLVED_COOKIES__=" in stdout:
    cookie_str = stdout.split("__SOLVED_COOKIES__=")[1].split("\\n")[0].strip()
    if cookie_str:
        log.info(f"Ghost Protocol: Challenge solved successfully...")
"""

# AFTER:
"""
from core.result_contracts import FragileParseFixer

cookie_str = FragileParseFixer.safe_marker_extraction(
    stdout, 
    marker_start="__SOLVED_COOKIES__=",
    marker_end="\\n",
    default=""
)
if cookie_str:
    log.info(f"Ghost Protocol: Challenge solved successfully...")
else:
    log.warning("Ghost Protocol: Solver did not produce cookie. Stdout: {stdout[:200]}")
"""

# ============================================================================
# ISSUE #3: Fragile Path Splitting in poc_templates.py:190
# ============================================================================
# PROBLEM:
#   HOST = TARGET.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
#   Chains splits without validation.
#   If TARGET is malformed (no /, no :), still returns something but may be wrong.
#
# CONTRACT VIOLATION:
#   Caller assumes HOST is valid hostname/IP.
#   If parsing is wrong, all downstream exploits use wrong target.
#
# FIX:
#   Use result_contracts.FragileParseFixer.safe_port_extraction()

# BEFORE (poc_templates.py:190):
"""
HOST = TARGET.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
"""

# AFTER:
"""
from core.result_contracts import FragileParseFixer

HOST, PORT = FragileParseFixer.safe_port_extraction(TARGET)
if not HOST:
    raise ValueError(f"Cannot extract hostname from target: {TARGET}")
# Now HOST and PORT are guaranteed valid
"""

# ============================================================================
# ISSUE #4: Fragile Output Parsing in agents/base_agent.py:679
# ============================================================================
# PROBLEM:
#   target_domain = cmd.split()[-1]
#   Works if cmd has words, but if cmd is empty string, returns empty.
#   Downstream code assumes target_domain is valid, crashes later.
#
# CONTRACT VIOLATION:
#   Code assumes command has predictable structure.
#   If AI generates malformed command, parsing is wrong.
#   Failure only appears much later when target_domain is used.
#
# FIX:
#   Validate command structure before parsing. Reject early if malformed.

# BEFORE (base_agent.py:679):
"""
target_domain = cmd.split()[-1]
"""

# AFTER:
"""
parts = cmd.split()
if not parts:
    raise ValueError(f"Cannot extract target from empty command: {cmd}")
target_domain = parts[-1]
if not target_domain or target_domain.startswith("-"):
    raise ValueError(f"Target extracted from command is not valid: '{target_domain}' from {cmd}")
"""

# ============================================================================
# ISSUE #5: Silent Failure in orchestrator.py:54
# ============================================================================
# PROBLEM:
#   except Exception:
#       pass
#   Catches ALL exceptions and silently continues.
#   Failure details are lost. Phase may mark complete even if it failed.
#
# CONTRACT VIOLATION:
#   Next phase assumes previous phase succeeded.
#   But with silent catch, previous phase might have partially failed.
#   Data passed to next phase is incomplete/corrupted.
#
# FIX:
#   Log all exceptions with traceback. Fail loudly. Never silently ignore.

# BEFORE (orchestrator.py:54):
"""
try:
    # Load rules
except Exception:
    pass
"""

# AFTER:
"""
try:
    # Load rules
except Exception as e:
    log.error(f"Failed to load rules: {e}", exc_info=True)
    raise  # Don't swallow - let caller handle
"""

# ============================================================================
# ISSUE #6: State Bug - Phase Marked Complete Before Data Verified
# ============================================================================
# PROBLEM:
#   Phase executes, marks self.store.set_phase_status("complete")
#   But never validates that phase_data is non-empty/valid
#   Next phase loads empty/corrupt data, crashes
#
# CONTRACT VIOLATION:
#   Caller assumes phase_data exists and is valid.
#   But if previous phase partially failed, phase_data is incomplete.
#
# FIX:
#   Validate phase_data before marking complete.
#   Use result_contracts.ResultValidator to enforce schema.

# BEFORE (typical agent.py):
"""
self.store.set_phase_status(engagement_id, "exploitation", "complete", "")
"""

# AFTER:
"""
# Validate before marking complete
validator = ResultValidator()
phase_result, is_valid = validator.validate_phase_result({
    "phase": "exploitation",
    "status": "success",
    "data": bundle,
    "tools_executed": len(commands_run),
    "tools_succeeded": commands_succeeded,
    "tools_failed": commands_failed,
})

if not is_valid:
    log.error(f"Phase data validation FAILED: {phase_result.validation_errors}")
    phase_result.status = ResultStatus.VALIDATION_ERROR
    self.store.set_phase_status(engagement_id, "exploitation", "validation_error", 
                               f"Phase data invalid: {', '.join(phase_result.validation_errors)}")
else:
    self.store.set_phase_status(engagement_id, "exploitation", "complete", "")
"""

# ============================================================================
# ISSUE #7: Environment Assumption - Missing Tools Not Detected
# ============================================================================
# PROBLEM:
#   Code runs: "nmap -sV ..."
#   If nmap not installed, subprocess fails silently or returns generic error
#   Downstream code assumes nmap output format, parses garbage
#
# CONTRACT VIOLATION:
#   Output parser assumes it got real nmap output.
#   But got error message instead (e.g., "command not found").
#
# FIX:
#   Pre-check tool availability before execution.
#   Validate tool in path. Get version. Verify before use.

# BEFORE:
"""
result = execute_command("nmap -sV target.com")
# Parse result assuming it's valid nmap output
"""

# AFTER:
"""
# Pre-check tool
tool_check = execute_command("which nmap && nmap --version")
if tool_check.exit_code != 0:
    log.error(f"nmap not available: {tool_check.stderr}")
    # Don't continue - fail fast
    return ToolResult(
        tool="nmap",
        command="nmap -sV target.com",
        exit_code=-1,
        status=ResultStatus.FAILURE,
        failure_reason="Tool 'nmap' not found in PATH",
        failure_severity=ResultSeverity.CRITICAL,
    )

# Only then run the actual command
result = execute_command("nmap -sV target.com")
"""

# ============================================================================
# ISSUE #8: Timeout Handling - Command Partial Success Treated as Failure
# ============================================================================
# PROBLEM:
#   Command times out but produces partial output.
#   Code treats as complete failure, discards partial data.
#   But partial data might be useful (e.g., first 5 open ports found).
#
# CONTRACT VIOLATION:
#   Downstream might accept partial_output=true, but code never sets it.
#   Partial data is lost forever.
#
# FIX:
#   Detect timeout, preserve partial output, mark as partial.

# BEFORE:
"""
try:
    result = subprocess.run(cmd, timeout=30)
except subprocess.TimeoutExpired:
    return ToolResult(
        tool="nmap",
        exit_code=-1,
        status=ResultStatus.TIMEOUT,
        stdout="",  # Partial output lost
        stderr=""
    )
"""

# AFTER:
"""
try:
    result = subprocess.run(cmd, timeout=30, capture_output=True, text=True)
    tool_result = ToolResult(
        tool="nmap",
        exit_code=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        status=ResultStatus.SUCCESS if result.returncode == 0 else ResultStatus.FAILURE,
    )
except subprocess.TimeoutExpired as e:
    # Preserve whatever partial output we got
    tool_result = ToolResult(
        tool="nmap",
        exit_code=-1,
        status=ResultStatus.TIMEOUT,
        stdout=e.stdout or "",  # Partial output
        stderr=e.stderr or "",
        was_timeout=True,
        partial_output=True,
        failure_reason="Command exceeded 30s timeout",
    )

return tool_result
"""

# ============================================================================
# ISSUE #9: Schema Mismatch - stdout/stderr vs output/error
# ============================================================================
# PROBLEM:
#   StateStore returns: (stdout, stderr)
#   But EngagementAnalyzer read: run.get("output"), run.get("error")
#   Mismatch causes learning from empty fields
#
# CONTRACT VIOLATION:
#   Contract says tool_runs return (phase, tool, command, status, stdout, stderr, ...)
#   But code reads from wrong field names.
#
# FIX:
#   Use ToolResult schema consistently everywhere.
#   Never mix field naming. Validate field access.

# ============================================================================
# ISSUE #10: Silent Exception Handling in JSON Parsing
# ============================================================================
# PROBLEM:
#   try:
#       data = json.loads(response)
#   except Exception:
#       data = {}  # Silently default to empty
#   
#   Downstream code treats empty dict as valid, tries to process it.
#   Later crashes when expected keys missing.
#
# CONTRACT VIOLATION:
#   Contract says JSON parsing will succeed or fail loudly.
#   Silently returning {} makes caller think parsing succeeded.
#
# FIX:
#   Log error with full context. Raise. Don't silently default.

# BEFORE:
"""
try:
    parsed = json.loads(response)
except Exception:
    parsed = {}
"""

# AFTER:
"""
try:
    parsed = json.loads(response)
except json.JSONDecodeError as e:
    log.error(f"Failed to parse JSON response from AI:\\n{response[:500]}\\nError: {e}")
    raise ValueError(f"AI returned invalid JSON: {e}")
except Exception as e:
    log.error(f"Unexpected error parsing JSON: {e}", exc_info=True)
    raise
"""

# ============================================================================
# SUMMARY OF FIXES TO APPLY
# ============================================================================
"""
1. tool_manager.py:310 & 535
   - Use FragileParseFixer.safe_split_json_extraction()
   - Add default {} fallback
   - Log failures loudly

2. waf_ghost_engine.py:246
   - Use FragileParseFixer.safe_marker_extraction()
   - Add logging for missing marker

3. poc_templates.py:190
   - Use FragileParseFixer.safe_port_extraction()
   - Validate result before use

4. base_agent.py:679
   - Add command validation before parsing
   - Reject early with clear error

5. orchestrator.py:54, message_bus.py:35
   - Replace 'except Exception: pass' with proper logging + raise

6. All agents
   - Use ResultValidator.validate_phase_result() before marking complete
   - Never mark phase complete without verifying data

7. All tool execution
   - Pre-check tool availability
   - Use ToolResult schema consistently
   - Preserve partial output on timeout

8. All JSON parsing
   - Log full response on parse error
   - Raise, don't silently default
   - Use safe extraction functions

9. All field access
   - Use result_contracts.ToolResult and PhaseResult dataclasses
   - Validate at boundaries with ResultValidator
   - Never mix field naming conventions

10. All output parsing
    - Use safe_* functions from FragileParseFixer
    - Validate parsed results before using
    - Log exact parsing failures
"""
