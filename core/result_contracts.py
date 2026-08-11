"""
Strict boundary validation layer: ensures all stage outputs conform to unified schema.
This prevents contract breakage where one stage outputs shape X but next expects shape Y.

Every stage result must conform to ToolResult or PhaseResult schema.
Validation is STRICT: fails fast on schema violations, logs exact violations.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
import json


class ResultStatus(str, Enum):
    """Valid result statuses - only these are allowed"""
    SUCCESS = "success"
    # Command executed successfully but returned no actionable results
    NO_FINDINGS = "no_findings"
    PARTIAL = "partial"      # Some output, may not be complete
    FAILURE = "failure"      # Complete failure
    TIMEOUT = "timeout"      # Command timeout
    BLOCKED = "blocked"      # WAF or Scope block
    SCOPE_BLOCKED = "scope_blocked"
    WAF_BLOCKED = "waf_blocked"
    TLS_BLOCKED = "tls_blocked"
    CAPTCHA_BLOCKED = "captcha_blocked"
    NOT_INSTALLED = "not_installed"
    FALLBACK = "fallback"
    FALLBACK_SUCCESS = "fallback_success"
    RATE_LIMITED = "rate_limited"
    VALIDATION_ERROR = "validation_error"
    SKIPPED = "skipped"      # Phase or tool was skipped (e.g. preflight)
    ERROR = "error"          # Unhandled internal error
    UNKNOWN = "unknown"


class ResultSeverity(str, Enum):
    """Severity of failures - for triaging"""
    CRITICAL = "critical"    # Blocks subsequent phases
    HIGH = "high"            # Degrades quality but continuable
    MEDIUM = "medium"        # Non-blocking
    LOW = "low"              # Info only


@dataclass
class ToolResult:
    """
    UNIFIED result schema for all tool executions.
    Every tool (curl, nmap, nikto, sqlmap, etc) outputs this format.

    Strict rules:
    - stdout, stderr must be strings (never None)
    - exit_code must be int
    - status must be one of ResultStatus enum
    - timestamp must exist
    - Never silently drop fields or use defaults
    """
    # Execution tracking
    tool: str                           # Tool name (e.g., "nmap", "curl")
    command: str                        # Full executed command
    exit_code: int                      # Exit code (0 = success)
    status: ResultStatus                # Normalized status

    # Output streams - MUST be strings, never None
    stdout: str = field(default="")     # Standard output
    stderr: str = field(default="")     # Standard error

    # Metadata
    timestamp: float = field(default=0.0)
    duration_seconds: float = field(default=0.0)
    target: str = field(default="")

    # Failure diagnostics
    failure_reason: Optional[str] = None
    failure_severity: ResultSeverity = field(default=ResultSeverity.LOW)
    exception_traceback: Optional[str] = None

    # Output characteristics
    stdout_size_bytes: int = field(default=0)
    stderr_size_bytes: int = field(default=0)

    # Validation state
    is_valid: bool = field(default=True)
    validation_errors: list[str] = field(default_factory=list)

    # Context for downstream processing
    was_timeout: bool = field(default=False)
    was_rate_limited: bool = field(default=False)
    partial_output: bool = field(default=False)
    parsed: dict = field(default_factory=dict)

    # P0-10: the state-store tool_runs.id assigned when this run was persisted.
    # Lets an agent stamp any finding derived from this run with an EXACT
    # originating-run link (state_store.add_finding(tool_run_id=...)). None until
    # the run is logged.
    tool_run_id: Optional[int] = None

    # P3-3: the normalized WAF-evasion tactic applied to THIS run (e.g.
    # "header_mutation", "ip_rotation"), or None when the command ran without
    # evasion. Persisted to tool_runs.evasion_applied so the batch WAF learner
    # (learn_from_engagement) can attribute per-tactic effectiveness from the
    # durable run log instead of a phase_data key that was never populated.
    evasion_applied: Optional[str] = None

    def __post_init__(self):
        if isinstance(self.status, str):
            try:
                self.status = ResultStatus(self.status)
            except ValueError:
                status_text = self.status.strip().lower().replace(" ", "_")
                status_aliases = {
                    "failed": ResultStatus.FAILURE,
                    "failure": ResultStatus.FAILURE,
                    "blocked": ResultStatus.BLOCKED,
                    "scope_blocked": ResultStatus.SCOPE_BLOCKED,
                    "waf_blocked": ResultStatus.WAF_BLOCKED,
                    "tls_blocked": ResultStatus.TLS_BLOCKED,
                    "captcha_blocked": ResultStatus.CAPTCHA_BLOCKED,
                    "not_installed": ResultStatus.NOT_INSTALLED,
                    "fallback": ResultStatus.FALLBACK,
                    "fallback_success": ResultStatus.FALLBACK_SUCCESS,
                    "timeout": ResultStatus.TIMEOUT,
                    "partial": ResultStatus.PARTIAL,
                    # tool_manager emits "partial_success" (useful output despite
                    # a WAF/partial block). Without this alias it normalized to
                    # UNKNOWN, silently discarding the "this run produced data"
                    # signal. Map it to the canonical PARTIAL status.
                    "partial_success": ResultStatus.PARTIAL,
                    "rate_limited": ResultStatus.RATE_LIMITED,
                    "validation_error": ResultStatus.VALIDATION_ERROR,
                    "skipped": ResultStatus.SKIPPED,
                    "error": ResultStatus.ERROR,
                    "unknown": ResultStatus.UNKNOWN,
                    "success": ResultStatus.SUCCESS,
                    "no_findings": ResultStatus.NO_FINDINGS,
                }
                self.status = status_aliases.get(
                    status_text, ResultStatus.UNKNOWN)

        if isinstance(self.failure_severity, str):
            try:
                self.failure_severity = ResultSeverity(self.failure_severity)
            except ValueError:
                self.failure_severity = ResultSeverity.LOW

    @property
    def success(self) -> bool:
        # PARTIAL ("partial_success") means the tool produced USEFUL output
        # despite a problem (e.g. whatweb fingerprinting behind a WAF). It MUST
        # count as success or the caller's `if r.success` finding-parse gate
        # silently DROPS those findings — a real "found nothing" cause on WAF'd
        # targets.
        return self.status in (ResultStatus.SUCCESS,
                               ResultStatus.FALLBACK_SUCCESS,
                               ResultStatus.PARTIAL)

    @success.setter
    def success(self, value: bool):
        if value:
            # Don't mask validation errors with success
            if self.status not in (
                    ResultStatus.SUCCESS, ResultStatus.FALLBACK_SUCCESS,
                    ResultStatus.PARTIAL, ResultStatus.VALIDATION_ERROR):
                self.status = ResultStatus.SUCCESS
        else:
            if self.status in (ResultStatus.SUCCESS,
                               ResultStatus.FALLBACK_SUCCESS,
                               ResultStatus.PARTIAL):
                self.status = ResultStatus.FAILURE

    def produced_result(self, capability: str = "") -> bool:
        """P0-9 — capability-keyed, PARSED-field result-presence predicate.

        Answers "did this run actually produce the KIND of result its capability
        implies?", derived from the structured ``parsed`` output — NOT a per-tool
        banner table and NOT raw stdout length. It is distinct from ``success``
        (a status) and from "differs from baseline": a fetch that GETS A RESPONSE
        produced a result even if that response equals the baseline. Callers pass
        the tool's capability so a banner-only nmap (`exit 0`, no parsed ports)
        reads as NO_FINDINGS, while a whatweb-behind-a-WAF partial still counts.
        """
        p = self.parsed if isinstance(self.parsed, dict) else {}

        def _nonempty(*keys) -> bool:
            for k in keys:
                v = p.get(k)
                if isinstance(v, (list, dict, set, tuple)) and len(v) > 0:
                    return True
                if isinstance(v, bool) and v:
                    return True
            return False

        cap = (capability or "").strip().lower()
        # Scanners: real ports / services / findings / vulns parsed.
        if any(t in cap for t in ("scan", "port", "vuln")):
            return _nonempty("open_ports", "services", "port_details",
                             "findings", "vulnerabilities")
        # Discovery / enumeration / fingerprint: a non-empty parsed asset list.
        if any(t in cap for t in ("discover", "recon", "enum", "crawl",
                                  "fingerprint", "subdomain", "brute", "dir")):
            return _nonempty("subdomains", "discovered_paths", "hosts",
                             "live_hosts", "discovered_urls", "technologies",
                             "emails", "credentials", "users", "is_behind_waf")
        # Fetch / HTTP: GOT A RESPONSE (a body), NOT a differential.
        if any(t in cap for t in ("fetch", "http", "request", "curl", "probe")):
            return len((self.stdout or "").strip()) > 0

        # Unknown capability: any non-empty parsed collection counts; else fall
        # back to a non-trivial body. This is the generic honest signal — no
        # per-tool table.
        for v in p.values():
            if isinstance(v, (list, dict, set, tuple)) and len(v) > 0:
                return True
        return len((self.stdout or "").strip()) > 0

    @property
    def duration(self) -> float:
        return self.duration_seconds

    @duration.setter
    def duration(self, value: float):
        self.duration_seconds = float(value or 0.0)

    # Legacy attributes for compatibility
    @property
    def has_error(self) -> bool:
        return not self.success

    def get_output(self) -> str:
        return self.stdout if self.stdout else self.stderr

    def validate(self) -> tuple[bool, list[str]]:
        """
        Validate this result against schema.
        Returns (is_valid, list_of_errors)
        """
        errors = []

        # Type validation
        if not isinstance(self.tool, str) or not self.tool:
            errors.append("tool must be non-empty string")
        if not isinstance(self.command, str):
            errors.append("command must be string")
        if not isinstance(self.exit_code, int):
            errors.append(f"exit_code must be int, got {type(self.exit_code)}")
        if not isinstance(self.stdout, str):
            errors.append(f"stdout must be string, got {type(self.stdout)}")
        if not isinstance(self.stderr, str):
            errors.append(f"stderr must be string, got {type(self.stderr)}")
        if not isinstance(self.timestamp, float):
            errors.append(
                f"timestamp must be float, got {
                    type(
                        self.timestamp)}")
        if not isinstance(self.duration_seconds, float):
            errors.append(
                f"duration_seconds must be float, got {
                    type(
                        self.duration_seconds)}")

        # Enum validation
        if not isinstance(self.status, ResultStatus):
            errors.append(f"status must be ResultStatus, got {self.status}")
        if not isinstance(self.failure_severity, ResultSeverity):
            errors.append(
                f"failure_severity must be ResultSeverity, got {
                    self.failure_severity}")

        # Logical validation
        if self.success and self.exit_code != 0:
            errors.append("status is SUCCESS but exit_code is non-zero")
        if self.success and not self.stdout and not self.stderr:
            errors.append(
                "status is SUCCESS but both stdout and stderr are empty")
        if self.exit_code == 0 and self.status in (
                ResultStatus.FAILURE, ResultStatus.VALIDATION_ERROR):
            errors.append(f"exit_code is 0 but status is {self.status}")

        self.is_valid = len(errors) == 0
        self.validation_errors = errors
        return self.is_valid, errors

    def to_dict(self) -> dict:
        """Convert to dict, ensuring no None values"""
        return {
            "tool": self.tool,
            "command": self.command,
            "exit_code": self.exit_code,
            "status": self.status.value,
            "stdout": self.stdout or "",
            "stderr": self.stderr or "",
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "target": self.target,
            "failure_reason": self.failure_reason or "",
            "failure_severity": self.failure_severity.value,
            "exception_traceback": self.exception_traceback or "",
            "stdout_size_bytes": len(self.stdout.encode('utf-8')),
            "stderr_size_bytes": len(self.stderr.encode('utf-8')),
            "was_timeout": self.was_timeout,
            "was_rate_limited": self.was_rate_limited,
            "partial_output": self.partial_output,
        }

    def __repr__(self) -> str:
        return (
            f"ToolResult(tool={self.tool}, status={self.status.value}, "
            f"exit_code={self.exit_code}, stdout_len={len(self.stdout)}, "
            f"stderr_len={len(self.stderr)})"
        )


@dataclass
class PhaseResult:
    """
    UNIFIED result schema for phase execution.
    Each agent (recon, exploitation, etc) returns this format.
    """
    phase: str                          # Phase name
    status: ResultStatus                # Overall phase status
    timestamp: float = field(default=0.0)

    # Outputs - phase-specific structured data
    data: dict = field(default_factory=dict)      # Findings, results, etc

    # Diagnostics
    tools_executed: int = field(default=0)
    tools_succeeded: int = field(default=0)
    tools_failed: int = field(default=0)
    total_runtime_seconds: float = field(default=0.0)

    # Error tracking
    error_message: Optional[str] = None
    exception_traceback: Optional[str] = None

    # Validation state
    is_valid: bool = field(default=True)
    validation_errors: list[str] = field(default_factory=list)

    def validate(self) -> tuple[bool, list[str]]:
        """Validate against schema"""
        errors = []

        if not isinstance(self.phase, str) or not self.phase:
            errors.append("phase must be non-empty string")
        if not isinstance(self.status, ResultStatus):
            errors.append(f"status must be ResultStatus, got {self.status}")
        if not isinstance(self.data, dict):
            errors.append(f"data must be dict, got {type(self.data)}")
        if not isinstance(self.tools_executed, int):
            errors.append(
                f"tools_executed must be int, got {
                    type(
                        self.tools_executed)}")

        # Logical checks
        if self.tools_executed < 0:
            errors.append("tools_executed cannot be negative")
        if self.tools_succeeded > self.tools_executed:
            errors.append("tools_succeeded exceeds tools_executed")
        if self.tools_failed > self.tools_executed:
            errors.append("tools_failed exceeds tools_executed")

        self.is_valid = len(errors) == 0
        self.validation_errors = errors
        return self.is_valid, errors

    def to_dict(self) -> dict:
        """Convert to dict"""
        return {
            "phase": self.phase,
            "status": self.status.value,
            "timestamp": self.timestamp,
            "data": self.data,
            "tools_executed": self.tools_executed,
            "tools_succeeded": self.tools_succeeded,
            "tools_failed": self.tools_failed,
            "total_runtime_seconds": self.total_runtime_seconds,
            "error_message": self.error_message or "",
        }


class ResultValidator:
    """
    Strict validation at stage boundaries.
    Every input/output between stages goes through this.
    """

    @staticmethod
    def validate_tool_result(
            result: Any, tool_name: str) -> tuple[ToolResult, bool]:
        """
        Convert any tool output to ToolResult and validate strictly.
        If validation fails, returns best-effort ToolResult with error details.

        Args:
            result: Raw output (dict, string, tuple, or ToolResult)
            tool_name: Name of tool for context

        Returns:
            (validated_result, is_valid)
        """
        # If already ToolResult, validate it
        if isinstance(result, ToolResult):
            is_valid, errors = result.validate()
            if not is_valid:
                result.is_valid = False
                result.validation_errors = errors
                result.status = ResultStatus.VALIDATION_ERROR
            return result, is_valid

        # Convert from dict
        if isinstance(result, dict):
            try:
                tr = ToolResult(
                    tool=result.get("tool", tool_name),
                    command=result.get("command", "unknown"),
                    exit_code=int(result.get("exit_code", -1)),
                    status=ResultStatus(
                        result.get(
                            "status",
                            "unknown")) if isinstance(
                        result.get("status"),
                        str) else ResultStatus.UNKNOWN,
                    stdout=str(result.get("stdout", "") or ""),
                    stderr=str(result.get("stderr", "") or ""),
                    timestamp=float(result.get("timestamp", 0.0)),
                    duration_seconds=float(
                        result.get("duration_seconds", 0.0)),
                    target=result.get("target", ""),
                    failure_reason=result.get("failure_reason"),
                    exception_traceback=result.get("exception_traceback"),
                    was_timeout=result.get("was_timeout", False),
                    was_rate_limited=result.get("was_rate_limited", False),
                    partial_output=result.get("partial_output", False),
                    parsed=result.get("parsed", {}),
                )
            except (ValueError, TypeError) as e:
                tr = ToolResult(
                    tool=tool_name,
                    command="",
                    exit_code=-1,
                    status=ResultStatus.VALIDATION_ERROR,
                    stdout="",
                    stderr="",
                    failure_reason=f"Failed to parse dict result: {str(e)}",
                    failure_severity=ResultSeverity.HIGH,
                )
            is_valid, errors = tr.validate()
            return tr, is_valid

        # Tuple/list format (exit_code, stdout, stderr)
        if isinstance(result, (tuple, list)) and len(result) >= 3:
            try:
                tr = ToolResult(
                    tool=tool_name,
                    command="",
                    exit_code=int(result[0]),
                    status=ResultStatus.SUCCESS if int(
                        result[0]) == 0 else ResultStatus.FAILURE,
                    stdout=str(result[1] or ""),
                    stderr=str(result[2] or ""),
                    timestamp=0.0,
                )
            except (ValueError, IndexError) as e:
                tr = ToolResult(
                    tool=tool_name,
                    command="",
                    exit_code=-1,
                    status=ResultStatus.VALIDATION_ERROR,
                    failure_reason=f"Failed to parse tuple result: {str(e)}",
                    failure_severity=ResultSeverity.HIGH,
                )
            is_valid, errors = tr.validate()
            return tr, is_valid

        # Unrecognized format
        tr = ToolResult(
            tool=tool_name,
            command="",
            exit_code=-1,
            status=ResultStatus.VALIDATION_ERROR,
            failure_reason=f"Cannot parse result format: {
                type(result).__name__}",
            failure_severity=ResultSeverity.HIGH,
        )
        return tr, False

    @staticmethod
    def validate_phase_result(
            result: Any, phase_name: str) -> tuple[PhaseResult, bool]:
        """
        Convert any phase output to PhaseResult and validate strictly.
        """
        if isinstance(result, PhaseResult):
            is_valid, errors = result.validate()
            if not is_valid:
                result.is_valid = False
                result.validation_errors = errors
                result.status = ResultStatus.VALIDATION_ERROR
            return result, is_valid

        if isinstance(result, dict):
            try:
                pr = PhaseResult(
                    phase=result.get("phase", phase_name),
                    status=ResultStatus(
                        result.get(
                            "status",
                            "unknown")) if isinstance(
                        result.get("status"),
                        str) else ResultStatus.UNKNOWN,
                    data=result.get("data", {}),
                    tools_executed=int(result.get("tools_executed", 0)),
                    tools_succeeded=int(result.get("tools_succeeded", 0)),
                    tools_failed=int(result.get("tools_failed", 0)),
                    total_runtime_seconds=float(
                        result.get("total_runtime_seconds", 0.0)),
                    error_message=result.get("error_message"),
                    exception_traceback=result.get("exception_traceback"),
                )
            except (ValueError, TypeError) as e:
                pr = PhaseResult(
                    phase=phase_name,
                    status=ResultStatus.VALIDATION_ERROR,
                    error_message=f"Failed to parse phase result: {str(e)}",
                )
            is_valid, errors = pr.validate()
            if not is_valid:
                pr.is_valid = False
                pr.validation_errors = errors
                pr.status = ResultStatus.VALIDATION_ERROR
            return pr, is_valid

        # Unrecognized
        pr = PhaseResult(
            phase=phase_name,
            status=ResultStatus.VALIDATION_ERROR,
            error_message=f"Cannot parse phase result format: {
                type(result).__name__}",
        )
        return pr, False

    @staticmethod
    def enforce_boundary(input_data: Any, stage_name: str,
                         expected_type: str, logger) -> Any:
        """
        Enforce strict validation at stage boundary.
        Prevents bad data from propagating to next stage.

        Args:
            input_data: Data from previous stage
            stage_name: Current stage name
            expected_type: "tool_result" or "phase_result"
            logger: Logger instance

        Returns:
            Validated result (ToolResult or PhaseResult)

        Raises:
            ValueError if validation fails on critical fields
        """
        if expected_type == "tool_result":
            result, is_valid = ResultValidator.validate_tool_result(
                input_data, stage_name)
            if not is_valid:
                logger.error(
                    f"[BOUNDARY] Tool result validation FAILED at {stage_name}\n"
                    f"  Errors: {', '.join(result.validation_errors)}\n"
                    f"  Result: {result}"
                )
                if result.failure_severity == ResultSeverity.CRITICAL:
                    raise ValueError(
                        f"Critical validation failure at {stage_name}: {
                            ', '.join(
                                result.validation_errors)}")
            return result

        elif expected_type == "phase_result":
            result, is_valid = ResultValidator.validate_phase_result(
                input_data, stage_name)
            if not is_valid:
                logger.error(
                    f"[BOUNDARY] Phase result validation FAILED at {stage_name}\n"
                    f"  Errors: {', '.join(result.validation_errors)}"
                )
                raise ValueError(
                    f"Validation failure at {stage_name}: {
                        ', '.join(
                            result.validation_errors)}")
            return result

        raise ValueError(f"Unknown expected_type: {expected_type}")


class FragileParseFixer:
    """
    Fixes for fragile parsing patterns that break contracts.
    Use these instead of .split() patterns.
    """

    @staticmethod
    def safe_split_json_extraction(text: str, default: dict = None) -> dict:
        """
        Safely extract JSON from text that may have markdown fences, extra text.
        Never crashes with IndexError.
        """
        if default is None:
            default = {}

        import re

        # Try markdown-fenced JSON first
        if "```json" in text:
            try:
                match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
                if match:
                    return json.loads(match.group(1))
            except (json.JSONDecodeError, IndexError):
                pass

        # Try bare JSON object
        try:
            match = re.search(r'\{[\s\S]*\}', text)
            if match:
                return json.loads(match.group(0))
        except (json.JSONDecodeError, IndexError):
            pass

        # Failed to parse - log and return default
        return default

    @staticmethod
    def safe_marker_extraction(
            text: str, marker_start: str, marker_end: str = "\n", default: str = "") -> str:
        """
        Safely extract content between markers (no IndexError crashes).
        """
        if not text or marker_start not in text:
            return default

        try:
            start_idx = text.index(marker_start) + len(marker_start)
            remainder = text[start_idx:]

            if marker_end:
                end_idx = remainder.index(marker_end)
                return remainder[:end_idx].strip()
            else:
                return remainder.strip()
        except (ValueError, IndexError):
            return default

    @staticmethod
    def safe_path_extraction(text: str, separator: str = "/") -> list[str]:
        """
        Safely extract path components without crashing on missing separators.
        """
        if not text:
            return []

        parts = text.split(separator)
        return [p for p in parts if p]  # Filter empties

    @staticmethod
    def safe_port_extraction(host_port: str) -> tuple[str, int]:
        """
        Safely extract host and port (e.g., "example.com:8080").
        Returns (host, port) with port defaulting to 80/443 based on protocol.
        """
        if not host_port:
            return "", 80

        host_port = host_port.strip()

        # Remove protocol if present
        for proto in ["https://", "http://", "//"]:
            if host_port.startswith(proto):
                host_port = host_port[len(proto):]

        # Remove path if present
        if "/" in host_port:
            host_port = host_port.split("/")[0]

        # Split on colon
        if ":" in host_port:
            parts = host_port.split(":")
            try:
                return parts[0], int(parts[1])
            except (ValueError, IndexError):
                return parts[0], 80

        return host_port, 80


@dataclass
class Evidence:
    """WS4 — structured proof object attached to a confirmed vulnerability.

    "Proof or it didn't happen": a finding is only a vulnerability when it ships
    a reproducible differential (control vs. test) or a self-proving artifact.
    This object captures exactly that so the report can show *why* it's real and
    a reviewer can re-run it.
    """
    # what proved it: "differential" (response delta vs baseline),
    # "artifact" (self-proving content e.g. /etc/passwd, data dump),
    # "oob" (out-of-band callback), "none" (unproven — should not be confirmed)
    proof_type: str = "none"
    reproducible_command: str = ""
    request: str = ""               # the test request (curl/raw)
    response_excerpt: str = ""      # the test response (truncated)
    baseline_excerpt: str = ""      # the control/normal response (truncated)
    differential: str = ""          # concrete description of what differs
    similarity_to_baseline: float = -1.0  # -1 = not measured
    # P0-1: per-type persisted measurements that is_proven() now REQUIRES, so a
    # proof can no longer be forged by setting proof_type alone
    # (closes EVIDENCE-ISPROVEN-FORGEABLE).
    control_absent: bool = False  # artifact: proving content ABSENT in control/baseline
    test_present: bool = False    # artifact: proving content PRESENT in the test response
    oob_token: str = ""                    # unique out-of-band token actually observed
    notes: str = ""

    def is_proven(self) -> bool:
        """True only when this evidence carries a MEASURED demonstration of
        impact — P0-1 hardened. ``proof_type`` alone is never sufficient; each
        type requires its persisted measurement, closing
        EVIDENCE-ISPROVEN-FORGEABLE.
        """
        if self.proof_type == "differential":
            # Must be MEASURED (>= 0.0) and materially different from baseline.
            # The old `similarity < 0` branch trusted an unmeasured, AI-described
            # delta — a forgery hole — and is deliberately removed: no baseline
            # measurement now means LEAD, not proof.
            return bool(self.differential) and (0.0 <= self.similarity_to_baseline < 0.97)
        if self.proof_type == "artifact":
            # The proving content must be ABSENT in control and PRESENT in test.
            return bool(self.control_absent and self.test_present)
        if self.proof_type == "oob":
            # A real out-of-band callback carries a unique token that was observed.
            return bool(self.oob_token)
        return False

    def to_dict(self) -> dict:
        return {
            "proof_type": self.proof_type,
            "reproducible_command": self.reproducible_command,
            "request": self.request[:2000],
            "response_excerpt": self.response_excerpt[:2000],
            "baseline_excerpt": self.baseline_excerpt[:1000],
            "differential": self.differential[:800],
            "similarity_to_baseline": self.similarity_to_baseline,
            "control_absent": self.control_absent,
            "test_present": self.test_present,
            "oob_token": self.oob_token[:200],
            "notes": self.notes[:500],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Evidence":
        if not isinstance(d, dict):
            return cls()
        return cls(
            proof_type=d.get("proof_type", "none"),
            reproducible_command=d.get("reproducible_command", ""),
            request=d.get("request", ""),
            response_excerpt=d.get("response_excerpt", ""),
            baseline_excerpt=d.get("baseline_excerpt", ""),
            differential=d.get("differential", ""),
            similarity_to_baseline=float(d.get("similarity_to_baseline", -1.0)),
            control_absent=bool(d.get("control_absent", False)),
            test_present=bool(d.get("test_present", False)),
            oob_token=d.get("oob_token", ""),
            notes=d.get("notes", ""),
        )


@dataclass
class TargetModel:
    """WS2 — Target Comprehension Layer output.

    The synthesized *thesis* about a target that recon produces and exploitation
    consumes. It is what turns a pile of facts into a strategy, so the engine
    stops attacking impossible surfaces (e.g. apex SQLi on a static SPA).

    AI-synthesized (no hardcoded "if SPA then X" rules) — the profiler feeds the
    AI real evidence (headers, JS bundle, tech signals, endpoints) and the AI
    reasons about type, value, and which vuln classes are plausible.
    """
    target: str = ""
    # spa | api | cms | monolith | static | gateway | unknown
    target_type: str = "unknown"
    # framework / CDN / server / language / auth scheme
    stack: dict = field(default_factory=dict)
    # concrete endpoints / params / forms / API routes (incl. JS-bundle-parsed)
    attack_surface: list[str] = field(default_factory=list)
    api_routes: list[str] = field(default_factory=list)
    # where the value is (admin, billing, reseller API, auth) — AI-reasoned
    value_map: list[str] = field(default_factory=list)
    # vuln classes worth trying, ranked
    plausible_vuln_classes: list[str] = field(default_factory=list)
    # vuln classes that are impossible on this target type (do NOT attempt)
    implausible_vuln_classes: list[str] = field(default_factory=list)
    # free-text strategic guidance injected into downstream agent prompts
    recommended_strategy: str = ""
    # ranked subdomains by likely value (high → low)
    ranked_subdomains: list[str] = field(default_factory=list)
    confidence: float = 0.0
    reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "stack": self.stack,
            "attack_surface": self.attack_surface,
            "api_routes": self.api_routes,
            "value_map": self.value_map,
            "plausible_vuln_classes": self.plausible_vuln_classes,
            "implausible_vuln_classes": self.implausible_vuln_classes,
            "recommended_strategy": self.recommended_strategy,
            "ranked_subdomains": self.ranked_subdomains,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TargetModel":
        if not isinstance(d, dict):
            return cls()
        return cls(
            target=d.get("target", ""),
            target_type=d.get("target_type", "unknown"),
            stack=d.get("stack", {}) if isinstance(d.get("stack"), dict) else {},
            attack_surface=list(d.get("attack_surface", []) or []),
            api_routes=list(d.get("api_routes", []) or []),
            value_map=list(d.get("value_map", []) or []),
            plausible_vuln_classes=list(d.get("plausible_vuln_classes", []) or []),
            implausible_vuln_classes=list(d.get("implausible_vuln_classes", []) or []),
            recommended_strategy=d.get("recommended_strategy", ""),
            ranked_subdomains=list(d.get("ranked_subdomains", []) or []),
            confidence=float(d.get("confidence", 0.0) or 0.0),
            reasoning=d.get("reasoning", ""),
        )


@dataclass
class ReconBundle:
    """
    Contract schema for the Recon phase output data bundle.
    """
    open_ports: list[int] = field(default_factory=list)
    masscan_ports: list[int] = field(default_factory=list)
    services: dict = field(default_factory=dict)
    base_paths: list[str] = field(default_factory=list)
    ai_analysis: str = ""
    waf_present: bool = False
    waf_type: str = ""
    waf_fingerprint: dict = field(default_factory=dict)
    waf_bypass_url: Optional[str] = None
    is_cdn: bool = False
    baseline_size: int = 0
    resolved_ip: Optional[str] = None
    subdomain_liveness: dict = field(default_factory=dict)
    subdomains: list[dict] = field(default_factory=list)
    subdomains_high: list[str] = field(default_factory=list)
    subdomains_medium: list[str] = field(default_factory=list)
    structured_findings: dict = field(default_factory=dict)
    tactical_reasoning: dict = field(default_factory=dict)
    system_awareness: dict = field(default_factory=dict)

    def validate(self) -> tuple[bool, list[str]]:
        errors = []
        if not isinstance(self.open_ports, list):
            errors.append("open_ports must be a list")
        if not isinstance(self.services, dict):
            errors.append("services must be a dict")
        if not isinstance(self.base_paths, list):
            errors.append("base_paths must be a list")
        if not isinstance(self.subdomains, list):
            errors.append("subdomains must be a list")
        return len(errors) == 0, errors
