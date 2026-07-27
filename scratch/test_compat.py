from core.result_contracts import ToolResult as ContractToolResult, ResultStatus
from tools.tool_manager import ToolResult as LegacyToolResult
import sys

# Add project root to path
sys.path.append(r"C:\Users\ASUS\Desktop\red team")


def test_legacy_tool_result():
    print("Testing Legacy ToolResult shape parity...")
    t = LegacyToolResult(
        tool="curl",
        command="curl http://target.com",
        stdout="Hello World",
        stderr="no errors",
        exit_code=0,
        duration=1.23,
        status="success"
    )

    # 1. Properties
    assert t.duration_seconds == 1.23
    t.duration_seconds = 4.56
    assert t.duration == 4.56
    assert t.duration_seconds == 4.56

    # 2. Defaults/Schema parity
    assert hasattr(t, "timestamp")
    assert isinstance(t.timestamp, float)
    assert t.target == ""
    assert t.failure_reason is None
    assert t.failure_severity == "low"
    assert t.exception_traceback is None
    assert t.is_valid is True
    assert t.validation_errors == []
    assert t.partial_output is False

    # 3. size properties
    assert t.stdout_size_bytes == 11
    assert t.stderr_size_bytes == 9

    # 4. timeouts & rate limits
    assert t.was_timeout is False
    t.was_timeout = True
    assert t.status == "timeout"
    assert t.was_timeout is True

    t.was_rate_limited = True
    assert t.status == "rate_limited"
    assert t.was_rate_limited is True

    print("[+] Legacy ToolResult verified successfully!")


def test_contracts_alignment():
    print("Testing Contract ToolResult alignment...")
    t = ContractToolResult(
        tool="curl",
        command="curl http://target.com",
        exit_code=0,
        status=ResultStatus.SUCCESS,
        stdout="Hello World",
        stderr="no errors",
        duration_seconds=1.23
    )

    # Aliases
    assert t.duration == 1.23
    t.duration = 4.56
    assert t.duration_seconds == 4.56

    print("[+] Contract ToolResult verified successfully!")


if __name__ == "__main__":
    test_legacy_tool_result()
    test_contracts_alignment()
    print("[+] All alignment tests passed successfully!")
