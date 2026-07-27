import re

with open(r"C:\Users\ASUS\Desktop\red team\tools\tool_manager.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Add imports
content = re.sub(
    r"from core.result_contracts import FragileParseFixer",
    "from core.result_contracts import FragileParseFixer, ToolResult, ResultStatus",
    content
)

# 2. Remove the ToolResult class definition entirely
class_pattern = r"class ToolResult:\s*def __init__.*?def __repr__\(self\) -> str:\s*return f\"<ToolResult tool=\{self\.tool\} status=\{self\.status\} duration=\{self\.duration:\.1f\}s>\""
content = re.sub(class_pattern, "", content, flags=re.DOTALL)

# 3. Replace kwargs: duration=duration -> duration_seconds=duration
content = re.sub(r"duration=duration", "duration_seconds=duration", content)

# 4. Replace string statuses with enums
content = re.sub(
    r'status="not_installed"',
    "status=ResultStatus.BLOCKED",
    content)
content = re.sub(r'status="blocked"', "status=ResultStatus.BLOCKED", content)
content = re.sub(r'status="timeout"', "status=ResultStatus.TIMEOUT", content)
content = re.sub(r'status="failed"', "status=ResultStatus.FAILURE", content)
content = re.sub(r'status="success"', "status=ResultStatus.SUCCESS", content)
content = re.sub(
    r'status=result\.status,',
    'status=result.status.value if hasattr(result.status, "value") else str(result.status),',
    content)

# 5. Fix the explicit status=status in _execute
content = content.replace(
    'status = "success"',
    'status = ResultStatus.SUCCESS')
content = content.replace('status = "failed"', 'status = ResultStatus.FAILURE')

with open(r"C:\Users\ASUS\Desktop\red team\tools\tool_manager.py", "w", encoding="utf-8") as f:
    f.write(content)

print("tool_manager.py patched.")
