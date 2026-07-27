import re
from pathlib import Path


def refactor():
    target_dir = Path(r"C:\Users\ASUS\Desktop\red team")

    # 1. Clean up wsl_executor.py
    wsl_file = target_dir / "core" / "wsl_executor.py"
    if wsl_file.exists():
        content = wsl_file.read_text(encoding="utf-8")
        # Remove the alias lines
        content = re.sub(
            r"^WSLExecutor\s*=\s*WSLExecutor\s*\n?",
            "",
            content,
            flags=re.MULTILINE)
        content = re.sub(
            r"^SSHExecutor\s*=\s*WSLExecutor\s*\n?",
            "",
            content,
            flags=re.MULTILINE)
        # Remove the legacy commented-out block at the bottom
        content = re.sub(
            r"# ==============================================================================[\s\S]*",
            "",
            content)
        wsl_file.write_text(content.strip() + "\n", encoding="utf-8")
        print("Cleaned up wsl_executor.py")

    # 2. Refactor all other files
    for py_file in target_dir.rglob("*.py"):
        if py_file.name == "refactor_wsl.py":
            continue

        try:
            content = py_file.read_text(encoding="utf-8")
            original_content = content

            # Replace import path
            content = content.replace("core.ssh_executor", "core.wsl_executor")
            content = content.replace("from ssh_executor", "from wsl_executor")

            # Replace class names
            content = content.replace("SSHExecutor", "WSLExecutor")
            content = content.replace("ssh_executor=", "remote_executor=")

            # Replace function arguments (e.g. def __init__(self,
            # ssh_executor=None))
            content = re.sub(r'\bssh_executor\b', 'remote_executor', content)

            # Replace string variables, docstrings
            # Replace self._ssh ? We can leave self._ssh as is to minimize breakage, or rename it.
            # It's safer to just do the core class and argument renaming as
            # planned.

            if content != original_content:
                py_file.write_text(content, encoding="utf-8")
                print(f"Refactored {py_file.name}")
        except Exception as e:
            print(f"Failed to refactor {py_file.name}: {e}")


if __name__ == "__main__":
    refactor()
