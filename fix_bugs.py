import os


def fix_bug_6():
    path = "agents/recon_agent.py"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    old_code = "cmd = _re2.sub(r'https?://', '', cmd)"
    new_code = """schemeless_target = _re2.sub(r'^https?://', '', target)
                    cmd = cmd.replace(f" {target}", f" {schemeless_target}")"""

    if old_code in content:
        content = content.replace(old_code, new_code)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print("BUG-06 Fixed")
    else:
        print("BUG-06 old code not found")


def fix_bug_10():
    path = "agents/validation_agent.py"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    old_code = """if any(x in fixed_cmd for x in ["curl", "wget", "nmap", "hydra", "sqlmap"]):
            if "timeout " not in fixed_cmd:
                fixed_cmd = f"timeout 30 {fixed_cmd}" """

    new_code = """if any(fixed_cmd.startswith(x + " ") or fixed_cmd == x for x in ["curl", "wget", "nmap", "hydra", "sqlmap"]):
            import re as _val_re
            if not _val_re.search(r'(^|\\s)timeout(\\s|$)', fixed_cmd):
                fixed_cmd = f"timeout 30 {fixed_cmd}" """

    if old_code in content:
        content = content.replace(old_code, new_code)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print("BUG-10 Fixed")


def fix_bug_12():
    path = "core/tool_installer.py"
    if os.path.exists(path):
        pass  # Wait, bug 12 is in tool_manager.py
    path = "tools/tool_manager.py"
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        old_code = "rel = str(local_path).replace(\"\\\\\", \"/\").split(\"results/\")[-1]"
        new_code = "rel = Path(local_path).as_posix().split(\"results/\")[-1]"
        if old_code in content:
            content = content.replace(old_code, new_code)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            print("BUG-12 Fixed")

        old_code_2 = "return command.replace(original_tool, fallback_tool, 1)"
        new_code_2 = """import re as _bm_re
        return _bm_re.sub(r'(^|\\s)' + _bm_re.escape(original_tool) + r'(\\s|$)', r'\\1' + fallback_tool + r'\\2', command, 1)"""
        if old_code_2 in content:
            content = content.replace(old_code_2, new_code_2)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            print("BUG-15 Fixed")


def fix_bug_18():
    path = "core/orchestrator.py"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    old_code = "while self.task_queue:"
    new_code = "while self.task_queue:\n            if self.session.shutdown.is_set():\n                break"
    if old_code in content:
        content = content.replace(old_code, new_code)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print("BUG-18 Fixed (Orchestrator)")


fix_bug_6()
fix_bug_10()
fix_bug_12()
fix_bug_18()
