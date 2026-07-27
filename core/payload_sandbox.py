import ast
from typing import Optional


class SafePayloadValidator(ast.NodeVisitor):
    """AST validator to enforce safe, read-only offensive scripting."""
    FORBIDDEN_MODULES = {
        'os',
        'sys',
        'shutil',
        'subprocess',
        'platform',
        'socket',
        'ctypes',
        'code',
        'pickle',
        'importlib'}
    FORBIDDEN_FUNCTIONS = {
        'eval',
        'exec',
        'open',
        'write',
        'remove',
        'system',
        '__import__'}

    def __init__(self):
        self.is_safe = True
        self.errors = []

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in self.FORBIDDEN_MODULES:
                self.is_safe = False
                self.errors.append(f"Forbidden module import: {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module in self.FORBIDDEN_MODULES:
            self.is_safe = False
            self.errors.append(f"Forbidden from-import: {node.module}")
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id in self.FORBIDDEN_FUNCTIONS:
                self.is_safe = False
                self.errors.append(f"Forbidden function call: {node.func.id}")
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in self.FORBIDDEN_FUNCTIONS:
                self.is_safe = False
                self.errors.append(
                    f"Forbidden function call: {
                        node.func.attr}")
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name):
            if node.value.id in self.FORBIDDEN_MODULES:
                self.is_safe = False
                self.errors.append(
                    f"Forbidden attribute access on module: {
                        node.value.id}.{
                        node.attr}")
        self.generic_visit(node)


class PayloadSandbox:
    """Executes validated payload scripts in an isolated subprocess on the VPS."""

    def __init__(self, tool_manager=None):
        self.validator = SafePayloadValidator()
        self.tool_manager = tool_manager

    def run(self, script_code: str, proxy: Optional[str] = None) -> str:
        if not self.tool_manager:
            return "Blocked: Sandbox requires tool_manager for remote execution."

        # 1. Validate AST
        tree = ast.parse(script_code)
        self.validator.visit(tree)

        if not self.validator.is_safe:
            return f"Blocked: Dangerous statements detected: {', '.join(self.validator.errors)}"

        # 2. Execute securely over SSH on remote VPS
        import uuid
        remote_file = f"/tmp/sandbox_{uuid.uuid4().hex[:8]}.py"
        try:
            # Write file to remote using remote_executor or locally
            if getattr(self.tool_manager, 'remote', None):
                self.tool_manager.remote.upload_content(
                    script_code, remote_file)
            else:
                with open(remote_file, 'w', encoding='utf-8') as f:
                    f.write(script_code)

            # Execute it via tool_manager bash runner
            import shlex
            quoted_remote_file = shlex.quote(remote_file)
            cmd = f"python3 {quoted_remote_file}"
            if proxy:
                quoted_proxy = shlex.quote(proxy)
                cmd = f"HTTP_PROXY={quoted_proxy} HTTPS_PROXY={quoted_proxy} {cmd}"

            res = self.tool_manager.run("bash", cmd, "sandbox", silent=True)
            output = res.stdout if res else ""
            if res and res.stderr:
                output += f"\n[STDERR]\n{res.stderr}"
            return output if output else "Execution completed with no output."
        except Exception as e:
            return f"Blocked: Execution failed: {str(e)}"
        finally:
            try:
                if getattr(self.tool_manager, 'remote', None):
                    self.tool_manager.remote.execute(f"rm -f {remote_file}")
                else:
                    import os
                    if os.path.exists(remote_file):
                        os.remove(remote_file)
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f'Swallowed exception in payload_sandbox.py: {_e}')


def validate_script(script_code: str) -> list:
    """Validates the given script code and returns a list of error strings."""
    validator = SafePayloadValidator()
    try:
        tree = ast.parse(script_code)
        validator.visit(tree)
        # Match test expectations for error messages
        # "Forbidden module import: os"
        return validator.errors
    except Exception as e:
        return [f"Syntax error: {e}"]


def execute_in_sandbox(
        script_code: str, proxy: Optional[str] = None, tool_manager=None) -> str:
    """Executes the given script in a sandbox."""
    sandbox = PayloadSandbox(tool_manager=tool_manager)
    return sandbox.run(script_code, proxy=proxy)
