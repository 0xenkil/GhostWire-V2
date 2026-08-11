import ast
import os
from typing import Optional

# P2-5 (SEC-1): real isolation mechanisms, strongest first. Each is a shell prefix
# that ACTUALLY confines execution (no network + namespace/filesystem isolation).
# If NONE is present the run is NEVER silently trusted as isolated — it is either
# refused (require_sandbox) or clearly tagged UNSANDBOXED.
_ISOLATION_MECHANISMS = [
    ("firejail", "firejail --quiet --noprofile --net=none --private "
                 "--rlimit-fsize=104857600 --rlimit-nproc=64"),
    ("bwrap", "bwrap --unshare-all --die-with-parent --ro-bind / / "
              "--tmpfs /tmp --proc /proc --dev /dev"),
    ("unshare", "unshare --map-root-user --net --fork --pid --mount-proc"),
]


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
    """Executes validated payload scripts on the VPS, ISOLATED when a sandbox
    mechanism (firejail/bwrap/unshare) is available on the host. P2-5 (SEC-1): the
    boundary is NEVER falsely claimed — if no mechanism is present the run is
    tagged ``[UNSANDBOXED]`` (or refused when isolation is required), so no
    consumer trusts a boundary that isn't there."""

    def __init__(self, tool_manager=None):
        self.validator = SafePayloadValidator()
        self.tool_manager = tool_manager

    def _have_binary(self, name: str) -> bool:
        """Is ``name`` present on the EXECUTION host (remote if configured, else local)?"""
        try:
            if getattr(self.tool_manager, "remote", None):
                ec, out, _ = self.tool_manager.remote.execute(f"command -v {name}")
                return ec == 0 and bool((out or "").strip())
            import shutil
            return shutil.which(name) is not None
        except Exception:
            return False

    def detect_isolation(self):
        """Return ``(mechanism, prefix)`` for the strongest AVAILABLE isolation
        tool, or ``(None, "")`` if none — never assumes one exists."""
        for name, prefix in _ISOLATION_MECHANISMS:
            if self._have_binary(name):
                return name, prefix
        return None, ""

    def run(self, script_code: str, proxy: Optional[str] = None,
            require_sandbox: Optional[bool] = None) -> str:
        if not self.tool_manager:
            return "Blocked: Sandbox requires tool_manager for remote execution."

        # 1. Validate AST
        tree = ast.parse(script_code)
        self.validator.visit(tree)

        if not self.validator.is_safe:
            return f"Blocked: Dangerous statements detected: {', '.join(self.validator.errors)}"

        # 2. Establish REAL isolation (P2-5). Fail-closed: if the operator requires
        # a sandbox and none can be established, refuse rather than run unconfined.
        mechanism, prefix = self.detect_isolation()
        sandboxed = mechanism is not None
        if require_sandbox is None:
            require_sandbox = os.getenv(
                "REQUIRE_SANDBOX", "false").strip().lower() in ("1", "true", "yes")
        if require_sandbox and not sandboxed:
            return ("Blocked: sandbox REQUIRED but no isolation mechanism "
                    "(firejail/bwrap/unshare) is available on the host — refusing "
                    "to execute UNSANDBOXED (SEC-1 fail-closed).")

        # 3. Execute on the VPS, wrapped in the isolation prefix when available.
        import uuid
        remote_file = f"/tmp/sandbox_{uuid.uuid4().hex[:8]}.py"
        try:
            if getattr(self.tool_manager, 'remote', None):
                self.tool_manager.remote.upload_content(
                    script_code, remote_file)
            else:
                with open(remote_file, 'w', encoding='utf-8') as f:
                    f.write(script_code)

            import shlex
            quoted_remote_file = shlex.quote(remote_file)
            inner = f"timeout 120 python3 {quoted_remote_file}"
            if proxy:
                quoted_proxy = shlex.quote(proxy)
                inner = f"HTTP_PROXY={quoted_proxy} HTTPS_PROXY={quoted_proxy} {inner}"
            cmd = f"{prefix} {inner}" if sandboxed else inner

            res = self.tool_manager.run("bash", cmd, "sandbox", silent=True)
            output = res.stdout if res else ""
            if res and res.stderr:
                output += f"\n[STDERR]\n{res.stderr}"
            # Tag the provenance honestly so no consumer mistakes unconfined output
            # for isolated output.
            label = f"[SANDBOXED:{mechanism}]" if sandboxed else "[UNSANDBOXED]"
            return f"{label}\n" + (output if output else "Execution completed with no output.")
        except Exception as e:
            return f"Blocked: Execution failed: {str(e)}"
        finally:
            try:
                if getattr(self.tool_manager, 'remote', None):
                    self.tool_manager.remote.execute(f"rm -f {remote_file}")
                else:
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
