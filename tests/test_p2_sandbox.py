"""Phase 2 — P2-5 real sandbox or no sandbox claim (SEC-1).

The old "sandbox" ran python3 with NO isolation while claiming to be isolated.
Now: real isolation (firejail/bwrap/unshare) is used when available and the run
is tagged [SANDBOXED:<mech>]; with none available it is tagged [UNSANDBOXED]
(never falsely isolated) or REFUSED when isolation is required (fail-closed).
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.payload_sandbox import PayloadSandbox  # noqa: E402

SAFE = "result = 1 + 1"


class _Remote:
    def __init__(self, have):
        self._have = set(have)

    def execute(self, cmd, timeout=None):
        name = cmd.split()[-1]                 # "command -v <name>"
        return (0, f"/usr/bin/{name}", "") if name in self._have else (1, "", "")

    def upload_content(self, content, path):
        pass


class _TM:
    def __init__(self, have):
        self.remote = _Remote(have)
        self.last_cmd = None

    def run(self, tool, cmd, phase, silent=False):
        self.last_cmd = cmd
        return types.SimpleNamespace(stdout="ok", stderr="")


def test_isolation_wraps_command_and_tags_sandboxed():
    tm = _TM(have={"firejail"})
    out = PayloadSandbox(tool_manager=tm).run(SAFE)
    assert out.startswith("[SANDBOXED:firejail]")
    assert tm.last_cmd.startswith("firejail ")
    assert "python3" in tm.last_cmd


def test_prefers_strongest_available():
    tm = _TM(have={"bwrap", "unshare"})     # no firejail → bwrap wins over unshare
    out = PayloadSandbox(tool_manager=tm).run(SAFE)
    assert out.startswith("[SANDBOXED:bwrap]")


def test_no_isolation_is_tagged_unsandboxed_not_faked():
    tm = _TM(have=set())
    out = PayloadSandbox(tool_manager=tm).run(SAFE)
    assert out.startswith("[UNSANDBOXED]")           # honest, never a false claim
    assert not tm.last_cmd.startswith(("firejail", "bwrap", "unshare"))


def test_require_sandbox_refuses_when_none_available():
    tm = _TM(have=set())
    out = PayloadSandbox(tool_manager=tm).run(SAFE, require_sandbox=True)
    assert "Blocked: sandbox REQUIRED" in out
    assert tm.last_cmd is None                        # nothing executed


def test_require_sandbox_runs_when_isolation_present():
    tm = _TM(have={"unshare"})
    out = PayloadSandbox(tool_manager=tm).run(SAFE, require_sandbox=True)
    assert out.startswith("[SANDBOXED:unshare]")


def test_dangerous_script_still_blocked_before_isolation():
    tm = _TM(have={"firejail"})
    out = PayloadSandbox(tool_manager=tm).run("import os\nos.system('id')")
    assert out.startswith("Blocked:")
    assert tm.last_cmd is None
