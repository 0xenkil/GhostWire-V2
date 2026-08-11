"""Windows/WSL provisioning path must work as well as native Linux.

A go-install for the modern arsenal (gau/katana/…) was raising Windows
`[WinError 2]` because it ran a raw `["bash","-c",cmd]` — there is no bash.exe on
the Windows host; go-install must run INSIDE WSL. And even once installed, the
binary lands in ~/go/bin, which was NOT on the executor's tool PATH, so it was
neither runnable nor detectable (re-installed forever). Both are fixed here.
"""
from unittest.mock import patch

import config_paths
from tools.tool_manager import _local_user_bash_argv, _local_root_bash_argv


def test_go_install_routes_through_wsl_on_windows():
    with patch("platform.system", return_value="Windows"):
        # go-install runs as the USER inside WSL (binary -> ~/go/bin)
        assert _local_user_bash_argv("go install X@latest") == \
            ["wsl", "-e", "bash", "-c", "go install X@latest"]
        # the symlink step runs as root inside WSL
        assert _local_root_bash_argv("ln -sf a b")[:4] == ["wsl", "-u", "root", "-e"]


def test_go_install_is_native_bash_on_linux():
    with patch("platform.system", return_value="Linux"):
        assert _local_user_bash_argv("go install X@latest") == \
            ["bash", "-c", "go install X@latest"]
        assert _local_root_bash_argv("ln a b") == ["sudo", "bash", "-c", "ln a b"]


def test_exec_tool_path_includes_go_bin():
    # go-installed tools live in $HOME/go/bin; the executor PATH (and _wsl_which)
    # must include it so tools are runnable/detectable without a root symlink —
    # which matters on a WSL user without passwordless sudo.
    assert "$HOME/go/bin" in config_paths.WSL_TOOL_PATH
