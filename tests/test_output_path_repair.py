"""Guard: output paths must not trigger the input-file repair (2026-06-18).

`_validate_and_fix_command` repairs MISSING INPUT files (find → canonical). But it
treated an OUTPUT destination (-o/-oN/--output ...) the same way: the output file
doesn't exist yet by design, so `test -e` failed and it ran a full-filesystem
`find /` (30s timeout) on EVERY command writing to a fresh -o file — pure wasted
time that never helped. The fix skips the repair for output flags. These tests pin
that output paths are left alone while input repair still runs.
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fake(calls):
    class Remote:
        def execute(self, cmd, timeout=5):
            calls.append(cmd)
            if cmd.startswith("echo"):
                return (0, "/home/en", "")
            if cmd.startswith("test -e"):
                return (1, "", "")           # nothing exists
            if "find /" in cmd:
                return (1, "", "")           # find finds nothing
            return (0, "", "")
    f = types.SimpleNamespace()
    f.remote = Remote()
    f.validate_and_filter_flags = lambda c, t: c
    f._fix_glued_path_flags = lambda c: c
    f._remote_home_dir = "/home/en"
    f._canonical_substitute = lambda p, fl: "/home/en/redteam-workspace/recon_hosts.txt"
    return f


def test_output_path_skips_filesystem_find():
    from tools.tool_manager import ToolManager
    calls = []
    out = ToolManager._validate_and_fix_command(
        _fake(calls), "nuclei -u http://x -o /root/scan.txt", "nuclei")
    assert "/root/scan.txt" in out                      # preserved, not substituted
    assert not any("find /" in c for c in calls)        # no 30s filesystem scan


def test_nmap_output_flags_skip_find():
    from tools.tool_manager import ToolManager
    calls = []
    out = ToolManager._validate_and_fix_command(
        _fake(calls), "nmap -sT example.com -oN /tmp/fresh_scan.txt", "nmap")
    assert "/tmp/fresh_scan.txt" in out
    assert not any("find /" in c for c in calls)


def test_missing_input_file_still_repaired():
    from tools.tool_manager import ToolManager
    calls = []
    out = ToolManager._validate_and_fix_command(
        _fake(calls), "httpx -l /tmp/missing_hosts.txt", "httpx")
    assert "recon_hosts.txt" in out                     # input repair still runs
    assert any("find /" in c for c in calls)
