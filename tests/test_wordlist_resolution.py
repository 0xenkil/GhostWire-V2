"""Guard: ffuf/gobuster wordlists resolve UNIVERSALLY at the execution layer (2026-06-20).

The #1 cause of ffuf/gobuster failures was a bad/placeholder/`{WORDLIST}` value
reaching the tool (commands come from many paths — grounding, repair, make-lighter
— so the agent-level substitution missed cases) → "no such file or directory".
`tool_manager._validate_and_fix_command` (which EVERY command passes through) now
resolves the `{WORDLIST}` token and any missing `-w` value to a real wordlist
(`_canonical_wordlist`, which prefers the AI-provisioned list, then standard
lists, then writes a generic fallback so the tool always runs).
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fake(existing):
    from tools.tool_manager import ToolManager

    class R:
        def execute(self, cmd, timeout=5):
            if cmd.startswith("test -e") or cmd.startswith("test -s"):
                path = cmd.split('"')[1] if '"' in cmd else ""
                return (0, "", "") if any(e in path for e in existing) else (1, "", "")
            return (0, "", "")   # mkdir/printf etc.
    f = types.SimpleNamespace()
    f.remote = R()
    f.validate_and_filter_flags = lambda c, t: c
    f._fix_glued_path_flags = lambda c: c
    f._canonical_wordlist = lambda: ToolManager._canonical_wordlist(f)
    # The resolver now goes through the generic local-or-remote helpers; bind them.
    f._path_exists = lambda p: ToolManager._path_exists(f, p)
    f._materialize_file = lambda p, c: ToolManager._materialize_file(f, p, c)
    # The path-repair loop also expands ~ and does the find-fallback via
    # _exec_on_host (local-or-remote). Bind it so the fake exercises that path.
    f._exec_on_host = lambda c, timeout=15: ToolManager._exec_on_host(f, c, timeout)
    # _validate_and_fix_command now also mkdir -p's output dirs at the end.
    f._ensure_output_dirs = lambda c: ToolManager._ensure_output_dirs(f, c)
    # ...and expands a leading ~/ in args to the host home.
    f._expand_home_tokens = lambda c: ToolManager._expand_home_tokens(f, c)
    return f, ToolManager


def test_canonical_prefers_ai_provisioned_wordlist():
    f, TM = _fake(["ai_wordlist.txt"])
    assert TM._canonical_wordlist(f).endswith("ai_wordlist.txt")


def test_canonical_writes_fallback_when_nothing_installed():
    f, TM = _fake(["fallback_wordlist.txt"])   # only the fallback 'exists' (after write)
    assert TM._canonical_wordlist(f).endswith("fallback_wordlist.txt")


def test_wordlist_token_resolved():
    f, TM = _fake(["ai_wordlist.txt"])
    out = TM._validate_and_fix_command(f, "gobuster dir -u https://x -w '{WORDLIST}'", "gobuster")
    assert "{WORDLIST}" not in out and "ai_wordlist.txt" in out


def test_missing_wordlist_placeholder_resolved():
    f, TM = _fake(["ai_wordlist.txt"])
    out = TM._validate_and_fix_command(f, "ffuf -u http://x/FUZZ -w /path/to/wordlist", "ffuf")
    assert "/path/to/wordlist" not in out and "ai_wordlist.txt" in out


def test_existing_wordlist_left_alone():
    f, TM = _fake(["common.txt", "ai_wordlist.txt"])
    out = TM._validate_and_fix_command(f, "ffuf -u http://x/FUZZ -w /usr/share/common.txt", "ffuf")
    assert "/usr/share/common.txt" in out
