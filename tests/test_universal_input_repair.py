"""Universal pre-execution input-file repair — works for ANY tool, any flag.

The AI routinely references input files that were never written (e.g. the
hallucinated `live_subdomains.txt`). ToolManager's universal layer redirects any
MISSING input file to a canonical resource (host list / wordlist) regardless of
tool or flag, while leaving real files and output files alone.
"""

import pytest
from tools.tool_manager import ToolManager


class _Remote:
    def __init__(self, existing=None):
        self.existing = set(existing or [])

    def execute(self, cmd, timeout=5):
        if "echo $HOME" in cmd:
            return (0, "/home/en", "")
        if cmd.startswith("test -e") or "test -e" in cmd:
            # extract the quoted path
            path = cmd.split('test -e "', 1)[-1].rstrip('"') if 'test -e "' in cmd else ""
            return (0, "", "") if path in self.existing else (1, "", "")
        if "find /" in cmd:
            return (0, "", "")  # find locates nothing
        return (0, "", "")  # mkdir/rm/echo


class _Store:
    def __init__(self, hosts):
        self._hosts = hosts

    def get_all_findings(self, eid):
        return [{"type": "subdomain", "detail": f"{h} is live"} for h in self._hosts]


class _Sess:
    engagement_id = "eng1"
    target = "novalink.lk"


def _tm(existing=None, hosts=("api.novalink.lk", "project242.novalink.lk")):
    tm = ToolManager.__new__(ToolManager)
    tm.remote = _Remote(existing)
    tm.store = _Store(list(hosts))
    tm.session = _Sess()
    tm.validate_and_filter_flags = lambda c, t: c
    tm._help_brief_cache = {}
    tm._valid_flags_cache = {}
    return tm


def _tm_local(hosts=("api.novalink.lk",)):
    """A ToolManager with NO remote executor — the native-Linux-VPS case where
    tools run locally. This is the config that silently skipped ALL command repair
    (the {WORDLIST}/missing-path bugs found on the live VM)."""
    tm = ToolManager.__new__(ToolManager)
    tm.remote = None
    tm.store = _Store(list(hosts))
    tm.session = _Sess()
    tm.validate_and_filter_flags = lambda c, t: c
    tm._help_brief_cache = {}
    tm._valid_flags_cache = {}
    return tm


class TestLocalModeRepair:
    def test_wordlist_placeholder_substituted_locally(self):
        # The literal {WORDLIST} must be resolved to a REAL local file even with
        # no remote executor (was skipped → gobuster ran with literal {WORDLIST}).
        import os
        tm = _tm_local()
        wl = tm._canonical_wordlist()
        assert wl and os.path.exists(wl) and os.path.getsize(wl) > 0
        out = tm._validate_and_fix_command(
            "gobuster dir -u http://novalink.lk -w {WORDLIST}", "gobuster")
        assert "{WORDLIST}" not in out
        # Substituted with a real resolved wordlist. Assert the basename (the full
        # path is backslash-mangled by shlex only on Windows; on the Linux VPS the
        # forward-slash path survives intact).
        assert os.path.basename(wl) in out

    def test_missing_wordlist_path_fixed_locally(self):
        tm = _tm_local()
        out = tm._validate_and_fix_command(
            "ffuf -u http://t/FUZZ -w /usr/share/wordlists/dirb/common.txt", "ffuf")
        # The nonexistent dirb path is redirected to a real local wordlist.
        assert "/usr/share/wordlists/dirb/common.txt" not in out

    def test_canonical_wordlist_returns_real_local_file(self):
        tm = _tm_local()
        wl = tm._canonical_wordlist()
        import os
        assert wl and os.path.exists(wl)

    def test_exec_on_host_delegates_to_remote_when_present(self):
        # The generic host-exec seam uses the remote executor when wired...
        tm = _tm(existing=[])
        tm.remote = _Remote([])
        ec, out, err = tm._exec_on_host("echo $HOME")
        assert ec == 0 and out == "/home/en"

    def test_exec_on_host_runs_locally_without_remote(self):
        # ...and falls back to a LOCAL subprocess (no remote) — returning a 3-tuple,
        # never raising. This is what lets grounding fetch `--help` for ANY tool on
        # a native VPS (generic, not per-tool).
        tm = _tm_local()
        res = tm._exec_on_host("echo hello_local")
        assert isinstance(res, tuple) and len(res) == 3

    def test_repair_loop_no_crash_when_remote_is_none(self):
        # REGRESSION (found by the live heavy-tool harness): the path-detection
        # loop in _validate_and_fix_command called self.remote.execute directly
        # (echo $HOME / test -e / find) — AttributeError('NoneType' has no
        # 'execute') on a native-local host. It must now route through
        # _exec_on_host / _path_exists and never raise. Stub the host-exec seam
        # so the find-fallback returns instantly (no real 30s filesystem scan)
        # and to PROVE the loop uses the seam, not raw self.remote.
        tm = _tm_local()
        seen = []
        tm._exec_on_host = lambda c, timeout=15: (seen.append(c) or (1, "", ""))
        out = tm._validate_and_fix_command(
            "httpx -l /home/x/live_subdomains.txt -silent", "httpx")
        assert isinstance(out, str) and "httpx" in out   # did not raise

    def test_ensure_output_dirs_mkdirs_parent(self):
        # REGRESSION (live novalink.lk run): tools that WRITE results (gau --o,
        # nmap -oN, ffuf -o) abort when the output DIRECTORY is absent on a
        # native-local host. _ensure_output_dirs mkdir -p's it, tool-agnostically.
        tm = _tm_local()
        seen = []
        tm._exec_on_host = lambda c, timeout=15: (seen.append(c) or (0, "", ""))
        for cmd in (
            "gau novalink.lk --o /home/x/ws/eng1/results/urls.txt",
            "nmap -sV -oN /home/x/ws/eng1/results/scan.txt t",
            "ffuf -u http://t/FUZZ -w /tmp/w.txt -o /home/x/ws/eng1/out/ffuf.json",
        ):
            tm._ensure_output_dirs(cmd)
        mk = " ".join(c for c in seen if c.startswith("mkdir -p"))
        assert "/home/x/ws/eng1/results" in mk
        assert "/home/x/ws/eng1/out" in mk

    def test_output_dir_created_via_validate_for_nmap(self):
        # -oN is recognised by the repair loop (path left intact); the final
        # command's output dir must then be created before the tool runs.
        tm = _tm_local()
        seen = []
        tm._exec_on_host = lambda c, timeout=15: (seen.append(c) or (0, "", ""))
        out = tm._validate_and_fix_command(
            "nmap -sV -oN /home/x/ws/eng1/results/scan.txt novalink.lk", "nmap")
        assert "scan.txt" in out
        assert any(c.startswith("mkdir -p") and "/home/x/ws/eng1/results" in c
                   for c in seen)

    def test_leading_tilde_expanded_in_output_path(self):
        # REGRESSION (live novalink.lk run): gau/masscan/whatweb got a quoted
        # '~/redteam-workspace/...' output path and aborted — the tool receives a
        # LITERAL ~ the shell never expanded. _expand_home_tokens must rewrite it
        # to the host's absolute home before the tool runs.
        tm = _tm_local()
        tm._exec_on_host = lambda c, timeout=15: (0, "/home/ubuntu", "")
        out = tm._validate_and_fix_command(
            "gau --subs novalink.lk --o ~/redteam-workspace/eng1/results/u.txt", "gau")
        assert "~/redteam-workspace" not in out
        assert "/home/ubuntu/redteam-workspace/eng1/results/u.txt" in out

    def test_tilde_glued_flag_expanded(self):
        tm = _tm_local()
        tm._exec_on_host = lambda c, timeout=15: (0, "/home/ubuntu", "")
        out = tm._validate_and_fix_command(
            "whatweb -v http://t '--log-verbose=~/redteam-workspace/e1/r/w.txt'", "whatweb")
        assert "~/" not in out
        assert "--log-verbose=/home/ubuntu/redteam-workspace/e1/r/w.txt" in out

    def test_help_brief_grounds_without_remote(self):
        # REGRESSION: get_tool_help_brief early-returned "" when self.remote was
        # None, silently disabling ALL help-grounding on the native-VPS config
        # this engine actually runs in. It must fetch via _exec_on_host instead.
        tm = _tm_local()
        tm._exec_on_host = lambda c, timeout=15: (
            0,
            "Usage: mytool [options]\n  -u, --url string   target URL\n"
            "  -w, --wordlist string  wordlist file\n  -o string  output file\n"
            "  --silent  quiet mode\n  -mc string  match status codes\n",
            "")
        brief = tm.get_tool_help_brief("mytool")
        assert brief and "url" in brief.lower()


class TestCanonicalHostsFile:
    def test_materializes_absolute_path(self):
        tm = _tm()
        hp = tm._canonical_hosts_file()
        assert hp.startswith("/home/en/")
        assert hp.endswith("recon_hosts.txt")
        assert "~" not in hp

    def test_primary_target_always_included(self):
        # Even with no subdomain findings, the primary target is a known host.
        tm = _tm(hosts=[])
        hp = tm._canonical_hosts_file()
        assert hp and hp.endswith("recon_hosts.txt")

    def test_none_when_truly_no_hosts(self):
        tm = _tm(hosts=[])
        tm.session.target = ""  # no primary, no findings → nothing to write
        assert tm._canonical_hosts_file() is None


class TestClassifier:
    def test_host_flags_route_to_hosts(self):
        tm = _tm()
        hp = tm._canonical_hosts_file()
        for flag in ("-iL", "-l", "-list", "--input-file"):
            assert tm._canonical_substitute("whatever.txt", flag) == hp

    def test_wordlist_flag_routes_to_wordlist(self):
        wl = "/usr/share/wordlists/dirb/common.txt"
        tm = _tm(existing=[wl])
        assert tm._canonical_substitute("missing.txt", "-w") == wl

    def test_filename_keyword_classifies(self):
        tm = _tm()
        hp = tm._canonical_hosts_file()
        assert tm._canonical_substitute("live_subdomains.txt", "") == hp


class TestUniversalRepair:
    def test_nmap_iL_space_form(self):
        tm = _tm()
        out = tm._validate_and_fix_command(
            "nmap -iL /home/en/x/results/live_subdomains.txt -sV", "nmap")
        assert "recon_hosts.txt" in out
        assert "live_subdomains.txt" not in out

    def test_whatweb_glued_input_file(self):
        tm = _tm()
        out = tm._validate_and_fix_command(
            "whatweb --input-file=/home/en/results/live_subdomains.txt", "whatweb")
        assert "recon_hosts.txt" in out

    def test_httpx_l_form(self):
        tm = _tm()
        out = tm._validate_and_fix_command("httpx -l subs.txt -silent", "httpx")
        assert "recon_hosts.txt" in out

    def test_existing_wordlist_untouched(self):
        wl = "/usr/share/wordlists/dirb/common.txt"
        tm = _tm(existing=[wl])
        out = tm._validate_and_fix_command(f"gobuster dir -u https://x -w {wl}", "gobuster")
        assert wl in out

    def test_output_file_protected(self):
        tm = _tm()
        out = tm._validate_and_fix_command(
            "nmap -sT -oN /home/en/results/scan_output.txt novalink.lk", "nmap")
        assert "scan_output.txt" in out  # output not clobbered
        assert "recon_hosts.txt" not in out


class TestDeterministicNoRetry:
    """A failure that cannot change on an identical retry must run only once."""

    def _run_tm(self):
        from unittest.mock import MagicMock
        from core.result_contracts import ToolResult, ResultStatus
        tm = ToolManager.__new__(ToolManager)
        tm.remote = None
        tm.session = MagicMock()
        tm.session.results_dir = "/tmp"
        tm.parser = MagicMock()
        tm.parser.parse = lambda *a, **k: {}
        tm.ensure_installed = lambda t: True
        tm._validate_and_fix_command = lambda c, t: c
        tm._log_result = lambda *a, **k: None
        tm._calls = {"n": 0}

        def fake_exec(tool, cmd, timeout, silent=False):
            tm._calls["n"] += 1
            return ToolResult(
                tool=tool, command=cmd, stdout="",
                stderr='Failed to resolve "usageapi.novalink.lk". '
                       "WARNING: No targets were specified",
                exit_code=0, duration_seconds=1.0, status=ResultStatus.NO_FINDINGS)
        tm._execute = fake_exec
        return tm

    def test_dns_failure_runs_once(self):
        from unittest.mock import patch
        tm = self._run_tm()
        with patch("tools.tool_manager.get_config") as gc:
            gc.return_value.vps.use_remote_vps = False
            tm.run("nmap", "nmap -sT usageapi.novalink.lk", "recon",
                   timeout=60, save_raw=False)
        # 3 retries would be wasteful; deterministic DNS failure → exactly 1 run.
        assert tm._calls["n"] == 1
