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
    return tm


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
