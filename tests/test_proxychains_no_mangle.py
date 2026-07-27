"""Guard: proxychains wrapping must not split a LITERAL pipe inside an argument
(2026-06-23). `build_proxychains_cmd` split on every '|', so a git
--pretty=format:"%h | %s" / awk script / regex got `proxychains4 -q` inserted
mid-argument and the command broke (observed: git "unknown option
'pretty=format:%h %ad | proxychains4 -q %s'"). Only a genuine pipeline stage
(starts with a command word) is wrapped; literal pipes are left intact.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ip_rotator import IpRotator  # noqa: E402


def _rot():
    r = IpRotator.__new__(IpRotator)
    r._tor_disabled = False
    return r


def test_literal_pipe_in_arg_not_split():
    r = _rot()
    out = r.build_proxychains_cmd("git log --pretty=format:%h %ad | %s%d [%an]")
    assert "proxychains4 -q %s" not in out      # not inserted mid-format
    assert out.startswith("proxychains4 -q git log")
    assert "| %s%d [%an]" in out                 # literal pipe preserved


def test_genuine_pipeline_wraps_each_stage():
    r = _rot()
    out = r.build_proxychains_cmd("subfinder -d x.com | httpx")
    assert out.count("proxychains4 -q") == 2


def test_plain_command_wrapped_once():
    r = _rot()
    assert r.build_proxychains_cmd("nuclei -u http://x") == "proxychains4 -q nuclei -u http://x"


def test_env_exports_not_wrapped():
    r = _rot()
    out = r.build_proxychains_cmd("export A=b && nuclei -u http://x")
    assert out.startswith("export A=b &&")
    assert "proxychains4 -q nuclei" in out
