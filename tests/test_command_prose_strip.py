"""Guard: prose/filler prefixes are stripped from commands (2026-06-20).

Real runs showed the COMMAND GUARDIAN blocking 'Run'/'use'/'rerun'/'Try'/'run'
because the AI (and the hypothesis-engine refinement field) prepended prose to a
command — "rerun ffuf ...", "Use gobuster ...", "Try sqlmap ..." — and the first
word was parsed as the tool name. _strip_command_prose drops those leading words
(none are real tools) so the real tool is found and the command runs.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_strip_leading_prose():
    from agents.base_agent import BaseAgent as B
    cases = {
        "rerun ffuf -u http://x": "ffuf -u http://x",
        "Use gobuster dir -u x": "gobuster dir -u x",
        "Try sqlmap -u x --batch": "sqlmap -u x --batch",
        "Run nikto -h x": "nikto -h x",
        "rerun the ffuf command": "ffuf command",
        # real commands are untouched
        "nmap -sT x": "nmap -sT x",
        "ffuf -u x": "ffuf -u x",
    }
    for inp, exp in cases.items():
        assert B._strip_command_prose(inp) == exp, inp


def test_extract_primary_tool_skips_prose():
    import types
    from agents.base_agent import BaseAgent as B
    f = types.SimpleNamespace()
    f._strip_command_prose = B._strip_command_prose
    cases = {
        "rerun ffuf -u http://x": "ffuf",
        "Use gobuster dir": "gobuster",
        "Try sqlmap -u x": "sqlmap",
        "Run nikto -h x": "nikto",
        "nikto -h x": "nikto",
        "proxychains4 -q ffuf -u x": "ffuf",
    }
    for inp, exp in cases.items():
        assert B._extract_primary_tool(f, inp) == exp, inp
