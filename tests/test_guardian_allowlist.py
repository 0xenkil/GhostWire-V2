"""Guard: guardian allowlist is case-insensitive and a superset of the registry (2026-06-21).

Drift bug: the guardian tool allowlist was case-SENSITIVE and held "theHarvester",
but the tool registry advertises it lowercased ("theharvester") — so the lowercase
form the AI generates was BLOCKED ("not allowlisted"). Also `curl-impersonate` (the
TLS/JA3 evasion binary the WAF-evasion tier rewrites curl onto) was advertised but
missing from the allowlist, so the bypass got blocked at the guardian gate. Fix:
compare on .lower() (kills casing drift universally) and add the missing real
binaries. Unknown tools must still be blocked.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.guardian import _ALLOWED_RECON_TOOLS_LOWER as L  # noqa: E402


def test_theharvester_any_casing_allowed():
    for t in ("theharvester", "theHarvester", "THEHARVESTER"):
        assert t.lower() in L, t


def test_evasion_and_internal_binaries_allowed():
    for t in ("curl-impersonate", "playwright", "tor"):
        assert t in L, t


def test_unknown_tool_still_blocked():
    assert "definitely_not_a_real_tool" not in L
    assert "rm" not in L  # destructive shells are not silently allowlisted here
