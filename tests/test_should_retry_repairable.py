"""Guard: should_retry must NOT abandon AI-repairable failures (2026-06-21).

Purpose-vs-reality + design bug: `should_retry` is a coarse pre-filter, but it
had exit code 2 ("invalid arguments") in its no-retry set — and exit 2 is exactly
what argparse-based tools (sqlmap, theHarvester, wafw00f, ...) return for a bad
flag, i.e. THE case the repair loop + --help grounding exist to fix. The AI triage
(`_interpret_outcome`) already runs first and is the decision authority; a
hardcoded exit-code list must not override it and abandon a repairable command.
Fix: only structurally un-repairable failures (DNS/refused/permission/not-found/
signals) short-circuit; argument/URL/protocol/transient errors reach the bounded
repair loop.
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.safe_executor import should_retry, classify_unrepairable  # noqa: E402


def _r(code):
    return types.SimpleNamespace(exit_code=code)


def test_argument_errors_are_repairable():
    # exit 2 = argparse usage error — the core repair case — must be retryable
    assert should_retry(_r(2)) is True
    assert should_retry({"exit_code": 2}) is True
    # malformed URL / TLS / transient — repairable too
    for code in (3, 28, 35, 52, 56):
        assert should_retry(_r(code)) is True, code


def test_structurally_unrepairable_short_circuit():
    # DNS, refused, permission, not-found, signals — a rewrite can't help
    for code in (6, 7, 126, 127, 137, 143, -1):
        assert should_retry(_r(code)) is False, code


def test_success_and_generic_failure_retry():
    assert should_retry(_r(0)) is True       # success-ish exit retryable (not blocked)
    assert should_retry(_r(1)) is True       # generic tool error -> let repair try
    assert should_retry(None) is False       # nothing to act on


# ── classify_unrepairable: deterministic pre-triage guard (2026-07-29) ───────
# Missing/un-executable binaries (126/127) must route to NOT_INSTALLED — never
# into the AI triage or repair loop, where the operator would guess flags at a
# binary that isn't there. Other structural failures abandon; repairable exits
# return None so the bounded repair loop still runs. Kept in lockstep with
# should_retry so the two exit-code sets can never drift apart.
def test_classify_missing_binary_is_not_installed():
    for code in (126, 127):
        assert classify_unrepairable(_r(code)) == "not_installed", code
        assert classify_unrepairable({"exit_code": code}) == "not_installed", code


def test_classify_structural_failure_abandons():
    for code in (-1, 6, 7, 137, 143):
        assert classify_unrepairable(_r(code)) == "abandon", code


def test_classify_repairable_returns_none():
    # These reach the bounded repair loop — must NOT be pre-classified.
    for code in (0, 1, 2, 3, 28, 35, 52, 56):
        assert classify_unrepairable(_r(code)) is None, code
    assert classify_unrepairable(None) is None


def test_classify_and_should_retry_never_drift():
    # Every exit code classify_unrepairable flags MUST also be a no-retry exit,
    # and vice-versa — the two share a single source of truth.
    for code in range(-5, 260):
        flagged = classify_unrepairable(_r(code)) is not None
        assert flagged == (should_retry(_r(code)) is False), code
