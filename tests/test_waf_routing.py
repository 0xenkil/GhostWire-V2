"""Guard: WAF BLOCKs route to the EVASION path, not the rate-limit backoff (2026-06-21).

Purpose-vs-reality bug: the engine has a whole WAF-evasion subsystem (WafGhost /
WafEvasionEngine / WafBypassOrchestrator) meant to MUTATE a blocked request and
retry to bypass the WAF. But `_should_rate_limit` returned True for BLOCKED, so a
block hit the rate-limit branch (back off / abandon) and the evasion code was
unreachable — the engine never actually evaded a WAF. Fix: rate-limit means
THROUGHPUT (429 / RATE_LIMITED) only; a BLOCK falls through to evasion. A block
that ALSO carries a 429 is still a rate-limit.
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _r(status, out="", err=""):
    return types.SimpleNamespace(status=status, stdout=out, stderr=err)


def test_block_is_not_a_rate_limit():
    from agents.base_agent import BaseAgent
    from core.result_contracts import ResultStatus
    f = types.SimpleNamespace()
    assert BaseAgent._should_rate_limit(f, _r(ResultStatus.BLOCKED), "x.com") is False
    assert BaseAgent._should_rate_limit(f, _r(ResultStatus.WAF_BLOCKED), "x.com") is False


def test_genuine_rate_limit_still_detected():
    from agents.base_agent import BaseAgent
    from core.result_contracts import ResultStatus
    f = types.SimpleNamespace()
    assert BaseAgent._should_rate_limit(f, _r(ResultStatus.RATE_LIMITED), "x.com") is True
    # a 429 in the output is a throughput limit even if status says blocked
    assert BaseAgent._should_rate_limit(
        f, _r(ResultStatus.BLOCKED, err="HTTP 429 Too Many Requests"), "x.com") is True


def test_no_host_is_never_rate_limit():
    from agents.base_agent import BaseAgent
    from core.result_contracts import ResultStatus
    f = types.SimpleNamespace()
    assert BaseAgent._should_rate_limit(f, _r(ResultStatus.RATE_LIMITED), "") is False
