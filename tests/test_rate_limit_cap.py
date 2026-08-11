"""_wait_rate_limit must never sleep longer than RATE_LIMIT_MAX_BACKOFF.

A live full-deployment run spent its tail blocked in _wait_rate_limit: the
server/WAF-supplied `Retry-After` was slept RAW (`wait = int(retry)`), so a
`retry-after: 3600` would freeze the whole engagement for an hour. Only the
exponential-backoff arm was capped. Both arms must respect the cap — the same
bounded-sleep discipline P4-1 applied to the AI-backend recovery.
"""
import logging
from unittest.mock import patch

import pytest

from agents.exploitation_agent import ExploitationAgent
from agents.base_agent import RATE_LIMIT_MAX_BACKOFF
from core.result_contracts import ToolResult, ResultStatus


def _agent():
    a = ExploitationAgent.__new__(ExploitationAgent)
    a.log = logging.getLogger("test")
    a._host_rate_limits = {}
    return a


def _res(stderr):
    return ToolResult(tool="x", command="x", stdout="", stderr=stderr,
                      exit_code=0, duration_seconds=0.0,
                      status=ResultStatus.NO_FINDINGS)


def test_retry_after_is_capped():
    a = _agent()
    slept = []
    with patch("agents.base_agent._time_module.sleep", slept.append):
        a._wait_rate_limit(_res("HTTP/1.1 429 Too Many Requests\nRetry-After: 3600"),
                           "t.example")
    assert slept == [RATE_LIMIT_MAX_BACKOFF]        # 3600 -> 120, NOT an hour


def test_small_retry_after_unchanged():
    a = _agent()
    slept = []
    with patch("agents.base_agent._time_module.sleep", slept.append):
        a._wait_rate_limit(_res("retry-after: 5"), "t.example")
    assert slept == [5]                             # under the cap → honoured as-is


def test_backoff_arm_stays_capped():
    a = _agent()
    slept = []
    with patch("agents.base_agent._time_module.sleep", slept.append):
        for _ in range(12):                         # exponential growth, no Retry-After
            a._wait_rate_limit(_res("429 too many requests"), "t.example")
    assert slept and all(w <= RATE_LIMIT_MAX_BACKOFF for w in slept)
