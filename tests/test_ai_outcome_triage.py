"""Guard for the universal AI outcome triage (2026-06-18).

The engine must handle a tool/error/defense it has NEVER seen by REASONING about
it, not by matching hardcoded signature lists. `_interpret_outcome` is that
generic, tool-agnostic triage. These tests pin its contract:
  - it can salvage useful output from any tool (no hardcoded tool whitelist),
  - abandon a non-recoverable failure (no hardcoded deterministic-error list),
  - it is bounded (one AI call per distinct error-signature, then cached),
  - and it fails SAFE (any error → "repair", today's default path).
"""
import json
import logging
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.CRITICAL)


class _AI:
    def __init__(self, action):
        self.action = action
        self.calls = 0

    def query(self, system, prompt, model_id=None):
        self.calls += 1
        return json.dumps({"action": self.action, "reason": "because"})


def _res(stdout="", stderr="", code=2, status="failure"):
    return types.SimpleNamespace(
        stdout=stdout, stderr=stderr, exit_code=code, status=status)


def _fake(ai):
    f = types.SimpleNamespace()
    f.ai = ai
    f.log = logging.getLogger("t")
    return f


def test_accept_salvages_unknown_tool_output():
    from agents.base_agent import BaseAgent
    v = BaseAgent._interpret_outcome(
        _fake(_AI("accept")), "brand_new_scanner",
        "brand_new_scanner --x", _res(stdout="Found 3 open services ..."))
    assert v["action"] == "accept"


def test_abandon_on_nonrecoverable_novel_error():
    from agents.base_agent import BaseAgent
    v = BaseAgent._interpret_outcome(
        _fake(_AI("abandon")), "foo", "foo x",
        _res(stderr="target architecture not supported by foo"))
    assert v["action"] == "abandon"


def test_bounded_one_ai_call_per_signature():
    from agents.base_agent import BaseAgent
    f = _fake(_AI("repair"))
    r = _res(stderr="some identical error text")
    BaseAgent._interpret_outcome(f, "t", "t a", r)
    BaseAgent._interpret_outcome(f, "t", "t a", r)
    assert f.ai.calls == 1  # second call served from cache


def test_fail_safe_defaults_to_repair():
    from agents.base_agent import BaseAgent

    class Boom:
        def query(self, system, prompt, model_id=None):
            raise RuntimeError("backend down")

    v = BaseAgent._interpret_outcome(_fake(Boom()), "t", "t", _res())
    assert v["action"] == "repair"


def test_no_ai_backend_defaults_to_repair():
    from agents.base_agent import BaseAgent
    f = types.SimpleNamespace(ai=None, log=logging.getLogger("t"))
    v = BaseAgent._interpret_outcome(f, "t", "t", _res())
    assert v["action"] == "repair"
