import pytest
import time
from unittest.mock import patch, MagicMock

# Create minimal mocks for agents to test just the time logic
class MockAgent:
    def __init__(self):
        self.log = MagicMock()
        self._findings = []
        self._command_history = {}

def test_recon_deadline():
    with open("agents/recon_agent.py", "r", encoding="utf-8") as f:
        code = f.read()
    assert "_time_module.time()" not in code
    assert "_time_module.monotonic(" in code

def test_exploit_deadline():
    with open("agents/exploitation_agent.py", "r", encoding="utf-8") as f:
        code = f.read()
    assert "_time_module.time()" not in code
    assert "_time_module.monotonic(" in code
