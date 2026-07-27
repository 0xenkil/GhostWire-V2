from core.scope_enforcer import ScopeEnforcer, ScopeViolation
import sys
from pathlib import Path
# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))


class MockSession:
    def __init__(self, scope):
        self.scope = scope
        self.rules_of_engagement = {"allow_exploitation": True}


def test_scope_enforcer():
    print("Testing ScopeEnforcer...")
    session = MockSession(["example.com", "8.8.8.0/24"])
    enforcer = ScopeEnforcer(session)

    # In scope
    assert enforcer.check_target("example.com")
    assert enforcer.check_target("sub.example.com")
    assert enforcer.check_target("http://example.com/path")
    assert enforcer.check_target("8.8.8.8")

    # Out of scope
    try:
        enforcer.check_target("google.com")
        assert False, "Should have raised ScopeViolation for blocked domain"
    except ScopeViolation:
        pass

    try:
        enforcer.check_target("127.0.0.1")
        assert False, "Should have raised ScopeViolation for blocked IP"
    except ScopeViolation:
        pass

    try:
        enforcer.check_target("other.com")
        assert False, "Should have raised ScopeViolation for out-of-scope domain"
    except ScopeViolation:
        pass

    print("ScopeEnforcer passed!")


if __name__ == "__main__":
    test_scope_enforcer()
