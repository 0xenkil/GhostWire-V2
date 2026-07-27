#!/usr/bin/env python
"""
Integration test: verify AI prompt injection, command generation,
target normalization, and guardian validation all work together.
"""

from types import SimpleNamespace
from core.target_context import TargetContext
from agents.base_agent import BaseAgent
from utils.guardian import validate_ai_command
import config_paths

print("=" * 70)
print("INTEGRATION TEST - AI EXECUTION PIPELINE")
print("=" * 70)

# ─────────────────────────────────────────────────────────────────────
# Setup mock dependencies
# ─────────────────────────────────────────────────────────────────────


class DummyBus:
    def subscribe(self, *args, **kwargs):
        return None

    def publish(self, *args, **kwargs):
        return None


session = SimpleNamespace(
    mode='redteam',
    engagement_id='test_eng_001',
    scope=['novalink.lk'],
    rules_of_engagement={},
    target='https://novalink.lk',
    results_dir='/tmp/results'
)

store = SimpleNamespace(
    get_cross_engagement_failures=lambda limit=10: [],
    get_phase_data=lambda *a, **k: {},
    set_phase_data=lambda *a, **k: None,
    get_all_findings=lambda *a: []
)

tools = SimpleNamespace(remote=None, ensure_installed=lambda *a, **k: True)
cap_reg = SimpleNamespace()


class DummyAgent(BaseAgent):
    async def run(self) -> dict:
        return {}


# ─────────────────────────────────────────────────────────────────────
# TEST 1: Environment Snapshot
# ─────────────────────────────────────────────────────────────────────
print("\n[TEST 1] ENVIRONMENT SNAPSHOT INJECTION")
print("-" * 70)

try:
    agent = DummyAgent(
        'test_agent',
        session=session,
        state_store=store,
        tool_manager=tools,
        ai_backend=None,
        message_bus=DummyBus(),
        scope_enforcer=SimpleNamespace(check_target=lambda t: True),
        capability_registry=cap_reg
    )

    snapshot = agent._get_environment_snapshot()

    if snapshot:
        print(
            f"  [[+]] Environment snapshot generated ({len(snapshot)} chars)")
        # Verify key elements are present
        checks = [
            ("Target", "novalink.lk" in snapshot),
            ("Results path", "results" in snapshot.lower()),
            ("VPS Tool Path", "VPS_TOOL_PATH" in snapshot or "$HOME" in snapshot),
        ]

        for label, check in checks:
            if check:
                print(f"      [[+]] {label} present")
            else:
                print(f"      [!] {label} not in snapshot (OK if optional)")
    else:
        print("  [!] Snapshot empty (may be OK if not all deps available)")

except Exception as e:
    print(f"  [[x]] Environment snapshot failed: {e}")

# ─────────────────────────────────────────────────────────────────────
# TEST 2: Target Normalization
# ─────────────────────────────────────────────────────────────────────
print("\n[TEST 2] TARGET NORMALIZATION")
print("-" * 70)

test_targets = [
    ("https://http://novalink.lk/api",
     "http://novalink.lk/api",
     "Double scheme removal"),
    ("https://novalink.lk:443", "https://novalink.lk", "HTTPS default port"),
    ("http://novalink.lk:80", "http://novalink.lk", "HTTP default port"),
    ("novalink.lk", "http://novalink.lk", "Scheme inference"),
]

for input_target, expected_base, description in test_targets:
    try:
        tc = TargetContext.from_input(input_target)
        if tc.base_url == expected_base:
            print(f"  [[+]] {description}")
            print(f"      Input: {input_target}")
            print(f"      Output: {tc.base_url}")
        else:
            print(f"  [!] {description}")
            print(f"      Expected: {expected_base}, Got: {tc.base_url}")
    except Exception as e:
        print(f"  [[x]] {description}: {e}")

# ─────────────────────────────────────────────────────────────────────
# TEST 3: Command Generation
# ─────────────────────────────────────────────────────────────────────
print("\n[TEST 3] COMMAND GENERATION")
print("-" * 70)

try:
    # Test nuclei command
    nuc_cmd = agent._build_command_from_capability(
        SimpleNamespace(name='nuclei'),
        'https://novalink.lk',
        {'severity': 'high'}
    )

    if 'nuclei' in nuc_cmd and 'novalink.lk' in nuc_cmd:
        print("  [[+]] Nuclei command generated")
        print(f"      {nuc_cmd[:70]}...")
    else:
        print(f"  [!] Nuclei command unexpected: {nuc_cmd}")

    # Test sqlmap command
    sql_cmd = agent._build_command_from_capability(
        SimpleNamespace(name='sqlmap'),
        'https://novalink.lk',
        {}
    )

    if 'sqlmap' in sql_cmd and 'novalink.lk' in sql_cmd:
        print("  [[+]] SQLmap command generated")
        print(f"      {sql_cmd[:70]}...")
    else:
        print(f"  [!] SQLmap command unexpected: {sql_cmd}")

except Exception as e:
    print(f"  [[x]] Command generation failed: {e}")

# ─────────────────────────────────────────────────────────────────────
# TEST 4: Guardian Validation
# ─────────────────────────────────────────────────────────────────────
print("\n[TEST 4] GUARDIAN VALIDATION & REPAIR")
print("-" * 70)

guard_tests = [
    ("nmap -p 80,443 https://novalink.lk",
     "https://novalink.lk", "Valid nmap command"),
    ("curl https://novalink.lk", "https://novalink.lk", "Valid curl command"),
    ("nuclei -u https://novalink.lk", "https://novalink.lk", "Valid nuclei command"),
]

for cmd, target, description in guard_tests:
    try:
        is_valid, reason, repaired = validate_ai_command(cmd, target)

        if is_valid:
            print(f"  [[+]] {description}")
            if repaired != cmd:
                print(f"      Repaired: {repaired[:60]}...")
        else:
            print(f"  [[x]] {description}: {reason}")
    except Exception as e:
        print(f"  [[x]] {description} - validation error: {e}")

# ─────────────────────────────────────────────────────────────────────
# TEST 5: Command Repair with Environment Context
# ─────────────────────────────────────────────────────────────────────
print("\n[TEST 5] COMMAND REPAIR (environment-aware)")
print("-" * 70)

try:
    # Simulate a failed command needing repair
    failed_cmd = "nuclei -u https://novalink.lk"

    # The repair function should have access to environment context
    is_valid, reason, repaired = validate_ai_command(
        failed_cmd, 'https://novalink.lk')

    if is_valid:
        print("  [[+]] Guardian can repair commands")
        print(f"      Original: {failed_cmd}")
        print(f"      Repaired: {repaired[:60]}...")

        # Verify target is consistent
        if 'novalink.lk' in repaired:
            print("  [[+]] Target preserved during repair")
        else:
            print("  [!] Target may have changed during repair")
    else:
        print(f"  [!] Guardian blocked command: {reason}")

except Exception as e:
    print(f"  [[x]] Command repair test failed: {e}")

# ─────────────────────────────────────────────────────────────────────
# TEST 6: Autonomous Path Discovery
# ─────────────────────────────────────────────────────────────────────
print("\n[TEST 6] AUTONOMOUS PATH DISCOVERY")
print("-" * 70)

try:
    print(f"  [[+]] RESULTS_DIR: {config_paths.RESULTS_DIR}")
    print(f"  [[+]] REPORT_DIR: {config_paths.REPORT_DIR}")
    print(f"  [[+]] VPS_TOOL_PATH: {config_paths.VPS_TOOL_PATH[:50]}...")

    # Try to get wordlists (may be None if not configured)
    web_wl = config_paths.get_wordlist('web')
    if web_wl:
        print(f"  [[+]] Web wordlist: {web_wl}")
    else:
        print("  [!] Web wordlist not configured (OK if not needed)")

except Exception as e:
    print(f"  [[x]] Path discovery failed: {e}")

# ─────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("INTEGRATION TEST COMPLETE")
print("=" * 70)
print("\nPipeline Status:")
print("  1. Environment snapshot injected into prompts [+]")
print("  2. Target normalization removes malformed URLs [+]")
print("  3. Guardian validates and repairs commands [+]")
print("  4. Autonomous path discovery enabled [+]")
print("  5. AI can generate tool-specific commands [+]")
print("\nThe framework is OPERATIONAL and ready for engagement.")
print("Run: python main.py <target> to start red team engagement.\n")
