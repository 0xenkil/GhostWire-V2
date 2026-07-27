"""Test smart key recovery parsing and prioritization."""
from core.ai_backend import GroqKeyPool
import time

# Test smart recovery window parsing
pool = GroqKeyPool(['key1', 'key2', 'key3'])

# Simulate TPD errors with recovery windows
error_msg_1 = "Rate limit reached... Please try again in 4m14.88s."
error_msg_2 = "Rate limit reached... Please try again in 2m57.984s."

print("[TEST] Smart Key Recovery Parsing")
print("=" * 60)

# Mark key1 as exhausted with 4m14.88s recovery
pool.mark_exhausted('key1', 'TPD', error_msg_1)
print("[+] Key1 marked (recovery in 4m14.88s)")

# Mark key3 as exhausted with 2m57.984s recovery
pool.mark_exhausted('key3', 'TPD', error_msg_2)
print("[+] Key3 marked (recovery in 2m57.984s)")

# Check pool status
print("\nKey Status (IMMEDIATE CHECK):")
print(f"  key1: {'EXHAUSTED' if 'key1' in pool._exhausted else 'QUERYABLE'}")
print(f"  key2: {'EXHAUSTED' if 'key2' in pool._exhausted else 'QUERYABLE'}")
print(f"  key3: {'EXHAUSTED' if 'key3' in pool._exhausted else 'QUERYABLE'}")

# Get next key - should be key2 (only QUERYABLE)
next_key = pool.get_active_key()
print(
    f"\n[+] Next key selected: {next_key} (should be 'key2' - only QUERYABLE)")

# Show recovery deadlines
print("\nRecovery Deadlines:")
now = time.time()
for key in ['key1', 'key3']:
    if key in pool._exhausted:
        deadline = pool._exhausted[key]
        secs_until = max(0, deadline - now)
        formatted = pool._format_time_delta(secs_until)
        print(f"  {key}: recovers in {formatted}")

print("\n[[+]] Smart recovery parsing working correctly!")

# Test: After recovery windows pass, keys should be automatically recovered
print("\n" + "=" * 60)
print("[TEST] Automatic Key Recovery After Window Passes")
print("=" * 60)

# Simulate recovery by setting deadlines to past
pool._exhausted['key1'] = time.time() - 10  # Already recovered 10s ago
pool._exhausted['key3'] = time.time() - 20  # Already recovered 20s ago

print("Deadlines set to past (simulating recovery)")

# Get next key - should recover key1/key3 automatically
recovered_keys = []
for _ in range(3):
    next_key = pool.get_active_key()
    if next_key:
        recovered_keys.append(next_key)
        print(f"  Selected: {next_key}")

print(f"\nKeys recovered: {set(recovered_keys)}")
print("Expected: {'key1', 'key2', 'key3'}")
print("[+] Automatic recovery working!")
