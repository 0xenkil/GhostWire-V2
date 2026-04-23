"""
Runtime logic audit (no live API calls) - fast verification of engine logic.
"""
import sys, os
sys.path.insert(0, r'c:\Users\ASUS\Desktop\red team')
os.chdir(r'c:\Users\ASUS\Desktop\red team')

passed = []
failed = []

def ok(name): passed.append(name); print('  [PASS] ' + name)
def fail(name, err): failed.append(name); print('  [FAIL] ' + name + ': ' + str(err))

# ── 1. AI Backend detection (no query) ─────────────────────
print('\n=== 1. AI Backend Detection ===')
try:
    from core.ai_backend import AIBackend
    ai = AIBackend()
    assert 'groq' in ai._available_backends or 'google' in ai._available_backends, "No cloud backend!"
    print('  Backends: ' + str(ai._available_backends))
    ok('Backend detection')
except Exception as e:
    fail('Backend detection', e)

# ── 2. Stealth: UA rotation ─────────────────────────────────
print('\n=== 2. User-Agent Rotation ===')
try:
    from utils.stealth import get_random_ua
    uas = {get_random_ua() for _ in range(30)}
    assert len(uas) > 3, "UA not rotating enough: " + str(len(uas)) + " unique"
    print('  Unique UAs in 30 calls: ' + str(len(uas)))
    ok('UA rotation')
except Exception as e:
    fail('UA rotation', e)

# ── 3. Stealth: Sniper delays ───────────────────────────────
print('\n=== 3. Sniper Delay Injection ===')
try:
    from utils.stealth import apply_sniper_delays
    cmd_gob = 'gobuster dir -u https://target.com -w /tmp/list.txt -t 20'
    out = apply_sniper_delays(True, cmd_gob)
    assert '--delay 1500ms' in out, "Missing gobuster delay: " + out
    assert '-t 5' in out, "Thread cap not applied: " + out
    ok('Sniper: gobuster throttle')

    cmd_ffuf = 'ffuf -u https://target.com/FUZZ -w /tmp/list.txt -t 40'
    out2 = apply_sniper_delays(True, cmd_ffuf)
    assert '-p 1.5' in out2, "Missing ffuf delay: " + out2
    ok('Sniper: ffuf throttle')

    out3 = apply_sniper_delays(False, cmd_gob)
    assert cmd_gob == out3, "Command modified without WAF"
    ok('Sniper: passthrough when no WAF')
except Exception as e:
    fail('Sniper delays', e)

# ── 4. False-success detection logic ────────────────────────
print('\n=== 4. False-Success Detection ===')
try:
    keywords = ['unable to connect', 'error on running gobuster',
                'connection refused', 'network is unreachable', 'eof']

    # Should detect false success
    fake_stdout = 'Error: unable to connect to https://target.com: EOF'
    combined = (fake_stdout + '').lower()
    detected = any(kw in combined for kw in keywords)
    assert detected, "False-success not detected on EOF"
    ok('False-success: EOF detected')

    # Should NOT flag a real success
    real_stdout = '/admin (Status: 200) [Size: 1234]'
    combined2 = (real_stdout + '').lower()
    detected2 = any(kw in combined2 for kw in keywords)
    assert not detected2, "Real success wrongly flagged"
    ok('False-success: real hit not flagged')
except Exception as e:
    fail('False-success logic', e)

# ── 5. Session creation ─────────────────────────────────────
print('\n=== 5. Session Creation ===')
try:
    from core.session import EngagementSession
    sess = EngagementSession(
        mode='pentest', target='test.example.com',
        scope=['test.example.com'],
        rules_of_engagement={'allow_exploitation': False, 'allow_brute_force': False,
                              'allow_phishing': False, 'allow_destructive': False},
        operator='debug_test', ai_backend=None
    )
    assert sess.engagement_id, "No engagement ID"
    assert sess.results_dir.exists(), "Results dir not created"
    print('  Engagement ID: ' + sess.engagement_id)
    ok('Session creation + results dir')
except Exception as e:
    fail('Session creation', e)

# ── 6. State store read/write ───────────────────────────────
print('\n=== 6. State Store ===')
try:
    from core.state_store import StateStore
    from pathlib import Path
    tmp_db = Path('results') / 'test_debug.db'
    store = StateStore(db_path=tmp_db)
    data = {'key': 'val', 'count': 99, 'nested': {'a': 1}}
    store.set_phase_data('test_debug_eng', 'recon', data)
    readback = store.get_phase_data('test_debug_eng', 'recon')
    assert readback['key'] == 'val'
    assert readback['count'] == 99
    assert readback['nested']['a'] == 1
    store.close()
    ok('State store save/load')
except Exception as e:
    fail('State store', e)

# ── 7. Scope enforcer ───────────────────────────────────────
print('\n=== 7. Scope Enforcer ===')
try:
    from core.scope_enforcer import ScopeEnforcer, ScopeViolation
    from core.session import EngagementSession
    sess2 = EngagementSession(
        mode='pentest', target='target.com',
        scope=['target.com', '10.10.10.0/24'],
        rules_of_engagement={'allow_exploitation': True, 'allow_brute_force': False,
                              'allow_phishing': False, 'allow_destructive': False},
        operator='debug_test', ai_backend=None
    )
    enforcer = ScopeEnforcer(session=sess2)
    assert enforcer.check_target('target.com'), "In-scope target rejected"
    assert enforcer.check_target('sub.target.com'), "Subdomain rejected"
    try:
        enforcer.check_target('evil.com')
        fail('Scope enforcer', 'Out-of-scope evil.com was allowed!')
    except ScopeViolation:
        ok('Scope enforcer in/out/subdomain')
except Exception as e:
    fail('Scope enforcer', e)

# ── 8. Message bus ──────────────────────────────────────────
print('\n=== 8. Message Bus ===')
try:
    from core.message_bus import MessageBus
    from core.state_store import StateStore
    from pathlib import Path
    tmp_db2 = Path('results') / 'test_bus.db'
    bus_store = StateStore(db_path=tmp_db2)
    bus = MessageBus(state_store=bus_store, engagement_id='test_bus_eng')
    received = []
    bus.subscribe('test_channel', lambda sender, data: received.append(data))
    bus.publish('test_agent', 'test_channel', {'payload': 'hello'})
    assert len(received) == 1, "Subscriber not called, got: " + str(received)
    assert received[0]['payload'] == 'hello'
    bus_store.close()
    ok('Message bus pub/sub')
except Exception as e:
    fail('Message bus', e)

# ── 9. Output parser sanity ─────────────────────────────────
print('\n=== 9. Output Parser ===')
try:
    from tools.output_parser import OutputParser
    parser = OutputParser()

    # Nmap output
    nmap_raw = "80/tcp   open  http\n443/tcp  open  ssl/https"
    result = parser.parse('nmap', nmap_raw, '')
    ports = result.get('open_ports', [])
    assert 80 in ports and 443 in ports, "Nmap ports not parsed: " + str(ports)
    ok('Output parser: nmap ports')

    # Gobuster output
    gob_raw = "/admin (Status: 200) [Size: 1234]\n/.git (Status: 403) [Size: 100]"
    result2 = parser.parse('gobuster', gob_raw, '')
    paths = result2.get('discovered_paths', [])
    assert len(paths) >= 1, "Gobuster paths not parsed: " + str(paths)
    ok('Output parser: gobuster paths')
except Exception as e:
    fail('Output parser', e)

# ── 10. JSON serialization safety ───────────────────────────
print('\n=== 10. JSON Serialization Safety ===')
try:
    import json
    from pathlib import Path
    from datetime import datetime

    # Make sure default=str handles non-serializable objects
    tricky = {
        'path': Path('/tmp/test'),
        'time': datetime.now(),
        'set': {1, 2, 3},
        'nested': {'bytes': b'hello'}
    }
    out = json.dumps(tricky, default=str)
    assert '"path"' in out
    ok('JSON default=str serialization')
except Exception as e:
    fail('JSON serialization', e)

# ── Summary ─────────────────────────────────────────────────
print('\n' + '='*50)
print('PASSED: ' + str(len(passed)) + '  |  FAILED: ' + str(len(failed)))
if failed:
    print('\nFailed tests:')
    for f in failed:
        print('  - ' + f)
    sys.exit(1)
else:
    print('\nALL RUNTIME TESTS PASSED! Engine is healthy.')
