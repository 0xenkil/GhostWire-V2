import sys, os
sys.path.insert(0, r'c:\Users\ASUS\Desktop\red team')
os.chdir(r'c:\Users\ASUS\Desktop\red team')

issues = []

# 1. Config imports
print('=== 1. Config ===')
try:
    from config import (AI_BACKEND, GROQ_API_KEY, GROQ_MODEL,
                        GOOGLE_API_KEY, GOOGLE_MODEL, OLLAMA_BASE_URL,
                        OLLAMA_MODEL, USE_REMOTE_VPS, VPS_HOST,
                        CURL_TLS_FLAGS, STEALTH_HEADERS, TOOL_AI_TIMEOUT)
    print('  AI_BACKEND=' + AI_BACKEND)
    print('  GROQ_API_KEY=' + ('SET' if GROQ_API_KEY else 'MISSING'))
    print('  GOOGLE_API_KEY=' + ('SET' if GOOGLE_API_KEY else 'MISSING'))
    print('  USE_REMOTE_VPS=' + str(USE_REMOTE_VPS))
    print('  VPS_HOST=' + (VPS_HOST or 'MISSING'))
    print('  [OK] config.py')
except Exception as e:
    issues.append('config.py: ' + str(e))
    print('  [FAIL] ' + str(e))

# 2. AI Backend
print()
print('=== 2. AI Backend ===')
try:
    from core.ai_backend import AIBackend
    ai = AIBackend()
    print('  Backends: ' + str(ai._available_backends))
    print('  [OK] ai_backend.py')
except Exception as e:
    issues.append('ai_backend: ' + str(e))
    print('  [FAIL] ' + str(e))

# 3. Stealth module
print()
print('=== 3. Stealth module ===')
try:
    from utils.stealth import get_random_ua, get_sniper_headers, apply_sniper_delays
    ua = get_random_ua()
    hdrs = get_sniper_headers(for_curl=True)
    throttled = apply_sniper_delays(True, 'gobuster dir -u http://test.com -w list.txt -t 20')
    print('  UA sample: ' + ua[:60])
    print('  Throttled cmd has delay: ' + str('--delay' in throttled))
    print('  [OK] utils/stealth.py')
except Exception as e:
    issues.append('stealth: ' + str(e))
    print('  [FAIL] ' + str(e))

# 4. Core imports
print()
print('=== 4. Core modules ===')
for mod in ['core.session', 'core.orchestrator', 'core.state_store',
            'core.message_bus', 'core.scope_enforcer', 'core.ssh_executor', 'core.safe_executor']:
    try:
        __import__(mod)
        print('  [OK] ' + mod)
    except Exception as e:
        issues.append(mod + ': ' + str(e))
        print('  [FAIL] ' + mod + ': ' + str(e))

# 5. Agent imports
print()
print('=== 5. Agents ===')
for mod in ['agents.base_agent', 'agents.planning_agent', 'agents.recon_agent',
            'agents.weaponization_agent', 'agents.exploitation_agent',
            'agents.persistence_agent', 'agents.objectives_agent', 'agents.reporting_agent']:
    try:
        __import__(mod)
        print('  [OK] ' + mod)
    except Exception as e:
        issues.append(mod + ': ' + str(e))
        print('  [FAIL] ' + mod + ': ' + str(e))

# 6. Tool modules
print()
print('=== 6. Tools ===')
for mod in ['tools.tool_manager', 'tools.tool_registry', 'tools.output_parser', 'tools.installers']:
    try:
        __import__(mod)
        print('  [OK] ' + mod)
    except Exception as e:
        issues.append(mod + ': ' + str(e))
        print('  [FAIL] ' + mod + ': ' + str(e))

# 7. Utils
print()
print('=== 7. Utils ===')
for mod in ['utils.display', 'utils.logger', 'utils.sanitizer', 'utils.validator', 'utils.stealth']:
    try:
        __import__(mod)
        print('  [OK] ' + mod)
    except Exception as e:
        issues.append(mod + ': ' + str(e))
        print('  [FAIL] ' + mod + ': ' + str(e))

# Summary
print()
print('=== SUMMARY ===')
if issues:
    print('FAILED (' + str(len(issues)) + ' issues):')
    for i in issues:
        print('  - ' + i)
else:
    print('ALL MODULES IMPORT SUCCESSFULLY!')
