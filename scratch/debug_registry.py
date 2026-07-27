from core.capability_registry import ALL_TOOLS
import sys
import os
sys.path.append(os.getcwd())

print(f"ALL_TOOLS count: {len(ALL_TOOLS)}")
for t in ALL_TOOLS:
    print(f" - {t.name} (can_auto_install: {getattr(t, 'can_auto_install', True)})")
