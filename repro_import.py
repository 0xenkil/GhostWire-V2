
try:
    from core.unified_config_loader import MAX_VPS_LOAD
    print(f"SUCCESS: MAX_VPS_LOAD is {MAX_VPS_LOAD}")
except ImportError as e:
    print(f"FAILED: {e}")

import core.unified_config_loader as config
print(f"config attributes: {dir(config)}")
