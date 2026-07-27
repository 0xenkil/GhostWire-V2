import sys
import os
sys.path.insert(0, os.getcwd())
try:
    import core.unified_config_loader as config
    print("Successfully imported config")
    print(f"MAX_VPS_LOAD: {getattr(config, 'MAX_VPS_LOAD', 'NOT FOUND')}")
    print(
        f"TOOL_INSTALL_CHECK_TIMEOUT: {
            getattr(
                config,
                'TOOL_INSTALL_CHECK_TIMEOUT',
                'NOT FOUND')}")
    print(f"config file: {config.__file__}")
except Exception as e:
    print(f"Error importing config: {e}")
    import traceback
    traceback.print_exc()
