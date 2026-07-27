import sys
import os

# Add current directory to path
sys.path.append(os.getcwd())

try:
    from core.unified_config_loader import MAX_VPS_LOAD
    print(f"Successfully imported MAX_VPS_LOAD: {MAX_VPS_LOAD}")
except ImportError as e:
    print(f"ImportError: {e}")
except Exception as e:
    print(f"An error occurred: {e}")
