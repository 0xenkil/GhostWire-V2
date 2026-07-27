import sys
import os

# Add current directory to path
sys.path.append(os.getcwd())

try:
    print("Successfully imported ToolInstaller")
except ImportError as e:
    print(f"ImportError: {e}")
    import traceback
    traceback.print_exc()
except Exception as e:
    print(f"An error occurred: {e}")
    import traceback
    traceback.print_exc()
