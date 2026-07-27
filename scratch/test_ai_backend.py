import pprint
from core.ai_backend import AIBackend
import os
import sys
from dotenv import load_dotenv

load_dotenv()

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


backend = AIBackend()
print("Available backends:", backend._available_backends)
print("Running check_all_backends()...")
report = backend.check_all_backends()
pprint.pprint(report)
