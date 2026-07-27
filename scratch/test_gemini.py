import config_backends
from dotenv import load_dotenv
from core.ai_backend import AIBackend
import sys
import os

# Add parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Force load .env to ensure the new values are read
load_dotenv(
    os.path.join(
        os.path.dirname(
            os.path.dirname(
                os.path.abspath(__file__))),
        ".env"),
    override=True)

print("Configured GOOGLE_MODEL:", config_backends.GOOGLE_MODEL)
print("Configured GOOGLE_API_KEY:",
      config_backends.GOOGLE_API_KEY[:10] + "..." if config_backends.GOOGLE_API_KEY else "None")

try:
    backend = AIBackend()
    print("Available Backends:", backend._available_backends)

    # Query Gemini explicitly
    print("Attempting to query Google Gemini...")
    res = backend._query_backend(
        "google",
        "You are a helpful red-team assistant.",
        "State 'Gemini 3.1 Connection Verified' if you can read this.")
    print("\n[SUCCESS] Response from Gemini:")
    print(res)
except Exception:
    print("\n[FAILURE] Failed to query Gemini:")
    import traceback
    traceback.print_exc()
