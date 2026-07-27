from utils.display import info
from main import pre_flight_checks
import sys
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))


if __name__ == "__main__":
    info("Running verification of pre-flight checks...")
    failed = pre_flight_checks(auto_confirm=True)
    if failed:
        print("\nVerification FAILED.")
        sys.exit(1)
    else:
        print("\nVerification PASSED.")
        sys.exit(0)
