from core.ai_backend import AIBackend
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


if __name__ == '__main__':
    backend = AIBackend()
    report = backend.check_all_backends()
    print(json.dumps(report, indent=2))
