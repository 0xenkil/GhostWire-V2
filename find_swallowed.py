import re
from pathlib import Path

target_dir = Path(r"C:\Users\ASUS\Desktop\red team")

# Looking for `except Exception as e:` or `except:` followed immediately
# by `pass`
pattern = re.compile(r"except.*:[\s\n]*pass")

for py_file in target_dir.rglob("*.py"):
    try:
        content = py_file.read_text(encoding="utf-8")
        matches = pattern.finditer(content)
        for m in matches:
            print(
                f"Swallowed exception in {
                    py_file.name}: {
                    m.group(0).strip()}")
    except Exception as _e:
        import logging
        logging.getLogger(__name__).debug(
            f'Swallowed exception in find_swallowed.py: {_e}')
