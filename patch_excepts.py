import re
import os

FILES = [
    'agents/base_agent.py',
    'core/remote_executor.py',
    'intelligence/waf_fingerprinter.py'
]

PATTERNS = [
    (re.compile(r'(^[ \t]+except.*:\n)(^[ \t]+)pass\n', re.MULTILINE),
     r'\1\2if hasattr(self, "log"):\n\2    self.log.error("Exception caught", exc_info=True)\n\2else:\n\2    import logging\n\2    logging.error("Exception caught", exc_info=True)\n\2raise\n')
]

for file_path in FILES:
    if not os.path.exists(file_path):
        continue
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    orig_content = content
    for pattern, repl in PATTERNS:
        content = pattern.sub(repl, content)

    if content != orig_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Patched {file_path}")
    else:
        print(f"No changes in {file_path}")
