#!/usr/bin/env python3
"""
Audit all .py files for hardcoded values that should come from config/YAML.
Categories: timeouts, paths, model names, URLs, ports, thresholds, magic numbers.
"""
from collections import defaultdict
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
SKIP_DIRS = {
    '.git',
    '.venv',
    'venv',
    '__pycache__',
    'scratch',
    'tests',
    '.cursor',
    '.vscode',
    'results',
    'node_modules'}
SKIP_FILES = {'audit_hardcoded.py', 'config.py', 'config_backends.py',
              'config_thresholds.py', 'config_paths.py', 'integration_test.py',
              'repro.py', 'debug_snapshot.py', 'health_check.py'}

# Patterns: (label, regex, exclude_if_line_contains)
PATTERNS = [
    ("TIMEOUT_LITERAL",
     r'\btimeout\s*=\s*(\d{2,})\b',
     ['config', 'yaml', 'get(', 'cfg[', 'thresholds', 'infra', '.get(', 'test']),

    ("SLEEP_LITERAL",
     r'\btime\.sleep\s*\(\s*(\d+\.?\d*)\s*\)',
     ['config', 'yaml', 'get(', 'cfg[']),

    ("HARDCODED_PATH_TMP",
     r'["\']\/tmp\/[^"\']+["\']',
     ['paths.yaml', 'config', 'get_config', '# fallback', '# default', 'f"', "f'"]),

    ("HARDCODED_PATH_USR",
     r'["\']\/usr\/share\/[^"\']+["\']',
     ['paths.yaml', 'config', 'yaml', '# fallback']),

    ("HARDCODED_PATH_OPT",
     r'["\']\/opt\/[^"\']+["\']',
     ['paths.yaml', 'config', 'yaml']),

    ("HARDCODED_MODEL_NAME",
     r'["\'](?:llama|gemma|gemini|gpt|mistral|phi|claude|deepseek|qwen)[^"\']*["\']',
     ['config', 'yaml', 'get(', 'cfg[', '.env', 'comment', '#', 'log', 'test']),

    ("HARDCODED_PORT",
     r'\b(?:port|PORT)\s*=\s*(\d{2,5})\b',
     ['config', 'yaml', 'get(', 'cfg[', 'self\\.port', 'args\\.']),

    ("HARDCODED_RATE_LIMIT",
     r'rate.limit\s*=\s*(\d+)\b',
     ['config', 'yaml', 'get(', 'cfg[']),

    ("HARDCODED_CONCURRENCY",
     r'concurren\w+\s*=\s*(\d+)\b',
     ['config', 'yaml', 'get(', 'cfg[']),

    ("HARDCODED_RETRY_COUNT",
     r'\bmax_retries?\s*=\s*(\d+)\b',
     ['config', 'yaml', 'get(', 'cfg[', 'requests', 'urllib']),

    ("MAGIC_URL",
     r'["\']https?://(?!openrouter|generativelanguage|localhost)[a-z0-9.-]+\.[a-z]{2,}[^"\']*["\']',
     ['config', 'yaml', 'get(', 'cfg[', '#', 'log', 'test', 'comment',
      'openrouter.ai', 'generativelanguage', 'api.groq', 'openai', '.env']),

    ("OLLAMA_URL_LITERAL",
     r'["\']http://localhost:11434["\']',
     ['config', 'yaml', 'get(', 'cfg[', 'OLLAMA_BASE_URL', '_base_url']),

    ("HARDCODED_COLLABORATOR",
     r'collaborator\.[a-z]+',
     ['config', 'yaml', 'get(', 'cfg[']),

    ("HARDCODED_TEMP_DIR",
     r'["\']\/tmp\/antigravity["\']',
     ['config', 'yaml', 'get(', 'cfg[', 'paths', 'TEMP_DIR']),

    ("HARDCODED_RESULTS_DIR",
     r'["\']\/root\/results["\']',
     ['config', 'yaml', 'get(', 'cfg[', 'paths', 'RESULTS_DIR']),

    ("HARDCODED_VPS_USER",
     r'["\']root["\']',
     ['config', 'yaml', 'get(', 'cfg[', '#', 'su -', 'chown', 'chmod', 'user.*root', 'root.*user',
      'VPS_USER', 'username', 'shadow', '/root/', 'uid=0']),

    ("HARDCODED_DNS_RESOLVER",
     r'["\']1\.1\.1\.1["\']|["\']8\.8\.8\.8["\']',
     ['config', 'yaml', 'get(', 'cfg[', 'infra', 'infrastructure', 'dns_resolver']),
]

findings = []

for py_file in ROOT.rglob('*.py'):
    # Skip dirs
    if any(skip in py_file.parts for skip in SKIP_DIRS):
        continue
    if py_file.name in SKIP_FILES:
        continue

    try:
        lines = py_file.read_text(
            encoding='utf-8',
            errors='replace').splitlines()
    except Exception:
        continue

    rel = str(py_file.relative_to(ROOT))
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue

        for label, pattern, exclusions in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # Check if any exclusion phrase appears in the line
                if any(excl in line for excl in exclusions):
                    continue
                findings.append((label, rel, lineno, line.strip()))

# Print results grouped by category
by_cat = defaultdict(list)
for label, path, lineno, line in findings:
    by_cat[label].append((path, lineno, line))

total = 0
for cat in sorted(by_cat):
    items = by_cat[cat]
    print(f"\n{'=' * 70}")
    print(f"  {cat}  ({len(items)} occurrences)")
    print(f"{'=' * 70}")
    for path, lineno, line in items:
        print(f"  {path}:{lineno}")
        print(f"    {line[:120]}")
    total += len(items)

print(f"\n\nTOTAL HARDCODED FINDINGS: {total}")
