#!/usr/bin/env python3
"""
Comprehensive codebase analysis script
"""
import os
import re
from collections import defaultdict

issues = defaultdict(list)
stats = {
    'total_files': 0,
    'total_lines': 0,
    'bare_except': 0,
    'pass_statements': 0,
    'broad_imports': 0,
    'global_mutable': 0,
}

for root, dirs, files in os.walk('.'):
    # Skip venv and cache
    dirs[:] = [
        d for d in dirs if d not in [
            '.venv',
            '__pycache__',
            '.git',
            '.vscode',
            '.cursor',
            'scratch']]
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            stats['total_files'] += 1
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
                    stats['total_lines'] += len(lines)

                    for i, line in enumerate(lines, 1):
                        # Bare except
                        if re.search(r'except\s*:\s*(?:#.*)?$', line):
                            issues['bare_except'].append(
                                (filepath, i, line.strip()[:60]))
                            stats['bare_except'] += 1

                        # Pass statements (likely unimplemented)
                        if re.match(r'^\s*pass\s*(?:#.*)?$', line):
                            issues['pass_statements'].append((filepath, i))
                            stats['pass_statements'] += 1

                        # Broad imports
                        if re.match(r'from\s+\S+\s+import\s+\*', line):
                            issues['broad_imports'].append((filepath, i))
                            stats['broad_imports'] += 1

                        # Global mutable defaults
                        if re.match(
                                r'^[A-Z_][A-Z0-9_]*\s*=\s*(?:\[|\{)', line) and '__init__' not in filepath:
                            issues['global_mutable'].append(
                                (filepath, i, line.strip()[:60]))
                            stats['global_mutable'] += 1
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f'Swallowed exception in analyze_codebase.py: {_e}')

print("\n=== CODEBASE STATISTICS ===")
print(f"Total Python files: {stats['total_files']}")
print(f"Total lines: {stats['total_lines']}")
print("\nCODE QUALITY ISSUES:")
print(f"Bare except clauses: {stats['bare_except']}")
print(f"Pass statements: {stats['pass_statements']}")
print(f"Broad imports (*): {stats['broad_imports']}")
print(f"Global mutable defaults: {stats['global_mutable']}")

print("\n=== BARE EXCEPT STATEMENTS (First 20) ===")
for filepath, line_no, line_text in issues['bare_except'][:20]:
    print(f"  {filepath}:{line_no}")

print("\n=== PASS STATEMENTS (First 20) ===")
for filepath, line_no in issues['pass_statements'][:20]:
    print(f"  {filepath}:{line_no}")

print("\n=== BROAD IMPORTS (First 20) ===")
for filepath, line_no in issues['broad_imports'][:20]:
    print(f"  {filepath}:{line_no}")

print("\n=== GLOBAL MUTABLE (First 20) ===")
for filepath, line_no, text in issues['global_mutable'][:20]:
    print(f"  {filepath}:{line_no}: {text}")
