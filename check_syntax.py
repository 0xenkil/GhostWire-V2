#!/usr/bin/env python3
"""Check all Python files for syntax errors and common issues"""

import py_compile
import sys
from pathlib import Path

issues = []

for py_file in Path("agents").glob("*.py"):
    try:
        py_compile.compile(str(py_file), doraise=True)
        print(f"[OK] {py_file.name}: Syntax OK")
    except py_compile.PyCompileError as e:
        print(f"[FAIL] {py_file.name}: {e}")
        issues.append((py_file.name, str(e)))

# Also check core files
for py_file in Path("core").glob("*.py"):
    try:
        py_compile.compile(str(py_file), doraise=True)
    except py_compile.PyCompileError as e:
        print(f"[FAIL] {py_file.name}: {e}")
        issues.append((py_file.name, str(e)))

if issues:
    print(f"\n{len(issues)} files have syntax errors")
    sys.exit(1)
else:
    print("\nAll Python files compile successfully")
    sys.exit(0)
