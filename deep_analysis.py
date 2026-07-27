#!/usr/bin/env python3
"""
Deep codebase analysis for GHOSTWIRE V6
"""
import os
import re
from collections import defaultdict

issues = {
    'bare_except': [],
    'none_checks': [],
    'hardcoded_paths': [],
    'thread_unsafe': [],
    'unhandled_errors': [],
    'type_issues': [],
    'resource_leaks': [],
    'circular_deps': [],
}

stats = {
    'total_files': 0,
    'total_lines': 0,
}

patterns = {
    'bare_except': r'except\s*:\s*(?:#.*)?$',
    'pass_stmt': r'^\s*pass\s*(?:#.*)?$',
    'hardcoded_path': r'(["\']/(home|tmp|root|usr)/[^"\']*|["\']C:\\\\[^"\']*)',
    'thread_access': r'self\._[a-z_]+\s*=',
    'unhandled_error': r'except\s+\w+\s*:\s*(?:pass|print|continue)',
    'none_issue': r'\.get\([^)]+\)(?:\s*\[|\s*\.)',
}

for root, dirs, files in os.walk('.'):
    dirs[:] = [
        d for d in dirs if d not in [
            '.venv',
            '__pycache__',
            '.git',
            '.vscode',
            '.cursor',
            'scratch',
            'results',
            '.github']]

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
                            issues['bare_except'].append((filepath, i))

                        # Hardcoded paths
                        if re.search(
                                r"(['\"]/(home|tmp|root|usr|var)/|['\"]C:\\\\)", line):
                            issues['hardcoded_paths'].append(
                                (filepath, i, line.strip()[:70]))

                        # Thread access without locks
                        if 'self._' in line and '=' in line and not any(x in content[max(0, content.find(
                                line) - 200):content.find(line) + 100] for x in ['_lock', 'threading.Lock']):
                            pass  # Too noisy

                        # Unhandled errors
                        if re.search(
                                r'except\s+\w+\s*:\s*(?:pass|print\(|continue|logger\.)', line):
                            issues['unhandled_errors'].append((filepath, i))

                        # Type issues
                        if 'or {}' in line or 'or []' in line:
                            if '.get(' in line:
                                issues['type_issues'].append((filepath, i))

                        # Resource leaks (open without with)
                        if 'open(' in line and 'with' not in lines[max(
                                0, i - 3):i]:
                            issues['resource_leaks'].append((filepath, i))
            except Exception as _read_err:
                print(f"  [SKIP] Could not read {filepath}: {_read_err}")

print("\n=== DEEP CODEBASE ANALYSIS ===\n")
print(f"Total Python Files: {stats['total_files']}")
print(f"Total Lines: {stats['total_lines']}")
print("\n=== CRITICAL PATTERNS ===\n")
print(f"Bare except clauses: {len(issues['bare_except'])}")
for filepath, line_no in issues['bare_except'][:10]:
    print(f"  {filepath}:{line_no}")

print(f"\nHardcoded paths/credentials: {len(issues['hardcoded_paths'])}")
for filepath, line_no, text in issues['hardcoded_paths'][:10]:
    print(f"  {filepath}:{line_no}: {text}")

print(f"\nUnhandled error patterns: {len(issues['unhandled_errors'])}")
for filepath, line_no in issues['unhandled_errors'][:10]:
    print(f"  {filepath}:{line_no}")

print(f"\nResource leaks (open without with): {len(issues['resource_leaks'])}")
for filepath, line_no in issues['resource_leaks'][:10]:
    print(f"  {filepath}:{line_no}")

print(f"\nType safety issues: {len(issues['type_issues'])}")
for filepath, line_no in issues['type_issues'][:10]:
    print(f"  {filepath}:{line_no}")

# Check for circular imports and dependencies
print("\n=== DEPENDENCY ANALYSIS ===\n")
imports_map = defaultdict(set)
for root, dirs, files in os.walk('.'):
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
            filepath = os.path.join(root, file).replace('.\\', '')
            module_name = filepath.replace('.py', '').replace('\\', '/')
            try:
                with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    imports = re.findall(
                        r'(?:^from|^import)\s+([a-zA-Z0-9_.]+)', content, re.MULTILINE)
                    for imp in imports:
                        if imp.startswith(
                                ('.', 'core', 'agents', 'tools', 'intelligence', 'utils')):
                            imports_map[module_name].add(imp)
            except Exception as _read_err:
                print(
                    f"  [SKIP] Could not read {
                        os.path.join(
                            root,
                            file)}: {_read_err}")

# Detect cycles


def has_cycle(graph, start, visited, rec_stack, path):
    visited.add(start)
    rec_stack.add(start)
    path.append(start)

    for neighbor in graph.get(start, set()):
        # Normalize the neighbor
        if neighbor in graph:
            neighbor = neighbor
        else:
            continue

        if neighbor not in visited:
            if has_cycle(graph, neighbor, visited, rec_stack, path):
                return True
        elif neighbor in rec_stack:
            print(f"  Potential cycle: {' -> '.join(path)} -> {neighbor}")
            return True

    path.pop()
    rec_stack.remove(start)
    return False


cycles_found = False
visited = set()
for node in imports_map:
    if node not in visited:
        if has_cycle(imports_map, node, visited, set(), []):
            cycles_found = True

if not cycles_found:
    print("No obvious circular import detected.")

print("\n=== ARCHITECTURE ASSESSMENT ===\n")
# Check for architectural antipatterns
antipatterns = {
    'global_state': 0,
    'magic_numbers': 0,
    'god_objects': 0,
    'dead_code': 0,
}

for root, dirs, files in os.walk('.'):
    dirs[:] = [
        d for d in dirs if d not in [
            '.venv',
            '__pycache__',
            '.git',
            '.vscode']]
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    # Count global mutable state
                    for line in lines:
                        if re.match(
                                r'^[A-Z_][A-Z0-9_]*\s*=\s*(\{|\[|[0-9]+)', line):
                            antipatterns['global_state'] += 1
                        if re.search(r'\b(1000|5000|10000|999|666)\b', line):
                            antipatterns['magic_numbers'] += 1
                        if len(lines) > 500:
                            antipatterns['god_objects'] += 1
                        if re.match(r'^\s*#.*TODO|FIXME|XXX|HACK', line):
                            antipatterns['dead_code'] += 1
            except Exception as _read_err:
                print(f"  [SKIP] Could not analyse {filepath}: {_read_err}")

print("Antipattern Count:")
for pattern, count in antipatterns.items():
    print(f"  {pattern}: {count}")
