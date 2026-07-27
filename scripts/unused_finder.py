import ast
import os
import json
import sys


def get_py_files(root):
    py_files = []
    for dirpath, _, filenames in os.walk(root):
        for f in filenames:
            if f.endswith('.py') and not f.startswith('.'):
                py_files.append(os.path.join(dirpath, f))
    return py_files


def collect_definitions(py_files):
    defs = {}
    for path in py_files:
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                source = fh.read()
            tree = ast.parse(source, filename=path)
        except Exception as e:
            import logging as __logging_tmp
            __logging_tmp.getLogger(__name__).error(
                f"Unhandled exception: {e}", exc_info=True)
            # Skip files that cannot be parsed (e.g., generated code blocks)
            continue
        for node in ast.walk(tree):
            if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = node.name
                full = f"{path}:{name}"
                defs[full] = {
                    'path': path,
                    'name': name,
                    'type': type(node).__name__}
    return defs


def collect_usages(py_files):
    usage = set()
    for path in py_files:
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                source = fh.read()
            tree = ast.parse(source, filename=path)
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in unused_finder.py: {_e}')
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                usage.add(node.id)
            elif isinstance(node, ast.Attribute):
                # Capture attribute name for possible class usage
                usage.add(node.attr)
    return usage


def main(root_dir):
    py_files = get_py_files(root_dir)
    defs = collect_definitions(py_files)
    usage = collect_usages(py_files)
    unused = []
    for full, info in defs.items():
        if info['name'] not in usage:
            unused.append(info)
    report = {
        'total_files': len(py_files),
        'total_defs': len(defs),
        'unused_count': len(unused),
        'unused': unused,
    }
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    main(root)
