import ast
import os
import json
import sys


def get_py_files(root):
    py_files = []
    for dirpath, _, filenames in os.walk(root):
        for f in filenames:
            if f.endswith('.py'):
                py_files.append(os.path.join(dirpath, f))
    return py_files


def parse_defs(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        source = f.read()
    tree = ast.parse(source, filename=file_path)
    defs = []
    for node in ast.walk(tree):
        if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defs.append((node.name, file_path, node.lineno))
    return defs


def main(root):
    py_files = get_py_files(root)
    all_defs = []
    for f in py_files:
        all_defs.extend(parse_defs(f))
    # map name to definition locations
    name_to_defs = {}
    for name, file, line in all_defs:
        name_to_defs.setdefault(name, []).append((file, line))
    unused = []
    for name, locations in name_to_defs.items():
        # ignore dunder names
        if name.startswith('__'):
            continue
        used = False
        for py in py_files:
            with open(py, 'r', encoding='utf-8') as f:
                content = f.read()
            for def_file, def_line in locations:
                # remove the definition line from content when checking same
                # file
                if py == def_file:
                    lines = content.splitlines()
                    if 1 <= def_line <= len(lines):
                        lines[def_line - 1] = ''
                    content_to_check = '\n'.join(lines)
                else:
                    content_to_check = content
                if name in content_to_check:
                    used = True
                    break
            if used:
                break
        if not used:
            for file, line in locations:
                unused.append({"name": name, "file": file, "line": line})
    print(json.dumps(unused, indent=2))


if __name__ == '__main__':
    root_dir = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    main(root_dir)
