import ast


def analyze_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    tree = ast.parse(content)

    print(f"\nAnalyzing {filepath}:")
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            # Check if body only contains pass
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                print(f"Line {node.lineno}: Bare except with 'pass'")
            else:
                # Check if it doesn't contain raise or logging
                has_raise = any(isinstance(n, ast.Raise)
                                for n in ast.walk(node))
                has_log = any(
                    isinstance(
                        n,
                        ast.Call) and isinstance(
                        n.func,
                        ast.Attribute) and n.func.attr in (
                        'error',
                        'exception',
                        'warning') for n in ast.walk(node))
                if not has_raise and not has_log:
                    print(
                        f"Line {
                            node.lineno}: Silent except (no raise, no log)")


for f in ['agents/base_agent.py', 'core/remote_executor.py',
          'intelligence/waf_fingerprinter.py']:
    analyze_file(f)
