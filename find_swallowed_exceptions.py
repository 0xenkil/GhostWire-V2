import ast
from pathlib import Path


def analyze_file(filepath):
    code = Path(filepath).read_text(encoding='utf-8')
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return

    class ExceptVisitor(ast.NodeVisitor):
        def visit_ExceptHandler(self, node):
            if isinstance(node.type, ast.Name) and node.type.id == 'Exception':
                has_raise = False
                has_error_log = False
                for stmt in node.body:
                    if isinstance(stmt, ast.Raise):
                        has_raise = True
                    if isinstance(stmt, ast.Expr) and isinstance(
                            stmt.value, ast.Call):
                        func = stmt.value.func
                        if isinstance(func, ast.Attribute) and func.attr in (
                                'error', 'warning', 'critical'):
                            has_error_log = True
                if not has_raise and not has_error_log:
                    print(f'{filepath}:{node.lineno} - Swallowed Exception')
            self.generic_visit(node)

    ExceptVisitor().visit(tree)


for p in Path('.').rglob('*.py'):
    if 'venv' in str(p) or 'site-packages' in str(p):
        continue
    analyze_file(p)
