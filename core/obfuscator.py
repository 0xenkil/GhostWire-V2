import base64
import ast


class DynamicObfuscator:
    def __init__(self, level="light"):
        self.level = level

    def obfuscate_python(self, source: str) -> str:
        try:
            ast.parse(source)
            encoded = base64.b64encode(source.encode('utf-8')).decode('utf-8')
            return f"import base64\nexec(base64.b64decode('{encoded}').decode('utf-8'))"
        except SyntaxError:
            return source
