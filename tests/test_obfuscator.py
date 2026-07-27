import unittest
from core.obfuscator import DynamicObfuscator


class TestObfuscator(unittest.TestCase):
    def test_python_light_obfuscation(self):
        source = "print('hello world')"
        obfuscator = DynamicObfuscator(level="light")
        obfuscated = obfuscator.obfuscate_python(source)

        self.assertIn("import base64", obfuscated)
        self.assertIn("exec(base64.b64decode", obfuscated)

        # Verify it still runs properly
        import io
        import sys

        captured_output = io.StringIO()
        sys.stdout = captured_output
        exec(obfuscated)
        sys.stdout = sys.__stdout__

        self.assertEqual(captured_output.getvalue().strip(), "hello world")

    def test_invalid_python_obfuscation(self):
        source = "print('hello world"  # Syntax error
        obfuscator = DynamicObfuscator(level="light")
        obfuscated = obfuscator.obfuscate_python(source)

        # Should return raw un-obfuscated due to syntax error
        self.assertEqual(obfuscated, source)


if __name__ == "__main__":
    unittest.main()
