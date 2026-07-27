import unittest
from core.payload_sandbox import validate_script


class TestAstSanitizer(unittest.TestCase):
    def test_blocks_os(self):
        code = "import os\nos.system('id')"
        errors = validate_script(code)
        self.assertTrue(
            any("Forbidden module import: os" in e for e in errors))

    def test_blocks_subprocess(self):
        code = "import subprocess\nsubprocess.run('id')"
        errors = validate_script(code)
        self.assertTrue(
            any("Forbidden module import: subprocess" in e for e in errors))

    def test_blocks_eval(self):
        code = "eval('1+1')"
        errors = validate_script(code)
        self.assertTrue(
            any("Forbidden function call: eval" in e for e in errors))

    def test_allows_safe_code(self):
        code = "import urllib.request\nx = 1 + 1\nprint(x)"
        errors = validate_script(code)
        self.assertEqual(len(errors), 0)


if __name__ == '__main__':
    unittest.main()
