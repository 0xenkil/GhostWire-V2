"""
WAF Evasion Engine - Generic, adaptive evasion tactics for ANY WAF

Maps detected WAF behaviors to appropriate evasion techniques.
NOT hardcoded per-WAF, but behavior-based and extensible.

Evasion tactics work by:
1. Identifying what the WAF detects (behaviors)
2. Applying tactics that counter those behaviors
3. Rotating tactics if current one fails
4. Learning what works for future engagements
"""

import time
import random
from typing import Dict, List, Any, Optional, Callable


class EvasionTactic:
    """Represents a single evasion technique"""

    def __init__(self, name: str, applies_to: List[str], implementation: Callable,
                 effectiveness_on: List[str], priority: int, parameters: Dict[str, Any] = None):
        """
        Initialize evasion tactic

        Args:
            name: Tactic name (e.g., 'slow_requests')
            applies_to: Which WAF behaviors this counters
            implementation: Function that implements the tactic
            effectiveness_on: What behaviors this is effective against
            priority: Priority order (1 = highest)
            parameters: Configuration parameters for the tactic
        """
        self.name = name
        self.applies_to = applies_to
        self.implementation = implementation
        self.effectiveness_on = effectiveness_on
        self.priority = priority
        self.parameters = parameters or {}

        self.success_count = 0
        self.failure_count = 0
        self.last_used = None

    @property
    def success_rate(self) -> float:
        """Calculate success rate of this tactic"""
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.5

    def record_success(self):
        """Record successful use of this tactic"""
        self.success_count += 1
        self.last_used = time.time()

    def record_failure(self):
        """Record failed use of this tactic"""
        self.failure_count += 1
        self.last_used = time.time()


class WafEvasionEngine:
    """Applies generic evasion tactics based on WAF behaviors"""

    def __init__(self, database_file: str = None):
        """Initialize evasion engine with available tactics"""
        if database_file is None:
            from config_paths import WAF_DATABASE_FILE
            self.database_file = str(WAF_DATABASE_FILE)
        else:
            self.database_file = database_file
        self.tactics = self._initialize_tactics()
        self.active_tactics = []
        self.tactic_history = []

    def build_evasion_strategy(
            self, fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build an evasion strategy based on detected WAF behaviors

        Args:
            fingerprint: WAF fingerprint from fingerprinter

        Returns:
            Strategy dict with tactics to apply in order
        """
        strategy = {
            "based_on_fingerprint": fingerprint,
            "detected_behaviors": fingerprint.get("detected_patterns", []),
            "evasion_tactics": [],
            "parameters": {}
        }

        behaviors = fingerprint.get("detected_patterns", [])

        # Find all tactics that apply to detected behaviors
        applicable_tactics = []
        for tactic in self.tactics:
            for behavior in behaviors:
                if behavior in tactic.applies_to:
                    applicable_tactics.append(tactic)
                    break

        # Sort by priority and success rate
        applicable_tactics.sort(key=lambda t: (t.priority, -t.success_rate))

        # Build strategy
        for tactic in applicable_tactics:
            strategy["evasion_tactics"].append({
                "name": tactic.name,
                "priority": tactic.priority,
                "success_rate": tactic.success_rate,
                "parameters": tactic.parameters
            })

        # Add default parameters
        strategy["parameters"] = self._build_parameters(behaviors)

        return strategy

    def apply_tactic(self, tactic_name: str,
                     target_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply a specific evasion tactic to tool execution data

        Args:
            tactic_name: Name of tactic to apply
            target_data: Data from tool execution (headers, payload, etc.)

        Returns:
            Modified data with evasion applied
        """
        tactic = self._get_tactic(tactic_name)
        if not tactic:
            return target_data

        try:
            result = tactic.implementation(target_data, tactic.parameters)
            return result
        except Exception as e:
            return {"error": str(e), "original_data": target_data}

    def rotate_tactic(self) -> Optional[str]:
        """
        Rotate to next available evasion tactic

        Returns:
            Name of next tactic to try, or None if all exhausted
        """
        if self.active_tactics:
            return self.active_tactics.pop(0)
        return None

    def record_tactic_result(self, tactic_name: str, success: bool):
        """Record success/failure of a tactic for learning"""
        tactic = self._get_tactic(tactic_name)
        if tactic:
            if success:
                tactic.record_success()
            else:
                tactic.record_failure()

            self.tactic_history.append({
                "tactic": tactic_name,
                "success": success,
                "timestamp": time.time()
            })

    # Evasion Implementations

    def _tactic_slow_requests(
            self, data: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Space out requests to avoid rate limiting"""
        delay = params.get("delay", 3)
        data["_evasion_delay"] = delay
        data["_evasion_applied"] = "slow_requests"
        return data

    def _tactic_header_rotation(
            self, data: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Rotate headers per request"""
        params.get("headers", ["User-Agent", "Accept", "Referer"])

        if "headers" not in data:
            data["headers"] = {}

        # Generate random but realistic headers
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "curl/7.64.1",
            "wget/1.20.3"
        ]

        data["headers"]["User-Agent"] = random.choice(user_agents)
        data["headers"]["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        data["headers"]["Referer"] = "https://www.google.com/"
        data["headers"]["Accept-Language"] = "en-US,en;q=0.5"

        data["_evasion_applied"] = "header_rotation"
        return data

    def _tactic_http_method_variation(
            self, data: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Vary HTTP methods"""
        methods = params.get("methods", ["GET", "POST", "HEAD", "OPTIONS"])

        # Try less common methods first
        preferred_methods = ["HEAD", "OPTIONS", "POST"]
        for method in preferred_methods:
            if method in methods:
                data["method"] = method
                data["_evasion_applied"] = "http_method_variation"
                return data

        data["method"] = random.choice(methods)
        data["_evasion_applied"] = "http_method_variation"
        return data

    def _tactic_payload_encoding(
            self, data: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Encode payloads to evade detection"""
        encoding = params.get("encoding", "hex")

        if "payload" in data:
            original = data["payload"]

            if encoding == "hex":
                data["payload"] = "".join(f"\\x{ord(c):02x}" for c in original)
            elif encoding == "url":
                import urllib.parse
                data["payload"] = urllib.parse.quote(original)
            elif encoding == "double_url":
                import urllib.parse
                data["payload"] = urllib.parse.quote(
                    urllib.parse.quote(original))
            elif encoding == "comment_injection":
                # Break payload with comments: "; /**/ DROP
                data["payload"] = original.replace(" ", "; /**/ ")

            data["_evasion_applied"] = "payload_encoding"

        return data

    def _tactic_ip_rotation(
            self, data: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Request IP rotation (proxy/VPN/Tor)"""
        rotation_service = params.get("rotation_service", "tor")

        data["_proxy_request"] = rotation_service
        data["_evasion_applied"] = "ip_rotation"
        return data

    def _tactic_timing_randomization(
            self, data: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Randomize timing between requests"""
        base_delay = params.get("base_delay", 1)
        randomness = params.get("randomness", 0.3)

        variance = base_delay * randomness
        import secrets
        delay = base_delay + secrets.SystemRandom().uniform(-variance, variance)

        data["_evasion_delay"] = delay
        data["_evasion_applied"] = "timing_randomization"
        return data

    def _tactic_fingerprint_spoofing(
            self, data: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Spoof browser fingerprint"""
        if "headers" not in data:
            data["headers"] = {}

        # Add realistic browser headers
        data["headers"]["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        data["headers"]["Accept-Encoding"] = "gzip, deflate"
        data["headers"]["Accept-Language"] = "en-US,en;q=0.5"
        data["headers"]["DNT"] = "1"
        data["headers"]["Connection"] = "keep-alive"
        data["headers"]["Upgrade-Insecure-Requests"] = "1"
        data["headers"]["Sec-Fetch-Dest"] = "document"
        data["headers"]["Sec-Fetch-Mode"] = "navigate"
        data["headers"]["Sec-Fetch-Site"] = "none"

        data["_evasion_applied"] = "fingerprint_spoofing"
        return data

    def _tactic_dummy_requests(
            self, data: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Intersperse legitimate traffic to confuse WAF"""
        data["_send_dummy_requests"] = True
        data["_dummy_count"] = params.get("dummy_count", 3)
        data["_evasion_applied"] = "dummy_requests"
        return data

    def _tactic_null_bytes(
            self, data: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Inject null bytes to bypass filters"""
        if "payload" in data:
            data["payload"] = data["payload"].replace(" ", "%00")
        data["_evasion_applied"] = "null_bytes"
        return data

    def _tactic_case_variation(
            self, data: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Vary case in URLs and payloads"""
        if "path" in data:
            parts = data["path"].split("/")
            data["path"] = "/".join(
                p.upper() if random.random() > 0.5 else p.lower() for p in parts
            )
        data["_evasion_applied"] = "case_variation"
        return data

    # Helper methods

    def _initialize_tactics(self) -> List[EvasionTactic]:
        """Initialize all available evasion tactics"""
        return [
            EvasionTactic(
                name="slow_requests",
                applies_to=["rate_limiting", "timing_detection"],
                implementation=self._tactic_slow_requests,
                effectiveness_on=["rate_limit", "ddos_protection"],
                priority=1,
                parameters={"delay": 3}
            ),
            EvasionTactic(
                name="header_rotation",
                applies_to=["user_agent_detection"],
                implementation=self._tactic_header_rotation,
                effectiveness_on=["header_based_blocking"],
                priority=2,
                parameters={"headers": ["User-Agent", "Accept", "Referer"]}
            ),
            EvasionTactic(
                name="http_method_variation",
                applies_to=["method_blocking"],
                implementation=self._tactic_http_method_variation,
                effectiveness_on=["method_blocking"],
                priority=3,
                parameters={"methods": ["GET", "POST", "HEAD", "OPTIONS"]}
            ),
            EvasionTactic(
                name="payload_encoding",
                applies_to=["payload_detection"],
                implementation=self._tactic_payload_encoding,
                effectiveness_on=["payload_detection"],
                priority=4,
                parameters={"encoding": "hex"}
            ),
            EvasionTactic(
                name="ip_rotation",
                applies_to=["ip_based_blocking"],
                implementation=self._tactic_ip_rotation,
                effectiveness_on=["ip_blocking"],
                priority=5,
                parameters={"rotation_service": "tor"}
            ),
            EvasionTactic(
                name="timing_randomization",
                applies_to=["timing_detection"],
                implementation=self._tactic_timing_randomization,
                effectiveness_on=["exponential_backoff"],
                priority=6,
                parameters={"base_delay": 1, "randomness": 0.3}
            ),
            EvasionTactic(
                name="fingerprint_spoofing",
                applies_to=["header_signature", "user_agent_detection"],
                implementation=self._tactic_fingerprint_spoofing,
                effectiveness_on=["fingerprint_based_blocking"],
                priority=7,
                parameters={}
            ),
            EvasionTactic(
                name="dummy_requests",
                applies_to=["rate_limiting"],
                implementation=self._tactic_dummy_requests,
                effectiveness_on=["pattern_detection"],
                priority=8,
                parameters={"dummy_count": 3}
            ),
            EvasionTactic(
                name="null_bytes",
                applies_to=["payload_detection"],
                implementation=self._tactic_null_bytes,
                effectiveness_on=["filter_bypasses"],
                priority=9,
                parameters={}
            ),
            EvasionTactic(
                name="case_variation",
                applies_to=["path_blocking"],
                implementation=self._tactic_case_variation,
                effectiveness_on=["case_sensitive_filters"],
                priority=10,
                parameters={}
            )
        ]

    def _get_tactic(self, tactic_name: str) -> Optional[EvasionTactic]:
        """Get tactic by name"""
        for tactic in self.tactics:
            if tactic.name == tactic_name:
                return tactic
        return None

    def _build_parameters(self, behaviors: List[str]) -> Dict[str, Any]:
        """Build optimal parameters based on detected behaviors"""
        params = {}

        if "rate_limiting" in behaviors:
            params["delay"] = 3
            params["request_spacing"] = "adaptive"

        if "response_delay" in behaviors:
            params["timeout"] = 30
            params["retry_delay"] = 5

        if "ip_based_blocking" in behaviors:
            params["use_proxy"] = True
            params["proxy_type"] = "rotating"

        if "user_agent_detection" in behaviors:
            params["rotate_user_agent"] = True
            params["rotation_frequency"] = "per_request"

        return params

    def get_tactic_stats(self) -> Dict[str, Any]:
        """Get statistics on tactic effectiveness"""
        stats = {
            "total_tactics": len(self.tactics),
            "tactics_by_effectiveness": []
        }

        sorted_tactics = sorted(
            self.tactics,
            key=lambda t: t.success_rate,
            reverse=True)
        for tactic in sorted_tactics:
            stats["tactics_by_effectiveness"].append({
                "name": tactic.name,
                "success_rate": tactic.success_rate,
                "successes": tactic.success_count,
                "failures": tactic.failure_count
            })

        return stats
