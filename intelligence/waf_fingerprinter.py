"""
WAF Fingerprinter - Behavioral fingerprinting for any WAF

Instead of detecting "Cloudflare" or "AWS WAF", this identifies
WAF behavior patterns and creates fingerprints that can match
any WAF, including unknown ones.

Behavioral patterns:
- Rate limiting thresholds
- Blocking response codes
- Header signatures
- Timing delays
- Method blocking
- Path blocking
- Payload blocking patterns
"""

import json
import os
import time
import re
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class WafFingerprinter:
    """Fingerprints any WAF through behavioral analysis"""
    
    _waf_cache = {}

    def __init__(self, database_file: str = None):
        """Initialize fingerprinter with known WAF profiles"""
        self.database_file = database_file or os.path.join(
            os.path.dirname(__file__), "waf_database.json"
        )
        self.known_fingerprints = self._load_waf_database()
        self.current_fingerprint = {}
    
    def fingerprint_target(self, target_url: str, test_paths: List[str] = None) -> Dict[str, Any]:
        """
        Fingerprint a target by analyzing its WAF behavior
        
        Args:
            target_url: URL to test
            test_paths: Paths to test (default: common endpoints)
            
        Returns:
            Fingerprint dict with detected behaviors and evasion tactics
        """
        if target_url in self.__class__._waf_cache:
            return self.__class__._waf_cache[target_url]

        if not test_paths:
            test_paths = [
                "/",
                "/index.html",
                "/admin",
                "/api",
                "/.git/config",
                "/wp-admin",
                "/phpmyadmin",
                "/backup.zip"
            ]
        
        fingerprint = {
            "timestamp": time.time(),
            "target": target_url,
            "behaviors": {},
            "detected_patterns": [],
            "evasion_candidates": [],
            "confidence": 0.0,
            "similar_to_known": []
        }
        
        try:
            # Test 1: Rate limiting detection
            fingerprint["behaviors"]["rate_limit_threshold"] = self._detect_rate_limit(target_url, test_paths)
            
            # Test 2: Blocking response codes
            fingerprint["behaviors"]["blocking_status_codes"] = self._detect_blocking_codes(target_url, test_paths)
            
            # Test 3: Header signatures
            fingerprint["behaviors"]["blocking_headers"] = self._detect_blocking_headers(target_url)
            
            # Test 4: Response timing patterns
            fingerprint["behaviors"]["response_delay"] = self._detect_timing_pattern(target_url, test_paths)
            
            # Test 5: HTTP method blocking
            fingerprint["behaviors"]["request_methods_blocked"] = self._detect_method_blocking(target_url)
            
            # Test 6: Path pattern blocking
            fingerprint["behaviors"]["path_patterns_blocked"] = self._detect_path_blocking(target_url)
            
            # Test 7: Payload pattern blocking
            fingerprint["behaviors"]["payload_patterns_blocked"] = self._detect_payload_blocking(target_url)
            
            # Test 8: IP-based blocking
            fingerprint["behaviors"]["ip_rotation_required"] = self._detect_ip_blocking(target_url)
            
            # Test 9: User-Agent sensitivity
            fingerprint["behaviors"]["user_agent_sensitive"] = self._detect_useragent_sensitivity(target_url)
            
            # Test 10: Timing attack detection
            fingerprint["behaviors"]["timing_pattern"] = self._detect_timing_attack_pattern(target_url)
            
            # Match against known fingerprints
            fingerprint["similar_to_known"] = self._match_known_fingerprints(fingerprint["behaviors"])
            
            # Determine detected patterns
            fingerprint["detected_patterns"] = self._identify_patterns(fingerprint["behaviors"])
            
            # Suggest evasion tactics
            fingerprint["evasion_candidates"] = self._suggest_evasion_tactics(fingerprint["detected_patterns"])
            
            # Calculate confidence
            fingerprint["confidence"] = self._calculate_confidence(fingerprint)
            
            self.current_fingerprint = fingerprint
            self.__class__._waf_cache[target_url] = fingerprint
            
        except Exception as e:
            fingerprint["error"] = str(e)
        
        return fingerprint
    
    def _detect_rate_limit(self, target_url: str, test_paths: List[str]) -> Optional[int]:
        """Detect at what request count rate limiting kicks in"""
        try:
            session = self._create_session()
            blocked_count = 0
            
            for i, path in enumerate(test_paths[:10]):
                try:
                    url = target_url.rstrip('/') + path
                    resp = session.get(url, timeout=5)
                    
                    if resp.status_code in [429, 503, 418]:  # Rate limit codes
                        blocked_count = i
                        return i
                    
                    time.sleep(0.5)  # Small delay between requests
                
                except requests.exceptions.Timeout:
                    blocked_count = i
                    return i
                except requests.exceptions.RequestException as e:
                    if hasattr(self, "log"): self.log.debug(f"Rate limit probe failed: {e}")
                    break
            
            return None
        except:
            return None
    
    def _detect_blocking_codes(self, target_url: str, test_paths: List[str]) -> List[int]:
        """Detect which HTTP status codes indicate blocking"""
        try:
            session = self._create_session()
            blocking_codes = []
            
            for path in test_paths[:5]:
                try:
                    url = target_url.rstrip('/') + path
                    resp = session.get(url, timeout=5)
                    
                    # 403, 429, 418, 403.11, 403.14 are blocking indicators
                    if resp.status_code in [403, 429, 418, 451]:
                        blocking_codes.append(resp.status_code)
                    
                    time.sleep(0.3)
                except requests.exceptions.RequestException as e:
                    if hasattr(self, "log"): self.log.debug(f"Blocking codes probe failed: {e}")
                    continue
            
            return list(set(blocking_codes)) if blocking_codes else [403, 429]
        except:
            return [403, 429]
    
    def _detect_blocking_headers(self, target_url: str) -> List[str]:
        """Detect WAF-specific headers in responses"""
        try:
            session = self._create_session()
            headers_seen = []
            
            for _ in range(3):
                try:
                    resp = session.get(target_url, timeout=5)
                    
                    # Common WAF headers
                    waf_headers = [
                        "__cfruid", "cf_clearance",  # Cloudflare
                        "x-amzn-waf", "x-amzn-RequestId",  # AWS
                        "x-aspnetmvc-version",  # Azure/ModSecurity
                        "x-protected-by",
                        "x-waf",
                        "x-force-ssl",
                        "cf-ray",
                        "x-cdn"
                    ]
                    
                    for header in resp.headers:
                        if header.lower() in waf_headers or any(w in header.lower() for w in waf_headers):
                            headers_seen.append(header)
                    
                    time.sleep(0.3)
                except requests.exceptions.RequestException as e:
                    if hasattr(self, "log"): self.log.debug(f"Headers probe failed: {e}")
                    continue
            
            return list(set(headers_seen))
        except:
            return []
    
    def _detect_timing_pattern(self, target_url: str, test_paths: List[str]) -> float:
        """Detect if WAF adds response delays"""
        try:
            session = self._create_session()
            times = []
            
            for path in test_paths[:3]:
                try:
                    url = target_url.rstrip('/') + path
                    start = time.time()
                    resp = session.get(url, timeout=10)
                    elapsed = time.time() - start
                    times.append(elapsed)
                    time.sleep(0.2)
                except requests.exceptions.RequestException as e:
                    if hasattr(self, "log"): self.log.debug(f"Timing probe failed: {e}")
                    continue
            
            if times:
                avg_delay = sum(times) / len(times)
                return round(avg_delay, 2) if avg_delay > 1 else 0
            return 0
        except:
            return 0
    
    def _detect_method_blocking(self, target_url: str) -> List[str]:
        """Detect which HTTP methods are blocked"""
        try:
            session = self._create_session()
            blocked_methods = []
            methods = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE", "PATCH"]
            
            for method in methods:
                try:
                    req = requests.Request(method, target_url)
                    prepared = session.prepare_request(req)
                    resp = session.send(prepared, timeout=5)
                    
                    if resp.status_code in [403, 405, 501]:
                        blocked_methods.append(method)
                    
                    time.sleep(0.2)
                except requests.exceptions.RequestException as e:
                    if hasattr(self, "log"): self.log.debug(f"Method blocking probe failed: {e}")
                    blocked_methods.append(method)
            
            return blocked_methods
        except:
            return []
    
    def _detect_path_blocking(self, target_url: str) -> List[str]:
        """Detect which path patterns are blocked"""
        try:
            session = self._create_session()
            blocked_paths = []
            
            suspicious_paths = [
                "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
                "/.env", "/.git", "/.git/config", "/.gitignore",
                "/backup.sql", "/backup.zip", "/config.php", "/web.config"
            ]
            
            for path in suspicious_paths[:8]:
                try:
                    url = target_url.rstrip('/') + path
                    resp = session.get(url, timeout=5)
                    
                    if resp.status_code == 403:
                        blocked_paths.append(path)
                    
                    time.sleep(0.2)
                except requests.exceptions.RequestException as e:
                    if hasattr(self, "log"): self.log.debug(f"Path blocking probe failed: {e}")
                    continue
            
            return blocked_paths
        except:
            return []
    
    def _detect_payload_blocking(self, target_url: str) -> List[str]:
        """Detect which payload patterns are blocked"""
        try:
            session = self._create_session()
            blocked_patterns = []
            
            payloads = [
                "<script>alert(1)</script>",
                "' or '1'='1",
                "union select",
                "../../../etc/passwd",
                "<?php system($_GET['cmd']); ?>",
                "eval(",
                "exec(",
                "system("
            ]
            
            for payload in payloads[:5]:
                try:
                    # Test as query parameter
                    url = target_url + "?test=" + payload
                    resp = session.get(url, timeout=5)
                    
                    if resp.status_code in [403, 406]:
                        blocked_patterns.append(payload[:20])  # Store first 20 chars
                    
                    time.sleep(0.2)
                except requests.exceptions.RequestException as e:
                    if hasattr(self, "log"): self.log.debug(f"Payload probe failed: {e}")
                    blocked_patterns.append(payload[:20])
            
            return blocked_patterns
        except:
            return []
    
    def _detect_ip_blocking(self, target_url: str) -> bool:
        """Detect if IP-based blocking is in effect"""
        try:
            session = self._create_session()
            
            # Make multiple requests from same IP
            responses = []
            for _ in range(5):
                try:
                    resp = session.get(target_url, timeout=5)
                    responses.append(resp.status_code)
                    time.sleep(0.5)
                except requests.exceptions.RequestException as e:
                    if hasattr(self, "log"): self.log.debug(f"IP blocking probe failed: {e}")
                    responses.append(None)
            
            # If we see 429 or 403 after multiple requests, IP blocking likely
            if 429 in responses or (responses.count(403) > 2):
                return True
            return False
        except:
            return False
    
    def _detect_useragent_sensitivity(self, target_url: str) -> bool:
        """Detect if WAF is User-Agent sensitive"""
        try:
            session = self._create_session()
            
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "curl/7.64.1",
                "python-requests/2.25.1",
                "sqlmap/1.4",
                "nikto/2.1.5"
            ]
            
            responses = []
            for ua in user_agents:
                try:
                    resp = session.get(target_url, headers={"User-Agent": ua}, timeout=5)
                    responses.append(resp.status_code)
                    time.sleep(0.2)
                except requests.exceptions.RequestException as e:
                    if hasattr(self, "log"): self.log.debug(f"UA sensitivity probe failed: {e}")
                    responses.append(None)
            
            # If response codes vary significantly, UA sensitivity detected
            unique_codes = len(set([r for r in responses if r]))
            return unique_codes > 2
        except:
            return False
    
    def _detect_timing_attack_pattern(self, target_url: str) -> str:
        """Detect if WAF uses timing attacks (exponential backoff, etc)"""
        try:
            session = self._create_session()
            times = []
            
            for i in range(3):
                try:
                    start = time.time()
                    resp = session.get(target_url, timeout=10)
                    elapsed = time.time() - start
                    times.append(elapsed)
                    time.sleep(0.5)
                except requests.exceptions.RequestException as e:
                    if hasattr(self, "log"): self.log.debug(f"Timing attack probe failed: {e}")
                    times.append(10)  # Timeout = long delay
            
            # Check if delays increase (exponential pattern)
            if len(times) >= 2:
                if times[1] > times[0] * 1.5 and times[2] > times[1] * 1.5:
                    return "exponential"
                elif all(t > 1 for t in times):
                    return "consistent_delay"
            
            return "none"
        except:
            return "unknown"
    
    def _identify_patterns(self, behaviors: Dict[str, Any]) -> List[str]:
        """Identify which security patterns the WAF uses"""
        patterns = []
        
        if behaviors.get("rate_limit_threshold"):
            patterns.append("rate_limiting")
        if behaviors.get("blocking_headers"):
            patterns.append("header_signature")
        if behaviors.get("response_delay", 0) > 0.5:
            patterns.append("response_delay")
        if behaviors.get("request_methods_blocked"):
            patterns.append("method_blocking")
        if behaviors.get("path_patterns_blocked"):
            patterns.append("path_blocking")
        if behaviors.get("payload_patterns_blocked"):
            patterns.append("payload_detection")
        if behaviors.get("ip_rotation_required"):
            patterns.append("ip_based_blocking")
        if behaviors.get("user_agent_sensitive"):
            patterns.append("user_agent_detection")
        if behaviors.get("timing_pattern") != "none":
            patterns.append("timing_detection")
        
        return patterns
    
    def _suggest_evasion_tactics(self, patterns: List[str]) -> List[str]:
        """Suggest evasion tactics based on detected patterns"""
        tactic_map = {
            "rate_limiting": ["slow_requests", "timing_randomization"],
            "header_signature": ["header_rotation", "header_spoofing"],
            "response_delay": ["connection_pooling", "persistence"],
            "method_blocking": ["http_method_variation"],
            "path_blocking": ["url_encoding", "path_normalization"],
            "payload_detection": ["payload_encoding", "comment_injection"],
            "ip_based_blocking": ["ip_rotation", "proxy_rotation"],
            "user_agent_detection": ["user_agent_rotation", "fingerprint_spoofing"],
            "timing_detection": ["timing_randomization", "dummy_requests"]
        }
        
        tactics = []
        for pattern in patterns:
            tactics.extend(tactic_map.get(pattern, []))
        
        return list(set(tactics))  # Remove duplicates
    
    def _match_known_fingerprints(self, behaviors: Dict[str, Any]) -> List[str]:
        """Match against known WAF fingerprints"""
        matches = []
        
        for fp_name, fp_data in self.known_fingerprints.items():
            score = self._calculate_fingerprint_similarity(behaviors, fp_data.get("behaviors", {}))
            if score > 0.6:  # > 60% match
                matches.append(f"{fp_name} (match: {score:.0%})")
        
        return matches
    
    def _calculate_fingerprint_similarity(self, behaviors1: Dict, behaviors2: Dict) -> float:
        """Calculate similarity between two fingerprints (0-1)"""
        if not behaviors2:
            return 0.0
        
        matches = 0
        total = max(len(behaviors1), len(behaviors2))
        
        for key in behaviors1:
            if key in behaviors2:
                val1 = behaviors1[key]
                val2 = behaviors2[key]
                
                if isinstance(val1, bool) and isinstance(val2, bool):
                    if val1 == val2:
                        matches += 1
                elif isinstance(val1, list) and isinstance(val2, list):
                    if set(val1) & set(val2):  # Any overlap
                        matches += 0.5
        
        return matches / total if total > 0 else 0
    
    def _calculate_confidence(self, fingerprint: Dict[str, Any]) -> float:
        """Calculate confidence in the fingerprint"""
        behaviors = fingerprint.get("behaviors", {})
        patterns = fingerprint.get("detected_patterns", [])
        
        # More patterns detected = higher confidence
        pattern_confidence = min(len(patterns) / 5, 1.0)
        
        # Similar to known WAF = higher confidence
        matches = fingerprint.get("similar_to_known", [])
        match_confidence = 0.7 if matches else 0.3
        
        return (pattern_confidence * 0.6 + match_confidence * 0.4)
    
    def _create_session(self, retries: int = 0) -> requests.Session:
        """Create a requests session with retry logic"""
        session = requests.Session()
        retry_strategy = Retry(total=retries, connect=retries, read=retries)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def _load_waf_database(self) -> Dict[str, Any]:
        """Load known WAF fingerprints"""
        if os.path.exists(self.database_file):
            try:
                with open(self.database_file, "r") as f:
                    data = json.load(f)
                    return data.get("fingerprints", {})
            except Exception as e:
                if hasattr(self, "log"):
                    self.log.warning(f"Could not load WAF database: {e}")
                else:
                    import logging
                    logging.warning(f"Could not load WAF database: {e}")
                return {}
        return {}
    
    def save_fingerprint(self, fingerprint: Dict[str, Any], name: str = None) -> str:
        """Save a discovered fingerprint to the database"""
        if not name:
            name = f"unknown_waf_{int(time.time())}"
        
        # Load existing database
        db = {}
        if os.path.exists(self.database_file):
            try:
                with open(self.database_file, "r") as f:
                    db = json.load(f)
            except:
                db = {"fingerprints": {}, "tactics": []}
        
        # Add new fingerprint
        if "fingerprints" not in db:
            db["fingerprints"] = {}
        
        db["fingerprints"][name] = {
            "behaviors": fingerprint.get("behaviors", {}),
            "confidence": fingerprint.get("confidence", 0),
            "discovered": fingerprint.get("timestamp", time.time())
        }
        
        # Save back
        os.makedirs(os.path.dirname(self.database_file), exist_ok=True)
        with open(self.database_file, "w") as f:
            json.dump(db, f, indent=2)
        
        return name
