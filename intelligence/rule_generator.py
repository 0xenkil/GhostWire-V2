"""
Rule Generator - Creates new JSON rules from discovered patterns

Generates:
- New exploitation rules
- Tool fallback sequences
- Technology-specific exploitation strategies
- WAF evasion techniques
"""

import json
import os
from typing import Dict, List, Any, Tuple
from collections import defaultdict


class RuleGenerator:
    """Generates new system rules from engagement learnings"""

    def __init__(self, rules_dir: str = None):
        """Initialize rule generator"""
        self.rules_dir = rules_dir or os.path.join(
            os.path.dirname(__file__), "..", "rules"
        )
        self.new_rules = []

    def generate_rules_from_insights(
            self, insights: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate new rules from engagement insights

        Args:
            insights: Dictionary from engagement_analyzer

        Returns:
            Dict of new rules to potentially add to system
        """
        rules_package = {
            "engagement_id": insights.get("engagement_id"),
            "timestamp": insights.get("timestamp"),
            "rules": {
                "exploitation": [],
                "infrastructure": [],
                "recon": [],
                "weaponization": []
            },
            "generated_from_patterns": []
        }

        # Generate exploitation rules
        rules_package["rules"]["exploitation"] = self._generate_exploitation_rules(
            insights)

        # Generate infrastructure rules
        rules_package["rules"]["infrastructure"] = self._generate_infrastructure_rules(
            insights)

        # Generate recon rules
        rules_package["rules"]["recon"] = self._generate_recon_rules(insights)

        # Generate weaponization rules
        rules_package["rules"]["weaponization"] = self._generate_weaponization_rules(
            insights)

        # Track patterns that generated rules
        rules_package["generated_from_patterns"] = self._track_pattern_sources(
            insights)

        return rules_package

    def _generate_exploitation_rules(
            self, insights: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate new exploitation rules"""
        rules = []

        tech_patterns = insights.get(
            "technology_patterns", {}).get(
            "detected_technologies", {})
        tool_rates = insights.get(
            "tool_effectiveness", {}).get(
            "tool_rates", {})
        findings = insights.get("findings_confirmed", [])

        # Rule for each confirmed technology
        for tech, info in tech_patterns.items():
            if not isinstance(info, dict):
                continue

            if info.get("confirmed"):
                # Find best tools for this tech
                best_tools = sorted(
                    [(t, r.get("success_rate", 0))
                     for t, r in tool_rates.items() if r.get("success_rate", 0) > 0],
                    key=lambda x: x[1],
                    reverse=True
                )

                rule = self._create_tech_exploitation_rule(
                    tech, best_tools, info)
                if rule:
                    rules.append(rule)

        # Rules for specific vulnerabilities found
        vuln_types = defaultdict(int)
        for finding in findings:
            vuln_type = finding.get("type", "")
            if vuln_type:
                vuln_types[vuln_type] += 1

        for vuln_type, count in vuln_types.items():
            if count >= 2:  # Pattern if found multiple times
                rule = self._create_vulnerability_exploitation_rule(vuln_type)
                if rule:
                    rules.append(rule)

        return rules

    def _generate_infrastructure_rules(
            self, insights: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate infrastructure/WAF handling rules"""
        rules = []

        waf_patterns = insights.get("waf_patterns", {})
        waf_type = waf_patterns.get("waf_type")

        if waf_type:
            tools_blocked = waf_patterns.get("tools_blocked", [])
            tools_effective = waf_patterns.get("tools_effective", [])

            rule = {
                "id": f"waf_{waf_type}_handling",
                "name": f"Handle {waf_type} WAF",
                "type": "waf_detection",
                "condition": {
                    "waf_detected": waf_type
                },
                "actions": {
                    "skip_tools": tools_blocked,
                    "prefer_tools": tools_effective,

                    "use_evasion": True
                },
                "confidence": 0.9,
                "source": f"engagement_{insights.get('engagement_id')}"
            }
            rules.append(rule)

        return rules

    def _generate_recon_rules(
            self, insights: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate reconnaissance rules"""
        rules = []

        insights.get("target_profile", {})
        tech_patterns = insights.get(
            "technology_patterns", {}).get(
            "detected_technologies", {})

        confirmed_techs = [
            t for t, info in tech_patterns.items() if isinstance(
                info, dict) and info.get("confirmed")]

        if confirmed_techs:
            rule = {
                "id": f"recon_for_techs_{len(confirmed_techs)}",
                "name": "Recon for Confirmed Technologies",
                "type": "reconnaissance",
                "technologies": confirmed_techs,
                "recommended_tools": ["curl", "wget"],
                "endpoints_to_check": self._get_tech_specific_endpoints(confirmed_techs),
                "confidence": 0.85,
                "source": f"engagement_{insights.get('engagement_id')}"
            }
            rules.append(rule)

        return rules

    def _generate_weaponization_rules(
            self, insights: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate weaponization/PoC rules"""
        rules = []

        findings = insights.get("findings_confirmed", [])

        if len(findings) >= 2:
            rule = {
                "id": "weaponize_confirmed_vulns",
                "name": "Create Payloads for Confirmed Vulnerabilities",
                "type": "weaponization",
                "confirmed_vulnerability_count": len(findings),
                "payload_types": self._get_payload_types_for_findings(findings),
                "automation_level": "high",
                "confidence": 0.8,
                "source": f"engagement_{insights.get('engagement_id')}"
            }
            rules.append(rule)

        return rules

    def _create_tech_exploitation_rule(
            self, tech: str, best_tools: List[Tuple[str, float]], info: Dict) -> Dict[str, Any]:
        """Create exploitation rule for specific technology"""
        if not best_tools:
            return None

        tool_names = [t[0] for t in best_tools[:3]]
        success_rates = [t[1] for t in best_tools[:3]]

        return {
            "id": f"exploit_{tech}_identified",
            "name": f"Exploit {tech.title()}",
            "type": "exploitation",
            "technology": tech,
            "tool_sequence": tool_names,
            "expected_success_rate": sum(success_rates) / len(success_rates) if success_rates else 0,
            "commands": self._get_exploit_commands_for_tech(tech, tool_names),
            "confidence": min(0.95, 0.7 + (info.get("occurrences", 0) * 0.05)),
            "source": "engagement_pattern"
        }

    def _create_vulnerability_exploitation_rule(
            self, vuln_type: str) -> Dict[str, Any]:
        """Create rule for specific vulnerability type"""
        return {
            "id": f"exploit_{vuln_type}",
            "name": f"Exploit {vuln_type.replace('_', ' ').title()}",
            "type": "vulnerability",
            "vulnerability_type": vuln_type,
            "automation_level": "high",
            "confidence": 0.8,
            "tools": self._get_tools_for_vuln_type(vuln_type)
        }

    def _get_tech_specific_endpoints(self, techs: List[str]) -> List[str]:
        """Get endpoints to check for technologies"""
        endpoints = {
            "wordpress": [
                "/wp-admin/",
                "/wp-content/",
                "/wp-includes/",
                "/wp-json/wp/v2/plugins/",
                "/wp-json/wp/v2/themes/",
                "/readme.html",
                "/license.txt"
            ],
            "apache": [
                "/.htaccess",
                "/.htpasswd",
                "/server-status",
                "/manual/"
            ],
            "nginx": [
                "/.gitignore",
                "/.git/config"
            ],
            "php": [
                "/info.php",
                "/phpinfo.php",
                "/test.php"
            ],
            "nodejs": [
                "/package.json",
                "/.env",
                "/config.json"
            ]
        }

        result = []
        for tech in techs:
            result.extend(endpoints.get(tech.lower(), []))

        return list(set(result))  # Remove duplicates

    def _get_exploit_commands_for_tech(
            self, tech: str, tools: List[str]) -> List[str]:
        """Get example exploit commands for technology"""
        commands_map = {
            "wordpress": [
                "curl -s {target}/wp-json/wp/v2/plugins/ | jq",
                "curl -s {target}/wp-json/wp/v2/themes/ | jq",
                "curl -s {target}/wp-admin/"
            ],
            "apache": [
                "curl -s {target}/.htaccess",
                "curl -s {target}/server-status"
            ],
            "php": [
                "curl -s {target}/info.php",
                "curl -s {target}/phpinfo.php"
            ]
        }

        return commands_map.get(tech.lower(), ["curl -s {target}"])

    def _get_tools_for_vuln_type(self, vuln_type: str) -> List[str]:
        """Get tools for vulnerability type"""
        tools_map = {
            "sql_injection": ["sqlmap", "dalfox"],
            "xss": ["dalfox", "curl"],
            "rce": ["curl", "commix"],
            "lfi": ["curl", "ffuf"],
            "cors": ["curl"],
            "csrf": ["curl"]
        }

        return tools_map.get(vuln_type.lower(), ["curl"])

    def _get_payload_types_for_findings(
            self, findings: List[Dict]) -> List[str]:
        """Get payload types needed for findings"""
        payloads = set()

        for finding in findings:
            finding_type = finding.get("type", "").lower()

            if "sql" in finding_type:
                payloads.add("sql_payload")
            if "xss" in finding_type:
                payloads.add("javascript_payload")
            if "rce" in finding_type:
                payloads.add("shell_payload")
            if "upload" in finding_type:
                payloads.add("webshell")

        return list(payloads)

    def _track_pattern_sources(self, insights: Dict[str, Any]) -> List[str]:
        """Track which patterns generated which rules"""
        sources = []

        patterns = insights.get("patterns_discovered", [])
        sources.extend(patterns)

        findings_count = len(insights.get("findings_confirmed", []))
        if findings_count > 0:
            sources.append(f"Pattern: {findings_count} confirmed findings")

        waf_type = insights.get("waf_patterns", {}).get("waf_type")
        if waf_type:
            sources.append(f"Pattern: {waf_type} WAF detection")

        return sources

    def save_rules(
            self, rules_package: Dict[str, Any], output_file: str = None) -> str:
        """Save generated rules to file"""
        if not output_file:
            output_file = os.path.join(
                self.rules_dir,
                f"generated_{rules_package.get('engagement_id')}.json"
            )

        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        with open(output_file, "w") as f:
            json.dump(rules_package, f, indent=2)

        return output_file

    def merge_rules_to_system(
            self, rules_package: Dict[str, Any], truth_gate=None) -> Dict[str, int]:
        """
        Merge generated rules into system rule files — ONLY those a TruthGate
        admits.

        P3-6 (RULEGEN-MERGE-DEAD): the old 0.8 *confidence* threshold let a rule
        the AI merely felt confident about rewrite the system. The gate is now
        proof, not self-assessed confidence: each rule_type's rules are merged
        only if ``truth_gate.supports`` admits the change. No gate → merge
        NOTHING (fail-closed) — the loop stays open (wire a TruthGate built from a
        cross-engagement proven-outcome ledger to re-enable), but it can never
        self-modify on an unproven signal.

        Returns count of rules merged per type.
        """
        merged_count = {
            "exploitation": 0,
            "infrastructure": 0,
            "recon": 0,
            "weaponization": 0
        }
        if truth_gate is None:
            return merged_count  # fail-closed: no proof authority → no merge

        for rule_type in merged_count.keys():
            rules = rules_package.get("rules", {}).get(rule_type, [])
            if not rules:
                continue
            try:
                admitted = truth_gate.supports({"rule_type": rule_type,
                                                "rules": rules})
            except Exception:
                admitted = False
            if admitted:
                self._append_to_rule_file(rule_type, rules)
                merged_count[rule_type] = len(rules)

        return merged_count

    def _append_to_rule_file(self, rule_type: str,
                             rules: List[Dict[str, Any]]) -> None:
        """Append rules to system rule file safely"""
        import time
        rule_file = os.path.join(self.rules_dir, f"{rule_type}.json")
        lock_dir = rule_file + ".lock"

        # Acquire lock
        for _ in range(50):
            try:
                os.mkdir(lock_dir)
                break
            except FileExistsError:
                time.sleep(0.1)
        else:
            import logging as __logging_tmp
            __logging_tmp.getLogger(__name__).error(
                f"Timeout acquiring lock for {rule_file}")
            return

        try:
            # P3-6 (RULEGEN-APPEND-LATENT): load existing content and REMEMBER its
            # shape. The live rule files are CONFIG DICTS (web_ports, timeouts, …)
            # with NO "rules" key — the old code did `content.get("rules", [])` →
            # [], appended, then wrote back a BARE LIST, obliterating the entire
            # config. Now: rules live under the dict's "rules" list (every other
            # config key preserved), or stay a bare list for a legacy list-file.
            content = None
            if os.path.exists(rule_file):
                try:
                    with open(rule_file, "r") as f:
                        content = json.load(f)
                except Exception as _e:
                    import logging
                    logging.getLogger(__name__).debug(
                        f'Swallowed exception in rule_generator.py: {_e}')
                    content = None

            is_dict_shape = isinstance(content, dict)
            if is_dict_shape:
                existing_rules = content.get("rules", [])
                if not isinstance(existing_rules, list):
                    existing_rules = []
            elif isinstance(content, list):
                existing_rules = content
            else:
                existing_rules = []

            # id-dedup: a re-run must UPDATE a rule with the same id, not append a
            # duplicate. Preserve first-seen order; id-less rules are appended once.
            merged, by_id, seen_idless = [], {}, set()
            for r in existing_rules + list(rules):
                rid = r.get("id") if isinstance(r, dict) else None
                if rid is not None:
                    if rid in by_id:
                        merged[by_id[rid]] = r  # later wins (the fresh rule)
                    else:
                        by_id[rid] = len(merged)
                        merged.append(r)
                else:
                    key = json.dumps(r, sort_keys=True, default=str)
                    if key not in seen_idless:
                        seen_idless.add(key)
                        merged.append(r)

            # Reassemble preserving the ORIGINAL shape (never clobber config keys).
            if is_dict_shape:
                content["rules"] = merged
                payload = content
            else:
                payload = merged

            # Atomic write: temp in the same dir + os.replace, so a crash mid-write
            # can never leave a truncated/corrupt rule file.
            tmp = rule_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp, rule_file)
        finally:
            try:
                os.rmdir(lock_dir)
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Ignored error: {e}")
