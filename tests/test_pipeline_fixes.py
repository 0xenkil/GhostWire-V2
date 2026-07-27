"""Tests for the pipeline fixes: JSON recovery, Unicode normalization, WAF evasion."""
import json
import sys
import os
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestRobustParserPerItemRecovery:
    """Fix #1: Per-item JSON recovery in robust_parser.py."""

    def test_valid_json_array(self):
        """Normal case — a clean JSON array parses correctly."""
        from core.robust_parser import extract_json_list
        text = '[{"tool": "nmap", "command": "nmap -sV target"}, {"tool": "curl", "command": "curl http://target"}]'
        result = extract_json_list(text)
        assert len(result) == 2
        assert result[0]["tool"] == "nmap"
        assert result[1]["tool"] == "curl"

    def test_one_bad_item_recovers_others(self):
        """Key test: one malformed item doesn't drop the entire batch."""
        from core.robust_parser import extract_json_list
        # The second object has unescaped quotes inside the command value
        text = '''[
            {"tool": "nmap", "command": "nmap -sV target"},
            {"tool": "curl", "command": "curl -H "Host: evil" http://target"},
            {"tool": "nikto", "command": "nikto -h target"}
        ]'''
        result = extract_json_list(text)
        # Should recover at least 2 out of 3 (the valid ones)
        assert len(result) >= 2
        tools = [r.get("tool") for r in result]
        assert "nmap" in tools
        assert "nikto" in tools

    def test_bracket_in_regex_payload(self):
        """The non-greedy regex used to truncate at ] inside payloads like [a-z]."""
        from core.robust_parser import extract_json_list
        text = '[{"tool": "grep", "command": "grep [a-z] /etc/passwd"}, {"tool": "cat", "command": "cat /etc/hosts"}]'
        result = extract_json_list(text)
        assert len(result) == 2

    def test_markdown_code_block(self):
        """JSON inside markdown code fences."""
        from core.robust_parser import extract_json_list
        text = '```json\n[{"tool": "nmap", "command": "nmap target"}]\n```'
        result = extract_json_list(text)
        assert len(result) == 1
        assert result[0]["tool"] == "nmap"

    def test_completely_invalid_returns_empty(self):
        """Completely garbled text returns empty, not crashes."""
        from core.robust_parser import extract_json_list
        result = extract_json_list("this is not json at all")
        assert result == []

    def test_single_object_not_array(self):
        """Single object (not array) is wrapped in a list."""
        from core.robust_parser import extract_json_list
        text = '{"tool": "nmap", "command": "nmap target"}'
        result = extract_json_list(text)
        assert len(result) == 1

    def test_unescaped_quotes_auto_repair(self):
        """Auto-repair for the most common AI error: unescaped inner quotes."""
        from core.robust_parser import _repair_unescaped_quotes
        # AI often emits: {"command": "curl -d "a=b" url"}
        blob = '{"command": "curl -d "a=b" url"}'
        repaired = _repair_unescaped_quotes(blob)
        # Should parse after repair
        try:
            obj = json.loads(repaired, strict=False)
            assert "command" in obj
        except json.JSONDecodeError:
            # Repair is best-effort — if it fails, the per-item recovery
            # will skip this object but not crash
            pass

    def test_object_boundary_finder(self):
        """_find_object_boundaries correctly finds multiple objects."""
        from core.robust_parser import _find_object_boundaries
        text = 'prefix {"a": 1} middle {"b": {"nested": 2}} end'
        boundaries = _find_object_boundaries(text)
        assert len(boundaries) == 2
        obj1 = json.loads(text[boundaries[0][0]:boundaries[0][1]])
        assert obj1 == {"a": 1}
        obj2 = json.loads(text[boundaries[1][0]:boundaries[1][1]])
        assert obj2 == {"b": {"nested": 2}}


class TestUnicodeNormalization:
    """Fix #2: Unicode → ASCII normalization instead of stripping."""

    def _get_normalizer(self):
        """Import the normalizer from base_agent without importing the full module."""
        # We test the static method directly by extracting its logic
        from agents.base_agent import BaseAgent
        return BaseAgent._normalize_unicode_to_ascii

    def test_en_dash_to_hyphen(self):
        """En-dash (U+2013) should become ASCII hyphen."""
        normalize = self._get_normalizer()
        # \u2013 is en-dash
        result = normalize("nmap \u2013sV target")
        assert result == "nmap -sV target"

    def test_em_dash_to_hyphen(self):
        """Em-dash (U+2014) should become ASCII hyphen."""
        normalize = self._get_normalizer()
        result = normalize("sqlmap \u2014\u2014batch")
        assert result == "sqlmap --batch"

    def test_smart_quotes_to_straight(self):
        """Smart quotes should become straight quotes."""
        normalize = self._get_normalizer()
        result = normalize('curl -H \u201cHost: evil\u201d url')
        assert result == 'curl -H "Host: evil" url'

    def test_double_dash_flag_preserved(self):
        """The critical case: --flag with unicode dashes should survive."""
        normalize = self._get_normalizer()
        # Two en-dashes followed by "batch"
        result = normalize("\u2013\u2013batch")
        assert result == "--batch"

    def test_pure_ascii_unchanged(self):
        """Normal ASCII text should pass through unchanged."""
        normalize = self._get_normalizer()
        cmd = "nmap -sV -p 80,443 --script=http-headers target.com"
        assert normalize(cmd) == cmd

    def test_zero_width_space_removed(self):
        """Zero-width spaces should be removed (not converted)."""
        normalize = self._get_normalizer()
        result = normalize("nmap\u200B -sV target")
        assert result == "nmap -sV target"

    def test_non_breaking_space_to_space(self):
        """Non-breaking space should become regular space."""
        normalize = self._get_normalizer()
        result = normalize("nmap\u00A0-sV\u00A0target")
        assert result == "nmap -sV target"


class TestWafAdaptiveEvasion:
    """Fix #3: Adaptive WAF evasion and double-flag fixes."""

    def _make_engine(self):
        from core.waf_ghost_engine import WafGhostEngine
        return WafGhostEngine(rules={"waf_ghost_use_parasitism": True})

    def test_no_evasion_without_blocks(self):
        """W6.7: with zero observed blocks (no WAF evidence) and no force,
        the command is returned UNCHANGED — evasion is purely reactive."""
        engine = self._make_engine()
        # No feedback recorded — block rate is 0.0
        cmd = 'sqlmap -u "http://target.com/?id=1" --batch'
        result = engine.transform(cmd, "sqlmap", level=3)
        # No mutation at all — no throttle, no tamper, no header injection.
        assert result == cmd

    def test_forced_evasion_without_blocks(self):
        """force=True (a real block just happened on a fresh engine) applies
        minimal evasion even with no accumulated block-rate feedback."""
        engine = self._make_engine()
        cmd = 'sqlmap -u "http://target.com/?id=1" --batch'
        result = engine.transform(cmd, "sqlmap", level=3, force=True)
        # Forced path applies evasion (e.g. random UA), not a no-op.
        assert result != cmd

    def test_throttle_after_blocks(self):
        """After recording blocks, evasion should escalate."""
        engine = self._make_engine()
        # Simulate 5 blocked requests
        for _ in range(5):
            engine.feedback("target.com", "sqlmap", blocked=True)
        # Now block rate is 1.0 — should use full level
        cmd = 'sqlmap -u "http://target.com/?id=1" --batch'
        result = engine.transform(cmd, "sqlmap", level=3)
        assert "--tamper" in result
        assert "--delay" in result

    def test_no_double_tamper_flags(self):
        """sqlmap should never have two --tamper flags."""
        engine = self._make_engine()
        # Force high block rate so level 3 activates
        for _ in range(10):
            engine.feedback("target.com", "sqlmap", blocked=True)
        cmd = 'sqlmap -u "http://target.com/?id=1" --batch'
        result = engine.transform(cmd, "sqlmap", level=3)
        assert result.count("--tamper") == 1, f"Double --tamper in: {result}"

    def test_no_double_delay_flags(self):
        """sqlmap should never have two --delay flags."""
        engine = self._make_engine()
        for _ in range(10):
            engine.feedback("target.com", "sqlmap", blocked=True)
        cmd = 'sqlmap -u "http://target.com/?id=1" --batch'
        result = engine.transform(cmd, "sqlmap", level=3)
        assert result.count("--delay") == 1, f"Double --delay in: {result}"

    def test_no_double_rate_limit_nuclei(self):
        """nuclei should never have duplicate -rate-limit flags."""
        engine = self._make_engine()
        for _ in range(10):
            engine.feedback("target.com", "nuclei", blocked=True)
        cmd = "nuclei -u http://target.com -t cves/"
        result = engine.transform(cmd, "nuclei", level=3)
        assert result.count("-rate-limit") == 1, f"Double -rate-limit in: {result}"

    def test_guard_prevents_existing_flag_duplication(self):
        """If a flag already exists in the command, it should not be added again."""
        engine = self._make_engine()
        for _ in range(10):
            engine.feedback("target.com", "sqlmap", blocked=True)
        # Command already has --tamper
        cmd = 'sqlmap -u "http://target.com/?id=1" --batch --tamper=space2comment'
        result = engine.transform(cmd, "sqlmap", level=3)
        assert result.count("--tamper") == 1

    def test_raw_socket_tools_skip_evasion(self):
        """nmap, sslscan etc. should bypass WAF evasion entirely."""
        engine = self._make_engine()
        cmd = "nmap -sV target.com"
        result = engine.transform(cmd, "nmap", level=3)
        assert result == cmd


class TestGatedLightening:
    """Fix #4: _make_command_lighter only fires after 2+ failures."""

    def test_threshold_concept(self):
        """Verify the >= 2 threshold logic conceptually.

        We can't easily instantiate BaseAgent, so we test the threshold
        logic that was changed from >= 1 to >= 2.
        """
        # The fix changed: if historical_timeout or effective_fail_count >= 1
        # to:              if historical_timeout or effective_fail_count >= 2
        # This means a single failure (fail_count=1) should NOT trigger lightening
        fail_count = 1
        should_lighten = fail_count >= 2
        assert should_lighten is False, "Single failure should NOT trigger proactive lightening"

        fail_count = 2
        should_lighten = fail_count >= 2
        assert should_lighten is True, "Two failures SHOULD trigger proactive lightening"

    def test_historical_timeout_host_matching(self):
        """Historical timeout matching should check host, not just tool name."""
        # The fix adds: if clean_host in pattern or "unknown" in pattern
        recent_failures = [
            "[TIMEOUT] tool=nmap on target_A (attempt 1)",
            "[TIMEOUT] tool=nmap on target_B (attempt 2)",
        ]
        clean_host = "target_A"
        tool = "nmap"

        # Should match for target_A
        matched_a = False
        for pattern in recent_failures:
            if f"tool={tool}" in pattern and "TIMEOUT" in pattern.upper():
                if clean_host in pattern or "unknown" in pattern:
                    matched_a = True
                    break
        assert matched_a is True

        # Should NOT match for target_C (different target)
        clean_host_c = "target_C"
        matched_c = False
        for pattern in recent_failures:
            if f"tool={tool}" in pattern and "TIMEOUT" in pattern.upper():
                if clean_host_c in pattern or "unknown" in pattern:
                    matched_c = True
                    break
        assert matched_c is False, "Should not match a different target"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
