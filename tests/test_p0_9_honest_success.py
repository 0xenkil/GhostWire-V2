"""P0-9 — Honest success signal.

A tool that exits SUCCESS but produced none of the KIND of result its
capability implies must read as NO_FINDINGS, not SUCCESS — keyed off the PARSED
output and the static capability table, NOT a per-tool banner heuristic. This is
the link that stops a banner-only nmap (exit 0, zero parsed ports) from
masquerading as a win and feeding the objective/self-awareness layers as
"progress".
"""

import pytest

from core.result_contracts import ToolResult, ResultStatus
from core.capability_registry import tool_primary_capability


def _res(tool, parsed, stdout="", status=ResultStatus.SUCCESS):
    r = ToolResult(tool=tool, command="x", stdout=stdout, stderr="",
                   exit_code=0, duration_seconds=1.0, status=status)
    r.parsed = parsed
    return r


def _downgraded_status(r):
    """Replicate the tool_manager P0-9 gate: plain SUCCESS + no produced result
    → NO_FINDINGS; everything else is left as-is."""
    status_val = getattr(r.status, "value", r.status)
    if status_val == ResultStatus.SUCCESS.value:
        if not r.produced_result(tool_primary_capability(r.tool)):
            return ResultStatus.NO_FINDINGS
    return r.status


class TestProducedResult:
    def test_banner_only_nmap_is_not_a_result(self):
        # exit 0, non-empty banner, but ZERO parsed open ports.
        r = _res("nmap",
                 {"open_ports": [], "services": {}, "os_guess": "", "total_open": 0},
                 stdout="Starting Nmap 7.94\nNmap done: 1 IP address (0 hosts up)")
        assert tool_primary_capability("nmap") == "port_scan"
        assert r.produced_result("port_scan") is False
        assert _downgraded_status(r) == ResultStatus.NO_FINDINGS

    def test_nmap_with_open_ports_counts(self):
        r = _res("nmap", {"open_ports": [80, 443], "services": {"80": {}},
                          "os_guess": "", "total_open": 2})
        assert r.produced_result("port_scan") is True
        assert _downgraded_status(r) == ResultStatus.SUCCESS

    def test_curl_response_body_is_a_result(self):
        # http_probe: getting a RESPONSE is the result, not a differential.
        r = _res("curl",
                 {"raw_lines": ["HTTP/1.1 200 OK"], "discovered_paths": [],
                  "discovered_urls": [], "parameters": [], "line_count": 1,
                  "has_errors": False},
                 stdout="HTTP/1.1 200 OK\nServer: nginx")
        assert tool_primary_capability("curl") == "http_probe"
        assert r.produced_result("http_probe") is True
        assert _downgraded_status(r) == ResultStatus.SUCCESS

    def test_gobuster_empty_vs_hit(self):
        empty = _res("gobuster", {"discovered_paths": [], "count": 0})
        assert empty.produced_result(tool_primary_capability("gobuster")) is False
        assert _downgraded_status(empty) == ResultStatus.NO_FINDINGS
        hit = _res("gobuster",
                   {"discovered_paths": [{"path": "/admin", "status": 200}], "count": 1})
        assert hit.produced_result(tool_primary_capability("gobuster")) is True

    def test_whatweb_tags_vs_empty(self):
        tagged = _res("whatweb", {"technologies": ["HTTPServer[nginx]"],
                                  "http_server": "nginx", "title": None,
                                  "ip": None, "targets": [], "count": 1})
        assert tagged.produced_result(tool_primary_capability("whatweb")) is True
        empty = _res("whatweb", {"technologies": [], "http_server": None,
                                 "title": None, "ip": None, "targets": [], "count": 0})
        assert empty.produced_result(tool_primary_capability("whatweb")) is False

    def test_unknown_capability_falls_back_to_parsed_or_body(self):
        # A tool with no capability keyword and no parsed collections still
        # counts if it emitted a real body — unknown tools get the benefit of
        # the doubt (no per-tool table, no false NO_FINDINGS).
        r = _res("some_new_tool", {"weird_scalar": "value"}, stdout="lots of real output here")
        assert tool_primary_capability("some_new_tool") == ""
        assert r.produced_result("") is True


class TestDowngradeGuardExemptions:
    def test_partial_success_is_exempt(self):
        # whatweb-behind-WAF carve-out sets a raw "partial_success" string; it
        # must NOT be downgraded even with an empty parse.
        r = _res("whatweb", {"technologies": [], "count": 0})
        r.status = "partial_success"
        assert _downgraded_status(r) == "partial_success"

    def test_fallback_success_is_exempt(self):
        r = _res("nmap", {"open_ports": [], "services": {}}, status=ResultStatus.FALLBACK_SUCCESS)
        assert _downgraded_status(r) == ResultStatus.FALLBACK_SUCCESS

    def test_failure_is_left_alone(self):
        r = _res("nmap", {"open_ports": []}, status=ResultStatus.FAILURE)
        assert _downgraded_status(r) == ResultStatus.FAILURE
