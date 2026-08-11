"""Lead -> self-proof bridge (exploitation_agent).

A tool-confirmed injection LEAD (e.g. sqlmap flags a param injectable, recorded
as an unproven `exploit_lead`) is turned into the engine's OWN deterministic
TRUE-vs-FALSE differential and stamped via the non-forgeable ledger. Boolean SQLi
needs `AND 1=1` vs `AND 1=2` (not test-vs-homepage) — that was why an
already-tool-confirmed SQLi kept coming back "unproven".

The proof gate itself is covered by the proof-spine tests; these verify the
bridge WIRING + that it only stamps on a REAL measured delta (never fabricates).
"""
import logging

from agents.exploitation_agent import ExploitationAgent


def _agent(findings, tool_runs=None):
    a = ExploitationAgent.__new__(ExploitationAgent)
    a.log = logging.getLogger("test")
    a._findings = []
    a._exploitation_state = {"confirmed_vulns": []}
    _tr = tool_runs or []

    class _Store:
        def get_all_findings(self, eid=None):
            return findings

        def get_tool_runs(self, eid=None):
            return _tr

        def get(self, k):
            return ""

    class _Sess:
        engagement_id = "e1"
        mode = "pentest"
        target = "127.0.0.1"

    a.store = _Store()
    a.session = _Sess()
    a._raw_http_get = lambda *x, **k: ""   # default: no network (override per test)
    return a


_SQLMAP_LEAD = {
    "type": "exploit_lead",
    "target": "http://127.0.0.1:8081",
    "source_tool": "sqlmap",
    "detail": ("Unverified lead (generic error/db keyword). Command: sqlmap -u "
               "http://127.0.0.1:8081/ --crawl=2\nOutput: GET parameter 'id' is "
               "vulnerable ... back-end DBMS SQLite"),
}

_PROBE = ('{"vuln_class":"sql_injection",'
          '"control_url":"http://127.0.0.1:8081/item?id=1%20AND%201=1",'
          '"test_url":"http://127.0.0.1:8081/item?id=1%20AND%201=2"}')


def _wire(a, control_body, test_body, probe=_PROBE):
    class _AI:
        def query(self, s, u):
            return probe
    a.ai = _AI()
    bodies = iter([control_body, test_body])
    a._raw_http_get = lambda u, timeout=10: next(bodies)   # control, then test
    cap = {}

    def _af(ft, tgt, detail, severity="info", source_tool=None, command=None,
            proof_method=None, proof_ctx=None, **kw):
        cap.update({"ft": ft, "detail": detail, "proof_method": proof_method,
                    "proof_ctx": proof_ctx})
    a.add_finding = _af
    return cap


def test_boolean_sqli_true_false_differential_proves():
    a = _agent([_SQLMAP_LEAD])
    cap = _wire(a, "ITEMS:\n1:apple\n2:banana\n3:cherry", "ITEMS:\n(none)")
    ok = a._prove_injection_lead_differential(
        _SQLMAP_LEAD["detail"], "http://127.0.0.1:8081", "127.0.0.1")
    assert ok is True
    assert cap["ft"] == "confirmed_vulnerability"
    assert cap["proof_method"] == "differential"
    # the ProofContext carries the two REAL differing responses (re-measurable)
    assert cap["proof_ctx"].control_response != cap["proof_ctx"].test_response


def test_identical_responses_never_proven():
    a = _agent([_SQLMAP_LEAD])
    cap = _wire(a, "ITEMS:\n1:apple", "ITEMS:\n1:apple")   # true==false → not injectable
    ok = a._prove_injection_lead_differential(
        _SQLMAP_LEAD["detail"], "http://127.0.0.1:8081", "127.0.0.1")
    assert ok is False
    assert cap.get("proof_method") is None   # add_finding NOT called with a proof


def test_off_target_probe_rejected():
    a = _agent([_SQLMAP_LEAD])
    cap = _wire(a, "x", "y",
                probe='{"vuln_class":"sql_injection",'
                      '"control_url":"http://evil.example/a",'
                      '"test_url":"http://evil.example/b"}')
    ok = a._prove_injection_lead_differential(
        _SQLMAP_LEAD["detail"], "http://127.0.0.1:8081", "127.0.0.1")
    assert ok is False
    assert cap.get("proof_method") is None


def test_prove_pending_leads_runs_per_in_scope_lead():
    a = _agent([_SQLMAP_LEAD])
    called = {"n": 0}
    a._prove_injection_lead_differential = lambda lt, bu, tg: (
        called.__setitem__("n", called["n"] + 1) or True)
    n = a._prove_pending_leads("http://127.0.0.1:8081", "127.0.0.1")
    assert called["n"] == 1 and n == 1


def test_noop_without_leads():
    a = _agent([{"type": "info", "detail": "recon", "target": "http://127.0.0.1:8081"}])
    a._prove_injection_lead_differential = lambda *x: (_ for _ in ()).throw(
        AssertionError("should not be called"))
    assert a._prove_pending_leads("http://127.0.0.1:8081", "127.0.0.1") == 0


def test_other_target_leads_excluded():
    other = dict(_SQLMAP_LEAD,
                 detail="lead ... Command: sqlmap -u http://evil.example/x",
                 target="http://evil.example")
    a = _agent([other])
    called = {"n": 0}
    a._prove_injection_lead_differential = lambda *x: (
        called.__setitem__("n", called["n"] + 1) or True)
    a._prove_pending_leads("http://127.0.0.1:8081", "127.0.0.1")
    assert called["n"] == 0


# ── surface probe (deterministic, tool-independent) ────────────────────────

def _wire_get(a, bodies, cap):
    """_raw_http_get returns successive bodies; add_finding captured into cap."""
    seq = iter(bodies)
    a._raw_http_get = lambda u, timeout=10: next(seq)

    def _af(ft, tgt, detail, severity="info", source_tool=None, command=None,
            proof_method=None, proof_ctx=None, **kw):
        cap.update({"ft": ft, "proof_method": proof_method, "proof_ctx": proof_ctx})
    a.add_finding = _af


def test_url_param_sqli_true_false_differential_proves():
    a = _agent([])
    cap = {}
    # control(AND 1=1)=rows, test(AND 1=2)=none, control-repeat=rows (stable)
    _wire_get(a, ["ITEMS:1:apple 2:banana 3:cherry", "ITEMS:(none)",
                  "ITEMS:1:apple 2:banana 3:cherry"], cap)
    ok = a._prove_url_param_sqli("http://127.0.0.1:8081/item?id=1", "127.0.0.1")
    assert ok is True and cap["proof_method"] == "differential"
    assert cap["proof_ctx"].control_response != cap["proof_ctx"].test_response


def test_url_param_stable_endpoint_not_proven():
    a = _agent([])
    cap = {}
    _wire_get(a, ["OK healthy", "OK healthy"], cap)   # true==false → no delta
    ok = a._prove_url_param_sqli("http://127.0.0.1:8081/safe?id=1", "127.0.0.1")
    assert ok is False and cap.get("proof_method") is None


def test_url_param_dynamic_endpoint_rejected():
    a = _agent([])
    cap = {}
    # true/false differ, BUT a control-repeat also differs → dynamic → skip
    _wire_get(a, ["nonce=aaa", "nonce=bbb", "nonce=ccc"], cap)
    ok = a._prove_url_param_sqli("http://127.0.0.1:8081/x?id=1", "127.0.0.1")
    assert ok is False and cap.get("proof_method") is None


def test_surface_probe_finds_and_probes_in_scope_param_urls():
    findings = [
        {"type": "web_endpoint", "detail": "discovered http://127.0.0.1:8081/item?id=1"},
        {"type": "web_endpoint", "detail": "external http://evil.example/x?q=1"},
        {"type": "info", "detail": "no params here http://127.0.0.1:8081/about"},
    ]
    a = _agent(findings)
    probed = []
    a._prove_url_param_sqli = lambda u, tg: probed.append(u) or True
    n = a._probe_injectable_surface("http://127.0.0.1:8081", "127.0.0.1")
    assert n == 1
    assert probed == ["http://127.0.0.1:8081/item?id=1"]   # only the in-scope param URL


def test_surface_probe_noop_without_param_urls():
    a = _agent([{"type": "info", "detail": "http://127.0.0.1:8081/no-params"}])
    a._prove_url_param_sqli = lambda *x: (_ for _ in ()).throw(
        AssertionError("should not probe"))
    assert a._probe_injectable_surface("http://127.0.0.1:8081", "127.0.0.1") == 0


def test_surface_probe_mines_relative_links_in_crawl_output():
    # the injectable endpoint is only in a crawler's TOOL OUTPUT as a RELATIVE
    # href (<a href="/item?id=1">) — the probe must resolve it against base_url.
    tool_runs = [{"tool": "curl", "command": "curl http://127.0.0.1:8081/",
                  "stdout": '<html><a href="/item?id=1">x</a> '
                            '<a href="/ping?host=127.0.0.1">y</a></html>'}]
    a = _agent([], tool_runs=tool_runs)
    probed = []
    a._prove_url_param_sqli = lambda u, tg: probed.append(u) or (
        "/item?id=1" in u)   # only count the sqli one as proven
    n = a._probe_injectable_surface("http://127.0.0.1:8081", "127.0.0.1")
    assert "http://127.0.0.1:8081/item?id=1" in probed
    assert "http://127.0.0.1:8081/ping?host=127.0.0.1" in probed
    assert n == 1


def test_resolve_working_base_picks_responding_url():
    # base_url mis-normalized to https (port dropped); scope has the real http:8081.
    a = _agent([])
    a.session.scope = ["http://127.0.0.1:8081"]
    a._raw_http_get = lambda u, timeout=10: (
        "<html>ok</html>" if u == "http://127.0.0.1:8081" else "")
    assert a._resolve_working_base("https://127.0.0.1") == "http://127.0.0.1:8081"


def test_resolve_working_base_falls_back_when_none_answer():
    a = _agent([])
    a._raw_http_get = lambda *x, **k: ""     # nothing answers
    assert a._resolve_working_base("http://127.0.0.1:8081") == "http://127.0.0.1:8081"


def test_surface_probe_dedups_same_param_point():
    # ?id=1 and ?id=2 are ONE injectable point → probed once.
    tool_runs = [{"tool": "gau", "command": "gau",
                  "stdout": "http://127.0.0.1:8081/item?id=1\n"
                            "http://127.0.0.1:8081/item?id=2\n"
                            "http://127.0.0.1:8081/item?id=999"}]
    a = _agent([], tool_runs=tool_runs)
    probed = []
    a._prove_url_param_sqli = lambda u, tg: probed.append(u) or False
    a._probe_injectable_surface("http://127.0.0.1:8081", "127.0.0.1")
    assert len(probed) == 1   # (/item, id) deduped to a single probe
