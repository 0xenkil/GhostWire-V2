"""Phase 5 — P5-5 arsenal conformance: credential_finder Evidence-or-lead (CREDFINDER-NO-VALUE).

Old behavior: reported a "credential" whenever a bypass-header NAME appeared in any
finding (no value captured) — useless, and it made the orchestrator's
create_bypass_request raise. And test_credential_validity called a lone 200 a
bypass. Now: only a header with a captured VALUE is harvested, and a bypass is
confirmed only by a control-vs-test status differential through is_proven.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.waf_bypass.credential_finder import CredentialFinder  # noqa: E402
from intelligence.waf_bypass.technique import WafTechnique  # noqa: E402


class _Store:
    def __init__(self, findings):
        self._f = findings

    def get_all_findings(self, engagement_id):
        return self._f


class _SSH:
    """Executor returning scripted HTTP codes per command in order."""
    def __init__(self, codes):
        self._codes = list(codes)

    def execute(self, cmd, timeout=None):
        return (0, str(self._codes.pop(0)), "")


def test_conforms_to_waf_technique_protocol():
    assert isinstance(CredentialFinder(), WafTechnique)
    assert CredentialFinder().name == "credential_finder"


def test_name_only_mention_is_not_harvested():
    # A finding that merely names the header (no value) yields NO credential.
    store = _Store([{"detail": "response echoed an X-WAF-Key header somewhere"}])
    cf = CredentialFinder(state_store=store)
    out = cf.find_bypass_credentials("eng1", "t")
    assert out["credentials_found"] == []


def test_header_with_value_is_harvested_with_its_value():
    store = _Store([{"detail": "leaked config: X-WAF-Key: s3cr3t-key-9f included"}])
    cf = CredentialFinder(state_store=store)
    out = cf.find_bypass_credentials("eng1", "t")
    assert len(out["credentials_found"]) == 1
    c = out["credentials_found"][0]
    assert c["name"] == "X-WAF-Key" and c["value"] == "s3cr3t-key-9f"
    assert out["suggested_headers"]["X-WAF-Key"] == "s3cr3t-key-9f"


def test_validity_requires_control_blocked_test_allowed():
    cred = {"type": "header_key", "name": "X-WAF-Key", "value": "s3cr3t"}
    # control 403 (blocked), test 200 (allowed) → real differential → confirmed.
    cf_ok = CredentialFinder(remote_executor=_SSH([403, 200]))
    assert cf_ok.test_credential_validity(cred, "https://t/") is True

    # control 200 (already allowed w/o header) → no differential → NOT a bypass.
    cf_no = CredentialFinder(remote_executor=_SSH([200, 200]))
    assert cf_no.test_credential_validity(cred, "https://t/") is False


def test_run_confirms_via_evidence_when_credential_valued_and_differential():
    store = _Store([{"detail": "X-WAF-Key=abc123"}])
    cf = CredentialFinder(state_store=store, remote_executor=_SSH([403, 200]))
    from intelligence.waf_bypass.technique import confirmed_bypass
    ev = cf.run("https://t/", {"engagement_id": "eng1"})
    assert ev is not None and confirmed_bypass(ev) is True


def test_run_none_when_no_valued_credential():
    store = _Store([{"detail": "no headers of interest here"}])
    cf = CredentialFinder(state_store=store, remote_executor=_SSH([403, 200]))
    assert cf.run("https://t/", {"engagement_id": "eng1"}) is None


def test_no_executor_is_not_a_bypass():
    cred = {"type": "header_key", "name": "X-WAF-Key", "value": "s3cr3t"}
    assert CredentialFinder().test_credential_validity(cred, "https://t/") is False
