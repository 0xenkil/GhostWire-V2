"""Phase 5 — P5-11 (ROUTER-CMD-DEMOTED) + P5-13 (CVE-1): TechStackRouter emits
leads-only via a pluggable CVESource Protocol; the dead command table is gone."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import intelligence.evidence_router as er  # noqa: E402
from intelligence.evidence_router import TechStackRouter, CVESource  # noqa: E402


def _fake_source(tech_name, version):
    if tech_name == "wordpress":
        return [{"cves": ["CVE-2021-1234"], "description": "WP thing", "severity": "high"}]
    return []


def test_leads_have_no_runnable_command():
    leads = TechStackRouter.route_tech_stack(["WordPress 5.8"], cve_source=_fake_source)
    assert leads and all("command" not in l for l in leads)
    assert all(l["status"] == "lead" for l in leads)


def test_lead_shape_matches_caller_expectations():
    # _gather_cve_seeds reads tech/version/description/priority — all present.
    lead = TechStackRouter.route_tech_stack(["WordPress 5.8"], cve_source=_fake_source)[0]
    assert lead["tech"] == "wordpress"
    assert lead["version"] == "5.8"
    assert lead["description"] == "WP thing"
    assert lead["priority"] == "high"
    assert lead["cves"] == ["CVE-2021-1234"]


def test_cve_source_is_pluggable_protocol():
    assert isinstance(_fake_source, CVESource)   # any (tech, version)->list callable
    # A new feed changes results with zero TechStackRouter edits.
    other = lambda t, v: [{"cves": ["CVE-9999-0001"], "description": "x", "severity": "low"}]
    leads = TechStackRouter.route_tech_stack(["Apache 2.4"], cve_source=other)
    assert leads[0]["cves"] == ["CVE-9999-0001"] and leads[0]["priority"] == "low"


def test_command_table_is_deleted():
    assert not hasattr(TechStackRouter, "_exploit_type_to_command")
    # The actual dead command strings are gone (docstring may still name them).
    src = __import__("inspect").getsource(TechStackRouter)
    assert "curl -sk --max-time" not in src
    assert "nuclei -u" not in src
    assert '"command"' not in src


def test_prefix_normalisation_and_dedup():
    src = lambda t, v: [{"cves": ["CVE-1"], "description": "d", "severity": "medium"}]
    leads = TechStackRouter.route_tech_stack(
        ["CMS: WordPress 5.8", "WordPress 5.8"], cve_source=src)
    assert len(leads) == 1  # same (tech,label) deduped


def test_default_source_is_used_when_none_given():
    # Must not raise; returns a list (contents depend on the offline table).
    out = TechStackRouter.route_tech_stack(["nonexistent_tech 1.0"])
    assert isinstance(out, list)
