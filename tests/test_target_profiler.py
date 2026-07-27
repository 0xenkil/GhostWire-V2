"""WS2 — Target Comprehension Layer tests."""

import json
import pytest

from intelligence.target_profiler import TargetProfiler
from core.result_contracts import TargetModel


class TestRobustEvidence:
    """The profiler must classify ANY reachable web target even when recon is
    thin, and must not be fooled by a noisy port scan (rules: AI-driven + any site)."""

    def test_self_fetches_homepage_when_recon_thin(self):
        calls = {"n": 0}

        def fetch(url):
            calls["n"] += 1
            return ('<html><head><script src="/a.js"></script></head>'
                    '<body>fetch("/api/v1/users")</body></html>')

        p = TargetProfiler(ai_backend=None, fetch_fn=fetch)
        # bundle has NO homepage + only weird ports (the failing scenario)
        m = p.build("x.lk", {"open_ports": [80, 443, 22, 3306, 9000], "is_cdn": True}, [])
        assert calls["n"] > 0                  # fetched its own evidence
        assert "/api/v1/users" in m.api_routes  # mined from the self-fetched page

    def test_no_fetch_when_evidence_sufficient(self):
        calls = {"n": 0}

        def fetch(url):
            calls["n"] += 1
            return "x"

        p = TargetProfiler(ai_backend=None, fetch_fn=fetch)
        big_home = "<html>" + ("a" * 600) + "</html>"
        p.build("x.lk", {"homepage_html": big_home}, [])
        assert calls["n"] == 0  # already had enough — no redundant fetch

    def test_prompt_guides_web_first_and_port_artifact(self):
        captured = {}

        class _AI:
            def query(self, system, user):
                captured["system"] = system
                return json.dumps({"target_type": "spa", "confidence": 0.8})

        p = TargetProfiler(ai_backend=_AI())
        p.build("x.lk", {"homepage_html": "<html>" + "a" * 600 + "</html>"}, [])
        sysp = captured["system"].lower()
        # AI-driven guidance present: classify from web, distrust port scan
        assert "web evidence" in sysp
        assert "artifact" in sysp
        assert "do not return 'unknown'" in sysp or "do not return \"unknown\"" in sysp or "not return 'unknown'" in sysp


class _MockSpaAI:
    """Returns a realistic SPA target model regardless of prompt."""

    def query(self, system, user):
        return json.dumps({
            "target_type": "spa",
            "stack": {"framework": "React", "server": "Vercel",
                      "cdn": "Cloudflare", "language": "JS", "auth": "JWT"},
            "attack_surface": ["/api/v1/resellers", "/api/v1/billing"],
            "api_routes": ["/api/v1/resellers", "/api/v1/billing"],
            "value_map": ["reseller API", "billing", "auth"],
            "plausible_vuln_classes": ["IDOR", "BOLA", "broken auth"],
            "implausible_vuln_classes": ["apex SQLi", "server-side forms", "LFI"],
            "recommended_strategy": "Ignore the static apex; pivot to the backend API.",
            "ranked_subdomains": ["resellerapi.x.lk", "control.x.lk", "cdn.x.lk"],
            "confidence": 0.85,
            "reasoning": "React SPA on Vercel; no server-side apex.",
        })


class TestJsBundleMining:
    """W2.2 — API routes mined from HTML + JS bundles, no AI needed."""

    def test_routes_from_html_and_bundle(self):
        homepage = (
            '<script src="/assets/index-abc.js"></script>'
            'fetch("/api/v1/resellers")'
            'axios.get("https://api.x.lk/v2/billing/invoices")'
        )

        def fake_fetch(url):
            return 'const b="/api/v1/orders"; r("/api/v1/account"); "/graphql"'

        p = TargetProfiler(ai_backend=None, fetch_fn=fake_fetch)
        m = p.build("x.lk", {"homepage_html": homepage}, [])
        assert "/api/v1/resellers" in m.api_routes
        assert "/api/v1/orders" in m.api_routes      # from fetched bundle
        assert "/graphql" in m.api_routes
        assert "https://api.x.lk/v2/billing/invoices" in m.api_routes

    def test_static_assets_excluded(self):
        homepage = '"/api/v1/users" "/assets/app.js" "/style.css"'
        p = TargetProfiler(ai_backend=None)
        m = p.build("x.lk", {"homepage_html": homepage}, [])
        assert "/api/v1/users" in m.api_routes
        assert not any(r.endswith((".js", ".css")) for r in m.api_routes)


class TestAiSynthesis:
    """W2.1 — the AI reasons a strategic model from evidence."""

    def test_spa_marks_sqli_impossible(self):
        bundle = {"homepage_html": '<script src="/x.js"></script>',
                  "is_cdn": True, "subdomains_high": ["resellerapi.x.lk"]}
        p = TargetProfiler(ai_backend=_MockSpaAI())
        m = p.build("x.lk", bundle, [])
        assert m.target_type == "spa"
        assert "apex SQLi" in m.implausible_vuln_classes
        assert "IDOR" in m.plausible_vuln_classes
        assert m.confidence == pytest.approx(0.85)

    def test_fallback_when_ai_returns_garbage(self):
        class BadAI:
            def query(self, system, user):
                return "not json at all"

        p = TargetProfiler(ai_backend=BadAI())
        m = p.build("x.lk", {"homepage_html": ""}, [])
        # Falls back without crashing
        assert isinstance(m, TargetModel)
        assert m.target_type == "unknown"

    def test_no_ai_uses_fallback(self):
        p = TargetProfiler(ai_backend=None)
        m = p.build("x.lk", {}, [])
        assert m.target_type == "unknown"
        assert m.confidence == 0.0


class TestPromptFormatting:
    """W2.3 — the model renders as a strategy section for downstream prompts."""

    def test_format_includes_impossible_warning(self):
        p = TargetProfiler(ai_backend=_MockSpaAI())
        m = p.build("x.lk", {"homepage_html": ""}, [])
        section = TargetProfiler.format_for_prompt(m)
        assert "DO NOT ATTEMPT" in section
        assert "apex SQLi" in section
        assert "spa" in section.lower()

    def test_empty_model_renders_empty(self):
        section = TargetProfiler.format_for_prompt(TargetModel())
        assert section == ""


class TestTargetModelContract:
    """Round-trip serialization of the contract dataclass."""

    def test_to_from_dict_roundtrip(self):
        m = TargetModel(
            target="x.lk", target_type="api",
            plausible_vuln_classes=["IDOR"],
            implausible_vuln_classes=["SQLi"],
            confidence=0.7)
        d = m.to_dict()
        m2 = TargetModel.from_dict(d)
        assert m2.target == "x.lk"
        assert m2.target_type == "api"
        assert m2.plausible_vuln_classes == ["IDOR"]
        assert m2.confidence == pytest.approx(0.7)

    def test_from_dict_handles_none(self):
        m = TargetModel.from_dict(None)
        assert m.target_type == "unknown"
