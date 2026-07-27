"""
WS2 — Target Comprehension Layer.

After recon collects a pile of facts, this module synthesizes a *thesis*: a
TargetModel that tells exploitation WHAT the target is, WHERE its value is, and
which vuln classes are plausible vs. impossible. It is the strategic spine that
stops the engine from throwing apex SQLi / server-side forms at a static React
SPA for three hours.

Design (honors `fully-ai-driven-no-hardcoding`):
  - We do NOT hardcode "if SPA then skip SQLi". We gather real EVIDENCE (response
    headers, server banner, JS bundle contents, discovered endpoints, tech-stack
    fingerprints, open ports) and ask the AI to REASON about the target type and
    the strategy. The AI's own knowledge decides what's plausible.
  - JS-bundle ingestion (W2.2): the profiler extracts script URLs from the
    homepage HTML and, when a fetcher is provided, pulls the bundles and mines
    them for API base URLs / route tables / embedded endpoints — the real attack
    surface of a SPA lives in its JS, not its HTML.
  - Defensive: if the AI is unavailable or returns garbage, it falls back to a
    minimal evidence-only model (never crashes recon).
"""

import re
from typing import Callable, Optional

from core.result_contracts import TargetModel
from core.robust_parser import extract_json_object
from utils.logger import get_logger

log = get_logger("target_profiler")


# Script/asset URL patterns in HTML (SPA bundles, chunk files, etc.)
_SCRIPT_SRC_RE = re.compile(
    r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
_MODULE_SRC_RE = re.compile(
    r'<link[^>]+href=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)

# API-route-looking strings inside JS bundles: "/api/...", "/v1/...", fetch/axios
# base URLs, GraphQL endpoints. Intentionally broad — the AI filters noise.
_API_ROUTE_RE = re.compile(
    r'["\'`](/(?:api|v\d|graphql|rest|rpc|internal|admin|auth|oauth|user|users|'
    r'account|billing|payment|order|orders|reseller|dashboard|dash|control)'
    r'[a-zA-Z0-9_\-/.{}:]*)["\'`]')
_ABS_API_URL_RE = re.compile(
    r'["\'`](https?://[a-zA-Z0-9.\-]+/(?:api|v\d|graphql)[a-zA-Z0-9_\-/.{}:]*)["\'`]')


class TargetProfiler:
    """Synthesizes a TargetModel from recon evidence."""

    def __init__(self, ai_backend=None, fetch_fn: Optional[Callable[[str], str]] = None):
        """
        Args:
            ai_backend: AIBackend for the reasoning synthesis step.
            fetch_fn: optional callable(url) -> body text, used to pull JS
                bundles for route mining. If None, the profiler works only on
                evidence already present in the recon bundle.
        """
        self.ai = ai_backend
        self._fetch = fetch_fn

    # ── public API ──────────────────────────────────────────────────────────

    def build(self, target: str, recon_bundle: dict,
              findings: list | None = None) -> TargetModel:
        """Produce a TargetModel for `target` from the recon bundle + findings."""
        recon_bundle = recon_bundle or {}
        findings = findings or []

        evidence = self._gather_evidence(target, recon_bundle, findings)

        # If recon left us thin web evidence (it timed out, got rate-limited,
        # etc.), fetch the target's own homepage so we can still classify ANY
        # reachable web target — never fall back to "unknown" just because recon
        # was incomplete. This is evidence-gathering, not hardcoding.
        self._ensure_web_evidence(target, evidence)

        # JS-bundle ingestion (W2.2): mine API routes from script bundles.
        _home_html = evidence.get("_full_homepage") or recon_bundle.get("homepage_html", "")
        api_routes = self._extract_api_routes(_home_html, evidence)
        if api_routes:
            evidence["api_routes"] = api_routes

        model = self._synthesize(target, evidence)
        # Always carry the mined routes even if the AI step dropped them.
        merged = sorted(set(model.api_routes) | set(api_routes))
        model.api_routes = merged[:60]
        if not model.attack_surface:
            model.attack_surface = evidence.get("endpoints", [])[:40]
        return model

    def _ensure_web_evidence(self, target: str, evidence: dict) -> None:
        """Guarantee the AI has the target's own web evidence to classify from.

        Recon can be incomplete (timeout, rate-limit, exhausted budget), leaving
        the homepage/headers thin — and then the AI fixates on a noisy port scan
        and returns 'unknown'. If a fetcher is available and the homepage we have
        is thin, pull it directly. Works for ANY website; no hardcoded logic.
        """
        if not self._fetch:
            return
        if len((evidence.get("homepage_excerpt") or "")) >= 400:
            return  # already have enough to classify
        url = target if str(target).startswith("http") else f"https://{target}"
        try:
            body = self._fetch(url) or ""
        except Exception as e:
            log.debug(f"homepage self-fetch failed for {url}: {e}")
            body = ""
        if body and len(body) > len(evidence.get("homepage_excerpt", "") or ""):
            evidence["homepage_excerpt"] = body[:1500]
            evidence["_full_homepage"] = body
            log.info(f"[TARGET MODEL] Self-fetched homepage for {url} "
                     f"({len(body)} bytes) — recon evidence was thin.")

    # ── evidence gathering ──────────────────────────────────────────────────

    def _gather_evidence(self, target: str, bundle: dict, findings: list) -> dict:
        """Collect the concrete signals the AI will reason over."""
        tech_stack = []
        endpoints = []
        forms = []
        emails = []
        headers_blob = []
        for f in findings:
            try:
                ft = (f.get("type", "") or "").lower()
                detail = f.get("detail", "") or ""
            except AttributeError:
                continue
            if "tech" in ft or "fingerprint" in ft or "web_fingerprint" in ft:
                tech_stack.append(detail[:200])
            elif "endpoint" in ft or "directory" in ft or "path" in ft or ft == "discovered_endpoint":
                endpoints.append(detail[:200])
            elif "form" in ft or "parameter" in ft or "input" in ft:
                forms.append(detail[:200])
            elif "email" in ft:
                emails.append(detail[:120])
            elif "header" in ft:
                headers_blob.append(detail[:200])

        services = bundle.get("services", {}) or {}
        open_ports = bundle.get("open_ports", []) or []
        subdomains = self._collect_subdomains(bundle)

        return {
            "target": target,
            "open_ports": open_ports[:40],
            "services": {str(k): str(v)[:80] for k, v in list(services.items())[:20]},
            "tech_stack": tech_stack[:25],
            "endpoints": _dedup(endpoints)[:60],
            "forms": _dedup(forms)[:25],
            "emails": _dedup(emails)[:10],
            "headers": _dedup(headers_blob)[:25],
            "is_cdn": bool(bundle.get("is_cdn", False)),
            "waf_present": bool(bundle.get("waf_present", False)),
            "waf_type": bundle.get("waf_type", "") or "",
            "subdomains": subdomains[:40],
            "homepage_excerpt": (bundle.get("homepage_html", "") or "")[:1500],
        }

    @staticmethod
    def _collect_subdomains(bundle: dict) -> list:
        subs = []
        for key in ("subdomains_high", "subdomains_medium"):
            for s in bundle.get(key, []) or []:
                if isinstance(s, str):
                    subs.append(s)
        for s in bundle.get("subdomains", []) or []:
            if isinstance(s, dict):
                host = s.get("host") or s.get("subdomain") or s.get("name")
                if host:
                    subs.append(host)
            elif isinstance(s, str):
                subs.append(s)
        return _dedup(subs)

    # ── JS-bundle ingestion (W2.2) ──────────────────────────────────────────

    def _extract_api_routes(self, homepage_html: str, evidence: dict) -> list:
        """Mine API routes from the homepage HTML and (if a fetcher is set) JS bundles."""
        routes: set = set()

        # 1. Routes already visible in the HTML / collected endpoints.
        for blob in [homepage_html or ""] + evidence.get("endpoints", []):
            for m in _API_ROUTE_RE.finditer(blob):
                routes.add(m.group(1))
            for m in _ABS_API_URL_RE.finditer(blob):
                routes.add(m.group(1))

        # 2. Pull JS bundles and mine them (the real SPA surface).
        if self._fetch and homepage_html:
            script_urls = self._script_urls(homepage_html, evidence.get("target", ""))
            for url in script_urls[:6]:  # bound network work
                try:
                    body = self._fetch(url) or ""
                except Exception as e:
                    log.debug(f"JS bundle fetch failed for {url}: {e}")
                    continue
                for m in _API_ROUTE_RE.finditer(body):
                    routes.add(m.group(1))
                for m in _ABS_API_URL_RE.finditer(body):
                    routes.add(m.group(1))

        # Drop obvious static-asset false positives.
        cleaned = [
            r for r in routes
            if not r.lower().endswith(
                (".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".ico", ".map"))
        ]
        return sorted(cleaned)[:60]

    @staticmethod
    def _script_urls(homepage_html: str, target: str) -> list:
        raw = _SCRIPT_SRC_RE.findall(homepage_html or "") + \
            _MODULE_SRC_RE.findall(homepage_html or "")
        base = target.rstrip("/")
        if base and not base.startswith("http"):
            base = "https://" + base
        out = []
        for u in raw:
            if u.startswith("http"):
                out.append(u)
            elif u.startswith("//"):
                out.append("https:" + u)
            elif u.startswith("/"):
                out.append(base + u)
            else:
                out.append(base + "/" + u)
        return _dedup(out)

    # ── AI synthesis ────────────────────────────────────────────────────────

    def _synthesize(self, target: str, evidence: dict) -> TargetModel:
        """Ask the AI to reason a TargetModel from the evidence. Falls back safely."""
        if not self.ai:
            return self._fallback_model(target, evidence)

        system = (
            "You are a senior red-team operator building a TARGET MODEL before "
            "attacking. Reason from the EVIDENCE only. Your job is to decide what "
            "the target actually is, where its value lives, and which vulnerability "
            "classes are PLAUSIBLE vs. IMPOSSIBLE on this kind of target — so the "
            "team does not waste hours attacking surfaces that cannot exist. "
            "Be concrete and honest: a static SPA served from a CDN has no "
            "server-side SQL/forms at its apex; its real surface is the backend "
            "API the JS talks to.\n"
            "CLASSIFY PRIMARILY FROM THE WEB EVIDENCE: the HTTP response headers, "
            "server banner, homepage HTML/scripts, tech-stack signals and JS API "
            "routes are what determine the target type. A reachable HTTPS server "
            "with a homepage IS classifiable — do NOT return 'unknown' just "
            "because other evidence is thin.\n"
            "TREAT THE PORT SCAN AS LOW-TRUST: a port scan that lists many ports "
            "or services that don't match the web stack is almost always a SCAN "
            "ARTIFACT (proxy/Tor connect-scan, tarpit, CDN) — NOTE it as an "
            "anomaly but do NOT conclude 'honeypot' and do NOT let it override "
            "the web evidence. For a CDN-fronted web app, expect only 80/443.\n"
            "Return ONLY a JSON object."
        )
        import json as _json
        user = f"""### TARGET
{target}

### EVIDENCE
Open ports: {evidence.get('open_ports')}
Services: {_json.dumps(evidence.get('services', {}))[:600]}
Tech-stack signals: {_json.dumps(evidence.get('tech_stack', []))[:900]}
Response headers: {_json.dumps(evidence.get('headers', []))[:600]}
CDN in front: {evidence.get('is_cdn')}
WAF: {evidence.get('waf_type') or ('present' if evidence.get('waf_present') else 'none')}
Discovered endpoints: {_json.dumps(evidence.get('endpoints', []))[:900]}
Forms/params: {_json.dumps(evidence.get('forms', []))[:500]}
API routes mined from JS bundle: {_json.dumps(evidence.get('api_routes', []))[:900]}
Subdomains: {_json.dumps(evidence.get('subdomains', []))[:700]}
Homepage excerpt: {evidence.get('homepage_excerpt', '')[:800]}

### TASK
Synthesize the target model. Return ONLY this JSON object:
{{
  "target_type": "spa | api | cms | monolith | static | gateway | unknown",
  "stack": {{"framework": "", "server": "", "cdn": "", "language": "", "auth": ""}},
  "attack_surface": ["concrete endpoints/params/forms worth attacking"],
  "api_routes": ["backend API routes the app actually calls"],
  "value_map": ["where the value is: admin, billing, reseller API, auth, etc."],
  "plausible_vuln_classes": ["ranked vuln classes that COULD exist here"],
  "implausible_vuln_classes": ["classes that are impossible on this target type — do NOT attempt"],
  "recommended_strategy": "2-4 sentences: the single best line of attack and what to ignore",
  "ranked_subdomains": ["subdomains ordered by likely value, highest first"],
  "confidence": 0.0,
  "reasoning": "1-3 sentences justifying target_type and the implausible list"
}}"""

        try:
            resp = self.ai.query(system, user)
            data = extract_json_object(resp)
            if not data or not isinstance(data, dict):
                log.warning("[TARGET MODEL] AI returned no usable JSON — using fallback.")
                return self._fallback_model(target, evidence)
            data["target"] = target
            model = TargetModel.from_dict(data)
            log.info(
                f"[TARGET MODEL] {target} → type={model.target_type} "
                f"conf={model.confidence:.2f} | plausible={model.plausible_vuln_classes[:4]} "
                f"| implausible={model.implausible_vuln_classes[:4]}")
            return model
        except Exception as e:
            log.warning(f"[TARGET MODEL] synthesis failed ({e}); using fallback.")
            return self._fallback_model(target, evidence)

    @staticmethod
    def _fallback_model(target: str, evidence: dict) -> TargetModel:
        """Evidence-only model when the AI can't run — never block recon."""
        return TargetModel(
            target=target,
            target_type="unknown",
            stack={},
            attack_surface=evidence.get("endpoints", [])[:40],
            api_routes=evidence.get("api_routes", [])[:40],
            value_map=[],
            plausible_vuln_classes=[],
            implausible_vuln_classes=[],
            recommended_strategy=(
                "AI synthesis unavailable — proceed with standard methodology "
                "but treat all findings as leads until proven with a differential."),
            ranked_subdomains=evidence.get("subdomains", [])[:40],
            confidence=0.0,
            reasoning="fallback: no AI synthesis",
        )

    # ── prompt-injection helper (W2.3) ──────────────────────────────────────

    @staticmethod
    def format_for_prompt(model: TargetModel) -> str:
        """Render the TargetModel as a strategic prompt section for downstream agents."""
        if not model or model.target_type == "unknown" and not model.recommended_strategy:
            return ""
        lines = ["### 🎯 TARGET MODEL (synthesized strategic thesis — follow this)"]
        lines.append(f"Target type: {model.target_type}  (confidence {model.confidence:.0%})")
        if model.stack:
            stack_str = ", ".join(f"{k}={v}" for k, v in model.stack.items() if v)
            if stack_str:
                lines.append(f"Stack: {stack_str}")
        if model.value_map:
            lines.append(f"Where the value is: {', '.join(model.value_map[:6])}")
        if model.api_routes:
            lines.append(f"Backend API routes (real surface): {', '.join(model.api_routes[:12])}")
        if model.plausible_vuln_classes:
            lines.append(f"PLAUSIBLE vuln classes (focus here): {', '.join(model.plausible_vuln_classes[:8])}")
        if model.implausible_vuln_classes:
            lines.append(
                f"IMPOSSIBLE on this target — DO NOT ATTEMPT: {', '.join(model.implausible_vuln_classes[:8])}")
        if model.recommended_strategy:
            lines.append(f"Strategy: {model.recommended_strategy}")
        return "\n".join(lines) + "\n"


def _dedup(items: list) -> list:
    seen = set()
    out = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out
