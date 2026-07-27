"""
WS6 / W6.6c — Web cache deception & poisoning probe (CDN edge cache).

novalink served `x-vercel-cache: HIT` — a CDN cache sits in front of the app.
Two classes of bug live there:

  • Cache DECEPTION — a sensitive *dynamic* page (e.g. /account) is made to look
    like a static asset by appending a fake extension (`/account/x.css`,
    `/account;.js`). If the CDN caches the dynamic response as a static file, an
    attacker can later fetch another logged-in user's cached private page.

  • Cache POISONING — an unkeyed input (e.g. `X-Forwarded-Host`) is reflected
    into a cacheable response, so an attacker can poison the cache served to
    everyone.

This module only DETECTS (non-destructive, within standing ROE): it observes
cache headers and reflection, and judges by an observable differential (ties to
WS4). It never serves a poisoned entry to real users. Degrades to a neutral
result if `requests` is unavailable.
"""

import re
import time
import uuid
from typing import Optional

from utils.logger import get_logger

log = get_logger("cache_deception")

_CACHE_HEADERS = ("cache-control", "x-cache", "cf-cache-status", "x-vercel-cache",
                  "age", "x-cache-hits", "x-served-by", "cdn-cache")
_STATIC_SUFFIXES = ["/{rand}.css", "/{rand}.js", "%2f{rand}.css", ";{rand}.css",
                    "/..%2f{rand}.css"]


def _requests():
    try:
        import requests
        return requests
    except Exception:
        return None


def _cache_signals(headers) -> dict:
    out = {}
    for k, v in headers.items():
        if k.lower() in _CACHE_HEADERS:
            out[k.lower()] = v
    return out


def _looks_cached(signals: dict) -> bool:
    """A response that the CDN cached (HIT, age>0, or public/cacheable)."""
    for k, v in signals.items():
        vl = str(v).lower()
        if "hit" in vl:
            return True
        if k == "age" and vl.isdigit() and int(vl) > 0:
            return True
        if k == "cache-control" and ("public" in vl or "max-age" in vl) and "no-store" not in vl and "private" not in vl:
            return True
    return False


class CacheDeceptionProbe:
    """Detects web-cache deception and unkeyed-input poisoning at the edge."""

    def __init__(self, timeout: int = 12, verify_tls: bool = False):
        self.timeout = timeout
        self.verify = verify_tls

    # ── cache deception ───────────────────────────────────────────────────────

    def probe_deception(self, base_url: str,
                        sensitive_path: str = "/") -> dict:
        """Test whether a dynamic page can be cached as a static asset.

        Returns {"vulnerable","evidence","signals","path"}.
        """
        req = _requests()
        result = {"vulnerable": False, "evidence": "", "signals": {}, "path": sensitive_path}
        if req is None:
            result["evidence"] = "requests unavailable"
            return result

        base = base_url.rstrip("/")
        sensitive_path = "/" + sensitive_path.lstrip("/")
        headers = {"User-Agent": "Mozilla/5.0 (compatible; GhostwireCacheProbe/1.0)"}

        # Control: the real dynamic page.
        try:
            ctrl = req.get(base + sensitive_path, headers=headers,
                           timeout=self.timeout, verify=self.verify)
        except Exception as e:
            result["evidence"] = f"control request failed: {e}"
            return result
        ctrl_body = (ctrl.text or "")[:4000]
        ctrl_dynamic = not _looks_cached(_cache_signals(ctrl.headers))

        for suffix_tpl in _STATIC_SUFFIXES:
            rand = uuid.uuid4().hex[:8]
            suffix = suffix_tpl.format(rand=rand)
            test_url = base + sensitive_path.rstrip("/") + suffix
            try:
                # First request (priming) then a second to see if it cached.
                req.get(test_url, headers=headers, timeout=self.timeout, verify=self.verify)
                time.sleep(0.4)
                r2 = req.get(test_url, headers=headers, timeout=self.timeout, verify=self.verify)
            except Exception:
                continue
            signals = _cache_signals(r2.headers)
            body2 = (r2.text or "")[:4000]
            # Deception = the static-suffixed URL returns the SAME dynamic page
            # content, but the response is now cacheable/cached.
            same_dynamic_content = (
                r2.status_code == 200 and len(body2) >= 40
                and self._similar(ctrl_body, body2) >= 0.85)
            if ctrl_dynamic and same_dynamic_content and _looks_cached(signals):
                result["vulnerable"] = True
                result["path"] = test_url
                result["signals"] = signals
                result["evidence"] = (
                    f"Dynamic page {sensitive_path} served (200, {len(body2)}B, "
                    f"{self._similar(ctrl_body, body2):.0%} identical) under static suffix "
                    f"'{suffix}' WITH cache hit/cacheable headers {signals} — web cache "
                    "deception: a sensitive page can be cached and retrieved by others.")
                return result
        result["evidence"] = "no static-suffix cached a dynamic page"
        return result

    # ── cache poisoning (unkeyed input) ───────────────────────────────────────

    def probe_poisoning(self, base_url: str, path: str = "/") -> dict:
        """Test whether an unkeyed header (X-Forwarded-Host) is reflected into a
        cacheable response. Detection only — uses a unique benign canary and
        never persists a malicious value."""
        req = _requests()
        result = {"vulnerable": False, "evidence": "", "header": "", "signals": {}}
        if req is None:
            result["evidence"] = "requests unavailable"
            return result
        base = base_url.rstrip("/")
        url = base + ("/" + path.lstrip("/"))
        canary = f"ghostwire-{uuid.uuid4().hex[:10]}.example"
        for hdr in ("X-Forwarded-Host", "X-Forwarded-Server", "X-Host", "X-Forwarded-Scheme"):
            headers = {"User-Agent": "Mozilla/5.0 (compatible; GhostwireCacheProbe/1.0)",
                       hdr: canary}
            try:
                r = req.get(url, headers=headers, timeout=self.timeout, verify=self.verify)
            except Exception:
                continue
            body = (r.text or "")[:6000]
            signals = _cache_signals(r.headers)
            reflected = canary in body or canary in str(r.headers)
            if reflected and (_looks_cached(signals) or "cache-control" in signals):
                result["vulnerable"] = True
                result["header"] = hdr
                result["signals"] = signals
                result["evidence"] = (
                    f"Unkeyed header '{hdr}: {canary}' was reflected into a cacheable response "
                    f"(cache signals {signals}) — cache poisoning: an attacker-controlled value "
                    "can be cached and served to other users.")
                return result
        result["evidence"] = "no unkeyed header reflected into a cacheable response"
        return result

    def probe(self, base_url: str, sensitive_path: str = "/") -> dict:
        """Run both probes and return a combined verdict."""
        deception = self.probe_deception(base_url, sensitive_path)
        poisoning = self.probe_poisoning(base_url, sensitive_path)
        return {
            "vulnerable": deception.get("vulnerable") or poisoning.get("vulnerable"),
            "deception": deception,
            "poisoning": poisoning,
        }

    @staticmethod
    def _similar(a: str, b: str) -> float:
        a, b = (a or "").strip(), (b or "").strip()
        if not a or not b:
            return 0.0
        if a == b:
            return 1.0
        import difflib
        return difflib.SequenceMatcher(None, a[:4000], b[:4000]).quick_ratio()
