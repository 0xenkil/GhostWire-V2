"""core/egress_probe.py — egress causality for WAF-block attribution (P4-4).

When a tool receives a WAF block signal (403/429/…), the engine must know WHY
before it wastes the whole budget rotating Tor: is the TARGET's WAF blocking us,
or is our OWN egress (a burned Tor exit / rate-limited datacenter IP) blocked
*everywhere*? The old code assumed "target" and rotated Tor against its own 403
(RC-1/RC-2/DEEP-1/DEEP-7 — the self-inflicted 403→rotate→still-403 cascade).

``EgressProbe.classify`` answers it by probing a DIVERSE control set — including
at least one CDN/WAF-fronted endpoint — FROM THE SAME EGRESS:

  - controls also blocked  → ``self_egress``  (our exit is the problem; do NOT
    fire evasion at the target — rotate once or abandon)
  - controls clean         → ``target``       (only the target blocked us; a real
    WAF block, evasion is warranted)
  - can't tell / flaky net → ``unknown``      (fail-safe: do NOT fire evasion)

Design notes:
- Majority vote over the controls we could actually reach; if we can't reach a
  majority, we return ``unknown`` rather than guess.
- ``egress_fingerprint`` is captured at the tool's exec time; if a fingerprint
  provider is supplied and the CURRENT egress no longer matches (a mid-flight Tor
  rotation), we return ``unknown`` — a probe of a *different* exit can't attribute
  the *original* block.
- The block SIGNAL itself (whether the tool's own request was WAF-blocked) is the
  caller's hypothesis; this module only attributes causality. Pure/​injectable so
  the decision logic is unit-testable without network.
"""
from __future__ import annotations

import re
from typing import Callable, Optional, Sequence

# HTTP status codes that indicate an (edge/WAF) block rather than a normal answer.
BLOCK_CODES = frozenset({403, 406, 429, 503, 418, 451})

# A REAL block of the tool's OWN request shows up as an HTTP status LINE
# ("HTTP/1.1 403", "HTTP/2 429") or a status TAG ("[403]", nuclei/httpx style) —
# NOT the bare substring "403" that a scanner prints as DATA. This is what lets us
# DELETE the _WAF_EXEMPT_TOOLS band-aid: nmap/subfinder listing a 403 in their
# findings no longer trips block detection, because that isn't a status line.
_BLOCK_STATUS_RE = re.compile(
    r'(?:HTTP/\d(?:\.\d)?\s+|\[\s*|status[_ ]?code["\s:=]+)(403|406|429|451|503)\b',
    re.IGNORECASE)

# Challenge/interstitial BODY markers — a real WAF response to the tool's own
# request that may carry a 200 status (JS/CAPTCHA challenge). Kept tight and
# specific so they don't match incidental prose.
_CHALLENGE_BODY_MARKERS = (
    "attention required! | cloudflare",
    "cloudflare ray id",
    "please verify you are human",
    "checking your browser before accessing",
    "error 1020",  # Cloudflare access-rule block
)


def looks_like_http_block(output: str) -> bool:
    """True only when ``output`` carries a WAF block for the TOOL'S OWN request —
    an HTTP block status line/tag, or a specific challenge-page body marker — as
    opposed to the substring '403' appearing as scan DATA. Replaces the loose
    substring markers + the hardcoded ``_WAF_EXEMPT_TOOLS`` exempt list."""
    if not output:
        return False
    if _BLOCK_STATUS_RE.search(output):
        return True
    low = output.lower()
    return any(m in low for m in _CHALLENGE_BODY_MARKERS)


def attribute_block(output: str, target_host: str = "", *,
                    egress_probe: "EgressProbe" = None,
                    went_through_tor: bool = False,
                    egress_fingerprint: str = None) -> str:
    """Attribute a tool result's block: ``'not_blocked'`` | ``'self_egress'`` |
    ``'target'`` | ``'unknown'``.

    1. If the output is not a real HTTP block of the tool's own request →
       ``'not_blocked'`` (kills the nmap/subfinder '403-as-data' false block).
    2. A DIRECT request (``went_through_tor=False`` — raw-socket/direct tools, or
       stealth off) is the target answering OUR real IP → ``'target'``.
    3. Only when the request traversed a shared exit (Tor/proxy) do we probe
       egress causality — a burned exit blocked everywhere reads ``'self_egress'``
       and evasion is NOT fired at the target."""
    if not looks_like_http_block(output):
        return "not_blocked"
    if not went_through_tor:
        return "target"
    probe = egress_probe or EgressProbe()
    return probe.classify(target_host, egress_fingerprint=egress_fingerprint)

# Diverse control set: at least one CDN/WAF-fronted endpoint, across distinct
# providers/ASNs. robots.txt is small, cache-friendly, and universally present.
#
# EMPIRICALLY VALIDATED on a live datacenter host + Tor (2026-08-06):
#   - Permissive CDN robots.txt (below) answered 200 from BOTH a datacenter IP and
#     a normal Tor exit → a clean egress reads 'target' (evasion allowed). Good.
#   - Aggressive bot/WAF endpoints (g2.com, expedia.com) 403/429'd the DATACENTER
#     IP itself, not just Tor → they produce a FALSE 'self_egress' on any
#     datacenter-hosted engine, which would suppress ALL legitimate evasion.
# So the control set is deliberately PERMISSIVE-CDN: it flips to 'self_egress' only
# when even these broadly-open endpoints block us — i.e. our egress is genuinely
# burned (on major blocklists) — never merely because an endpoint dislikes Tor or
# datacenters. A false 'self_egress' (miss a real target WAF) is worse here than a
# false 'target' (waste one rotation), so the default fails toward 'target'.
DEFAULT_CONTROLS: tuple[str, ...] = (
    "https://www.cloudflare.com/robots.txt",   # Cloudflare edge (CDN/WAF-fronted)
    "https://www.google.com/robots.txt",        # Google edge
    "https://en.wikipedia.org/robots.txt",      # different provider/ASN
)


class EgressProbe:
    def __init__(self, controls: Sequence[str] = None,
                 fetcher: Callable[[str], Optional[int]] = None,
                 fingerprint_provider: Callable[[], str] = None):
        self.controls = tuple(controls) if controls else DEFAULT_CONTROLS
        self._fetch = fetcher or self._http_status
        self._fingerprint = fingerprint_provider

    # ── network (overridable for tests) ──────────────────────────────────────
    def _http_status(self, url: str) -> Optional[int]:
        """Return the HTTP status for a control URL, or None if unreachable."""
        try:
            import requests
            r = requests.get(url, timeout=8, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 (compatible; GhostwireEgress/1.0)"})
            return int(r.status_code)
        except Exception:
            return None

    # ── the causality decision ───────────────────────────────────────────────
    def classify(self, target_host: str = "",
                 egress_fingerprint: str = None) -> str:
        """Attribute a target block to ``'self_egress'`` | ``'target'`` |
        ``'unknown'`` by probing the control set from the current egress.

        ``egress_fingerprint`` is the egress identity captured when the target
        block occurred; if a fingerprint_provider is set and the egress has since
        changed, the attribution can't be trusted → ``'unknown'``.
        """
        # Drift guard: a mid-flight rotation means we'd be probing a DIFFERENT
        # exit than the one that got blocked — can't attribute the original block.
        if egress_fingerprint is not None and self._fingerprint is not None:
            try:
                if self._fingerprint() != egress_fingerprint:
                    return "unknown"
            except Exception:
                return "unknown"

        statuses = [self._fetch(u) for u in self.controls]
        probed = [s for s in statuses if s is not None]

        # Must reach a MAJORITY of controls to say anything at all.
        if len(probed) * 2 < len(self.controls):
            return "unknown"

        blocked = sum(1 for s in probed if s in BLOCK_CODES)
        clean = sum(1 for s in probed if 200 <= s < 400)

        if blocked * 2 > len(probed):
            # Our egress is blocked across diverse, normally-open endpoints →
            # the target's "block" is really our exit. Do NOT rotate at the target.
            return "self_egress"
        if clean * 2 > len(probed):
            # Diverse controls answer fine → only the target blocked us: real WAF.
            return "target"
        return "unknown"


def should_fire_evasion(classification: str) -> bool:
    """Evasion (WAF bypass / Tor rotation *at the target*) is warranted ONLY when
    the block is attributable to the TARGET. ``self_egress`` means rotate-once-or-
    abandon (not hammer the target), and ``unknown`` fails safe (no evasion)."""
    return classification == "target"
