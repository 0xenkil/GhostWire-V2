"""
WS6 / W6.6a — TLS/JA3 + HTTP/2 client-fingerprint randomization.

Modern WAFs (Cloudflare, Akamai) fingerprint the TLS ClientHello (JA3/JA4) and
the HTTP/2 SETTINGS frame to tell a real browser from `curl`/`python-requests` —
*before* a single byte of the request is inspected. No header spoofing defeats
this, because the giveaway is in the handshake itself. The fix is to present a
genuine browser TLS fingerprint.

This module makes requests look like a real Chrome/Firefox/Safari client by
preferring an impersonation transport when one is available:
  - `curl_cffi` (Python lib wrapping curl-impersonate) — used for in-process
    requests with a real browser JA3.
  - `curl-impersonate` binaries (`curl_chrome*`, `curl-impersonate-chrome`) — used
    to rewrite a shell `curl` command onto a browser-fingerprinted binary.

Degrades gracefully: if no impersonation tooling is present, `available` is
False and every method is a safe no-op (returns the input unchanged / None), so
it can only ever help. No hardcoded target logic.
"""

import shutil
from typing import Optional

from utils.logger import get_logger

log = get_logger("tls_fingerprint")

# Named browser profiles → (curl_cffi impersonate token, curl-impersonate binaries).
# These are *client* fingerprints, learned from the impersonation tools, not
# target-specific hardcoding.
_BROWSER_PROFILES = {
    "chrome120": {"cffi": "chrome120",
                  "bins": ["curl_chrome120", "curl_chrome116", "curl-impersonate-chrome"]},
    "chrome116": {"cffi": "chrome116",
                  "bins": ["curl_chrome116", "curl-impersonate-chrome"]},
    "firefox": {"cffi": "firefox120",
                "bins": ["curl_ff117", "curl_ff109", "curl-impersonate-ff"]},
    "safari": {"cffi": "safari17_0",
               "bins": ["curl_safari17_0", "curl-impersonate"]},
    "edge": {"cffi": "edge101", "bins": ["curl_edge101"]},
}


def curl_cffi_available() -> bool:
    try:
        import curl_cffi  # noqa: F401
        return True
    except Exception:
        return False


class TlsFingerprintEvasion:
    """Present a browser TLS/JA3 + HTTP/2 fingerprint instead of a tool's default."""

    def __init__(self, default_profile: str = "chrome120"):
        self.default_profile = default_profile if default_profile in _BROWSER_PROFILES else "chrome120"
        self._has_cffi = curl_cffi_available()
        self._bin_cache: dict = {}

    @property
    def available(self) -> bool:
        """True if any impersonation transport (lib or binary) is usable."""
        if self._has_cffi:
            return True
        return self.find_impersonate_binary(self.default_profile) is not None

    def profiles(self) -> list:
        return list(_BROWSER_PROFILES.keys())

    # ── binary discovery / command rewrite ───────────────────────────────────

    def find_impersonate_binary(self, profile: Optional[str] = None) -> Optional[str]:
        """Return the path to a curl-impersonate binary for `profile`, or None."""
        profile = profile if profile in _BROWSER_PROFILES else self.default_profile
        if profile in self._bin_cache:
            return self._bin_cache[profile]
        found = None
        for b in _BROWSER_PROFILES[profile]["bins"]:
            p = shutil.which(b)
            if p:
                found = b  # use the command name; WSL resolves it
                break
        self._bin_cache[profile] = found
        return found

    def rewrite_curl_for_impersonation(self, command: str,
                                       profile: Optional[str] = None) -> tuple[str, str]:
        """Rewrite a `curl ...` command onto a browser-fingerprinted binary.

        Returns (new_command, note). If no impersonation binary exists, returns
        the command unchanged and a note explaining why (so the caller can log
        it / fall back to header-only evasion).
        """
        if not command.strip().startswith("curl") and " curl " not in f" {command}":
            return command, "not a curl command"
        binary = self.find_impersonate_binary(profile)
        if not binary:
            return command, "no curl-impersonate binary available (header-only evasion)"
        # Swap the leading `curl` token only; preserve all flags/target.
        new_cmd = command.replace("curl ", f"{binary} ", 1)
        prof = profile or self.default_profile
        return new_cmd, f"rewrote curl → {binary} (browser TLS profile {prof})"

    # ── in-process impersonated request (curl_cffi) ──────────────────────────

    def fetch_impersonated(self, url: str, profile: Optional[str] = None,
                           method: str = "GET", timeout: int = 15,
                           headers: Optional[dict] = None) -> Optional[dict]:
        """Make a real request with a browser TLS/JA3 fingerprint via curl_cffi.

        Returns {"status","body","ja3_profile"} or None if curl_cffi is absent
        or the request failed.
        """
        if not self._has_cffi:
            return None
        try:
            from curl_cffi import requests as cffi_requests
        except Exception:
            return None
        prof = profile if profile in _BROWSER_PROFILES else self.default_profile
        impersonate = _BROWSER_PROFILES[prof]["cffi"]
        try:
            resp = cffi_requests.request(
                method.upper(), url, impersonate=impersonate,
                timeout=timeout, headers=headers or {}, verify=False)
            return {"status": resp.status_code,
                    "body": (resp.text or "")[:8000],
                    "ja3_profile": impersonate}
        except Exception as e:
            log.debug(f"curl_cffi impersonated fetch failed: {e}")
            return None

    def evasion_note(self) -> str:
        """Guidance for the AI / logs on the current TLS-evasion capability."""
        if self._has_cffi:
            return (f"TLS/JA3 evasion ACTIVE via curl_cffi (browser profile "
                    f"{self.default_profile}); requests present a real browser handshake.")
        b = self.find_impersonate_binary()
        if b:
            return f"TLS/JA3 evasion available via {b}; curl commands can be rewritten to it."
        return ("TLS/JA3 evasion UNAVAILABLE (install curl_cffi or curl-impersonate to defeat "
                "handshake fingerprinting); falling back to header-only evasion.")
