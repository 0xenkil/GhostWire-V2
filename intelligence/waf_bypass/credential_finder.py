"""
Credential Finder - Hunts for WAF bypass keys (e.g. X-WAF-Key) and internal headers.
"""

import logging
import re
from typing import Optional


log = logging.getLogger(__name__)


class CredentialFinder:
    """Hunts for credentials that can be used to bypass WAF protections.

    P5-5: conforms to the WafTechnique contract — a harvested bypass header is a
    CONFIRMED bypass only when adding it flips a BLOCKED control into an ALLOWED
    response (a measured differential through Evidence.is_proven), never because a
    lone request returned 200.
    """

    name = "credential_finder"

    def __init__(self, state_store=None, remote_executor=None):
        self.state_store = state_store
        self.ssh = remote_executor
        self._bypass_headers = [
            "X-WAF-Key", "X-WAF-Secret", "X-Origin-Secret",
            "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP",
            "X-Internal-Secret", "X-Gateway-Auth"
        ]

    def run(self, target: str, ctx=None) -> "Optional[object]":
        """WafTechnique entry point: prove a credential-based WAF bypass. Harvests
        bypass headers (WITH values), then proves the first one via a control-vs-
        test status differential. Returns an Evidence (is_proven only on a real
        differential — else a LEAD) or None when there is no valued credential /
        no executor."""
        eng = ctx.get("engagement_id", "") if isinstance(ctx, dict) else ""
        valued = [c for c in
                  self.find_bypass_credentials(eng, target).get("credentials_found", [])
                  if c.get("value")]
        if not valued:
            return None
        return self._prove_credential_bypass(valued[0], target)

    def find_bypass_credentials(self, engagement_id: str, target: str) -> dict:
        """
        Scan for bypass keys in findings and common files.
        """
        results = {
            "engagement_id": engagement_id,
            "target": target,
            "credentials_found": [],
            "suggested_headers": {}
        }

        # 1. Look in state store for leaked keys.
        if self.state_store:
            findings = self.state_store.get_all_findings(engagement_id)
            for f in findings:
                detail = f.get("detail", "") or ""
                low = detail.lower()
                for header in self._bypass_headers:
                    if header.lower() not in low:
                        continue
                    # P5-5 (CREDFINDER-NO-VALUE): a header NAME alone is worthless —
                    # create_bypass_request rightly refuses a value-less credential,
                    # so the old name-only entry produced NOTHING usable (and made
                    # the orchestrator's create_bypass_request raise). Only a
                    # captured VALUE is a credential: extract `Header: value` /
                    # `Header=value`; no value → not harvested.
                    m = re.search(
                        re.escape(header) + r'\s*[:=]\s*([^\s"\'<>,;]+)',
                        detail, re.IGNORECASE)
                    if not m:
                        continue
                    value = m.group(1).strip()
                    if not value:
                        continue
                    results["credentials_found"].append({
                        "type": "header_key",
                        "name": header,
                        "value": value,
                        "source": "findings",
                    })
                    results["suggested_headers"][header] = value

        # 2. Check common environment files if we have some access or if they are exposed
        # (This is a simplified representation of the logic)
        # In a real engagement, the agent would use tools like gobuster to find
        # these

        return results

    def create_bypass_request(self, credential: dict, target: str) -> dict:
        """
        Generate headers for a bypass attempt using found credentials.
        FIX #3.1: Validate credential has a value before using
        """
        # Validate credential structure
        if not credential:
            log.error("[FIX 3.1] Credential is None or empty")
            raise ValueError("Credential cannot be None or empty")

        if not isinstance(credential, dict):
            log.error(
                f"[FIX 3.1] Credential is not dict: {
                    type(credential).__name__}")
            raise TypeError(
                f"Credential must be dict, got {
                    type(credential).__name__}")

        headers = {}
        if credential.get("type") == "header_key":
            # FIX #3.1: Validate credential has a value - NEVER use placeholder
            credential_name = credential.get("name")
            credential_value = credential.get("value")

            if not credential_name:
                log.error("[FIX 3.1] Credential missing 'name' field")
                raise ValueError("Credential must have 'name' field")

            if credential_value is None:
                log.error(
                    f"[FIX 3.1] Credential '{credential_name}' missing 'value' field - refusing to use placeholder")
                raise ValueError(
                    f"Credential '{credential_name}' has no value - cannot proceed with WAF bypass attempt")

            if not isinstance(credential_value,
                              str) or not credential_value.strip():
                log.error(
                    f"[FIX 3.1] Credential '{credential_name}' has invalid value: {
                        type(credential_value).__name__}")
                raise ValueError(
                    f"Credential '{credential_name}' value must be non-empty string")

            headers[credential_name] = credential_value

        return {
            "target": target,
            "headers": headers
        }

    def _curl_status(self, cmd: str) -> "Optional[int]":
        """Run a status-only curl over the executor and return the HTTP code, or
        None if it could not be obtained."""
        if not self.ssh:
            return None
        try:
            exit_code, out, err = self.ssh.execute(cmd, timeout=15)
        except Exception as e:
            log.error(f"[credential_finder] executor command failed: {e}")
            return None
        try:
            return int(str(out).strip()[:3])
        except (ValueError, TypeError):
            return None

    def _prove_credential_bypass(self, credential: dict, target: str):
        """P5-5: prove a header credential is a real WAF bypass via a control
        (NO bypass header) vs test (WITH header) STATUS differential — a bypass is
        control BLOCKED → test ALLOWED. Returns a differential Evidence (is_proven
        only when the differential holds) or None. Replaces the old "a lone 200 ⇒
        bypass" check, which confirmed a bypass on any target that returns 200
        without any header at all."""
        if not self.ssh:
            return None
        try:
            bypass_data = self.create_bypass_request(credential, target)
        except (ValueError, TypeError) as e:
            log.warning(f"[credential_finder] cannot test credential - {e}")
            return None
        headers = bypass_data.get("headers") or {}
        if not headers:
            return None

        import shlex
        headers_str = " ".join(
            [f"-H {shlex.quote(k + ': ' + str(v))}" for k, v in headers.items()])
        q = shlex.quote(target)
        base = f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 15 {q}"
        test = f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 15 {headers_str} {q}"

        ctrl_code = self._curl_status(base)   # control: no bypass header
        test_code = self._curl_status(test)   # test: with bypass header
        if ctrl_code is None or test_code is None:
            return None

        from core.result_contracts import Evidence
        blocked_codes = {403, 406, 429, 503, 418, 451}
        ctrl_blocked = ctrl_code in blocked_codes
        test_allowed = test_code not in blocked_codes
        note = (f"control={ctrl_code} (blocked={ctrl_blocked}), "
                f"test={test_code} (allowed={test_allowed}) via {list(headers)}")
        # Same status-differential encoding as the orchestrator's bypass gate:
        # convincing differential → similarity 0.0 (proven), else 0.99 (lead).
        return Evidence(
            proof_type="differential",
            reproducible_command=f"curl {headers_str} {target}",
            request=f"header-credential bypass vs baseline on {target}",
            differential=note,
            similarity_to_baseline=0.0 if (ctrl_blocked and test_allowed) else 0.99,
        )

    def test_credential_validity(self, credential: dict, target: str) -> bool:
        """Verify a credential actually bypasses the WAF: True only when the
        control-vs-test status differential re-measures is_proven()."""
        from intelligence.waf_bypass.technique import confirmed_bypass
        return confirmed_bypass(self._prove_credential_bypass(credential, target))
