"""
Credential Finder - Hunts for WAF bypass keys (e.g. X-WAF-Key) and internal headers.
"""

import logging


log = logging.getLogger(__name__)


class CredentialFinder:
    """Hunts for credentials that can be used to bypass WAF protections."""

    def __init__(self, state_store=None, remote_executor=None):
        self.state_store = state_store
        self.ssh = remote_executor
        self._bypass_headers = [
            "X-WAF-Key", "X-WAF-Secret", "X-Origin-Secret",
            "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP",
            "X-Internal-Secret", "X-Gateway-Auth"
        ]

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

        # 1. Look in state store for leaked keys
        if self.state_store:
            findings = self.state_store.get_all_findings(engagement_id)
            for f in findings:
                detail = f.get("detail", "").lower()
                for header in self._bypass_headers:
                    if header.lower() in detail:
                        # Extract value if possible (simple regex simulation)
                        results["credentials_found"].append({
                            "type": "header_key",
                            "name": header,
                            "source": "findings"
                        })

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

    def test_credential_validity(self, credential: dict, target: str) -> bool:
        """
        Verify if a credential actually bypasses the WAF.
        FIX #3.1: Handle invalid credentials gracefully
        """
        if not self.ssh:
            log.warning(
                "[FIX 3.1] SSH executor not available for credential testing")
            return False

        try:
            bypass_data = self.create_bypass_request(credential, target)
        except (ValueError, TypeError) as e:
            log.warning(f"[FIX 3.1] Cannot test credential validity - {e}")
            return False

        import shlex
        headers_str = " ".join(
            [f"-H {shlex.quote(k + ': ' + str(v))}" for k, v in bypass_data["headers"].items()])

        cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {headers_str} {
            shlex.quote(target)}"
        try:
            exit_code, out, err = self.ssh.execute(cmd, timeout=15)
        except Exception as e:
            log.error(f"[FIX 3.1] SSH command execution failed: {e}")
            return False

        if exit_code == 0 and out.strip() == "200":
            return True

        return False
