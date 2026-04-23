import ipaddress
from config import BLOCKED_IP_RANGES, ALWAYS_BLOCKED_DOMAINS
from utils.logger import get_logger

log = get_logger("scope_enforcer")

class ScopeViolation(Exception):
    pass

class ScopeEnforcer:
    def __init__(self, session):
        self.session = session
        self._blocked_nets = [
            ipaddress.ip_network(r, strict=False) for r in BLOCKED_IP_RANGES
        ]

    def check_target(self, target: str) -> bool:
        """
        Returns True if target is in scope.
        Raises ScopeViolation with a reason if not.
        Called before EVERY tool execution.
        """
        if not target:
            raise ScopeViolation("Empty target passed to scope check.")

        # 1. Must be inside declared scope
        if not self._in_declared_scope(target):
            raise ScopeViolation(
                f"Target '{target}' is NOT in the declared engagement scope. "
                f"Declared scope: {self.session.scope}"
            )

        # 2. Never attack always-blocked domains
        for blocked in ALWAYS_BLOCKED_DOMAINS:
            # Use suffix match to prevent "cloudflare.com" matching "notcloudflare.com"
            if target == blocked or target.endswith(f".{blocked}"):
                raise ScopeViolation(
                    f"Target '{target}' matches a globally blocked domain: {blocked}"
                )

        # 3. Check if IP falls in protected ranges
        try:
            ip = ipaddress.ip_address(target)
            for net in self._blocked_nets:
                if ip in net:
                    raise ScopeViolation(
                        f"IP '{target}' falls within a protected range: {net}"
                    )
        except ValueError:
            pass  # Not an IP — domain check already done above

        log.debug(f"Scope check passed for: {target}")
        return True

    def _in_declared_scope(self, target: str) -> bool:
        """
        Check if target is in scope using exact or suffix matching only.
        We do NOT use substring matching (e.g. 's in target') to prevent
        false positives like 'space' matching 'myspace.com'.
        """
        for s in self.session.scope:
            # Exact match
            if target == s:
                return True
            # Subdomain suffix match: sub.example.com is in scope if scope has example.com
            if target.endswith(f".{s}"):
                return True
            # CIDR range check
            try:
                net = ipaddress.ip_network(s, strict=False)
                ip = ipaddress.ip_address(target)
                if ip in net:
                    return True
            except ValueError:
                continue
        return False

    def check_action(self, action: str, risk_level: str = "medium") -> bool:
        """
        Checks if a proposed action is allowed given current ROE.
        risk_level: 'low', 'medium', 'high', 'critical'
        """
        roe = self.session.rules_of_engagement
        if risk_level == "critical" and not roe.get("allow_destructive", False):
            raise ScopeViolation(
                f"Action '{action}' requires destructive permission which is not granted."
            )
        if risk_level == "high" and not roe.get("allow_exploitation", True):
            raise ScopeViolation(
                f"Action '{action}' requires exploitation permission which is not granted."
            )
        return True
