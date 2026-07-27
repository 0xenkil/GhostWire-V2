"""
TargetContext - Universal target representation for Ghostwire V6.
Preserves full URL context (scheme, host, port, path, query) so the AI
can reason about the exact entry point rather than guessing from a bare domain.
"""
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlunparse
import re
import json


@dataclass
class TargetContext:
    """
    Universal target context for any web application.
    Stores the original user input, parsed components, and dynamically
    discovered knowledge (endpoints, tech stack, auth points, etc.).
    """
    original_input: str                       # What the user typed
    scheme: str = "http"                      # http or https
    host: str = ""                            # hostname or IP
    port: Optional[int] = None                # explicit port
    path: str = "/"                           # path component
    query: str = ""                           # query string
    fragment: str = ""                        # fragment

    # Dynamic discoveries (populated by ReconAgent / AI loop)
    discovered_endpoints: list[str] = field(default_factory=list)
    discovered_subdomains: list[str] = field(default_factory=list)
    # e.g. ["PHP", "Laravel", "MySQL"]
    tech_stack: list[str] = field(default_factory=list)
    auth_endpoints: list[str] = field(
        default_factory=list)      # login, admin panels
    api_endpoints: list[str] = field(
        default_factory=list)       # REST/GraphQL paths
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    baseline_response: str = ""               # homepage body for FP filtering
    baseline_size: int = 0                    # response size for filtering
    waf_detected: bool = False
    waf_type: str = ""
    is_cdn: bool = False
    cdn_provider: str = ""

    # Scope tracking
    scope_hosts: set[str] = field(
        default_factory=set)   # all in-scope hostnames
    scope_paths: set[str] = field(
        default_factory=set)   # all in-scope base paths

    @classmethod
    def from_input(cls, raw: str) -> "TargetContext":
        """Parse any user input into a rich TargetContext."""
        text = str(raw).strip()
        if not text:
            raise ValueError("Target cannot be empty")

        # Repair only a clearly duplicated LEADING scheme such as
        # https://http://example.com → http://example.com. The old logic stripped
        # the first scheme whenever ANY "://" appeared later in the string, so a
        # legitimate URL with "://" in its path/query (e.g. ?next=https://x or a
        # path segment "/a://b") had its REAL scheme stripped and got silently
        # downgraded to http://. Only collapse when the text *starts* with
        # scheme://scheme:// (handles triples via the loop).
        _dup_scheme = re.compile(
            r'^[a-zA-Z][a-zA-Z0-9+.-]*://(?=[a-zA-Z][a-zA-Z0-9+.-]*://)')
        while _dup_scheme.match(text):
            text = _dup_scheme.sub('', text, count=1)

        # If no scheme remains, assume http:// (AI can upgrade to https after
        # probing)
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text):
            text = "http://" + text

        parsed = urlparse(text)

        # Extract port if present
        port = None
        if parsed.port:
            port = parsed.port
        elif parsed.scheme == "https":
            port = 443
        elif parsed.scheme == "http":
            port = 80

        # Normalize path: ensure it starts with /
        path = parsed.path if parsed.path else "/"

        ctx = cls(
            original_input=raw,
            scheme=parsed.scheme,
            host=parsed.hostname or "",
            port=port,
            path=path,
            query=parsed.query,
            fragment=parsed.fragment,
        )
        ctx.scope_hosts.add(ctx.host)
        ctx.scope_paths.add(ctx.path)
        return ctx

    # ── Property helpers ────────────────────────────────────────────────
    @property
    def base_url(self) -> str:
        """https://target.com:8443  (no path)"""
        netloc = self.host
        if self.port and (
            (self.scheme == "http" and self.port != 80) or
            (self.scheme == "https" and self.port != 443)
        ):
            netloc += f":{self.port}"
        return f"{self.scheme}://{netloc}"

    @property
    def full_url(self) -> str:
        """https://target.com:8443/app/login?x=1  (original full input reconstructed)"""
        parts = (
            self.scheme,
            self.netloc,
            self.path,
            "",
            self.query,
            self.fragment,
        )
        return urlunparse(parts)

    @property
    def netloc(self) -> str:
        """target.com:8443"""
        if self.port and (
            (self.scheme == "http" and self.port != 80) or
            (self.scheme == "https" and self.port != 443)
        ):
            return f"{self.host}:{self.port}"
        return self.host

    @property
    def root_domain(self) -> str:
        """Bare hostname for DNS/subdomain ops."""
        return self.host

    # ── Dynamic knowledge methods ───────────────────────────────────────
    def add_endpoint(self, path: str):
        """Register a discovered endpoint (e.g. /admin/login)."""
        cleaned = path.strip()
        if cleaned and cleaned not in self.discovered_endpoints:
            self.discovered_endpoints.append(cleaned)

    def add_subdomain(self, subdomain: str):
        """Register a discovered subdomain and auto-expand scope."""
        sub = subdomain.strip().lower().rstrip("/")
        if sub and sub not in self.discovered_subdomains:
            self.discovered_subdomains.append(sub)
            self.scope_hosts.add(sub)

    def add_tech(self, tech: str):
        """Register a detected technology."""
        t = tech.strip()
        if t and t not in self.tech_stack:
            self.tech_stack.append(t)

    def add_auth_endpoint(self, path: str):
        """Register a login/admin/auth endpoint."""
        p = path.strip()
        if p and p not in self.auth_endpoints:
            self.auth_endpoints.append(p)

    def add_api_endpoint(self, path: str):
        """Register a REST/GraphQL/WebSocket endpoint."""
        p = path.strip()
        if p and p not in self.api_endpoints:
            self.api_endpoints.append(p)

    def is_in_scope(self, url: str) -> bool:
        """Check if a discovered URL is within the engagement scope."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        # Exact host match or subdomain of root domain
        if host == self.host or host.endswith(f".{self.host}"):
            return True
        if host in self.scope_hosts:
            return True
        return False

    def to_dict(self) -> dict:
        """Serialize for prompts, state storage, or JSON logging."""
        return {
            "original_input": self.original_input,
            "base_url": self.base_url,
            "full_url": self.full_url,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "discovered_endpoints": self.discovered_endpoints,
            "discovered_subdomains": self.discovered_subdomains,
            "tech_stack": self.tech_stack,
            "auth_endpoints": self.auth_endpoints,
            "api_endpoints": self.api_endpoints,
            "baseline_size": self.baseline_size,
            "waf_detected": self.waf_detected,
            "waf_type": self.waf_type,
            "is_cdn": self.is_cdn,
            "cdn_provider": self.cdn_provider,
            "scope_hosts": sorted(self.scope_hosts),
        }

    def to_json(self, indent: int = 0) -> str:
        return json.dumps(
            self.to_dict(), indent=indent if indent else None, default=str)

    def __repr__(self) -> str:
        return f"TargetContext({self.full_url}, endpoints={len(self.discovered_endpoints)}, tech={self.tech_stack})"
