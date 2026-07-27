"""
core/target_graph.py
====================
Cross-target relationship engine for GHOSTWIRE multi-scope engagements.

Tracks relationships between all targets in session.scope so the AI can:
  - Identify shared infrastructure (same IP, same CDN, same cert)
  - Find pivot paths (creds from A → test on B)
  - Detect internal references (JS on A calls API on B)
  - Cluster targets by ASN / hosting provider

Relationship types:
  shared_ip          — two targets resolve to the same IP
  shared_cert        — same TLS certificate / CN / SAN entry
  shared_nameserver  — same NS records
  shared_mx          — same mail infrastructure
  subdomain_of       — one scope target is a subdomain of another
  internal_reference — HTML/JS on one target directly references another
  credential_tested  — credentials from A were tested on B (with result)
  pivot_path         — confirmed path from A to B through a vuln/access
"""

from __future__ import annotations

import ipaddress
import re
import socket
import json
from dataclasses import dataclass, field
from typing import Optional
from utils.logger import get_logger

log = get_logger("target_graph")


# ─────────────────────────────────────────────────────────────
#  DATA CLASSES
# ─────────────────────────────────────────────────────────────

@dataclass
class TargetNode:
    host: str
    ip: Optional[str] = None
    asn: Optional[str] = None
    cert_cn: Optional[str] = None
    cert_sans: list = field(default_factory=list)
    nameservers: list = field(default_factory=list)
    mx_records: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    tech_stack: list = field(default_factory=list)
    credentials_found: list = field(
        default_factory=list)   # list of "user:pass" strings
    is_primary: bool = False

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "ip": self.ip,
            "asn": self.asn,
            "cert_cn": self.cert_cn,
            "cert_sans": self.cert_sans,
            "nameservers": self.nameservers,
            "mx_records": self.mx_records,
            "open_ports": self.open_ports,
            "tech_stack": self.tech_stack,
            "credentials_found": self.credentials_found,
            "is_primary": self.is_primary,
        }


@dataclass
class TargetEdge:
    src: str
    dst: str
    rel_type: str       # one of the relation type strings above
    evidence: str = ""  # human-readable proof
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "src": self.src,
            "dst": self.dst,
            "rel_type": self.rel_type,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


# ─────────────────────────────────────────────────────────────
#  MAIN CLASS
# ─────────────────────────────────────────────────────────────

class TargetGraph:
    """
    Lightweight in-memory graph tracking cross-target relationships.
    Serialisable to dict / JSON for state-store persistence.
    """

    def __init__(self):
        self.nodes: dict[str, TargetNode] = {}   # host → TargetNode
        self.edges: list[TargetEdge] = []

    # ── Node management ──────────────────────────────────────

    def add_target(
        self,
        host: str,
        ip: str = None,
        asn: str = None,
        cert_cn: str = None,
        cert_sans: list = None,
        nameservers: list = None,
        mx_records: list = None,
        open_ports: list = None,
        tech_stack: list = None,
        is_primary: bool = False,
    ) -> TargetNode:
        node = self.nodes.get(host)
        if node is None:
            node = TargetNode(host=host, is_primary=is_primary)
            self.nodes[host] = node
        # Update fields if provided
        if ip:
            node.ip = ip
        if asn:
            node.asn = asn
        if cert_cn:
            node.cert_cn = cert_cn
        if cert_sans:
            node.cert_sans = list(cert_sans)
        if nameservers:
            node.nameservers = list(nameservers)
        if mx_records:
            node.mx_records = list(mx_records)
        if open_ports:
            node.open_ports = list(open_ports)
        if tech_stack:
            node.tech_stack = list(tech_stack)
        if is_primary:
            node.is_primary = True
        return node

    def add_credential(self, host: str, credential: str):
        """Register a discovered credential (user:pass) on a host."""
        node = self.nodes.get(host)
        if node and credential not in node.credentials_found:
            node.credentials_found.append(credential)

    # ── Edge management ──────────────────────────────────────

    def add_relationship(
        self,
        src: str,
        dst: str,
        rel_type: str,
        evidence: str = "",
        confidence: float = 1.0,
    ):
        """Add a directional relationship. Skips exact duplicates."""
        # Avoid exact duplicates
        for e in self.edges:
            if e.src == src and e.dst == dst and e.rel_type == rel_type:
                return
        self.edges.append(TargetEdge(src=src, dst=dst, rel_type=rel_type,
                                     evidence=evidence, confidence=confidence))
        log.info(f"[GRAPH] {src} --[{rel_type}]--> {dst} | {evidence[:80]}")

    # ── Analysis helpers ─────────────────────────────────────

    def analyze(self):
        """
        Run all automated cross-target relationship detection passes
        based on the node data collected so far.
        """
        self._detect_shared_ips()
        self._detect_shared_certs()
        self._detect_shared_nameservers()
        self._detect_shared_mx()
        self._detect_subdomain_relationships()

    def _detect_shared_ips(self):
        hosts = list(self.nodes.values())
        for i, a in enumerate(hosts):
            for b in hosts[i + 1:]:
                if a.ip and b.ip and a.ip == b.ip:
                    self.add_relationship(
                        a.host, b.host, "shared_ip",
                        evidence=f"Both resolve to {a.ip}",
                    )
                    self.add_relationship(
                        b.host, a.host, "shared_ip",
                        evidence=f"Both resolve to {a.ip}",
                    )

    def _detect_shared_certs(self):
        hosts = list(self.nodes.values())
        for i, a in enumerate(hosts):
            for b in hosts[i + 1:]:
                # CN match
                if a.cert_cn and b.cert_cn and a.cert_cn == b.cert_cn:
                    self.add_relationship(
                        a.host, b.host, "shared_cert",
                        evidence=f"Same cert CN: {a.cert_cn}",
                    )
                # SAN cross-reference: b.host appears in a's SAN list
                for san in a.cert_sans:
                    san_clean = san.lstrip("*.")
                    if b.host.endswith(san_clean) or b.host == san_clean:
                        self.add_relationship(
                            a.host, b.host, "shared_cert",
                            evidence=f"SAN '{san}' on {
                                a.host} cert covers {
                                b.host}",
                        )

    def _detect_shared_nameservers(self):
        hosts = list(self.nodes.values())
        for i, a in enumerate(hosts):
            for b in hosts[i + 1:]:
                if a.nameservers and b.nameservers:
                    common = set(a.nameservers) & set(b.nameservers)
                    if common:
                        self.add_relationship(
                            a.host, b.host, "shared_nameserver",
                            evidence=f"Common NS: {
                                ', '.join(
                                    list(common)[
                                        :3])}",
                        )

    def _detect_shared_mx(self):
        hosts = list(self.nodes.values())
        for i, a in enumerate(hosts):
            for b in hosts[i + 1:]:
                if a.mx_records and b.mx_records:
                    common = set(a.mx_records) & set(b.mx_records)
                    if common:
                        self.add_relationship(
                            a.host, b.host, "shared_mx",
                            evidence=f"Common MX: {
                                ', '.join(
                                    list(common)[
                                        :2])}",
                        )

    def _detect_subdomain_relationships(self):
        hosts = list(self.nodes.keys())
        for a in hosts:
            for b in hosts:
                if a == b:
                    continue
                # Is 'a' a subdomain of 'b'?
                if a.endswith("." + b):
                    self.add_relationship(
                        a, b, "subdomain_of",
                        evidence=f"{a} is a subdomain of {b}",
                    )

    def add_internal_reference(
            self, src_host: str, referenced_host: str, context: str = ""):
        """Call this when HTML/JS on src_host contains a link to referenced_host."""
        self.add_relationship(
            src_host, referenced_host, "internal_reference",
            evidence=context or f"Content on {src_host} references {referenced_host}",
            confidence=0.9,
        )

    def register_credential_test(
            self, cred: str, src_host: str, dst_host: str, success: bool):
        """Register that a credential found on src_host was tested on dst_host."""
        result = "SUCCESS" if success else "failed"
        self.add_relationship(
            src_host, dst_host, "credential_tested",
            evidence=f"Cred '{cred[:20]}...' tested on {dst_host}: {result}",
            confidence=1.0 if success else 0.5,
        )

    def register_pivot(self, src_host: str, dst_host: str, method: str):
        """Register a confirmed pivot path between two targets."""
        self.add_relationship(
            src_host, dst_host, "pivot_path",
            evidence=f"Confirmed pivot via: {method}",
            confidence=1.0,
        )

    # ── Query helpers ────────────────────────────────────────

    def get_pivot_candidates(self, from_host: str) -> list[dict]:
        """
        Return all targets reachable from from_host via any relationship,
        sorted by relationship strength (pivot_path first, then shared_ip, etc.).
        """
        priority = {
            "pivot_path": 0,
            "credential_tested": 1,
            "shared_ip": 2,
            "shared_cert": 3,
            "internal_reference": 4,
            "subdomain_of": 5,
            "shared_nameserver": 6,
            "shared_mx": 7,
        }
        results = []
        for edge in self.edges:
            if edge.src == from_host:
                results.append({
                    "host": edge.dst,
                    "rel_type": edge.rel_type,
                    "evidence": edge.evidence,
                    "confidence": edge.confidence,
                    "priority": priority.get(edge.rel_type, 99),
                })
        results.sort(key=lambda x: (x["priority"], -x["confidence"]))
        return results

    def get_shared_infra_clusters(self) -> list[list[str]]:
        """
        Return clusters of targets that share infrastructure (IP / cert / NS).
        Uses simple union-find over shared_ip + shared_cert edges.
        """
        parent: dict[str, str] = {h: h for h in self.nodes}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        infra_rels = {"shared_ip", "shared_cert", "shared_nameserver"}
        for edge in self.edges:
            if edge.rel_type in infra_rels:
                if edge.src in parent and edge.dst in parent:
                    union(edge.src, edge.dst)

        clusters: dict[str, list[str]] = {}
        for host in self.nodes:
            root = find(host)
            clusters.setdefault(root, []).append(host)

        return [c for c in clusters.values() if len(c) > 1]

    def get_all_credentials(self) -> list[dict]:
        """Return all discovered credentials across all targets."""
        out = []
        for host, node in self.nodes.items():
            for cred in node.credentials_found:
                out.append({"host": host, "credential": cred})
        return out

    def get_cross_target_intel_summary(self) -> str:
        """
        Generate a human-readable intelligence summary for injection
        into the AI exploitation prompt.
        """
        lines = []

        clusters = self.get_shared_infra_clusters()
        if clusters:
            lines.append("### 🔗 SHARED INFRASTRUCTURE CLUSTERS")
            for cluster in clusters:
                lines.append(
                    f"  [{' ⟷ '.join(cluster)}] — likely same host/operator")

        creds = self.get_all_credentials()
        if creds:
            lines.append("\n### 🔑 CREDENTIALS DISCOVERED ACROSS TARGETS")
            for c in creds:
                lines.append(f"  {c['host']}: {c['credential']}")
            lines.append(
                "  ⚡ TEST THESE ON ALL OTHER SCOPE TARGETS — credential reuse is common!")

        # Pivot candidates for each node
        pivot_lines = []
        for host in self.nodes:
            candidates = self.get_pivot_candidates(host)
            if candidates:
                top = candidates[0]
                pivot_lines.append(
                    f"  {host} → {top['host']} via [{top['rel_type']}]: {top['evidence'][:80]}"
                )
        if pivot_lines:
            lines.append("\n### 🎯 IDENTIFIED PIVOT PATHS")
            lines.extend(pivot_lines[:10])

        # Internal references
        ref_edges = [
            e for e in self.edges if e.rel_type == "internal_reference"]
        if ref_edges:
            lines.append("\n### 🌐 CROSS-TARGET INTERNAL REFERENCES")
            for e in ref_edges[:5]:
                lines.append(
                    f"  {e.src} → references → {e.dst}: {e.evidence[:80]}")

        if not lines:
            return ""

        return (
            "\n### 🕸️ CROSS-TARGET INTELLIGENCE (Multi-Scope Red Team)\n"
            + "\n".join(lines)
            + "\n\nMANDATE: Use the relationships above to pivot between targets. "
            "A vulnerability on one host may give access to another via shared infrastructure or credential reuse.\n"
        )

    # ── Serialisation ────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "nodes": {h: n.to_dict() for h, n in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TargetGraph":
        g = cls()
        for host, node_data in data.get("nodes", {}).items():
            g.nodes[host] = TargetNode(**node_data)
        for edge_data in data.get("edges", []):
            g.edges.append(TargetEdge(**edge_data))
        return g

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ─────────────────────────────────────────────────────────────
#  UTILITY: resolve a scope entry to a clean hostname list
# ─────────────────────────────────────────────────────────────

def resolve_scope_entry(entry: str) -> list[str]:
    """
    Given a raw scope string (domain, URL, CIDR, bare IP),
    return a list of canonical hostnames/IPs to add to the graph.

    - "https://example.com/path" → ["example.com"]
    - "192.168.1.0/24"           → CIDR kept as-is (nmap handles it)
    - "192.168.1.5"              → ["192.168.1.5"]
    - "example.com"              → ["example.com"]
    """
    entry = entry.strip()
    if not entry:
        return []

    # Strip scheme
    clean = re.sub(r'^https?://', '', entry)
    # Strip path
    clean = clean.split('/')[0].split('?')[0]

    # CIDR range — return as-is for nmap
    try:
        ipaddress.ip_network(clean, strict=False)
        return [clean]
    except ValueError:
        pass

    # Bare IP
    try:
        ipaddress.ip_address(clean)
        return [clean]
    except ValueError:
        pass

    # Domain (strip port)
    host = clean.split(':')[0]
    if host:
        return [host]

    return []


def quick_resolve_ip(host: str, timeout: float = 3.0) -> Optional[str]:
    """Best-effort DNS resolve of a hostname to an IPv4 address."""
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        import logging as __logging_tmp
        __logging_tmp.getLogger(__name__).error(
            f"Unhandled exception: {e}", exc_info=True)
        return None
