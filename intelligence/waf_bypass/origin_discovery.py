"""
Origin Server Discovery - Layer 2 WAF Bypass

Discovers the actual origin server IPs that bypass CDN/WAF protection:
- Historical DNS records
- SSL certificate analysis
- ASN/IP range enumeration
- Subdomain enumeration
- Shodan/Censys queries
- Cloud metadata services
- Direct connection testing
"""

import socket
import ssl
from typing import Dict, List, Set, Any


class OriginDiscovery:
    """Finds origin server IPs that bypass CDN/WAF.

    P5-5: conforms to the WafTechnique contract — run() returns an Evidence|None,
    and a discovered IP is a CONFIRMED origin bypass only when a direct connection
    serves the SAME app as the fronted domain (is_proven), never because the IP
    merely answered.
    """

    name = "origin_discovery"

    def __init__(self, dns_resolver: str = "1.1.1.1"):
        """Initialize origin discovery"""
        self.dns_resolver = dns_resolver
        self.discovered_ips = set()
        self.discovered_services = {}
        self.port_scan_results = {}

    def run(self, target: str, ctx=None) -> "Optional[object]":
        """WafTechnique entry point: discover candidate origin IPs and return the
        Evidence for the FIRST one that proves to be the real origin (its direct
        response matches the WAF-fronted app). None if none prove out — every
        candidate that merely responds is a lead, not a confirmation."""
        import re
        domain = re.sub(r'^https?://', '', target).split('/')[0]
        control = self._fetch_fronted_response(domain)
        disc = self.discover_origin_ips(domain, aggressive=False)
        for cand in (disc.get("origin_candidates", []) or [])[:5]:
            ip = cand.get("ip") if isinstance(cand, dict) else cand
            if not ip:
                continue
            probe = {"ip": ip, "domain": domain, "port": 443, "reachable": False,
                     "ssl_valid": False, "headers_received": {}, "bypass_viable": False}
            origin_body = self._fetch_origin_response(ip, domain, 443, probe)
            if not origin_body:
                continue
            ev = self._origin_bypass_evidence(control, origin_body, ip, domain)
            if ev is not None and ev.is_proven():
                return ev  # first PROVEN origin
        return None

    def discover_origin_ips(
            self, domain: str, aggressive: bool = True) -> Dict[str, Any]:
        """
        Discover all possible origin server IPs for a domain

        Args:
            domain: Target domain
            aggressive: Include CPU-intensive techniques

        Returns:
            Dict with discovered IPs, ports, services, confidence
        """
        # Ensure domain doesn't contain scheme or path
        import re
        clean_domain = re.sub(r'^https?://', '', domain).split('/')[0]

        results = {
            "domain": clean_domain,
            "discovered_ips": set(),
            "origin_candidates": [],
            "techniques_used": [],
            "metadata": {},
            "confidence": 0.0
        }

        domain = clean_domain

        # Technique 1: Current DNS resolution
        current_ips = self._resolve_dns(domain)
        if current_ips:
            results["discovered_ips"].update(current_ips)
            results["techniques_used"].append("current_dns")
            results["metadata"]["current_dns"] = list(current_ips)

        # Technique 2: Removed (stub)

        # Technique 3: SSL certificate analysis
        cert_ips = self._extract_ips_from_ssl_cert(domain)
        if cert_ips:
            results["discovered_ips"].update(cert_ips)
            results["techniques_used"].append("ssl_certificate")
            results["metadata"]["ssl_certificate_ips"] = list(cert_ips)

        # Technique 4: Subdomain enumeration
        subdomains = self._enumerate_subdomains(domain)
        for subdomain in subdomains:
            sub_ips = self._resolve_dns(subdomain)
            if sub_ips:
                results["discovered_ips"].update(sub_ips)
        if subdomains:
            results["techniques_used"].append("subdomain_enumeration")
            results["metadata"]["subdomains"] = list(subdomains)[:10]

        # Technique 5: Removed (stub)

        # Technique 6: Reverse DNS lookup
        reverse_ips = self._reverse_dns_lookup(domain)
        if reverse_ips:
            results["discovered_ips"].update(reverse_ips)
            results["techniques_used"].append("reverse_dns")
            results["metadata"]["reverse_dns"] = list(reverse_ips)

        # Technique 7: Removed (stub)

        # Technique 8: Mail server lookup (often less protected)
        mail_ips = self._get_mail_server_ips(domain)
        if mail_ips:
            results["discovered_ips"].update(mail_ips)
            results["techniques_used"].append("mail_server_lookup")
            results["metadata"]["mail_ips"] = list(mail_ips)

        # Technique 9: Removed (stub)

        # Rank origin candidates
        results["origin_candidates"] = self._rank_origin_candidates(
            list(results["discovered_ips"]),
            domain
        )

        # Calculate confidence based on techniques used
        results["confidence"] = min(len(results["techniques_used"]) / 9.0, 1.0)
        results["discovered_ips"] = list(results["discovered_ips"])

        return results

    def _resolve_dns(self, domain: str) -> Set[str]:
        """Resolve domain to IPs"""
        ips = set()
        try:
            # Try multiple record types
            for record_type in ['A', 'AAAA']:
                try:
                    result = socket.getaddrinfo(
                        domain, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
                    for entry in result:
                        ip = entry[4][0]
                        if ip not in ['127.0.0.1', '::1']:
                            ips.add(ip)
                except Exception as _e:
                    import logging
                    logging.getLogger(__name__).debug(
                        f'Swallowed exception in origin_discovery.py: {_e}')
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in origin_discovery.py: {_e}')

        return ips

    def _get_historical_dns(self, domain: str) -> Set[str]:
        """
        Retrieve historical DNS records
        In real implementation, would query SecurityTrails, VirusTotal DNS API, etc.
        """
        ips = set()

        # Simulate historical records that might be old origin IPs
        # Real implementation would query actual DNS history services
        try:
            # Attempt to find older A records
            # In practice, would use SecurityTrails API, etc.
            pass
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in origin_discovery.py: {_e}')

        return ips

    def _extract_ips_from_ssl_cert(self, domain: str) -> Set[str]:
        """Extract IPs from SSL certificate SAN"""
        ips = set()

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # Extract subject alternative names
                    if 'subjectAltName' in cert:
                        for alt_name in cert['subjectAltName']:
                            if alt_name[0] == 'IP Address':
                                ips.add(alt_name[1])

                    # Extract issuer info (sometimes contains origin hints)
                    dict(x[0] for x in cert.get('subject', []))
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in origin_discovery.py: {_e}')

        return ips

    def _enumerate_subdomains(self, domain: str) -> Set[str]:
        """Enumerate common subdomains"""
        subdomains = set()

        common_subs = [
            "api", "admin", "internal", "dev", "test", "staging",
            "mail", "ftp", "sftp", "ssh", "vpn", "proxy",
            "cdn", "cache", "origin", "server", "backend",
            "app", "www", "web", "portal", "dashboard",
            "api-internal", "internal-api", "direct", "origin-server",
            "static", "assets", "img", "images", "downloads",
            "logs", "monitoring", "metrics", "analytics"
        ]

        for sub in common_subs:
            full_subdomain = f"{sub}.{domain}"
            try:
                # Try to resolve each subdomain
                ips = self._resolve_dns(full_subdomain)
                if ips:
                    subdomains.add(full_subdomain)
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f'Swallowed exception in origin_discovery.py: {_e}')

        return subdomains

    def _get_asn_ips(self, domain: str) -> Set[str]:
        """
        Get IP ranges from ASN (Autonomous System Number)
        Would use BGP data, WHOIS, or Shodan
        """
        ips = set()

        try:
            # In real implementation, would:
            # 1. Query Shodan: "ASN:AS1234"
            # 2. Query Censys
            # 3. Query Team Cymru
            # This is a placeholder for the actual logic
            pass
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in origin_discovery.py: {_e}')

        return ips

    def _reverse_dns_lookup(self, domain: str) -> Set[str]:
        """Reverse DNS lookup to find related IPs"""
        ips = set()

        try:
            # Get current IP
            current_ip = list(self._resolve_dns(domain))[
                0] if self._resolve_dns(domain) else None

            if current_ip:
                # Try to reverse lookup
                try:
                    reverse_name = socket.gethostbyaddr(current_ip)
                    # Extract IPs from reverse lookup
                    if reverse_name[1]:  # Alias list
                        for alias in reverse_name[1]:
                            resolved = self._resolve_dns(alias)
                            ips.update(resolved)
                except Exception as _e:
                    import logging
                    logging.getLogger(__name__).debug(
                        f'Swallowed exception in origin_discovery.py: {_e}')
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in origin_discovery.py: {_e}')

        return ips

    def _detect_cloud_metadata(self, domain: str) -> Set[str]:
        """Detect cloud hosting and find metadata endpoints"""
        ips = set()

        # Known cloud metadata endpoint (AWS & Azure share the link-local IP;
        # GCP uses a hostname). Surfaced as a candidate for SSRF-based origin
        # probing. NOTE: ASN-based cloud detection below is not yet implemented.
        metadata_ips = {"169.254.169.254", "metadata.google.internal"}

        try:
            current_ips = self._resolve_dns(domain)
            for ip in current_ips:
                # TODO: ASN-database lookup to confirm cloud provider.
                pass
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in origin_discovery.py: {_e}')

        ips.update(metadata_ips)
        return ips

    def _get_mail_server_ips(self, domain: str) -> Set[str]:
        """Get MX record IPs (often same origin, less protected)"""
        ips = set()

        try:
            import dns.resolver
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                for mx in mx_records:
                    mx_domain = str(mx.exchange).rstrip('.')
                    mx_ips = self._resolve_dns(mx_domain)
                    ips.update(mx_ips)
            except Exception as _e:
                import logging
                logging.getLogger(__name__).warning(
                    f"Swallowed exception: {_e}")
        except ImportError:
            # dns library not available
            pass

        return ips

    def _probe_common_internal_ips(self, domain: str) -> Set[str]:
        """Probe for common internal/private IPs"""
        ips = set()

        internal_ranges = [
            ("10.0.0.0", "10.255.255.255"),
            ("172.16.0.0", "172.31.255.255"),
            ("192.168.0.0", "192.168.255.255"),
        ]
        # Common gateway / first-host addresses of each private range — the most
        # likely internal origins to probe. (Full range sweeping / timing / DNS
        # rebinding methods are not yet implemented.)
        for net_start, _ in internal_ranges:
            base = net_start.rsplit(".", 1)[0]
            ips.add(f"{base}.1")

        try:
            # TODO: timing-based and DNS-rebinding internal IP detection.
            pass
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in origin_discovery.py: {_e}')

        return ips

    def _rank_origin_candidates(
            self, ips: List[str], domain: str) -> List[Dict[str, Any]]:
        """Rank which IPs are most likely the origin server"""
        candidates = []

        for ip in ips:
            candidate = {
                "ip": ip,
                "score": 0.0,
                "indicators": []
            }

            # Score based on characteristics

            # Indicator 1: Private IP (likely internal/origin)
            if self._is_private_ip(ip):
                candidate["score"] += 0.5
                candidate["indicators"].append("private_ip")

            # Indicator 2: Different from CDN IPs
            # (would compare against known CDN ranges)
            cdn_ranges = [
                "104.16.0.0/12",  # Cloudflare
                "13.32.0.0/15",   # CloudFront
                "18.60.0.0/15",   # CloudFront
            ]
            if not self._ip_in_ranges(ip, cdn_ranges):
                candidate["score"] += 0.3
                candidate["indicators"].append("not_cdn")

            # Indicator 3: Responsive on common ports
            responsive_ports = self._test_ports(ip)
            if responsive_ports:
                candidate["score"] += 0.2 * len(responsive_ports)
                candidate["indicators"].append(f"ports_{responsive_ports}")

            # Indicator 4: Historical (old records = likely origin)
            candidate["score"] += 0.1

            candidates.append(candidate)

        # Sort by score descending
        candidates.sort(key=lambda x: x["score"], reverse=True)
        return candidates

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private range"""
        try:
            import ipaddress
            return ipaddress.ip_address(ip).is_private
        except Exception as e:
            import logging as __logging_tmp
            __logging_tmp.getLogger(__name__).error(
                f"Unhandled exception: {e}", exc_info=True)
            return False

    def _ip_in_ranges(self, ip: str, ranges: List[str]) -> bool:
        """Check if IP falls in any CIDR range"""
        try:
            import ipaddress
            ip_addr = ipaddress.ip_address(ip)
            for cidr_range in ranges:
                if ip_addr in ipaddress.ip_network(cidr_range, strict=False):
                    return True
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in origin_discovery.py: {_e}')
        return False

    def _test_ports(self, ip: str, ports: List[int] = None) -> List[int]:
        """Test which ports are open on origin IP"""
        if ports is None:
            ports = [80, 443, 8080, 8443, 3000, 5000, 9000]

        responsive = []

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    responsive.append(port)
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f'Swallowed exception in origin_discovery.py: {_e}')

        return responsive

    def test_origin_connection(
            self, origin_ip: str, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Test if a candidate IP is the real origin behind the WAF.

        P5-5 (ORIGIN-STUBS): the old check set ``bypass_viable=True`` the moment
        ANY bytes came back from the IP — but a random server, a default nginx
        page, or the CDN itself answers on that IP too. recon_agent then adopts
        that IP as ``waf_bypass_url``, ADDS IT TO ENGAGEMENT SCOPE, and retargets
        exploitation — so a wrong IP meant attacking the wrong host. Now the IP is
        a confirmed origin ONLY when a direct connection serves the SAME
        application as the WAF-fronted domain (high-similarity differential via
        the P5-6 ``test_origin_connection`` proof method, gated by is_proven).
        Merely reachable but not-the-same-app is a LEAD (``reachable=True``,
        ``bypass_viable=False``).
        """
        result = {
            "ip": origin_ip,
            "domain": domain,
            "port": port,
            "reachable": False,
            "ssl_valid": False,
            "headers_received": {},
            "bypass_viable": False,
        }

        origin_body = self._fetch_origin_response(origin_ip, domain, port, result)
        if not origin_body:
            return result  # not reachable / no usable app response → not viable

        from intelligence.waf_bypass.technique import confirmed_bypass
        control_body = self._fetch_fronted_response(domain)
        result["bypass_viable"] = confirmed_bypass(
            self._origin_bypass_evidence(control_body, origin_body, origin_ip, domain))
        return result

    def _fetch_origin_response(self, origin_ip: str, domain: str, port: int,
                               result: Dict[str, Any]) -> str:
        """Raw GET to the candidate origin IP with the real Host header. Populates
        result[reachable]/[ssl_valid]/[headers_received] and returns the response
        BODY (''; on any failure). Split out so the proof gating is unit-testable."""
        try:
            import ssl
            import time

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((origin_ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    result["reachable"] = True
                    result["ssl_valid"] = True
                    # GET (not HEAD) so we get a BODY to compare against the
                    # fronted app — sameness is what proves this is the origin.
                    ssock.sendall(
                        f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode())

                    response = b""
                    start_recv = time.time()
                    while time.time() - start_recv <= 5.0:
                        try:
                            ssock.settimeout(1.0)
                            chunk = ssock.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                            if len(response) > 200000:
                                break
                        except socket.timeout:
                            continue
                        except Exception:
                            break

                    raw = response.decode('utf-8', errors='ignore')
                    head, _, body = raw.partition('\r\n\r\n')
                    for line in head.split('\r\n'):
                        if ':' in line:
                            key, val = line.split(':', 1)
                            result["headers_received"][key.strip()] = val.strip()
                    return body
        except Exception as e:
            result["error"] = str(e)
            return ""

    def _fetch_fronted_response(self, domain: str) -> str:
        """Fetch the WAF-fronted domain's response body (the control/baseline the
        origin must match). '' on failure — which yields no proof (safe)."""
        try:
            import requests
            r = requests.get(f"https://{domain}/", timeout=8, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"})
            return r.text or ""
        except Exception as e:
            import logging
            logging.getLogger(__name__).debug(
                f"fronted baseline fetch failed for {domain}: {e}")
            return ""

    def _origin_bypass_evidence(self, fronted_body: str, origin_body: str,
                                origin_ip: str, domain: str):
        """Build the origin-reachability Evidence via the P5-6 registered proof
        method (high-similarity artifact). Returns Evidence|None; is_proven only
        when the direct-origin body matches the fronted app (>=0.9 similarity)."""
        from core.proof import ProofRegistry, ProofContext
        return ProofRegistry.build("test_origin_connection", ProofContext(
            control_response=fronted_body or "",
            test_response=origin_body or "",
            command=f"curl --resolve {domain}:443:{origin_ip} https://{domain}/",
            notes=f"direct origin {origin_ip} vs WAF-fronted {domain}",
        ))
