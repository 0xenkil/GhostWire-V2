"""
Dynamic PoC Customizer
──────────────────────
Analyzes recon data to customize PoC templates with:
- Actual discovered endpoints (not hardcoded)
- Target-specific technology stacks
- Framework-specific verification logic
- Real ports/services found during reconnaissance
"""

import json
import re


class PoCCustomizer:
    """Customizes PoC templates based on recon data."""

    def __init__(self, engagement_id: str, state_store, logger):
        self.engagement_id = engagement_id
        self.store = state_store
        self.log = logger

    def customize_poc_params(
            self, target: str, vuln_type: str, finding_detail: str) -> dict:
        """
        Analyze target and customize PoC parameters.
        Returns dict with: paths, endpoints, headers, frameworks, ports, services, etc.
        """
        # Get recon data from state store
        recon_data = self.store.get_phase_data(
            self.engagement_id, "recon") or {}

        profile = {
            "target": target,
            "vuln_type": vuln_type,
            "frameworks": self._detect_frameworks(recon_data),
            "hosting_provider": self._detect_hosting(recon_data),
            "discovered_endpoints": self._extract_endpoints(recon_data),
            "discovered_ports": self._extract_ports(recon_data),
            "discovered_services": self._extract_services(recon_data),
            "cms_type": self._detect_cms(recon_data),
            "response_headers": self._extract_headers(recon_data),
            "waf_present": recon_data.get("waf_fingerprint") is not None,
            "waf_type": recon_data.get("waf_fingerprint", {}).get("type", "unknown"),
        }

        # Generate customized params based on profile and vulnerability type
        if "disclosure" in vuln_type.lower() or "header" in vuln_type.lower():
            return self._customize_disclosure_poc(profile, recon_data)

        elif "misconfiguration" in vuln_type.lower() or "debug" in vuln_type.lower():
            return self._customize_misconfig_poc(profile, recon_data)

        elif "traversal" in vuln_type.lower() or "path" in vuln_type.lower():
            return self._customize_traversal_poc(profile, recon_data)

        elif "ssrf" in vuln_type.lower():
            return self._customize_ssrf_poc(profile, recon_data)

        elif "redirect" in vuln_type.lower():
            return self._customize_redirect_poc(profile, recon_data)

        else:
            # Default customization
            return {
                "target": target,
                "endpoints": profile["discovered_endpoints"][:5] or ["/"],
                "headers_to_check": profile["response_headers"],
                "framework_context": profile["frameworks"],
                "hosting_context": profile["hosting_provider"],
            }

    # ──────────────────────────────────────────────────────────────────────
    # DISCLOSURE/HEADER CUSTOMIZATION
    # ──────────────────────────────────────────────────────────────────────

    def _customize_disclosure_poc(
            self, profile: dict, recon_data: dict) -> dict:
        """
        Customize disclosure PoC based on:
        - Detected frameworks (WordPress, Django, Flask, etc)
        - Hosting provider (Vercel, Heroku, AWS, etc)
        - Known technologies in response headers
        """
        framework = profile["frameworks"][0] if profile["frameworks"] else "unknown"
        hosting = profile["hosting_provider"]

        # Headers to check based on framework
        headers_to_check = {
            # WP typically uses these
            "wordpress": ["Server", "X-Powered-By", "Link"],
            "django": ["Server", "X-Powered-By", "X-Frame-Options", "X-Content-Type-Options"],
            "flask": ["Server", "X-Powered-By"],
            "aspnet": ["Server", "X-Aspnet-Version", "X-Runtime"],
            "php": ["Server", "X-Powered-By"],
            "nodejs": ["Server", "X-Powered-By"],
            "vercel": ["Server", "Via", "X-Vercel"],  # Vercel-specific
            # But behind WAF usually
            "cloudflare": ["Server", "Cf-Ray", "Cf-Cache-Status"],
            "unknown": ["Server", "X-Powered-By", "X-Version", "Via", "X-Generator"],
        }

        # Error paths that expose tech stack (framework-specific)
        error_paths = {
            "wordpress": ["/wp-admin/", "/wp-includes/", "/wp-content/plugins/"],
            "django": ["/admin/", "/static/admin/", "/__debug__/"],
            "flask": ["/admin/", "/api/", "/static/"],
            "aspnet": ["/App_Data/", "/bin/", "/web.config"],
            "php": ["/index.php", "/config.php", "/admin.php"],
            "nodejs": ["/api/", "/admin/", "/assets/"],
            "unknown": ["/", "/admin/", "/api/", "/debug/"],
        }

        return {
            "target": profile["target"],
            "headers_to_check": headers_to_check.get(framework.lower(), headers_to_check["unknown"]),
            "error_paths": error_paths.get(framework.lower(), error_paths["unknown"]),
            "framework": framework,
            "hosting": hosting,
            "endpoints_to_test": profile["discovered_endpoints"][:5] or ["/"],
            "reason": f"Detected {framework} framework on {hosting}",
        }

    # ──────────────────────────────────────────────────────────────────────
    # MISCONFIGURATION CUSTOMIZATION
    # ──────────────────────────────────────────────────────────────────────

    def _customize_misconfig_poc(
            self, profile: dict, recon_data: dict) -> dict:
        """
        Customize misconfig PoC to test actual discovered endpoints.
        Don't test random paths - test what we found.
        """
        framework = profile["frameworks"][0] if profile["frameworks"] else "unknown"

        # Framework-specific debug/admin endpoints
        debug_endpoints = {
            "django": ["/admin/", "/__debug__/", "/api/", "/graphql"],
            "flask": ["/admin/", "/_debug/", "/metrics/"],
            "aspnet": ["/Admin.aspx", "/Debug.aspx", "/Health"],
            "nodejs": ["/admin/", "/api/", "/debug", "/metrics"],
            "wordpress": ["/wp-admin/", "/wp-json/", "/xmlrpc.php"],
            "unknown": ["/admin/", "/api/", "/debug/", "/metrics/"],
        }

        # Use discovered endpoints first, then add framework-specific ones
        endpoints_to_test = profile["discovered_endpoints"][:10]
        if not endpoints_to_test:
            endpoints_to_test = debug_endpoints.get(
                framework.lower(), debug_endpoints["unknown"])
        else:
            # Combine discovered + framework-specific
            framework_eps = debug_endpoints.get(framework.lower(), [])
            endpoints_to_test = list(
                set(endpoints_to_test + framework_eps))[:15]

        return {
            "target": profile["target"],
            "endpoints_to_test": endpoints_to_test,
            "debug_indicators": ["error", "traceback", "debug", "exception", "warning", "Notice"],
            "framework": framework,
            "reason": f"Testing {framework} for debug/admin access",
        }

    # ──────────────────────────────────────────────────────────────────────
    # TRAVERSAL CUSTOMIZATION
    # ──────────────────────────────────────────────────────────────────────

    def _customize_traversal_poc(
            self, profile: dict, recon_data: dict) -> dict:
        """
        Customize traversal PoC based on detected services/OS.
        Test framework-specific config files, not just /etc/passwd.
        """
        framework = profile["frameworks"][0] if profile["frameworks"] else "unknown"
        hosting = profile["hosting_provider"].lower()

        # Framework-specific config files to target
        config_files = {
            "wordpress": ["wp-config.php", "wp-config.php.bak", "wp-config.php~"],
            "django": ["settings.py", "manage.py", ".env"],
            "flask": ["config.py", ".env", "instance/config.py"],
            "aspnet": ["web.config", "web.config.bak", "appsettings.json"],
            "nodejs": ["package.json", ".env", "config.json", "config.js"],
            "php": ["config.php", ".env", "config.ini"],
            "unknown": [".env", "config.php", "web.config", ".git/config"],
        }

        # Linux files (universal)
        linux_files = ["/etc/passwd", "/etc/shadow", "/etc/hosts"]

        # Cloud-specific files (for Vercel, Heroku, etc)
        cloud_files = {
            "vercel": [".vercelignore", ".env.local", "vercel.json"],
            "heroku": ["Procfile", "runtime.txt"],
            "aws": [".aws/credentials", ".aws/config"],
            "gcp": [".gcp/credentials.json"],
        }

        files_to_test = (
            config_files.get(framework.lower(), config_files["unknown"]) +
            linux_files +
            cloud_files.get(hosting, [])
        )

        return {
            "target": profile["target"],
            "files_to_test": files_to_test[:20],  # Limit to 20 files
            "traversal_patterns": ["../", "..\\", "....//", "....\\\\", "%2e%2e/"],
            "framework": framework,
            "hosting": hosting,
            "reason": f"Testing {framework} on {hosting} for file traversal",
        }

    # ──────────────────────────────────────────────────────────────────────
    # SSRF CUSTOMIZATION
    # ──────────────────────────────────────────────────────────────────────

    def _customize_ssrf_poc(self, profile: dict, recon_data: dict) -> dict:
        """
        Customize SSRF PoC based on discovered services and environment.
        Check for actual metadata endpoints, internal services we found.
        """
        # Discovered internal services from port scan
        internal_services = profile["discovered_services"]

        # Cloud metadata endpoints to try (based on hosting provider)
        hosting = profile["hosting_provider"].lower()
        metadata_endpoints = {
            "aws": [
                "169.254.169.254/latest/meta-data/iam/security-credentials/",
                "169.254.169.254/latest/user-data",
            ],
            "gcp": [
                "169.254.169.254/computeMetadata/v1/",
                "metadata.google.internal/computeMetadata/v1/",
            ],
            "azure": [
                "169.254.169.254/metadata/instance?api-version=2021-02-01",
            ],
            "vercel": [
                "169.254.169.254/latest/meta-data/iam/security-credentials/",  # Still AWS underneath
            ],
            "unknown": [
                "169.254.169.254/latest/meta-data/",  # Try AWS first
                "169.254.169.254/computeMetadata/",  # Then GCP
            ],
        }

        endpoints_to_target = metadata_endpoints.get(
            hosting, metadata_endpoints["unknown"])

        # Combine with discovered internal services
        if internal_services:
            endpoints_to_target += [
                f"http://{svc}" for svc in internal_services[:5]]

        return {
            "target": profile["target"],
            "metadata_endpoints": endpoints_to_target,
            "internal_services": internal_services,
            "hosting": hosting,
            "reason": f"Testing SSRF for {hosting} metadata access",
        }

    # ──────────────────────────────────────────────────────────────────────
    # REDIRECT CUSTOMIZATION
    # ──────────────────────────────────────────────────────────────────────

    def _customize_redirect_poc(self, profile: dict, recon_data: dict) -> dict:
        """
        Customize redirect PoC to test discovered redirects + new targets.
        """
        framework = profile["frameworks"][0] if profile["frameworks"] else "unknown"

        # Common redirect endpoints by framework
        redirect_endpoints = {
            "wordpress": ["/", "/wp-login.php", "/wp-admin/"],
            "django": ["/", "/admin/", "/accounts/login/"],
            "nodejs": ["/", "/login", "/auth"],
            "unknown": ["/", "/login", "/admin/"],
        }

        test_redirects = redirect_endpoints.get(
            framework.lower(), redirect_endpoints["unknown"])

        # Add discovered endpoints that likely redirect
        test_redirects += profile["discovered_endpoints"][:5]

        return {
            "target": profile["target"],
            "endpoints_to_test": list(set(test_redirects)),
            "redirect_destinations_to_try": [
                "https://evil.com/",
                "https://attacker.com/",
                "javascript:alert(1)",
                "data:text/html,<img src=x onerror=alert(1)>",
            ],
            "framework": framework,
            "reason": f"Testing redirect vulnerabilities on {framework}",
        }

    # ──────────────────────────────────────────────────────────────────────
    # DETECTION HELPERS
    # ──────────────────────────────────────────────────────────────────────

    def _detect_frameworks(self, recon_data: dict) -> list:
        """Detect framework from recon data."""
        frameworks = []

        # Check AI recon results
        for key, value in recon_data.items():
            if isinstance(value, dict):
                text = json.dumps(value).lower()
            elif isinstance(value, str):
                text = value.lower()
            else:
                continue

            if "wordpress" in text or "wp-" in text:
                frameworks.append("WordPress")
            if "django" in text or "python" in text:
                frameworks.append("Django")
            if "flask" in text:
                frameworks.append("Flask")
            if "laravel" in text or "php" in text:
                frameworks.append("Laravel")
            if "rails" in text or "ruby" in text:
                frameworks.append("Rails")
            if "express" in text or "node" in text:
                frameworks.append("NodeJS")
            if "asp.net" in text or "aspnet" in text:
                frameworks.append("ASP.NET")
            if "vercel" in text:
                frameworks.append("Vercel")

        return list(set(frameworks)) or ["Unknown"]

    def _detect_hosting(self, recon_data: dict) -> str:
        """Detect hosting provider."""
        whois = recon_data.get("whois", {})
        if isinstance(whois, dict):
            whois.get("registrar", "").lower()
        else:
            pass

        # Check for hosting indicators
        all_text = json.dumps(recon_data).lower()

        if "vercel" in all_text:
            return "Vercel"
        if "heroku" in all_text:
            return "Heroku"
        if "netlify" in all_text:
            return "Netlify"
        if "aws" in all_text or "amazon" in all_text:
            return "AWS"
        if "azure" in all_text or "microsoft" in all_text:
            return "Azure"
        if "gcp" in all_text or "google" in all_text:
            return "GCP"
        if "cloudflare" in all_text:
            return "Cloudflare"
        if "digitalocean" in all_text:
            return "DigitalOcean"
        if "linode" in all_text:
            return "Linode"

        return "Unknown"

    def _detect_cms(self, recon_data: dict) -> str:
        """Detect CMS."""
        all_text = json.dumps(recon_data).lower()

        if "wordpress" in all_text or "wp-" in all_text:
            return "WordPress"
        if "drupal" in all_text:
            return "Drupal"
        if "joomla" in all_text:
            return "Joomla"
        if "magento" in all_text:
            return "Magento"

        return "Unknown"

    def _extract_endpoints(self, recon_data: dict) -> list:
        """Extract discovered endpoints from recon data."""
        endpoints = []

        # Look for URL patterns in recon results
        for key, value in recon_data.items():
            if isinstance(value, str):
                # Find URLs and paths
                for match in re.finditer(
                        r'https?://[^\s"\'<>]+(?P<path>/[^\s"\'<>]*)?', value):
                    path = match.group("path") or "/"
                    endpoints.append(path)

                # Find paths in text
                path_matches = re.findall(r'(/[a-zA-Z0-9/_\-\.]*)', value)
                endpoints.extend(path_matches)

        # Remove duplicates and empty strings
        endpoints = list(set(e for e in endpoints if e and e != "/"))
        return endpoints[:20]  # Limit to 20

    def _extract_ports(self, recon_data: dict) -> list:
        """Extract discovered ports."""
        ports = []
        nmap = recon_data.get("nmap", {})
        if isinstance(nmap, dict):
            hosts = nmap.get("hosts", [])
            for host in hosts:
                ports_data = host.get("ports", [])
                for port in ports_data:
                    ports.append(port.get("port"))

        return [p for p in ports if p]

    def _extract_services(self, recon_data: dict) -> list:
        """Extract discovered services."""
        services = []
        nmap = recon_data.get("nmap", {})
        if isinstance(nmap, dict):
            hosts = nmap.get("hosts", [])
            for host in hosts:
                ports_data = host.get("ports", [])
                for port in ports_data:
                    service = port.get("service", {})
                    if isinstance(service, dict):
                        name = service.get("name")
                        if name:
                            services.append(name)

        return list(set(services))

    def _extract_headers(self, recon_data: dict) -> dict:
        """Extract response headers from recon."""
        headers = {}

        # Look for header patterns in recon data
        for key, value in recon_data.items():
            if isinstance(value, dict) and "headers" in value:
                headers.update(value["headers"])

        return headers
