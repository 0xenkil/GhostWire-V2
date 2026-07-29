"""
CVE Database: Maps technologies to known exploitable vulnerabilities.
Enables evidence-driven exploit selection instead of random tool attempts.
"""

CVE_MAPPINGS = {
    # WordPress vulnerabilities
    "wordpress": {
        "5.0": {"cves": ["CVE-2019-8943", "CVE-2019-8944"], "severity": "critical"},
        "5.1": {"cves": ["CVE-2019-9787"], "severity": "high"},
        "5.2": {"cves": ["CVE-2019-16223", "CVE-2019-16224"], "severity": "high"},
        "5.3": {"cves": ["CVE-2019-16222"], "severity": "medium"},
        "5.4": {"cves": ["CVE-2020-10546"], "severity": "medium"},
        "5.5": {"cves": ["CVE-2020-10546"], "severity": "medium"},
        "5.6": {"cves": ["CVE-2020-10546"], "severity": "medium"},
        "5.7": {"cves": ["CVE-2020-11738"], "severity": "medium"},
        "5.8": {"cves": ["CVE-2021-39200", "CVE-2021-39201"], "severity": "high"},
        "generic": {
            "default_plugins": ["akismet", "jetpack", "elementor"],
            "discovery_patterns": [r"/wp-admin/", r"/wp-content/", r"/wp-includes/"],
            "exploit_types": ["plugin_upload_rce", "unauthenticated_options_exposure", "user_enumeration"]
        }
    },

    # Apache vulnerabilities
    "apache": {
        "2.4.49": {"cves": ["CVE-2021-41773"], "severity": "critical", "type": "path_traversal_rce"},
        "2.4.50": {"cves": ["CVE-2021-41773", "CVE-2021-42013"], "severity": "critical", "type": "path_traversal_rce"},
        "generic": {
            "discovery_patterns": [r"Server:\s*Apache"],
            "exploit_types": ["mod_userdir_disclosure", "trace_method_enabled", "directory_listing"]
        }
    },

    # Nginx vulnerabilities
    "nginx": {
        "generic": {
            "discovery_patterns": [r"Server:\s*nginx"],
            "exploit_types": ["alias_traversal", "header_injection", "cache_poisoning"]
        }
    },

    # PHP vulnerabilities
    "php": {
        "7.0": {"cves": ["CVE-2019-9020"], "severity": "high"},
        "7.1": {"cves": ["CVE-2019-9020"], "severity": "high"},
        "7.4": {"cves": ["CVE-2021-21240"], "severity": "high"},
        "generic": {
            "discovery_patterns": [r"X-Powered-By:\s*PHP"],
            "exploit_types": ["rfi", "lfi", "arbitrary_file_upload"]
        }
    },

    # MySQL vulnerabilities
    "mysql": {
        "5.7": {"cves": [], "severity": "medium", "notes": "Check for weak credentials"},
        "8.0": {"cves": [], "severity": "medium"},
        "generic": {
            "discovery_patterns": [r"mysql|mariadb"],
            "exploit_types": ["weak_credentials", "unauthenticated_access"]
        }
    },
}


def find_cves_for_tech(tech_name: str, version: str = None) -> list:
    """
    Find all CVEs potentially affecting a technology dynamically.
    Falls back to AI context generation if unlisted in static knowledge base.
    """
    tech_key = tech_name.lower().strip()
    results = []

    if tech_key in CVE_MAPPINGS:
        tech_data = CVE_MAPPINGS[tech_key]
        if version:
            version_key = '.'.join(str(v) for v in version.split('.')[0:2])
            if version_key in tech_data:
                results.append({"tech": tech_name, "version": version_key, **tech_data[version_key]})
        if "generic" in tech_data:
            results.append({"tech": tech_name, "version": "all", **tech_data["generic"]})
    else:
        # Fully autonomous dynamic fallback structure for AI reasoning
        results.append({
            "tech": tech_name,
            "version": version or "unknown",
            "cves": [],
            "severity": "medium",
            "exploit_types": ["generic_vulnerability_scan", "parameter_fuzzing"]
        })

    return results


def get_exploit_types_for_tech(tech_name: str) -> list:
    """Get all known exploit types for a technology."""
    tech_key = tech_name.lower().strip()
    if tech_key not in CVE_MAPPINGS:
        return []

    tech_data = CVE_MAPPINGS[tech_key]
    exploit_types = []

    for version_data in tech_data.values():
        if isinstance(version_data, dict):
            exploit_types.extend(version_data.get("exploit_types", []))

    return list(set(exploit_types))  # Deduplicate


def get_discovery_patterns(tech_name: str) -> list:
    """Get regex patterns to identify a technology."""
    tech_key = tech_name.lower().strip()
    if tech_key not in CVE_MAPPINGS:
        return []

    tech_data = CVE_MAPPINGS[tech_key]
    patterns = []

    for version_data in tech_data.values():
        if isinstance(version_data, dict):
            patterns.extend(version_data.get("discovery_patterns", []))

    return list(set(patterns))
