"""
Centralized Path Configuration
─────────────────────────────────
All filesystem paths, wordlists, databases, and directories.
Can be overridden via environment variables or .env file.
"""

import os
from pathlib import Path
from core.config_loader import get_config, load_yaml_config


# ─── Base Directories ───────────────────────────────────────────────────
RULES_DIR = Path(
    get_config(
        "paths",
        "directories.rules",
        "rules",
        "RULES_DIR"))
RESULTS_DIR = Path(
    get_config(
        "paths",
        "directories.results",
        "results",
        "RESULTS_DIR"))
TOOLS_DIR = Path(
    get_config(
        "paths",
        "directories.tools",
        "tools",
        "TOOLS_DIR"))
INTEL_DIR = Path(
    get_config(
        "paths",
        "directories.intelligence",
        "intelligence",
        "INTEL_DIR"))
UTILS_DIR = Path(
    get_config(
        "paths",
        "directories.utils",
        "utils",
        "UTILS_DIR"))
SCRATCH_DIR = Path(
    get_config(
        "paths",
        "directories.scratch",
        "scratch",
        "SCRATCH_DIR"))
CUSTOM_TOOLS_DIR = Path(
    get_config(
        "paths", "directories.custom_tools", str(
            TOOLS_DIR / "custom_tools"), "CUSTOM_TOOLS_DIR"))

# Ensure directories exist
for d in [RULES_DIR, RESULTS_DIR, INTEL_DIR, CUSTOM_TOOLS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ─── Database & Metrics Files ───────────────────────────────────────────
TOOL_METRICS_FILE = Path(
    get_config(
        "paths", "files.tool_metrics", str(
            RESULTS_DIR / "tool_metrics.json"), "TOOL_METRICS_FILE"))
WAF_DATABASE_FILE = Path(
    get_config(
        "paths", "files.waf_database", str(
            INTEL_DIR / "waf_database.json"), "WAF_DATABASE_FILE"))
FAILURE_HISTORY_FILE = Path(
    get_config(
        "paths", "files.failure_history", str(
            INTEL_DIR / "failure_history.json"), "FAILURE_HISTORY_FILE"))

# ─── Rule Files ─────────────────────────────────────────────────────────
paths_config = load_yaml_config("paths")
RULE_FILES = paths_config.get("rule_files", {
    "exploitation": str(RULES_DIR / "exploitation.json"),
    "infrastructure": str(RULES_DIR / "infrastructure.json"),
    "recon": str(RULES_DIR / "recon.json"),
    "weaponization": str(RULES_DIR / "weaponization.json"),
})
# Convert to Path objects
RULE_FILES = {k: Path(v) for k, v in RULE_FILES.items()}

# Override any via env vars
for rule_name in RULE_FILES:
    env_var = f"RULE_{rule_name.upper()}_FILE"
    if env_var in os.environ:
        RULE_FILES[rule_name] = Path(os.getenv(env_var))

# ─── Wordlist Paths (Priority Order) ────────────────────────────────────
WORDLIST_PATHS = paths_config.get("wordlists", {}).get("local", {})
# Ensure they are Path objects
WORDLIST_PATHS = {k: [Path(p) for p in v] for k, v in WORDLIST_PATHS.items()}

# SecLists directory is fully config-driven.
DIR_SECLISTS = get_config(
    "paths",
    "wordlists.local.seclists_dir",
    "",
    "DIR_SECLISTS")


def get_wordlist(wordlist_type: str) -> Path | None:
    """Find first available wordlist of given type (LOCAL machine)."""
    if wordlist_type not in WORDLIST_PATHS:
        return None

    for path in WORDLIST_PATHS[wordlist_type]:
        if path.exists():
            return path

    return None


# ─── Wordlist URLs ────────────────────────────────────────────────────────
WORDLIST_URLS = paths_config.get("wordlist_urls", {})


# ─── WSL Wordlist Paths ────────────────────────────────────
WSL_WORDLIST_PATHS = paths_config.get(
    "wordlists",
    {}).get(
        "wsl",
        paths_config.get(
            "wordlists",
            {}).get(
                "vps",
            {}))


def get_wsl_wordlist(wordlist_type: str, wsl_executor=None) -> str | None:
    """Return the first WSL-side wordlist path for the given type."""
    if wordlist_type not in WSL_WORDLIST_PATHS:
        return None

    candidates = WSL_WORDLIST_PATHS[wordlist_type]

    if wsl_executor is None:
        return candidates[0] if candidates else None

    for path in candidates:
        try:
            ec, out, _ = wsl_executor.execute(
                f"[ -f {path} ] && echo YES || echo NO", timeout=8)
            if ec == 0 and "YES" in out:
                return path
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in config_paths.py: {_e}')
            continue

    return WSL_TEMP_DIR + "/ai_wordlist.txt"


# Alias so legacy imports of get_vps_wordlist still work after WSL migration.
# All six call-sites in base_agent.py import this name - must not raise
# AttributeError.
get_vps_wordlist = get_wsl_wordlist


# ─── WSL Paths (Replaces VPS) ───────────────────────────────────────────
WSL_TOOL_PATH = get_config(
    "paths",
    "wsl_settings.tool_path",
    get_config(
        "paths",
        "vps_settings.tool_path",
        "$HOME/go/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin",
        "VPS_TOOL_PATH"),
    "WSL_TOOL_PATH")
WSL_TEMP_DIR = get_config(
    "paths",
    "wsl_settings.temp_dir",
    get_config(
        "paths",
        "vps_settings.temp_dir",
        "~/redteam-workspace",
        "VPS_TEMP_DIR"),
    "WSL_TEMP_DIR")
WSL_RESULTS_DIR = get_config(
    "paths",
    "wsl_settings.results_dir",
    get_config(
        "paths",
        "vps_settings.results_dir",
        "~/redteam-workspace/results",
        "VPS_RESULTS_DIR"),
    "WSL_RESULTS_DIR")
THEHARVESTER_DIR = get_config(
    "paths",
    "wsl_settings.theharvester_dir",
    get_config(
        "paths",
        "vps_settings.theharvester_dir",
        "/opt/theHarvester",
        "THEHARVESTER_DIR"),
    "THEHARVESTER_DIR")

# Legacy aliases for VPS
VPS_TOOL_PATH = WSL_TOOL_PATH
VPS_TEMP_DIR = WSL_TEMP_DIR
VPS_RESULTS_DIR = WSL_RESULTS_DIR

# ─── Tor/Proxy Files ────────────────────────────────────────────────────
TOR_CONFIG_FILE = Path(
    get_config(
        "paths",
        "system_paths.tor_config",
        "/etc/tor/torrc",
        "TOR_CONFIG_FILE"))
PROXYCHAINS_CONFIG = Path(
    get_config(
        "paths",
        "system_paths.proxychains_config",
        "/etc/proxychains4.conf",
        "PROXYCHAINS_CONFIG"))

# ─── Temporary Files ────────────────────────────────────────────────────
TEMP_POC_DIR = Path(
    get_config(
        "paths",
        "system_paths.temp_poc_dir",
        str(SCRATCH_DIR),
        "TEMP_POC_DIR"))
TEMP_SCRIPT_DIR = Path(
    get_config(
        "paths",
        "system_paths.temp_script_dir",
        str(SCRATCH_DIR),
        "TEMP_SCRIPT_DIR"))

# ─── Log Files ──────────────────────────────────────────────────────────
LOG_DIR = Path(
    get_config(
        "paths", "directories.logs", str(
            RESULTS_DIR / "logs"), "LOG_DIR"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

MAIN_LOG_FILE = Path(
    get_config(
        "paths", "files.main_log", str(
            LOG_DIR / "ghostwire.log"), "MAIN_LOG_FILE"))
ERROR_LOG_FILE = Path(
    get_config(
        "paths", "files.error_log", str(
            LOG_DIR / "errors.log"), "ERROR_LOG_FILE"))
DEBUG_LOG_FILE = Path(
    get_config(
        "paths", "files.debug_log", str(
            LOG_DIR / "debug.log"), "DEBUG_LOG_FILE"))

# ─── Report Output ──────────────────────────────────────────────────────
REPORT_DIR = Path(
    get_config(
        "paths", "directories.report", str(
            RESULTS_DIR / "report"), "REPORT_DIR"))
REPORT_DIR.mkdir(parents=True, exist_ok=True)

FINDINGS_JSON = Path(
    get_config(
        "paths", "files.findings", str(
            REPORT_DIR / "findings.json"), "FINDINGS_JSON"))
HEALTH_SUMMARY_JSON = Path(
    get_config(
        "paths", "files.health_summary", str(
            REPORT_DIR / "health_summary.json"), "HEALTH_SUMMARY_JSON"))
EMERGENCY_RESULTS_JSON = Path(
    get_config(
        "paths", "files.emergency_results", str(
            REPORT_DIR / "emergency_results.json"), "EMERGENCY_RESULTS_JSON"))
