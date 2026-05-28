import os
from dotenv import load_dotenv
from pathlib import Path
import sys
import json
from core.config_loader import get_config, load_yaml_config

load_dotenv()

# ── Import Modular Configs ───────────────────────────────────
from config_backends import (
    OLLAMA_BASE_URL, OLLAMA_TIMEOUT,
    GROQ_API_KEY, GROQ_API_KEY_POOL, GROQ_MODEL, GROQ_FALLBACK_MODEL,
    GOOGLE_API_KEY, GOOGLE_MODEL,
    OPENROUTER_API_KEY, OPENROUTER_MODEL,
    PROXY_URL, TOR_SOCKS_PORT, TOR_CONTROL_PORT, TOR_ENABLED,
    VPS_HOST, VPS_PORT, VPS_USERNAME, VPS_KEY_FILE, VPS_PASSWORD,
    SHODAN_API_KEY, SECURITYTRAILS_API_KEY, GITHUB_TOKEN, VIRUSTOTAL_API_KEY,
    OOB_COLLABORATOR_DOMAIN,
)

# Alias for backward compatibility in downstream modules (ssh_executor.py, etc)
VPS_USER = VPS_USERNAME
VPS_KEY_PATH = VPS_KEY_FILE

from config_paths import (
    RULES_DIR, RESULTS_DIR, TOOLS_DIR, INTEL_DIR, UTILS_DIR,
    TOOL_METRICS_FILE, WAF_DATABASE_FILE, RULE_FILES,
    get_wordlist,
    VPS_TOOL_PATH, VPS_TEMP_DIR, VPS_RESULTS_DIR,
    LOG_DIR, MAIN_LOG_FILE, ERROR_LOG_FILE, DEBUG_LOG_FILE,
    REPORT_DIR, FINDINGS_JSON,
)

from config_thresholds import (
    WAF_DELAY_BETWEEN_COMMANDS_SECS,
    TOOL_VERIFY_TIMEOUT, TOOL_INSTALL_CHECK_TIMEOUT, DB_CONNECTION_TIMEOUT,
    TOOL_VERIFY_LONG_TIMEOUT,
    MIN_FREE_DISK_MB, MIN_FREE_RAM_MB, TOOL_CLEANUP_TIMEOUT,
    VPS_ZOMBIE_AGE_MINUTES, VPS_DISK_WARN_PCT, VPS_DISK_ABORT_PCT,
    VPS_MEM_LOW_MB, VPS_HEALTH_CHECK_TIMEOUT, MAX_VPS_LOAD,
    WAF_DELAY_BETWEEN_REQUESTS, WAF_DELAY_SHORT, WAF_DELAY_MEDIUM, WAF_DELAY_LONG,
    SSH_RECONNECT_DELAY, SSH_STREAM_POLL_DELAY, SSH_RESILIENT_PID_WAIT,
    SSH_RESILIENT_POLL_INTERVAL, SSH_RESILIENT_ERROR_WAIT,
    AI_NAME_GEMINI, AI_NAME_GROQ, AI_NAME_OLLAMA, AI_NAME_OPENROUTER,
    AI_VERSION_V1BETA, AI_VERSION_V1,
    TOOL_NMAP_TIMEOUT, TOOL_MASSCAN_TIMEOUT, TOOL_NUCLEI_TIMEOUT,
    TOOL_GOBUSTER_TIMEOUT, TOOL_FFUF_TIMEOUT, TOOL_METASPLOIT_TIMEOUT,
    TOOL_WAF_TIMEOUT, TOOL_NIKTO_TIMEOUT, TOOL_CURL_TIMEOUT,
    TOOL_AI_TIMEOUT, DEFAULT_NETWORK_TIMEOUT, TOOL_DEFAULT_TIMEOUT,
    TLS_BREAKER_MAX_RETRIES, MAX_RESPONSE_SIZE, RATE_LIMIT_MAX_BACKOFF,
    HOST_MAX_TOTAL_ERRORS
)

# ── AI Backend ──────────────────────────────────────────────
AI_BACKEND = get_config("general", "agent_defaults.ai_backend", "groq", "AI_BACKEND")
OLLAMA_MODEL = get_config("backends", "ai_backends.ollama.model", "huihui_ai/gemma-4-abliterated:e4b-q8_0", "OLLAMA_MODEL")

# ── Remote VPS Settings ─────────────────────
USE_REMOTE_VPS = get_config("general", "network.use_remote_vps", False, "USE_REMOTE_VPS")

# Automatic install approval for AI-suggested installs. Default is False for safety.
AUTO_APPROVE_INSTALLS = get_config("general", "security.auto_approve_installs", False, "AUTO_APPROVE_INSTALLS")

# Fail-fast: if remote mode is on AND VPS_HOST is configured, validate SSH key exists
if USE_REMOTE_VPS and VPS_HOST:
    if not VPS_KEY_FILE and not VPS_PASSWORD:
        print("[FATAL] USE_REMOTE_VPS=true and VPS_HOST is set, but neither VPS_KEY_FILE nor VPS_PASSWORD provided")
        sys.exit(1)
    if VPS_KEY_FILE and not Path(VPS_KEY_FILE).exists():
        print(f"[FATAL] SSH key not found at: {VPS_KEY_FILE}")
        sys.exit(1)

# ── Resilience / Anti-Block Settings ────────────────────────
POST_HEAVY_SCAN_COOLDOWN = get_config("general", "resilience.post_heavy_scan_cooldown", 90, "POST_HEAVY_SCAN_COOLDOWN")
TLS_BREAKER_BACKOFF_SECS = get_config("general", "resilience.tls_breaker_backoff_secs", 60, "TLS_BREAKER_BACKOFF_SECS")
NUCLEI_RATE_LIMIT_DEFAULT = get_config("general", "resilience.nuclei_rate_limit_default", 40, "NUCLEI_RATE_LIMIT_DEFAULT")
NUCLEI_RATE_LIMIT_WAF = get_config("general", "resilience.nuclei_rate_limit_waf", 15, "NUCLEI_RATE_LIMIT_WAF")

NETWORK_UNFIXABLE_EXITS = set(get_config("general", "resilience.network_unfixable_exits", [3, 6, 7, 28, 35, 52, 56], "NETWORK_UNFIXABLE_EXITS"))

# VPS health thresholds
VPS_DISK_WARN_PCT = get_config("general", "vps_health.disk_warn_pct", VPS_DISK_WARN_PCT, "VPS_DISK_WARN_PCT")
VPS_DISK_ABORT_PCT = get_config("general", "vps_health.disk_abort_pct", VPS_DISK_ABORT_PCT, "VPS_DISK_ABORT_PCT")
VPS_MEM_LOW_MB = get_config("general", "vps_health.mem_low_mb", VPS_MEM_LOW_MB, "VPS_MEM_LOW_MB")
VPS_ZOMBIE_AGE_MINUTES = get_config("general", "vps_health.zombie_age_minutes", VPS_ZOMBIE_AGE_MINUTES, "VPS_ZOMBIE_AGE_MINUTES")
VPS_HEALTH_CHECK_TIMEOUT = get_config("general", "vps_health.health_check_timeout", VPS_HEALTH_CHECK_TIMEOUT, "VPS_HEALTH_CHECK_TIMEOUT")
MAX_VPS_LOAD = get_config("general", "vps_health.max_vps_load", MAX_VPS_LOAD, "MAX_VPS_LOAD")

# WAF request delays
WAF_DELAY_BETWEEN_REQUESTS = get_config("general", "resilience.waf_delay_between_requests", WAF_DELAY_BETWEEN_REQUESTS, "WAF_DELAY_BETWEEN_REQUESTS")
WAF_DELAY_SHORT = get_config("general", "resilience.waf_delay_short", WAF_DELAY_SHORT, "WAF_DELAY_SHORT")
WAF_DELAY_MEDIUM = get_config("general", "resilience.waf_delay_medium", WAF_DELAY_MEDIUM, "WAF_DELAY_MEDIUM")
WAF_DELAY_LONG = get_config("general", "resilience.waf_delay_long", WAF_DELAY_LONG, "WAF_DELAY_LONG")

# SSH timings
SSH_RECONNECT_DELAY = get_config("general", "network.ssh_reconnect_delay", SSH_RECONNECT_DELAY, "SSH_RECONNECT_DELAY")
SSH_STREAM_POLL_DELAY = get_config("general", "network.ssh_stream_poll_delay", SSH_STREAM_POLL_DELAY, "SSH_STREAM_POLL_DELAY")
SSH_RESILIENT_PID_WAIT = get_config("general", "resilience.ssh_resilient_pid_wait", SSH_RESILIENT_PID_WAIT, "SSH_RESILIENT_PID_WAIT")
SSH_RESILIENT_POLL_INTERVAL = get_config("general", "resilience.ssh_resilient_poll_interval", SSH_RESILIENT_POLL_INTERVAL, "SSH_RESILIENT_POLL_INTERVAL")
SSH_RESILIENT_ERROR_WAIT = get_config("general", "resilience.ssh_resilient_error_wait", SSH_RESILIENT_ERROR_WAIT, "SSH_RESILIENT_ERROR_WAIT")

# Rate limiting
RATE_LIMIT_INITIAL_BACKOFF = get_config("general", "resilience.rate_limit_initial_backoff", 10, "RATE_LIMIT_INITIAL_BACKOFF")

# DNS fallback servers
DNS_FALLBACK_SERVERS = get_config("general", "network.dns_fallback_servers", ["1.1.1.1", "8.8.8.8", "9.9.9.9"], "DNS_FALLBACK_SERVERS")

TOOL_RETRY_COUNT = get_config("general", "resilience.tool_retry_count", 2, "TOOL_RETRY_COUNT")
TOOL_RETRY_DELAY = get_config("general", "resilience.tool_retry_delay", 1, "TOOL_RETRY_DELAY")

# Ollama Specifics
OLLAMA_NUM_THREAD = get_config("backends", "ai_backends.ollama.num_thread", 4, "OLLAMA_NUM_THREAD")
OLLAMA_KEEP_ALIVE = get_config("backends", "ai_backends.ollama.keep_alive", "0", "OLLAMA_KEEP_ALIVE")
OLLAMA_NUM_CTX = get_config("backends", "ai_backends.ollama.num_ctx", 2048, "OLLAMA_NUM_CTX")

# ── Paths ────────────────────────────────────────────────────
LOG_LEVEL = get_config("general", "agent_defaults.log_level", "INFO", "LOG_LEVEL")

# ── Legal / Scope ────────────────────────────────────────────
REQUIRE_WRITTEN_CONSENT = get_config("general", "agent_defaults.require_written_consent", True, "REQUIRE_WRITTEN_CONSENT")

scope_config = load_yaml_config("scope_rules")
BLOCKED_IP_RANGES = scope_config.get("blocked_ip_ranges", [
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4"
])
ALWAYS_BLOCKED_DOMAINS = scope_config.get("always_blocked_domains", [
    "google.com", "cloudflare.com", "amazonaws.com",
    "microsoft.com", "apple.com", "facebook.com"
])

# TLS / HTTP / Stealth Flags ─────────────────────────────────
stealth_config = load_yaml_config("stealth")
STEALTH_HEADERS = stealth_config.get("stealth_headers", {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
})

# Load CURL_TLS_FLAGS from rules or build from STEALTH_HEADERS
try:
    curl_rules_path = RULES_DIR / "curl_config.json"
    if curl_rules_path.exists():
        with open(curl_rules_path, "r") as f:
            curl_config = json.load(f)["curl_stealth_config"]
        CURL_TLS_FLAGS = curl_config["curl_tls_flags_string"]
    else:
        CURL_TLS_FLAGS = " ".join([f'-H "{k}: {v}"' for k, v in STEALTH_HEADERS.items()])
except Exception:
    CURL_TLS_FLAGS = " ".join([f'-H "{k}: {v}"' for k, v in STEALTH_HEADERS.items()])

USE_PROXY = get_config("general", "network.use_proxy", False, "USE_PROXY")

# ── Recon Optimization ──────────────────────────────────────
SPA_RECON_LEVEL = get_config("general", "recon.spa_recon_level", "high", "SPA_RECON_LEVEL")

PROXY_PORT = 8080
