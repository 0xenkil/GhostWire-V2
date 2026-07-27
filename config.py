from config_thresholds import (
    VPS_ZOMBIE_AGE_MINUTES, VPS_DISK_WARN_PCT, VPS_DISK_ABORT_PCT,
    VPS_MEM_LOW_MB, VPS_HEALTH_CHECK_TIMEOUT, MAX_VPS_LOAD,
    WAF_DELAY_BETWEEN_REQUESTS, WAF_DELAY_SHORT, WAF_DELAY_MEDIUM, WAF_DELAY_LONG,
    SSH_RECONNECT_DELAY, SSH_STREAM_POLL_DELAY, SSH_RESILIENT_PID_WAIT,
    SSH_RESILIENT_POLL_INTERVAL, SSH_RESILIENT_ERROR_WAIT
)
from config_paths import (
    RULES_DIR,
)
from config_backends import (
    WSL_DISTRO, VPS_USERNAME, VPS_KEY_FILE,
)
from dotenv import load_dotenv
import json
from core.config_loader import get_config, load_yaml_config

load_dotenv()

# ── Import Modular Configs ───────────────────────────────────

# Alias for backward compatibility in downstream modules
# (remote_executor.py, etc)
VPS_USER = VPS_USERNAME
VPS_KEY_PATH = VPS_KEY_FILE


# ── AI Backend ──────────────────────────────────────────────
AI_BACKEND = get_config(
    "general",
    "agent_defaults.ai_backend",
    "groq",
    "AI_BACKEND")
OLLAMA_MODEL = get_config(
    "backends",
    "ai_backends.ollama.model",
    "huihui_ai/gemma-4-abliterated:e4b-q8_0",
    "OLLAMA_MODEL")

# ── Remote VPS / WSL Settings ─────────────────────
USE_REMOTE_VPS = get_config(
    "general",
    "network.use_remote_vps",
    False,
    "USE_REMOTE_VPS")

# Automatic install approval for AI-suggested installs. Defaults to True so the
# autonomous engine can install tools the AI needs (apt/pip only, package names
# validated, apt simulated first). Set security.auto_approve_installs /
# AUTO_APPROVE_INSTALLS to false to require manual approval.
AUTO_APPROVE_INSTALLS = get_config(
    "general",
    "security.auto_approve_installs",
    True,
    "AUTO_APPROVE_INSTALLS")

# WSL Pre-flight Check Availability Instead of VPS SSH Gate
# If USE_WSL is active, verify WSL availability (moved to runtime /
# main.py check for safety)


def verify_wsl_availability() -> bool:
    import subprocess
    try:
        if WSL_DISTRO:
            res = subprocess.run(["wsl",
                                  "-d",
                                  WSL_DISTRO,
                                  "-e",
                                  "bash",
                                  "-c",
                                  "echo OK"],
                                 capture_output=True,
                                 text=True,
                                 timeout=15)
        else:
            res = subprocess.run(["wsl",
                                  "-e",
                                  "bash",
                                  "-c",
                                  "echo OK"],
                                 capture_output=True,
                                 text=True,
                                 timeout=15)
        return res.returncode == 0 and "OK" in res.stdout
    except Exception as e:
        import logging as __logging_tmp
        __logging_tmp.getLogger(__name__).error(
            f"Unhandled exception: {e}", exc_info=True)
        return False


# ── Resilience / Anti-Block Settings ────────────────────────
POST_HEAVY_SCAN_COOLDOWN = get_config(
    "general",
    "resilience.post_heavy_scan_cooldown",
    90,
    "POST_HEAVY_SCAN_COOLDOWN")
TLS_BREAKER_BACKOFF_SECS = get_config(
    "general",
    "resilience.tls_breaker_backoff_secs",
    60,
    "TLS_BREAKER_BACKOFF_SECS")
NUCLEI_RATE_LIMIT_DEFAULT = get_config(
    "general",
    "resilience.nuclei_rate_limit_default",
    40,
    "NUCLEI_RATE_LIMIT_DEFAULT")
NUCLEI_RATE_LIMIT_WAF = get_config(
    "general",
    "resilience.nuclei_rate_limit_waf",
    15,
    "NUCLEI_RATE_LIMIT_WAF")

NETWORK_UNFIXABLE_EXITS = set(
    get_config(
        "general", "resilience.network_unfixable_exits", [
            3, 6, 7, 28, 35, 52, 56], "NETWORK_UNFIXABLE_EXITS"))

# VPS health thresholds
VPS_DISK_WARN_PCT = get_config(
    "general",
    "vps_health.disk_warn_pct",
    VPS_DISK_WARN_PCT,
    "VPS_DISK_WARN_PCT")
VPS_DISK_ABORT_PCT = get_config(
    "general",
    "vps_health.disk_abort_pct",
    VPS_DISK_ABORT_PCT,
    "VPS_DISK_ABORT_PCT")
VPS_MEM_LOW_MB = get_config(
    "general",
    "vps_health.mem_low_mb",
    VPS_MEM_LOW_MB,
    "VPS_MEM_LOW_MB")
VPS_ZOMBIE_AGE_MINUTES = get_config(
    "general",
    "vps_health.zombie_age_minutes",
    VPS_ZOMBIE_AGE_MINUTES,
    "VPS_ZOMBIE_AGE_MINUTES")
VPS_HEALTH_CHECK_TIMEOUT = get_config(
    "general",
    "vps_health.health_check_timeout",
    VPS_HEALTH_CHECK_TIMEOUT,
    "VPS_HEALTH_CHECK_TIMEOUT")
MAX_VPS_LOAD = get_config(
    "general",
    "vps_health.max_vps_load",
    MAX_VPS_LOAD,
    "MAX_VPS_LOAD")

# WAF request delays
WAF_DELAY_BETWEEN_REQUESTS = get_config(
    "general",
    "resilience.waf_delay_between_requests",
    WAF_DELAY_BETWEEN_REQUESTS,
    "WAF_DELAY_BETWEEN_REQUESTS")
WAF_DELAY_SHORT = get_config(
    "general",
    "resilience.waf_delay_short",
    WAF_DELAY_SHORT,
    "WAF_DELAY_SHORT")
WAF_DELAY_MEDIUM = get_config(
    "general",
    "resilience.waf_delay_medium",
    WAF_DELAY_MEDIUM,
    "WAF_DELAY_MEDIUM")
WAF_DELAY_LONG = get_config(
    "general",
    "resilience.waf_delay_long",
    WAF_DELAY_LONG,
    "WAF_DELAY_LONG")

# SSH timings
SSH_RECONNECT_DELAY = get_config(
    "general",
    "network.ssh_reconnect_delay",
    SSH_RECONNECT_DELAY,
    "SSH_RECONNECT_DELAY")
SSH_STREAM_POLL_DELAY = get_config(
    "general",
    "network.ssh_stream_poll_delay",
    SSH_STREAM_POLL_DELAY,
    "SSH_STREAM_POLL_DELAY")
SSH_RESILIENT_PID_WAIT = get_config(
    "general",
    "resilience.ssh_resilient_pid_wait",
    SSH_RESILIENT_PID_WAIT,
    "SSH_RESILIENT_PID_WAIT")
SSH_RESILIENT_POLL_INTERVAL = get_config(
    "general",
    "resilience.ssh_resilient_poll_interval",
    SSH_RESILIENT_POLL_INTERVAL,
    "SSH_RESILIENT_POLL_INTERVAL")
SSH_RESILIENT_ERROR_WAIT = get_config(
    "general",
    "resilience.ssh_resilient_error_wait",
    SSH_RESILIENT_ERROR_WAIT,
    "SSH_RESILIENT_ERROR_WAIT")

# Rate limiting
RATE_LIMIT_INITIAL_BACKOFF = get_config(
    "general",
    "resilience.rate_limit_initial_backoff",
    10,
    "RATE_LIMIT_INITIAL_BACKOFF")

# DNS fallback servers
DNS_FALLBACK_SERVERS = get_config(
    "general", "network.dns_fallback_servers", [
        "1.1.1.1", "8.8.8.8", "9.9.9.9"], "DNS_FALLBACK_SERVERS")

TOOL_RETRY_COUNT = get_config(
    "general",
    "resilience.tool_retry_count",
    2,
    "TOOL_RETRY_COUNT")
TOOL_RETRY_DELAY = get_config(
    "general",
    "resilience.tool_retry_delay",
    1,
    "TOOL_RETRY_DELAY")

# Ollama Specifics
OLLAMA_NUM_THREAD = get_config(
    "backends",
    "ai_backends.ollama.num_thread",
    4,
    "OLLAMA_NUM_THREAD")
OLLAMA_KEEP_ALIVE = get_config(
    "backends",
    "ai_backends.ollama.keep_alive",
    "0",
    "OLLAMA_KEEP_ALIVE")
OLLAMA_NUM_CTX = get_config(
    "backends",
    "ai_backends.ollama.num_ctx",
    2048,
    "OLLAMA_NUM_CTX")

# ── Paths ────────────────────────────────────────────────────
LOG_LEVEL = get_config(
    "general",
    "agent_defaults.log_level",
    "INFO",
    "LOG_LEVEL")

# ── Legal / Scope ────────────────────────────────────────────
REQUIRE_WRITTEN_CONSENT = get_config(
    "general",
    "agent_defaults.require_written_consent",
    True,
    "REQUIRE_WRITTEN_CONSENT")

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
        CURL_TLS_FLAGS = " ".join(
            [f'-H "{k}: {v}"' for k, v in STEALTH_HEADERS.items()])
except Exception as e:
    import logging as __logging_tmp
    __logging_tmp.getLogger(__name__).error(
        f"Unhandled exception: {e}", exc_info=True)
    CURL_TLS_FLAGS = " ".join(
        [f'-H "{k}: {v}"' for k, v in STEALTH_HEADERS.items()])

USE_PROXY = get_config("general", "network.use_proxy", False, "USE_PROXY")

# ── Recon Optimization ──────────────────────────────────────
SPA_RECON_LEVEL = get_config(
    "general",
    "recon.spa_recon_level",
    "high",
    "SPA_RECON_LEVEL")

PROXY_PORT = 8080
