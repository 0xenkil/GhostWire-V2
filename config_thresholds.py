"""
Centralized Timeouts & Thresholds Configuration
────────────────────────────────────────────────
All timing values, retry counts, detection thresholds, and tuning parameters.
Can be overridden via environment variables or .env file.
"""

import os


# ─── Default Tool Timeouts (seconds) ────────────────────────────────────
TOOL_DEFAULT_TIMEOUT = int(os.getenv("TOOL_DEFAULT_TIMEOUT", "120"))

# Specific tool timeouts (can override defaults)
TOOL_NMAP_TIMEOUT = int(os.getenv("TOOL_NMAP_TIMEOUT", "600"))
TOOL_NUCLEI_TIMEOUT = int(os.getenv("TOOL_NUCLEI_TIMEOUT", "2400"))
TOOL_FFUF_TIMEOUT = int(os.getenv("TOOL_FFUF_TIMEOUT", "1200"))
TOOL_GOBUSTER_TIMEOUT = int(os.getenv("TOOL_GOBUSTER_TIMEOUT", "900"))
TOOL_MASSCAN_TIMEOUT = int(os.getenv("TOOL_MASSCAN_TIMEOUT", "1800"))
TOOL_NIKTO_TIMEOUT = int(os.getenv("TOOL_NIKTO_TIMEOUT", "600"))
TOOL_CURL_TIMEOUT = int(os.getenv("TOOL_CURL_TIMEOUT", "30"))
TOOL_AI_TIMEOUT = int(os.getenv("TOOL_AI_TIMEOUT", "180"))
TOOL_METASPLOIT_TIMEOUT = int(os.getenv("TOOL_METASPLOIT_TIMEOUT", "600"))
TOOL_WAF_TIMEOUT = int(os.getenv("TOOL_WAF_TIMEOUT", "120"))

# ─── TLS/Certificate Cracking ──────────────────────────────────────────
TLS_HANDSHAKE_TIMEOUT = int(os.getenv("TLS_HANDSHAKE_TIMEOUT", "10"))
TLS_BREAKER_MAX_RETRIES = int(os.getenv("TLS_BREAKER_MAX_RETRIES", "5"))
TLS_CIPHER_SUITE_TIMEOUT = int(os.getenv("TLS_CIPHER_SUITE_TIMEOUT", "2"))

# ─── Phase Timeouts ────────────────────────────────────────────────────


# ─── Per-Phase Token Budgets (W1.2 circuit breaker) ────────────────────
# Approximate token ceiling per phase. When exceeded, the phase's loop
# stops issuing new AI calls and wraps up — prevents a repair/retry storm
# from burning the entire Groq TPD on one phase. 0 = unlimited.
PHASE_TOKEN_BUDGET_RECON = int(os.getenv("PHASE_TOKEN_BUDGET_RECON", "400000"))
PHASE_TOKEN_BUDGET_EXPLOITATION = int(
    os.getenv("PHASE_TOKEN_BUDGET_EXPLOITATION", "600000"))
PHASE_TOKEN_BUDGET_DEFAULT = int(
    os.getenv("PHASE_TOKEN_BUDGET_DEFAULT", "300000"))


# ─── Retry & Backoff Configuration ────────────────────────────────────
MAX_COMMAND_RETRIES = int(os.getenv("MAX_COMMAND_RETRIES", "3"))
MAX_EXPLOIT_ATTEMPTS = int(os.getenv("MAX_EXPLOIT_ATTEMPTS", "5"))
MAX_POC_EXECUTION_RETRIES = int(os.getenv("MAX_POC_EXECUTION_RETRIES", "2"))
MAX_SELF_HEAL_RETRIES = int(os.getenv("MAX_SELF_HEAL_RETRIES", "2"))

RATE_LIMIT_BACKOFF_BASE = int(os.getenv("RATE_LIMIT_BACKOFF_BASE", "5"))
RATE_LIMIT_MAX_BACKOFF = int(os.getenv("RATE_LIMIT_MAX_BACKOFF", "120"))

# ─── Delay & Spacing ──────────────────────────────────────────────────
WAF_DELAY_BETWEEN_COMMANDS_SECS = int(
    os.getenv("WAF_DELAY_BETWEEN_COMMANDS_SECS", "3"))
POC_EXECUTION_DELAY_SECS = int(os.getenv("POC_EXECUTION_DELAY_SECS", "1"))

# ─── Payload Limits ────────────────────────────────────────────────────
MAX_RESPONSE_SIZE = int(
    os.getenv(
        "MAX_RESPONSE_SIZE", str(
            5 * 1024 * 1024)))  # 5MB
MAX_PAYLOAD_SIZE = int(
    os.getenv(
        "MAX_PAYLOAD_SIZE", str(
            1 * 1024 * 1024)))    # 1MB
MAX_COMMAND_OUTPUT_LINES = int(os.getenv("MAX_COMMAND_OUTPUT_LINES", "1000"))

# ─── Finding & Detection Thresholds ────────────────────────────────────
HIGH_CONFIDENCE_THRESHOLD = float(
    os.getenv("HIGH_CONFIDENCE_THRESHOLD", "0.75"))
MEDIUM_CONFIDENCE_THRESHOLD = float(
    os.getenv("MEDIUM_CONFIDENCE_THRESHOLD", "0.50"))
LOW_CONFIDENCE_THRESHOLD = float(os.getenv("LOW_CONFIDENCE_THRESHOLD", "0.30"))

HIGH_VALUE_SCORE_THRESHOLD = float(
    os.getenv("HIGH_VALUE_SCORE_THRESHOLD", "0.70"))
MEDIUM_VALUE_SCORE_THRESHOLD = float(
    os.getenv("MEDIUM_VALUE_SCORE_THRESHOLD", "0.50"))

WAF_BYPASS_VIABILITY_THRESHOLD = float(
    os.getenv("WAF_BYPASS_VIABILITY_THRESHOLD", "0.30"))

# ─── Port & Network Scanning ────────────────────────────────────────────
PORT_SCAN_TIMEOUT_PER_HOST = int(
    os.getenv("PORT_SCAN_TIMEOUT_PER_HOST", "120"))
PORT_SCAN_THREAD_COUNT = int(os.getenv("PORT_SCAN_THREAD_COUNT", "100"))
PORT_SCAN_MAX_PORTS = int(os.getenv("PORT_SCAN_MAX_PORTS", "10000"))

# ─── Health & VPS Thresholds ────────────────────────────────────────────
HOST_MAX_CONSECUTIVE_ERRORS = int(
    os.getenv("HOST_MAX_CONSECUTIVE_ERRORS", "3"))
HOST_MAX_TOTAL_ERRORS = int(os.getenv("HOST_MAX_TOTAL_ERRORS", "15"))
VPS_HEALTH_CHECK_INTERVAL = int(os.getenv("VPS_HEALTH_CHECK_INTERVAL", "60"))
VPS_HEALTH_CHECK_TIMEOUT = int(os.getenv("VPS_HEALTH_CHECK_TIMEOUT", "5"))

# Network error types that are considered unfixable
NETWORK_UNFIXABLE_EXIT_CODES = {3, 6, 7, 28, 35, 52, 56}

# ─── Honeypot/Tripwire Detection ────────────────────────────────────────
HONEYPOT_PORT_THRESHOLD = int(os.getenv("HONEYPOT_PORT_THRESHOLD", "50"))
HONEYPOT_RESPONSE_SIMILARITY_THRESHOLD = float(
    os.getenv("HONEYPOT_RESPONSE_SIMILARITY_THRESHOLD", "0.95"))

# ─── AI/LLM Configuration ────────────────────────────────────────────────
AI_REQUEST_TIMEOUT = int(os.getenv("AI_REQUEST_TIMEOUT", "60"))
AI_MAX_RETRIES = int(os.getenv("AI_MAX_RETRIES", "3"))
AI_TEMPERATURE = float(os.getenv("AI_TEMPERATURE", "0.7"))
AI_TOP_P = float(os.getenv("AI_TOP_P", "0.9"))

# ─── Exploitation Configuration ────────────────────────────────────────
MAX_AI_EXPLOIT_COMMANDS = int(os.getenv("MAX_AI_EXPLOIT_COMMANDS", "5"))
MIN_EXPLOIT_SUCCESS_RATE = float(os.getenv("MIN_EXPLOIT_SUCCESS_RATE", "0.20"))

# ─── Nuclei Configuration ────────────────────────────────────────────────
NUCLEI_RATE_LIMIT = int(os.getenv("NUCLEI_RATE_LIMIT", "150"))
NUCLEI_CONCURRENCY = int(os.getenv("NUCLEI_CONCURRENCY", "25"))
NUCLEI_TIMEOUT = int(os.getenv("NUCLEI_TIMEOUT", "10"))

# ─── Cache & Memoization ────────────────────────────────────────────────
TOOL_CACHE_EXPIRY_MINS = int(os.getenv("TOOL_CACHE_EXPIRY_MINS", "5"))
FINDING_CACHE_EXPIRY_MINS = int(os.getenv("FINDING_CACHE_EXPIRY_MINS", "10"))

# ─── Display & Logging ────────────────────────────────────────────────────
MAX_LIVE_DISPLAY_LINES = int(os.getenv("MAX_LIVE_DISPLAY_LINES", "200"))
MAX_SUMMARY_LINES = int(os.getenv("MAX_SUMMARY_LINES", "50"))

# ─── Network Conditions ────────────────────────────────────────────────
SLOW_NETWORK_TIMEOUT_MULTIPLIER = float(
    os.getenv("SLOW_NETWORK_TIMEOUT_MULTIPLIER", "2.0"))
SLOW_NETWORK_DELAY_MULTIPLIER = float(
    os.getenv("SLOW_NETWORK_DELAY_MULTIPLIER", "2.0"))

DB_CONNECTION_TIMEOUT = 30
TOOL_VERIFY_LONG_TIMEOUT = 300
MIN_FREE_DISK_MB = 1000
MIN_FREE_RAM_MB = 500
TOOL_CLEANUP_TIMEOUT = 60
WAF_DELAY_BETWEEN_REQUESTS = float(
    os.getenv("WAF_DELAY_BETWEEN_REQUESTS", "1.0"))
WAF_DELAY_SHORT = float(os.getenv("WAF_DELAY_SHORT", "0.5"))
WAF_DELAY_MEDIUM = float(os.getenv("WAF_DELAY_MEDIUM", "2.0"))
WAF_DELAY_LONG = float(os.getenv("WAF_DELAY_LONG", "5.0"))
SSH_RECONNECT_DELAY = int(os.getenv("SSH_RECONNECT_DELAY", "5"))
SSH_STREAM_POLL_DELAY = 1
SSH_RESILIENT_PID_WAIT = 5
SSH_RESILIENT_POLL_INTERVAL = 2
SSH_RESILIENT_ERROR_WAIT = 5
AI_NAME_GEMINI = 'gemini'
AI_NAME_GROQ = 'groq'
AI_NAME_OLLAMA = 'ollama'
AI_NAME_OPENROUTER = 'openrouter'
AI_VERSION_V1BETA = 'v1beta'
AI_VERSION_V1 = 'v1'
DEFAULT_NETWORK_TIMEOUT = 30

MAX_VPS_LOAD = float(os.getenv("MAX_VPS_LOAD", "15.0"))
VPS_DISK_ABORT_PCT = int(os.getenv("VPS_DISK_ABORT_PCT", "95"))
VPS_ZOMBIE_AGE_MINUTES = int(os.getenv("VPS_ZOMBIE_AGE_MINUTES", "60"))
VPS_DISK_WARN_PCT = int(os.getenv("VPS_DISK_WARN_PCT", "85"))
VPS_MEM_LOW_MB = int(os.getenv("VPS_MEM_LOW_MB", "1024"))

AI_RETRY_DELAY = 5

SSH_CONNECT_TIMEOUT = 5

SSH_BANNER_TIMEOUT = 5

SSH_AUTH_TIMEOUT = 5
