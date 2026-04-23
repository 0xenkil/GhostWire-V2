import os
from dotenv import load_dotenv
from pathlib import Path
import sys

load_dotenv()

# ── AI Backend ──────────────────────────────────────────────
AI_BACKEND = os.getenv("AI_BACKEND", "groq")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "huihui_ai/gemma-4-abliterated:e4b-q8_0")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# Key pool — comma-separated list of Groq API keys for rotation
_raw_pool = os.getenv("GROQ_API_KEYS", "")
if _raw_pool:
    # Deduplicate while preserving order
    _seen = set()
    GROQ_API_KEY_POOL = []
    for k in _raw_pool.split(","):
        k = k.strip()
        if k and k not in _seen:
            _seen.add(k)
            GROQ_API_KEY_POOL.append(k)
else:
    # Fall back to single key if pool not configured
    GROQ_API_KEY_POOL = [GROQ_API_KEY] if GROQ_API_KEY else []
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
GOOGLE_MODEL = os.getenv("GOOGLE_MODEL", "gemini-2.0-flash-lite")

# ── Remote VPS Settings (all from .env) ─────────────────────
USE_REMOTE_VPS = os.getenv("USE_REMOTE_VPS", "false").lower() in ("true", "1", "yes")
VPS_HOST = os.getenv("VPS_HOST", "")
VPS_USER = os.getenv("VPS_USER", "root")
VPS_KEY_PATH = os.getenv("VPS_KEY_PATH", "")

# Fail-fast: if remote mode is on, validate SSH key exists
if USE_REMOTE_VPS:
    if not VPS_HOST:
        print("[FATAL] USE_REMOTE_VPS=true but VPS_HOST is not set in .env")
        sys.exit(1)
    if not VPS_KEY_PATH:
        print("[FATAL] USE_REMOTE_VPS=true but VPS_KEY_PATH is not set in .env")
        sys.exit(1)
    _key = Path(VPS_KEY_PATH)
    if not _key.exists():
        print(f"[FATAL] SSH key not found at: {VPS_KEY_PATH}")
        sys.exit(1)

# ── Timeouts (seconds) ──────────────────────────────────────
TOOL_DEFAULT_TIMEOUT = 120
TOOL_NMAP_TIMEOUT    = 1200
TOOL_MASSCAN_TIMEOUT = 600
TOOL_METASPLOIT_TIMEOUT = 600
TOOL_FFUF_TIMEOUT    = 1200
TOOL_AI_TIMEOUT      = 180
TOOL_NUCLEI_TIMEOUT  = 2400
TOOL_GOBUSTER_TIMEOUT = 600
TOOL_WAF_TIMEOUT     = 120

# ── Resilience / Anti-Block Settings ────────────────────────
# Post-scan cooldown: seconds to wait after a heavy scan (Nuclei/masscan)
# before launching curl-based probes — lets WAF rate-limit windows expire
# !! 90s: kandyx.lk hcdn blocks for ~60s after nuclei flood; 90s gives margin
POST_HEAVY_SCAN_COOLDOWN = int(os.getenv("POST_HEAVY_SCAN_COOLDOWN", "90"))

# TLS circuit breaker: recoverable with backoff instead of permanent kill
# !! 60s: matches the new POST_HEAVY_SCAN_COOLDOWN; prevents cascade blocking
TLS_BREAKER_BACKOFF_SECS = int(os.getenv("TLS_BREAKER_BACKOFF_SECS", "60"))
TLS_BREAKER_MAX_RETRIES  = int(os.getenv("TLS_BREAKER_MAX_RETRIES", "5"))

# Max response body size (bytes) to prevent OOM on huge pages
MAX_RESPONSE_SIZE = int(os.getenv("MAX_RESPONSE_SIZE", str(5 * 1024 * 1024)))  # 5MB

# Nuclei rate limits (requests/sec) — reduced for WAF targets
# !! DEFAULT dropped from 150→40: 150 RPS was causing hcdn to IP-block VPS mid-scan
# !! WAF dropped from 50→15: for confirmed WAF targets, go very slow
NUCLEI_RATE_LIMIT_DEFAULT = int(os.getenv("NUCLEI_RATE_LIMIT_DEFAULT", "40"))
NUCLEI_RATE_LIMIT_WAF     = int(os.getenv("NUCLEI_RATE_LIMIT_WAF", "15"))

# Network exit codes that should never trigger Ghost Protocol AI repair
# 6=DNS fail, 7=conn refused, 28=timeout, 35=TLS, 56=TCP reset, 52=empty reply
NETWORK_UNFIXABLE_EXITS = {3, 6, 7, 28, 35, 52, 56}

# VPS health thresholds
VPS_DISK_WARN_PCT  = int(os.getenv("VPS_DISK_WARN_PCT", "90"))
VPS_DISK_ABORT_PCT = int(os.getenv("VPS_DISK_ABORT_PCT", "95"))
VPS_MEM_LOW_MB     = int(os.getenv("VPS_MEM_LOW_MB", "200"))

# Zombie process cleanup: kill orphaned processes older than this (minutes)
VPS_ZOMBIE_AGE_MINUTES = int(os.getenv("VPS_ZOMBIE_AGE_MINUTES", "120"))

# Rate limiting: backoff when target returns HTTP 429
RATE_LIMIT_INITIAL_BACKOFF = int(os.getenv("RATE_LIMIT_INITIAL_BACKOFF", "10"))
RATE_LIMIT_MAX_BACKOFF     = int(os.getenv("RATE_LIMIT_MAX_BACKOFF", "120"))

# Honeypot detection: flag targets with more than this many ports open
HONEYPOT_PORT_THRESHOLD = int(os.getenv("HONEYPOT_PORT_THRESHOLD", "50"))

# DNS fallback servers (tried in order when primary fails)
DNS_FALLBACK_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

TOOL_RETRY_COUNT = 2
TOOL_RETRY_DELAY = 1
OLLAMA_NUM_THREAD = int(os.getenv("OLLAMA_NUM_THREAD", "4"))
OLLAMA_KEEP_ALIVE = os.getenv("OLLAMA_KEEP_ALIVE", "0") # Unload immediately to prevent memory leaks/shortages
OLLAMA_NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "2048")) # Reduced context to save RAM

# ── Paths ────────────────────────────────────────────────────
RESULTS_DIR = Path("results")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# ── Legal / Scope ────────────────────────────────────────────
REQUIRE_WRITTEN_CONSENT = True
BLOCKED_IP_RANGES = [
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4"
]
ALWAYS_BLOCKED_DOMAINS = [
    "google.com", "cloudflare.com", "amazonaws.com",
    "microsoft.com", "apple.com", "facebook.com"
]

# ── TLS / HTTP / Stealth Flags ─────────────────────────────────
# Robust headers to make curl look like a legitimate Chrome browser
STEALTH_HEADERS = (
    "-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36' "
    "-H 'Accept-Language: en-US,en;q=0.9' "
    "-H 'Accept: text/html,application/xhtml+xml,*/*;q=0.8' "
    "-H 'Connection: keep-alive'"
)

# Optional Proxy settings for IP masking (e.g. Tor or Proxy list)
USE_PROXY = os.getenv("USE_PROXY", "false").lower() in ("true", "1")
PROXY_URL = os.getenv("PROXY_URL", "socks5h://127.0.0.1:9050")

CURL_TLS_FLAGS = STEALTH_HEADERS
if USE_PROXY and PROXY_URL:
    CURL_TLS_FLAGS += f"--proxy {PROXY_URL} "

# ── Recon Optimization ──────────────────────────────────────
# Set to 'high' for aggressive JS/API discovery on SPAs
SPA_RECON_LEVEL = os.getenv("SPA_RECON_LEVEL", "high")
