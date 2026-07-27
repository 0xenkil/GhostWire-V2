"""
Centralized Backend & Endpoint Configuration
──────────────────────────────────────────────
All service endpoints, API keys, ports, and external services.
Can be overridden via environment variables or .env file.
"""

import os

# ─── AI Backends ────────────────────────────────────────────────────────
# Ollama (local fallback AI)
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "30"))

# Groq (primary AI)
# Best free Production models (as of 2026-05): llama-3.3-70b-versatile (complex tasks),
# llama-3.1-8b-instant (high-volume / fallback when 70B hits TPD rate limits)
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
_raw_pool = os.getenv("GROQ_API_KEYS", "")
# Do not invent keys in config. Only use keys explicitly provided by the
# runtime environment.
GROQ_API_KEY_POOL = [k.strip() for k in _raw_pool.split(
    ",") if k.strip()] if _raw_pool else ([GROQ_API_KEY] if GROQ_API_KEY else [])
GROQ_MODEL = os.getenv(
    "GROQ_MODEL",
    "llama-3.3-70b-versatile")  # Primary: best reasoning
GROQ_FALLBACK_MODEL = os.getenv(
    "GROQ_FALLBACK_MODEL",
    "llama-3.1-8b-instant")    # Fallback: 10x higher rate limits

# Google Gemini (secondary fallback AI)
# gemini-3.1-flash-lite = new high-efficiency model (v1beta endpoint)
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
GOOGLE_MODEL = os.getenv("GOOGLE_MODEL", "gemini-3.1-flash-lite")

# ─── Proxy & Network ────────────────────────────────────────────────────
PROXY_URL = os.getenv("PROXY_URL", "socks5h://127.0.0.1:9050")
PROXY_TIMEOUT = int(os.getenv("PROXY_TIMEOUT", "10"))
TOR_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT", "9050"))
TOR_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT", "9051"))
TOR_ENABLED = os.getenv("TOR_ENABLED", "false").lower() in ("true", "1", "yes")
TOR_PASSWORD = os.getenv("TOR_CONTROL_PASSWORD", "")

# ─── WSL Settings (replaces VPS) ────────────────────────────────────────
USE_WSL = os.getenv("USE_WSL", "true").lower() in ("true", "1", "yes")
WSL_DISTRO = os.getenv("WSL_DISTRO", "")      # blank = default distro
WSL_USER = os.getenv("WSL_USER", "")           # blank = default WSL user
WSL_TEMP_DIR = os.getenv("WSL_TEMP_DIR", "~/redteam-workspace")
WSL_RESULTS_DIR = os.getenv("WSL_RESULTS_DIR", "~/redteam-workspace/results")
WSL_TOOL_PATH = os.getenv(
    "WSL_TOOL_PATH",
    "$HOME/go/bin:$HOME/.local/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")

# ─── Remote VPS Settings (DEPRECATED) ───────────────────────────────────
VPS_HOST = os.getenv("VPS_HOST", "")
VPS_PORT = int(os.getenv("VPS_PORT", "22"))
VPS_USERNAME = os.getenv("VPS_USERNAME", os.getenv("VPS_USER", "root"))
VPS_KEY_FILE = os.getenv("VPS_KEY_FILE", os.getenv("VPS_KEY_PATH", ""))
VPS_PASSWORD = os.getenv("VPS_PASSWORD", "")

# ─── Security API Keys ──────────────────────────────────────────────────
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# ─── Validation Logic ───────────────────────────────────────────────────


def validate_endpoints():
    """Validates connectivity to critical AI and Security APIs."""
    critical_errors = []
    warnings = []

    if not GROQ_API_KEY_POOL:
        warnings.append(
            "No Groq keys configured (GROQ_API_KEY or GROQ_API_KEYS is empty)")

    if not GOOGLE_API_KEY:
        warnings.append("Google Gemini key is missing")

    return critical_errors, warnings


# ─── Out-of-Band Collaboration ──────────────────────────────────────────
OOB_COLLABORATOR_DOMAIN = os.getenv(
    "OOB_COLLABORATOR_DOMAIN",
    "collaborator.oob")

# OpenRouter stub variables (REMOVED fallback option)
OPENROUTER_API_KEY = ""
OPENROUTER_MODEL = ""
