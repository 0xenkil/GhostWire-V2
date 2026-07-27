import time
import threading
import requests
from config import (
    AI_BACKEND, OLLAMA_MODEL,
    OLLAMA_NUM_THREAD,
    OLLAMA_KEEP_ALIVE, OLLAMA_NUM_CTX
)
from config_backends import (
    OLLAMA_BASE_URL,
    GROQ_MODEL, GROQ_FALLBACK_MODEL, GROQ_API_KEY_POOL,
    GOOGLE_API_KEY, GOOGLE_MODEL
)
from config_thresholds import (
    TOOL_AI_TIMEOUT,
    AI_NAME_GEMINI, AI_NAME_GROQ, AI_NAME_OLLAMA, AI_NAME_OPENROUTER,
    AI_VERSION_V1BETA, AI_VERSION_V1
)
from config_thresholds import AI_RETRY_DELAY
from utils.logger import get_logger

log = get_logger("ai_backend")


class GroqKeyPool:
    """
    Thread-safe rotating pool of Groq API keys.
    SMART rotation: Parses actual Groq recovery windows from error messages.

    Distinguishes between:
      - TPD (tokens per day) exhaustion  -> key is DEAD until recovery window passes
      - RPM (requests per minute) limit  -> key is temporarily busy, skip for now
      - Auth errors                      -> key is invalid, mark exhausted permanently

    Smart features:
      - Parses "Please try again in Xm Y.ZZs" from error messages
      - Stores per-key recovery deadlines
      - Prioritizes keys that will recover soonest
      - Only uses exhausted keys after all queryable keys fail
    """

    def __init__(self, keys: list):
        self._keys = list(keys)
        # {key: recovery_deadline_timestamp} (parsed from error or default)
        self._exhausted: dict = {}
        self._recovery_reasons: dict = {}  # {key: reason_string} for logging
        self._rpm_skipped: set = set()    # Temporarily skipped due to RPM (not dead)
        self._lock = threading.Lock()
        self._current_idx = 0
        # Fallback if recovery time not parsed from error
        self._default_recovery_ttl = 3600
        total = len(self._keys)
        log.debug(f"Groq key pool initialized with {total} key(s).")

    def _parse_recovery_window(self, error_str: str) -> float:
        """Parse Groq error message to extract recovery time in seconds."""
        import re
        match = re.search(
            r'try again in (?:(\d+)h)?(?:(\d+)m)?([\d.]+)s',
            error_str,
            re.IGNORECASE)
        if match:
            hours = int(match.group(1) or 0)
            minutes = int(match.group(2) or 0)
            seconds = float(match.group(3))
            total = hours * 3600 + minutes * 60 + seconds
            log.debug(f"Parsed recovery window: {total:.1f}s")
            return total
        return self._default_recovery_ttl

    def get_active_key(self, skip_rpm: bool = False) -> str | None:
        """Return the next usable key, preferring ones that will recover soon.

        Smart rotation:
          1. Skip all exhausted keys that haven't recovered yet
          2. Return the first non-exhausted key (QUERYABLE)
          3. If all QUERYABLE keys used, return key with earliest recovery deadline
          4. If skip_rpm=True, avoid RPM-flagged keys

        Args:
            skip_rpm: If True, also skip keys flagged for RPM rate-limit.
        """
        with self._lock:
            now = time.monotonic()
            queryable = []      # Keys not in exhausted state
            recoverable = []    # Keys that have exceeded recovery deadline

            for idx, key in enumerate(self._keys):
                # Skip RPM-flagged if requested
                if skip_rpm and key in self._rpm_skipped:
                    continue

                # Check exhaustion state
                if key in self._exhausted:
                    recovery_deadline = self._exhausted[key]
                    if now >= recovery_deadline:
                        # Key has recovered! Move it to available pool
                        reason = self._recovery_reasons.get(key, "unknown")
                        log.info(
                            f"Key ...{key[-4:]} recovered (was: {reason})")
                        del self._exhausted[key]
                        del self._recovery_reasons[key]
                        queryable.append(key)
                    else:
                        # Still exhausted, add to recoverable for later
                        recoverable.append((recovery_deadline, key))
                else:
                    # Key is QUERYABLE (never exhausted or already recovered)
                    queryable.append(key)

            # Smart selection:
            # 1. Use round-robin on QUERYABLE keys first
            if queryable:
                for i in range(len(queryable)):
                    idx_in_queryable = (self._current_idx + i) % len(queryable)
                    key = queryable[idx_in_queryable]
                    self._current_idx = (
                        idx_in_queryable + 1) % max(len(queryable), 1)
                    return key

            # 2. All QUERYABLE keys used -> try the key that will recover
            # soonest
            if recoverable:
                # Sort by recovery_deadline (soonest first)
                recoverable.sort(key=lambda x: x[0])
                recovery_deadline, key = recoverable[0]
                soonest_recovery = max(0, recovery_deadline - now)
                log.debug(
                    f"All QUERYABLE keys busy. Next key ...{key[-4:]} recovers in {soonest_recovery:.0f}s")
                # Still return it; caller will handle retry logic
                return key

        return None

    def mark_exhausted(
            self, key: str, reason: str = "Daily limit hit", error_str: str = None):
        """Mark a key as exhausted and parse recovery deadline from error message.

        Args:
            key: API key to mark exhausted
            reason: Human-readable reason (e.g., "Daily token limit (TPD)")
            error_str: Full error message (to parse recovery window like "4m14.88s")
        """
        with self._lock:
            if key not in self._exhausted:
                # Parse recovery window from error message if available
                if error_str:
                    recovery_seconds = self._parse_recovery_window(error_str)
                    recovery_deadline = time.monotonic() + recovery_seconds
                    log.debug(
                        f"Parsed recovery window: {
                            recovery_seconds:.0f}s from error message")
                else:
                    # Fallback to default recovery time
                    recovery_deadline = time.monotonic() + self._default_recovery_ttl
                    recovery_seconds = self._default_recovery_ttl

                # Store deadline (not just timestamp)
                self._exhausted[key] = recovery_deadline
                self._recovery_reasons[key] = reason
                self._rpm_skipped.discard(key)  # Clean up any RPM skip entry
                masked = key[:8] + "..." + key[-4:]
                remaining = len(self._keys) - len(self._exhausted)
                recovery_str = self._format_time_delta(recovery_seconds)
                log.warning(
                    f"Groq key {masked} marked EXHAUSTED. "
                    f"Reason: {reason}. "
                    f"Recovery in {recovery_str}. "
                    f"{remaining}/{len(self._keys)} keys remaining."
                    # Surface the RAW provider error so a genuine daily-limit hit
                    # can be told apart from a misclassified per-minute limit.
                    + (f"\n             [raw: {error_str[:200]}]" if error_str else "")
                )
                self._current_idx = (self._current_idx + 1) % len(self._keys)

    def _format_time_delta(self, seconds: float) -> str:
        """Format seconds as 'XmY.Zs' for readability."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m{secs:.1f}s"

    def mark_rpm_limited(self, key: str):
        """Temporarily skip this key due to RPM (it's still alive, just rate-limited)."""
        with self._lock:
            if key not in self._exhausted:
                self._rpm_skipped.add(key)
                masked = key[:8] + "..." + key[-4:]
                log.info(
                    f"Groq key {masked} temporarily skipped (RPM). Will retry after rotation.")

    def clear_rpm_flags(self):
        """Clear all RPM skip flags - call after trying all keys once."""
        with self._lock:
            if self._rpm_skipped:
                log.debug(
                    f"Clearing RPM flags for {len(self._rpm_skipped)} key(s). Attempting retry.")
            self._rpm_skipped.clear()

    @property
    def has_keys(self) -> bool:
        """True if at least one key is available now or will recover soon."""
        with self._lock:
            now = time.monotonic()
            for key in self._keys:
                if key not in self._exhausted:
                    return True
                # Check if key will recover soon (deadline passed)
                recovery_deadline = self._exhausted.get(key, 0)
                if now >= recovery_deadline:
                    return True  # Key has recovered!
            return False

    @property
    def has_non_rpm_keys(self) -> bool:
        """True if at least one key is not exhausted AND not RPM-skipped."""
        with self._lock:
            return any(
                k not in self._exhausted and k not in self._rpm_skipped
                for k in self._keys
            )

    @property
    def pool_status(self) -> str:
        with self._lock:
            active = len(self._keys) - len(self._exhausted)
            return f"{active}/{len(self._keys)} Groq keys active"


class AIBackend:
    def __init__(self, preferred_backend: str = None):
        # Validate Groq configuration before initializing
        if GROQ_API_KEY_POOL:
            if not GROQ_MODEL:
                raise RuntimeError("GROQ_MODEL is empty in .env or config")
            if GROQ_FALLBACK_MODEL and GROQ_FALLBACK_MODEL == GROQ_MODEL:
                log.debug(
                    f"GROQ_FALLBACK_MODEL == GROQ_MODEL (both '{GROQ_MODEL}'). Fallback disabled.")
            elif not GROQ_FALLBACK_MODEL:
                log.debug(
                    "GROQ_FALLBACK_MODEL is empty. Fallback to smaller model disabled.")

        self.backend = preferred_backend or AI_BACKEND
        self._groq_pool = GroqKeyPool(GROQ_API_KEY_POOL)
        self._backend_cooldowns: dict[str, float] = {}
        self._available_backends = self._detect_available()
        active = self._available_backends[0] if self._available_backends else "none"
        log.debug(
            f"AI Backend active: {active} | {
                self._groq_pool.pool_status}")

        # W1.2 — token budget tracking
        import threading as _threading
        self._usage_lock = _threading.Lock()
        self._call_count: int = 0
        self._approx_chars_in: int = 0   # rough proxy for input tokens
        self._approx_chars_out: int = 0  # rough proxy for output tokens
        self._phase_call_counts: dict[str, int] = {}
        self._phase_char_counts: dict[str, int] = {}
        self._current_phase: str = ""    # set by orchestrator per phase

    def _backend_is_cooled_down(self, backend: str) -> bool:
        until = self._backend_cooldowns.get(backend)
        return bool(until and time.monotonic() < until)

    def _cooldown_backend(self, backend: str, seconds: int, reason: str):
        until = time.monotonic() + max(1, seconds)
        self._backend_cooldowns[backend] = until
        log.warning(f"'{backend}' cooled down for {seconds}s ({reason}).")

    def get_shortest_recovery_time(self) -> int | None:
        """Return seconds until the next backend/key recovers from exhaustion, or None.

        Checks:
          1. Groq key pool recovery deadlines (_exhausted dict)
          2. Per-backend cooldown timestamps (_backend_cooldowns dict)

        Returns the shortest wait time across all exhausted backends.
        Used by agents to wait for recovery instead of breaking loops.
        """
        now = time.monotonic()
        recovery_times = []

        # Check Groq key pool recovery deadlines
        if hasattr(self, '_groq_pool') and hasattr(
                self._groq_pool, '_exhausted'):
            with self._groq_pool._lock:
                for key, deadline in self._groq_pool._exhausted.items():
                    if isinstance(deadline, (int, float)) and deadline > now:
                        recovery_times.append(deadline - now)

        # Check per-backend cooldown timestamps
        if hasattr(self, '_backend_cooldowns'):
            for backend, until in self._backend_cooldowns.items():
                if isinstance(until, (int, float)) and until > now:
                    recovery_times.append(until - now)

        if recovery_times:
            shortest = int(min(recovery_times)) + 1  # +1s buffer
            log.debug(
                f"Shortest recovery time: {shortest}s across {
                    len(recovery_times)} exhausted sources")
            return shortest
        return None

    def set_current_phase(self, phase: str) -> None:
        """Orchestrator calls this before each phase so usage is attributed correctly."""
        with self._usage_lock:
            self._current_phase = phase or ""

    def _record_usage(self, prompt_chars: int, response: str, phase: str = "") -> None:
        """Track approximate token usage (chars ≈ 4× tokens heuristic)."""
        out_chars = len(response) if response else 0
        with self._usage_lock:
            self._call_count += 1
            self._approx_chars_in += prompt_chars
            self._approx_chars_out += out_chars
            phase = phase or self._current_phase
            if phase:
                self._phase_call_counts[phase] = self._phase_call_counts.get(phase, 0) + 1
                self._phase_char_counts[phase] = self._phase_char_counts.get(phase, 0) + prompt_chars + out_chars

    def get_usage_stats(self, phase: str = "") -> dict:
        """Return current usage snapshot for circuit-breaker checks."""
        with self._usage_lock:
            total_chars = self._approx_chars_in + self._approx_chars_out
            approx_tokens = total_chars // 4
            stats = {
                "call_count": self._call_count,
                "approx_tokens": approx_tokens,
                "approx_chars_in": self._approx_chars_in,
                "approx_chars_out": self._approx_chars_out,
            }
            if phase:
                stats["phase_calls"] = self._phase_call_counts.get(phase, 0)
                stats["phase_chars"] = self._phase_char_counts.get(phase, 0)
                stats["phase_approx_tokens"] = self._phase_char_counts.get(phase, 0) // 4
            return stats

    def is_phase_budget_exceeded(self, phase: str, max_tokens: int) -> bool:
        """Return True when approximate phase token usage exceeds the budget."""
        stats = self.get_usage_stats(phase=phase)
        exceeded = stats.get("phase_approx_tokens", 0) >= max_tokens
        if exceeded:
            log.warning(
                f"[BUDGET] Phase '{phase}' exceeded token budget "
                f"({stats['phase_approx_tokens']:,} / {max_tokens:,} approx tokens). "
                "Triggering circuit breaker.")
        return exceeded

    def _compact_prompt_text(self, text: str, max_chars: int,
                             label: str = "prompt", markers: list = None) -> str:
        """Deterministically compress long prompt text while preserving useful signal."""
        if not text or len(text) <= max_chars:
            return text

        lines = [line.rstrip() for line in text.splitlines()]

        if markers is None:
            important_markers = (
                "error", "error:", "fail", "failed:", "timeout", "blocked", "success", "warning",
                "finding", "port", "service", "waf", "cloudflare", "tech_stack",
                "confidence", "probability", "summary", "target", "target:", "scope",
                "command", "command:", "tool:", "phase:", "result", "response", "observation", "recommendation",
                "{", "}", "verification focus", "rule", "must", "autonomous tool execution rules"
            )
        else:
            important_markers = tuple(markers)

        important_lines = [
            line for line in lines
            if line and any(marker in line.lower() for marker in important_markers)
        ]

        keep_each_side = max(20, min(60, len(lines) // 8 or 20))
        head = lines[:keep_each_side]
        tail = lines[-keep_each_side:] if len(lines) > keep_each_side else []

        chunks = [
            f"[{label} COMPRESSED: {len(text)} chars -> {max_chars} chars budget]"]

        if important_lines:
            chunks.append("--- IMPORTANT EXCERPTS ---")
            chunks.extend(important_lines[:80])
        else:
            # Fallback when no important lines match: ensure we keep a middle
            # chunk
            mid_start = len(lines) // 2 - keep_each_side
            if mid_start > keep_each_side:
                chunks.append("--- MIDDLE EXCERPTS ---")
                chunks.extend(lines[mid_start:mid_start + keep_each_side])

        if head:
            chunks.append("--- LEADING CONTEXT ---")
            chunks.extend(head)

        if tail:
            chunks.append("--- TRAILING CONTEXT ---")
            chunks.extend(tail)

        compacted = "\n".join(chunks)
        if len(compacted) > max_chars:
            compacted = compacted[: max_chars - 20] + "\n...[truncated]"
        return compacted

    def _prompt_budget_for_backend(
            self, backend: str, model_id: str = None) -> int:
        """Return a conservative character budget for a backend/model combination."""
        backend = (backend or "").lower()
        if backend == AI_NAME_GROQ.lower():
            model = (model_id or GROQ_MODEL or "").lower()
            if model and model == (GROQ_FALLBACK_MODEL or "").lower():
                # The 8B "instant" fallback's free-tier limit is a small
                # tokens-per-MINUTE ceiling (~6000), NOT the 128K context window.
                # Sizing this to the context window (was 50000 chars) made every
                # fallback query 413 "request too large ... on tokens per minute
                # (TPM): Limit 6000, Requested 7163" — so a single 70B daily-limit
                # (TPD) then cascaded ALL keys to exhausted because the rescue path
                # was dead. Keep input well under 6000 tokens (~24000 chars).
                return 16000
            return 30000
        if backend == AI_NAME_OPENROUTER.lower():
            return 50000
        if backend == AI_NAME_GEMINI.lower() or backend == "google":
            return 60000
        if backend == AI_NAME_OLLAMA.lower():
            return 12000
        return 30000

    def _select_backend_order_for_prompt(self, prompt_chars: int) -> list:
        """Choose backend order based on prompt size and live backend health.

        Groq is PRIMARY, Gemini is the FALLBACK. Escalation rules:
          1. If Groq pool is fully exhausted -> skip Groq, lead with Gemini (free cloud)
          2. For very large prompts (>=50K chars) -> prefer Gemini then Groq (bigger context)
          3. Otherwise -> follow self.backend (Groq) preference, then availability order
        """
        groq_alive = self._groq_pool.has_keys and not self._backend_is_cooled_down(
            "groq")

        if not groq_alive:
            # Groq dead - immediately lead with free cloud backends
            preferred = (AI_NAME_GEMINI.lower(), AI_NAME_OLLAMA.lower())
        elif prompt_chars >= 50000:
            # Large prompt - use big-context backends first to avoid truncation
            preferred = (
                AI_NAME_GEMINI.lower(),
                AI_NAME_GROQ.lower(),
                AI_NAME_OLLAMA.lower())
        else:
            preferred = ()

        ordered = []

        # Honor explicit backend preference if it's alive
        if self.backend and self.backend in self._available_backends:
            if not (self.backend == "groq" and not groq_alive):
                ordered.append(self.backend)

        for backend in preferred:
            if backend not in ordered:
                ordered.append(backend)

        for backend in self._available_backends:
            if backend not in ordered:
                ordered.append(backend)

        # Absolute safety net - make sure all known backends are represented.
        for backend in (AI_NAME_GROQ.lower(),
                        AI_NAME_GEMINI.lower(), AI_NAME_OLLAMA.lower()):
            if backend not in ordered:
                ordered.append(backend)

        return ordered

    def _prepare_prompt_payload(self, backend: str, system_prompt: str,
                                user_message: str, model_id: str = None) -> tuple[str, str, int]:
        """Trim prompt payload to a conservative backend-specific size budget."""
        budget = self._prompt_budget_for_backend(backend, model_id=model_id)
        total_chars = len(system_prompt) + len(user_message)
        if total_chars <= budget:
            return system_prompt, user_message, budget

        system_cap = min(len(system_prompt), max(1200, budget // 4))
        user_cap = max(2000, budget - system_cap - 400)
        compact_system = self._compact_prompt_text(
            system_prompt, system_cap, label=f"{backend} SYSTEM")
        compact_user = self._compact_prompt_text(
            user_message, user_cap, label=f"{backend} USER")
        log.warning(
            f"Prompt too large for {backend} (chars={total_chars}, budget={budget}). "
            f"Compacting system/user payload before query."
        )
        return compact_system, compact_user, budget

    def _is_endpoint_reachable(self, url: str, timeout: int = 10) -> bool:
        """Lightweight connection check using browser User-Agent and streamed GET request, with retry logic for robust DNS lookup under WSL."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                # Streamed GET fetches only headers, extremely fast and
                # compatible
                r = requests.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=True,
                    stream=True)
                return r.status_code < 500
            except Exception as e:
                if attempt < max_attempts - 1:
                    log.debug(
                        f"[PREFLIGHT DNS RETRY] Connection to {url} failed (attempt {
                            attempt + 1}/{max_attempts}): {e}. Retrying in 1s...")
                    time.sleep(1)
                else:
                    log.debug(
                        f"[PREFLIGHT DNS FAILURE] Connection to {url} failed after {max_attempts} attempts: {e}")
        return False

    def _detect_available(self) -> list:
        available = []

        # Priority 1: Groq key pool (PRIMARY)
        if self._groq_pool.has_keys:
            available.append("groq")
            log.debug(f"Groq pool ready - {self._groq_pool.pool_status}")
        else:
            log.debug("Groq: no API keys configured or all exhausted")

        # Priority 3: Google Gemini (FALLBACK)
        if GOOGLE_API_KEY:
            available.append(AI_NAME_GEMINI.lower())
            if self._is_endpoint_reachable(
                    "https://generativelanguage.googleapis.com"):
                log.debug(
                    "Google Gemini API key found + endpoint reachable - free cloud fallback enabled.")
            else:
                log.warning(
                    "[SYS.WARN] Google Gemini: API key configured but preflight check failed. "
                    "Fallback capability enabled but may experience execution stalls."
                )
        else:
            log.debug("[!] Google: skipped (no GOOGLE_API_KEY in .env)")

        # Priority 4: Ollama (local)
        try:
            r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                if any(OLLAMA_MODEL.split(":")[0] in m for m in models):
                    available.append("ollama")
                    log.info(f"Ollama available with model {OLLAMA_MODEL}")
                else:
                    log.debug(
                        f"[!] Ollama: running but model {OLLAMA_MODEL} not found")
        except Exception:
            pass
        if not available:
            log.warning(
                "No AI backend available. Check GROQ_API_KEYS or GOOGLE_API_KEY in .env")
        return available

    def check_all_backends(self) -> dict:
        """Test all backends and return a detailed status report."""
        report = {
            "groq": {"status": "OFFLINE", "configured": bool(GROQ_API_KEY_POOL), "keys": []},
            "google": {"status": "OFFLINE", "details": ""},
            "ollama": {"status": "OFFLINE", "details": ""}
        }

        # Test Groq keys
        if GROQ_API_KEY_POOL:
            for key in GROQ_API_KEY_POOL:
                masked = key[:8] + "..." + key[-4:]
                try:
                    if not self._groq_sdk_available():
                        raise RuntimeError("groq package not installed")
                    r = requests.get(
                        "https://api.groq.com/openai/v1/models",
                        headers={
                            "Authorization": f"Bearer {key}"},
                        timeout=5)
                    r.raise_for_status()
                    report["groq"]["keys"].append(
                        {"key": masked, "status": "QUERYABLE"})
                except Exception as e:
                    report["groq"]["keys"].append(
                        {"key": masked, "status": "OFFLINE", "error": str(e)})

            if any(k["status"] == "QUERYABLE" for k in report["groq"]["keys"]):
                report["groq"]["status"] = "ONLINE"
            elif report["groq"]["configured"]:
                report["groq"]["status"] = "CONFIGURED"

        # Test Google
        if GOOGLE_API_KEY:
            try:
                # Use model metadata endpoint to verify key + model
                # availability where possible.
                api_version = self._google_api_version(GOOGLE_MODEL)
                meta_url = (
                    f"https://generativelanguage.googleapis.com/{api_version}/models/"
                    f"{GOOGLE_MODEL}?key={GOOGLE_API_KEY}"
                )
                r = requests.get(meta_url, timeout=5)
                if r.status_code == 200:
                    report["google"]["status"] = "ONLINE"
                elif r.status_code == 429:
                    report["google"]["status"] = "RATE_LIMITED"
                    report["google"]["details"] = "Metadata endpoint returned 429 Too Many Requests"
                else:
                    # Fall back to attempting a small generate call to capture
                    # detailed errors
                    try:
                        self._query_backend("google", "test", "hi")
                        report["google"]["status"] = "ONLINE"
                    except Exception as e:
                        err_str = str(e)
                        if "429" in err_str or "too many requests" in err_str.lower():
                            report["google"]["status"] = "RATE_LIMITED"
                        report["google"]["details"] = f"meta:{r.status_code}:{r.text[:200]} | gen:{e}"
            except Exception as e:
                report["google"]["details"] = str(e)

        # Test Ollama
        if "ollama" in self._available_backends:
            try:
                self._query_backend("ollama", "test", "hi")
                report["ollama"]["status"] = "ONLINE"
            except Exception as e:
                report["ollama"]["details"] = str(e)

        return report

    def get_backend_report(self) -> dict:
        """Return human-readable backend status for display at orchestrator startup."""
        report = {
            "backends": {},
            "all_available": self._available_backends,
            "timestamp": time.monotonic()
        }

        # Groq status
        if GROQ_API_KEY_POOL:
            active_keys = len(self._groq_pool._keys) - \
                len(self._groq_pool._exhausted)
            status = "ONLINE" if self._groq_pool.has_keys else "EXHAUSTED"
            report["backends"]["groq"] = {
                "status": status,
                "detail": f"{active_keys}/{len(self._groq_pool._keys)} keys active",
                "icon": "[+]" if status == "ONLINE" else "[x]"
            }
        else:
            report["backends"]["groq"] = {
                "status": "NOT_CONFIGURED",
                "detail": "no GROQ_API_KEY in .env",
                "icon": "[x]"
            }

        # Google status
        if GOOGLE_API_KEY:
            report["backends"]["google"] = {
                "status": "ONLINE",
                "detail": f"model: {GOOGLE_MODEL}",
                "icon": "[+]"
            }
        else:
            report["backends"]["google"] = {
                "status": "NOT_CONFIGURED",
                "detail": "no GOOGLE_API_KEY in .env",
                "icon": "[x]"
            }

        # Ollama status
        if "ollama" in self._available_backends:
            report["backends"]["ollama"] = {
                "status": "ONLINE",
                "detail": f"model: {OLLAMA_MODEL}",
                "icon": "[+]"
            }
        else:
            report["backends"]["ollama"] = {
                "status": "OFFLINE",
                "detail": f"connection refused ({OLLAMA_BASE_URL})",
                "icon": "[x]"
            }

        return report

    def _groq_sdk_available(self) -> bool:
        try:
            return True
        except ImportError:
            return False

    @property
    def ai_available(self) -> bool:
        """Re-check LIVE if at least one AI backend is currently functional.

        This is intentionally NOT cached - key exhaustion can happen mid-session.
        """
        if self._groq_pool.has_keys and not self._backend_is_cooled_down(
                "groq"):
            return True
        if GOOGLE_API_KEY and not self._backend_is_cooled_down("google"):
            return True
        if "ollama" in self._available_backends and not self._backend_is_cooled_down(
                "ollama"):
            return True
        return False

    def _clean_llama_tags(self, text: str) -> str:
        if not text:
            return text
        import re
        # Strip Llama-3 special tokens/headers
        cleaned = re.sub(r'<\|(?:start_header_id|end_header_id|eot_id|reserved_special_token_[^|]+)(?:\|>|assistant|system|user)?', '', text)
        # Handle cases where tags might not have matching end or are partially parsed
        for tag in ["<|start_header_id|>", "<|end_header_id|>", "<|eot_id|>", "<|start_header_id|>assistant", "<|start_header_id|>system", "<|start_header_id|>user"]:
            cleaned = cleaned.replace(tag, "")
        return cleaned.strip()

    def query(self, system_prompt: str, user_message: str,
              max_retries: int = 4, model_id: str = None, _depth: int = 0) -> str:
        """
        Query AI with automatic fallback:
          Groq (key 1 -> key 2 -> key 3, PRIMARY) -> Google Gemini (fallback) -> Ollama
        Raises RuntimeError if all backends fail - FIX #3.4: Never return empty/invalid response.
        """
        prompt_chars = len(system_prompt) + len(user_message)

        # Reduce retry pressure on large prompts so we do not burn tokens on
        # repeated retries.
        if prompt_chars >= 50000:
            max_retries = min(max_retries, 3)  # Was 2, too aggressive
        elif prompt_chars >= 25000:
            max_retries = min(max_retries, 4)  # Was 3

        # Compact oversized prompts before sending them to any provider.
        # This is deterministic and avoids another AI call just to shorten
        # context.
        primary_backend = self.backend if self.backend in self._available_backends else None
        if primary_backend is None:
            primary_backend = "groq" if self._groq_pool.has_keys else (
                self._available_backends[0] if self._available_backends else "groq")
        system_prompt, user_message, _ = self._prepare_prompt_payload(
            primary_backend, system_prompt, user_message, model_id=model_id)

        # Rebuild fresh backend order each call (reflects live key state)
        backends_to_try = self._select_backend_order_for_prompt(prompt_chars)

        last_error = None
        for backend in backends_to_try:
            # Skip Groq if ALL keys are dead
            if backend == "groq" and not self._groq_pool.has_keys:
                log.debug("Groq: all keys exhausted, skipping backend.")
                continue

            # Skip Google if no key configured
            if backend == "google" and not GOOGLE_API_KEY:
                continue

            # Skip Ollama if not detected
            if backend == "ollama" and "ollama" not in self._available_backends:
                continue

            # Respect temporary backend cooldowns after repeated 429s /
            # provider backpressure
            if self._backend_is_cooled_down(backend):
                log.debug(f"Skipping {backend}: temporary cooldown active.")
                continue

            # ── Groq: iterate keys internally ────────────────────────────
            if backend == "groq":
                groq_model = model_id
                if groq_model is None:
                    # Prefer the smaller Groq fallback model for large prompts
                    # to reduce TPD pressure.
                    if prompt_chars >= 25000 and GROQ_FALLBACK_MODEL and GROQ_FALLBACK_MODEL != GROQ_MODEL:
                        groq_model = GROQ_FALLBACK_MODEL
                    else:
                        groq_model = GROQ_MODEL

                groq_result = self._query_groq_with_rotation(
                    system_prompt, user_message, max_retries, model_id=groq_model)
                if groq_result is not None:
                    # FIX #3.4: Validate response is not empty
                    result_str = groq_result.strip()
                    if result_str:
                        self._record_usage(prompt_chars, result_str)
                        return self._clean_llama_tags(result_str)
                    else:
                        log.warning(
                            "[FIX 3.4] Groq returned empty response - treating as failure")
                        last_error = "Empty response from Groq"
                # All Groq keys failed -> fall through to next backend
                if not self._groq_pool.has_keys:
                    log.warning(
                        "[->] All Groq keys exhausted (TPD). Falling back to Google/Ollama...")
                else:
                    log.warning(
                        "[->] Groq queries failed. Falling back to next backend...")
                continue

            # ── Non-Groq backends ─────────────────────────────────────────
            for attempt in range(max_retries):
                try:
                    log.debug(
                        f"AI query via {backend} (attempt {
                            attempt + 1})")
                    result = self._query_backend(
                        backend, system_prompt, user_message, model_id=model_id)
                    # FIX #3.4: Validate result is not empty
                    if result and result.strip():
                        self._record_usage(prompt_chars, result.strip())
                        return self._clean_llama_tags(result.strip())
                    elif result is not None:
                        log.warning(
                            f"[FIX 3.4] {backend} returned empty response - treating as failure")
                        last_error = f"Empty response from {backend}"
                except Exception as e:
                    err_str = str(e).lower()
                    last_error = e

                    # Connection / DNS error: skip backend entirely to avoid
                    # NameResolutionError stalls
                    if "nameresolutionerror" in err_str or "gaierror" in err_str or "connection refused" in err_str:
                        log.error(
                            f"[->] '{backend}' connection/DNS failure. Skipping to next backend.")
                        self._cooldown_backend(
                            backend, 60, "connection failure")
                        break

                    # Quota / billing error: skip backend entirely
                    if "quota" in err_str or "billing" in err_str or "unauthorized" in err_str or "invalid_api_key" in err_str:
                        log.error(
                            f"[->] '{backend}' quota/auth error. Skipping to next backend.")
                        break

                    # Rate limit: exponential backoff for free tiers (429s are
                    # common)
                    if "429" in err_str or "too many requests" in err_str or "rate_limit" in err_str:
                        if backend == "gemini" and (
                                not GOOGLE_API_KEY or GOOGLE_API_KEY == "your_gemini_api_key_here"):
                            log.error(
                                f"[->] '{backend}' hit 429 but key is missing/default. Skipping.")
                            break

                        delay = min(10 * (attempt + 1), 30)
                        log.warning(
                            f"[->] '{backend}' rate-limited (429). Retrying in {delay}s (attempt {attempt + 1}).")
                        time.sleep(delay)
                        continue

                    # Generic: exponential backoff
                    delay = min(2 ** (attempt + 1), 20)
                    log.warning(
                        f"'{backend}' attempt {
                            attempt +
                            1} failed: {e}. Retry in {delay}s...")
                    time.sleep(delay)

        # All backends exhausted
        recovery_time = self.get_shortest_recovery_time()
        if recovery_time and _depth < 3:
            log.warning(
                f"[!] All AI backends exhausted. Sleeping {recovery_time}s for recovery window...")
            time.sleep(recovery_time)
            # Retry query after sleep
            return self.query(system_prompt, user_message,
                              max_retries, model_id, _depth=_depth + 1)

        # FIX #3.4: Raise exception instead of returning error string
        error_msg = f"{last_error}" if last_error else "unknown error"
        error_text = f"All AI backends exhausted. Last error: {error_msg}"
        log.error(f"[X] {error_text}")
        raise RuntimeError(error_text)

    def _query_groq_with_rotation(
            self, system: str, user: str, max_retries: int, model_id: str = None) -> str | None:
        """
        Internal Groq query with proper key rotation.
        Returns response string on success, or None if all keys failed.

        Key rotation policy:
          - TPD (daily limit)  -> try fallback model on different key, then mark_exhausted()
          - RPM (per-minute)   -> mark_rpm_limited(), rotate to next non-RPM key
          - Auth (401/403)     -> mark_exhausted(), rotate immediately
          - Generic error      -> exponential backoff, then try next key
        """
        rpm_pass_done = False
        tpd_fallback_tried = False
        capacity_fallback_tried = False
        deadline = time.monotonic() + 90

        for attempt in range(
                max_retries * max(len(self._groq_pool._keys), 1) + max_retries):
            if time.monotonic() > deadline:
                log.error("Groq rotation loop hit wall-clock deadline (90s).")
                return None
            # Get next key (skip RPM-flagged ones first; if none available,
            # allow them)
            key = self._groq_pool.get_active_key(skip_rpm=True)
            if key is None:
                if not rpm_pass_done:
                    # Try RPM-limited keys as last resort
                    self._groq_pool.clear_rpm_flags()
                    rpm_pass_done = True
                    key = self._groq_pool.get_active_key(skip_rpm=False)
                if key is None:
                    log.error("All Groq keys are exhausted (TPD).")
                    return None

            try:
                log.debug(
                    f"Groq query with key ...{key[-4:]} (attempt {attempt + 1})")
                result = self._groq(
                    system, user, api_key=key, model_id=model_id)
                if result and result.strip():
                    return result
            except Exception as e:
                err_str = str(e).lower()

                # ── TPD: daily token limit hit -> try fallback on different ke
                if self._is_tpd_error(e):
                    _active_model = (model_id or GROQ_MODEL or "").lower()
                    # Re-trim to the fallback model's (smaller) TPM budget before
                    # ANY fallback attempt. The primary-sized prompt otherwise
                    # 413s "request too large ... on tokens per minute (TPM)" on
                    # the 8B every time, leaving the rescue path dead so one 70B
                    # TPD cascades every key to exhausted.
                    _fb_system, _fb_user, _ = self._prepare_prompt_payload(
                        AI_NAME_GROQ, system, user,
                        model_id=GROQ_FALLBACK_MODEL)
                    # The PRIMARY (70B) model's DAILY tokens are gone for THIS key,
                    # but the smaller fallback model (8B) has a SEPARATE, higher
                    # daily budget that is usually still available on the SAME key.
                    # Try it BEFORE writing the whole key off — otherwise a 70B TPD
                    # needlessly kills the key (and drops the engagement to Gemini)
                    # while the 8B on that key still works. This is why a "first
                    # run" could burn all keys at once: ONE 70B TPD marked the
                    # ENTIRE key dead for 60m. Skipped when the call that hit TPD
                    # already WAS the fallback model (then it's genuinely out).
                    if (GROQ_FALLBACK_MODEL
                            and GROQ_FALLBACK_MODEL.lower() != _active_model):
                        try:
                            same_key_result = self._groq(
                                _fb_system, _fb_user, api_key=key,
                                model_id=GROQ_FALLBACK_MODEL)
                            if same_key_result and same_key_result.strip():
                                log.info(
                                    f"[->] '{model_id or GROQ_MODEL}' hit its daily limit on "
                                    f"key ...{key[-4:]}; served by fallback model "
                                    f"'{GROQ_FALLBACK_MODEL}' on the SAME key (key kept alive).")
                                return same_key_result
                        except Exception as _fb_same_err:
                            log.debug(
                                f"Fallback model on same key also failed after primary "
                                f"TPD (key genuinely out): {_fb_same_err}")

                    # Fallback unavailable on this key too -> write the key off.
                    self._groq_pool.mark_exhausted(
                        key, reason="Daily token limit (TPD)", error_str=err_str)

                    # Try fallback model on a DIFFERENT key before giving up on
                    # this iteration
                    if not tpd_fallback_tried and GROQ_FALLBACK_MODEL and GROQ_FALLBACK_MODEL != GROQ_MODEL:
                        tpd_fallback_tried = True
                        log.info(
                            f"[->] Primary model hit TPD on key ...{key[-4:]}. Trying fallback model on different key...")

                        # Get a DIFFERENT key for fallback attempt
                        next_key = self._groq_pool.get_active_key(
                            skip_rpm=True)
                        if next_key and next_key != key:
                            try:
                                result = self._groq(
                                    _fb_system, _fb_user, api_key=next_key, model_id=GROQ_FALLBACK_MODEL)
                                if result and result.strip():
                                    log.info(
                                        f"[+] Fallback model succeeded on key ...{next_key[-4:]}.")
                                    return result
                            except Exception as fallback_err:
                                log.debug(
                                    f"Fallback model also failed on key ...{next_key[-4:]}: {fallback_err}")
                                # Fallback failed, continue to normal key
                                # exhaustion flow

                    if not self._groq_pool.has_keys:
                        log.error("All Groq keys exhausted (TPD).")
                        return None
                    continue  # Immediately try next key

                # ── Auth / Invalid key -> permanent death ──────────────────
                is_auth_error = (
                    "401" in err_str or "403" in err_str or
                    "unauthorized" in err_str or "forbidden" in err_str or
                    "invalid api key" in err_str or "invalid_api_key" in err_str
                )
                if is_auth_error:
                    self._groq_pool.mark_exhausted(
                        key, reason="Invalid/Blocked key (auth error)")
                    if not self._groq_pool.has_keys:
                        log.error(
                            "All Groq keys are invalid/blocked (auth error).")
                        return None
                    continue

                # ── RPM: per-minute rate limit -> temporary skip, rotate ───
                is_rpm = (
                    ("rate_limit_exceeded" in err_str and "day" not in err_str) or
                    "429" in err_str or
                    "too many requests" in err_str or
                    "requests per minute" in err_str
                )
                if is_rpm:
                    self._groq_pool.mark_rpm_limited(key)
                    next_key = self._groq_pool.get_active_key(skip_rpm=True)
                    if next_key and next_key != key:
                        log.info(
                            f"Groq RPM limit hit on ...{key[-4:]}. Rotating to ...{next_key[-4:]}.")
                        continue
                    else:
                        log.warning(
                            f"Groq RPM limit hit and no other keys. Waiting {AI_RETRY_DELAY}s...")
                        self._cooldown_backend(
                            "groq", AI_RETRY_DELAY, "RPM limit")
                        self._groq_pool.clear_rpm_flags()
                        time.sleep(AI_RETRY_DELAY)
                        continue

                # ── 503 over-capacity / overloaded -> switch to fallback model ─
                # The PRIMARY model is temporarily overloaded server-side (a Groq
                # incident, not our quota / not key-specific). Backing off and
                # retrying the SAME 70B just stalls (the "over capacity... Retry
                # in Ns" loop). The smaller fallback model is a separate capacity
                # pool and is usually unaffected, so switch to it on the SAME key
                # immediately rather than waiting out the incident.
                _active_model = (model_id or GROQ_MODEL or "").lower()
                is_capacity = (
                    "over capacity" in err_str or "over_capacity" in err_str
                    or "503" in err_str or "service unavailable" in err_str
                    or "internal_server_error" in err_str
                    or "currently overloaded" in err_str
                    or "temporarily unavailable" in err_str
                )
                if (is_capacity and not capacity_fallback_tried
                        and GROQ_FALLBACK_MODEL
                        and GROQ_FALLBACK_MODEL.lower() != _active_model):
                    capacity_fallback_tried = True
                    log.info(
                        f"[->] '{model_id or GROQ_MODEL}' is over capacity (503). "
                        f"Switching to fallback model '{GROQ_FALLBACK_MODEL}' on the same key...")
                    try:
                        result = self._groq(
                            system, user, api_key=key, model_id=GROQ_FALLBACK_MODEL)
                        if result and result.strip():
                            log.info(
                                "[+] Fallback model served the over-capacity request.")
                            return result
                    except Exception as cap_err:
                        log.debug(
                            f"Fallback model also failed during over-capacity: {cap_err}")
                    # fall through to generic backoff if the fallback also failed

                # ── Generic error -> exponential backoff ──────────────────
                delay = min(2 ** (attempt + 1), 20)
                log.warning(
                    f"Groq attempt {
                        attempt +
                        1} failed: {e}. Retry in {delay}s...")
                time.sleep(delay)

                # After a few generic failures, try next key
                if attempt > 0 and attempt % 2 == 0:
                    self._groq_pool.mark_rpm_limited(
                        key)  # Temporarily skip this key

            if attempt > max_retries * 3:
                break  # Hard limit to prevent infinite loops

        return None

    def _query_backend(self, backend: str, system: str, user: str,
                       api_key: str = None, model_id: str = None) -> str:
        backend_lower = backend.lower()
        if backend_lower == AI_NAME_GROQ.lower():
            return self._groq(system, user, api_key=api_key, model_id=model_id)
        # `model_id` here is a GROQ-specific model name (it comes from think()'s
        # tier routing / the Groq fallback model). It is meaningless to Gemini /
        # Ollama — forwarding it caused "Gemini 404 - model
        # 'llama-3.1-8b-instant' not found" when Groq exhausted and the call fell
        # back to Gemini. Non-Groq backends must use their OWN configured default.
        if backend_lower == AI_NAME_OLLAMA.lower():
            return self._ollama(system, user, model_id=None)
        elif backend_lower in (AI_NAME_GEMINI.lower(), "google"):
            return self._google(system, user, model_id=None)
        raise ValueError(f"Unknown backend: {backend}")

    def _ollama(self, system: str, user: str, model_id: str = None) -> str:
        model = model_id or OLLAMA_MODEL
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "stream": False,
            "keep_alive": OLLAMA_KEEP_ALIVE,
            "options": {
                "num_ctx": OLLAMA_NUM_CTX,
                "num_predict": 1024,
                "num_thread": OLLAMA_NUM_THREAD,
                "temperature": 0.1,
                "top_p": 0.9
            }
        }
        r = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json=payload,
            timeout=TOOL_AI_TIMEOUT
        )
        r.raise_for_status()
        return r.json()["message"]["content"]

    def _is_tpd_error(self, exception: Exception) -> bool:
        """Check if exception is a tokens-per-day exhaustion error (error code or message)."""
        err_str = str(exception).lower()

        # Check for Groq SDK structured error (if available)
        if hasattr(exception, 'response') and isinstance(
                exception.response, dict):
            error_code = exception.response.get('error', {}).get('code')
            if error_code in ('daily_token_limit_exceeded',
                              'tokens_per_day_limit_exceeded'):
                return True

        # Fallback: string matching (covers both error message formats)
        if any(phrase in err_str for phrase in [
            "tokens per day",
            "daily_token_limit",
            "tokens_per_day_limit_exceeded",
            "tpd"
        ]):
            return True

        # Check for rate_limit_exceeded with "day" in message
        if "rate_limit_exceeded" in err_str and "day" in err_str:
            return True

        return False

    def _groq(self, system: str, user: str, api_key: str = None,
              model_id: str = None) -> str:
        """Query Groq using the active key from the pool, or an override key.

        Note: Fallback model retry is handled by _query_groq_with_rotation(), not here.
        This method simply raises exceptions naturally so key rotation can handle them.
        """
        key = api_key or self._groq_pool.get_active_key()
        if not key:
            raise RuntimeError("All Groq API keys are exhausted for today.")

        # Groq limit increased to preserve command context (Groq supports up to
        # 128K with Pro)
        MAX_CHARS = 100000
        if len(system) + len(user) > MAX_CHARS:
            log.warning("Prompt too large. Truncating for Groq.")
            user = user[:MAX_CHARS - len(system) - 50] + "\n...[truncated]"

        try:
            from groq import Groq
        except ImportError:
            raise RuntimeError(
                "groq package not installed. Run: pip install groq")

        client = Groq(api_key=key)
        # Use primary model or override
        model = model_id or GROQ_MODEL

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            # 2048 was too tight: multi-command JSON attack plans were being
            # truncated mid-array, so extract_json_list() returned [] and the
            # agent saw "no prescriptions". 4096 leaves room for a full plan.
            max_tokens=4096,
            timeout=TOOL_AI_TIMEOUT
        )
        # Let exceptions (including TPD) bubble up naturally for key rotation
        # to handle
        return response.choices[0].message.content

    def _google_api_version(self, model: str = None) -> str:
        """
        Return the correct API version for a given Gemini model.
        - v1beta: all gemini-2.x and gemini-1.5 models (experimental / preview)
        - v1:     legacy stable models only (gemini-1.0-pro, etc.)
        """
        model_name = model or GOOGLE_MODEL
        model_lower = (model_name or "").lower()
        # gemini-3.x, gemini-2.x and gemini-1.5-x require v1beta
        if model_lower.startswith("gemini-3.") or model_lower.startswith(
                "gemini-2.") or "2.5" in model_lower or "2.0" in model_lower:
            return AI_VERSION_V1BETA
        if model_lower.startswith("gemini-1.5"):
            return AI_VERSION_V1BETA
        # Older stable models use v1
        return AI_VERSION_V1

    def _google(self, system: str, user: str, model_id: str = None) -> str:
        """Google Gemini via direct REST API (no SDK needed)."""
        MAX_CHARS = 100000
        if len(system) + len(user) > MAX_CHARS:
            log.warning("Prompt too large. Truncating for Gemini.")
            user = user[:MAX_CHARS - len(system) - 50] + "\n...[truncated]"

        primary_model = model_id or GOOGLE_MODEL or "gemini-3.1-flash-lite"

        # Build candidate list: primary model first, followed by free/lite
        # models
        free_models = [
            "gemini-3.1-flash-lite",
            "gemini-2.0-flash",
            "gemini-1.5-flash",
        ]

        candidates = [primary_model]
        for fm in free_models:
            if fm not in candidates:
                candidates.append(fm)

        last_err = None
        for model in candidates:
            try:
                api_version = self._google_api_version(model)
                url = (
                    f"https://generativelanguage.googleapis.com/{api_version}/models/"
                    f"{model}:generateContent?key={GOOGLE_API_KEY}"
                )
                log.debug(
                    f"Google Gemini: using API version {api_version} for model {model}")

                payload = {
                    "contents": [
                        {
                            "role": "user",
                            "parts": [{"text": f"{system}\n\n{user}"}]
                        }
                    ],
                    "generationConfig": {
                        "temperature": 0.2,
                        # Matches the Groq cap — avoids truncating multi-command
                        # JSON attack plans mid-array.
                        "maxOutputTokens": 4096,
                        "topP": 0.9
                    },
                    "safetySettings": [
                        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                            "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_HARASSMENT",
                            "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_HATE_SPEECH",
                            "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                            "threshold": "BLOCK_NONE"},
                    ]
                }

                r = requests.post(url, json=payload, timeout=TOOL_AI_TIMEOUT)

                # Provide a more helpful error message if API version is wrong
                if r.status_code == 404:
                    raise ValueError(
                        f"Gemini 404 - model '{model}' not found on {api_version} endpoint."
                    )
                r.raise_for_status()
                data = r.json()

                # Check for prompt blocking
                prompt_feedback = data.get("promptFeedback", {})
                if prompt_feedback.get("blockReason"):
                    raise ValueError(
                        f"Gemini blocked prompt: {
                            prompt_feedback.get('blockReason')}")

                candidates_res = data.get("candidates", [])
                if not candidates_res:
                    raise ValueError(f"Gemini returned no candidates: {data}")

                # Check finish reason
                finish_reason = candidates_res[0].get("finishReason", "")
                if finish_reason in ("SAFETY", "RECITATION", "OTHER"):
                    raise ValueError(
                        f"Gemini refused response (finishReason={finish_reason})")

                parts = candidates_res[0].get("content", {}).get("parts", [])
                if not parts:
                    raise ValueError(f"Gemini returned empty parts: {data}")

                content = parts[0].get("text", "")
                if content and content.strip():
                    if model != primary_model:
                        log.info(
                            f"Google Gemini: fallback model '{model}' succeeded.")
                    return content
                raise ValueError("Gemini returned empty text response")
            except Exception as e:
                log.warning(
                    f"Google Gemini model '{model}' query failed: {e}. Trying next available free model...")
                last_err = e

        raise last_err
