import time
import threading
import requests
from config import (
    AI_BACKEND, OLLAMA_BASE_URL, OLLAMA_MODEL,
    GROQ_API_KEY, GROQ_MODEL, GROQ_API_KEY_POOL,
    GOOGLE_API_KEY, GOOGLE_MODEL,
    TOOL_AI_TIMEOUT, OLLAMA_NUM_THREAD,
    OLLAMA_KEEP_ALIVE, OLLAMA_NUM_CTX
)
from utils.logger import get_logger

log = get_logger("ai_backend")


class GroqKeyPool:
    """
    Thread-safe rotating pool of Groq API keys.
    When a key hits its daily token limit (TPD), it is parked
    and the next key is tried automatically.
    """
    def __init__(self, keys: list):
        self._keys = list(keys)          # all keys
        self._exhausted = set()          # keys that hit TPD today
        self._lock = threading.Lock()
        self._current_idx = 0
        total = len(self._keys)
        log.info(f"Groq key pool initialized with {total} key(s).")

    def get_active_key(self) -> str | None:
        """Return the current active key, or None if all are exhausted."""
        with self._lock:
            for i in range(len(self._keys)):
                idx = (self._current_idx + i) % len(self._keys)
                key = self._keys[idx]
                if key not in self._exhausted:
                    self._current_idx = idx
                    return key
        return None

    def mark_exhausted(self, key: str):
        """Mark a key as TPD-exhausted. Rotates to next automatically."""
        with self._lock:
            if key not in self._exhausted:
                self._exhausted.add(key)
                masked = key[:8] + "..." + key[-4:]
                remaining = len(self._keys) - len(self._exhausted)
                log.warning(
                    f"Groq key {masked} daily limit hit. "
                    f"{remaining}/{len(self._keys)} key(s) remaining in pool."
                )
                # Advance index past this key
                self._current_idx = (self._current_idx + 1) % len(self._keys)

    @property
    def has_keys(self) -> bool:
        with self._lock:
            return any(k not in self._exhausted for k in self._keys)

    @property
    def pool_status(self) -> str:
        with self._lock:
            active = len(self._keys) - len(self._exhausted)
            return f"{active}/{len(self._keys)} Groq keys active"


class AIBackend:
    def __init__(self, preferred_backend: str = None):
        self.backend = preferred_backend or AI_BACKEND
        self._groq_pool = GroqKeyPool(GROQ_API_KEY_POOL)
        self._available_backends = self._detect_available()
        active = self._available_backends[0] if self._available_backends else "none"
        log.info(f"AI Backend active: {active} | {self._groq_pool.pool_status}")

    def _detect_available(self) -> list:
        available = []

        # Priority 1: Groq key pool
        if self._groq_pool.has_keys:
            available.append("groq")
            log.info(f"Groq pool ready — {self._groq_pool.pool_status}")

        # Priority 2: Google Gemini
        if GOOGLE_API_KEY:
            available.append("google")
            log.info("Google Gemini API key found — free cloud fallback enabled.")

        # Priority 3: Ollama (local)
        try:
            r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                if any(OLLAMA_MODEL.split(":")[0] in m for m in models):
                    available.append("ollama")
                    log.info(f"Ollama available with model {OLLAMA_MODEL}")
                else:
                    log.warning(f"Ollama running but model {OLLAMA_MODEL} not found.")
        except Exception:
            log.debug("Ollama not reachable (normal if using cloud API).")

        if not available:
            log.warning("No AI backend available. Check GROQ_API_KEYS or GOOGLE_API_KEY in .env")
        return available

    @property
    def ai_available(self) -> bool:
        """Check if at least one AI backend is still functional."""
        return bool(self._available_backends) and (
            self._groq_pool.has_keys or
            "google" in self._available_backends or
            "ollama" in self._available_backends
        )

    def query(self, system_prompt: str, user_message: str, max_retries: int = 4) -> str:
        """
        Query AI with automatic fallback:
          Groq (key 1 → key 2 → key 3) → Google Gemini → Ollama
        Never raises — returns a degraded string on total failure.
        """
        # Auto-truncate oversized prompts
        MAX_PROMPT = 18000
        if len(system_prompt) + len(user_message) > MAX_PROMPT:
            log.warning(f"Prompt too large ({len(system_prompt)+len(user_message)} chars). Truncating.")
            user_message = user_message[:MAX_PROMPT - len(system_prompt) - 200] + "\n...[truncated]"

        # Build ordered backend list: preferred first
        backends_to_try = []
        if self.backend and self.backend in self._available_backends:
            backends_to_try.append(self.backend)
        for b in self._available_backends:
            if b not in backends_to_try:
                backends_to_try.append(b)

        if not backends_to_try:
            backends_to_try = ["groq", "google", "ollama"]

        last_error = None
        for backend in backends_to_try:
            for attempt in range(max_retries):
                try:
                    log.debug(f"AI query via {backend} (attempt {attempt + 1})")
                    result = self._query_backend(backend, system_prompt, user_message)
                    if result and result.strip():
                        return result.strip()
                except Exception as e:
                    err_str = str(e).lower()

                    # ── Groq TPD: rotate to next key ──────────────────
                    if "tokens per day" in err_str or "rate_limit_exceeded" in err_str and "day" in err_str:
                        key = getattr(e, "active_key", None)
                        if key:
                            self._groq_pool.mark_exhausted(key)
                        if self._groq_pool.has_keys:
                            log.info("Rotated to next Groq key — retrying immediately.")
                            continue  # retry same backend with next key
                        else:
                            log.error("All Groq keys exhausted. Falling through to next backend.")
                            break

                    # ── 429 Rate Limit (RPM): wait and retry ──────────
                    elif "429" in err_str or "too many requests" in err_str:
                        if attempt < 2:
                            wait = 15 * (attempt + 1)  # 15s, 30s
                            log.warning(f"'{backend}' rate-limited (429). Waiting {wait}s...")
                            time.sleep(wait)
                            continue
                        else:
                            log.warning(f"'{backend}' still rate-limited after retries. Next backend.")
                            break

                    # ── Quota / billing error: skip backend entirely ───
                    elif "quota" in err_str and "429" not in err_str:
                        log.error(f"'{backend}' quota/billing error. Skipping.")
                        break

                    # ── Generic error: exponential backoff ────────────
                    else:
                        last_error = e
                        delay = min(2 ** (attempt + 1), 20)
                        log.warning(f"'{backend}' attempt {attempt+1} failed: {e}. Retry in {delay}s...")
                        time.sleep(delay)

        log.error(f"All AI backends exhausted. Last error: {last_error}")
        return f"[AI unavailable — all backends exhausted. Last error: {last_error}]"

    def _query_backend(self, backend: str, system: str, user: str) -> str:
        if backend == "ollama":
            return self._ollama(system, user)
        elif backend == "groq":
            return self._groq(system, user)
        elif backend == "google":
            return self._google(system, user)
        raise ValueError(f"Unknown backend: {backend}")

    def _ollama(self, system: str, user: str) -> str:
        payload = {
            "model": OLLAMA_MODEL,
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

    def _groq(self, system: str, user: str) -> str:
        """Query Groq using the active key from the pool."""
        key = self._groq_pool.get_active_key()
        if not key:
            raise RuntimeError("All Groq API keys are exhausted for today.")

        # Groq free tier cap
        MAX_CHARS = 20000
        if len(system) + len(user) > MAX_CHARS:
            log.warning(f"Prompt too large. Truncating for Groq.")
            user = user[:MAX_CHARS - len(system) - 200] + "\n...[truncated]"

        try:
            from groq import Groq
        except ImportError:
            raise RuntimeError("groq package not installed. Run: pip install groq")

        client = Groq(api_key=key)
        try:
            response = client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user}
                ],
                max_tokens=2048,
                timeout=TOOL_AI_TIMEOUT
            )
            return response.choices[0].message.content
        except Exception as e:
            e.active_key = key
            raise

    def _google(self, system: str, user: str) -> str:
        """Google Gemini via direct REST API (no SDK needed)."""
        MAX_CHARS = 28000
        if len(system) + len(user) > MAX_CHARS:
            log.warning(f"Prompt too large. Truncating for Gemini.")
            user = user[:MAX_CHARS - len(system) - 200] + "\n...[truncated]"

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{GOOGLE_MODEL}:generateContent?key={GOOGLE_API_KEY}"
        )
        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": f"{system}\n\n{user}"}]}
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 2048,
                "topP": 0.9
            }
        }

        r = requests.post(url, json=payload, timeout=TOOL_AI_TIMEOUT)
        r.raise_for_status()
        data = r.json()

        candidates = data.get("candidates", [])
        if not candidates:
            raise ValueError(f"Gemini returned no candidates: {data}")
        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            raise ValueError(f"Gemini returned empty parts: {data}")
        return parts[0].get("text", "")
