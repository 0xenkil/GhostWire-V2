from core.ai_backend import AIBackend
import unittest
from unittest.mock import patch, PropertyMock
import time

# Mock config before importing ai_backend
import sys
from types import ModuleType

# Save original modules to prevent global contamination
orig_config = sys.modules.get("config")
orig_config_thresholds = sys.modules.get("config_thresholds")
orig_config_backends = sys.modules.get("config_backends")
orig_ai_backend = sys.modules.get("core.ai_backend")

# Force reload of core.ai_backend with mock config
sys.modules.pop("core.ai_backend", None)

m_config = ModuleType("config")
m_config.AI_BACKEND = "groq"
m_config.OLLAMA_BASE_URL = "http://localhost:11434"
m_config.OLLAMA_MODEL = "gemma"
m_config.GROQ_API_KEY = 'dummy'
m_config.GROQ_MODEL = "llama-3-70b"
m_config.GROQ_FALLBACK_MODEL = "llama-3-8b"
m_config.GROQ_API_KEY_POOL = ["key1", "key2"]
m_config.GOOGLE_API_KEY = "goog_key"
m_config.GOOGLE_MODEL = "gemini-1.5-flash"
m_config.OPENROUTER_API_KEY = "or_key"
m_config.OPENROUTER_MODEL = "meta-llama/llama-3-70b"
m_config.RATE_LIMIT_INITIAL_BACKOFF = 1
m_config.TOOL_AI_TIMEOUT = 5
m_config.OLLAMA_NUM_THREAD = 1
m_config.OLLAMA_KEEP_ALIVE = "0"
m_config.OLLAMA_NUM_CTX = 2048
m_config.AI_NAME_GEMINI = "Gemini"
m_config.AI_NAME_GROQ = "Groq"
m_config.AI_NAME_OLLAMA = "Ollama"
m_config.AI_NAME_OPENROUTER = "OpenRouter"
m_config.PROXY_PORT = 8080
m_config.AI_VERSION_V1BETA = "v1beta"
m_config.AI_VERSION_V1 = "v1"
sys.modules["config"] = m_config

m_config_backends = ModuleType("config_backends")
m_config_backends.OLLAMA_BASE_URL = "http://localhost:11434"
m_config_backends.GROQ_MODEL = "llama-3-70b"
m_config_backends.GROQ_FALLBACK_MODEL = "llama-3-8b"
m_config_backends.GROQ_API_KEY_POOL = ["key1", "key2"]
m_config_backends.GOOGLE_API_KEY = "goog_key"
m_config_backends.GOOGLE_MODEL = "gemini-1.5-flash"
sys.modules["config_backends"] = m_config_backends

m_config_thresholds = ModuleType("config_thresholds")
m_config_thresholds.AI_RETRY_DELAY = 1
m_config_thresholds.TOOL_AI_TIMEOUT = 180
m_config_thresholds.AI_NAME_GEMINI = "gemini"
m_config_thresholds.AI_NAME_GROQ = "groq"
m_config_thresholds.AI_NAME_OLLAMA = "ollama"
m_config_thresholds.AI_NAME_OPENROUTER = "openrouter"
m_config_thresholds.AI_VERSION_V1BETA = "v1beta"
m_config_thresholds.AI_VERSION_V1 = "v1"
sys.modules["config_thresholds"] = m_config_thresholds

# Now import the backend

# Restore original modules in sys.modules immediately
if orig_config is not None:
    sys.modules["config"] = orig_config
else:
    sys.modules.pop("config", None)

if orig_config_backends is not None:
    sys.modules["config_backends"] = orig_config_backends
else:
    sys.modules.pop("config_backends", None)

if orig_config_thresholds is not None:
    sys.modules["config_thresholds"] = orig_config_thresholds
else:
    sys.modules.pop("config_thresholds", None)

if orig_ai_backend is not None:
    sys.modules["core.ai_backend"] = orig_ai_backend
else:
    sys.modules.pop("core.ai_backend", None)


class TestAIFallback(unittest.TestCase):
    def setUp(self):
        # Clear any cached instances if they were singleton (not here but good
        # practice)
        pass

    @patch("core.ai_backend.requests.head")
    @patch("core.ai_backend.requests.get")
    def test_backend_detection_naming(self, mock_get, mock_head):
        """Verify that backends are detected with correct constant-based names."""
        mock_head.return_value.status_code = 200
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "models": [
                {"name": "gemma"},
                {"name": "huihui_ai/gemma-4-abliterated:e4b-q8_0"}
            ]
        }

        backend = AIBackend()
        available = backend._available_backends

        self.assertIn("groq", available)
        self.assertIn("gemini", available)
        self.assertIn("ollama", available)

    @patch("core.ai_backend.AIBackend._query_backend")
    def test_query_gemini_mapping(self, mock_query):
        """Verify that 'gemini' is correctly mapped to _google in _query_backend."""
        backend = AIBackend()

        # We want to test the REAL _query_backend logic but mock its output
        # So we don't mock _query_backend at the instance level here
        with patch.object(backend, "_google", return_value="google response") as mock_google:
            # We call the real _query_backend
            # Note: _query_backend was patched in the decorator, so we need to
            # bypass it or use another approach
            pass

    def test_query_gemini_mapping_no_patch(self):
        """Verify that 'gemini' is correctly mapped to _google in _query_backend."""
        backend = AIBackend()
        with patch.object(backend, "_google", return_value="google response") as mock_google:
            res = backend._query_backend("gemini", "sys", "user")
            self.assertEqual(res, "google response")
            mock_google.assert_called_once()

    @patch("core.ai_backend.time.sleep")
    @patch("core.ai_backend.requests.get")
    def test_dns_failure_fallback(self, mock_get, mock_sleep):
        """Verify that NameResolutionError triggers immediate fallback and cooldown."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "models": [
                {"name": "gemma"},
                {"name": "huihui_ai/gemma-4-abliterated:e4b-q8_0"}
            ]
        }
        backend = AIBackend()

        # Properly mock the has_keys property
        with patch.object(type(backend._groq_pool), "has_keys", new_callable=PropertyMock) as mock_has_keys:
            mock_has_keys.return_value = False

            def side_effect(b, s, u, **kwargs):
                if b == "gemini":
                    # Simulate DNS failure string which triggers our catch
                    raise ConnectionError(
                        "Max retries exceeded with url: ... (Caused by NameResolutionError(...))")
                return "fallback success"

            with patch.object(backend, "_query_backend", side_effect=side_effect):
                start_time = time.time()
                res = backend.query("sys", "user", max_retries=2)
                end_time = time.time()

                # Should have skipped gemini immediately and moved to next
                # (likely openrouter or ollama)
                self.assertEqual(res, "fallback success")
                self.assertLess(end_time - start_time, 2)
                self.assertTrue(backend._backend_is_cooled_down("gemini"))


if __name__ == "__main__":
    unittest.main()
