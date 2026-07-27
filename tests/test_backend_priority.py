"""Guard: Groq is PRIMARY, Gemini is FALLBACK (reverted 2026-06-20).

Gemini-primary was tried but a FREE Gemini key rate-limits after a few calls and
served ~0 queries in a real run (everything fell back to Groq anyway), so it was
reverted. These tests pin Groq-primary / Gemini-fallback so it can't silently flip
back. (If a PAID Gemini key is used, set AI_BACKEND=gemini explicitly.)
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fake(available, backend="groq", groq_keys=True):
    f = types.SimpleNamespace()
    f.backend = backend
    f._available_backends = available
    f._groq_pool = types.SimpleNamespace(has_keys=groq_keys)
    f._backend_is_cooled_down = lambda b: False
    return f


def test_default_ai_backend_is_groq():
    import config
    assert config.AI_BACKEND == "groq"


def test_small_prompt_leads_with_groq():
    import core.ai_backend as ab
    ab.GOOGLE_API_KEY = "fake"
    order = ab.AIBackend._select_backend_order_for_prompt(
        _fake(["groq", "gemini"]), 3000)
    assert order[0] == "groq"
    assert order.index("groq") < order.index("gemini")


def test_gemini_leads_only_when_groq_unavailable():
    import core.ai_backend as ab
    ab.GOOGLE_API_KEY = "fake"
    # Groq pool dead -> fall back to Gemini (free cloud)
    order = ab.AIBackend._select_backend_order_for_prompt(
        _fake(["gemini"], backend="groq", groq_keys=False), 3000)
    assert order[0] == "gemini"
