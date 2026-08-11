"""Phase 4 — P4-1 bounded/interruptible backend recovery + BackendExhausted
(AIBACKEND-SLEEP-1 / ORCH-TIMEOUT-1 / DEEP-9).

The exhaustion path used to `time.sleep(recovery_time)` with the FULL provider
recovery window (up to ~an hour), pinning the caller past the phase deadline.
Now:
  - the inline recovery sleep is CAPPED at RECOVERY_SLEEP_CAP and runs in 1s
    slices so an abort Event breaks out promptly,
  - a window longer than the cap is surfaced as BackendExhausted (the caller
    waits within its own budget), and
  - BackendExhausted subclasses RuntimeError so existing catches still hold.

These are the deterministic pieces (no live backend needed). The remaining piece
— running query() via asyncio.to_thread so asyncio.timeout can cancel mid-recovery
— needs a live event loop + backend and is verified in a live-env session.
"""
import os
import sys
import threading
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.ai_backend as m  # noqa: E402
from core.ai_backend import AIBackend, BackendExhausted, RECOVERY_SLEEP_CAP  # noqa: E402


def test_backend_exhausted_is_runtimeerror_with_recovery():
    e = BackendExhausted("all out", recovery_seconds=42)
    assert isinstance(e, RuntimeError)     # existing `except RuntimeError` still catches it
    assert e.recovery_seconds == 42
    assert "all out" in str(e)


def test_recovery_cap_is_sane():
    assert isinstance(RECOVERY_SLEEP_CAP, int) and 0 < RECOVERY_SLEEP_CAP <= 600


def test_bounded_sleep_caps_a_huge_window(monkeypatch):
    # Never sleep the full hour — cap it. (time.sleep stubbed so the test is fast.)
    monkeypatch.setattr(m.time, "sleep", lambda s: None)
    fake = types.SimpleNamespace(_shutdown_event=None)
    slept = AIBackend._bounded_recovery_sleep(fake, 3600)
    assert slept == RECOVERY_SLEEP_CAP


def test_bounded_sleep_respects_short_window(monkeypatch):
    monkeypatch.setattr(m.time, "sleep", lambda s: None)
    fake = types.SimpleNamespace(_shutdown_event=None)
    assert AIBackend._bounded_recovery_sleep(fake, 5) == 5


def test_bounded_sleep_is_interruptible(monkeypatch):
    monkeypatch.setattr(m.time, "sleep", lambda s: None)
    ev = threading.Event()
    ev.set()  # abort already requested
    fake = types.SimpleNamespace(_shutdown_event=ev)
    assert AIBackend._bounded_recovery_sleep(fake, 3600) == 0


def test_bounded_sleep_handles_bad_input(monkeypatch):
    monkeypatch.setattr(m.time, "sleep", lambda s: None)
    fake = types.SimpleNamespace(_shutdown_event=None)
    assert AIBackend._bounded_recovery_sleep(fake, None) == 0
    assert AIBackend._bounded_recovery_sleep(fake, "nope") == 0
