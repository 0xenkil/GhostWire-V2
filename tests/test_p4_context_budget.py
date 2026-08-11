"""Phase 4 — P4-6 deterministic context-window budget (DEEP-4)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.context_budget import (  # noqa: E402
    cap_output, trim_history, DEFAULT_MAX_OUTPUT_BYTES,
)


def test_short_output_unchanged():
    assert cap_output("hello") == "hello"
    assert cap_output("") == ""


def test_huge_output_capped_with_visible_marker_and_bounded():
    big = "A" * 100 + "B" * 50000 + "Z" * 100
    out = cap_output(big, max_bytes=2000)
    assert len(out.encode("utf-8")) <= 2000
    assert "CONTEXT-BUDGET" in out          # visible, never silent
    assert out.startswith("A")               # head kept
    assert out.rstrip().endswith("Z")        # tail kept (final result line survives)


def test_cap_is_idempotent():
    big = "X" * 40000
    once = cap_output(big, max_bytes=1000)
    twice = cap_output(once, max_bytes=1000)
    assert once == twice


def test_trim_history_bounds_count_and_bytes():
    items = [f"obs-{i}-" + "x" * 100 for i in range(50)]
    kept, dropped = trim_history(items, max_items=10, max_bytes=10_000)
    assert len(kept) <= 10 and dropped == len(items) - len(kept)
    # newest survive, oldest dropped
    assert kept[-1] == items[-1]
    assert items[0] not in kept


def test_trim_history_keeps_at_least_newest():
    huge = ["y" * 100000 for _ in range(5)]
    kept, dropped = trim_history(huge, max_items=20, max_bytes=1000)
    assert len(kept) == 1 and kept[0] == huge[-1]  # never loses the latest observation


def test_default_output_cap_is_reasonable():
    assert 1000 <= DEFAULT_MAX_OUTPUT_BYTES <= 64000
