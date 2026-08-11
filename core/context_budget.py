"""core/context_budget.py — deterministic context-window budget (P4-6 / DEEP-4).

Alongside the TOKEN budget (P4-2, which bounds how many LLM calls happen), this
bounds how much goes INTO each prompt so growth can't cause silent mid-response
truncation (the JSON/parse-failure family). Everything here is RULE-BASED — no new
LLM pass — and leaves a VISIBLE marker, so trimming is never silent.
"""
from __future__ import annotations

DEFAULT_MAX_OUTPUT_BYTES = 8000
DEFAULT_MAX_HISTORY_ITEMS = 20
DEFAULT_MAX_HISTORY_BYTES = 40000

_MARKER = "\n...[CONTEXT-BUDGET: dropped {dropped} bytes deterministically]...\n"


def cap_output(text: str, max_bytes: int = DEFAULT_MAX_OUTPUT_BYTES) -> str:
    """Deterministically cap ``text`` to ~max_bytes, keeping the HEAD and TAIL —
    a tool's banner/columns AND its final result/error line are the informative
    ends; the middle is the least useful. Inserts a visible marker. Idempotent
    (re-capping capped text is a no-op) and never silently truncates."""
    if not text:
        return text or ""
    raw = text.encode("utf-8", "ignore")
    if len(raw) <= max_bytes:
        return text
    dropped = len(raw) - max_bytes
    marker = _MARKER.format(dropped=dropped)
    budget = max(0, max_bytes - len(marker.encode("utf-8")))
    head = (budget * 2) // 3
    tail = budget - head
    return (raw[:head].decode("utf-8", "ignore")
            + marker
            + (raw[-tail:].decode("utf-8", "ignore") if tail else ""))


def trim_history(items, max_items: int = DEFAULT_MAX_HISTORY_ITEMS,
                 max_bytes: int = DEFAULT_MAX_HISTORY_BYTES, serialize=None):
    """Keep the most RECENT items under BOTH a count and a byte budget, dropping
    the OLDEST first (recency = relevance in a ReAct loop). Returns
    ``(kept, dropped_count)``. Deterministic; always keeps at least the newest
    item so the loop never loses its latest observation."""
    if not items:
        return [], 0
    ser = serialize or (lambda x: str(x))
    kept = list(items[-max_items:])
    while len(kept) > 1:
        total = sum(len(ser(x).encode("utf-8", "ignore")) for x in kept)
        if total <= max_bytes:
            break
        kept.pop(0)
    return kept, len(items) - len(kept)
