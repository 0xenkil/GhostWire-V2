"""Defensive HTTP pacing helpers."""


def get_random_ua() -> str:
    """Return a plain tool User-Agent for compatibility."""
    return "antigravity-security-assessment"


