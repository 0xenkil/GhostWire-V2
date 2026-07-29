"""Structural, tool-agnostic classification of process exit codes.

The single source of truth for "which failures can a command *rewrite* possibly
fix?". Everything here reasons purely from POSIX exit-code semantics — there is
NO per-tool, per-flag, or per-error-string logic, so a tool the system has never
seen inherits the same guarantees automatically.
"""

# ── Exit-code classes (single source of truth) ──────────────────────────────
# A missing / non-executable binary. No flag change can conjure a binary that
# isn't there — route to the installer / NOT_INSTALLED handling instead of the
# AI repair loop (which would otherwise guess flags at a command that can never
# run — the #1 hallucination-compounding path).
_MISSING_BINARY_EXITS = frozenset({126, 127})  # 126 not executable, 127 not found

# Structurally un-repairable for OTHER reasons: the target/host/process is the
# problem, not the command string. Rewriting the command cannot help.
#   -1  no exit code captured — nothing to reason about
#    6  DNS resolution failure (host does not resolve)
#    7  connection refused      (port closed)
#  137  SIGKILL  (OOM / external kill)
#  143  SIGTERM  (killed, e.g. our own timeout)
_UNREPAIRABLE_EXITS = frozenset({-1, 6, 7, 137, 143})

# Union: the full set of exits that NO command rewrite can fix. Derived from the
# two sub-sets above so the classifier and should_retry() can never drift apart.
_NO_RETRY_EXITS = _MISSING_BINARY_EXITS | _UNREPAIRABLE_EXITS


def _exit_code_of(result):
    """Extract the exit code from either a dict or a ToolResult-like object."""
    if not result:
        return None
    if isinstance(result, dict):
        return result.get("exit_code")
    return getattr(result, "exit_code", None)


def classify_unrepairable(result) -> str | None:
    """Classify a NON-success result by exit-code semantics alone.

    Returns:
      • "not_installed" — exit 126/127: the binary is missing/not executable.
        The caller should mark NOT_INSTALLED (so tool-install / ban logic acts)
        and NOT enter the AI triage or repair loop.
      • "abandon"       — exit -1/6/7/137/143: a real, non-recoverable failure of
        the target/process that a command rewrite cannot fix.
      • None            — not structurally hopeless; let the normal AI triage +
        --help-grounded repair flow decide (this is the common case).

    Deliberately returns None for repairable exits (2 bad-args, 3 bad-URL,
    28 timeout, 35 TLS, 52 empty-reply, 56 conn-reset, …) — those are exactly
    what the bounded repair loop exists to fix.
    """
    exit_code = _exit_code_of(result)
    if exit_code in _MISSING_BINARY_EXITS:
        return "not_installed"
    if exit_code in _UNREPAIRABLE_EXITS:
        return "abandon"
    return None


def should_retry(result) -> bool:
    """
    Coarse pre-filter for the repair loop. This is NOT the decision authority —
    `_interpret_outcome` (the AI triage in safe_run_tool) already ran on this
    result and chose not to accept/abandon it, i.e. it judged the failure worth
    repairing. So this function must only short-circuit failures that NO command
    rewrite could fix — never argument/URL/protocol errors, which are exactly
    what the repair loop + --help grounding exist to fix.

    Returns False ONLY for STRUCTURALLY un-repairable failures (a different
    command string cannot help): the `_NO_RETRY_EXITS` set defined above
    (126, 127, -1, 6, 7, 137, 143).

    Deliberately NOT in that set (these ARE repairable, the repair loop handles
    them, bounded by max_repairs):
    - Exit 2:  invalid arguments  (argparse usage error — THE repair case)
    - Exit 3:  malformed URL
    - Exit 28: operation timeout  (can lighten/extend or retry transient)
    - Exit 35: TLS handshake      (can add -k / switch http<->https)
    - Exit 52: empty reply        (often transient / WAF)
    - Exit 56: connection reset   (often transient / WAF)
    """
    if not result:
        return False
    return _exit_code_of(result) not in _NO_RETRY_EXITS
