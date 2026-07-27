def should_retry(result) -> bool:
    """
    Coarse pre-filter for the repair loop. This is NOT the decision authority —
    `_interpret_outcome` (the AI triage in safe_run_tool) already ran on this
    result and chose not to accept/abandon it, i.e. it judged the failure worth
    repairing. So this function must only short-circuit failures that NO command
    rewrite could fix — never argument/URL/protocol errors, which are exactly
    what the repair loop + --help grounding exist to fix.

    Returns False ONLY for STRUCTURALLY un-repairable failures (a different
    command string cannot help):
    - Exit 6:   DNS resolution failure  (host does not resolve)
    - Exit 7:   Connection refused       (port closed)
    - Exit 126: Permission denied / not executable
    - Exit 127: Command not found        (tool not installed)
    - Exit 137: SIGKILL  (OOM / killed)
    - Exit 143: SIGTERM  (killed, e.g. our own timeout)
    - Exit -1:  No exit code captured — nothing to reason about

    Deliberately NOT here (these ARE repairable, the repair loop handles them,
    bounded by max_repairs):
    - Exit 2:  invalid arguments  (argparse usage error — THE repair case)
    - Exit 3:  malformed URL
    - Exit 28: operation timeout  (can lighten/extend or retry transient)
    - Exit 35: TLS handshake      (can add -k / switch http<->https)
    - Exit 52: empty reply        (often transient / WAF)
    - Exit 56: connection reset   (often transient / WAF)
    """
    if not result:
        return False

    # Get exit code safely from either a dict or a ToolResult object
    if isinstance(result, dict):
        exit_code = result.get("exit_code")
    else:
        exit_code = getattr(result, 'exit_code', None)

    # Only structurally un-repairable failures — a command rewrite cannot help.
    _NO_RETRY_EXITS = {-1, 6, 7, 126, 127, 137, 143}
    return exit_code not in _NO_RETRY_EXITS
