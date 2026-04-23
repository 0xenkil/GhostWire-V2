def should_retry(result) -> bool:
    """
    Determines if a tool execution should be retried by the Ghost Protocol.
    Handles both ToolResult objects and plain dicts safely.

    Returns False for failures that AI repair cannot fix:
    - Exit 2:  Shell misuse / invalid arguments
    - Exit 3:  Curl malformed URL
    - Exit 6:  DNS resolution failure
    - Exit 7:  Connection refused
    - Exit 28: Connection timeout
    - Exit 35: TLS/SSL handshake failure
    - Exit 52: Empty reply from server
    - Exit 56: TCP connection reset (RST)
    """
    if not result:
        return False

    # Get exit code safely from either a dict or a ToolResult object
    if isinstance(result, dict):
        exit_code = result.get("code")
    else:
        exit_code = getattr(result, 'exit_code', None)

    # Network and input errors that AI repair cannot fix
    _NO_RETRY_EXITS = {2, 3, 6, 7, 28, 35, 52, 56, 127}
    return exit_code not in _NO_RETRY_EXITS
