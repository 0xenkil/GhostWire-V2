import re


def clean_text(text):
    return text


def _clean_command(command: str) -> str:
    if not command:
        return ""
    command = re.sub(r'[^\x20-\x7E\n\t]', '', command.strip())
    # Remove $(dig +short TARGET) wrapper since Python handles resolution
    # natively
    command = re.sub(r'\$\(\s*dig\s+\+short\s+([^\)]+)\)', r'\1', command)
    command = re.sub(r'`\s*dig\s+\+short\s+([^`]+)`', r'\1', command)
    return command


def _normalize_command_targets(command: str) -> str:
    return command


def _repair_common_tool_flags(tool_name: str, repaired: str) -> str:
    if tool_name == "masscan":
        # Strip bash subshell injections like $(dig +short TARGET)
        subshell_match = re.search(
            r'\$\(\s*dig\s+\+short\s+([^)]+)\)', repaired)
        if subshell_match:
            repaired = repaired.replace(
                subshell_match.group(0),
                subshell_match.group(1).strip())
            print(
                f"[MASSCAN FIX] Stripped bash subshell syntax, resolved to: {
                    subshell_match.group(1).strip()}")

        repaired = re.sub(r"https?://", "", repaired)
        repaired = re.sub(r"(?<=[0-9a-zA-Z._-])/+\s", " ", repaired)
        repaired = re.sub(r"(?<=[0-9a-zA-Z._-])/+$", "", repaired)

        # Detect and resolve any non-IP token that sits between 'masscan' and '-p'.
        # Pattern: masscan [options] TARGET -p... where TARGET is not a pure
        # IP/CIDR.
        def _resolve_masscan_target(m: re.Match) -> str:
            token = m.group(1)
            # Is it already a valid IPv4 or CIDR?
            if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?$', token):
                return m.group(0)  # Already fine
            # Token looks like "subdomain.1.2.3.4" - extract the trailing IP
            ip_suffix = re.search(r'(?:\d{1,3}\.){3}\d{1,3}', token)
            if ip_suffix:
                return m.group(0).replace(token, ip_suffix.group())
            # Pure hostname - try to resolve to IP
            return m.group(0)
        repaired = re.sub(
            r'(?<=masscan\s)(?!-[a-zA-Z])([^\s]+)(?=\s+-p|\s*$)',
            _resolve_masscan_target,
            repaired)
        repaired = re.sub(
            r'(?<=\s)([^\s]+)(?=\s+-p|\s*$)',
            _resolve_masscan_target,
            repaired)
    return repaired


cmd = "masscan -p80,443 $(dig +short usageapi.216.198.79.1)"
print("Original:", cmd)
c1 = clean_text(cmd)
c2 = _clean_command(c1)
c3 = _normalize_command_targets(c2)
c4 = _repair_common_tool_flags("masscan", c3)
print("Final:", c4)
