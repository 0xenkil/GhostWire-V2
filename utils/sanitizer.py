from core.robust_parser import extract_json_list as robust_extract_json_list
import re


def remove_ansi(text: str) -> str:
    """Remove ANSI escape sequences from strings."""
    if not isinstance(text, str):
        return str(text)
    # Remove ANSI CSI escape sequences (e.g. \x1b[31m, \x1b[2K)
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    return ansi_escape.sub('', text)


def remove_artifacts(text: str) -> str:
    """Remove leftover terminal control sequences that are NOT part of tool output.

    IMPORTANT: We must NOT strip bracket patterns like [Status: 200] which appear
    in gobuster/ffuf output and are required for parsing. Only strip pure escape
    sequences that start with ESC (\x1b) or VT100 cursor control codes.
    """
    # Remove VT100 cursor hide/show: ESC[?25l, ESC[?25h
    text = re.sub(r'\x1b\[\?[0-9]+[a-zA-Z]', '', text)
    # Remove dangling ANSI erase line codes that lost their ESC byte across
    # chunk boundaries
    text = re.sub(r'^\[2K\r?', '', text)
    text = text.replace("[2K", "")
    return text


def _collapse_carriage_returns(text: str) -> str:
    """Collapse in-line carriage-return redraws (progress bars) WITHOUT
    deleting real content — SANITIZE-1 (P0-0b).

    The old ``re.sub(r'[^\n]*\r', '', text)`` deleted everything up to and
    including *each* ``\\r``, so a meaningful line terminated by a lone ``\\r``
    (a result printed without a trailing newline, a status line, an ffuf
    ``[Status: 200]`` hit) vanished entirely — the engine then read a
    successful tool as empty and looped repair/evasion on a tool that worked.

    Faithful rule: within each physical line (split on ``\\n``), a ``\\r``
    returns the cursor to column 0 and the following text overwrites; the
    visible line is the **last non-empty** carriage-return segment. A trailing
    ``\\r`` (empty tail segment) therefore keeps the text BEFORE it, never the
    empty tail — so real result lines survive while progress redraws still
    collapse to their final frame.
    """
    out_lines = []
    for line in text.split("\n"):
        if "\r" not in line:
            out_lines.append(line)
            continue
        visible = ""
        for seg in line.split("\r"):
            if seg != "":
                visible = seg
        out_lines.append(visible)
    return "\n".join(out_lines)


def clean_text(text: str) -> str:
    """Universal cleaner for tool outputs and inputs. (v5.0 Universal Fix)"""
    if not text:
        return ""
    # Normalize Windows CRLF to prevent \r matching from destroying valid lines
    text = text.replace("\r\n", "\n")
    # SANITIZE-1: CR-safe collapse of terminal carriage-return redraws.
    # Replaces the old `re.sub(r'[^\n]*\r', '', text)` that silently deleted
    # real result lines terminated by a lone \r.
    text = _collapse_carriage_returns(text)
    text = remove_ansi(text)
    text = remove_artifacts(text)
    return text.strip()


def clean_target(target: str) -> str:
    """Aggressive cleaner specifically for subdomain/IP strings."""
    if not target:
        return ""
    target = clean_text(target)
    # Remove any character that isn't valid in a URL, domain, or IP.
    # We now allow _, ?, &, =, #, %, ~ for full URLs
    target = re.sub(r'[^a-zA-Z0-9\.\-\:\/\_\?\&\=\#\%\~]', '', target)
    return target


def extract_json_list(text: str) -> list:
    """Extract a JSON list from a string, handling markdown formatting (DEPRECATED: uses core.robust_parser)."""
    return robust_extract_json_list(text)
