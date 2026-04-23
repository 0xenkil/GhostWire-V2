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
    # Remove dangling ANSI erase line codes that lost their ESC byte across chunk boundaries
    text = re.sub(r'^\[2K\r?', '', text)
    text = text.replace("[2K", "")
    return text

def normalize_whitespace(text: str) -> str:
    """Normalize multi-space blocks and newlines for consistent parsing."""
    return " ".join(text.split())

def clean_text(text: str) -> str:
    """Universal cleaner for tool outputs and inputs. (v5.0 Universal Fix)"""
    if not text:
        return ""
    text = remove_ansi(text)
    text = remove_artifacts(text)
    return text.strip()

def clean_target(target: str) -> str:
    """Aggressive cleaner specifically for subdomain/IP strings."""
    if not target:
        return ""
    target = clean_text(target)
    # Remove any character that isn't a domain/IP character
    # Keep A-Za-z0-9, dots, hyphens, colons (ports/IPv6), and slashes (paths)
    target = re.sub(r'[^a-zA-Z0-9\.\-\:\/]', '', target)
    return target
