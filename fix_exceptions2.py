import re
from pathlib import Path

for path in Path('.').rglob('*.py'):
    if 'venv' in str(path) or 'site-packages' in str(path) or '.agents' in str(
            path) or 'scratch' in str(path) or 'results' in str(path) or 'tests' in str(path):
        continue

    content = path.read_text(encoding='utf-8')
    original = content

    # 1. Replace "except Exception:" with "except Exception as e:"
    # But only if it's the exact line "except Exception:"
    # We will be careful.
    content = re.sub(
        r'(^[ \t]*)except Exception:\s*\n([ \t]+)pass\s*$',
        r'\1except Exception as e:\n\2import logging as __logging_tmp; __logging_tmp.getLogger(__name__).error(f"Swallowed exception: {e}", exc_info=True)',
        content,
        flags=re.MULTILINE)

    content = re.sub(
        r'(^[ \t]*)except Exception:\s*\n([ \t]+)log\.debug\((.*?)\)\s*$',
        r'\1except Exception as e:\n\2log.error(f"Critical failure: {e}", exc_info=True)',
        content,
        flags=re.MULTILINE)

    # Also just "except Exception:" without pass that might be followed by
    # continue or return, but log an error before
    def repl_empty_except(match):
        indent = match.group(1)
        next_line_indent = match.group(2)
        next_line_content = match.group(3)
        if "log.error" in next_line_content or "raise" in next_line_content:
            return match.group(0)  # leave it alone

        # Rewrite to add log.error
        return f"{indent}except Exception as e:\n{next_line_indent}import logging as __logging_tmp; __logging_tmp.getLogger(__name__).error(f\"Unhandled exception: {{e}}\")\n{next_line_indent}{next_line_content}"

    # We match "except Exception:" \n "    statement"
    # But this is tricky. Let's rely on a simpler approach. We just globally
    # replace all except Exception: with except Exception as e: and if the
    # next line doesn't have an error log, we add it.

    lines = content.split('\n')
    new_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        match = re.match(r'^([ \t]*)except Exception:$', line)
        if match:
            indent = match.group(1)
            new_lines.append(f"{indent}except Exception as e:")
            # Check next line
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                next_match = re.match(r'^([ \t]+)(.*)', next_line)
                if next_match:
                    next_indent = next_match.group(1)
                    stmt = next_match.group(2)
                    if not any(x in stmt for x in [
                               'log.error', 'log.warning', 'log.critical', 'raise', 'logging.getLogger']):
                        new_lines.append(
                            f"{next_indent}import logging as __logging_tmp; __logging_tmp.getLogger(__name__).error(f\"Unhandled exception: {{e}}\", exc_info=True)")
        else:
            new_lines.append(line)
        i += 1

    content = '\n'.join(new_lines)

    if content != original:
        path.write_text(content, encoding='utf-8')
        print(f"Fixed exceptions in {path}")
