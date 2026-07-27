import json
import re
import logging

log = logging.getLogger("robust_parser")


def _repair_unescaped_quotes(blob: str) -> str:
    """Attempt to fix unescaped double quotes inside JSON string values.

    AI-generated JSON frequently contains shell commands with inner quotes
    like: {"command": "curl -H "Host: x" url"}. This tries to escape
    those inner quotes so json.loads succeeds.

    Strategy: find string-value regions (between key-colon-quote and the
    next structural character) and escape unbalanced quotes within them.
    """
    # Fast path: if it parses already, don't touch it
    try:
        json.loads(blob, strict=False)
        return blob
    except Exception:
        pass

    result = []
    i = 0
    n = len(blob)
    while i < n:
        ch = blob[i]
        if ch == '"':
            # Check if this starts a key or value string
            # Find the matching close quote, handling escapes
            result.append(ch)
            i += 1
            # Collect string contents
            str_chars = []
            while i < n:
                sc = blob[i]
                if sc == '\\' and i + 1 < n:
                    str_chars.append(sc)
                    str_chars.append(blob[i + 1])
                    i += 2
                    continue
                if sc == '"':
                    # Is this the real end of the string?
                    # Peek ahead: if the next non-whitespace char is structural
                    # (, : } ] or another key start "), it's the real end.
                    rest = blob[i + 1:].lstrip()
                    if not rest or rest[0] in (',', ':', '}', ']', '"'):
                        break
                    else:
                        # This is an unescaped inner quote — escape it
                        str_chars.append('\\')
                        str_chars.append('"')
                        i += 1
                        continue
                str_chars.append(sc)
                i += 1
            result.append(''.join(str_chars))
            if i < n:
                result.append('"')  # closing quote
                i += 1
        else:
            result.append(ch)
            i += 1

    repaired = ''.join(result)
    return repaired


def _find_object_boundaries(text: str) -> list[tuple[int, int]]:
    """Find all top-level {...} object boundaries using stack-based parsing.

    Returns a list of (start, end) index tuples for each balanced object.
    Handles nested braces and strings correctly.
    """
    boundaries = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == '{':
            # Found a potential object start
            start = i
            brace_count = 0
            in_string = False
            escape = False
            j = i
            while j < n:
                char = text[j]
                if in_string:
                    if escape:
                        escape = False
                    elif char == '\\':
                        escape = True
                    elif char == '"':
                        in_string = False
                else:
                    if char == '"':
                        in_string = True
                    elif char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            boundaries.append((start, j + 1))
                            i = j + 1
                            break
                j += 1
            else:
                # Unbalanced — skip this opening brace
                i += 1
        else:
            i += 1
    return boundaries


def _extract_objects_individually(text: str) -> list:
    """Extract JSON objects one at a time from text, recovering valid items
    even when some are malformed.

    This is the key fallback that prevents one bad command from killing the
    entire batch. Each {...} blob is parsed independently, with auto-repair
    for unescaped quotes attempted on failures.
    """
    boundaries = _find_object_boundaries(text)
    if not boundaries:
        return []

    results = []
    for start, end in boundaries:
        blob = text[start:end]
        # Attempt 1: direct parse
        try:
            obj = json.loads(blob, strict=False)
            if isinstance(obj, dict):
                results.append(obj)
                continue
        except Exception:
            pass

        # Attempt 2: repair unescaped quotes then parse
        try:
            repaired = _repair_unescaped_quotes(blob)
            obj = json.loads(repaired, strict=False)
            if isinstance(obj, dict):
                results.append(obj)
                continue
        except Exception:
            pass

        # This object is unrecoverable — skip it but don't kill the batch
        log.debug(f"[PARSER] Skipping unrecoverable JSON object: {blob[:120]}...")

    return results


def _find_balanced_array(text: str) -> str | None:
    """Find the first balanced [...] array in text using stack-based parsing.

    Unlike the non-greedy regex `\\[.*?\\]`, this correctly handles `]`
    inside strings (e.g., regex payloads like `[a-z]`).
    """
    start_idx = text.find('[')
    if start_idx == -1:
        return None

    brace_count = 0
    in_string = False
    escape = False
    for i in range(start_idx, len(text)):
        char = text[i]
        if in_string:
            if escape:
                escape = False
            elif char == '\\':
                escape = True
            elif char == '"':
                in_string = False
        else:
            if char == '"':
                in_string = True
            elif char == '[':
                brace_count += 1
            elif char == ']':
                brace_count -= 1
                if brace_count == 0:
                    return text[start_idx:i + 1]
    return None


def extract_json_list(text):
    if not text:
        return []

    # 1. Try markdown block — use balanced extraction, not non-greedy regex
    md_match = re.search(r"```(?:json)?\s*(\[)", text, re.DOTALL)
    if md_match:
        # Extract from the opening bracket to find the balanced array
        array_text = _find_balanced_array(text[md_match.start(1):])
        if array_text:
            try:
                parsed = json.loads(array_text, strict=False)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                pass

    # 2. Try naive load (strip markdown fences)
    text_clean = re.sub(r"^```(?:json)?", "", text.strip())
    text_clean = re.sub(r"```$", "", text_clean.strip())
    try:
        parsed = json.loads(text_clean, strict=False)
        if isinstance(parsed, list):
            return parsed
        elif isinstance(parsed, dict):
            return [parsed]
    except Exception:
        pass

    # 3. Stack-based bracket parser for the whole array
    array_str = _find_balanced_array(text)
    if array_str:
        try:
            parsed = json.loads(array_str, strict=False)
            if isinstance(parsed, list):
                return parsed
            elif isinstance(parsed, dict):
                return [parsed]
        except Exception:
            pass

        # 3b. Array-level parse failed — try repairing the whole array
        try:
            repaired = _repair_unescaped_quotes(array_str)
            parsed = json.loads(repaired, strict=False)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass

    # 4. KEY FALLBACK: Per-item recovery — parse each {...} independently
    # This prevents one malformed command from dropping the entire batch.
    items = _extract_objects_individually(text)
    if items:
        return items

    # 5. Last resort: single object extraction
    obj = extract_json_object(text)
    if obj:
        return [obj]

    return []

def safe_split_json_extraction(text):
    return extract_json_list(text)

def extract_json_object(text):
    if not text:
        return {}

    # 1. Try markdown block first
    md_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if md_match:
        try:
            parsed = json.loads(md_match.group(1), strict=False)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    # 2. Try naive load
    text_clean = re.sub(r"^```(?:json)?", "", text.strip())
    text_clean = re.sub(r"```$", "", text_clean.strip())
    try:
        parsed = json.loads(text_clean, strict=False)
        if isinstance(parsed, dict):
            return parsed
        elif isinstance(parsed, list) and len(parsed) > 0 and isinstance(parsed[0], dict):
            return parsed[0]
    except Exception:
        pass

    # 3. Stack-based brace parser to ignore trailing/leading garbage
    start_idx = text.find('{')
    if start_idx != -1:
        brace_count = 0
        in_string = False
        escape = False
        for i in range(start_idx, len(text)):
            char = text[i]
            if in_string:
                if escape:
                    escape = False
                elif char == '\\':
                    escape = True
                elif char == '"':
                    in_string = False
            else:
                if char == '"':
                    in_string = True
                elif char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        blob = text[start_idx:i+1]
                        try:
                            parsed = json.loads(blob, strict=False)
                            if isinstance(parsed, dict):
                                return parsed
                        except Exception:
                            pass
                        # Try repair
                        try:
                            repaired = _repair_unescaped_quotes(blob)
                            parsed = json.loads(repaired, strict=False)
                            if isinstance(parsed, dict):
                                return parsed
                        except Exception:
                            pass
                        break

    return {}

def extract_json(text):
    return extract_json_object(text)
