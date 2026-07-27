import json

log_path = r"C:\Users\ASUS\.gemini\antigravity\brain\9192f495-4fd4-4963-a820-51a956d44cda\.system_generated\logs\transcript.jsonl"

with open(log_path, "r", encoding="utf-8") as f:
    for line_idx, line in enumerate(f):
        try:
            data = json.loads(line)
            # Search everywhere in the line for "utils/display.py" or "Tokyo
            # Night Blue"
            if "Tokyo Night Blue" in line:
                print(f"Found on line {line_idx}")
                # Save the whole line to a file for analysis
                with open(f"scratch/found_line_{line_idx}.json", "w", encoding="utf-8") as out:
                    out.write(line)
        except Exception as _e:
            import logging
            logging.getLogger(__name__).warning(f"Swallowed exception: {_e}")
