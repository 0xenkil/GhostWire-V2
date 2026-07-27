import json
import re

log_path = r"C:\Users\ASUS\.gemini\antigravity\brain\9192f495-4fd4-4963-a820-51a956d44cda\.system_generated\logs\transcript.jsonl"

with open(log_path, "r", encoding="utf-8") as f:
    for idx, line in enumerate(f):
        if idx == 7200:
            data = json.loads(line)
            content = data.get("content")
            print(
                f"Line 7200 Content Type: {
                    type(content)} Len={
                    len(content) if content else 0}")
            if content:
                # Remove any Rich markup or line numbers like "100: "
                # The format is "100: def info(msg: str):\n"
                lines = content.split("\n")
                cleaned_lines = []
                for l in lines:
                    match = re.match(r"^\s*\d+:\s?(.*)$", l)
                    if match:
                        cleaned_lines.append(match.group(1))
                    else:
                        cleaned_lines.append(l)

                full_code = "\n".join(cleaned_lines)
                with open("scratch/recovered_full_display.py", "w", encoding="utf-8") as out:
                    out.write(full_code)
                print("Wrote full code to scratch/recovered_full_display.py")
