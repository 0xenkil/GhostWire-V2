import json
import re

log_path = r"C:\Users\ASUS\.gemini\antigravity\brain\9192f495-4fd4-4963-a820-51a956d44cda\.system_generated\logs\transcript.jsonl"

with open(log_path, "r", encoding="utf-8") as f:
    for idx, line in enumerate(f):
        if idx == 7474:
            data = json.loads(line)
            content = data.get("content")
            print(
                f"Line 7474 Content Type: {
                    type(content)} Len={
                    len(content) if content else 0}")
            if content:
                # Let's save the raw content first
                with open("scratch/raw_7474.txt", "w", encoding="utf-8") as out:
                    out.write(content)
                print("Wrote raw content to scratch/raw_7474.txt")

                # Try cleaning it
                lines = content.split("\n")
                cleaned_lines = []
                for l in lines:
                    match = re.match(r"^\s*\d+:\s?(.*)$", l)
                    if match:
                        cleaned_lines.append(match.group(1))
                    else:
                        cleaned_lines.append(l)

                full_code = "\n".join(cleaned_lines)
                with open("scratch/recovered_full_display_7474.py", "w", encoding="utf-8") as out:
                    out.write(full_code)
                print("Wrote cleaned code to scratch/recovered_full_display_7474.py")
        elif idx == 7473:
            data = json.loads(line)
            print(
                f"Line 7473 info: Type={
                    data.get('type')}, Keys={
                    list(
                        data.keys())}")
            # print tool calls
            for tc in data.get("tool_calls", []):
                print(
                    f"  Tool: {
                        tc.get('name') or tc.get('ToolName')}, Args={
                        tc.get('args') or tc.get('Arguments')}")
