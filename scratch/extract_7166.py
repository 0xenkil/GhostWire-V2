import json

log_path = r"C:\Users\ASUS\.gemini\antigravity\brain\9192f495-4fd4-4963-a820-51a956d44cda\.system_generated\logs\transcript.jsonl"


def try_extract(line_idx):
    with open(log_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if idx == line_idx:
                data = json.loads(line)
                # Look at tool_calls
                for tc in data.get("tool_calls", []):
                    args = tc.get("Arguments", {})
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except BaseException:
                            pass
                    if isinstance(args, dict):
                        content = args.get(
                            "ReplacementContent") or args.get("CodeContent")
                        if content:
                            return content
                # Look at content
                content = data.get("content")
                if content:
                    return content
    return None


# Try extracting from line 7166
content = try_extract(7166)
if content:
    with open("scratch/recovered_7166.txt", "w", encoding="utf-8") as out:
        out.write(content)
    print("Wrote content to scratch/recovered_7166.txt")
else:
    print("Failed to extract from 7166")
