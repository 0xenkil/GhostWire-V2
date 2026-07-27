import json

log_path = r"C:\Users\ASUS\.gemini\antigravity\brain\9192f495-4fd4-4963-a820-51a956d44cda\.system_generated\logs\transcript.jsonl"

found_replacements = []

with open(log_path, "r", encoding="utf-8") as f:
    for line_idx, line in enumerate(f):
        try:
            data = json.loads(line)
            tool_calls = data.get("tool_calls", [])
            for tc in tool_calls:
                # Find replace_file_content or multi_replace_file_content
                name = tc.get("ToolName") or tc.get("type") or ""
                if "replace_file_content" in name:
                    args = tc.get("Arguments", {})
                    if isinstance(args, str):
                        args = json.loads(args)
                    if isinstance(args, dict):
                        target = args.get("TargetFile") or ""
                        if "display.py" in target:
                            # It's an edit to display.py!
                            found_replacements.append((line_idx, args))
        except BaseException:
            pass

print(f"Found {len(found_replacements)} edits to display.py.")
for idx, (lidx, args) in enumerate(found_replacements):
    desc = args.get("Description") or args.get("Instruction") or "No desc"
    print(f"Edit {idx} at line {lidx}: {desc}")
    # Let's write the ReplacementContent to a scratch file
    with open(f"scratch/edit_{idx}.txt", "w", encoding="utf-8") as out:
        out.write(json.dumps(args, indent=2))
