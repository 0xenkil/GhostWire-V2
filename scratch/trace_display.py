import json

log_path = r"C:\Users\ASUS\.gemini\antigravity\brain\9192f495-4fd4-4963-a820-51a956d44cda\.system_generated\logs\transcript.jsonl"

with open(log_path, "r", encoding="utf-8") as f:
    for idx, line in enumerate(f):
        if "display.py" in line:
            try:
                data = json.loads(line)
                # Print the step index, the tool name, and if it's MODEL or
                # SYSTEM
                source = data.get("source")
                ttype = data.get("type")
                tc = data.get("tool_calls", [])
                tc_str = ""
                if tc:
                    tc_str = " -> ".join([t.get("name")
                                         or t.get("ToolName") or "" for t in tc])
                print(
                    f"Line {idx}: Step={
                        data.get('step_index')}, Source={source}, Type={ttype}, Tools={tc_str}")
            except BaseException:
                pass
