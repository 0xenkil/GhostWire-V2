import json

log_path = r"C:\Users\ASUS\.gemini\antigravity\brain\9192f495-4fd4-4963-a820-51a956d44cda\.system_generated\logs\transcript.jsonl"


def inspect_line(lidx):
    with open(log_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if idx == lidx:
                data = json.loads(line)
                print(
                    f"Line {lidx}: Type={
                        data.get('type')}, Source={
                        data.get('source')}, Status={
                        data.get('status')}")
                # Print keys
                print("Keys:", list(data.keys()))
                # If there is content, print a snippet
                content = data.get("content")
                if content:
                    print("Content snippet:", content[:200])
                # If there are tool_calls, print tool details
                tc = data.get("tool_calls", [])
                if tc:
                    print("Tool Calls count:", len(tc))
                    for i, t in enumerate(tc):
                        print(
                            f"  Tool {i}: name={
                                t.get('name') or t.get('ToolName')}")
                        args = t.get("args") or t.get("Arguments")
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except BaseException:
                                pass
                        if isinstance(args, dict):
                            print("  Args keys:", list(args.keys()))
                            # Print a snippet of replacement content if present
                            repl = args.get("ReplacementContent")
                            if repl:
                                print("  ReplacementContent snippet:",
                                      repl[:200])


inspect_line(7166)
inspect_line(7192)
