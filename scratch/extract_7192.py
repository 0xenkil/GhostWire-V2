import json

log_path = r"C:\Users\ASUS\.gemini\antigravity\brain\9192f495-4fd4-4963-a820-51a956d44cda\.system_generated\logs\transcript.jsonl"

with open(log_path, "r", encoding="utf-8") as f:
    for idx, line in enumerate(f):
        if idx == 7192:
            data = json.loads(line)
            tc = data.get("tool_calls", [])[0]
            args = tc.get("args") or tc.get("Arguments") or {}
            if isinstance(args, str):
                args = json.loads(args)
            content = args.get("CodeContent")
            target = args.get("TargetFile")
            print(f"Target: {target}")
            if content:
                with open("scratch/recovered_7192.txt", "w", encoding="utf-8") as out:
                    out.write(content)
                print("Wrote content to scratch/recovered_7192.txt")
            else:
                print("No content found in 7192")
