import os
import json
import glob

brain_dir = r"C:\Users\ASUS\.gemini\antigravity\brain"
transcripts = glob.glob(
    os.path.join(
        brain_dir,
        "*",
        ".system_generated",
        "logs",
        "transcript.jsonl"))

print(
    f"Searching {
        len(transcripts)} conversations for any display.py writes...")

found = []

for t_path in transcripts:
    try:
        with open(t_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f):
                if "display.py" in line:
                    if "write_to_file" in line or "replace_file_content" in line or "multi_replace_file_content" in line:
                        data = json.loads(line)
                        tc_list = data.get("tool_calls", [])
                        for tc in tc_list:
                            args = tc.get("args") or tc.get("Arguments") or {}
                            if isinstance(args, str):
                                args = json.loads(args)
                            content = args.get("CodeContent") or args.get(
                                "ReplacementContent")
                            if content and len(content) > 5000:
                                print(
                                    f"Found version in {
                                        os.path.basename(
                                            os.path.dirname(
                                                os.path.dirname(t_path)))} at line {line_idx} (len={
                                        len(content)})")
                                found.append((t_path, line_idx, content))
    except Exception as _e:
        import logging
        logging.getLogger(__name__).warning(f"Swallowed exception: {_e}")

if found:
    found.sort(key=lambda x: len(x[2]), reverse=True)
    best = found[0]
    out_path = "scratch/historical_recovered.py"
    with open(out_path, "w", encoding="utf-8") as out:
        out.write(best[2])
    print(
        f"Successfully recovered full display.py from {
            best[0]} and wrote to {out_path}")
else:
    print("No large historical versions of display.py found.")
