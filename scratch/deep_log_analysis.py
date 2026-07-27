import re
from collections import Counter


def analyze_log(filepath):
    print("Starting deep A-Z analysis of:", filepath)

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    print(f"Total log size: {len(content)} characters")

    # 1. Identify all executed commands [ CMD ]
    cmd_blocks = []
    # Let's find matches of [ CMD ] command_string
    # and extract the following [ STS ] if present
    matches = re.finditer(r'\[ CMD \]\s*(.*?)\n', content)
    for m in matches:
        cmd = m.group(1).strip()
        # Find next occurrence of [ STS ]
        start_idx = m.end()
        sts_match = re.search(r'\[ STS \]\s*(.*?)\n',
                              content[start_idx:start_idx + 1000])
        sts = sts_match.group(1).strip() if sts_match else "UNKNOWN"
        cmd_blocks.append((cmd, sts))

    print(f"Total commands executed: {len(cmd_blocks)}")

    # 2. Check for Command Repetitions (Loops)
    print("\n--- CHECKING FOR COMMAND REPETITIONS (LOOPS) ---")
    cmd_counts = Counter([b[0] for b in cmd_blocks])
    loops = {cmd: count for cmd, count in cmd_counts.items() if count > 1}
    sorted_loops = sorted(loops.items(), key=lambda x: x[1], reverse=True)
    print(f"Number of duplicate commands executed: {len(sorted_loops)}")
    for cmd, count in sorted_loops[:15]:
        safe_cmd = cmd.encode('ascii', errors='replace').decode('ascii')
        print(f"  - Count: {count} | Command: {safe_cmd}")

    # 3. Analyze Tool-Specific Failures
    print("\n--- ANALYZING TOOL SPECIFIC FAILURE PATTERNS ---")
    tool_status = {}
    for cmd, sts in cmd_blocks:
        tool = cmd.split()[0]
        if tool == "proxychains4" and len(cmd.split()) > 2:
            tool = cmd.split()[2]
        if tool.startswith("$("):
            tool = "bash_subshell"

        if tool not in tool_status:
            tool_status[tool] = Counter()
        tool_status[tool][sts] += 1

    for tool, counter in sorted(
            tool_status.items(), key=lambda x: sum(x[1].values()), reverse=True):
        sts_str = ", ".join([f"{k}: {v}" for k, v in counter.items()])
        raw_out = f"  - Tool: {tool:<15} | Statuses -> {sts_str}"
        safe_out = raw_out.encode('ascii', errors='replace').decode('ascii')
        print(safe_out)

    # 4. Search for common unhandled Python exceptions or tracebacks in the
    # entire log
    print("\n--- UNHANDLED PY EXTREMES / TRACEBACK SEARCH ---")
    tb_matches = re.findall(
        r'(Traceback \(most recent call last\):.*?\n\w+Error:.*?\n)',
        content,
        re.DOTALL)
    print(f"Found {len(tb_matches)} tracebacks:")
    for i, tb in enumerate(tb_matches):
        print(f"\nTraceback #{i + 1}:")
        print(tb)

    # 5. Check if the AI skipped repairs or got stuck in infinite loops
    print("\n--- AI REPAIR GATES & SKIPS ---")
    repair_skips = len(re.findall(r'\[AI REPAIR SKIPPED\]', content))
    unfixable_errors = len(re.findall(r'Unfixable network error', content))
    print(f"  - AI Repair Skips ([AI REPAIR SKIPPED]): {repair_skips}")
    print(f"  - Unfixable Network Errors reported: {unfixable_errors}")

    # 6. Deep analysis of loop phases (RECON/EXPLOITATION loops)
    print("\n--- PHASE ITERATION ANALYSIS ---")
    recon_loops = re.findall(r'RECON LOOP (\d+)', content)
    exploit_loops = re.findall(r'EXPLOITATION LOOP (\d+)', content)

    if recon_loops:
        print(
            f"  - Recon Loop reached up to index: {max(map(int, recon_loops))}")
    if exploit_loops:
        print(
            f"  - Exploitation Loop reached up to index: {max(map(int, exploit_loops))}")


analyze_log('last ran cli out.txt')
