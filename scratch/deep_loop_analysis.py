import re
import os
from collections import defaultdict


def clean_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def safe_print(text):
    # Ensure ASCII only for printing in Windows host to prevent CP1252 errors
    try:
        print(text.encode('ascii', errors='replace').decode('ascii'))
    except Exception:
        # Fallback to absolute bare minimum if encode/decode fails
        print("".join(c if ord(c) < 128 else '?' for c in text))


def deep_loop_analysis():
    log_path = r"C:\Users\ASUS\Desktop\red team\last ran cli out.txt"
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        return

    with open(log_path, 'rb') as f:
        content_bytes = f.read()

    # Standard splitting of bytes by newline
    raw_lines = content_bytes.split(b'\n')

    cleaned_lines = []
    for line_bytes in raw_lines:
        line_bytes = line_bytes.replace(b'\r', b'')
        try:
            line = line_bytes.decode('utf-8', errors='ignore')
        except Exception:
            line = line_bytes.decode('latin1', errors='ignore')
        cleaned_lines.append(clean_ansi(line))

    safe_print(f"Loaded {len(cleaned_lines)} lines from run log.")

    current_loop = "START"
    loop_commands = defaultdict(list)
    loop_failures = defaultdict(list)
    loop_warnings = defaultdict(list)

    all_cmds = []
    cmd_runs = defaultdict(int)

    active_cmd = None
    active_cmd_output = []
    active_cmd_status = None
    active_cmd_line = None

    for idx, line in enumerate(cleaned_lines):
        line_num = idx + 1
        line_stripped = line.strip()

        # Detect loop progression (supporting ASCII and unicode)
        # Using general word checks to avoid encoding mismatches
        if "RECON LOOP" in line:
            current_loop = "RECON LOOP " + \
                line.split("RECON LOOP")[1].split()[0]
        elif "EXPLOITATION LOOP" in line:
            current_loop = "EXPLOITATION LOOP " + \
                line.split("EXPLOITATION LOOP")[1].split()[0]
        elif "ATTACK LOOP" in line:
            current_loop = "ATTACK LOOP " + \
                line.split("ATTACK LOOP")[1].split()[0]
        elif "Phase Recon complete" in line or "Phase RCN complete" in line:
            current_loop = "PHASE RECON COMPLETE"
        elif "Phase Exploitation complete" in line or "Phase XPL complete" in line:
            current_loop = "PHASE EXPLOITATION COMPLETE"

        # Detect command execution
        cmd_match = re.search(r'\[ CMD \]\s+(.+)', line)
        if cmd_match:
            cmd_str = cmd_match.group(1).strip()
            # Clean trailing box characters if any
            cmd_str = re.sub(r'\s*│\s*$', '', cmd_str).strip()
            cmd_str = re.sub(r'\s*â”‚\s*$', '', cmd_str).strip()

            # Store previous active command before starting new one
            if active_cmd:
                all_cmds.append({
                    'cmd': active_cmd,
                    'status': active_cmd_status,
                    'output': list(active_cmd_output),
                    'loop': current_loop,
                    'line': active_cmd_line
                })

            active_cmd = cmd_str
            active_cmd_output = []
            active_cmd_status = "UNKNOWN"
            active_cmd_line = line_num
            cmd_runs[cmd_str] += 1
            loop_commands[current_loop].append((line_num, cmd_str))
            continue

        # Detect command status
        sts_match = re.search(r'\[ STS \]\s+([A-Z]+)', line)
        if sts_match and active_cmd:
            active_cmd_status = sts_match.group(1).strip()

        # Append to active command output
        if active_cmd:
            # If line is part of output block
            if line.startswith('│') or line.startswith(
                    'â”‚') or line.startswith('|'):
                clean_out = re.sub(r'^[│â”‚|]\s*', '', line)
                clean_out = re.sub(r'\s*[│â”‚|]\s*$', '', clean_out).strip()
                if clean_out and not clean_out.startswith('[!] [!]') and not clean_out.startswith(
                        '───') and not clean_out.startswith('╰───'):
                    active_cmd_output.append(clean_out)

        # Track warning and failure lines globally with context
        if "[ SYS.WARN ]" in line:
            loop_warnings[current_loop].append((line_num, line_stripped))
        if "[ SYS.FAIL ]" in line:
            loop_failures[current_loop].append((line_num, line_stripped))

    # Add final command
    if active_cmd:
        all_cmds.append({
            'cmd': active_cmd,
            'status': active_cmd_status,
            'output': list(active_cmd_output),
            'loop': current_loop,
            'line': active_cmd_line
        })

    safe_print(f"Parsed {len(all_cmds)} total command executions.")

    # 1. Analyse duplicate commands
    safe_print("\n=======================================================")
    safe_print("TOP DUPLICATED COMMANDS & THEIR OUTCOMES:")
    safe_print("=======================================================")
    sorted_duplicates = sorted(
        cmd_runs.items(),
        key=lambda x: x[1],
        reverse=True)
    for cmd, count in sorted_duplicates:
        if count > 1:
            safe_print(f"\nCommand (Executed {count} times):")
            safe_print(f"  `{cmd}`")
            # Find the outcomes and loops
            occurrences = [c for c in all_cmds if c['cmd'] == cmd]
            safe_print("  Runs & Outcomes:")
            for o in occurrences:
                out_snippet = " | ".join(o['output'][:2])[:120]
                safe_print(
                    f"    - Line {o['line']} in {o['loop']}: STS={o['status']} | Out: {out_snippet}")

    # 2. Analyse loop iterations and command repetitions within loops
    safe_print("\n=======================================================")
    safe_print("LOOP ITERATIONS & COMMAND REPETITIONS:")
    safe_print("=======================================================")
    for loop, cmds in sorted(loop_commands.items(), key=lambda x: x[0]):
        safe_print(f"\n{loop} (Total commands: {len(cmds)}):")
        # Check for duplicate commands in THIS loop
        this_loop_runs = defaultdict(int)
        for _, c in cmds:
            this_loop_runs[c] += 1
        for c, cnt in sorted(this_loop_runs.items(),
                             key=lambda x: x[1], reverse=True):
            if cnt > 1:
                safe_print(f"  [REPEATED IN LOOP] Executed {cnt} times: `{c}`")
            else:
                safe_print(f"  Executed 1 time: `{c}`")

        # Warnings and failures in this loop
        warns = loop_warnings.get(loop, [])
        if warns:
            safe_print("  System Warnings in this loop:")
            for ln, w in warns:
                safe_print(f"    - Line {ln}: {w}")
        fails = loop_failures.get(loop, [])
        if fails:
            safe_print("  System Failures in this loop:")
            for ln, f in fails:
                safe_print(f"    - Line {ln}: {f}")


if __name__ == "__main__":
    deep_loop_analysis()
