import subprocess
import re
import shlex
import difflib

# Get real help output from WSL
result = subprocess.run(
    ["wsl", "-e", "bash", "-c", "ffuf -h"],
    capture_output=True, text=True, timeout=10
)
help_out = result.stdout + result.stderr

valid_flags = set(
    re.findall(
        r'(?:(?<=\s)|(?<=,)|^)(-{1,2}[a-zA-Z0-9][a-zA-Z0-9\-]*)',
        help_out,
        re.MULTILINE)
)

command = "ffuf -H 'User-Agent: Mozilla/5.0' -u https://resellerapi.novalink.lk/FUZZ -w /home/en/redteam-workspace/ai_wordlist.txt -fs 33822 -p 0.5-1.5 -k -ac -t 5"

parts = shlex.split(command)
fixed_parts = []
skip_next = False
for i, part in enumerate(parts):
    if skip_next:
        skip_next = False
        continue
    if part.startswith('-') and len(part) > 1 and not part.startswith('http'):
        base_flag = part.split('=')[0]
        if base_flag not in valid_flags:
            matches = difflib.get_close_matches(
                base_flag, valid_flags, n=1, cutoff=0.7)
            if matches:
                new_flag = matches[0]
                if '=' in part:
                    new_flag += "=" + part.split('=', 1)[1]
                print(f"Dynamic Flag Corrector: {base_flag} -> {matches[0]}")
                fixed_parts.append(new_flag)
            else:
                print(
                    f"Dynamic Flag Corrector: Removing invalid flag {base_flag}")
                if i + 1 < len(parts):
                    nxt = parts[i + 1]
                    is_url_or_path = nxt.startswith(
                        'http') or nxt.startswith('/')
                    if not nxt.startswith('-') and not is_url_or_path:
                        skip_next = True
                    else:
                        fixed_parts.append(part)
                else:
                    fixed_parts.append(part)
        else:
            fixed_parts.append(part)
    else:
        fixed_parts.append(part)

corrected_cmd = shlex.join(fixed_parts)
print(f"Original command:  {command}")
print(f"Corrected command: {corrected_cmd}")
