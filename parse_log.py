
def parse_wsl_log(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    # The blocks look like:
    # [ CMD ] the command
    # [ STS ] STATUS (time)
    # ───...
    # (Output lines)
    # ╰───...

    blocks = []

    # We can split by "[ CMD ] "
    parts = content.split('[ CMD ] ')
    for part in parts[1:]:
        lines = part.split('\n')
        cmd = lines[0].strip()

        sts = ""
        output = []
        in_output = False

        for line in lines[1:]:
            line_stripped = line.strip('│ \t\r')
            if line_stripped.startswith('[ STS ]'):
                sts = line_stripped.split('[ STS ]')[1].strip()
            elif '──────────────────' in line_stripped and sts:
                in_output = True
            elif '╰────────' in line_stripped or '╭────────' in line_stripped:
                break
            elif in_output:
                if line_stripped and not line_stripped.startswith('[!] [!]'):
                    output.append(line_stripped)

        blocks.append({
            'cmd': cmd,
            'sts': sts,
            'output': output
        })

    return blocks


blocks = parse_wsl_log('last ran cli out.txt')

findings = {}
for b in blocks:
    cmd = b['cmd']
    sts = b['sts']
    out_text = ' '.join(b['output']).lower()

    reasons = []
    is_anomaly = False

    if 'FAILED' in sts or 'TIMEOUT' in sts:
        is_anomaly = True
        reasons.append(sts.split()[0])  # FAILED or TIMEOUT

    if 'SUCCESS' in sts and not out_text:
        is_anomaly = True
        reasons.append('Empty Output on SUCCESS')

    if 'SUCCESS' in sts and '(no results/output returned from tool)' in out_text:
        is_anomaly = True
        reasons.append('Reported NO OUTPUT on SUCCESS')

    # Error keywords
    error_patterns = {
        'flag provided but not defined': 'Bad Flag',
        'invalid header': 'Bad Header',
        'unknown command-line parameter': 'Unknown Parameter',
        'there is no service': 'Hydra Bad Service',
        'host does not exist': 'Host Not Found',
        'page not found': 'HTTP 404',
        'could not find template': 'Nuclei Missing Template',
        'no templates provided': 'Nuclei No Templates',
        'keyword fuzz defined, but not found': 'FFUF Missing FUZZ',
        'usage:': 'Tool Printed Usage (Likely Syntax Error)',
        'error:': 'Generic Error',
        'failed to': 'Failed To Execute',
        'unrecognized option': 'Unrecognized Option',
        'bad request': 'HTTP 400 Bad Request',
        'syntax error': 'Syntax Error',
        'no such file or directory': 'File Not Found',
        'connection refused': 'Connection Refused',
        'connection timed out': 'Connection Timed Out',
        'ssl/tls connection failed': 'SSL Failed'
    }

    for pat, desc in error_patterns.items():
        if pat in out_text:
            is_anomaly = True
            reasons.append(desc)

    if is_anomaly:
        tool = cmd.split()[0]
        if tool == 'proxychains4' and len(cmd.split()) > 2:
            tool = cmd.split()[2]

        # specific fix for bash variables
        if tool.startswith('$('):
            tool = 'bash_subshell'

        key = tool + ' | ' + ', '.join(set(reasons))
        if key not in findings:
            findings[key] = []
        findings[key].append((cmd, sts, b['output'][:2]))

with open('BUGS_COMPREHENSIVE_AUDIT.md', 'w', encoding='utf-8') as f:
    f.write('# Comprehensive Log Audit Findings\n\n')
    f.write(f'Total executed commands analyzed: {len(blocks)}\n\n')
    for key, examples in sorted(
            findings.items(), key=lambda x: len(x[1]), reverse=True):
        f.write(f'## {key} (Count: {len(examples)})\n')
        for ex in examples[:5]:  # print up to 5
            f.write(f'- **CMD**: `{ex[0]}`\n')
            f.write(f'  **STS**: `{ex[1]}`\n')
            f.write(f'  **OUT**: `{str(ex[2])}`\n')
        if len(examples) > 5:
            f.write(f'- ... and {len(examples) - 5} more occurrences\n')
        f.write('\n')
