import re
import os


def clean_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def analyze_log_to_file():
    log_path = r"C:\Users\ASUS\Desktop\red team\last ran cli out.txt"
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        return

    with open(log_path, 'rb') as f:
        content_bytes = f.read()

    raw_lines = content_bytes.split(b'\r')

    cleaned_lines = []
    for line_bytes in raw_lines:
        try:
            line = line_bytes.decode('utf-8', errors='ignore')
        except Exception:
            line = line_bytes.decode('latin1', errors='ignore')
        cleaned_lines.append(clean_ansi(line))

    # Categorize lines
    exceptions = []
    failures = []
    errors = []
    warnings = []
    failed_steps = []
    other_noteworthy = []

    for idx, line in enumerate(cleaned_lines):
        line_num = idx + 1
        lower_line = line.lower()
        cleaned_line_str = line.strip()
        if not cleaned_line_str:
            continue

        is_matched = False

        # Check for exceptions/tracebacks
        if "traceback" in lower_line or "exception" in lower_line or "traceback" in lower_line:
            exceptions.append((line_num, cleaned_line_str))
            is_matched = True

        # Check for failures
        if "[ sys.fail ]" in lower_line or "failure" in lower_line or "failed" in lower_line or "✘  failure" in lower_line:
            failures.append((line_num, cleaned_line_str))
            is_matched = True

        # Check for errors
        if "[error]" in lower_line or "error:" in lower_line or "err" in lower_line:
            errors.append((line_num, cleaned_line_str))
            is_matched = True

        # Check for warnings
        if "[ sys.warn ]" in lower_line or "warning" in lower_line or "warn" in lower_line:
            warnings.append((line_num, cleaned_line_str))
            is_matched = True

        # Check for step status failures
        if "[ sts ] failed" in lower_line or "[ sts ] waf_blocked" in lower_line:
            failed_steps.append((line_num, cleaned_line_str))
            is_matched = True

        # Check for other noteworthy items like rate limits, timeouts, tool
        # overrides, skipped steps
        if "timeout" in lower_line or "rate limit" in lower_line or "cooldown" in lower_line or "skipping" in lower_line or "override" in lower_line or "exhausted" in lower_line:
            if not is_matched:
                other_noteworthy.append((line_num, cleaned_line_str))

    # Write report
    report_path = r"C:\Users\ASUS\Desktop\red team\scratch\log_analysis_findings.txt"
    with open(report_path, 'w', encoding='utf-8') as rf:
        rf.write(
            "========================================================================\n")
        rf.write("GHOSTWIRE V7 CLI LOG ANALYSIS FINDINGS REPORT\n")
        rf.write(f"Source File: {log_path}\n")
        rf.write(f"Total Log Lines parsed: {len(cleaned_lines)}\n")
        rf.write(
            "========================================================================\n\n")

        rf.write(f"SUMMARY OF DETECTED ISSUES:\n")
        rf.write(f"- Exceptions / Tracebacks: {len(exceptions)}\n")
        rf.write(f"- Failures (sys.fail or failure lines): {len(failures)}\n")
        rf.write(f"- Errors: {len(errors)}\n")
        rf.write(f"- Warnings: {len(warnings)}\n")
        rf.write(f"- Failed Steps / Commands: {len(failed_steps)}\n")
        rf.write(
            f"- Other Noteworthy Events (timeouts, rate-limits, overrides): {
                len(other_noteworthy)}\n\n")

        rf.write(
            "========================================================================\n")
        rf.write("1. EXCEPTIONS & TRACEBACKS\n")
        rf.write(
            "========================================================================\n")
        if exceptions:
            for ln, line in exceptions:
                rf.write(f"Line {ln:04d}: {line}\n")
        else:
            rf.write(
                "No Python Tracebacks or raw Exception blocks found in the log.\n")
        rf.write("\n")

        rf.write(
            "========================================================================\n")
        rf.write("2. FAILURES ([ SYS.FAIL ] or explicit Failure events)\n")
        rf.write(
            "========================================================================\n")
        if failures:
            for ln, line in failures:
                rf.write(f"Line {ln:04d}: {line}\n")
        else:
            rf.write("No explicit failure lines found.\n")
        rf.write("\n")

        rf.write(
            "========================================================================\n")
        rf.write("3. FAILED STEPS & COMMANDS ([ STS ] FAILED / WAF_BLOCKED)\n")
        rf.write(
            "========================================================================\n")
        if failed_steps:
            for ln, line in failed_steps:
                rf.write(f"Line {ln:04d}: {line}\n")
        else:
            rf.write("No failed steps/commands found.\n")
        rf.write("\n")

        rf.write(
            "========================================================================\n")
        rf.write("4. ERRORS & DETAILED CLI ERROR MESSAGES\n")
        rf.write(
            "========================================================================\n")
        if errors:
            for ln, line in errors:
                rf.write(f"Line {ln:04d}: {line}\n")
        else:
            rf.write("No detailed error messages found.\n")
        rf.write("\n")

        rf.write(
            "========================================================================\n")
        rf.write("5. SYSTEM WARNINGS ([ SYS.WARN ] or general warnings)\n")
        rf.write(
            "========================================================================\n")
        if warnings:
            for ln, line in warnings:
                rf.write(f"Line {ln:04d}: {line}\n")
        else:
            rf.write("No warnings found.\n")
        rf.write("\n")

        rf.write(
            "========================================================================\n")
        rf.write(
            "6. OTHER NOTEWORTHY EVENTS (timeouts, rate-limits, overrides, etc.)\n")
        rf.write(
            "========================================================================\n")
        if other_noteworthy:
            for ln, line in other_noteworthy:
                rf.write(f"Line {ln:04d}: {line}\n")
        else:
            rf.write("No other noteworthy events found.\n")

    print(f"Detailed analysis successfully written to {report_path}")


if __name__ == "__main__":
    analyze_log_to_file()
