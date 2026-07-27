import os
import re
import sys

# Directories to ignore
IGNORE_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "results",
    "scratch",
    "state",
    "config"}
# Files to ignore
IGNORE_FILES = {
    "audit_hardcoded.py",
    "config.py",
    "config_paths.py",
    "config_thresholds.py",
    "config_backends.py",
    "config_loader.py"}

# Patterns to look for
PATTERNS = [
    # URLs
    (r'https?://[^\s\'"]+', "Hardcoded URL"),
    # Absolute paths (Linux/Unix style)
    (r'/(?:usr|bin|etc|var|opt|tmp|home)/[^\s\'"]+',
     "Hardcoded absolute path"),
    # Timeouts in function calls
    (r'timeout\s*=\s*\d+', "Hardcoded timeout value"),
    # Sleep calls
    (r'time\.sleep\(\s*\d+(?:\.\d+)?\s*\)', "Hardcoded sleep duration"),
    # Thresholds/Retries (likely candidates)
    (r'max_retries\s*=\s*\d+', "Hardcoded retry count"),
]


def audit_file(file_path):
    issues = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                # Skip comments
                if line.strip().startswith("#"):
                    continue

                for pattern, desc in PATTERNS:
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        # Filter out some false positives
                        text = match.group(0)
                        if "get_config" in line or "os.getenv" in line:
                            continue

                        issues.append({
                            "line": i,
                            "text": text,
                            "description": desc
                        })
    except Exception as e:
        print(f"Error reading {file_path}: {e}")

    return issues


def main():
    print("Starting Ghostwire V6 Hardcoding Audit...")
    print("=" * 60)

    total_issues = 0
    files_audited = 0

    for root, dirs, files in os.walk("."):
        # Prune ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for file in files:
            if not file.endswith(".py") or file in IGNORE_FILES:
                continue

            file_path = os.path.join(root, file)
            issues = audit_file(file_path)

            if issues:
                print(f"\nFile: {file_path}")
                for issue in issues:
                    print(
                        f"  [Line {
                            issue['line']}] {
                            issue['description']}: {
                            issue['text']}")
                total_issues += len(issues)

            files_audited += 1

    print("\n" + "=" * 60)
    print("Audit Complete!")
    print(f"Files audited: {files_audited}")
    print(f"Potential hardcoded values found: {total_issues}")

    if total_issues > 0:
        print("\nRecommendation: Replace these values with get_config() calls in the respective config files.")
        sys.exit(1)
    else:
        print("\nNo obvious hardcoded values found in the logic files!")
        sys.exit(0)


if __name__ == "__main__":
    main()
