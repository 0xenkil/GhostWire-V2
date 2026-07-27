import shlex

# Simulate is_likely_file_path


def is_likely_file_path(part: str) -> bool:
    if not part:
        return False
    # Ignore options/flags and URLs
    if part.startswith(
            "-") or part.startswith("http://") or part.startswith("https://"):
        return False
    # Ignore strings containing characters that indicate query params,
    # templates, or options
    if any(c in part for c in ["?", "&", "=", "^", ":", "{", "}", "FUZZ"]):
        return False

    # If it starts with / but has only 1 slash and no extension, it's likely a
    # URL route
    if part.startswith("/") and part.count("/") == 1:
        if not any(part.endswith(ext) for ext in [
                   ".txt", ".lst", ".wordlist", ".git", ".db", ".conf", ".json", ".py", ".sh"]):
            return False

    # Check if it starts with / or ~
    if part.startswith("/") or part.startswith("~"):
        # Only check paths starting with common linux system dirs, user homes,
        # or having typical extensions
        common_dirs = [
            "/usr",
            "/opt",
            "/tmp",
            "/root",
            "/var",
            "/etc",
            "/home",
            "/bin",
            "/sbin",
            "/lib",
            "/mnt",
            "/dev",
            "~/"]
        if not any(part.startswith(d) for d in common_dirs):
            if not any(part.endswith(ext) for ext in [
                       ".txt", ".lst", ".wordlist", ".git", ".db", ".conf", ".json", ".py", ".sh"]):
                return False
        return True

    # If it doesn't start with / or ~ but has a file extension
    if any(part.endswith(ext) for ext in [
           ".txt", ".lst", ".wordlist", ".git", ".db", ".conf", ".json", ".py", ".sh"]):
        return True

    return False


command = "hydra -l admin -P /tmp/antigravity/ai_wordlist.txt hrapi.novalink.lk http-get /login"
parts = shlex.split(command)
for part in parts:
    print(
        f"part: {part:<40} -> is_likely_file_path: {is_likely_file_path(part)}")
