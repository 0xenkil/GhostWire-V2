import os
import re


def audit_codebase():
    base_dir = r"C:\Users\ASUS\Desktop\red team"
    exclude_dirs = {
        ".venv",
        ".tox",
        "scratch",
        "tests",
        "results",
        "__pycache__"}

    py_files = []
    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))

    py_files.sort(key=lambda x: os.path.basename(x).lower())

    suspicious = []

    for fpath in py_files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()

                # Check for base64 / obfuscation
                if re.search(r"base64\.b64decode",
                             content) and "obfuscator" not in fpath:
                    suspicious.append((fpath, "base64 decode"))

                # Check for exec/eval
                if re.search(
                        r"\b(exec|eval)\s*\(", content) and "obfuscator" not in fpath and "fingerprint" not in fpath:
                    suspicious.append((fpath, "exec/eval"))

                # Check for __import__
                if re.search(r"__import__\s*\(", content):
                    suspicious.append((fpath, "__import__ used"))

                # Check for subprocess.run without timeout
                if "subprocess.run(" in content and "timeout=" not in content:
                    suspicious.append(
                        (fpath, "subprocess.run without timeout"))

                # Check for very long lines
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if len(
                            line.strip()) > 300 and "import" not in line and "TODO" not in line:
                        if not re.search(
                                r'"""(.*?)"""', line) and not re.search(r"'''(.*?)'''", line):
                            # Exclude long strings if possible, or just flag it
                            suspicious.append(
                                (fpath,
                                 f"long line {
                                     i +
                                     1}: {
                                     len(line)} chars"))

                # Check for hidden IPs / URLs (not localhost)
                ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", content)
                for ip in ips:
                    if ip not in ["127.0.0.1", "0.0.0.0", "1.1.1.1",
                                  "8.8.8.8", "8.8.4.4", "169.254.169.254"]:
                        suspicious.append((fpath, f"Hardcoded IP: {ip}"))

                # Check for requests without timeout
                if re.search(r"requests\.(get|post|put|delete|patch|head|options)\s*\(",
                             content) and "timeout=" not in content:
                    suspicious.append((fpath, "requests without timeout"))

        except Exception as e:
            print(f"Error reading {fpath}: {e}")

    if suspicious:
        print("FOUND SUSPICIOUS ARTIFACTS:")
        for path, reason in suspicious:
            print(f"- {os.path.basename(path)}: {reason}")
    else:
        print("No suspicious artifacts found.")


if __name__ == "__main__":
    audit_codebase()
