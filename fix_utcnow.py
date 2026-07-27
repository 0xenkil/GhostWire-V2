import glob
import re


def fix_utcnow():
    pattern = re.compile(r'\bdatetime\.utcnow\(\)')
    for file_path in glob.glob(
            r"C:\Users\ASUS\Desktop\red team\**\*.py", recursive=True):
        if "venv" in file_path or ".agents" in file_path:
            continue
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            if "datetime.utcnow" in content:
                print(f"Fixing utcnow in {file_path}")
                # Replace datetime.now(timezone.utc) with
                # datetime.now(timezone.utc)
                content = pattern.sub("datetime.now(timezone.utc)", content)
                # Ensure timezone is imported from datetime
                if "from datetime import datetime" in content and "timezone" not in content:
                    content = content.replace(
                        "from datetime import datetime",
                        "from datetime import datetime, timezone")
                elif "import datetime" in content and "from datetime import" not in content:
                    # just use datetime.datetime.now(datetime.timezone.utc)
                    content = content.replace(
                        "datetime.now(timezone.utc)",
                        "datetime.now(datetime.timezone.utc)")
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
        except Exception as e:
            print(f"Skipping {file_path}: {e}")


if __name__ == "__main__":
    fix_utcnow()
