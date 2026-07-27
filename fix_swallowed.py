import glob
import re


def fix_swallowed():
    # Regex to match except Exception as _e:
    # import logging; logging.getLogger(__name__).warning(f"Swallowed
    # exception: {_e}") (and variants) with any whitespace
    pattern = re.compile(
        r'except\s+Exception\s*(?:as\s+\w+)?\s*:\s*(?:#.*?\n\s*)?pass')

    for file_path in glob.glob(
            r"C:\Users\ASUS\Desktop\red team\**\*.py", recursive=True):
        if "venv" in file_path or ".agents" in file_path:
            continue
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            if "except Exception" in content and "pass" in content:
                new_content = re.sub(
                    pattern,
                    r'except Exception as _e:\n            import logging; logging.getLogger(__name__).warning(f"Swallowed exception: {_e}")',
                    content)

                # Also replace the inline versions like `except Exception as _e:`
                # `import logging; logging.getLogger(__name__).warning(f"Swallowed exception: {_e}")`
                new_content = re.sub(
                    r'except\s+Exception\s*:\s*pass',
                    r'except Exception as _e: import logging; logging.getLogger(__name__).warning(f"Swallowed exception: {_e}")',
                    new_content)

                if new_content != content:
                    print(f"Fixed swallowed exceptions in {file_path}")
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(new_content)
        except Exception as e:
            print(f"Skipping {file_path}: {e}")


if __name__ == "__main__":
    fix_swallowed()
