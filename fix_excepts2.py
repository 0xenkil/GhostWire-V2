from pathlib import Path

target_files = [
    Path(r"C:\Users\ASUS\Desktop\red team\agents\reporting_agent.py"),
    Path(r"C:\Users\ASUS\Desktop\red team\core\robust_parser.py"),
    Path(r"C:\Users\ASUS\Desktop\red team\utils\poc_templates.py")
]

for py_file in target_files:
    try:
        if py_file.exists():
            content = py_file.read_text(encoding="utf-8")
            if "except:" in content:
                new_content = content.replace(
                    "except:", "except Exception as e:")
                py_file.write_text(new_content, encoding="utf-8")
                print(f"Fixed {py_file.name}")
    except Exception as e:
        print(f"Failed {py_file.name}: {e}")
