from pathlib import Path

target_dir = Path(r"C:\Users\ASUS\Desktop\red team\intelligence")

for py_file in target_dir.rglob("*.py"):
    try:
        content = py_file.read_text(encoding="utf-8")
        if "except:" in content:
            new_content = content.replace("except:", "except Exception as e:")
            py_file.write_text(new_content, encoding="utf-8")
            print(f"Fixed {py_file.name}")
    except Exception as e:
        print(f"Failed {py_file.name}: {e}")
