
with open(r"C:\Users\ASUS\Desktop\red team\tools\tool_manager.py", "r", encoding="utf-8") as f:
    content = f.read()

# Fix syntax errors
content = content.replace(
    "USE_REMOTE_VPS = get_config().vps.use_remote_vps",
    "get_config().vps.use_remote_vps")

with open(r"C:\Users\ASUS\Desktop\red team\tools\tool_manager.py", "w", encoding="utf-8") as f:
    f.write(content)

print("tool_manager.py syntax fixed.")
