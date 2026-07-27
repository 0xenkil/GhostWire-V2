import sys
import re
sys.stdout.reconfigure(encoding='utf-8')

with open("C:/Users/ASUS/Desktop/red team/utils/display.py", "r", encoding="utf-8") as f:
    content = f.read()

# Find the definition of ascii_art in display.py
lines = []
for line in content.split("\n"):
    if "r\"[bold" in line:
        # Extract the string inside r"..."
        match = re.search(r'r"\[bold[^\]]*\](.*?)\[/\]"', line)
        if match:
            lines.append(match.group(1))

for i, line in enumerate(lines):
    print(f"Line {i + 1} (len={len(line)}): '{line}'")
