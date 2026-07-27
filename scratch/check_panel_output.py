import utils.display as display
from rich.console import Console
import sys
import os
sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            '..')))

sys.stdout.reconfigure(encoding='utf-8')


# Capture the console output of the banner
console = Console(record=True, width=100)
# We temporarily replace the global console in display module with our
# capturing console
display.console = console

display.banner()

# Get the text representation
text = console.export_text()
for i, line in enumerate(text.split("\n")):
    if "██" in line or "▄" in line:
        print(f"Panel Line {i + 1} (len={len(line)}): '{line}'")
