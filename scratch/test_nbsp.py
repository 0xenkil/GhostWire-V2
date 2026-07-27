from rich.table import Table
from rich.panel import Panel
from rich.console import Console
import sys
sys.stdout.reconfigure(encoding='utf-8')


console = Console(width=100)

# Replace trailing space with non-breaking space (\xa0)
ascii_art = (
    r" ▄███▄ ██  ██  ▄██▄   ▄███▄ ██████ ██  ██ ██████ █████▄ ██████" + "\n"
    r"██▀  ▀ ██  ██ ██  ██ ██▀      ██   ██  ██   ██   ██  ██ ██    " +
    "\n"  # Contains 4 non-breaking spaces
    r"██ ▄█▄ ██████ ██  ██  ▀███▄   ██   ██  ██   ██   █████▀ █████ " +
    "\n"  # Contains 1 non-breaking space
    r"██▄  █ ██  ██ ██  ██ ▄   ██   ██   ▀████▀   ██   ██  ██ ██    " +
    "\n"  # Contains 4 non-breaking spaces
    r" ▀███▀ ██  ██  ▀██▀  ▀████▀   ██    ▀██▀  ██████ ██  ██ ██████"
)

# Replace spaces with non-breaking spaces in our strings
# Replacing the typed nbsp with unicode escape
ascii_art_nbsp = ascii_art.replace(" ", "\u00a0")

banner_layout = Table.grid(expand=True, padding=(1, 0))
banner_layout.add_column(justify="center")
banner_layout.add_row(ascii_art_nbsp)

header = Panel(
    banner_layout,
    border_style="#ff00a0",
    padding=(1, 2)
)
console.print(header)
