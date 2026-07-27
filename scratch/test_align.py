from rich.align import Align
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
import sys
sys.stdout.reconfigure(encoding='utf-8')


console = Console(width=100)

ascii_art_lines = [
    r"[bold #00f3ff] ▄███▄ ██  ██  ▄██▄   ▄███▄ ██████ ██  ██ ██████ █████▄ ██████[/]",
    r"[bold #2be4ff]██▀  ▀ ██  ██ ██  ██ ██▀      ██   ██  ██   ██   ██  ██ ██    [/]",
    r"[bold #56d5ff]██ ▄█▄ ██████ ██  ██  ▀███▄   ██   ██  ██   ██   █████▀ █████ [/]",
    r"[bold #b85eff]██▄  █ ██  ██ ██  ██ ▄   ██   ██   ▀████▀   ██   ██  ██ ██    [/]",
    r"[bold #ff00a0] ▀███▀ ██  ██  ▀██▀  ▀████▀   ██    ▀██▀  ██████ ██  ██ ██████[/]"
]

# We create a sub-grid specifically to hold the logo as a single visual block
logo_block = Table.grid()
logo_block.add_column()  # Left-aligned column by default!
for line in ascii_art_lines:
    logo_block.add_row(line)

banner_layout = Table.grid(expand=True, padding=(1, 0))
banner_layout.add_column()
# Align the logo block as a single entity in the center
banner_layout.add_row(Align.center(logo_block))

header = Panel(
    banner_layout,
    border_style="#ff00a0",
    padding=(1, 2)
)
console.print(header)
