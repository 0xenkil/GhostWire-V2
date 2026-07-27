from rich.align import Align
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
import sys
sys.stdout.reconfigure(encoding='utf-8')


COLORS = [
    "#00f3ff",
    "#1ce8ff",
    "#38deff",
    "#7ac4ff",
    "#b85eff",
    "#ff00a0",
]

logo_72 = [
    " █████  ██   ██  █████   █████  ███████ ██   ██ ██████  ██████  ███████ ",
    "██   ██ ██   ██ ██   ██ ██        ██    ██   ██   ██    ██   ██ ██      ",
    "██   ██ ███████ ██   ██  █████    ██    ██ █ ██   ██    ██████  █████   ",
    "██ ████ ██   ██ ██   ██      ██   ██    ██████    ██    ██  ██  ██      ",
    "██    █ ██   ██ ██   ██      ██   ██     ████     ██    ██   ██ ██      ",
    " █████  ██   ██  █████   █████    ██      ██    ██████  ██   ██ ███████ ",
]

specs = Table.grid(expand=True, padding=(0, 2))
specs.add_column(justify="right", style="bold #ff00a0")
specs.add_column(justify="left", style="bold white")
specs.add_column(justify="right", style="bold #ff00a0")
specs.add_column(justify="left", style="bold white")
specs.add_row(
    "CORE FLIGHT:", "GHOSTWIRE v6.2.0 [dim]// PROTOCOL-X[/dim]",
    "RUNTIME STATE:", "[#00ff88]ONLINE (SECURE)[/]"
)
specs.add_row(
    "COGNITIVE LAYER:", "SPA harvesting + Wildcard CDN profile",
    "INTELLIGENCE:", "Cognitive Reasoning Engine [bold #00f3ff][v7 ACTIVE][/]"
)
specs_panel = Panel(
    specs,
    border_style="#00f3ff",
    padding=(0, 1),
    title="[bold #ffe600]── SYSTEM TELEMETRY ──[/bold #ffe600]",
    title_align="center"
)

for width in [80, 100, 120]:
    console = Console(width=width)
    console.print(f"\n[bold white]=== Width {width} ===[/bold white]")

    logo_block = Table.grid()
    logo_block.add_column()
    for i, row in enumerate(logo_72):
        logo_block.add_row(f"[bold {COLORS[i]}]{row}[/]")

    banner_layout = Table.grid(expand=True, padding=(1, 0))
    banner_layout.add_column()
    banner_layout.add_row(Align.center(logo_block))
    banner_layout.add_row("")
    banner_layout.add_row(Align.center(specs_panel))

    header = Panel(
        banner_layout,
        border_style="#ff00a0",
        padding=(1, 1),
        title="[bold #ffe600]⚡ GHOSTWIRE INTELLIGENCE SYSTEM ⚡[/bold #ffe600]",
        subtitle="[dim #00f3ff]// HOST THREAT SCANNER AND COMPLIANCE ENGINE //[/dim #00f3ff]"
    )
    console.print(header)
