from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.text import Text

from utils.logger import get_logger

console = Console()
log = get_logger("engine")

def banner():
    ascii_art = """[bold cyan]
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗    ██╗██╗██████╗ ███████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║    ██║██║██╔══██╗██╔════╝
 ██║  ███╗███████║██║   ██║███████╗   ██║   ██║ █╗ ██║██║██████╔╝█████╗  
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║███╗██║██║██╔══██╗██╔══╝  
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚███╔███╔╝██║██║  ██║███████╗
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝[/bold cyan]
    """
    
    subtitle = Text.from_markup(
        "[bold magenta]AUTONOMOUS PENTEST ENGINE[/bold magenta]  |  [dim]Legal Use Only[/dim]\n"
        "[bold bright_green]Created by @TheENkil[/bold bright_green]"
    )
    
    panel = Panel(
        Align.center(ascii_art + "\n" + subtitle.markup),
        border_style="cyan",
        padding=(1, 4),
        title="[bold yellow]v5.0.0[/bold yellow]",
        title_align="right"
    )
    console.print()
    console.print(panel)
    console.print()
    log.debug("--- BANNER DISPLAYED ---")

def section(title: str):
    console.print()
    console.rule(f"[bold bright_magenta]✦ {title} ✦[/bold bright_magenta]", style="bright_magenta")
    console.print()
    log.debug(f"--- SECTION: {title} ---")

def success(msg: str):
    log.info(f"[SUCCESS] {msg}")

def warning(msg: str):
    log.warning(msg)

def error(msg: str):
    log.error(msg)

def info(msg: str):
    log.info(msg)

def agent_msg(agent: str, msg: str):
    color_map = {
        "planning": "black on cyan",
        "recon": "black on bright_blue",
        "weaponization": "black on yellow",
        "exploitation": "white on red",
        "persistence": "white on magenta",
        "objectives": "white on bright_red",
        "reporting": "black on bright_green",
        "orchestrator": "black on white"
    }
    color = color_map.get(agent, "black on white")
    console.print(f"[{color}] {agent.upper()} [/{color}] [bold {color.split(' ')[-1]}]{msg}[/]")

def tool_result_table(tool: str, findings: list[dict]):
    if not findings:
        return
    t = Table(title=f"[bold cyan]◈ {tool.upper()} FINDINGS ◈[/bold cyan]", border_style="bright_blue", title_style="bold cyan", header_style="bold bright_green")
    if findings:
        for k in findings[0].keys():
            t.add_column(k.replace('_', ' ').title())
        for row in findings:
            t.add_row(*[str(v) for v in row.values()])
    console.print()
    console.print(t)
    console.print()
