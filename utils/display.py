"""
GHOSTWIRE V7 — Premium Developer Visual Console UI Dashboard
Handles all terminal UI: banners, status messages, phase transitions,
live spinners, and engagement dashboards.
"""
import time
import sys
import os
import shutil
import contextlib

# ── Force UTF-8 on Windows ───────────────────────────────────────────────────
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        os.environ["PYTHONIOENCODING"] = "utf-8"
    except Exception as _e:
        import logging
        logging.getLogger(__name__).debug(
            f'Swallowed exception in display.py: {_e}')

try:
    from rich import box
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.padding import Padding
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

    class _MockBox:
        def __getattr__(self, name):
            return ""
    box = _MockBox()

    class Console:
        def __init__(self, *a, **k): pass
        def print(self, *a, **k): print(*a)

        def status(self, *a, **k):
            class _S:
                def start(self): pass
                def stop(self): pass
            return _S()

    class Panel:
        def __init__(self, c, **kw): self.c = c

    class Table:
        def __init__(self, **kw): self.rows = []
        def add_column(self, *a, **kw): pass
        def add_row(self, *a): self.rows.append(a)

    class Text:
        def __init__(self, m=""): pass
        @staticmethod
        def from_markup(m): return Text(m)

    class Group:
        def __init__(self, *a): pass

    class Align:
        @staticmethod
        def center(r, **kw): return r

from utils.logger import get_logger, _LOG_CONSOLE

console = _LOG_CONSOLE if _LOG_CONSOLE else Console(force_terminal=True)
log = get_logger("engine")

# ─── Ultra-Premium Ghostwire Indigo-Teal Cyber Palette ───────────────────────
C_ACCENT = "#8b5cf6"  # Indigo Violet (representing the ghostly "wire")
C_ACCENT2 = "#06b6d4"  # Cyber Teal
C_CYAN = "#00f5d4"  # Electric Mint / Aqua
C_SUCCESS = "#10b981"  # Emerald Toxic Green
C_WARN = "#ffb703"  # Amber Flame
C_DANGER = "#f43f5e"  # Cyberpunk Crimson
C_DIM = "#64748b"  # Cool Slate Gray
C_BRIGHT = "#f1f5f9"  # High-Contrast Snowy Gray
C_BG_DARK = "#0f172a"  # Slate-Black / Blue tint

PHASES = {
    "planning": {"c": C_CYAN, "tag": "PLN", "bar": "cyan"},
    "recon": {"c": C_ACCENT, "tag": "RCN", "bar": "blue"},
    "weaponization": {"c": C_WARN, "tag": "WPN", "bar": "yellow"},
    "exploitation": {"c": C_DANGER, "tag": "XPL", "bar": "red"},
    "persistence": {"c": "#d946ef", "tag": "PST", "bar": "magenta"},
    "objectives": {"c": "#f97316", "tag": "OBJ", "bar": "bright_red"},
    "reporting": {"c": C_SUCCESS, "tag": "RPT", "bar": "green"},
    "validation": {"c": "#eab308", "tag": "VAL", "bar": "yellow"},
}


def success(msg: str):
    text = Text.from_markup(f"  [bold {C_SUCCESS}]✔  SUCCESS [/] {msg}")
    console.print(text)
    log.debug(f"[SUCCESS] {msg}")


def warning(msg: str):
    text = Text.from_markup(f"  [bold {C_WARN}]⚠  WARNING [/] {msg}")
    console.print(text)
    log.debug(f"[WARNING] {msg}")


def error(msg: str):
    text = Text.from_markup(f"  [bold {C_DANGER}]✘  FAILURE [/] {msg}")
    console.print(text)
    log.debug(f"[ERROR] {msg}")


def info(msg: str):
    text = Text.from_markup(f"  [bold {C_ACCENT}]ℹ  SYSTEM  [/] {msg}")
    console.print(text)
    log.debug(f"[INFO] {msg}")


def agent_msg(agent: str, msg: str):
    p = PHASES.get(agent, {"c": C_BRIGHT, "tag": agent.upper()[:3]})
    text = Text.from_markup(f"  [bold {p['c']}]●  {p['tag']} [/] {msg}")
    console.print(text)


def banner():
    """Ultra-Premium responsive centralized brand header panel for GHOSTWIRE V7."""
    width = console.width or 80
    if width >= 90:
        # High-impact massive 3D custom block logo for large terminals (72
        # chars wide)
        logo_lines = [
            "  █████  ██   ██  █████   █████  ███████ ██   ██ ██████  ██████  ███████ ",
            " ██   ██ ██   ██ ██   ██ ██        ██    ██   ██   ██    ██   ██ ██      ",
            " ██   ██ ███████ ██   ██  █████    ██    ██ █ ██   ██    ██████  █████   ",
            " ██ ████ ██   ██ ██   ██      ██   ██    ██████    ██    ██  ██  ██      ",
            " ██    █ ██   ██ ██   ██      ██   ██     ████     ██    ██   ██ ██      ",
            "  █████  ██   ██  █████   █████    ██      ██    ██████  ██   ██ ███████ "
        ]
        gradient_colors = [
            "#00f5d4",
            "#06b6d4",
            "#3b82f6",
            "#8b5cf6",
            "#d946ef",
            "#f43f5e"]
    else:
        # Optimized compact slant logo for smaller terminals
        logo_lines = [
            "   ______ __                      __       _                 ",
            "  / ____// /_   ____   _____ / /_ _  __ (_)_____ ___       ",
            " / / __ / __ \\ / __ \\ / ___// __/| |/_// // ___// _ \\      ",
            "/ /_/ // / / // /_/ /(__  )/ /_ _>  < / // /   /  __/      ",
            "\\____//_/ /_/ \\____//____/ \\__//_/|_|/_//_/    \\___/  v7.0.0"
        ]
        gradient_colors = [
            "#00f5d4",
            "#06b6d4",
            "#3b82f6",
            "#8b5cf6",
            "#f43f5e"]

    logo_text = Text()
    for line, color in zip(logo_lines, gradient_colors):
        logo_text.append(line + "\n", style=f"bold {color}")

    logo_align = Align.center(logo_text)

    subtitle = Align.center(Text.from_markup(
        f"[bold {C_BRIGHT}] GHOSTWIRE V7 [/] [bold {C_DIM}]•[/] [bold {C_ACCENT2}]Universal Autonomous Penetration Testing Engine[/]"
    ))

    # Sleek status indicators matching the palette
    status_bar = Align.center(Text.from_markup(
        f"[bold {C_DIM}]»[/] [bold white]ENGINE:[/] [bold {C_SUCCESS}]ONLINE[/]   "
        f"[bold {C_DIM}]»[/] [bold white]EXECUTION:[/] [bold {C_CYAN}]REACT GRAPH[/]   "
        f"[bold {C_DIM}]»[/] [bold white]ROE:[/] [bold {C_DANGER}]STRICT SCOPE[/]"
    ))

    # Modern grid of capabilities
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", width=18)
    grid.add_column(justify="left")

    grid.add_row(
        Text.from_markup(f"[bold {C_ACCENT}]● COGNITIVE[/]"),
        Text.from_markup(
            f"[bold {C_BRIGHT}]Multi-Agent Reasoning & Incremental Learning[/]")
    )
    grid.add_row(
        Text.from_markup(f"[bold {C_ACCENT2}]● STEALTH[/]"),
        Text.from_markup(
            f"[bold {C_BRIGHT}]WAF Ghost Proxy Chains & IP Rotation Matrix[/]")
    )
    grid.add_row(
        Text.from_markup(f"[bold {C_SUCCESS}]● DATABASE[/]"),
        Text.from_markup(
            f"[bold {C_BRIGHT}]Actor-Model Transaction sqlite3 WAL Database[/]")
    )
    grid.add_row(
        Text.from_markup(f"[bold {C_DANGER}]● EXECUTION[/]"),
        Text.from_markup(
            f"[bold {C_BRIGHT}]Isolated Payload Sandbox & WSL local Linux Environment[/]")
    )

    divider = Align.center(Text("━" * 66, style=f"bold {C_DIM}"))

    panel_group = Group(
        logo_align,
        Padding(subtitle, (0, 0, 1, 0)),
        Padding(status_bar, (0, 0, 1, 0)),
        divider,
        Padding(Align.center(grid), (1, 0, 0, 0))
    )

    panel = Panel(
        panel_group,
        border_style=C_DIM,  # Sleek dark slate border so colors pop
        box=box.ROUNDED,
        expand=True,
        padding=(1, 2)
    )
    console.print(panel)
    console.print()
    log.debug("--- COMMAND CENTER HUD INITIALIZED ---")


def section(title: str):
    """Draw a clean horizontal separator panel."""
    term_width = min(shutil.get_terminal_size().columns, 80)
    sec_text = f"  ❯❯❯ {title.upper()} "
    remaining = max(10, term_width - len(sec_text) - 4)
    rule = f"[bold {C_ACCENT}]{sec_text}[/]" + \
        f"[bold {C_DIM}]" + "━" * remaining + "[/]"
    console.print(Text.from_markup(rule))
    console.print()
    log.debug(f"--- SECTION: {title} ---")


def print_legal():
    """Classified authorization panel warning."""
    body = (
        f"  [bold {C_DANGER}]⚠️  RESTRICTED OPERATIONAL SCOPE BOUNDARY MATRIX[/]\n\n"
        f"  [bold {C_BRIGHT}]1.[/] WRITTEN TARGET-OWNER TESTING SCOPE AUTHORIZATION IS MANDATORY.\n"
        f"  [bold {C_BRIGHT}]2.[/] OPERATOR ASSUMES 100% CIVIL AND CRIMINAL DEPLOYMENT LIABILITIES.\n"
        f"  [bold {C_BRIGHT}]3.[/] SECURITY LOGS & ENGAGEMENT METRICS ARE SIGNED IN TRANSACTION WAL."
    )
    panel = Panel(
        body,
        border_style=C_DANGER,
        box=box.SQUARE,
        padding=(1, 2),
        expand=False
    )
    console.print(Padding(panel, (0, 2)))
    console.print()


def preflight_check(label: str, status: str, ok: bool):
    """Extremely premium high-contrast diagnostics badge check."""
    if ok:
        badge = f"[bold white on {C_SUCCESS}]  PASS  [/]"
    elif (status and "warn" in status.lower()) or (not ok and status == "Windows (Degraded)"):
        badge = f"[bold black on {C_WARN}]  WARN  [/]"
    else:
        badge = f"[bold white on {C_DANGER}]  FAIL  [/]"

    left_side = f"  [bold {C_ACCENT}]◆[/]  {label}"
    if status and status != "NOMINAL" and status != "Windows (Degraded)":
        left_side += f" ({status})"

    plain_len = len(label) + (len(status) + 3 if status and status !=
                              "NOMINAL" and status != "Windows (Degraded)" else 0)
    dots_count = max(2, 55 - plain_len)
    dots = f"[bold {C_DIM}]" + "." * dots_count + "[/]"

    row = Text.from_markup(f"{left_side} {dots} {badge}")
    console.print(row)
    time.sleep(0.005)


def mission_briefing(params: dict):
    """Gorgeous structured operational briefing card."""
    t = Table.grid(padding=(0, 2))
    t.add_column(style=f"bold {C_DIM}")
    t.add_column(style=f"bold {C_BRIGHT}")

    def _add_row(label, val, col=C_BRIGHT):
        t.add_row(f"  ❯ {label}", f"[bold {col}]{val}[/]")

    _add_row(
        "Cognitive Engine ",
        params.get(
            "ai",
            "OLLAMA").upper(),
        C_ACCENT2)
    _add_row(
        "Assessment Mode  ",
        params.get(
            "mode",
            "PENTEST").upper(),
        C_ACCENT)
    _add_row(
        "Execution Node   ",
        params.get(
            "execution",
            "LOCAL").upper(),
        C_BRIGHT)
    _add_row("Target Endpoint  ", params.get("target", "localhost"), C_ACCENT)
    _add_row("Boundary Scope   ", params.get("scope", "localhost"), C_DIM)

    os_items = params.get("osint_list", [])
    _add_row(
        "Threat Intel     ",
        ", ".join(os_items) if os_items else "PASSIVE",
        C_SUCCESS if os_items else C_DIM)

    st_items = params.get("stealth_list", [])
    _add_row(
        "Evasion Policy   ",
        ", ".join(st_items) if st_items else "DEGRADED",
        C_SUCCESS if st_items else C_DANGER)

    roe = params.get("roe", {})
    roe_parts = []
    for k, v in roe.items():
        name = k.replace("allow_", "").upper()
        color = C_SUCCESS if v else C_DIM
        roe_parts.append(f"[bold {color}]{name}[/]")
    _add_row("ROE Boundaries   ", " / ".join(roe_parts), C_BRIGHT)

    panel = Panel(
        t,
        border_style=C_DIM,
        box=box.SQUARE,
        padding=(1, 2),
        expand=False,
        title=f" [bold {C_BRIGHT}]OPERATIONAL BRIEFING[/bold {C_BRIGHT}] ",
        title_align="left"
    )
    console.print(Padding(panel, (0, 2)))

    if roe.get("allow_destructive"):
        console.print()
        warn_panel = Panel(
            f" [bold {C_DANGER}]⚠️  HIGH RISK CLASSIFIED SECTOR: DESTRUCTIVE EXPLOITS AUTHORIZED[/]",
            border_style=C_DANGER,
            box=box.SQUARE,
            padding=(0, 2),
            expand=False
        )
        console.print(Padding(warn_panel, (0, 2)))
    console.print()


def kill_chain_status(
        all_phases: list[str], current_phase: str = None, completed: dict = None):
    """Sleek horizontal kill chain progress tracker panel."""
    completed = completed or {}
    parts = []

    for p in all_phases:
        ph = PHASES.get(p, {"c": C_DIM, "tag": p.upper()[:3]})
        tag = ph["tag"]

        if p == current_phase:
            parts.append(f"[bold white on {C_ACCENT2}] {tag} [/]")
        elif p in completed:
            status = completed[p]
            color = C_SUCCESS if status == "success" else C_DANGER
            parts.append(f"[bold {color}]■ {tag}[/]")
        else:
            parts.append(f"[bold {C_DIM}]□ {tag}[/]")

    chain = f"  [bold {C_DIM}]❯[/]  ".join(parts)
    panel = Panel(
        chain,
        border_style=C_DIM,
        box=box.SQUARE,
        expand=False,
        title=f" [bold {C_BRIGHT}]OPERATIONAL CHEVRON STATE[/bold {C_BRIGHT}] ",
        title_align="left"
    )
    console.print(Padding(panel, (0, 2)))
    console.print()


def phase_header(phase_name: str, description: str = ""):
    p = PHASES.get(phase_name, {"c": C_ACCENT, "tag": phase_name.upper()[:3]})
    term_width = min(shutil.get_terminal_size().columns, 80)

    sec_text = f"  ❯❯❯ PHASE: {phase_name.upper()} "
    remaining = max(10, term_width - len(sec_text) - 4)
    rule = f"[bold {p['c']}]{sec_text}[/]" + \
        f"[bold {C_DIM}]" + "━" * remaining + "[/]"
    console.print(Text.from_markup(rule))
    if description:
        console.print(
            Text.from_markup(
                f"  [bold {C_DIM}]Scope: {description}[/]"))
    console.print()


def phase_complete(phase_name: str, status: str,
                   duration_s: float, findings_count: int = 0):
    p = PHASES.get(phase_name, {"c": C_ACCENT, "tag": phase_name.upper()[:3]})
    st_upper = (status or "unknown").upper()

    if st_upper in ("SUCCESS", "COMPLETE"):
        st = f"[bold {C_SUCCESS}]● SUCCESS[/]"
    elif st_upper == "TIMEOUT":
        st = f"[bold {C_WARN}]▲ TIMEOUT[/]"
    elif st_upper == "SKIPPED":
        st = f"[bold {C_DIM}]◆ BYPASS[/]"
    else:
        st = f"[bold {C_DANGER}]■ FAILURE[/]"

    mins, secs = divmod(int(duration_s), 60)
    dur = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"

    findings_str = f" | [bold {C_SUCCESS}]+{findings_count} findings[/]" if findings_count > 0 else ""
    console.print(
        Text.from_markup(
            f"  [bold {C_ACCENT}]◆ Phase {
                p['tag']} complete[/]  Status: {st}  |  Duration: {dur}{findings_str}"))
    console.print()


@contextlib.contextmanager
def phase_spinner(phase_name: str):
    p = PHASES.get(phase_name, {"c": C_ACCENT, "tag": phase_name.upper()[:3]})
    label = f"  [bold {
        p['c']}]◆ {
        p['tag']}[/] [bold white]Active ReAct Strategy Reasoning Execution...[/bold white]"
    # Fix: Remove rich.console.status() to prevent massive log spam
    # when interleaved with standard logging statements.
    console.print(Text.from_markup(label))
    yield None


def engagement_dashboard(
        phases: dict, total_duration_s: float, engagement_id: str, target: str):
    t_min, t_sec = divmod(int(total_duration_s), 60)
    t_hr, t_min = divmod(t_min, 60)
    total_str = f"{t_hr}h {t_min}m {t_sec}s" if t_hr > 0 else (
        f"{t_min}m {t_sec}s" if t_min > 0 else f"{t_sec}s")

    total_findings = sum(d.get("findings", 0) for d in phases.values())

    t = Table(
        show_header=True,
        header_style=f"bold {C_ACCENT}",
        border_style=C_DIM,
        padding=(0, 2),
        expand=False,
        box=box.SQUARE
    )
    t.add_column("OPERATIONAL PHASE", style=f"bold {C_BRIGHT}")
    t.add_column("DIAGNOSTIC STATUS", justify="center")
    t.add_column("DURATION", justify="right", style=C_DIM)
    t.add_column("FINDINGS DISCOVERED", justify="right")

    for name, data in phases.items():
        p = PHASES.get(name, {"c": C_DIM, "tag": name.upper()[:3]})
        st = (data.get("status") or "unknown").upper()
        dur = data.get("duration", 0)
        finds = data.get("findings", 0)

        if st in ("SUCCESS", "COMPLETE"):
            st_cell = f"[bold {C_SUCCESS}]● COMPLETE[/]"
        elif st == "TIMEOUT":
            st_cell = f"[bold {C_WARN}]▲ TIMEOUT [/]"
        elif st == "SKIPPED":
            st_cell = f"[bold {C_DIM}]◆ BYPASS  [/]"
        else:
            st_cell = f"[bold {C_DANGER}]■ FAILED  [/]"

        d_min, d_sec = divmod(int(dur), 60)
        dur_str = f"{d_min}m {d_sec:02d}s" if d_min > 0 else f"{d_sec}s"
        finds_str = f"[bold {C_SUCCESS}]+{finds}[/] findings" if finds > 0 else f"[bold {C_DIM}]0 findings[/]"

        t.add_row(f"[{p['c']}]{name.upper()}[/]", st_cell, dur_str, finds_str)

    info_table = Table.grid(padding=(0, 2))
    info_table.add_column(style=f"bold {C_DIM}")
    info_table.add_column(style=f"bold {C_BRIGHT}")

    info_table.add_row("  ❯ Engagement ID   ", engagement_id)
    info_table.add_row("  ❯ Target Node     ", target)
    info_table.add_row("  ❯ Total Run Time  ", total_str)
    info_table.add_row(
        "  ❯ Vulns Logged    ",
        f"[bold {C_SUCCESS}]{total_findings}[/bold {C_SUCCESS}]")

    group = Group(
        t,
        Padding(info_table, (1, 0))
    )

    panel = Panel(
        group,
        border_style=C_SUCCESS,
        box=box.SQUARE,
        expand=False,
        title=f" [bold {C_SUCCESS}]MISSION POST-ENGAGEMENT REPORT SUMMARY[/bold {C_SUCCESS}] ",
        title_align="left"
    )
    console.print(panel)
    console.print()
