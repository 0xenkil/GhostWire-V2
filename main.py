#!/usr/bin/env python3
"""
AI-Driven Red Team & Penetration Testing Platform
Usage: python3 main.py
"""
import sys
import os
import io

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Force UTF-8 output on Windows CMD (fixes UnicodeEncodeError for █ ─ ╔ etc)
# Windows CMD defaults to cp1252 which can't encode Rich's box/bar characters.
# Setting UTF-8 mode prevents crashes when the reporting phase renders tables.
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
        os.environ["PYTHONIOENCODING"] = "utf-8"
    except Exception:
        pass

# ── Console buffer expansion (Windows CMD) ────────────────────────────────────
# Classic CMD has a ~9001-line scroll buffer. Long-running tools like gobuster
# or nuclei can exceed this, permanently losing early output. Expand to 32000.
if sys.platform == "win32":
    try:
        import ctypes
        STD_OUTPUT_HANDLE = -11
        handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

        class COORD(ctypes.Structure):
            _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

        # 220 columns wide, 32000 rows of scroll buffer
        bufsize = COORD(220, 32000)
        ctypes.windll.kernel32.SetConsoleScreenBufferSize(handle, bufsize)
    except Exception:
        pass
# ──────────────────────────────────────────────────────────────────────────────

from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.console import Console
from rich.table import Table
from utils.display import banner, section, info, warning, error, success
from utils.validator import is_valid_target, normalize_target
from core.session import EngagementSession
from core.orchestrator import Orchestrator
from config import USE_REMOTE_VPS, VPS_HOST, REQUIRE_WRITTEN_CONSENT

console = Console()

LEGAL_NOTICE = """
[bold red]
╔════════════════════════════════════════════════════════════════╗
║                      ⚠  LEGAL NOTICE  ⚠                        ║
╠════════════════════════════════════════════════════════════════╣
║                                                                ║
║  This tool is for [white]AUTHORIZED[/white] security testing [white]ONLY[/white].          ║
║  Unauthorized use against systems you do not own or            ║
║  have explicit written permission to test is [white]ILLEGAL[/white]           ║
║  and may result in criminal prosecution.                       ║
║                                                                ║
║  [bold yellow]By continuing you confirm:[/bold yellow]                                  ║
║  1. You have written authorization to test the target.         ║
║  2. You understand the scope of your engagement.               ║
║  3. You accept full legal responsibility for your actions.     ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝[/bold red]
"""

def get_mode() -> str:
    console.print(Panel("[bold cyan]SELECT OPERATION MODE[/bold cyan]", border_style="cyan"))
    console.print("  [bold bright_green][1][/bold bright_green] [cyan]Pentest Mode[/cyan]      [dim]— Structured vulnerability assessment (phases 1,2,4,7)[/dim]")
    console.print("  [bold bright_red][2][/bold bright_red] [red]Full Red Team[/red]     [dim]— Complete kill-chain simulation (all 7 phases)[/dim]\n")
    while True:
        choice = Prompt.ask("Mode", choices=["1", "2"], default="1")
        return "pentest" if choice == "1" else "redteam"

def get_target() -> str:
    while True:
        raw = Prompt.ask("Enter target (IP, CIDR, or domain)").strip()
        cleaned = normalize_target(raw)
        if is_valid_target(cleaned):
            if cleaned != raw:
                info(f"Target normalized to: {cleaned}")
            return cleaned
        error(f"'{raw}' could not be parsed as a valid IP, CIDR, or domain. Please try again.")

def get_scope(primary_target: str) -> list[str]:
    console.print(f"\n[dim]Primary target: {primary_target}[/dim]")
    console.print("[dim]Add additional in-scope targets (or press Enter to use primary target only)[/dim]")
    scope = [primary_target]
    while True:
        extra = Prompt.ask("Additional scope target (or Enter to finish)", default="").strip()
        if not extra:
            break
        if is_valid_target(extra):
            scope.append(normalize_target(extra))
            info(f"Added to scope: {extra}")
        else:
            warning(f"Invalid target '{extra}', skipping.")
    return scope

def get_roe(mode: str) -> dict:
    section("Rules of Engagement")
    console.print("[dim]Configure what actions are permitted during this engagement[/dim]\n")

    roe = {
        "allow_exploitation": True,
        "allow_brute_force": False,
        "allow_phishing": False,
        "allow_destructive": False,
    }

    roe["allow_exploitation"] = Confirm.ask(
        "Allow active exploitation (running exploits against services)?", default=True
    )

    if mode == "redteam":
        roe["allow_brute_force"] = Confirm.ask(
            "Allow credential brute-forcing?", default=False
        )
        roe["allow_phishing"] = Confirm.ask(
            "Allow phishing simulation (generates test phishing content)?", default=False
        )
        roe["allow_destructive"] = False  # Always False — never allow destructive actions
        info("Note: Destructive actions are always disabled regardless of ROE.")

    return roe

def get_operator() -> str:
    return Prompt.ask("Your name / operator ID (for report)", default="operator").strip()

def get_ai_choice() -> str:
    from core.ai_backend import AIBackend
    # Pass None to get default detection
    detector = AIBackend()
    available = detector._available_backends
    
    console.print(Panel("[bold magenta]SELECT AI ENGINE[/bold magenta]", border_style="magenta"))
    options = []
    
    # Check Ollama
    status_ollama = "[bold bright_green]ONLINE[/bold bright_green]" if "ollama" in available else "[bold red]OFFLINE[/bold red]"
    console.print(f"  [bold bright_cyan][1][/bold bright_cyan] [cyan]Local Ollama[/cyan]     ({status_ollama}) [dim]— Privacy-first, runs on your hardware[/dim]")
    options.append("1")
    
    # Check Cloud (Groq/Google Gemini)
    if "groq" in available or "google" in available:
        status_api = "[bold bright_green]ONLINE[/bold bright_green]"
        console.print(f"  [bold bright_cyan][2][/bold bright_cyan] [cyan]Cloud API[/cyan]        ({status_api}) [dim]— High performance, requires API keys[/dim]")
        options.append("2")
    else:
        status_api = "[bold red]MISSING KEYS[/bold red]"
        console.print(f"  [dim][2] Cloud API        ({status_api}) — Groq/Google keys not found in .env[/dim]")

    while True:
        choice = Prompt.ask("AI Engine", choices=options, default="1")
        if choice == "1":
            return "ollama"
        else:
            # Prefer Groq if available
            return "groq" if "groq" in available else "google"

def pre_flight_checks():
    """Check that minimum requirements are met before starting."""
    import platform
    issues = []

    if platform.system() == "Windows":
        # Only show AI backend hint if groq is NOT importable
        try:
            import groq as _groq_check  # noqa: F401
            _groq_missing = False
        except ImportError:
            _groq_missing = True

        ai_hint = ""
        if _groq_missing:
            ai_hint = (
                "\n\n[bold]AI backend fix needed:[/bold]\n"
                "  Run: pip install groq\n"
                "  Then in .env set: OLLAMA_MODEL=huihui_ai/gemma-4-abliterated:e4b-q8_0 (after running: ollama pull huihui_ai/gemma-4-abliterated:e4b-q8_0)\n"
                "  Or set GOOGLE_API_KEY in .env for Google Gemini fallback"
            )
        console.print(Panel(
            "[bold yellow]WARNING: Running on Windows[/bold yellow]\n\n"
            "This platform was designed for a Linux VPS. Most security tools\n"
            "(nmap, masscan, whois, nikto, etc.) require Linux.\n\n"
            "[bold]To run with full functionality, either:[/bold]\n"
            "  1. Deploy to a Linux VPS (recommended)\n"
            "  2. Use WSL2: open Windows Subsystem for Linux and run from there"
            + ai_hint,
            border_style="yellow"
        ))

    # Check Python version
    if sys.version_info < (3, 10):
        issues.append(f"Python 3.10+ required, found {sys.version_info.major}.{sys.version_info.minor}")

    # Check results directory is writable
    try:
        from pathlib import Path
        Path("results").mkdir(exist_ok=True)
        test_file = Path("results/.write_test")
        test_file.write_text("test", encoding="utf-8")
        test_file.unlink()
    except Exception as e:
        issues.append(f"Cannot write to results directory: {e}")

    # Check at least one AI backend is reachable
    try:
        import requests
        from config import OLLAMA_BASE_URL
        requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=2)
    except Exception:
        from config import GROQ_API_KEY, GOOGLE_API_KEY
        if not GROQ_API_KEY and not GOOGLE_API_KEY:
            issues.append(
                "No AI backend reachable. Start Ollama ('ollama serve') "
                "or add GROQ_API_KEY or GOOGLE_API_KEY to .env"
            )

    # Check VPS connection if enabled
    if USE_REMOTE_VPS:
        section("VPS Connection Check")
        from core.ssh_executor import SSHExecutor
        ssh = SSHExecutor()
        if ssh.connect():
            success(f"Successfully connected to VPS: {VPS_HOST}")
            ssh.close()
        else:
            issues.append(f"Could not connect to VPS at {VPS_HOST}. Check your SSH key and IP.")

    return issues

def main():
    banner()
    console.print(LEGAL_NOTICE, style="bold yellow")

    # Legal consent
    if REQUIRE_WRITTEN_CONSENT:
        if not Confirm.ask("Do you have written authorization to test the target system?", default=False):
            error("Authorization not confirmed. Exiting.")
            sys.exit(1)

    if not Confirm.ask("Do you understand this tool must only be used for authorized security testing?", default=False):
        error("Consent not confirmed. Exiting.")
        sys.exit(1)

    # Pre-flight checks
    section("Pre-flight Checks")
    issues = pre_flight_checks()
    if issues:
        for issue in issues:
            warning(f"Pre-flight issue: {issue}")
        if not Confirm.ask("Issues detected above. Continue anyway?", default=False):
            sys.exit(1)
    else:
        success("All pre-flight checks passed.")

    # Configuration
    section("Engagement Configuration")
    mode = get_mode()
    ai_choice = get_ai_choice()
    target = get_target()
    scope = get_scope(target)
    roe = get_roe(mode)
    operator = get_operator()

    # Confirmation
    section("Confirm Engagement")
    
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(justify="right", style="bold cyan")
    grid.add_column(justify="left", style="white")
    
    grid.add_row("MODE ⚡", f"[bold bright_yellow]{mode.upper()}[/bold bright_yellow]")
    grid.add_row("AI ENGINE 🧠", f"[bold bright_green]{ai_choice.upper()}[/bold bright_green]")
    grid.add_row("TARGET 🎯", f"[bold bright_blue]{target}[/bold bright_blue]")
    grid.add_row("SCOPE 🔍", f"{', '.join(scope)}")
    grid.add_row("EXECUTION 🖥️", f"{'Remote VPS (' + VPS_HOST + ')' if USE_REMOTE_VPS else 'Local Machine'}")
    grid.add_row("OPERATOR 👤", f"{operator}")
    
    roe_str = ", ".join([f"[green]{k}[/green]" if v else f"[dim red]{k}[/dim red]" for k, v in roe.items()])
    grid.add_row("ROE 📜", roe_str)

    console.print(Panel(
        grid,
        title="[bold bright_magenta]ENGAGEMENT PARAMETERS[/bold bright_magenta]", 
        border_style="bright_magenta",
        padding=(1, 4)
    ))

    if not Confirm.ask("Start engagement with these parameters?", default=False):
        info("Engagement cancelled.")
        sys.exit(0)

    # Create session and run
    session = EngagementSession(
        mode=mode,
        target=target,
        scope=scope,
        rules_of_engagement=roe,
        operator=operator,
        ai_backend=ai_choice
    )


    info(f"Engagement ID: {session.engagement_id}")
    info(f"Results directory: {session.results_dir}")

    orchestrator = Orchestrator(session)

    try:
        orchestrator.run()
    except KeyboardInterrupt:
        warning("\nEngagement interrupted by user.")
        session.shutdown.set() # Signally all background threads to stop
        warning("Partial results may be saved. Run reporting manually if needed.")
        try:
            orchestrator.store.close()
        except Exception:
            pass
        sys.exit(0)
    except Exception as e:
        error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
