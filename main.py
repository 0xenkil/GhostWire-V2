#!/usr/bin/env python3
"""
GHOSTWIRE V7 — Autonomous Pentest Engine
"""
from core.ai_backend import AIBackend
from config_backends import USE_WSL, WSL_DISTRO, validate_endpoints, SHODAN_API_KEY, SECURITYTRAILS_API_KEY, VIRUSTOTAL_API_KEY
from config import REQUIRE_WRITTEN_CONSENT
from core.orchestrator import Orchestrator
from core.session import EngagementSession
from core.target_context import TargetContext
from utils.validator import is_valid_target
from utils.display import (
    banner, section, info, warning, error, success,
    print_legal, preflight_check, mission_briefing,
    C_ACCENT, C_DIM, C_BRIGHT, C_DANGER, C_SUCCESS, C_WARN,
)
from rich.text import Text
from rich.console import Console
from rich.prompt import Prompt, Confirm
import sys
import os
import json
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Force UTF-8 on Windows
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
            f'Swallowed exception in main.py: {_e}')

    try:
        import ctypes
        from ctypes import wintypes
        handle = ctypes.windll.kernel32.GetStdHandle(-11)

        class CSBI(ctypes.Structure):
            _fields_ = [("dwSize", wintypes._COORD), ("dwCursorPosition", wintypes._COORD),
                        ("wAttributes", wintypes.WORD), ("srWindow",
                                                         wintypes.SMALL_RECT),
                        ("dwMaximumWindowSize", wintypes._COORD)]
        csbi = CSBI()
        if ctypes.windll.kernel32.GetConsoleScreenBufferInfo(
                handle, ctypes.byref(csbi)):
            # 32767 is the absolute Windows SHORT max — cannot go higher
            _MAX_BUFFER = 32767
            ok = ctypes.windll.kernel32.SetConsoleScreenBufferSize(
                handle, wintypes._COORD(csbi.dwSize.X, _MAX_BUFFER)
            )
            if ok:
                print(
                    f"  [SYS] Console buffer expanded to {_MAX_BUFFER} lines.")
    except Exception as _e:
        import logging
        logging.getLogger(__name__).debug(
            f'Swallowed exception in main.py: {_e}')


console = Console(force_terminal=True)


def _load_debug_cfg() -> dict:
    try:
        import uuid
        from config_paths import LOG_DIR
        session_id = os.getenv("SESSION_ID") or uuid.uuid4().hex[:8]
        log_file = LOG_DIR / f"debug-{session_id}.log"
        return {"log_file": str(log_file), "session_id": session_id}
    except Exception as e:
        import logging as __logging_tmp
        __logging_tmp.getLogger(__name__).error(
            f"Unhandled exception: {e}", exc_info=True)
        return {"log_file": "debug.log", "session_id": "unknown"}


def _agent_debug_log(location, message, data,
                     run_id="run1", hypothesis_id="H2"):
    try:
        dbg = _load_debug_cfg()
        Path(dbg["log_file"]).parent.mkdir(parents=True, exist_ok=True)
        with open(dbg["log_file"], "a", encoding="utf-8") as f:
            f.write(json.dumps({"sessionId": dbg["session_id"], "runId": run_id,
                                "hypothesisId": hypothesis_id, "location": location,
                                "message": message, "data": data,
                                "timestamp": int(time.time() * 1000)}, ensure_ascii=True) + "\n")
    except Exception as _e:
        import logging
        logging.getLogger(__name__).debug(
            f'Swallowed exception in main.py: {_e}')


# ═══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE SETUP FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def get_mode() -> str:
    console.print(
        f"  [bold {C_ACCENT}]◆[/]  [bold white]Tactical Assessment Mode[/]")
    console.print(
        f"     [bold {C_ACCENT}][1][/] [bold {C_BRIGHT}]PENTEST[/]  - Structured recon & vuln verification")
    console.print(
        f"     [bold {C_ACCENT}][2][/] [bold {C_BRIGHT}]RED TEAM[/] - Dynamic stealth & multi-hop persistence")
    choice = Prompt.ask(
        f"  [bold {C_ACCENT}]▸[/] [bold white]Select Mode[/]",
        choices=[
            "1",
            "2"],
        default="1")
    console.print()
    return "pentest" if choice == "1" else "redteam"


def get_target() -> TargetContext:
    console.print(
        f"  [bold {C_ACCENT}]◆[/]  [bold white]Identify Host Target[/]")
    while True:
        raw = Prompt.ask(
            f"  [bold {C_ACCENT}]▸[/] [bold white]Enter domain, URL, or IP[/]").strip()
        if not raw:
            error("Target cannot be empty.")
            continue
        try:
            ctx = TargetContext.from_input(raw)
            if not is_valid_target(ctx.host):
                error(f"Invalid target: '{raw}'")
                continue
            success(f"Target Parsed: {ctx.full_url} (host={ctx.host})")
            console.print()
            return ctx
        except Exception as e:
            error(f"Target parsing failure: {e}")


def get_scope(primary_ctx: TargetContext) -> list[str]:
    scope = [primary_ctx.original_input]
    console.print(
        f"  [bold {C_ACCENT}]◆[/]  [bold white]Define Additional Target Scope[/] [bold {C_DIM}](press ENTER to skip)[/]")
    while True:
        extra = Prompt.ask(
            f"  [bold {C_ACCENT}]▸[/] [bold white]Add Scope Address[/]",
            default="").strip()
        if not extra:
            break
        if not is_valid_target(extra):
            error(f"Invalid scope node: '{extra}'")
            continue
        scope.append(extra)
        success(f"Added target to scope: {extra}")
    console.print()
    return scope


def get_ai_choice() -> str:
    detector = AIBackend()
    available = detector._available_backends

    oll_status = f"[bold {C_SUCCESS}]ONLINE[/]" if "ollama" in available else f"[bold {C_DIM}]OFFLINE[/]"
    cloud_items = [x.title() for x in ["groq", "google"] if x in available]
    cloud_status = f"[bold {C_SUCCESS}]ONLINE[/] ({
        ', '.join(cloud_items)})" if cloud_items else f"[bold {C_DANGER}]NO KEYS[/]"

    console.print(
        f"  [bold {C_ACCENT}]◆[/]  [bold white]Assign AI Cognitive Orchestrator[/]")
    console.print(
        f"     [bold {C_ACCENT}][1][/] [bold {C_BRIGHT}]LOCAL OLLAMA[/]  - Status: {oll_status}")
    if cloud_items:
        console.print(
            f"     [bold {C_ACCENT}][2][/] [bold {C_BRIGHT}]CLOUD API[/]     - Status: {cloud_status}")

    opts = ["1"]
    if cloud_items:
        opts.append("2")
    choice = Prompt.ask(
        f"  [bold {C_ACCENT}]▸[/] [bold white]Select Platform[/]",
        choices=opts,
        default="1")
    console.print()
    if choice == "1":
        return "ollama"
    for name in ["groq", "google"]:
        if name in available:
            return name
    return "ollama"


def get_roe(mode: str, auto_confirm: bool = False) -> dict:
    roe = {"allow_exploitation": True, "allow_brute_force": False,
           "allow_phishing": False, "allow_destructive": False}

    console.print(
        f"  [bold {C_ACCENT}]◆[/]  [bold white]Rules of Engagement boundaries[/]")
    roe["allow_exploitation"] = Confirm.ask(
        f"  [bold {C_ACCENT}]▸[/] [bold white]Enable active exploitation?[/]", default=True)

    if Confirm.ask(
            f"  [bold {C_DANGER}]▸ Enable DESTRUCTIVE OPERATIONS?[/] (RCE/Exfil/Implantation)", default=False):
        warning("Operator is authorizing destructive exploits.")
        if not auto_confirm and Confirm.ask(
                f"  [bold {C_DANGER}]▸ CONFIRM DESTRUCTIVE SELECTION?[/]", default=False):
            roe["allow_destructive"] = True

    if mode == "redteam":
        roe["allow_brute_force"] = Confirm.ask(
            f"  [bold {C_ACCENT}]▸[/] [bold white]Allow brute-force credential attempts?[/]",
            default=False)
        roe["allow_phishing"] = Confirm.ask(
            f"  [bold {C_ACCENT}]▸[/] [bold white]Allow social engineering simulations?[/]",
            default=False)

    console.print()
    return roe


def get_stealth_config() -> dict:
    config = {"ghost_mode": False, "rotate_ip": False, "waf_defense": False}

    console.print(
        f"  [bold {C_ACCENT}]◆[/]  [bold white]Traffic Stealth & Evasion Matrix[/]")
    config["ghost_mode"] = Confirm.ask(
        f"  [bold {C_ACCENT}]▸[/] [bold white]Enable WafGhost? (User-Agent rotation + mutation)[/]",
        default=True)
    config["rotate_ip"] = Confirm.ask(
        f"  [bold {C_ACCENT}]▸[/] [bold white]Enable Tor-Rotate? (dynamic proxy SOCKS chains)[/]",
        default=True)
    if not config["ghost_mode"] and not config["rotate_ip"]:
        config["waf_defense"] = Confirm.ask(
            f"  [bold {C_ACCENT}]▸[/] [bold white]Enable WAF-Defense? (polite delay gating)[/]",
            default=True)
    console.print()
    return config


def get_operator() -> str:
    return Prompt.ask(
        f"  [bold {C_ACCENT}]▸[/] [bold white]Operator Identification Tag[/]", default="operator").strip()


# ═══════════════════════════════════════════════════════════════════════════════
#  PRE-FLIGHT
# ═══════════════════════════════════════════════════════════════════════════════

def pre_flight_checks(auto_confirm: bool = False) -> bool:
    import platform
    import shutil
    critical_found = False
    critical, backend_warnings = validate_endpoints()

    console.print(
        Text.from_markup(
            f"  [bold {C_ACCENT}]─── PRE-FLIGHT CORE DIAGNOSTICS ───[/]"))

    # Platform (Allow Windows if USE_WSL is active since it operates as a full
    # Linux VM)
    is_linux = platform.system() != "Windows" or USE_WSL
    status_label = ""
    if platform.system() == "Windows":
        status_label = f"WSL ({
            WSL_DISTRO or 'Ubuntu'})" if USE_WSL else "Windows (Degraded)"
    preflight_check("Platform Environment", status_label, is_linux)

    # WSL functional check if platform is Windows and USE_WSL is set
    if platform.system() == "Windows" and USE_WSL:
        from config import verify_wsl_availability
        wsl_ok = verify_wsl_availability()
        preflight_check(
            "WSL Linux Subsystem",
            "responsive" if wsl_ok else "unresponsive/missing",
            wsl_ok)
        if not wsl_ok:
            critical_found = True
            critical.append(
                "WSL is not responsive or VM virtualization is disabled in Windows BIOS/features.")

    # Python
    py_ok = sys.version_info >= (3, 10)
    preflight_check(
        "Python Runtime Execution", f"{
            sys.version_info.major}.{
            sys.version_info.minor}", py_ok)

    # AI
    detector = AIBackend()
    ai_report = detector.check_all_backends()
    try:
        from agents.base_agent import BaseAgent

        class DummyAgent(BaseAgent):
            async def run(self): pass
        dummy = DummyAgent("audit", session=None, state_store=None, tool_manager=None,
                           ai_backend=detector, message_bus=None, scope_enforcer=None)
        ping = detector.query(
            "system", "Respond with ONLY the word 'READY' if you can read this.")
        if dummy.analyzer and dummy.reasoning and "READY" in ping.upper():
            preflight_check("Intelligence Layer", "all modules loaded", True)
        elif dummy.analyzer and dummy.reasoning:
            preflight_check("Intelligence Layer", "AI no-response", False)
            backend_warnings.append(
                "AI backend active but failed connectivity ping.")
        else:
            preflight_check("Intelligence Layer", "modules missing", False)
            critical_found = True
    except Exception as e:
        preflight_check("Intelligence Layer", str(e)[:60], False)
        backend_warnings.append(f"Init failed: {e}")
        critical_found = True

    # Groq keys
    if ai_report["groq"]["keys"]:
        for k in ai_report["groq"]["keys"]:
            ok = k["status"] in ("ONLINE", "QUERYABLE")
            err = k.get("error", "")
            preflight_check(
                f"Groq API Key Pool ({
                    k['key']})",
                err if not ok else "ACTIVE",
                ok)

    # Google Gemini
    g_report = ai_report.get("google", {})
    if g_report.get("status"):
        g_ok = g_report.get("status") == "ONLINE"
        g_detail = "ACTIVE" if g_ok else g_report.get("details", "unreachable")
        preflight_check("Google Gemini Cloud API Key", g_detail, g_ok)

    term_width = min(shutil.get_terminal_size().columns, 80)
    console.print(Text.from_markup(
        f"  [bold {C_DIM}]" + "─" * (term_width - 4) + "[/]"))
    console.print()

    if platform.system() == "Windows" and not USE_WSL:
        warning("Windows host without WSL. Stealth and scanning may be limited.")

    for c in critical:
        error(f"CRITICAL: {c}")
        critical_found = True
    for w in backend_warnings:
        console.print(f"    [bold {C_DIM}]{w}[/]")

    if critical_found:
        error("Pre-flight failed.")
        return False

    if backend_warnings and not auto_confirm:
        if not Confirm.ask(
                f"\n  [bold {C_WARN}]Minor issues above. Continue?[/]", default=True):
            return False

    try:
        Path("results").mkdir(exist_ok=True)
        t = Path("results/.write_test")
        t.write_text("test", encoding="utf-8")
        t.unlink()
    except Exception as e:
        error(f"Cannot write to results/: {e}")
        return False

    return True


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="GHOSTWIRE V7 Universal Autonomous Penetration Testing Engine")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--target", type=str)
    parser.add_argument(
        "--mode",
        type=str,
        choices=[
            "pentest",
            "redteam"],
        default="pentest")
    parser.add_argument("--ai", type=str)
    parser.add_argument("--destructive", action="store_true")
    parser.add_argument("--brute-force", action="store_true",
                        help="Headless: allow brute-force credential attempts (ROE).")
    parser.add_argument("--phishing", action="store_true",
                        help="Headless: allow social-engineering simulations (ROE).")
    parser.add_argument(
        "--stealth", action="store_true",
        help="Headless: route ALL traffic through Tor + WafGhost (much slower; "
             "off by default so runs aren't 5x slower unless you want max stealth).")
    parser.add_argument(
        "--allow-direct-on-tor-fail", action="store_true",
        help="With --stealth: if Tor can't be verified, run DIRECT (exposing your "
             "real IP) instead of fail-closed blocking. Off by default (fail-closed).")
    args = parser.parse_args()

    auto_confirm = args.yes or args.headless
    _agent_debug_log("main.py:init", "V7 startup", {"headless": args.headless})

    # ── BOOT ──
    banner()

    # ── LEGAL ──
    if not auto_confirm:
        print_legal()
        if REQUIRE_WRITTEN_CONSENT:
            if not Confirm.ask(
                    f"  [bold {C_ACCENT}]◣ SEC › Confirm WRITTEN authorization to test target?[/bold {C_ACCENT}]", default=False):
                error("Authorization check failed. Exiting.")
                sys.exit(1)
        if not Confirm.ask(
                f"  [bold {C_ACCENT}]◣ SEC › Confirm understanding of RESTRICTED testing?[/bold {C_ACCENT}]", default=False):
            error("Consent denied. Exiting.")
            sys.exit(1)
    else:
        info("Auto-confirm bypass: legal checks deactivated.")

    # ── PRE-FLIGHT ──
    section("Pre-Flight Diagnostics")
    pre_flight_ok = pre_flight_checks(auto_confirm=auto_confirm)
    if not pre_flight_ok:
        if not auto_confirm:
            if not Confirm.ask(
                    f"  [bold {C_DANGER}]⚠️ CRITICAL SYSTEMS FAILED. Force launch anyway?[/bold {C_DANGER}]", default=False):
                sys.exit(1)
        else:
            warning(
                "Auto-confirm: forcing launch despite critical diagnostic failures.")
    else:
        success("All systems operational. Pre-flight diagnostics NOMINAL.")

    # ── SETUP ──
    section("Configuration")
    if args.headless:
        if not args.target:
            error("--target required in headless mode.")
            sys.exit(1)
        try:
            target_ctx = TargetContext.from_input(args.target)
        except Exception as e:
            error(f"Invalid target: {e}")
            sys.exit(1)
        mode = args.mode
        ai_choice = args.ai or "ollama"
        scope = [args.target]
        roe = {"allow_exploitation": True,
               "allow_brute_force": bool(args.brute_force),
               "allow_phishing": bool(args.phishing),
               "allow_destructive": bool(args.destructive)}
        # Stealth/Tor is OPT-IN in headless. Routing every command through Tor
        # made runs ~5x slower (2.5h vs ~50min) and produced artifacts (e.g. 504
        # fake "open" ports from CONNECT-through-Tor). Default OFF; pass --stealth
        # only when you specifically want max-stealth and accept the slowdown.
        stealth = {
            "ghost_mode": bool(args.stealth),
            "rotate_ip": bool(args.stealth),
            "waf_defense": False,
            # Fail-closed by default: if Tor can't be verified, BLOCK leak-prone
            # tools rather than silently exposing the real IP (GAP-2). Opt out
            # explicitly with --allow-direct-on-tor-fail.
            "allow_direct_on_tor_fail": bool(
                getattr(args, "allow_direct_on_tor_fail", False)),
        }
        operator = "headless"
    else:
        mode = args.mode if args.mode != "pentest" else get_mode()
        ai_choice = args.ai if args.ai in [
            "ollama", "groq", "google"] else get_ai_choice()
        target_ctx = get_target()
        scope = get_scope(target_ctx)
        roe = get_roe(mode, auto_confirm=auto_confirm)
        if args.destructive:
            roe["allow_destructive"] = True
        stealth = get_stealth_config()
        operator = get_operator()

    # ── MISSION BRIEFING ──
    # GAP-1: Ghost Mode does HEADER/JA3 evasion only — it does NOT route traffic
    # through Tor or hide your IP. Only IP-rotation (rotate_ip) anonymizes. Warn
    # loudly so "Ghost Mode" isn't mistaken for full stealth.
    if stealth.get("ghost_mode") and not stealth.get("rotate_ip"):
        try:
            warning(
                "[STEALTH] Ghost Mode = WAF/header evasion only — it does NOT "
                "anonymize your IP. Your REAL IP is exposed to the target. Enable "
                "IP rotation (Tor) if you need anonymity.")
        except Exception:
            print("[STEALTH] WARNING: Ghost Mode does NOT hide your IP — enable "
                  "IP rotation (Tor) for anonymity.")

    stealth_list = []
    if stealth.get("ghost_mode"):
        stealth_list.append("WafGhost")
    if stealth.get("rotate_ip"):
        stealth_list.append("Tor-Rotate")
    if stealth.get("waf_defense"):
        stealth_list.append("WAF-Defense")

    osint_list = []
    if SHODAN_API_KEY:
        osint_list.append("Shodan")
    if SECURITYTRAILS_API_KEY:
        osint_list.append("SecTrails")
    if VIRUSTOTAL_API_KEY:
        osint_list.append("VirusTotal")

    mission_briefing({
        "mode": mode, "ai": ai_choice,
        "target": target_ctx.full_url,
        "host": target_ctx.host, "port": target_ctx.port,
        "path": target_ctx.path,
        "scope": ", ".join(scope),
        "execution": f"WSL Local Linux ({WSL_DISTRO or 'Ubuntu'})" if USE_WSL else "Local Windows Machine",
        "operator": operator,
        "stealth_list": stealth_list,
        "osint_list": osint_list,
        "roe": roe,
    })

    if not auto_confirm:
        if not Confirm.ask(
                f"  [bold {C_ACCENT}]◣ HUD › Launch tactical engagement sequence?[/bold {C_ACCENT}]", default=False):
            info("Engagement sequence aborted by operator.")
            sys.exit(0)

    # ── SESSION ──
    session = EngagementSession(
        mode=mode, target_context=target_ctx, scope_strs=scope,
        rules_of_engagement=roe, operator=operator, ai_backend=ai_choice,
        stealth_config=stealth, guardian_enabled=True,
        destructive_mode=roe.get("allow_destructive", False),
    )

    success(f"Session established: {session.engagement_id}")
    success(f"Workspace path: {session.results_dir}")

    orchestrator = Orchestrator(session)
    try:
        import asyncio
        asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        warning("Interrupted by user.")
        session.shutdown.set()
        try:
            orchestrator.store.close()
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in main.py: {_e}')
        import os
        os._exit(0)
    except Exception as e:
        error(f"Fatal: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    if sys.platform != "win32":
        import signal
        def sigterm_handler(signum, frame):
            print("\n  [!] SIGTERM received. Gracefully shutting down.")
            sys.exit(0)
        signal.signal(signal.SIGTERM, sigterm_handler)

    try:
        main()
    except KeyboardInterrupt:
        print("\n  [!] Interrupted. Exiting.")
        import os
        os._exit(0)
