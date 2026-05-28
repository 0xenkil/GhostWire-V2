import logging
import sys
import os
from pathlib import Path

# ── Force UTF-8 on Windows BEFORE any Rich import ───────────────────────────
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        os.environ["PYTHONIOENCODING"] = "utf-8"
    except Exception:
        pass

try:
    from rich.console import Console as RichConsole
    from rich.logging import RichHandler
    # Single shared console for the entire logger subsystem — force_terminal
    # bypasses the legacy Windows renderer that chokes on Unicode.
    _LOG_CONSOLE = RichConsole(force_terminal=True, stderr=True)
    _RICH_OK = True
except ImportError:
    _RICH_OK = False
    _LOG_CONSOLE = None
    class RichHandler: pass

_loggers = {}
_log_dir: Path = None


def configure_log_dir(log_dir: Path):
    """Sets the global log directory and attaches file handlers to existing loggers."""
    global _log_dir
    _log_dir = log_dir
    _log_dir.mkdir(parents=True, exist_ok=True)
    for name, logger in _loggers.items():
        _attach_file_handler(logger, name, _log_dir)


def _attach_file_handler(logger: logging.Logger, name: str, log_dir: Path):
    if not log_dir:
        return
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        fh = logging.FileHandler(log_dir / f"{name}.log", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception as e:
        print(f"Warning: Failed to attach file handler for {name}: {e}", file=sys.stderr)


class RedTeamHandler(RichHandler):
    """Custom handler with HUD brackets-themed level prefixes."""
    def get_level_text(self, record: logging.LogRecord) -> str:
        level_map = {
            logging.DEBUG:    "[bold dim][ SYS.DBG  ][/bold dim]",
            logging.INFO:     "[bold #475266][ SYS.INFO ][/bold #475266]",
            logging.WARNING:  "[bold #ffaa00][ SYS.WARN ][/bold #ffaa00]",
            logging.ERROR:    "[bold #ff0055][ SYS.FAIL ][/bold #ff0055]",
            logging.CRITICAL: "[bold white on #ff0055][ SYS.CRIT ][/bold white on #ff0055]",
        }
        msg = record.getMessage()
        if isinstance(msg, str) and "[SUCCESS]" in msg:
            return "[bold #00ff66][  SYS.OK  ][/bold #00ff66]"
        return level_map.get(record.levelno, record.levelname)


def get_logger(name: str, log_dir: Path = None) -> logging.Logger:
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Console handler — use the shared force_terminal console
    if _RICH_OK and _LOG_CONSOLE:
        try:
            ch = RedTeamHandler(
                console=_LOG_CONSOLE,
                rich_tracebacks=True,
                markup=True,
                show_path=False,
                show_time=False,
                show_level=True,
            )
        except Exception:
            ch = logging.StreamHandler(sys.stdout)
    else:
        ch = logging.StreamHandler(sys.stdout)

    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

    # File handler
    actual_dir = log_dir or _log_dir
    if actual_dir:
        _attach_file_handler(logger, name, actual_dir)

    _loggers[name] = logger
    return logger
