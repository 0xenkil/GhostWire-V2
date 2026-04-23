import logging
import sys
from pathlib import Path
try:
    from rich.logging import RichHandler
except ImportError:
    # Fallback if rich is not installed
    class RichHandler: pass

_loggers = {}
_log_dir: Path = None

def configure_log_dir(log_dir: Path):
    """Sets the global log directory and attaches file handlers to existing loggers."""
    global _log_dir
    _log_dir = log_dir
    _log_dir.mkdir(parents=True, exist_ok=True)
    
    # Attach file handlers to all existing loggers
    for name, logger in _loggers.items():
        _attach_file_handler(logger, name, _log_dir)

def _attach_file_handler(logger: logging.Logger, name: str, log_dir: Path):
    """Attaches a DEBUG-level file handler to a logger with UTF-8 support."""
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    # Force UTF-8 encoding for file logs
    fh = logging.FileHandler(log_dir / f"{name}.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

class RedTeamHandler(RichHandler):
    """Custom handler that replaces 'INFO/WARNING' with red-team prefixes."""
    def get_level_text(self, record: logging.LogRecord) -> str:
        level_map = {
            logging.DEBUG: "[bold dim]DEBUG[/bold dim]",
            logging.INFO: "[bold blue][*][/bold blue]",
            logging.WARNING: "[bold yellow][!][/bold yellow]",
            logging.ERROR: "[bold red][-][/bold red]",
            logging.CRITICAL: "[bold red][CRITICAL][/bold red]",
        }
        # Success injection: if msg starts with [SUCCESS], use [+]
        msg = record.getMessage()
        if "[SUCCESS]" in msg:
            record.msg = msg.replace("[SUCCESS] ", "")
            return "[bold green][+][/bold green]"
            
        return level_map.get(record.levelno, record.levelname)

def get_logger(name: str, log_dir: Path = None) -> logging.Logger:
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Console handler (The Unified UI)
    try:
        ch = RedTeamHandler(
            rich_tracebacks=True, 
            markup=True, 
            show_path=False, 
            show_time=False, 
            show_level=True  # Required for custom prefixes
        )
    except Exception:
        ch = logging.StreamHandler(sys.stdout)
    
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

    # Attach file handler
    actual_dir = log_dir or _log_dir
    if actual_dir:
        _attach_file_handler(logger, name, actual_dir)

    _loggers[name] = logger
    return logger
