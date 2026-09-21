"""Logging + shared Rich console."""
from __future__ import annotations

import logging
from pathlib import Path

from rich.console import Console
from rich.theme import Theme

# WIRESHADOW theme: violet accent, ghost-grey dim, traffic-light risks.
WIRE_THEME = Theme({
    "accent": "bold magenta",
    "ghost": "dim",
    "ok": "bold green",
    "warn": "bold yellow",
    "bad": "bold red",
    "wire": "cyan",
})

_console = Console(theme=WIRE_THEME)
_logger: logging.Logger | None = None


def get_console() -> Console:
    return _console


def setup_logger(log_file: str = "scan_audit.log", level: int = logging.INFO) -> logging.Logger:
    global _logger
    if _logger is not None:
        return _logger
    logger = logging.getLogger("ai-network-scanner")
    logger.setLevel(level)
    if not logger.handlers:
        fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        fh = logging.FileHandler(Path(log_file))
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        # NOTE: no StreamHandler — audit goes to file only so Rich UI stays clean.
        # Use console.print() for anything the user should see.
    _logger = logger
    return logger


def get_logger() -> logging.Logger:
    if _logger is None:
        return setup_logger()
    return _logger
