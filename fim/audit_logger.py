"""
Centralized audit logging and SIEM event emitter.
Produces both human-readable text logs and structured JSON Lines (JSONL)
records compliant with SOC enterprise logging standards.
"""

from __future__ import annotations

import datetime
import json
import logging
import platform
import socket
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Union

# ANSI terminal escape sequences for visual SOC status alerting
class TerminalColors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def supports_color() -> bool:
    """Determine if running environment supports ANSI color codes."""
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    # Windows Terminal, Linux terminal, macOS terminal support ANSI
    if platform.system() == "Windows":
        return "WT_SESSION" in sys.platform or "TERM" in sys.platform or True
    return True


class AuditLogger:
    """
    Manages dual-channel logging:
    1. Standard rotational/append text log for Linux administrators.
    2. High-fidelity JSONL event streams for SIEM ingestion.
    """

    def __init__(
        self,
        log_file: Union[str, Path] = "logs/fim_audit.log",
        events_jsonl: Optional[Union[str, Path]] = "logs/fim_events.jsonl",
        console_level: int = logging.INFO,
    ):
        self.log_file = Path(log_file)
        self.events_jsonl = Path(events_jsonl) if events_jsonl else None
        self.hostname = socket.gethostname()
        self.use_color = supports_color()

        # Ensure target logging directories exist
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        if self.events_jsonl:
            self.events_jsonl.parent.mkdir(parents=True, exist_ok=True)

        self._init_standard_logger(console_level)

    def _init_standard_logger(self, console_level: int) -> None:
        """Configure standard Python logger writing to disk and terminal."""
        self.logger = logging.getLogger("FIM_Audit")
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()

        # File Handler (append mode, detailed timestamp)
        file_handler = logging.FileHandler(self.log_file, mode="a", encoding="utf-8")
        file_format = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)-8s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_format)
        file_handler.setLevel(logging.DEBUG)
        self.logger.addHandler(file_handler)

        # Console Handler (clean user-facing stream)
        console_handler = logging.StreamHandler(sys.stdout)
        console_format = logging.Formatter("%(message)s")
        console_handler.setFormatter(console_format)
        console_handler.setLevel(console_level)
        self.logger.addHandler(console_handler)

    def _emit_jsonl_event(self, event_record: Dict[str, Any]) -> None:
        """Append a structured JSON object to the events JSONL stream."""
        if not self.events_jsonl:
            return

        try:
            with self.events_jsonl.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event_record) + "\n")
        except OSError as err:
            self.logger.error(f"Failed to write to JSONL audit file: {err}")

    def log_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        file_path: Optional[str] = None,
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record a unified security audit event across text and JSONL logs.

        Args:
            event_type: Category (e.g. 'BASELINE_CREATED', 'FILE_MODIFIED', 'INTEGRITY_VIOLATION')
            severity: 'INFO', 'WARNING', 'CRITICAL', 'ERROR'
            message: Descriptive human-readable summary
            file_path: Associated file system path if applicable
            extra_data: Additional context dictionary (hashes, sizes, deltas)
        """
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        now_iso = now_dt.isoformat()

        # Build structured JSON payload
        event_payload = {
            "event_id": str(uuid.uuid4()),
            "timestamp": now_iso,
            "host": self.hostname,
            "event_type": event_type,
            "severity": severity,
            "file_path": file_path,
            "message": message,
            "data": extra_data or {},
        }
        self._emit_jsonl_event(event_payload)

        # Format console & text log output
        log_msg = f"[{event_type}] {message}"
        if file_path:
            log_msg += f" -> (Path: {file_path})"

        if severity == "CRITICAL":
            self.logger.critical(self._colorize(log_msg, TerminalColors.RED, bold=True))
        elif severity == "WARNING" or severity == "HIGH":
            self.logger.warning(self._colorize(log_msg, TerminalColors.YELLOW))
        elif severity == "ERROR":
            self.logger.error(self._colorize(log_msg, TerminalColors.RED))
        else:
            self.logger.info(self._colorize(log_msg, TerminalColors.GREEN if "CLEAN" in event_type else None))

    def _colorize(self, text: str, color: str, bold: bool = False) -> str:
        """Apply ANSI color codes if enabled."""
        if not self.use_color or not color:
            return text
        prefix = TerminalColors.BOLD + color if bold else color
        return f"{prefix}{text}{TerminalColors.RESET}"

    # Convenience helper methods
    def info(self, msg: str) -> None:
        self.log_event("INFO", "INFO", msg)

    def warning(self, msg: str, file_path: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> None:
        self.log_event("SECURITY_WARNING", "WARNING", msg, file_path=file_path, extra_data=extra)

    def critical(self, msg: str, file_path: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> None:
        self.log_event("INTEGRITY_VIOLATION", "CRITICAL", msg, file_path=file_path, extra_data=extra)

    def error(self, msg: str, file_path: Optional[str] = None) -> None:
        self.log_event("SYSTEM_ERROR", "ERROR", msg, file_path=file_path)
