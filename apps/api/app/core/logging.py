"""Structured logging setup with automated sensitive field redaction."""

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

# Context variable for correlating log entries with active HTTP request ID
correlation_id_ctx: ContextVar[str] = ContextVar("correlation_id_ctx", default="")

REDACTION_PATTERNS = [
    (
        re.compile(
            r"(?i)(password|passwd|secret|api[_-]?key|token|authorization)\s*[:=]\s*['\"]?([^'\"&\s,]+)"
        ),
        r"\1=[REDACTED]",
    ),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]+"), r"\1[REDACTED]"),
]


def redact_sensitive_string(text: str) -> str:
    """Mask sensitive credentials and tokens within a string."""
    result = text
    for pattern, replacement in REDACTION_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


class RedactingJsonFormatter(logging.Formatter):
    """JSON log formatter that redacts secrets and embeds correlation IDs."""

    def format(self, record: logging.LogRecord) -> str:
        req_id = correlation_id_ctx.get()
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_sensitive_string(record.getMessage()),
            "request_id": req_id or None,
            "source": f"{record.filename}:{record.lineno}",
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class StandardRedactingFormatter(logging.Formatter):
    """Human-readable console log formatter with redaction."""

    def format(self, record: logging.LogRecord) -> str:
        original_msg = record.getMessage()
        record.msg = redact_sensitive_string(original_msg)
        req_id = correlation_id_ctx.get()
        prefix = f"[{req_id}] " if req_id else ""
        formatted = super().format(record)
        return f"{prefix}{formatted}"


def setup_logging(log_level: str = "INFO", json_format: bool = False) -> None:
    """Initialize root and application loggers."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Clear existing handlers
    root_logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    if json_format:
        handler.setFormatter(RedactingJsonFormatter())
    else:
        handler.setFormatter(
            StandardRedactingFormatter(
                fmt="%(asctime)s | %(levelname)-7s | %(name)s:%(lineno)d | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )

    root_logger.addHandler(handler)

    # Silence noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


logger = logging.getLogger("cyberduel")
