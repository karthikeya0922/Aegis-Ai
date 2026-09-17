"""Redacting logger.

Aegis exists to stop credentials reaching places they should not. It would be
a self-defeating bug for Aegis itself to write one to stdout. Every log record
passes through RedactingFilter before it is emitted.

Phase 16 adds a test that captures log output and greps it for known secrets.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

# Patterns scrubbed from *all* log output regardless of source. This is a
# backstop, not the primary control -- the primary control is simply never
# passing sensitive values to the logger.
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "[REDACTED_GITHUB_PAT]"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     "[REDACTED_JWT]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     "[REDACTED_PRIVATE_KEY]"),
    # Credentials embedded in a URI: scheme://user:password@host
    (re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.\-]*://)([^:/\s]+):([^@/\s]+)@"),
     r"\1\2:[REDACTED_PASSWORD]@"),
    (re.compile(r"(?i)\b(authorization|api[_\-]?key|password|secret|token)"
                r"(\"?\s*[:=]\s*\"?)([^\s\",;}]+)"),
     r"\1\2[REDACTED]"),
]

_HEADER_DENYLIST = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "cookie",
    "set-cookie",
}


def scrub(text: str) -> str:
    """Apply every redaction pattern to a string."""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def safe_headers(headers: dict[str, Any]) -> dict[str, Any]:
    """Drop credential-bearing headers before they can be logged."""
    return {
        k: ("[REDACTED]" if k.lower() in _HEADER_DENYLIST else v)
        for k, v in headers.items()
    }


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = scrub(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {
                        k: scrub(v) if isinstance(v, str) else v
                        for k, v in record.args.items()
                    }
                elif isinstance(record.args, tuple):
                    record.args = tuple(
                        scrub(a) if isinstance(a, str) else a for a in record.args
                    )
        except Exception:  # noqa: BLE001 - logging must never raise
            return True
        return True


class RequestIdFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, "request_id"):
            record.request_id = "-"
        return super().format(record)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        RequestIdFormatter(
            fmt="%(asctime)s %(levelname)-7s [%(request_id)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    handler.addFilter(RedactingFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Uvicorn's own loggers must inherit the redacting handler too.
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
