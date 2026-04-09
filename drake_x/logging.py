"""Lightweight structured logging setup.

We keep things deliberately simple: a single root logger named ``drake_x`` with
either a human-readable format (default) or a flat JSON-style format when
``DRAKE_X_LOG_JSON`` is set. We avoid third-party dependencies here.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

LOGGER_NAME = "drake_x"


class _JsonFormatter(logging.Formatter):
    """Tiny JSON formatter — one log record per line, no nested context."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(verbose: bool = False) -> logging.Logger:
    """Configure and return the Drake-X logger.

    Idempotent: calling this twice will not duplicate handlers.
    """

    logger = logging.getLogger(LOGGER_NAME)
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    # Avoid duplicate handlers if configure_logging is called multiple times.
    if logger.handlers:
        for h in logger.handlers:
            h.setLevel(level)
        return logger

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)

    if os.environ.get("DRAKE_X_LOG_JSON"):
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
                datefmt="%H:%M:%S",
            )
        )

    logger.addHandler(handler)
    logger.propagate = False
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger of the Drake-X root logger."""
    if name is None:
        return logging.getLogger(LOGGER_NAME)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")
