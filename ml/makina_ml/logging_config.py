"""Structured JSON logging with request_id propagation.

The Rust core emits `x-request-id` on every call; a FastAPI middleware
binds it to a contextvar so every log record picks it up via a filter.
"""

from __future__ import annotations

import contextvars
import logging
import os
import sys

from pythonjsonlogger import jsonlogger

_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default="-"
)


def get_request_id() -> str:
    return _request_id_ctx.get()


def set_request_id(value: str) -> contextvars.Token:
    return _request_id_ctx.set(value)


def reset_request_id(token: contextvars.Token) -> None:
    _request_id_ctx.reset(token)


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id_ctx.get()
        return True


def setup_logging() -> None:
    level = os.environ.get("MAKINA_LOG_LEVEL", "INFO").upper()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        jsonlogger.JsonFormatter(
            "%(asctime)s %(levelname)s %(name)s %(request_id)s %(message)s",
            rename_fields={
                "asctime": "ts",
                "levelname": "level",
                "name": "logger",
            },
        )
    )
    handler.addFilter(_RequestIdFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers = [handler]
        lg.propagate = False
        lg.setLevel(level)
