from __future__ import annotations

import json
import logging
import os
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Optional

_JOB_ID: ContextVar[Optional[str]] = ContextVar("job_id", default=None)
_STEP: ContextVar[Optional[str]] = ContextVar("step", default=None)
_COMPONENT: ContextVar[Optional[str]] = ContextVar("component", default=None)


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "line": record.lineno,
            "msg": record.getMessage(),
            "job_id": getattr(record, "job_id", _JOB_ID.get()),
            "step": getattr(record, "step", _STEP.get()),
            "component": getattr(record, "component", _COMPONENT.get()),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class _ContextAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra = kwargs.get("extra", {})
        extra.setdefault("job_id", _JOB_ID.get())
        extra.setdefault("step", _STEP.get())
        extra.setdefault("component", _COMPONENT.get())
        kwargs["extra"] = extra
        return msg, kwargs


def _resolve_level() -> int:
    value = (os.getenv("LOG_LEVEL") or "INFO").upper()
    return getattr(logging, value, logging.INFO)


def set_log_context(job_id: Optional[str] = None, step: Optional[str] = None) -> None:
    if job_id is not None:
        _JOB_ID.set(job_id)
    if step is not None:
        _STEP.set(step)


def get_logger(name: str) -> logging.LoggerAdapter:
    return _ContextAdapter(logging.getLogger(name), {})


def configure_logging(component: Optional[str] = None) -> None:
    """Configure root logging once.

    LOG_LEVEL controls verbosity. Example: DEBUG, INFO, WARNING, ERROR.
    """
    level = _resolve_level()
    if component:
        _COMPONENT.set(component)

    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonFormatter())
        root.addHandler(handler)
        root.setLevel(level)
    else:
        root.setLevel(level)
