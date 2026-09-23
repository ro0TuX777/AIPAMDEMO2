"""
Redis pub/sub event bus for real-time pipeline progress.

The orchestrator (Celery worker) publishes events to a per-job Redis channel.
The SSE endpoint (web process) subscribes to that channel and forwards
events to the browser via Server-Sent Events.

Channel naming: ``aipam:job:{job_id}:events``
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("aipam.events")

# ---------------------------------------------------------------------------
# Channel helpers
# ---------------------------------------------------------------------------

def _channel(job_id: str) -> str:
    return f"aipam:job:{job_id}:events"


# ---------------------------------------------------------------------------
# Monotonic event counter (per-worker, good enough for SSE id)
# ---------------------------------------------------------------------------

_event_counter: int = 0


def _next_id() -> int:
    global _event_counter
    _event_counter += 1
    return _event_counter


# ---------------------------------------------------------------------------
# Redis client (lazy singleton)
# ---------------------------------------------------------------------------

_redis_client = None


def _get_redis():
    """Return a shared Redis client, creating it on first call.

    Falls back gracefully if Redis is unavailable — events are best-effort.
    """
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        import redis as _redis_mod
        url = os.getenv("AIPAM_REDIS_URL", "redis://redis:6379/0")
        _redis_client = _redis_mod.Redis.from_url(url, decode_responses=True, socket_connect_timeout=.5, socket_timeout=.5, retry_on_timeout=False)
        _redis_client.ping()
        logger.info("Event bus connected")
    except Exception as exc:
        logger.warning("Event bus unavailable; events disabled")
        _redis_client = None
    return _redis_client


# ---------------------------------------------------------------------------
# Publish (called from Celery worker / orchestrator)
# ---------------------------------------------------------------------------

def publish_job_event(
    job_id: str,
    event_type: str,
    data: dict[str, Any],
) -> None:
    """Publish an SSE-envelope event to the job's Redis channel.

    Args:
        job_id: The job this event belongs to.
        event_type: One of the SseEventType values (e.g. ``sensor.status``).
        data: The event payload dict.
    """
    r = _get_redis()
    if r is None:
        return  # Redis unavailable — silently skip
    envelope = {
        "id": _next_id(),
        "type": event_type,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "data": data,
    }
    try:
        r.publish(_channel(job_id), json.dumps(envelope))
    except Exception as exc:
        logger.debug("Event publish failed for job %s", job_id)


# ---------------------------------------------------------------------------
# Subscribe (called from web process SSE generator)
# ---------------------------------------------------------------------------

def subscribe_job_events(job_id: str):
    """Return a Redis PubSub object subscribed to the job's event channel.

    Returns None if Redis is unavailable.
    """
    r = _get_redis()
    if r is None:
        return None
    try:
        ps = r.pubsub(ignore_subscribe_messages=True)
        ps.subscribe(_channel(job_id))
        return ps
    except Exception as exc:
        logger.debug("Event subscribe failed for job %s", job_id)
        return None

