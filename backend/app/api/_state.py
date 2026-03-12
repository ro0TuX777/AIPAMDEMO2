"""Shared process-level state (uptime counter, lightweight in-process stats, etc.)."""

import threading
import time

_START_TIME = time.time()
_EXPLAIN_RESPONSE_COUNTS = {
    "deterministic": 0,
    "llm": 0,
    "fallback": 0,
}
_EXPLAIN_LATENCY_MS = {
    "count": 0,
    "total_ms": 0,
    "min_ms": 0,
    "max_ms": 0,
    "last_ms": 0,
}
_EXPLAIN_LLM_GATE = threading.Condition()
_EXPLAIN_LLM_IN_FLIGHT = 0
_EXPLAIN_LLM_WAITERS = 0


def get_uptime_seconds() -> int:
    """Seconds since the process started."""
    return int(time.time() - _START_TIME)


def increment_explain_response_count(source: str, duration_ms: int | None = None) -> None:
    """Increment explain-response counters and latency summary for a known source."""
    if source in _EXPLAIN_RESPONSE_COUNTS:
        _EXPLAIN_RESPONSE_COUNTS[source] += 1

    if duration_ms is None:
        return

    duration_ms = max(0, duration_ms)
    if _EXPLAIN_LATENCY_MS["count"] == 0:
        _EXPLAIN_LATENCY_MS["min_ms"] = duration_ms
        _EXPLAIN_LATENCY_MS["max_ms"] = duration_ms
    else:
        _EXPLAIN_LATENCY_MS["min_ms"] = min(_EXPLAIN_LATENCY_MS["min_ms"], duration_ms)
        _EXPLAIN_LATENCY_MS["max_ms"] = max(_EXPLAIN_LATENCY_MS["max_ms"], duration_ms)

    _EXPLAIN_LATENCY_MS["count"] += 1
    _EXPLAIN_LATENCY_MS["total_ms"] += duration_ms
    _EXPLAIN_LATENCY_MS["last_ms"] = duration_ms


def get_explain_response_counts() -> dict[str, int]:
    """Snapshot explain-response counters."""
    return dict(_EXPLAIN_RESPONSE_COUNTS)


def get_explain_latency_ms() -> dict[str, int]:
    """Snapshot explain-response latency summary."""
    count = _EXPLAIN_LATENCY_MS["count"]
    average_ms = round(_EXPLAIN_LATENCY_MS["total_ms"] / count) if count else 0
    return {
        "count": count,
        "average_ms": average_ms,
        "min_ms": _EXPLAIN_LATENCY_MS["min_ms"] if count else 0,
        "max_ms": _EXPLAIN_LATENCY_MS["max_ms"] if count else 0,
        "last_ms": _EXPLAIN_LATENCY_MS["last_ms"] if count else 0,
    }


def try_acquire_explain_llm_slot(wait_timeout_seconds: float = 1.0, max_waiters: int = 1) -> str:
    """Serialize LLM explain calls with a tiny bounded queue.

    Returns one of:
      - ``"acquired"`` when the caller may proceed immediately
      - ``"busy"`` when the caller briefly waited but should retry later
      - ``"queue_full"`` when the bounded wait queue is already full
    """
    global _EXPLAIN_LLM_IN_FLIGHT, _EXPLAIN_LLM_WAITERS

    deadline = time.monotonic() + max(0.0, wait_timeout_seconds)
    with _EXPLAIN_LLM_GATE:
        if _EXPLAIN_LLM_IN_FLIGHT == 0:
            _EXPLAIN_LLM_IN_FLIGHT = 1
            return "acquired"

        if _EXPLAIN_LLM_WAITERS >= max_waiters:
            return "queue_full"

        _EXPLAIN_LLM_WAITERS += 1
        try:
            while _EXPLAIN_LLM_IN_FLIGHT > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return "busy"
                _EXPLAIN_LLM_GATE.wait(timeout=remaining)

            _EXPLAIN_LLM_IN_FLIGHT = 1
            return "acquired"
        finally:
            _EXPLAIN_LLM_WAITERS -= 1


def release_explain_llm_slot() -> None:
    """Release the active LLM explain slot and wake one waiter."""
    global _EXPLAIN_LLM_IN_FLIGHT

    with _EXPLAIN_LLM_GATE:
        if _EXPLAIN_LLM_IN_FLIGHT > 0:
            _EXPLAIN_LLM_IN_FLIGHT -= 1
        _EXPLAIN_LLM_GATE.notify(1)


def reset_explain_response_counts() -> None:
    """Reset explain-response counters, latency summary, and busy gate for tests."""
    global _EXPLAIN_LLM_IN_FLIGHT, _EXPLAIN_LLM_WAITERS

    for key in _EXPLAIN_RESPONSE_COUNTS:
        _EXPLAIN_RESPONSE_COUNTS[key] = 0
    for key in _EXPLAIN_LATENCY_MS:
        _EXPLAIN_LATENCY_MS[key] = 0
    with _EXPLAIN_LLM_GATE:
        _EXPLAIN_LLM_IN_FLIGHT = 0
        _EXPLAIN_LLM_WAITERS = 0
        _EXPLAIN_LLM_GATE.notify_all()

