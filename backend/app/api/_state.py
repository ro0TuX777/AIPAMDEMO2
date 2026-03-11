"""Shared process-level state (uptime counter, etc.)."""

import time

_START_TIME = time.time()


def get_uptime_seconds() -> int:
    """Seconds since the process started."""
    return int(time.time() - _START_TIME)

