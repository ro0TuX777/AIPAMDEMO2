from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def _parse_iso_timestamp(value: str):
    """Parse an ISO8601 timestamp (optionally with trailing 'Z') into UTC.

    Returns None on failure instead of raising.
    """
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def _split_baseline_exploit(
    mode: str,
    metadata: Dict[str, Any],
    flows: List[Any],
    alerts: List[Any],
):
    """Split flows/alerts into baseline vs exploit sets and derive time ranges.

    For mode == "baseline_vs_exploit" and when metadata provides
    `baseline_time_range` and `exploit_time_range`, we use those windows
    to assign records. Otherwise we fall back to a single-window view
    where everything is treated as exploit-only and baseline is empty.

    Returns (baseline_flows, exploit_flows, baseline_alerts, exploit_alerts, time_ranges_info)
    where time_ranges_info is a dict mapping keys ("baseline","exploit" or
    "window") to (start_datetime, end_datetime) tuples.
    """

    baseline_flows: List[Any] = []
    exploit_flows: List[Any] = list(flows)
    baseline_alerts: List[Any] = []
    exploit_alerts: List[Any] = list(alerts)
    time_ranges: Dict[str, Any] = {}

    if not flows and not alerts:
        return baseline_flows, exploit_flows, baseline_alerts, exploit_alerts, time_ranges

    if mode == "baseline_vs_exploit":
        btr = metadata.get("baseline_time_range")
        etr = metadata.get("exploit_time_range")

        def parse_range(raw):
            if not isinstance(raw, dict):
                return None
            start_raw = raw.get("start")
            end_raw = raw.get("end")
            if not isinstance(start_raw, str) or not isinstance(end_raw, str):
                return None
            start_dt = _parse_iso_timestamp(start_raw)
            end_dt = _parse_iso_timestamp(end_raw)
            if start_dt is None or end_dt is None:
                return None
            return (start_dt, end_dt)

        b_range = parse_range(btr)
        e_range = parse_range(etr)

        if b_range and e_range:
            b_start, b_end = b_range
            e_start, e_end = e_range

            baseline_flows = []
            exploit_flows = []
            baseline_alerts = []
            exploit_alerts = []

            for f in flows:
                ts = getattr(f, "start_time", None)
                if ts is None:
                    continue
                if b_start <= ts <= b_end:
                    baseline_flows.append(f)
                if e_start <= ts <= e_end:
                    exploit_flows.append(f)

            for a in alerts:
                ts = getattr(a, "timestamp", None)
                if ts is None:
                    continue
                if b_start <= ts <= b_end:
                    baseline_alerts.append(a)
                if e_start <= ts <= e_end:
                    exploit_alerts.append(a)

            time_ranges["baseline"] = b_range
            time_ranges["exploit"] = e_range

            return baseline_flows, exploit_flows, baseline_alerts, exploit_alerts, time_ranges

    # Fallback: treat everything as a single window (exploit-only)
    exploit_flows = list(flows)
    exploit_alerts = list(alerts)

    timestamps = []
    for f in exploit_flows:
        ts = getattr(f, "start_time", None)
        if ts is not None:
            timestamps.append(ts)
    for a in exploit_alerts:
        ts = getattr(a, "timestamp", None)
        if ts is not None:
            timestamps.append(ts)

    if timestamps:
        start_dt = min(timestamps)
        end_dt = max(timestamps)
        time_ranges["window"] = (start_dt, end_dt)

    return baseline_flows, exploit_flows, baseline_alerts, exploit_alerts, time_ranges

