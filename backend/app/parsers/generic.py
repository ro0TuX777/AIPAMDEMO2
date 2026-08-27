"""Generic fallback log parser.

Handles unstructured text logs and arbitrary JSON/JSONL files by extracting:
  - Timestamps (ISO-8601, syslog-style)
  - IP addresses (v4)
  - Hostnames, usernames, ports from common patterns
  - Key-value pairs from JSON objects

This parser is registered LAST in the registry so it only activates
when no specialised parser claims the file.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from backend.app.parsers.base import BaseParser, ParserResult
from backend.app.schemas.common import NormalizedEventType, SourceType

logger = logging.getLogger("aipam.parsers.generic")

# ── Regex patterns ──────────────────────────────────────────────────────────

# IPv4 address (avoid matching version numbers like 1.0.0)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# ISO-8601 timestamp: 2026-03-19T17:58:27Z or 2026-03-19 17:58:27.992323Z
_RE_ISO_TS = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

# Syslog-style: Mar 19 17:58:27
_RE_SYSLOG_TS = re.compile(
    r"(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})"
)

# Port numbers in context (e.g., ":443", "port 22")
_RE_PORT = re.compile(r"(?::|\bport\s+)(\d{1,5})\b", re.IGNORECASE)

# Username patterns
_RE_USER = re.compile(
    r"(?:user(?:name)?|login|account|FULL_USERNAME)[=:\s]+[\"']?(\w[\w.@-]{1,63})[\"']?",
    re.IGNORECASE,
)

# Version-like strings to exclude from IP extraction (e.g., 1.14.2, 4.0.0)
_RE_VERSION = re.compile(r"\b\d+\.\d+\.\d+\b")

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
_CURRENT_YEAR = datetime.now(timezone.utc).year

# Skip lines that are mostly non-text (ASCII art, banners)
_MIN_ALPHA_RATIO = 0.15

# Max events per file to avoid flooding. Raised from 5 000 because a router or
# firewall syslog worth correlating routinely runs to hundreds of thousands of
# lines, and truncating at 5 000 silently discarded most of the window an
# analyst uploaded the file to cover. Truncation is now logged, not silent.
_MAX_EVENTS_PER_FILE = 500_000


def _warn_truncated(path: Path, kept: int, total: int | None = None) -> None:
    """Record that a log file was cut short, so it never happens silently."""
    suffix = f" of {total}" if total is not None else ""
    logger.warning(
        "Truncated %s at %d events%s — file exceeds the per-file parse limit; "
        "correlation will only see the first %d events",
        path.name, kept, suffix, kept,
    )


def _is_version_string(ip: str) -> bool:
    """Heuristic: if the IP looks like a semver (x.y.z with z < 100), skip it."""
    parts = ip.split(".")
    if len(parts) == 4:
        try:
            octets = [int(p) for p in parts]
            # Valid IP range check
            return all(0 <= o <= 255 for o in octets) is False
        except ValueError:
            return True
    return False


def _extract_ips(text: str) -> list[str]:
    """Extract unique IPv4 addresses, filtering out version strings."""
    candidates = _RE_IPV4.findall(text)
    # Filter: remove IPs that appear adjacent to known version-string patterns
    ips = []
    for ip in candidates:
        if ip.startswith("0.") or ip.startswith("255."):
            continue
        parts = ip.split(".")
        # Skip obvious version numbers (e.g., 1.0.0.0 → unlikely to be real)
        if parts[0] == "0":
            continue
        ips.append(ip)
    return list(dict.fromkeys(ips))  # dedupe preserving order



def _parse_timestamp(text: str) -> datetime:
    """Try to extract a timestamp from text, fall back to now()."""
    m = _RE_ISO_TS.search(text)
    if m:
        raw = m.group(1)
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    m = _RE_SYSLOG_TS.search(text)
    if m:
        month = _MONTHS.get(m.group(1), 1)
        day = int(m.group(2))
        h, mi, s = (int(x) for x in m.group(3).split(":"))
        return datetime(_CURRENT_YEAR, month, day, h, mi, s, tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def _extract_username(text: str) -> str | None:
    m = _RE_USER.search(text)
    return m.group(1) if m else None


def _extract_port(text: str) -> int | None:
    m = _RE_PORT.search(text)
    if m:
        p = int(m.group(1))
        return p if 1 <= p <= 65535 else None
    return None


# ── Parser class ────────────────────────────────────────────────────────────


class GenericLogParser(BaseParser):
    """Fallback parser for unstructured text and arbitrary JSON logs."""

    @property
    def name(self) -> str:
        return "generic"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_source_systems(self) -> list[str]:
        return ["generic"]

    def can_parse(self, path: Path, hint: str | None = None) -> bool:
        """Accept any text-readable file — this is the last-resort parser."""
        if hint == "generic":
            return True
        ext = path.suffix.lower()
        return ext in {".log", ".json", ".jsonl", ".csv", ".txt", ".evtx"}

    def parse(
        self,
        path: Path,
        job_id: str,
        source_type: SourceType = SourceType.log_bundle,
        exercise_id: str | None = None,
    ) -> Iterator[ParserResult]:
        ext = path.suffix.lower()
        if ext in (".json", ".jsonl"):
            yield from self._parse_json(path, source_type, exercise_id)
        else:
            yield from self._parse_text(path, source_type, exercise_id)

    # ── JSON parsing ──────────────────────────────────────────────────────

    def _parse_json(
        self, path: Path, source_type: SourceType, exercise_id: str | None,
    ) -> Iterator[ParserResult]:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.error("Failed to read %s: %s", path, exc)
            return

        # Try as single JSON object/array
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Fall back to JSONL (one object per line)
            count = 0
            for line_no, line in enumerate(raw.splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        result = self._json_record_to_result(obj, path, source_type, exercise_id, line_no)
                        if result:
                            yield self._fill_provenance(result, path)
                            count += 1
                            if count >= _MAX_EVENTS_PER_FILE:
                                _warn_truncated(path, count)
                                break
                except json.JSONDecodeError:
                    continue
            return

        records: list[dict] = []
        if isinstance(data, list):
            records = [r for r in data if isinstance(r, dict)]
        elif isinstance(data, dict):
            records = [data]

        if len(records) > _MAX_EVENTS_PER_FILE:
            _warn_truncated(path, _MAX_EVENTS_PER_FILE, total=len(records))
        for idx, record in enumerate(records[:_MAX_EVENTS_PER_FILE]):
            result = self._json_record_to_result(record, path, source_type, exercise_id, idx)
            if result:
                yield self._fill_provenance(result, path)

    def _json_record_to_result(
        self, record: dict, path: Path,
        source_type: SourceType, exercise_id: str | None, idx: int,
    ) -> ParserResult | None:
        """Extract a ParserResult from an arbitrary JSON object."""
        text = json.dumps(record, default=str)
        ips = _extract_ips(text)
        ts = _parse_timestamp(text)
        username = _extract_username(text)
        port = _extract_port(text)

        if not ips and not username:
            return None  # nothing useful to correlate

        corr: dict[str, str] = {}
        src_ip = ips[0] if ips else None
        dest_ip = ips[1] if len(ips) > 1 else None
        if src_ip:
            corr["src_ip"] = src_ip
        if dest_ip:
            corr["dest_ip"] = dest_ip
        if username:
            corr["username"] = username

        # Determine event type from content hints
        event_type = self._guess_event_type(record, text)

        return ParserResult(
            event_type=event_type,
            timestamp=ts,
            source_type=source_type,
            source_system="generic_json",
            src_ip=src_ip,
            dest_ip=dest_ip,
            dest_port=port,
            username=username,
            exercise_id=exercise_id,
            correlation_keys=corr,
            raw_ref=f"{path.name}:{idx}",
            data=self._summarise_record(record),
        )

    # ── Text log parsing ──────────────────────────────────────────────────

    def _parse_text(
        self, path: Path, source_type: SourceType, exercise_id: str | None,
    ) -> Iterator[ParserResult]:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            logger.error("Failed to read %s: %s", path, exc)
            return

        count = 0
        for line_no, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or len(stripped) < 10:
                continue
            # Skip ASCII art / banner lines (low alpha ratio)
            alpha_count = sum(1 for c in stripped if c.isalpha())
            if len(stripped) > 0 and alpha_count / len(stripped) < _MIN_ALPHA_RATIO:
                continue

            ips = _extract_ips(stripped)
            if not ips:
                continue  # no IPs → nothing to correlate

            ts = _parse_timestamp(stripped)
            username = _extract_username(stripped)
            port = _extract_port(stripped)

            corr: dict[str, str] = {}
            src_ip = ips[0]
            dest_ip = ips[1] if len(ips) > 1 else None
            corr["src_ip"] = src_ip
            if dest_ip:
                corr["dest_ip"] = dest_ip
            if username:
                corr["username"] = username

            yield self._fill_provenance(ParserResult(
                event_type=NormalizedEventType.connection,
                timestamp=ts,
                source_type=source_type,
                source_system="generic_text",
                src_ip=src_ip,
                dest_ip=dest_ip,
                dest_port=port,
                username=username,
                exercise_id=exercise_id,
                correlation_keys=corr,
                raw_ref=f"{path.name}:{line_no}",
                data={"raw": stripped[:500]},
            ), path)

            count += 1
            if count >= _MAX_EVENTS_PER_FILE:
                _warn_truncated(path, count)
                break

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _guess_event_type(record: dict, text: str) -> NormalizedEventType:
        """Heuristic event type classification from JSON content."""
        text_lower = text.lower()
        rec_type = str(record.get("type", "")).lower()

        if rec_type in ("scan", "survey") or "scan" in text_lower:
            return NormalizedEventType.connection
        if rec_type == "deployment" or "exploit" in text_lower:
            return NormalizedEventType.process
        if any(k in text_lower for k in ("login", "auth", "password", "credential")):
            return NormalizedEventType.auth
        if any(k in text_lower for k in ("dns", "resolve", "nslookup")):
            return NormalizedEventType.dns
        if any(k in text_lower for k in ("http", "url", "request", "response")):
            return NormalizedEventType.http
        if any(k in text_lower for k in ("file", "write", "create", "delete")):
            return NormalizedEventType.file
        return NormalizedEventType.connection

    @staticmethod
    def _summarise_record(record: dict) -> dict[str, Any]:
        """Create a compact summary dict from a JSON record (max depth 1)."""
        summary: dict[str, Any] = {}
        for key, val in record.items():
            if isinstance(val, (str, int, float, bool, type(None))):
                summary[key] = val
            elif isinstance(val, list):
                summary[key] = f"[{len(val)} items]"
            elif isinstance(val, dict):
                summary[key] = f"{{{len(val)} keys}}"
        return summary