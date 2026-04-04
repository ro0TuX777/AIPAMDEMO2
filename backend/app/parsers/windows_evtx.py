"""Windows Event Log (EVTX) JSON parser.

Parses JSON-exported Windows Security Event Logs and maps key
Event IDs to normalized auth events:
  - 4624: Successful logon
  - 4625: Failed logon
  - 4634/4647: Logoff
  - 4648: Explicit credential logon
  - 4672: Special privileges assigned
  - 4720/4726: User account created/deleted
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from backend.app.parsers.base import BaseParser, ParserResult
from backend.app.schemas.common import NormalizedEventType, SourceType

logger = logging.getLogger("aipam.parsers.windows_evtx")

# Map EventID to a human-readable sub-type and normalized event type
_EVTX_EVENT_MAP: dict[int, tuple[str, NormalizedEventType]] = {
    4624: ("logon_success", NormalizedEventType.auth),
    4625: ("logon_failure", NormalizedEventType.auth),
    4634: ("logoff", NormalizedEventType.auth),
    4647: ("logoff_interactive", NormalizedEventType.auth),
    4648: ("explicit_credential", NormalizedEventType.auth),
    4672: ("special_privileges", NormalizedEventType.auth),
    4720: ("user_created", NormalizedEventType.auth),
    4726: ("user_deleted", NormalizedEventType.auth),
}


class WindowsEvtxParser(BaseParser):
    """Parser for Windows Security Event Log JSON exports."""

    @property
    def name(self) -> str:
        return "windows_evtx"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_source_systems(self) -> list[str]:
        return ["windows_evtx", "windows_security"]

    def can_parse(self, path: Path, hint: str | None = None) -> bool:
        if hint and hint in self.supported_source_systems:
            return True
        name = path.name.lower()
        if not name.endswith(".json"):
            return False
        return "evtx" in name or "security" in name or "windows" in name

    def parse(
        self,
        path: Path,
        job_id: str,
        source_type: SourceType = SourceType.log_bundle,
        exercise_id: str | None = None,
    ) -> Iterator[ParserResult]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to read %s: %s", path, exc)
            return

        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            logger.error("Unexpected format in %s: expected list or dict", path)
            return

        for idx, record in enumerate(data):
            try:
                result = self._parse_record(record, path, job_id, source_type, exercise_id, idx)
                if result is not None:
                    yield self._fill_provenance(result, path)
            except Exception as exc:
                logger.warning("Skipping record %d in %s: %s", idx, path.name, exc)

    def _parse_record(
        self,
        record: dict,
        path: Path,
        job_id: str,
        source_type: SourceType,
        exercise_id: str | None,
        idx: int,
    ) -> ParserResult | None:
        event_id = record.get("EventID")
        if event_id is None:
            return None

        event_id = int(event_id)
        sub_type, event_type = _EVTX_EVENT_MAP.get(event_id, (f"event_{event_id}", NormalizedEventType.auth))

        ts_raw = record.get("TimeCreated", "")
        timestamp = _parse_timestamp(ts_raw)

        event_data = record.get("EventData", {})
        hostname = record.get("Computer")
        username = event_data.get("TargetUserName")
        domain = event_data.get("TargetDomainName")
        src_ip = event_data.get("IpAddress")
        src_port = _safe_int(event_data.get("IpPort"))
        logon_type = event_data.get("LogonType")

        correlation_keys: dict[str, str] = {}
        if hostname:
            correlation_keys["hostname"] = hostname
        if src_ip and src_ip != "-":
            correlation_keys["src_ip"] = src_ip
        if username:
            full_user = f"{domain}\\{username}" if domain else username
            correlation_keys["username"] = full_user

        return ParserResult(
            event_type=event_type,
            timestamp=timestamp,
            source_type=source_type,
            source_system="windows_evtx",
            hostname=hostname,
            username=f"{domain}\\{username}" if domain and username else username,
            src_ip=src_ip if src_ip and src_ip != "-" else None,
            src_port=src_port,
            exercise_id=exercise_id,
            correlation_keys=correlation_keys,
            raw_ref=f"{path.name}:{idx}",
            data={
                "sub_type": sub_type,
                "event_id": event_id,
                "channel": record.get("Channel"),
                "provider": record.get("Provider"),
                "logon_type": logon_type,
                "event_data": event_data,
            },
        )


def _parse_timestamp(raw: str) -> datetime:
    """Parse ISO-ish timestamp, falling back to UTC now."""
    if not raw:
        return datetime.now(timezone.utc)
    try:
        raw = raw.replace("Z", "+00:00")
        return datetime.fromisoformat(raw)
    except ValueError:
        return datetime.now(timezone.utc)


def _safe_int(val) -> int | None:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None

