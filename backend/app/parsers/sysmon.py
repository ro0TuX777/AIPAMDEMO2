"""Sysmon JSON parser.

Parses JSON-exported Sysmon logs and maps key Event IDs:
  - 1:  Process Create  → process
  - 3:  Network Connect → connection
  - 7:  Image Loaded    → file
  - 11: File Create     → file
  - 13: Registry Value Set → config_change
  - 22: DNS Query       → dns
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from backend.app.parsers.base import BaseParser, ParserResult
from backend.app.schemas.common import NormalizedEventType, SourceType

logger = logging.getLogger("aipam.parsers.sysmon")

_SYSMON_EVENT_MAP: dict[int, tuple[str, NormalizedEventType]] = {
    1:  ("process_create", NormalizedEventType.process),
    3:  ("network_connect", NormalizedEventType.connection),
    5:  ("process_terminate", NormalizedEventType.process),
    7:  ("image_loaded", NormalizedEventType.file),
    8:  ("create_remote_thread", NormalizedEventType.process),
    11: ("file_create", NormalizedEventType.file),
    12: ("registry_create_delete", NormalizedEventType.config_change),
    13: ("registry_value_set", NormalizedEventType.config_change),
    22: ("dns_query", NormalizedEventType.dns),
}


class SysmonParser(BaseParser):
    """Parser for Sysmon JSON exports."""

    @property
    def name(self) -> str:
        return "sysmon"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_source_systems(self) -> list[str]:
        return ["sysmon"]

    def can_parse(self, path: Path, hint: str | None = None) -> bool:
        if hint == "sysmon":
            return True
        name = path.name.lower()
        return name.endswith(".json") and "sysmon" in name

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
            return

        for idx, record in enumerate(data):
            try:
                result = self._parse_record(record, path, source_type, exercise_id, idx)
                if result is not None:
                    yield self._fill_provenance(result, path)
            except Exception as exc:
                logger.warning("Skipping record %d in %s: %s", idx, path.name, exc)

    def _parse_record(
        self, record: dict, path: Path,
        source_type: SourceType, exercise_id: str | None, idx: int,
    ) -> ParserResult | None:
        event_id = record.get("EventID")
        if event_id is None:
            return None
        event_id = int(event_id)
        sub_type, event_type = _SYSMON_EVENT_MAP.get(
            event_id, (f"sysmon_{event_id}", NormalizedEventType.process)
        )

        ts_raw = record.get("TimeCreated", "")
        timestamp = _parse_ts(ts_raw)
        ed = record.get("EventData", {})

        hostname = record.get("Computer")
        username = ed.get("User")
        process_guid = ed.get("ProcessGuid")

        # Network fields (EventID 3)
        src_ip = ed.get("SourceIp")
        src_port = _safe_int(ed.get("SourcePort"))
        dest_ip = ed.get("DestinationIp")
        dest_port = _safe_int(ed.get("DestinationPort"))
        proto = ed.get("Protocol")

        correlation_keys: dict[str, str] = {}
        if hostname:
            correlation_keys["hostname"] = hostname
        if process_guid:
            correlation_keys["process_guid"] = process_guid
        if src_ip:
            correlation_keys["src_ip"] = src_ip
        if dest_ip:
            correlation_keys["dest_ip"] = dest_ip

        return ParserResult(
            event_type=event_type,
            timestamp=timestamp,
            source_type=source_type,
            source_system="sysmon",
            hostname=hostname,
            username=username,
            src_ip=src_ip,
            src_port=src_port,
            dest_ip=dest_ip,
            dest_port=dest_port,
            proto=proto,
            process_guid=process_guid,
            exercise_id=exercise_id,
            correlation_keys=correlation_keys,
            raw_ref=f"{path.name}:{idx}",
            data={
                "sub_type": sub_type,
                "event_id": event_id,
                "image": ed.get("Image"),
                "command_line": ed.get("CommandLine"),
                "parent_image": ed.get("ParentImage"),
                "parent_command_line": ed.get("ParentCommandLine"),
                "hashes": ed.get("Hashes"),
                "event_data": ed,
            },
        )


def _parse_ts(raw: str) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _safe_int(val) -> int | None:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None

