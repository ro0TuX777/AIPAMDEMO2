"""C2 callback / checkin log parser.

Parses JSON-format C2 callback logs with fields:
  timestamp, agent_id, callback_type, source_ip, dest_ip, dest_port,
  uri, user_agent, sleep_seconds, jitter_pct, framework, operator,
  task_id, task_output

Supports: Cobalt Strike, Mythic, Sliver, and generic C2 frameworks.
Maps to NormalizedEventType.c2_callback.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from backend.app.parsers.base import BaseParser, ParserResult
from backend.app.schemas.common import NormalizedEventType, SourceType

logger = logging.getLogger("aipam.parsers.c2_callback")


class C2CallbackParser(BaseParser):
    """Parser for C2 callback/checkin JSON logs."""

    @property
    def name(self) -> str:
        return "c2_callback"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_source_systems(self) -> list[str]:
        return [
            "cobalt_strike", "mythic", "sliver", "havoc",
            "c2_callback", "c2_generic",
        ]

    def can_parse(self, path: Path, hint: str | None = None) -> bool:
        if hint and hint in self.supported_source_systems:
            return True
        name = path.name.lower()
        return name.endswith(".json") and ("callback" in name or "c2_cb" in name)

    def parse(
        self,
        path: Path,
        job_id: str,
        source_type: SourceType = SourceType.c2_bundle,
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
                logger.warning("Skipping callback record %d in %s: %s", idx, path.name, exc)

    def _parse_record(
        self, record: dict, path: Path,
        source_type: SourceType, exercise_id: str | None, idx: int,
    ) -> ParserResult | None:
        ts_raw = record.get("timestamp", "")
        timestamp = _parse_ts(ts_raw)

        agent_id = record.get("agent_id", "")
        callback_type = record.get("callback_type", "checkin")
        src_ip = record.get("source_ip")
        dest_ip = record.get("dest_ip")
        dest_port = record.get("dest_port")
        framework = record.get("framework", "unknown")

        correlation_keys: dict[str, str] = {}
        if src_ip:
            correlation_keys["src_ip"] = src_ip
        if dest_ip:
            correlation_keys["dest_ip"] = dest_ip
        if agent_id:
            correlation_keys["agent_id"] = agent_id

        return ParserResult(
            event_type=NormalizedEventType.c2_callback,
            timestamp=timestamp,
            source_type=source_type,
            source_system=framework,
            src_ip=src_ip,
            dest_ip=dest_ip,
            dest_port=int(dest_port) if dest_port is not None else None,
            exercise_id=exercise_id,
            correlation_keys=correlation_keys,
            raw_ref=f"{path.name}:{idx}",
            data={
                "agent_id": agent_id,
                "callback_type": callback_type,
                "uri": record.get("uri"),
                "user_agent": record.get("user_agent"),
                "sleep_seconds": record.get("sleep_seconds"),
                "jitter_pct": record.get("jitter_pct"),
                "framework": framework,
                "operator": record.get("operator"),
                "task_id": record.get("task_id"),
                "task_output": record.get("task_output"),
            },
        )


def _parse_ts(raw: str) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)

