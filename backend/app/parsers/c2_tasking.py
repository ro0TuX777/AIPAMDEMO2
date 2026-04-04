"""C2 operator tasking log parser.

Parses JSON-format C2 task/command logs with fields:
  timestamp, task_id, agent_id, operator, command, framework,
  status, completed_at

Maps to NormalizedEventType.c2_task.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from backend.app.parsers.base import BaseParser, ParserResult
from backend.app.schemas.common import NormalizedEventType, SourceType

logger = logging.getLogger("aipam.parsers.c2_tasking")


class C2TaskingParser(BaseParser):
    """Parser for C2 operator tasking JSON logs."""

    @property
    def name(self) -> str:
        return "c2_tasking"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_source_systems(self) -> list[str]:
        return [
            "cobalt_strike", "mythic", "sliver", "havoc",
            "c2_tasking", "c2_generic",
        ]

    def can_parse(self, path: Path, hint: str | None = None) -> bool:
        if hint and hint in ("c2_tasking",):
            return True
        name = path.name.lower()
        return name.endswith(".json") and ("tasking" in name or "c2_task" in name)

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
                logger.warning("Skipping tasking record %d in %s: %s", idx, path.name, exc)

    def _parse_record(
        self, record: dict, path: Path,
        source_type: SourceType, exercise_id: str | None, idx: int,
    ) -> ParserResult | None:
        ts_raw = record.get("timestamp", "")
        timestamp = _parse_ts(ts_raw)

        task_id = record.get("task_id", "")
        agent_id = record.get("agent_id", "")
        operator = record.get("operator", "")
        command = record.get("command", "")
        framework = record.get("framework", "unknown")
        status = record.get("status", "issued")

        correlation_keys: dict[str, str] = {}
        if agent_id:
            correlation_keys["agent_id"] = agent_id
        if task_id:
            correlation_keys["task_id"] = task_id

        return ParserResult(
            event_type=NormalizedEventType.c2_task,
            timestamp=timestamp,
            source_type=source_type,
            source_system=framework,
            exercise_id=exercise_id,
            correlation_keys=correlation_keys,
            raw_ref=f"{path.name}:{idx}",
            data={
                "task_id": task_id,
                "agent_id": agent_id,
                "operator": operator,
                "command": command,
                "framework": framework,
                "status": status,
                "completed_at": record.get("completed_at"),
            },
        )


def _parse_ts(raw: str) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)

