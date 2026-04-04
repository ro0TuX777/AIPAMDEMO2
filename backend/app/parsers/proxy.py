"""Proxy log JSON parser.

Parses JSON-format web proxy logs with fields:
  timestamp, client_ip, method, url, status_code, content_type, etc.

Maps to NormalizedEventType.proxy.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

from backend.app.parsers.base import BaseParser, ParserResult
from backend.app.schemas.common import NormalizedEventType, SourceType

logger = logging.getLogger("aipam.parsers.proxy")


class ProxyParser(BaseParser):
    """Parser for generic proxy JSON logs."""

    @property
    def name(self) -> str:
        return "proxy"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_source_systems(self) -> list[str]:
        return ["proxy", "squid", "bluecoat", "zscaler"]

    def can_parse(self, path: Path, hint: str | None = None) -> bool:
        if hint and hint in self.supported_source_systems:
            return True
        name = path.name.lower()
        return name.endswith(".json") and "proxy" in name

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
        ts_raw = record.get("timestamp", "")
        timestamp = _parse_ts(ts_raw)

        client_ip = record.get("client_ip")
        url = record.get("url", "")

        # Extract destination host from URL
        dest_host = None
        dest_port = None
        try:
            parsed = urlparse(url)
            dest_host = parsed.hostname
            dest_port = parsed.port
        except Exception:
            pass

        correlation_keys: dict[str, str] = {}
        if client_ip:
            correlation_keys["src_ip"] = client_ip
        if dest_host:
            correlation_keys["dest_host"] = dest_host

        return ParserResult(
            event_type=NormalizedEventType.proxy,
            timestamp=timestamp,
            source_type=source_type,
            source_system="proxy",
            src_ip=client_ip,
            dest_ip=dest_host,
            dest_port=dest_port,
            exercise_id=exercise_id,
            correlation_keys=correlation_keys,
            raw_ref=f"{path.name}:{idx}",
            data={
                "method": record.get("method"),
                "url": url,
                "status_code": record.get("status_code"),
                "content_type": record.get("content_type"),
                "bytes_transferred": record.get("bytes_transferred"),
                "user_agent": record.get("user_agent"),
                "category": record.get("category"),
                "action": record.get("action"),
            },
        )


def _parse_ts(raw: str) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)

