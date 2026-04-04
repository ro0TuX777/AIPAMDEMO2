"""DNS log JSON parser.

Parses JSON-format DNS query/response logs with fields:
  timestamp, client_ip, query, query_type, response, response_code, server_ip

Maps to NormalizedEventType.dns.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from backend.app.parsers.base import BaseParser, ParserResult
from backend.app.schemas.common import NormalizedEventType, SourceType

logger = logging.getLogger("aipam.parsers.dns")


class DnsParser(BaseParser):
    """Parser for generic DNS JSON logs."""

    @property
    def name(self) -> str:
        return "dns"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_source_systems(self) -> list[str]:
        return ["dns", "bind", "unbound", "pihole", "zeek_dns"]

    def can_parse(self, path: Path, hint: str | None = None) -> bool:
        if hint and hint in self.supported_source_systems:
            return True
        name = path.name.lower()
        return name.endswith(".json") and "dns" in name

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
        query = record.get("query", "")
        query_type = record.get("query_type", "A")
        response = record.get("response")
        rcode = record.get("response_code", "UNKNOWN")

        correlation_keys: dict[str, str] = {}
        if client_ip:
            correlation_keys["src_ip"] = client_ip
        if query:
            correlation_keys["dns_query"] = query
        if response:
            correlation_keys["dest_ip"] = response

        return ParserResult(
            event_type=NormalizedEventType.dns,
            timestamp=timestamp,
            source_type=source_type,
            source_system="dns",
            src_ip=client_ip,
            dest_ip=response,
            exercise_id=exercise_id,
            correlation_keys=correlation_keys,
            raw_ref=f"{path.name}:{idx}",
            data={
                "query": query,
                "query_type": query_type,
                "response": response,
                "response_code": rcode,
                "server_ip": record.get("server_ip"),
            },
        )


def _parse_ts(raw: str) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)

