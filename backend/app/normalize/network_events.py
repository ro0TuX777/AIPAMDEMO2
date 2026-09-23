"""Normalize PCAP sensor output into the normalized_events table.

PCAP-only jobs never run the telemetry/log pipeline (which is what normally
writes ``normalized_events``), so their **Raw Events** explorer was empty even
though zeek and suricata produced rich per-connection data. This reads each
network sensor's ``sensor.results.jsonl`` and maps every flow / event / alert
record to a NormalizedEvent, so Raw Events works for plain captures too.

Sources mapped:
  - zeek  ``flow``  records → connection / dns / http / tls (by app_proto)
  - zeek  ``event`` records → dns / http / tls / connection (by event_type)
  - suricata ``alert`` records → alert
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete
from sqlalchemy.orm import Session

from backend.app.models.normalized_event import NormalizedEvent

logger = logging.getLogger("aipam.normalize.network")

# Marker so re-analysis can replace exactly the events this module wrote.
# Also lets downstream correlators tell PCAP-derived events apart from events
# parsed out of user-uploaded log bundles.
PCAP_NORMALIZER_PARSER = "pcap_network_normalizer"
_PARSER_NAME = PCAP_NORMALIZER_PARSER

# Sensors whose records are network telemetry we surface as raw events.
_NETWORK_SENSORS = {"zeek", "suricata"}

# zeek flow app_proto → NormalizedEventType
_APP_PROTO_MAP = {"HTTP": "http", "TLS": "tls", "SSL": "tls", "DNS": "dns"}
# zeek 'event' record event_type → NormalizedEventType
_EVENT_TYPE_MAP = {"dns": "dns", "http": "http", "tls": "tls", "ssl": "tls"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _map_event_type(record: dict) -> str | None:
    """Map a sensor record to a NormalizedEventType value, or None to skip."""
    rtype = record.get("type")
    data = record.get("data") or {}
    if rtype == "flow":
        return _APP_PROTO_MAP.get(str(data.get("app_proto") or "").upper(), "connection")
    if rtype == "event":
        return _EVENT_TYPE_MAP.get(str(data.get("event_type") or "").lower(), "connection")
    if rtype == "alert":
        return "alert"
    return None


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _record_to_event(record: dict, job_id: str, sensor: str) -> NormalizedEvent | None:
    event_type = _map_event_type(record)
    if event_type is None:
        return None
    data = record.get("data") or {}
    # zeek uses start_time on flows and timestamp on events; suricata uses
    # "YYYY-MM-DD HH:MM:SS" — normalize the space to 'T' so all events sort together.
    ts = str(data.get("timestamp") or data.get("start_time") or _now_iso()).replace(" ", "T", 1)
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        job_id=job_id,
        event_type=event_type,
        timestamp=ts,
        source_type="pcap",
        source_system=sensor,
        source_filename="sensor.results.jsonl",
        parser_name=_PARSER_NAME,
        evidence_status="observed",
        src_ip=data.get("src_ip"),
        src_port=data.get("src_port"),
        dest_ip=data.get("dst_ip") or data.get("dest_ip"),
        dest_port=data.get("dst_port") or data.get("dest_port"),
        proto=data.get("transport_proto") or data.get("proto"),
        data_json=json.dumps(data) if data else None,
        pcap_label=record.get("pcap_label"),
    )


def normalize_network_events(job_id: str, run_output_dir: Path, db: Session) -> int:
    """(Re)write normalized_events for a PCAP job's zeek/suricata output.

    Idempotent: clears this job's previously-written network events first, so
    re-analysis replaces rather than duplicates them. Returns events written.
    """
    sensors_dir = Path(run_output_dir) / "sensors"
    events: list[NormalizedEvent] = []
    if sensors_dir.exists():
        for sensor_dir in sorted(sensors_dir.iterdir()):
            if not sensor_dir.is_dir() or sensor_dir.name not in _NETWORK_SENSORS:
                continue
            for record in _read_jsonl(sensor_dir / "sensor.results.jsonl"):
                ev = _record_to_event(record, job_id, sensor_dir.name)
                if ev is not None:
                    events.append(ev)

    db.execute(
        delete(NormalizedEvent).where(
            NormalizedEvent.job_id == job_id,
            NormalizedEvent.parser_name == _PARSER_NAME,
        )
    )
    if events:
        db.add_all(events)
    db.commit()
    logger.info("Normalized %d PCAP network events for job %s", len(events), job_id)
    return len(events)
