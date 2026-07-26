"""Normalizing PCAP sensor output (zeek/suricata) into Raw Events."""

import json

from sqlalchemy import func, select

from backend.app.models.job import Job
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.normalize.network_events import normalize_network_events


def _write_sensors(tmp_path):
    sd = tmp_path / "sensors"
    (sd / "zeek").mkdir(parents=True)
    (sd / "suricata").mkdir(parents=True)
    (sd / "capa").mkdir(parents=True)  # non-network sensor → ignored
    (sd / "zeek" / "sensor.results.jsonl").write_text(
        json.dumps({"type": "flow", "data": {
            "src_ip": "10.0.0.1", "src_port": 5, "dst_ip": "8.8.8.8", "dst_port": 443,
            "transport_proto": "TCP", "app_proto": "TLS", "start_time": "2025-01-01T00:00:00Z"},
            "pcap_label": "before"}) + "\n"
        + json.dumps({"type": "flow", "data": {
            "src_ip": "10.0.0.1", "dst_ip": "1.1.1.1", "dst_port": 80,
            "transport_proto": "TCP", "app_proto": "HTTP"}}) + "\n"
        + json.dumps({"type": "event", "data": {
            "event_type": "dns", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.53", "dst_port": 53,
            "transport_proto": "UDP", "timestamp": "2025-01-01T00:00:01Z",
            "details": {"query": "x.com"}}}) + "\n"
    )
    (sd / "suricata" / "sensor.results.jsonl").write_text(
        json.dumps({"type": "alert", "data": {
            "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "src_port": 5, "dst_port": 80,
            "signature_name": "ET TEST", "severity": "medium",
            "timestamp": "2025-01-01 00:00:02+00:00"}}) + "\n"
    )
    (sd / "capa" / "sensor.results.jsonl").write_text(
        json.dumps({"type": "capability", "data": {"rule": "x"}}) + "\n")


def _seed_job(db):
    db.add(Job(job_id="j1", status="completed", execution_profile="triage",
               priority="normal", source_type="pcap", created_at="t"))
    db.commit()


def test_zeek_and_suricata_map_to_raw_events(db_session, tmp_path):
    _seed_job(db_session)
    _write_sensors(tmp_path)

    n = normalize_network_events("j1", tmp_path, db_session)
    assert n == 4  # 2 flows + 1 event + 1 alert (capa ignored)

    rows = db_session.execute(select(NormalizedEvent).where(NormalizedEvent.job_id == "j1")).scalars().all()
    assert sorted(r.event_type for r in rows) == ["alert", "dns", "http", "tls"]

    tls = next(r for r in rows if r.event_type == "tls")
    assert tls.dest_ip == "8.8.8.8" and tls.dest_port == 443 and tls.proto == "TCP"
    assert tls.source_system == "zeek" and tls.source_type == "pcap" and tls.pcap_label == "before"

    alert = next(r for r in rows if r.event_type == "alert")
    assert alert.source_system == "suricata"
    # space in the suricata timestamp is normalized to 'T' for consistent sorting
    assert alert.timestamp.startswith("2025-01-01T00:00:02")


def test_reindex_replaces_not_duplicates(db_session, tmp_path):
    _seed_job(db_session)
    _write_sensors(tmp_path)
    normalize_network_events("j1", tmp_path, db_session)
    normalize_network_events("j1", tmp_path, db_session)  # re-run
    total = db_session.scalar(
        select(func.count()).select_from(NormalizedEvent).where(NormalizedEvent.job_id == "j1")
    )
    assert total == 4
