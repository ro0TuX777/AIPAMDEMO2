"""Phase 6 tests - C2 / Controlled-Range Telemetry Fusion.

Tests run against in-memory SQLite with the V2 schema.
Covers: C2 parsers, fusion strategies, pipeline integration.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session

from backend.app.database_v2 import Base, _set_sqlite_pragmas
from backend.app.models.finding import Finding
from backend.app.models.job import Job
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.parsers.c2_callback import C2CallbackParser
from backend.app.parsers.c2_tasking import C2TaskingParser
from backend.app.schemas.common import EvidenceStatus, SourceType
from backend.app.sensors.c2_fusion import (
    _confirm_beaconing,
    _match_callbacks_to_connections,
    _match_tasks_to_host_events,
    fuse_c2_with_observed,
    run_c2_fusion,
)


def _uid():
    return str(uuid.uuid4())


def _ts(offset_seconds=0):
    dt = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)
    yield session
    session.close()
    engine.dispose()


@pytest.fixture()
def job_id(db):
    jid = _uid()
    db.add(Job(
        job_id=jid, job_name="Fusion Test", status="running",
        execution_profile="standard", priority="normal",
        pcap_filename="test.pcap", pcap_size_bytes=0, pcap_sha256="abc",
        created_at=_ts(),
    ))
    db.commit()
    return jid


def _c2_cb(job_id, src_ip, dest_ip, dest_port, agent_id, ts_offset=0, **extra):
    data = {"agent_id": agent_id, "framework": "cobalt_strike",
            "callback_type": "checkin", **extra}
    return NormalizedEvent(
        event_id=_uid(), job_id=job_id, event_type="c2_callback",
        timestamp=_ts(ts_offset), source_type="c2_bundle",
        evidence_status="observed", src_ip=src_ip, dest_ip=dest_ip,
        dest_port=dest_port, data_json=json.dumps(data),
    )


def _c2_task(job_id, agent_id, command, ts_offset=0, **extra):
    data = {"agent_id": agent_id, "command": command,
            "operator": "redteam1", "task_id": _uid(), **extra}
    return NormalizedEvent(
        event_id=_uid(), job_id=job_id, event_type="c2_task",
        timestamp=_ts(ts_offset), source_type="c2_bundle",
        evidence_status="observed", data_json=json.dumps(data),
    )


def _conn(job_id, src_ip, dest_ip, dest_port, ts_offset=0):
    return NormalizedEvent(
        event_id=_uid(), job_id=job_id, event_type="connection",
        timestamp=_ts(ts_offset), source_type="log_bundle",
        evidence_status="observed", src_ip=src_ip, dest_ip=dest_ip,
        dest_port=dest_port,
    )


def _proc(job_id, src_ip, hostname, ts_offset=0):
    return NormalizedEvent(
        event_id=_uid(), job_id=job_id, event_type="process",
        timestamp=_ts(ts_offset), source_type="log_bundle",
        evidence_status="observed", src_ip=src_ip, hostname=hostname,
    )


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "telemetry" / "c2"


# -- C2 Parser Tests -------------------------------------------------------


class TestC2CallbackParser:
    def test_can_parse_callback_file(self):
        p = C2CallbackParser()
        assert p.can_parse(Path("callbacks.json"), hint="c2_callback")
        assert p.can_parse(Path("sample_callbacks.json"))
        assert not p.can_parse(Path("tasking.json"))

    def test_parse_sample_callbacks(self):
        p = C2CallbackParser()
        path = FIXTURES_DIR / "sample_callbacks.json"
        if not path.exists():
            pytest.skip("Sample fixture not found")
        results = list(p.parse(path, job_id="test-job"))
        assert len(results) > 0
        for r in results:
            assert r.event_type.value == "c2_callback"
            assert r.source_type == SourceType.c2_bundle
            assert "agent_id" in r.data


class TestC2TaskingParser:
    def test_can_parse_tasking_file(self):
        p = C2TaskingParser()
        assert p.can_parse(Path("tasking.json"), hint="c2_tasking")
        assert p.can_parse(Path("sample_tasking.json"))
        assert not p.can_parse(Path("callbacks.json"))

    def test_parse_sample_tasking(self):
        p = C2TaskingParser()
        path = FIXTURES_DIR / "sample_tasking.json"
        if not path.exists():
            pytest.skip("Sample fixture not found")
        results = list(p.parse(path, job_id="test-job"))
        assert len(results) > 0
        for r in results:
            assert r.event_type.value == "c2_task"
            assert "command" in r.data


# -- Fusion Strategy Tests --------------------------------------------------


class TestCallbackToConnectionFusion:
    def test_matching_callback_confirms_connection(self, db, job_id):
        obs = _conn(job_id, "10.0.0.5", "192.168.1.100", 443, ts_offset=0)
        cb = _c2_cb(job_id, "10.0.0.5", "192.168.1.100", 443, "agent-1", ts_offset=60)
        db.add_all([obs, cb])
        db.commit()

        findings = _match_callbacks_to_connections(db, job_id, [cb], [obs])
        assert len(findings) == 1
        assert findings[0].category == "c2_confirmed_connection"
        assert findings[0].confidence == 0.95

        db.expire_all()
        refreshed = db.get(NormalizedEvent, obs.id)
        assert refreshed.evidence_status == EvidenceStatus.confirmed.value

    def test_no_match_different_ip(self, db, job_id):
        obs = _conn(job_id, "10.0.0.99", "192.168.1.100", 443, ts_offset=0)
        cb = _c2_cb(job_id, "10.0.0.5", "192.168.1.100", 443, "agent-1", ts_offset=60)
        db.add_all([obs, cb])
        db.commit()

        findings = _match_callbacks_to_connections(db, job_id, [cb], [obs])
        assert len(findings) == 0

    def test_no_match_outside_time_window(self, db, job_id):
        obs = _conn(job_id, "10.0.0.5", "192.168.1.100", 443, ts_offset=0)
        cb = _c2_cb(job_id, "10.0.0.5", "192.168.1.100", 443, "agent-1", ts_offset=600)
        db.add_all([obs, cb])
        db.commit()

        findings = _match_callbacks_to_connections(db, job_id, [cb], [obs])
        assert len(findings) == 0


class TestTaskToHostFusion:
    def test_task_confirms_process_on_same_host(self, db, job_id):
        cb = _c2_cb(job_id, "10.0.0.5", "192.168.1.100", 443, "agent-1", ts_offset=0)
        proc = _proc(job_id, "10.0.0.5", "WORKSTATION1", ts_offset=30)
        task = _c2_task(job_id, "agent-1", "shell whoami", ts_offset=25)
        db.add_all([cb, proc, task])
        db.commit()

        findings = _match_tasks_to_host_events(db, job_id, [task], [proc])
        assert len(findings) == 1
        assert findings[0].category == "c2_confirmed_execution"
        assert findings[0].confidence == 0.90

    def test_no_match_unknown_agent(self, db, job_id):
        proc = _proc(job_id, "10.0.0.5", "WORKSTATION1", ts_offset=30)
        task = _c2_task(job_id, "unknown-agent", "shell whoami", ts_offset=25)
        db.add_all([proc, task])
        db.commit()

        findings = _match_tasks_to_host_events(db, job_id, [task], [proc])
        assert len(findings) == 0


class TestBeaconingConfirmation:
    def test_beacon_finding_uplifted(self, db, job_id):
        beacon_finding = Finding(
            job_id=job_id, finding_id=f"F-{_uid()[:12]}",
            sensor="netflow_behavior", severity="medium",
            category="beacon", title="Beaconing detected from 10.0.0.5",
            summary="Periodic connections detected",
            evidence_json=json.dumps({"src_ip": "10.0.0.5"}),
            confidence=0.70,
        )
        db.add(beacon_finding)
        db.commit()

        cb = _c2_cb(
            job_id, "10.0.0.5", "192.168.1.100", 443, "agent-1",
            ts_offset=0, sleep_seconds=60, jitter_pct=10,
        )
        db.add(cb)
        db.commit()

        findings = _confirm_beaconing(db, job_id, [cb])
        assert len(findings) == 1
        assert findings[0].category == "c2_confirmed_beacon"
        assert findings[0].severity == "critical"

        db.expire_all()
        refreshed = db.get(Finding, beacon_finding.id)
        assert refreshed.confidence == pytest.approx(0.95)

    def test_no_uplift_when_ip_doesnt_match(self, db, job_id):
        beacon_finding = Finding(
            job_id=job_id, finding_id=f"F-{_uid()[:12]}",
            sensor="netflow_behavior", severity="medium",
            category="beacon", title="Beaconing from 10.0.0.99",
            summary="Periodic connections",
            evidence_json=json.dumps({"src_ip": "10.0.0.99"}),
            confidence=0.70,
        )
        db.add(beacon_finding)
        db.commit()

        cb = _c2_cb(job_id, "10.0.0.5", "192.168.1.100", 443, "agent-1")
        db.add(cb)
        db.commit()

        findings = _confirm_beaconing(db, job_id, [cb])
        assert len(findings) == 0


# -- Orchestrator Tests -----------------------------------------------------


class TestFuseC2WithObserved:
    def test_full_fusion_pipeline(self, db, job_id):
        cb = _c2_cb(job_id, "10.0.0.5", "192.168.1.100", 443, "agent-1", ts_offset=0)
        obs = _conn(job_id, "10.0.0.5", "192.168.1.100", 443, ts_offset=30)
        proc = _proc(job_id, "10.0.0.5", "WKS1", ts_offset=60)
        task = _c2_task(job_id, "agent-1", "shell ipconfig", ts_offset=55)
        db.add_all([cb, obs, proc, task])
        db.commit()

        findings = fuse_c2_with_observed(db, job_id)
        assert len(findings) >= 2
        categories = {f.category for f in findings}
        assert "c2_confirmed_connection" in categories
        assert "c2_confirmed_execution" in categories

    def test_no_c2_events_returns_empty(self, db, job_id):
        obs = _conn(job_id, "10.0.0.5", "192.168.1.100", 443)
        db.add(obs)
        db.commit()

        findings = fuse_c2_with_observed(db, job_id)
        assert len(findings) == 0

    def test_run_c2_fusion_persists(self, db, job_id):
        cb = _c2_cb(job_id, "10.0.0.5", "192.168.1.100", 443, "agent-1", ts_offset=0)
        obs = _conn(job_id, "10.0.0.5", "192.168.1.100", 443, ts_offset=30)
        db.add_all([cb, obs])
        db.commit()

        findings = run_c2_fusion(db, job_id)
        assert len(findings) >= 1

        stored = list(db.execute(
            select(Finding).where(Finding.sensor == "c2_fusion")
        ).scalars().all())
        assert len(stored) == len(findings)
