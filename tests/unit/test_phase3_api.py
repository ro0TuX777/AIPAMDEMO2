"""Phase 3 tests — Correlation & API Expansion.

Covers:
  - Job management endpoints (cancel, delete, rerun, batch)
  - Job data endpoints (summary, sensors, timeline, iocs)
  - Host endpoints (list, detail, sub-resources)
  - Findings endpoints (list, explain)
  - Artifacts endpoints (list, evidence-package)
  - SSE events stream
"""

import json
import uuid
from datetime import datetime, timezone

import pytest

AUTH = {"Authorization": "Bearer test-token-v2"}


def _uuid():
    return str(uuid.uuid4())


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------------------
# Helpers to seed data via the DB session from app_client
# ---------------------------------------------------------------------------

def _seed_job(db, status="completed", **kwargs):
    from backend.app.models.job import Job
    jid = kwargs.pop("job_id", _uuid())
    job = Job(
        job_id=jid, job_name=kwargs.get("job_name", "Test Job"),
        status=status, execution_profile="standard", priority="normal",
        pcap_filename="test.pcap", pcap_size_bytes=1024, pcap_sha256="abc",
        created_at=kwargs.get("created_at", _now()), **{k: v for k, v in kwargs.items() if k not in ("job_name", "created_at")},
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _seed_host(db, job_id, ip="10.0.0.1", **kwargs):
    from backend.app.models.host import Host
    host = Host(job_id=job_id, ip=ip, role="internal", conn_count=10,
                alert_count=2, finding_count=1, first_seen=_now(), last_seen=_now(), **kwargs)
    db.add(host)
    db.commit()
    return host


def _seed_alert(db, job_id, host_ip="10.0.0.1", severity="high", **kwargs):
    from backend.app.models.alert import Alert
    a = Alert(job_id=job_id, alert_id=_uuid(), host_ip=host_ip, severity=severity,
              signature="ET MALWARE Test", ts=_now(), **kwargs)
    db.add(a)
    db.commit()
    return a


def _seed_finding(db, job_id, severity="high", **kwargs):
    from backend.app.models.finding import Finding
    payload = {
        "job_id": job_id,
        "finding_id": _uuid(),
        "sensor": "suricata",
        "severity": severity,
        "title": "Suspicious traffic",
        "summary": "Test finding",
    }
    payload.update(kwargs)
    f = Finding(**payload)
    db.add(f)
    db.commit()
    return f


def _seed_ioc(db, job_id, **kwargs):
    from backend.app.models.ioc import Ioc
    payload = {
        "job_id": job_id,
        "ioc_id": _uuid(),
        "ioc_type": "ip",
        "value": "192.168.1.100",
        "confidence": 0.9,
        "sources_json": '["suricata"]',
    }
    payload.update(kwargs)
    i = Ioc(**payload)
    db.add(i)
    db.commit()
    return i


def _seed_connection(db, job_id, host_ip="10.0.0.1"):
    from backend.app.models.connection import Connection
    c = Connection(job_id=job_id, connection_id=_uuid(), host_ip=host_ip,
                   src_ip=host_ip, dest_ip="8.8.8.8", src_port=12345, dest_port=443,
                   proto="tcp", ts=_now())
    db.add(c)
    db.commit()
    return c


def _seed_timeline(db, job_id, **kwargs):
    from backend.app.models.timeline import TimelineEvent
    evt_type = kwargs.pop("type", "alert")
    t = TimelineEvent(job_id=job_id, ts=_now(), type=evt_type,
                      title="Alert fired", details_json='{"description": "test"}', **kwargs)
    db.add(t)
    db.commit()
    return t


def _seed_sensor(db, job_id, sensor="suricata", status="completed"):
    from backend.app.models.sensor import JobSensor
    s = JobSensor(job_id=job_id, sensor=sensor, status=status,
                  started_at=_now(), completed_at=_now())
    db.add(s)
    db.commit()
    return s


# ===== Job Management Tests =====

class TestJobCancel:
    def test_cancel_queued_job(self, app_client):
        client, db = app_client
        job = _seed_job(db, status="queued")
        r = client.post(f"/api/v1/jobs/{job.job_id}/cancel", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["job"]["status"] == "canceled"

    def test_cancel_completed_job_409(self, app_client):
        client, db = app_client
        job = _seed_job(db, status="completed")
        r = client.post(f"/api/v1/jobs/{job.job_id}/cancel", headers=AUTH)
        assert r.status_code == 409


class TestJobDelete:
    def test_delete_completed_job(self, app_client):
        client, db = app_client
        job = _seed_job(db, status="completed")
        r = client.delete(f"/api/v1/jobs/{job.job_id}", headers=AUTH)
        assert r.status_code == 204

    def test_delete_running_job_409(self, app_client):
        client, db = app_client
        job = _seed_job(db, status="running")
        r = client.delete(f"/api/v1/jobs/{job.job_id}", headers=AUTH)
        assert r.status_code == 409


class TestJobBatch:
    def test_batch_cancel(self, app_client):
        client, db = app_client
        j1 = _seed_job(db, status="queued")
        j2 = _seed_job(db, status="completed")
        r = client.post("/api/v1/jobs/batch", headers=AUTH, json={
            "action": "cancel", "job_ids": [j1.job_id, j2.job_id]
        })
        assert r.status_code == 200
        data = r.json()
        assert j1.job_id in data["accepted"]
        assert len(data["rejected"]) == 1

    def test_batch_delete(self, app_client):
        client, db = app_client
        j1 = _seed_job(db, status="failed")
        r = client.post("/api/v1/jobs/batch", headers=AUTH, json={
            "action": "delete", "job_ids": [j1.job_id]
        })
        assert r.status_code == 200
        assert j1.job_id in r.json()["accepted"]


# ===== Job Data Endpoint Tests =====

class TestJobSummary:
    def test_summary_returns_counts(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_host(db, job.job_id)
        _seed_alert(db, job.job_id)
        _seed_finding(db, job.job_id)
        _seed_ioc(db, job.job_id)

        r = client.get(f"/api/v1/jobs/{job.job_id}/summary", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["alert_count"] == 1
        assert data["finding_count"] == 1
        assert data["ioc_count"] == 1
        assert data["host_count"] == 1
        assert "headline" in data

    def test_summary_404(self, app_client):
        client, db = app_client
        r = client.get(f"/api/v1/jobs/{_uuid()}/summary", headers=AUTH)
        assert r.status_code == 404


class TestJobSensors:
    def test_list_sensors(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_sensor(db, job.job_id, "suricata")
        _seed_sensor(db, job.job_id, "zeek")

        r = client.get(f"/api/v1/jobs/{job.job_id}/sensors", headers=AUTH)
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 2
        sensors = [i["sensor"] for i in items]
        assert "suricata" in sensors
        assert "zeek" in sensors


class TestJobTimeline:
    def test_list_timeline(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_timeline(db, job.job_id)

        r = client.get(f"/api/v1/jobs/{job.job_id}/timeline", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1
        assert r.json()["items"][0]["type"] == "alert"

    def test_timeline_type_filter(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_timeline(db, job.job_id, type="alert")
        _seed_timeline(db, job.job_id, type="connection")

        r = client.get(f"/api/v1/jobs/{job.job_id}/timeline?type=alert", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1


class TestJobIocs:
    def test_list_iocs(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_ioc(db, job.job_id)

        r = client.get(f"/api/v1/jobs/{job.job_id}/iocs", headers=AUTH)
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 1
        assert items[0]["type"] == "ip"
        assert items[0]["value"] == "192.168.1.100"

    def test_list_iocs_type_filter_uses_alias(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_ioc(db, job.job_id, ioc_type="ip", value="192.168.1.100")
        _seed_ioc(db, job.job_id, ioc_type="domain", value="bad.example")

        r = client.get(f"/api/v1/jobs/{job.job_id}/iocs?type=domain", headers=AUTH)
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 1
        assert items[0]["type"] == "domain"
        assert items[0]["value"] == "bad.example"


# ===== Host Endpoint Tests =====

class TestHostEndpoints:
    def test_list_hosts(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_host(db, job.job_id, ip="10.0.0.1")
        _seed_host(db, job.job_id, ip="10.0.0.2")

        r = client.get(f"/api/v1/jobs/{job.job_id}/hosts", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 2

    def test_host_detail(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_host(db, job.job_id, ip="10.0.0.5")

        r = client.get(f"/api/v1/jobs/{job.job_id}/hosts/10.0.0.5", headers=AUTH)
        assert r.status_code == 200
        host = r.json()["host"]
        assert host["ip"] == "10.0.0.5"
        assert "dns_summary" in host
        assert "tls_summary" in host

    def test_host_not_found(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        r = client.get(f"/api/v1/jobs/{job.job_id}/hosts/99.99.99.99", headers=AUTH)
        assert r.status_code == 404

    def test_host_connections(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_host(db, job.job_id, ip="10.0.0.1")
        _seed_connection(db, job.job_id, host_ip="10.0.0.1")

        r = client.get(f"/api/v1/jobs/{job.job_id}/hosts/10.0.0.1/connections", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1

    def test_host_alerts(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_host(db, job.job_id, ip="10.0.0.1")
        _seed_alert(db, job.job_id, host_ip="10.0.0.1")

        r = client.get(f"/api/v1/jobs/{job.job_id}/hosts/10.0.0.1/alerts", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1


# ===== Findings Endpoint Tests =====

class TestFindingsEndpoints:
    def test_list_findings(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_finding(db, job.job_id, severity="high")
        _seed_finding(db, job.job_id, severity="low")

        r = client.get(f"/api/v1/jobs/{job.job_id}/findings", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 2

    def test_findings_severity_filter(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_finding(db, job.job_id, severity="high")
        _seed_finding(db, job.job_id, severity="low")

        r = client.get(f"/api/v1/jobs/{job.job_id}/findings?severity=high", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1

    def test_findings_include_metadata_and_category_filter(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_finding(
            db,
            job.job_id,
            sensor="beaconing",
            category="dns",
            pcap_label="capture-a",
            title="DNS tunneling suspected",
        )
        _seed_finding(db, job.job_id, sensor="suricata", category="alert_group", title="Other finding")

        r = client.get(f"/api/v1/jobs/{job.job_id}/findings?category=dns", headers=AUTH)
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 1
        assert items[0]["category"] == "dns"
        assert items[0]["sensor"] == "beaconing"
        assert items[0]["pcap_label"] == "capture-a"

    def test_findings_q_filter_searches_title_summary_and_metadata(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_finding(
            db,
            job.job_id,
            sensor="beaconing",
            category="tls_anomaly",
            pcap_label="capture-b",
            title="TLS on high port",
            summary="Potential C2 over alternate TLS port",
        )
        _seed_finding(db, job.job_id, title="Benign finding", summary="Nothing to see")

        r = client.get(f"/api/v1/jobs/{job.job_id}/findings?q=capture-b", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1
        assert r.json()["items"][0]["pcap_label"] == "capture-b"


# ===== Artifacts Endpoint Tests =====

class TestArtifactsEndpoints:
    def test_list_artifacts_empty(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        r = client.get(f"/api/v1/jobs/{job.job_id}/artifacts", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["items"] == []

    def test_create_evidence_package(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        r = client.post(f"/api/v1/jobs/{job.job_id}/artifacts/evidence-package", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "available"
        assert "artifact_id" in data

        # Verify it shows in list
        r2 = client.get(f"/api/v1/jobs/{job.job_id}/artifacts", headers=AUTH)
        assert len(r2.json()["items"]) == 1


# ===== SSE Events Test =====

class TestSSEEvents:
    def test_events_stream_completed_job(self, app_client):
        client, db = app_client
        job = _seed_job(db, status="completed")
        r = client.get(f"/api/v1/jobs/{job.job_id}/events", headers=AUTH)
        assert r.status_code == 200
        assert "text/event-stream" in r.headers["content-type"]
        # Should contain a status event and a done event
        text = r.text
        assert "event: status" in text
        assert "event: done" in text

    def test_events_stream_not_found(self, app_client):
        client, db = app_client
        r = client.get(f"/api/v1/jobs/{_uuid()}/events", headers=AUTH)
        assert r.status_code == 404

