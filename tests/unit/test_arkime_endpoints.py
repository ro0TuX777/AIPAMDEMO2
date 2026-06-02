"""Tests for Arkime MVP API endpoints (Phase 2).

Tests:
  - POST /jobs/{id}/arkime/import
  - GET  /jobs/{id}/arkime/status
  - GET  /jobs/{id}/alerts/{id}/arkime-link
  - GET  /jobs/{id}/findings/{id}/arkime-link
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.job import Job

AUTH = {"Authorization": "Bearer test-token-v2"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _uid() -> str:
    return str(uuid.uuid4())


def _insert_job(db, job_id: str) -> Job:
    job = Job(
        job_id=job_id,
        job_name="Test",
        status="completed",
        execution_profile="standard",
        priority="normal",
        pcap_filename="test.pcap",
        pcap_size_bytes=1024,
        pcap_sha256="abc",
        created_at=_now(),
    )
    db.add(job)
    db.commit()
    return job


def _insert_alert(db, job_id: str, alert_id: str, **kwargs) -> Alert:
    alert = Alert(
        job_id=job_id,
        alert_id=alert_id,
        host_ip="10.0.0.1",
        severity="high",
        signature="ET MALWARE Test",
        ts=_now(),
        **kwargs,
    )
    db.add(alert)
    db.commit()
    return alert


def _insert_finding(db, job_id: str, finding_id: str, **kwargs) -> Finding:
    finding = Finding(
        job_id=job_id,
        finding_id=finding_id,
        sensor="suricata",
        severity="high",
        title="Test Finding",
        **kwargs,
    )
    db.add(finding)
    db.commit()
    return finding


# ---------------------------------------------------------------------------
# Arkime disabled — all endpoints should return enabled=false gracefully
# ---------------------------------------------------------------------------


class TestArkimeDisabled:
    """When arkime_enabled=False, endpoints return enabled=false."""

    def test_import_disabled(self, app_client):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)

        with patch("backend.app.connectors.ArkimeConnector") as MockCls:
            mock = MockCls.return_value
            mock.enabled = False
            r = client.post(f"/api/v1/jobs/{job_id}/arkime/import", headers=AUTH)

        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is False
        assert body["import_status"] == "not_imported"

    def test_status_disabled(self, app_client):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)

        with patch("backend.app.connectors.ArkimeConnector") as MockCls:
            mock = MockCls.return_value
            mock.enabled = False
            r = client.get(f"/api/v1/jobs/{job_id}/arkime/status", headers=AUTH)

        assert r.status_code == 200
        assert r.json()["enabled"] is False

    def test_alert_link_disabled(self, app_client):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)
        _insert_alert(db, job_id, "a-1", community_id="1:abc")

        with patch("backend.app.connectors.ArkimeConnector") as MockCls:
            mock = MockCls.return_value
            mock.enabled = False
            r = client.get(
                f"/api/v1/jobs/{job_id}/alerts/a-1/arkime-link", headers=AUTH
            )

        assert r.status_code == 200
        assert r.json()["enabled"] is False

    def test_finding_link_disabled(self, app_client):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)
        _insert_finding(db, job_id, "f-1", community_id="1:abc")

        with patch("backend.app.connectors.ArkimeConnector") as MockCls:
            mock = MockCls.return_value
            mock.enabled = False
            r = client.get(
                f"/api/v1/jobs/{job_id}/findings/f-1/arkime-link", headers=AUTH
            )

        assert r.status_code == 200
        assert r.json()["enabled"] is False


class TestArkimeImport:
    """POST /jobs/{id}/arkime/import — enabled scenarios."""

    def test_import_queues_pcaps(self, app_client, tmp_dirs):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)

        # Create job dir with a PCAP in input/
        job_dir = tmp_dirs["job_root"] / job_id / "input"
        job_dir.mkdir(parents=True)
        (job_dir / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

        with patch("backend.app.connectors.ArkimeConnector") as MockCls:
            mock = MockCls.return_value
            mock.enabled = True
            mock.import_enabled = True
            mock.get_import_status.return_value = {"status": "not_imported"}
            mock.queue_import.return_value = "queued"

            r = client.post(f"/api/v1/jobs/{job_id}/arkime/import", headers=AUTH)

        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is True
        assert body["import_status"] == "queued"
        mock.queue_import.assert_called_once()

    def test_import_no_pcaps(self, app_client, tmp_dirs):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)

        # Job dir exists but no PCAPs
        job_dir = tmp_dirs["job_root"] / job_id / "input"
        job_dir.mkdir(parents=True)

        with patch("backend.app.connectors.ArkimeConnector") as MockCls:
            mock = MockCls.return_value
            mock.enabled = True
            mock.import_enabled = True

            r = client.post(f"/api/v1/jobs/{job_id}/arkime/import", headers=AUTH)

        assert r.status_code == 200
        body = r.json()
        assert body["import_status"] == "not_imported"
        assert "No PCAP" in body["message"]

    def test_import_already_queued(self, app_client, tmp_dirs):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)

        job_dir = tmp_dirs["job_root"] / job_id / "input"
        job_dir.mkdir(parents=True)
        (job_dir / "test.pcap").write_bytes(b"\x00" * 50)

        with patch("backend.app.connectors.ArkimeConnector") as MockCls:
            mock = MockCls.return_value
            mock.enabled = True
            mock.import_enabled = True
            mock.get_import_status.return_value = {"status": "queued"}

            r = client.post(f"/api/v1/jobs/{job_id}/arkime/import", headers=AUTH)

        assert r.status_code == 200
        assert r.json()["import_status"] == "queued"
        assert "already" in r.json()["message"].lower()
        mock.queue_import.assert_not_called()

    def test_import_job_not_found(self, app_client):
        client, _ = app_client
        with patch("backend.app.connectors.ArkimeConnector") as MockCls:
            mock = MockCls.return_value
            mock.enabled = True
            mock.import_enabled = True
            r = client.post("/api/v1/jobs/nonexistent/arkime/import", headers=AUTH)
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Status endpoint — enabled
# ---------------------------------------------------------------------------


class TestArkimeStatus:
    def test_status_not_imported(self, app_client):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)

        with patch("backend.app.connectors.ArkimeConnector") as MockCls:
            mock = MockCls.return_value
            mock.enabled = True
            mock.get_import_status.return_value = {"status": "not_imported"}

            r = client.get(f"/api/v1/jobs/{job_id}/arkime/status", headers=AUTH)

        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is True
        assert body["import_status"] == "not_imported"

    def test_status_imported(self, app_client):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)

        with patch("backend.app.connectors.ArkimeConnector") as MockCls:
            mock = MockCls.return_value
            mock.enabled = True
            mock.get_import_status.return_value = {
                "status": "imported",
                "imported_at": "2026-03-25T12:00:00Z",
                "pcap_count": 2,
            }

            r = client.get(f"/api/v1/jobs/{job_id}/arkime/status", headers=AUTH)

        assert r.status_code == 200
        body = r.json()
        assert body["import_status"] == "imported"
        assert body["pcap_count"] == 2

    def test_status_job_not_found(self, app_client):
        client, _ = app_client
        with patch("backend.app.connectors.ArkimeConnector") as MockCls:
            mock = MockCls.return_value
            mock.enabled = True
            r = client.get("/api/v1/jobs/nonexistent/arkime/status", headers=AUTH)
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Alert pivot link
# ---------------------------------------------------------------------------


class TestAlertArkimeLink:
    def test_pivot_community_id(self, app_client):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)
        _insert_alert(db, job_id, "a-1", community_id="1:abc123")

        with patch("backend.app.connectors.ArkimeConnector") as MockCls, \
             patch("backend.app.config_v2.get_settings") as mock_settings:
            mock = MockCls.return_value
            mock.enabled = True
            mock.build_pivot_url.return_value = (
                "http://arkime:8005/sessions?expression=communityId%20%3D%3D%201%3Aabc123",
                "community_id",
            )
            mock.get_import_status.return_value = {"status": "imported"}
            mock_settings.return_value.aipam_job_root = Path("/tmp/test-jobs")

            r = client.get(
                f"/api/v1/jobs/{job_id}/alerts/a-1/arkime-link", headers=AUTH
            )

        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is True
        assert body["basis"] == "community_id"
        assert body["url"] is not None
        assert body["import_status"] == "imported"

    def test_pivot_five_tuple(self, app_client):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)
        _insert_alert(
            db, job_id, "a-2",
            src_ip="10.0.0.1", src_port=12345,
            dest_ip="192.168.1.1", dest_port=443,
            proto="tcp",
        )

        with patch("backend.app.connectors.ArkimeConnector") as MockCls, \
             patch("backend.app.config_v2.get_settings") as mock_settings:
            mock = MockCls.return_value
            mock.enabled = True
            mock.build_pivot_url.return_value = (
                "http://arkime:8005/sessions?expression=ip.src%20%3D%3D%2010.0.0.1",
                "five_tuple",
            )
            mock.get_import_status.return_value = {"status": "not_imported"}
            mock_settings.return_value.aipam_job_root = Path("/tmp/test-jobs")

            r = client.get(
                f"/api/v1/jobs/{job_id}/alerts/a-2/arkime-link", headers=AUTH
            )

        assert r.status_code == 200
        body = r.json()
        assert body["basis"] == "five_tuple"
        assert body["message"] is not None  # "PCAPs must be imported..."

    def test_alert_not_found(self, app_client):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)
        with patch("backend.app.connectors.ArkimeConnector") as MockCls:
            mock = MockCls.return_value
            mock.enabled = True
            r = client.get(
                f"/api/v1/jobs/{job_id}/alerts/nope/arkime-link", headers=AUTH
            )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Finding pivot link
# ---------------------------------------------------------------------------


class TestFindingArkimeLink:
    def test_pivot_community_id(self, app_client):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)
        _insert_finding(db, job_id, "f-1", community_id="1:xyz789")

        with patch("backend.app.connectors.ArkimeConnector") as MockCls, \
             patch("backend.app.config_v2.get_settings") as mock_settings:
            mock = MockCls.return_value
            mock.enabled = True
            mock.build_pivot_url.return_value = (
                "http://arkime:8005/sessions?expression=communityId%20%3D%3D%201%3Axyz789",
                "community_id",
            )
            mock.get_import_status.return_value = {"status": "imported"}
            mock_settings.return_value.aipam_job_root = Path("/tmp/test-jobs")

            r = client.get(
                f"/api/v1/jobs/{job_id}/findings/f-1/arkime-link", headers=AUTH
            )

        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is True
        assert body["basis"] == "community_id"
        assert body["url"] is not None

    def test_pivot_five_tuple_from_evidence(self, app_client):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)
        evidence = json.dumps({
            "src_ip": "10.0.0.5",
            "src_port": 54321,
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "proto": "udp",
        })
        _insert_finding(db, job_id, "f-2", evidence_json=evidence)

        with patch("backend.app.connectors.ArkimeConnector") as MockCls, \
             patch("backend.app.config_v2.get_settings") as mock_settings:
            mock = MockCls.return_value
            mock.enabled = True
            mock.build_pivot_url.return_value = (
                "http://arkime:8005/sessions?expression=ip.src%20%3D%3D%2010.0.0.5",
                "five_tuple",
            )
            mock.get_import_status.return_value = {"status": "not_imported"}
            mock_settings.return_value.aipam_job_root = Path("/tmp/test-jobs")

            r = client.get(
                f"/api/v1/jobs/{job_id}/findings/f-2/arkime-link", headers=AUTH
            )

        assert r.status_code == 200
        body = r.json()
        assert body["basis"] == "five_tuple"
        # Verify 5-tuple args were passed to build_pivot_url
        call_kwargs = mock.build_pivot_url.call_args.kwargs
        assert call_kwargs["src_ip"] == "10.0.0.5"
        assert call_kwargs["dest_port"] == 53

    def test_finding_not_found(self, app_client):
        client, db = app_client
        job_id = _uid()
        _insert_job(db, job_id)
        with patch("backend.app.connectors.ArkimeConnector") as MockCls:
            mock = MockCls.return_value
            mock.enabled = True
            r = client.get(
                f"/api/v1/jobs/{job_id}/findings/nope/arkime-link", headers=AUTH
            )
        assert r.status_code == 404
