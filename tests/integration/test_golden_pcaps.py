"""Phase 5 — Integration tests with golden PCAPs.

These tests exercise the full V2 API round-trip:
  upload → validate → create job → query detail → query sub-resources

They do NOT require Docker or real sensors — they test the API layer
and DB persistence using the FastAPI TestClient.
"""

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

os.environ.setdefault("AIPAM_API_TOKEN", "test-token-v2")

from backend.app.config_v2 import Settings, get_settings
from backend.app.database_v2 import Base, _set_sqlite_pragmas, get_db
from backend.app.main_v2 import create_app

TOKEN = "test-token-v2"
AUTH = {"Authorization": f"Bearer {TOKEN}"}

GOLDEN_DIR = Path(__file__).parent.parent / "fixtures" / "golden"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def integration_client(tmp_path):
    """Full TestClient backed by in-memory DB + temp dirs."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(bind=engine)

    connection = engine.connect()
    app = create_app()

    def _override_db():
        db = Session(bind=connection)
        try:
            yield db
        finally:
            db.close()

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    job_dir = tmp_path / "jobs"
    job_dir.mkdir()

    settings = Settings(
        aipam_api_token=TOKEN,
        aipam_upload_root=upload_dir,
        aipam_job_root=job_dir,
        aipam_db_path=Path("/tmp/unused.db"),
    )

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_settings] = lambda: settings

    client = TestClient(app)
    db = Session(bind=connection)
    yield client, db
    db.close()
    connection.close()
    engine.dispose()


def _upload_pcap(client: TestClient, pcap_path: Path) -> dict:
    """Upload a PCAP and return the response JSON."""
    data = pcap_path.read_bytes()
    r = client.post(
        f"/api/v1/uploads?filename={pcap_path.name}",
        content=data,
        headers=AUTH,
    )
    assert r.status_code == 201, f"Upload failed: {r.text}"
    return r.json()


def _validate_upload(client: TestClient, upload_id: str) -> dict:
    """Validate an upload and return the response JSON."""
    r = client.post(f"/api/v1/uploads/{upload_id}/validate", headers=AUTH)
    assert r.status_code == 200, f"Validate failed: {r.text}"
    return r.json()


def _create_job(client: TestClient, upload_id: str, profile: str = "standard") -> dict:
    """Create a job from an upload and return the response JSON."""
    r = client.post(
        "/api/v1/jobs",
        json={"upload_id": upload_id, "execution_profile": profile, "job_name": "integration-test"},
        headers=AUTH,
    )
    assert r.status_code == 201, f"Create job failed: {r.text}"
    return r.json()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGoldenPcapUploadValidate:
    """Test that all golden PCAPs pass the upload → validate flow."""

    @pytest.mark.parametrize("pcap_name", [
        "small_benign.pcap",
        "dns_queries.pcap",
        "mixed_traffic.pcap",
        "empty_valid.pcap",
        "large_synthetic.pcap",
    ])
    def test_upload_and_validate(self, integration_client, pcap_name, expected_findings):
        client, db = integration_client
        pcap_path = GOLDEN_DIR / pcap_name
        if not pcap_path.exists():
            pytest.skip(f"Golden PCAP {pcap_name} not generated")

        # Upload
        upload_resp = _upload_pcap(client, pcap_path)
        assert "upload_id" in upload_resp
        assert upload_resp["filename"] == pcap_name

        # Validate
        val_resp = _validate_upload(client, upload_resp["upload_id"])
        expected = expected_findings.get(pcap_name, {})
        assert val_resp["is_valid"] == expected.get("is_valid", True)
        if expected.get("format"):
            assert val_resp["format"] == expected["format"]


class TestFullApiRoundTrip:
    """Upload → validate → create job → query job detail and sub-resources."""

    def test_round_trip_standard_profile(self, integration_client):
        client, db = integration_client
        pcap_path = GOLDEN_DIR / "small_benign.pcap"
        if not pcap_path.exists():
            pytest.skip("Golden PCAP not generated")

        # 1. Upload
        upload = _upload_pcap(client, pcap_path)
        upload_id = upload["upload_id"]

        # 2. Validate
        val = _validate_upload(client, upload_id)
        assert val["is_valid"] is True

        # 3. Create job
        job = _create_job(client, upload_id, "standard")
        job_id = job["job_id"]
        assert job_id

        # 4. Get job detail
        r = client.get(f"/api/v1/jobs/{job_id}", headers=AUTH)
        assert r.status_code == 200
        detail = r.json()
        assert detail["job"]["job_id"] == job_id
        assert detail["job"]["status"] == "queued"
        assert detail["job"]["execution_profile"] == "standard"
        assert detail["job"]["pcap_filename"] == "small_benign.pcap"

        # 5. List jobs — should contain our job
        r = client.get("/api/v1/jobs", headers=AUTH)
        assert r.status_code == 200
        jobs = r.json()
        assert any(j["job_id"] == job_id for j in jobs["items"])

        # 6. Query sub-resources (should return empty lists, not errors)
        for sub in ["hosts", "findings", "timeline", "iocs", "sensors"]:
            r = client.get(f"/api/v1/jobs/{job_id}/{sub}", headers=AUTH)
            assert r.status_code == 200, f"GET /jobs/{job_id}/{sub} failed: {r.text}"
            body = r.json()
            assert "items" in body

    def test_round_trip_triage_profile(self, integration_client):
        client, db = integration_client
        pcap_path = GOLDEN_DIR / "dns_queries.pcap"
        if not pcap_path.exists():
            pytest.skip("Golden PCAP not generated")

        upload = _upload_pcap(client, pcap_path)
        val = _validate_upload(client, upload["upload_id"])
        assert val["is_valid"] is True

        job = _create_job(client, upload["upload_id"], "triage")
        r = client.get(f"/api/v1/jobs/{job['job_id']}", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["job"]["execution_profile"] == "triage"

    def test_round_trip_deep_profile(self, integration_client):
        client, db = integration_client
        pcap_path = GOLDEN_DIR / "mixed_traffic.pcap"
        if not pcap_path.exists():
            pytest.skip("Golden PCAP not generated")

        upload = _upload_pcap(client, pcap_path)
        _validate_upload(client, upload["upload_id"])
        job = _create_job(client, upload["upload_id"], "deep")
        r = client.get(f"/api/v1/jobs/{job['job_id']}", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["job"]["execution_profile"] == "deep"


class TestJobLifecycle:
    """Test job state transitions: cancel, delete, rerun."""

    def test_cancel_queued_job(self, integration_client):
        client, db = integration_client
        pcap_path = GOLDEN_DIR / "small_benign.pcap"

        upload = _upload_pcap(client, pcap_path)
        _validate_upload(client, upload["upload_id"])
        job = _create_job(client, upload["upload_id"])
        job_id = job["job_id"]

        # Cancel
        r = client.post(f"/api/v1/jobs/{job_id}/cancel", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["job"]["status"] == "canceled"

        # Verify persisted
        r = client.get(f"/api/v1/jobs/{job_id}", headers=AUTH)
        assert r.json()["job"]["status"] == "canceled"

    def test_delete_completed_job(self, integration_client):
        client, db = integration_client
        pcap_path = GOLDEN_DIR / "small_benign.pcap"

        upload = _upload_pcap(client, pcap_path)
        _validate_upload(client, upload["upload_id"])
        job = _create_job(client, upload["upload_id"])
        job_id = job["job_id"]

        # Cancel first (can't delete running)
        client.post(f"/api/v1/jobs/{job_id}/cancel", headers=AUTH)

        # Delete
        r = client.delete(f"/api/v1/jobs/{job_id}", headers=AUTH)
        assert r.status_code == 204


class TestEdgeCases:
    """Edge cases and error handling."""

    def test_invalid_upload_id_for_job(self, integration_client):
        client, db = integration_client
        r = client.post(
            "/api/v1/jobs",
            json={"upload_id": "nonexistent", "execution_profile": "standard"},
            headers=AUTH,
        )
        assert r.status_code == 400

    def test_get_nonexistent_job(self, integration_client):
        client, db = integration_client
        r = client.get("/api/v1/jobs/nonexistent-id", headers=AUTH)
        assert r.status_code == 404

    def test_empty_upload_rejected(self, integration_client):
        client, db = integration_client
        r = client.post(
            "/api/v1/uploads",
            content=b"",
            headers={**AUTH, "Content-Disposition": 'attachment; filename="empty.pcap"'},
        )
        assert r.status_code == 400

    def test_upload_without_auth_rejected(self, integration_client):
        client, db = integration_client
        pcap_path = GOLDEN_DIR / "small_benign.pcap"
        data = pcap_path.read_bytes()
        r = client.post("/api/v1/uploads", content=data)
        assert r.status_code in (401, 403)

    def test_job_summary_empty(self, integration_client):
        """Summary endpoint should return default response for fresh job."""
        client, db = integration_client
        pcap_path = GOLDEN_DIR / "small_benign.pcap"

        upload = _upload_pcap(client, pcap_path)
        _validate_upload(client, upload["upload_id"])
        job = _create_job(client, upload["upload_id"])

        r = client.get(f"/api/v1/jobs/{job['job_id']}/summary", headers=AUTH)
        assert r.status_code == 200

