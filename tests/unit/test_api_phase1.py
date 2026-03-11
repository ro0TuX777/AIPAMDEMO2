"""Phase 1 API endpoint tests: auth, uploads, jobs, health, system/config."""

import pytest

AUTH_HEADER = {"Authorization": "Bearer test-token-v2"}
BAD_AUTH = {"Authorization": "Bearer wrong-token"}

# PCAP magic bytes (little-endian standard pcap)
PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
PCAP_BODY = PCAP_MAGIC + b"\x00" * 100  # minimal valid-looking pcap


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

class TestAuth:
    def test_no_token_returns_403(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/health")
        assert r.status_code == 403

    def test_wrong_token_returns_401(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/health", headers=BAD_AUTH)
        assert r.status_code == 401

    def test_valid_token_returns_200(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/health", headers=AUTH_HEADER)
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Upload tests
# ---------------------------------------------------------------------------

class TestUploads:
    def test_upload_pcap(self, app_client):
        client, _ = app_client
        r = client.post(
            "/api/v1/uploads?filename=test.pcap",
            content=PCAP_BODY,
            headers={**AUTH_HEADER, "Content-Type": "application/octet-stream"},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["upload_id"]
        assert body["filename"] == "test.pcap"
        assert body["size_bytes"] == len(PCAP_BODY)
        assert body["sha256"]
        assert body["schema_version"] == "1.0"

    def test_upload_empty_body_returns_400(self, app_client):
        client, _ = app_client
        r = client.post(
            "/api/v1/uploads?filename=empty.pcap",
            content=b"",
            headers={**AUTH_HEADER, "Content-Type": "application/octet-stream"},
        )
        assert r.status_code == 400

    def test_validate_valid_pcap(self, app_client):
        client, _ = app_client
        # Upload first
        r = client.post(
            "/api/v1/uploads?filename=good.pcap",
            content=PCAP_BODY,
            headers={**AUTH_HEADER, "Content-Type": "application/octet-stream"},
        )
        upload_id = r.json()["upload_id"]

        # Validate
        r2 = client.post(
            f"/api/v1/uploads/{upload_id}/validate",
            headers=AUTH_HEADER,
        )
        assert r2.status_code == 200
        body = r2.json()
        assert body["is_valid"] is True
        assert body["format"] == "pcap"
        assert body["warnings"] == []

    def test_validate_invalid_file(self, app_client):
        client, _ = app_client
        r = client.post(
            "/api/v1/uploads?filename=bad.txt",
            content=b"this is not a pcap file at all!",
            headers={**AUTH_HEADER, "Content-Type": "application/octet-stream"},
        )
        upload_id = r.json()["upload_id"]

        r2 = client.post(
            f"/api/v1/uploads/{upload_id}/validate",
            headers=AUTH_HEADER,
        )
        assert r2.status_code == 200
        body = r2.json()
        assert body["is_valid"] is False
        assert len(body["warnings"]) > 0

    def test_validate_nonexistent_upload_returns_404(self, app_client):
        client, _ = app_client
        r = client.post(
            "/api/v1/uploads/nonexistent-id/validate",
            headers=AUTH_HEADER,
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Job tests
# ---------------------------------------------------------------------------

class TestJobs:
    def _create_upload(self, client):
        """Helper: upload a PCAP and return its upload_id."""
        r = client.post(
            "/api/v1/uploads?filename=test.pcap",
            content=PCAP_BODY,
            headers={**AUTH_HEADER, "Content-Type": "application/octet-stream"},
        )
        return r.json()["upload_id"]

    def test_create_job(self, app_client):
        client, _ = app_client
        uid = self._create_upload(client)
        r = client.post(
            "/api/v1/jobs",
            json={
                "upload_id": uid,
                "job_name": "My Analysis",
                "execution_profile": "standard",
            },
            headers=AUTH_HEADER,
        )
        assert r.status_code == 201
        body = r.json()
        assert body["job_id"]
        assert body["schema_version"] == "1.0"

    def test_create_job_invalid_upload_returns_400(self, app_client):
        client, _ = app_client
        r = client.post(
            "/api/v1/jobs",
            json={"upload_id": "fake-id", "execution_profile": "triage"},
            headers=AUTH_HEADER,
        )
        assert r.status_code == 400

    def test_list_jobs_empty(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/jobs", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["items"] == []
        assert body["page"]["has_more"] is False

    def test_list_jobs_with_data(self, app_client):
        client, _ = app_client
        uid = self._create_upload(client)
        # Create 3 jobs
        for i in range(3):
            client.post(
                "/api/v1/jobs",
                json={"upload_id": uid, "job_name": f"Job {i}", "execution_profile": "triage"},
                headers=AUTH_HEADER,
            )
        r = client.get("/api/v1/jobs", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert len(body["items"]) == 3

    def test_list_jobs_pagination(self, app_client):
        client, _ = app_client
        uid = self._create_upload(client)
        for i in range(5):
            client.post(
                "/api/v1/jobs",
                json={"upload_id": uid, "job_name": f"Job {i}", "execution_profile": "triage"},
                headers=AUTH_HEADER,
            )
        # Request limit=2
        r = client.get("/api/v1/jobs?limit=2", headers=AUTH_HEADER)
        body = r.json()
        assert len(body["items"]) == 2
        assert body["page"]["has_more"] is True
        assert body["page"]["next_cursor"] is not None

        # Fetch next page
        r2 = client.get(f"/api/v1/jobs?limit=2&cursor={body['page']['next_cursor']}", headers=AUTH_HEADER)
        body2 = r2.json()
        assert len(body2["items"]) == 2
        assert body2["page"]["has_more"] is True

    def test_get_job(self, app_client):
        client, _ = app_client
        uid = self._create_upload(client)
        r = client.post(
            "/api/v1/jobs",
            json={"upload_id": uid, "job_name": "Detail Test", "execution_profile": "deep"},
            headers=AUTH_HEADER,
        )
        job_id = r.json()["job_id"]

        r2 = client.get(f"/api/v1/jobs/{job_id}", headers=AUTH_HEADER)
        assert r2.status_code == 200
        body = r2.json()
        assert body["job"]["job_id"] == job_id
        assert body["job"]["job_name"] == "Detail Test"
        assert body["job"]["status"] == "queued"
        assert body["job"]["execution_profile"] == "deep"

    def test_get_job_not_found(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/jobs/nonexistent", headers=AUTH_HEADER)
        assert r.status_code == 404

    def test_list_jobs_status_filter(self, app_client):
        client, _ = app_client
        uid = self._create_upload(client)
        client.post(
            "/api/v1/jobs",
            json={"upload_id": uid, "job_name": "Queued Job", "execution_profile": "triage"},
            headers=AUTH_HEADER,
        )
        r = client.get("/api/v1/jobs?status=running", headers=AUTH_HEADER)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 0  # all jobs are queued

        r2 = client.get("/api/v1/jobs?status=queued", headers=AUTH_HEADER)
        assert r2.status_code == 200
        assert len(r2.json()["items"]) == 1


# ---------------------------------------------------------------------------
# Health & System tests
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_ok(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/health", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["status"] in ("ok", "degraded")
        assert body["schema_version"] == "1.0"
        assert isinstance(body["uptime_seconds"], int)
        assert "docker_ok" in body
        assert "disk_ok" in body
        assert "ollama_ok" in body


class TestSystemConfig:
    def test_system_config(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/system/config", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["aipam_version"] == "2.0.0"
        assert body["schema_version"] == "1.0"
        assert "triage" in body["profiles_enabled"]
        assert "standard" in body["profiles_enabled"]
        assert "deep" in body["profiles_enabled"]
        assert body["default_limits"]["max_job_disk_bytes"] > 0


# ---------------------------------------------------------------------------
# X-Request-Id tests
# ---------------------------------------------------------------------------

class TestRequestId:
    def test_request_id_echoed(self, app_client):
        client, _ = app_client
        r = client.get(
            "/api/v1/health",
            headers={**AUTH_HEADER, "X-Request-Id": "my-custom-id-123"},
        )
        assert r.headers.get("X-Request-Id") == "my-custom-id-123"

    def test_request_id_generated_when_missing(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/health", headers=AUTH_HEADER)
        rid = r.headers.get("X-Request-Id")
        assert rid is not None
        assert len(rid) > 0

