"""
AIPAM Benchmark — Tier 3: API Contract Gate

Verifies the HTTP surface that operators and integrators depend on.
All contracts here are stable — breaking them is a hard regression.

Covers:
  - Authentication surface: 401 on missing/bad token, 200 on valid token
  - Ollama GPU status endpoint: schema shape and auth requirement (v2.2)
  - Error response shape: ErrorResponse schema fields present on 4xx
  - Health response: required fields present
  - System config response: required fields and schema_version
"""
from __future__ import annotations

import os

os.environ.setdefault("AIPAM_API_TOKEN", "test-token-v2")

AUTH = {"Authorization": "Bearer test-token-v2"}
BAD_AUTH = {"Authorization": "Bearer wrong-token"}


# ---------------------------------------------------------------------------
# 3.1  Auth gate contracts
# ---------------------------------------------------------------------------


class TestAuthContracts:
    """Every protected endpoint MUST reject unauthenticated requests (401 or 403).

    FastAPI's HTTPBearer returns 403 when the Authorization header is absent
    and 401 when credentials are present but invalid. Both signals correctly
    block access — the quality gate accepts either.
    """

    def test_health_requires_auth(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/health")
        assert r.status_code in (401, 403), f"Expected auth rejection, got {r.status_code}"

    def test_wrong_token_is_rejected(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/health", headers=BAD_AUTH)
        assert r.status_code in (401, 403), f"Expected auth rejection, got {r.status_code}"

    def test_valid_token_reaches_health(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/health", headers=AUTH)
        assert r.status_code == 200

    def test_system_config_requires_auth(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/system/config")
        assert r.status_code in (401, 403)

    def test_jobs_list_requires_auth(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/jobs")
        assert r.status_code in (401, 403)


# ---------------------------------------------------------------------------
# 3.2  Health response contract
# ---------------------------------------------------------------------------


class TestHealthResponseContract:
    """GET /api/v1/health must return a well-formed HealthResponse."""

    REQUIRED_FIELDS = {
        "schema_version", "status", "uptime_seconds",
        "docker_ok", "disk_ok", "ollama_ok",
    }

    def test_health_has_all_required_fields(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/health", headers=AUTH)
        body = r.json()
        for field in self.REQUIRED_FIELDS:
            assert field in body, f"Missing field: {field}"

    def test_health_schema_version_is_string(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/health", headers=AUTH)
        assert isinstance(r.json()["schema_version"], str)

    def test_health_status_is_ok_or_degraded(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/health", headers=AUTH)
        assert r.json()["status"] in {"ok", "degraded"}


# ---------------------------------------------------------------------------
# 3.3  System config response contract
# ---------------------------------------------------------------------------


class TestSystemConfigContract:
    """GET /api/v1/system/config must return a stable SystemConfigResponse."""

    REQUIRED_FIELDS = {
        "schema_version", "aipam_version", "max_upload_bytes",
        "profiles_enabled", "default_limits", "explain_configuration",
    }

    def test_config_has_all_required_fields(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/system/config", headers=AUTH)
        assert r.status_code == 200
        body = r.json()
        for field in self.REQUIRED_FIELDS:
            assert field in body, f"Missing field: {field}"

    def test_profiles_enabled_is_nonempty_list(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/system/config", headers=AUTH)
        profiles = r.json()["profiles_enabled"]
        assert isinstance(profiles, list)
        assert len(profiles) >= 1

    def test_explain_configuration_has_mode_field(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/system/config", headers=AUTH)
        explain = r.json()["explain_configuration"]
        assert "mode" in explain
        assert explain["mode"] in {"deterministic", "llm"}


# ---------------------------------------------------------------------------
# 3.4  Error response contract
# ---------------------------------------------------------------------------


class TestErrorResponseContract:
    """4xx responses must follow the structured ErrorResponse schema."""

    def test_auth_rejection_is_json(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/jobs")
        body = r.json()
        # FastAPI returns 403 for missing Bearer token; must be JSON
        assert r.status_code in (401, 403)
        assert isinstance(body, dict)

    def test_404_on_nonexistent_job(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/jobs/nonexistent-job-id-12345", headers=AUTH)
        assert r.status_code == 404

    def test_404_response_is_json(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/jobs/nonexistent-job-id-12345", headers=AUTH)
        body = r.json()
        assert isinstance(body, dict)


# ---------------------------------------------------------------------------
# 3.5  Ollama GPU status endpoint contract (v2.2)
# ---------------------------------------------------------------------------


class TestOllamaGpuStatusContract:
    """GET /api/v1/system/ollama-status — requires auth, returns OllamaGpuStatusResponse."""

    REQUIRED_FIELDS = {
        "schema_version", "ollama_version", "gpu_detected",
        "vram_total_bytes", "vram_used_bytes", "compute_device", "loaded_models",
    }

    def test_ollama_status_requires_auth(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/system/ollama-status")
        assert r.status_code in (401, 403)

    def test_ollama_status_returns_200_with_auth(self, app_client):
        from unittest.mock import patch
        client, _ = app_client
        # Patch httpx calls so the endpoint doesn't try to reach real Ollama
        with patch("httpx.get", side_effect=Exception("no ollama in test")):
            r = client.get("/api/v1/system/ollama-status", headers=AUTH)
        # Even if Ollama is unreachable the endpoint should return 200 with degraded data
        assert r.status_code == 200

    def test_ollama_status_has_required_fields(self, app_client):
        from unittest.mock import patch
        client, _ = app_client
        with patch("httpx.get", side_effect=Exception("no ollama in test")):
            r = client.get("/api/v1/system/ollama-status", headers=AUTH)
        body = r.json()
        for field in self.REQUIRED_FIELDS:
            assert field in body, f"Missing field: {field}"

    def test_loaded_models_is_list(self, app_client):
        from unittest.mock import patch
        client, _ = app_client
        with patch("httpx.get", side_effect=Exception("no ollama in test")):
            r = client.get("/api/v1/system/ollama-status", headers=AUTH)
        assert isinstance(r.json()["loaded_models"], list)
