import pytest
import pytest_asyncio
import httpx
from unittest.mock import MagicMock

from app.main import app as real_app

@pytest_asyncio.fixture
async def client():
    transport = httpx.ASGITransport(app=real_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client

@pytest.mark.asyncio
async def test_health_check_all_ok(monkeypatch, tmp_path, client):
    # Mock settings
    class MockSettings:
        aipam_job_root = tmp_path
        aipam_disk_critical_pct = 95
        aipam_ollama_url = "http://mock-ollama"

    monkeypatch.setattr("app.api.system.get_settings", lambda: MockSettings())
    
    # Mock disk usage
    import shutil
    monkeypatch.setattr(shutil, "disk_usage", lambda x: (100, 10, 90))

    # Mock DB
    class MockSession:
        def __enter__(self): return self
        def __exit__(self, exc_type, exc_val, exc_tb): pass
        def exec(self, q):
            m = MagicMock()
            m.all.return_value = [1]
            return m
    monkeypatch.setattr("app.api.system.get_session", MockSession)

    # Mock Celery
    class MockCeleryApp:
        def connection(self):
            class MockConn:
                def __enter__(self): return self
                def __exit__(self, exc_type, exc_val, exc_tb): pass
                def heartbeat_check(self, timeout): pass
            return MockConn()
    monkeypatch.setattr("app.api.system.celery_app", MockCeleryApp())

    # Mock httpx
    class MockResponse:
        status_code = 200
    class MockAsyncClient:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return MockResponse()
    monkeypatch.setattr("httpx.AsyncClient", MockAsyncClient)

    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["disk_ok"] is True
    assert data["db_ok"] is True
    assert data["redis_ok"] is True
    assert data["docker_ok"] is True
    assert data["ollama_ok"] is True

@pytest.mark.asyncio
async def test_health_check_degraded(monkeypatch, tmp_path, client):
    # Same mocks but make some fail
    class MockSettings:
        aipam_job_root = tmp_path
        aipam_disk_critical_pct = 95
        aipam_ollama_url = "http://mock-ollama"

    monkeypatch.setattr("app.api.system.get_settings", lambda: MockSettings())
    
    # Mock disk usage (Critical)
    import shutil
    monkeypatch.setattr(shutil, "disk_usage", lambda x: (100, 99, 1))

    # Mock DB (Exception)
    def mock_get_session():
        raise Exception("DB Down")
    monkeypatch.setattr("app.api.system.get_session", mock_get_session)

    # Mock Celery (None or exception)
    monkeypatch.setattr("app.api.system.celery_app", None)

    # Mock httpx (Ollama down)
    class MockResponse:
        status_code = 500
    class MockAsyncClient:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return MockResponse()
    monkeypatch.setattr("httpx.AsyncClient", MockAsyncClient)

    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["disk_ok"] is False
    assert data["db_ok"] is False
    assert data["redis_ok"] is False
    assert data["docker_ok"] is False
    assert data["ollama_ok"] is False
