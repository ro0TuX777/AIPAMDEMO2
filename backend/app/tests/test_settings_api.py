from __future__ import annotations

import httpx
import pytest
import pytest_asyncio

from app.main import app
from app import database as database_mod
from app.db_models import SettingsDB


@pytest_asyncio.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.mark.asyncio
async def test_get_settings_returns_defaults_when_empty(monkeypatch, tmp_path, client):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test_settings.db")

    from sqlmodel import SQLModel, create_engine, Session

    engine = create_engine(f"sqlite:///{tmp_path}/test_settings.db", echo=False)
    SQLModel.metadata.create_all(engine)
    database_mod.engine = engine

    # No SettingsDB row yet
    with Session(engine) as session:
        assert session.get(SettingsDB, 1) is None

    resp = await client.get("/api/v1/settings")
    assert resp.status_code == 200
    body = resp.json()
    # All fields should be present but None by default
    assert "llm_endpoint" in body
    assert body["llm_endpoint"] is None


@pytest.mark.asyncio
async def test_put_and_get_settings_round_trip(monkeypatch, tmp_path, client):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test_settings_roundtrip.db")

    from sqlmodel import SQLModel, create_engine, Session

    engine = create_engine(f"sqlite:///{tmp_path}/test_settings_roundtrip.db", echo=False)
    SQLModel.metadata.create_all(engine)
    database_mod.engine = engine

    payload = {
        "llm_endpoint": "http://llm.example/v1/chat/completions",
        "llm_model_name": "gpt-test",
        "llm_max_tokens": 1024,
        "llm_temperature": 0.2,
        "security_onion_mode": "filesystem",
        "security_onion_base_pcap_path": "/srv/aipam/so-pcaps",
        "arkime_api_url": "http://arkime.local:8005",
    }

    resp_put = await client.put("/api/v1/settings", json=payload)
    assert resp_put.status_code == 200, resp_put.text
    body_put = resp_put.json()
    assert body_put["llm_endpoint"] == payload["llm_endpoint"]
    assert body_put["arkime_api_url"] == payload["arkime_api_url"]

    # Verify persisted in DB
    with Session(engine) as session:
        row = session.get(SettingsDB, 1)
        assert row is not None
        assert row.values["llm_endpoint"] == payload["llm_endpoint"]

    # GET should now reflect stored values
    resp_get = await client.get("/api/v1/settings")
    assert resp_get.status_code == 200
    body_get = resp_get.json()
    assert body_get["llm_endpoint"] == payload["llm_endpoint"]
    assert body_get["arkime_api_url"] == payload["arkime_api_url"]


@pytest.mark.asyncio
async def test_put_settings_rejects_invalid_so_mode(monkeypatch, tmp_path, client):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test_settings_invalid_mode.db")

    from sqlmodel import SQLModel, create_engine

    engine = create_engine(f"sqlite:///{tmp_path}/test_settings_invalid_mode.db", echo=False)
    SQLModel.metadata.create_all(engine)
    database_mod.engine = engine

    payload = {"security_onion_mode": "bogus"}

    resp = await client.put("/api/v1/settings", json=payload)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "invalid security_onion_mode"


@pytest.mark.asyncio
async def test_test_llm_connection_endpoint(monkeypatch, tmp_path, client):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test_settings_llm_test.db")

    from sqlmodel import SQLModel, create_engine

    engine = create_engine(f"sqlite:///{tmp_path}/test_settings_llm_test.db", echo=False)
    SQLModel.metadata.create_all(engine)
    database_mod.engine = engine

    # Monkeypatch LLMClient to avoid real HTTP and force success
    import app.llm_client as llm_mod

    class _FakeLLMClient(llm_mod.LLMClient):  # type: ignore[misc]
        async def analyze_chunk(self, bundle):  # type: ignore[override]
            return {}

    monkeypatch.setattr(llm_mod, "LLMClient", _FakeLLMClient)

    payload = {
        "llm_endpoint": "http://fake-endpoint",
        "llm_model_name": "fake-model",
        "llm_max_tokens": 16,
        "llm_temperature": 0.1,
    }

    resp = await client.post("/api/v1/settings/test_llm", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
