"""Tests for TrafficLLM integration."""
from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from app.llm_client import classify_traffic_with_trafficllm


class _DummyAsyncClientTrafficLLM:
    """AsyncClient stub that returns TrafficLLM classification responses."""

    def __init__(self, classification: str = "Zeus", *args: Any, **kwargs: Any) -> None:
        self.classification = classification

    async def __aenter__(self) -> "_DummyAsyncClientTrafficLLM":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def post(self, *args: Any, **kwargs: Any) -> httpx.Response:
        payload = {
            "id": "chatcmpl-trafficllm",
            "object": "chat.completion",
            "created": 0,
            "model": "trafficllm",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": self.classification},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
        return httpx.Response(
            status_code=200,
            json=payload,
            request=httpx.Request("POST", "http://test"),
        )


class _DummyAsyncClientError:
    """AsyncClient stub that raises connection error."""

    async def __aenter__(self) -> "_DummyAsyncClientError":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def post(self, *args: Any, **kwargs: Any) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=httpx.Request("POST", "http://test"))


# Tests for classify_traffic_with_trafficllm function

def test_classify_traffic_mtd_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test successful malware traffic detection."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _DummyAsyncClientTrafficLLM("Zeus"))

    async def _run():
        return await classify_traffic_with_trafficllm(
            packet_hex="45 00 00 3c 1c 46",
            task="MTD",
            trafficllm_endpoint="http://test:8001/v1/chat/completions",
        )

    result = asyncio.run(_run())

    assert result["success"] is True
    assert result["task"] == "MTD"
    assert result["classification"] == "Zeus"


def test_classify_traffic_bnd_normal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test botnet detection returning normal traffic."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _DummyAsyncClientTrafficLLM("normal"))

    async def _run():
        return await classify_traffic_with_trafficllm(
            packet_hex="45 00 00 3c",
            task="BND",
            trafficllm_endpoint="http://test:8001/v1/chat/completions",
        )

    result = asyncio.run(_run())

    assert result["success"] is True
    assert result["task"] == "BND"
    assert result["classification"] == "normal"


def test_classify_traffic_evd_vpn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test VPN traffic detection."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _DummyAsyncClientTrafficLLM("skype"))

    async def _run():
        return await classify_traffic_with_trafficllm(
            packet_hex="45 00 00 3c",
            task="EVD",
            trafficllm_endpoint="http://test:8001/v1/chat/completions",
        )

    result = asyncio.run(_run())

    assert result["success"] is True
    assert result["task"] == "EVD"
    assert result["classification"] == "skype"


def test_classify_traffic_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test handling of connection errors."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _DummyAsyncClientError())

    async def _run():
        return await classify_traffic_with_trafficllm(
            packet_hex="45 00 00 3c",
            task="MTD",
            trafficllm_endpoint="http://unreachable:8001/v1/chat/completions",
        )

    result = asyncio.run(_run())

    assert result["success"] is False
    assert result["classification"] == "error"
    assert "error" in result


def test_classify_traffic_tbd_tor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test Tor behavior detection."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _DummyAsyncClientTrafficLLM("browsing"))

    async def _run():
        return await classify_traffic_with_trafficllm(
            packet_hex="45 00 00 3c",
            task="TBD",
            trafficllm_endpoint="http://test:8001/v1/chat/completions",
        )

    result = asyncio.run(_run())

    assert result["success"] is True
    assert result["task"] == "TBD"
    assert result["classification"] == "browsing"


# Tests for TrafficLLM API endpoints

import pytest_asyncio


@pytest_asyncio.fixture
async def test_client(tmp_path, monkeypatch):
    """Create a test client for the FastAPI app with a temporary database."""
    import httpx
    from app import database
    from app.main import app

    # Use a temporary database
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    # Reset the database engine
    database.engine = database.create_engine(f"sqlite:///{db_path}")
    database.init_db()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.mark.asyncio
async def test_trafficllm_status_unavailable(test_client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test TrafficLLM status when service is unavailable."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _DummyAsyncClientError())
    monkeypatch.setenv("TRAFFICLLM_ENDPOINT", "http://localhost:8001/v1/chat/completions")

    response = await test_client.get("/api/v1/trafficllm/status")
    assert response.status_code == 200
    data = response.json()
    assert data["available"] is False
    assert "MTD" in data["supported_tasks"]


@pytest.mark.asyncio
async def test_trafficllm_status_available(test_client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test TrafficLLM status when service is available."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _DummyAsyncClientTrafficLLM("ping"))
    monkeypatch.setenv("TRAFFICLLM_ENDPOINT", "http://localhost:8001/v1/chat/completions")

    response = await test_client.get("/api/v1/trafficllm/status")
    assert response.status_code == 200
    data = response.json()
    assert data["available"] is True
    assert data["endpoint"] == "http://localhost:8001/v1/chat/completions"


@pytest.mark.asyncio
async def test_trafficllm_classify_success(test_client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test successful traffic classification."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _DummyAsyncClientTrafficLLM("Zeus"))
    monkeypatch.setenv("TRAFFICLLM_ENDPOINT", "http://localhost:8001/v1/chat/completions")

    response = await test_client.post(
        "/api/v1/trafficllm/classify",
        json={"packet_hex": "45 00 00 3c", "task": "MTD"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["task"] == "MTD"
    assert data["classification"] == "Zeus"


@pytest.mark.asyncio
async def test_trafficllm_classify_invalid_task(test_client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test classification with invalid task type."""
    monkeypatch.setenv("TRAFFICLLM_ENDPOINT", "http://localhost:8001/v1/chat/completions")

    response = await test_client.post(
        "/api/v1/trafficllm/classify",
        json={"packet_hex": "45 00 00 3c", "task": "INVALID"},
    )
    assert response.status_code == 400
    assert "Invalid task" in response.json()["detail"]


@pytest.mark.asyncio
async def test_trafficllm_classify_batch(test_client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test batch traffic classification."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _DummyAsyncClientTrafficLLM("normal"))
    monkeypatch.setenv("TRAFFICLLM_ENDPOINT", "http://localhost:8001/v1/chat/completions")

    response = await test_client.post(
        "/api/v1/trafficllm/classify/batch",
        json={
            "packets": [
                {"packet_hex": "45 00 00 3c", "task": "MTD"},
                {"packet_hex": "45 00 00 3d", "task": "BND"},
                {"packet_hex": "45 00 00 3e", "task": "EVD"},
            ]
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert data["successful"] == 3
    assert len(data["results"]) == 3


@pytest.mark.asyncio
async def test_trafficllm_test_connection_success(test_client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test TrafficLLM connection test endpoint."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _DummyAsyncClientTrafficLLM("normal"))
    monkeypatch.setenv("TRAFFICLLM_ENDPOINT", "http://localhost:8001/v1/chat/completions")

    response = await test_client.post(
        "/api/v1/settings/test_trafficllm",
        json={"trafficllm_endpoint": "http://localhost:8001/v1/chat/completions"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["test_result"] == "normal"


@pytest.mark.asyncio
async def test_trafficllm_test_connection_failure(test_client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test TrafficLLM connection test when service is unavailable."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _DummyAsyncClientError())

    response = await test_client.post(
        "/api/v1/settings/test_trafficllm",
        json={"trafficllm_endpoint": "http://unreachable:8001/v1/chat/completions"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is False
    assert "error" in data
