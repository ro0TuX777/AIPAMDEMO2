from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import asyncio

import httpx

from app.connectors import SecurityOnionConnector


def test_find_pcaps_filters_by_time_and_sensors(tmp_path, monkeypatch):
    """Filesystem mode: honor sensors and time_range using mtime.

    Layout:
      base/
        sensor1/old.pcap (before window)
        sensor1/new.pcap (within window)
        sensor2/other.pcap (within window)
    """

    base = tmp_path / "pcap"
    base.mkdir()

    sensor1 = base / "sensor1"
    sensor2 = base / "sensor2"
    sensor1.mkdir()
    sensor2.mkdir()

    old_pcap = sensor1 / "old.pcap"
    new_pcap = sensor1 / "new.pcap"
    other_pcap = sensor2 / "other.pcap"

    old_pcap.write_bytes(b"old")
    new_pcap.write_bytes(b"new")
    other_pcap.write_bytes(b"other")

    start_dt = datetime(2025, 5, 1, 10, 0, tzinfo=timezone.utc)
    mid_dt = datetime(2025, 5, 1, 10, 30, tzinfo=timezone.utc)
    end_dt = datetime(2025, 5, 1, 11, 0, tzinfo=timezone.utc)

    os.utime(old_pcap, (start_dt.timestamp() - 3600, start_dt.timestamp() - 3600))
    os.utime(new_pcap, (mid_dt.timestamp(), mid_dt.timestamp()))
    os.utime(other_pcap, (mid_dt.timestamp(), mid_dt.timestamp()))

    monkeypatch.setenv("SECURITY_ONION_MODE", "filesystem")
    monkeypatch.setenv("SECURITY_ONION_PCAP_PATH", str(base))

    connector = SecurityOnionConnector()
    time_range = {"start": "2025-05-01T10:00:00Z", "end": "2025-05-01T11:00:00Z"}

    # When requesting sensor1 only, we should get just new.pcap.
    pcaps_sensor1 = connector.find_pcaps(time_range=time_range, sensors=["sensor1"])
    assert [p.name for p in pcaps_sensor1] == ["new.pcap"]

    # When requesting all sensors (empty list), we should get new.pcap and other.pcap.
    pcaps_all = connector.find_pcaps(time_range=time_range, sensors=[])
    names_all = {p.name for p in pcaps_all}
    assert names_all == {"new.pcap", "other.pcap"}


class _DummyResponse:
    def __init__(self, content: bytes, links: Dict[str, Dict[str, str]] | None = None) -> None:
        self._content = content
        self._links = links or {}

    @property
    def content(self) -> bytes:
        return self._content

    def raise_for_status(self) -> None:  # pragma: no cover - trivial
        return None

    @property
    def links(self) -> Dict[str, Dict[str, str]]:
        return self._links


class _DummyAsyncClient:
    """Minimal async client that captures calls and simulates pagination."""

    def __init__(self, *args, **kwargs) -> None:  # pragma: no cover - wiring only
        self.calls: List[tuple[str, Dict[str, object] | None, Dict[str, str] | None]] = []

    async def __aenter__(self) -> "_DummyAsyncClient":  # pragma: no cover - trivial
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # pragma: no cover - trivial
        return None

    async def get(self, url: str, params: Dict[str, object] | None = None, headers: Dict[str, str] | None = None) -> _DummyResponse:
        self.calls.append((url, params, headers))
        # First call returns a next link; second call does not.
        if len(self.calls) == 1:
            return _DummyResponse(b"page1", {"next": {"url": "https://example/api/pcap?page=2"}})
        return _DummyResponse(b"page2", {})


def test_fetch_pcaps_via_api_uses_filters_and_pagination(monkeypatch):
    monkeypatch.setenv("SECURITY_ONION_API_URL", "https://example/api/pcap")
    monkeypatch.setenv("SECURITY_ONION_API_TOKEN", "TOKEN")

    dummy_client = _DummyAsyncClient()

    def _client_factory(*args, **kwargs):  # pragma: no cover - simple factory
        return dummy_client

    monkeypatch.setattr(httpx, "AsyncClient", _client_factory)

    connector = SecurityOnionConnector()
    time_range = {"start": "2025-05-01T10:00:00Z", "end": "2025-05-01T11:00:00Z"}
    sensors = ["sensor1", "sensor2"]

    blobs = asyncio.run(connector.fetch_pcaps_via_api(time_range=time_range, sensors=sensors))

    assert blobs == [b"page1", b"page2"]

    # First call should include filters and auth header.
    first_url, first_params, first_headers = dummy_client.calls[0]
    assert first_url == "https://example/api/pcap"
    assert first_params is not None
    assert first_params.get("start") == time_range["start"]
    assert first_params.get("end") == time_range["end"]
    assert first_params.get("sensor") == sensors
    assert first_headers is not None
    assert first_headers.get("Authorization") == "Bearer TOKEN"

    # Second call should follow the next link URL and not send params again.
    second_url, second_params, _ = dummy_client.calls[1]
    assert second_url == "https://example/api/pcap?page=2"
    assert second_params == {}

