"""Authenticated API tests for MNEMOS evidence receipt history."""

import pytest
import asyncio
import httpx

from backend.app.config_v2 import Settings, get_settings
from backend.app.main_v2 import create_app
from backend.app.services.mnemos_evidence_receipts import (
    build_evidence_receipt,
    write_evidence_receipt,
)


@pytest.fixture
def receipt_client(tmp_path):
    settings = Settings(_env_file=None, aipam_api_token="test-token",
                        mnemos_evidence_receipt_dir=tmp_path / "receipts")
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    async def send(method, path, **kwargs):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, path, **kwargs)

    return lambda method, path, **kwargs: asyncio.run(send(method, path, **kwargs)), settings.mnemos_evidence_receipt_dir


def _write(receipt_dir, receipt_id, created_at):
    receipt = build_evidence_receipt(
        receipt_id=receipt_id, created_at=created_at, job_id="job-1",
        conversation_id="conversation-1", assistant_message_id="message-1",
        request_id=None, query=f"question {receipt_id}", answer=f"answer {receipt_id}",
        model_id="model-1", generation=None, runtime=None, retrieval_status="complete",
        citations=[], evidence_refs=[],
    )
    write_evidence_receipt(receipt_dir, receipt, max_files=1)
    return receipt


def test_history_returns_active_and_archived_receipts_in_paginated_order(receipt_client):
    request, receipt_dir = receipt_client
    _write(receipt_dir, "receipt-old", "2026-01-01T00:00:00Z")
    _write(receipt_dir, "receipt-mid", "2026-01-02T00:00:00Z")
    _write(receipt_dir, "receipt-new", "2026-01-03T00:00:00Z")
    (receipt_dir / "broken.json").write_text("{bad json", encoding="utf-8")

    first = request("GET", "/api/v1/mnemos/evidence-receipts?limit=2",
                    headers={"Authorization": "Bearer test-token"})
    assert first.status_code == 200
    body = first.json()
    assert [item["receipt_id"] for item in body["items"]] == ["receipt-new", "receipt-mid"]
    assert body["page"]["has_more"] is True
    assert body["page"]["next_cursor"]
    assert all("/" not in str(item) for item in body["items"])

    second = request("GET", "/api/v1/mnemos/evidence-receipts",
                     params={"limit": 2, "cursor": body["page"]["next_cursor"]},
                     headers={"Authorization": "Bearer test-token"})
    assert second.status_code == 200
    assert [item["receipt_id"] for item in second.json()["items"]] == ["receipt-old"]
    assert second.json()["page"] == {"next_cursor": None, "has_more": False}


def test_detail_returns_full_receipt_from_archive(receipt_client):
    request, receipt_dir = receipt_client
    archived = _write(receipt_dir, "receipt-old", "2026-01-01T00:00:00Z")
    _write(receipt_dir, "receipt-new", "2026-01-02T00:00:00Z")

    response = request("GET", "/api/v1/mnemos/evidence-receipts/receipt-old",
                       headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    assert response.json() == archived


def test_receipt_routes_require_valid_bearer_token(receipt_client):
    request, _ = receipt_client
    for headers in ({}, {"Authorization": "Bearer wrong-token"}):
        history = request("GET", "/api/v1/mnemos/evidence-receipts", headers=headers)
        detail = request("GET", "/api/v1/mnemos/evidence-receipts/receipt-one", headers=headers)
        assert history.status_code == detail.status_code == 401


def test_invalid_cursor_and_receipt_ids_are_client_errors(receipt_client):
    request, _ = receipt_client
    headers = {"Authorization": "Bearer test-token"}
    response = request("GET", "/api/v1/mnemos/evidence-receipts?cursor=not-a-cursor", headers=headers)
    assert response.status_code == 400
    for receipt_id in ("missing", "../secret", "%2e%2e%2fsecret"):
        response = request("GET", f"/api/v1/mnemos/evidence-receipts/{receipt_id}", headers=headers)
        assert response.status_code == 404


def test_history_limit_is_bounded_and_missing_receipt_is_not_found(receipt_client):
    request, _ = receipt_client
    headers = {"Authorization": "Bearer test-token"}
    too_large = request("GET", "/api/v1/mnemos/evidence-receipts?limit=101", headers=headers)
    assert too_large.status_code == 422
    missing = request("GET", "/api/v1/mnemos/evidence-receipts/absent", headers=headers)
    assert missing.status_code == 404
