"""
Tests for the LanceDB-based flow vectorstore.

Exercises embed_flows, retrieve_relevant_flows, flow_to_text,
and lifecycle helpers (delete_flow_index, job_has_flow_index).
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

lancedb = pytest.importorskip("lancedb", reason="lancedb not installed")

from backend.app.domain_models import AlertRecord, FlowRecord
from backend.app.flow_vectorstore import (
    _humanize_bytes,
    _table_name,
    delete_flow_index,
    embed_flows,
    flow_to_text,
    job_has_flow_index,
    retrieve_relevant_flows,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

NOW = datetime.now(timezone.utc)


def _make_flow(
    *,
    id: str = "flow-1",
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    src_port: int = 49152,
    dst_port: int = 443,
    transport_proto: str = "tcp",
    app_proto: str = "tls",
    bytes_from_src: int = 2048,
    bytes_from_dst: int = 15360,
    duration_sec: float = 4.2,
    state: str | None = "established",
    tcp_flags_summary: str | None = "SAPF",
    tags: list[str] | None = None,
) -> FlowRecord:
    return FlowRecord(
        id=id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        transport_proto=transport_proto,
        app_proto=app_proto,
        start_time=NOW,
        end_time=NOW,
        duration_sec=duration_sec,
        bytes_from_src=bytes_from_src,
        bytes_from_dst=bytes_from_dst,
        packets_from_src=10,
        packets_from_dst=20,
        state=state,
        tcp_flags_summary=tcp_flags_summary,
        tags=tags or [],
    )


def _make_alert(
    *,
    id: str = "alert-1",
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    signature_name: str = "ET MALWARE C2 Beacon",
    severity: str = "high",
) -> AlertRecord:
    return AlertRecord(
        id=id,
        timestamp=NOW,
        src_ip=src_ip,
        dst_ip=dst_ip,
        alert_source="Suricata",
        signature_name=signature_name,
        severity=severity,
    )


# 384-dim fake embeddings (matches all-MiniLM-L6-v2 output dimension)
EMBED_DIM = 384


def _fake_encode(texts, **kwargs):
    """Return deterministic vectors: each text maps to a unique direction."""
    vecs = []
    for i, _ in enumerate(texts):
        vec = np.zeros(EMBED_DIM, dtype=np.float32)
        vec[i % EMBED_DIM] = 1.0
        vecs.append(vec)
    return np.array(vecs)


@pytest.fixture()
def mock_embedding_model():
    model = MagicMock()
    model.encode = _fake_encode
    return model


@pytest.fixture()
def lance_dir(tmp_path):
    """Provide a clean LanceDB directory and patch settings + model."""
    lance_path = tmp_path / "lance_store"
    lance_path.mkdir()

    mock_settings = MagicMock()
    mock_settings.file_storage_path = tmp_path
    mock_settings.vector_store_path = None
    mock_settings.embedding_model_name = "sentence-transformers/all-MiniLM-L6-v2"
    mock_settings.embedding_model_path = None

    import backend.app.flow_vectorstore as fvs

    # Reset module singletons
    fvs._lance_db = None
    fvs._embedding_model = None

    with patch.object(fvs, "_get_embedding_model") as mock_get_model:
        mock_model = MagicMock()
        mock_model.encode = _fake_encode
        mock_get_model.return_value = mock_model

        with patch("app.flow_vectorstore.get_effective_settings", return_value=mock_settings):
            yield tmp_path

    # Reset after test
    fvs._lance_db = None
    fvs._embedding_model = None


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------


class TestFlowToText:
    def test_basic_serialization(self) -> None:
        flow = _make_flow()
        text = flow_to_text(flow)
        assert "TCP" in text
        assert "192.168.1.10:49152" in text
        assert "10.0.0.1:443" in text
        assert "app=tls" in text
        assert "2.0KB" in text
        assert "duration=4.2s" in text
        assert "flags=SAPF" in text
        assert "state=established" in text

    def test_alert_context_appended(self) -> None:
        flow = _make_flow()
        alert = _make_alert()
        text = flow_to_text(flow, related_alerts=[alert])
        assert "ALERTS:" in text
        assert "C2 Beacon" in text
        assert "[high]" in text

    def test_no_optional_fields(self) -> None:
        flow = _make_flow(
            tcp_flags_summary=None,
            state=None,
            app_proto="",
        )
        text = flow_to_text(flow)
        assert "flags=" not in text
        assert "state=" not in text
        # Should still have the direction
        assert "TCP" in text


class TestHumanizeBytes:
    def test_bytes(self) -> None:
        assert _humanize_bytes(500) == "500B"

    def test_kilobytes(self) -> None:
        assert _humanize_bytes(2048) == "2.0KB"

    def test_megabytes(self) -> None:
        assert _humanize_bytes(5 * 1024 * 1024) == "5.0MB"


class TestTableName:
    def test_sanitizes_dashes(self) -> None:
        assert _table_name("abc-def-123") == "flows_abc_def_123"

    def test_truncates_long_ids(self) -> None:
        name = _table_name("a" * 100)
        assert len(name) <= 56  # prefix(6) + 50


# ---------------------------------------------------------------------------
# Integration tests (require LanceDB on disk)
# ---------------------------------------------------------------------------


class TestEmbedAndRetrieve:
    def test_embed_flows_creates_table(self, lance_dir) -> None:
        flows = [_make_flow(id=f"f{i}") for i in range(5)]
        count = embed_flows("job-1", flows, alerts=[])
        assert count == 5
        assert job_has_flow_index("job-1")

    def test_empty_flows_returns_zero(self, lance_dir) -> None:
        count = embed_flows("job-empty", [], alerts=[])
        assert count == 0

    def test_retrieve_returns_results(self, lance_dir) -> None:
        flows = [
            _make_flow(id="normal", dst_port=80, app_proto="http"),
            _make_flow(id="c2", dst_port=443, app_proto="tls", bytes_from_src=100),
            _make_flow(id="dns", dst_port=53, app_proto="dns", transport_proto="udp"),
        ]
        embed_flows("job-search", flows)

        results = retrieve_relevant_flows("job-search", "DNS traffic", top_k=3)
        assert len(results) > 0
        assert all("vector" not in r for r in results)

    def test_retrieve_with_filter(self, lance_dir) -> None:
        flows = [
            _make_flow(id="http", dst_port=80, app_proto="http"),
            _make_flow(id="tls", dst_port=443, app_proto="tls"),
            _make_flow(id="dns", dst_port=53, app_proto="dns"),
        ]
        embed_flows("job-filter", flows)

        results = retrieve_relevant_flows(
            "job-filter", "encrypted traffic", top_k=10, filters="dst_port = 443"
        )
        assert len(results) >= 1
        assert all(r["dst_port"] == 443 for r in results)

    def test_retrieve_nonexistent_job(self, lance_dir) -> None:
        results = retrieve_relevant_flows("job-doesnt-exist", "anything")
        assert results == []

    def test_embed_with_alerts(self, lance_dir) -> None:
        flows = [_make_flow(id="suspect")]
        alerts = [_make_alert(src_ip="192.168.1.10")]
        count = embed_flows("job-alerts", flows, alerts=alerts)
        assert count == 1

        results = retrieve_relevant_flows("job-alerts", "malware C2", top_k=1)
        assert len(results) == 1
        assert results[0]["has_alerts"] is True

    def test_reindex_replaces_table(self, lance_dir) -> None:
        flows = [_make_flow(id="v1")]
        embed_flows("job-reindex", flows)
        assert job_has_flow_index("job-reindex")

        # Re-index with different data
        new_flows = [_make_flow(id=f"v2-{i}") for i in range(3)]
        count = embed_flows("job-reindex", new_flows)
        assert count == 3


class TestLifecycle:
    def test_delete_flow_index(self, lance_dir) -> None:
        flows = [_make_flow()]
        embed_flows("job-del", flows)
        assert job_has_flow_index("job-del")

        assert delete_flow_index("job-del") is True
        assert not job_has_flow_index("job-del")

    def test_delete_nonexistent(self, lance_dir) -> None:
        # Should not raise
        result = delete_flow_index("job-nope")
        assert result is False

    def test_has_index_false_for_missing(self, lance_dir) -> None:
        assert not job_has_flow_index("missing-job")
