"""Tests for the partial results persistence module."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlmodel import Session, SQLModel, create_engine

from backend.app.partial_results import (
    delete_partial_result,
    get_partial_result,
    save_partial_result,
)


@pytest.fixture(autouse=True)
def _patch_engine(monkeypatch, tmp_path):
    """Create a throwaway SQLite database for each test."""
    db_path = tmp_path / "test.db"
    test_engine = create_engine(f"sqlite:///{db_path}")

    # Import all models so tables are registered
    from backend.app.db_models import (  # noqa: F401
        JobDB,
        JobResultDB,
        PartialJobResultDB,
    )

    SQLModel.metadata.create_all(test_engine)

    # Seed a parent JobDB row (required by FK)
    with Session(test_engine) as session:
        from backend.app.db_models import JobDB
        from backend.app.domain_models import JobStatus

        session.add(
            JobDB(
                id="test-job-1",
                source="upload",
                mode="single_window",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                status=JobStatus.RUNNING,
            )
        )
        session.commit()

    # Patch the engine used by partial_results
    import backend.app.partial_results as pr_mod
    monkeypatch.setattr(pr_mod, "get_engine", lambda: test_engine)

    return test_engine


class TestSaveAndGet:
    """save_partial_result / get_partial_result round-trip."""

    def test_save_and_retrieve(self):
        data = {"flow_count": 42, "alert_count": 5}
        save_partial_result("test-job-1", data)

        result = get_partial_result("test-job-1")
        assert result is not None
        assert result["flow_count"] == 42
        assert result["alert_count"] == 5

    def test_upsert_overwrites(self):
        save_partial_result("test-job-1", {"flow_count": 10})
        save_partial_result("test-job-1", {"flow_count": 99, "extra": True})

        result = get_partial_result("test-job-1")
        assert result is not None
        assert result["flow_count"] == 99
        assert result["extra"] is True

    def test_get_returns_none_when_missing(self):
        result = get_partial_result("nonexistent-id")
        assert result is None


class TestDelete:
    """delete_partial_result cleanup."""

    def test_delete_removes_row(self):
        save_partial_result("test-job-1", {"x": 1})
        assert get_partial_result("test-job-1") is not None

        delete_partial_result("test-job-1")
        assert get_partial_result("test-job-1") is None

    def test_delete_noop_when_missing(self):
        # Should not raise
        delete_partial_result("test-job-1")


class TestDataShape:
    """Verify the partial result can hold the expected pipeline data."""

    def test_full_shape(self):
        partial_data = {
            "flow_count": 12345,
            "alert_count": 87,
            "top_alerts": [
                {"signature_name": "ET MALWARE", "severity": "high", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
            ],
            "host_summaries": [
                {"ip": "10.0.0.1", "total_flows": 200, "alert_count": 3, "top_ports": [80, 443]},
            ],
            "anomaly_detection": {
                "findings": [{"category": "beaconing", "severity": "high"}],
                "overall_anomaly_score": 0.85,
                "zero_day_likelihood": "medium",
                "summary": "Suspicious beaconing detected",
            },
            "trafficllm": None,
        }
        save_partial_result("test-job-1", partial_data)
        result = get_partial_result("test-job-1")

        assert result is not None
        assert result["flow_count"] == 12345
        assert len(result["top_alerts"]) == 1
        assert result["anomaly_detection"]["overall_anomaly_score"] == 0.85
        assert result["trafficllm"] is None
