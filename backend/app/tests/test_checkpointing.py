"""Tests for pipeline checkpointing helpers."""

from __future__ import annotations


import pytest
from sqlmodel import Session, SQLModel, create_engine

from app.db_models import PipelineCheckpointDB


@pytest.fixture
def session():
    """Create an in-memory SQLite session for testing."""
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


# Import the helpers we want to test.  They live in tasks.py but we test them
# in isolation by calling them with our own sessions.
from app.tasks import _save_checkpoint, _load_checkpoints, _clear_checkpoints


class TestSaveCheckpoint:
    def test_creates_new_checkpoint(self, session: Session):
        """Saving a checkpoint for a new step creates a row."""
        _save_checkpoint(session, "j-001", "ingest", {"pcap_paths": ["/tmp/a.pcap"]})

        result = session.get(PipelineCheckpointDB, "j-001:ingest")
        assert result is not None
        assert result.state_data["pcap_paths"] == ["/tmp/a.pcap"]
        assert result.completed_at is not None

    def test_upserts_existing_checkpoint(self, session: Session):
        """Saving to an existing step updates the state_data."""
        _save_checkpoint(session, "j-002", "parse", {"flow_count": 10})
        _save_checkpoint(session, "j-002", "parse", {"flow_count": 42, "alert_count": 5})

        result = session.get(PipelineCheckpointDB, "j-002:parse")
        assert result is not None
        assert result.state_data["flow_count"] == 42
        assert result.state_data["alert_count"] == 5


class TestLoadCheckpoints:
    def test_loads_completed_checkpoints(self, session: Session):
        """Load returns only steps with completed_at set."""
        _save_checkpoint(session, "j-010", "ingest", {"pcap_paths": []})
        _save_checkpoint(session, "j-010", "parse", {"flow_count": 5})

        # Add an incomplete checkpoint manually
        incomplete = PipelineCheckpointDB(
            id="j-010:aggregate",
            job_id="j-010",
            step_name="aggregate",
            state_data={},
            completed_at=None,
        )
        session.add(incomplete)
        session.commit()

        checkpoints = _load_checkpoints(session, "j-010")
        assert "ingest" in checkpoints
        assert "parse" in checkpoints
        assert "aggregate" not in checkpoints  # incomplete

    def test_empty_for_no_checkpoints(self, session: Session):
        """Returns empty dict when no checkpoints exist."""
        checkpoints = _load_checkpoints(session, "nonexistent-job")
        assert checkpoints == {}


class TestClearCheckpoints:
    def test_clear_all(self, session: Session):
        """Clearing without from_step removes all checkpoints."""
        for step in ["ingest", "parse", "aggregate", "llm_analysis"]:
            _save_checkpoint(session, "j-020", step, {"step": step})

        deleted = _clear_checkpoints(session, "j-020")
        assert deleted == 4

        remaining = _load_checkpoints(session, "j-020")
        assert remaining == {}

    def test_clear_from_step(self, session: Session):
        """Clearing from a step removes that step and all subsequent ones."""
        for step in ["ingest", "parse", "aggregate", "llm_analysis", "report"]:
            _save_checkpoint(session, "j-030", step, {"step": step})

        deleted = _clear_checkpoints(session, "j-030", from_step="aggregate")
        assert deleted == 3  # aggregate, llm_analysis, report

        remaining = _load_checkpoints(session, "j-030")
        assert set(remaining.keys()) == {"ingest", "parse"}

    def test_clear_does_not_affect_other_jobs(self, session: Session):
        """Clearing checkpoints for one job doesn't touch another."""
        _save_checkpoint(session, "j-040", "ingest", {"a": 1})
        _save_checkpoint(session, "j-041", "ingest", {"b": 2})

        _clear_checkpoints(session, "j-040")

        assert _load_checkpoints(session, "j-040") == {}
        assert "ingest" in _load_checkpoints(session, "j-041")
