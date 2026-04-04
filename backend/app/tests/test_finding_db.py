"""Tests for FindingDB and PipelineCheckpointDB CRUD operations."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from backend.app.db_models import FindingDB, PipelineCheckpointDB


@pytest.fixture
def session():
    """Create an in-memory SQLite session for testing."""
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


class TestFindingDB:
    def test_create_and_read(self, session: Session):
        """Can create a FindingDB row and read it back."""
        finding = FindingDB(
            id="f-001",
            job_id="j-001",
            mitre_technique_id="T1071.001",
            mitre_technique_name="Web Protocols",
            classification="IcedID",
            severity="high",
            title="C2 Beacon",
            description="Detected C2 beaconing",
            evidence=["HTTPS to 185.X.X.X"],
            affected_hosts=["192.168.1.100"],
            confidence=0.85,
            analyzer_source="ollama",
            attack_chain_stage="command_and_control",
            created_at=datetime.now(timezone.utc),
        )
        session.add(finding)
        session.commit()

        result = session.get(FindingDB, "f-001")
        assert result is not None
        assert result.mitre_technique_id == "T1071.001"
        assert result.classification == "IcedID"
        assert result.confidence == 0.85

    def test_query_by_technique(self, session: Session):
        """Can query findings by MITRE technique ID."""
        now = datetime.now(timezone.utc)
        for i in range(3):
            session.add(FindingDB(
                id=f"f-{i}",
                job_id=f"j-{i % 2}",
                mitre_technique_id="T1071.001",
                severity="high",
                title=f"Finding {i}",
                description="Test",
                analyzer_source="ollama",
                created_at=now,
            ))
        session.add(FindingDB(
            id="f-other",
            job_id="j-0",
            mitre_technique_id="T1190",
            severity="critical",
            title="Different technique",
            description="Test",
            analyzer_source="ollama",
            created_at=now,
        ))
        session.commit()

        results = session.exec(
            select(FindingDB).where(FindingDB.mitre_technique_id == "T1071.001")
        ).all()
        assert len(results) == 3

    def test_query_by_job(self, session: Session):
        """Can query all findings for a specific job."""
        now = datetime.now(timezone.utc)
        for i in range(5):
            session.add(FindingDB(
                id=f"f-{i}",
                job_id="target-job",
                severity="medium",
                title=f"Finding {i}",
                description="Test",
                analyzer_source="ollama",
                created_at=now,
            ))
        session.add(FindingDB(
            id="f-other-job",
            job_id="other-job",
            severity="low",
            title="Other job finding",
            description="Test",
            analyzer_source="ollama",
            created_at=now,
        ))
        session.commit()

        results = session.exec(
            select(FindingDB).where(FindingDB.job_id == "target-job")
        ).all()
        assert len(results) == 5


class TestPipelineCheckpointDB:
    def test_create_checkpoint(self, session: Session):
        """Can create a pipeline checkpoint."""
        cp = PipelineCheckpointDB(
            id="j-001:ingest",
            job_id="j-001",
            step_name="ingest",
            state_data={"pcap_paths": ["/tmp/test.pcap"]},
            completed_at=datetime.now(timezone.utc),
        )
        session.add(cp)
        session.commit()

        result = session.get(PipelineCheckpointDB, "j-001:ingest")
        assert result is not None
        assert result.state_data["pcap_paths"] == ["/tmp/test.pcap"]

    def test_load_all_checkpoints_for_job(self, session: Session):
        """Can load all completed checkpoints for a job."""
        now = datetime.now(timezone.utc)
        for step in ["ingest", "parse", "aggregate"]:
            session.add(PipelineCheckpointDB(
                id=f"j-002:{step}",
                job_id="j-002",
                step_name=step,
                state_data={"step": step},
                completed_at=now,
            ))
        session.commit()

        results = session.exec(
            select(PipelineCheckpointDB).where(
                PipelineCheckpointDB.job_id == "j-002"
            )
        ).all()
        assert len(results) == 3
        step_names = {r.step_name for r in results}
        assert step_names == {"ingest", "parse", "aggregate"}

    def test_upsert_checkpoint(self, session: Session):
        """Updating a checkpoint replaces state_data."""
        cp = PipelineCheckpointDB(
            id="j-003:parse",
            job_id="j-003",
            step_name="parse",
            state_data={"flow_count": 10},
            completed_at=datetime.now(timezone.utc),
        )
        session.add(cp)
        session.commit()

        # Update it
        existing = session.get(PipelineCheckpointDB, "j-003:parse")
        assert existing is not None
        existing.state_data = {"flow_count": 42, "alert_count": 5}
        session.add(existing)
        session.commit()

        updated = session.get(PipelineCheckpointDB, "j-003:parse")
        assert updated is not None
        assert updated.state_data["flow_count"] == 42
        assert updated.state_data["alert_count"] == 5
