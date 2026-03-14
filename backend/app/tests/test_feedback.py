"""Tests for Phase 3 Analyst Feedback Loop — verify endpoint + FindingDB status."""

import pytest

from datetime import datetime
from sqlmodel import Session, create_engine, SQLModel

from app.db_models import FindingDB


# -------------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------------


def make_finding_db(finding_id: str = "finding-001", **overrides) -> FindingDB:
    """Create a FindingDB row for feedback tests."""
    defaults = {
        "id": finding_id,
        "job_id": "job-test",
        "mitre_technique_id": "T1071.001",
        "severity": "high",
        "title": "Suspicious C2 traffic",
        "description": "TLS beaconing pattern detected",
        "affected_hosts": {"192.168.1.100": "victim"},
        "confidence": 0.85,
        "analyzer_source": "ollama",
        "created_at": datetime(2025, 6, 1),
        "analyst_status": "unverified",
    }
    defaults.update(overrides)
    return FindingDB(**defaults)


@pytest.fixture
def feedback_session():
    """In-memory SQLite session for feedback tests."""
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


# -------------------------------------------------------------------------
# FindingDB analyst_status field
# -------------------------------------------------------------------------

class TestFindingDBAnalystStatus:
    """Direct DB operations for analyst feedback."""

    def test_default_status_is_unverified(self, feedback_session):
        """New findings default to 'unverified'."""
        f = make_finding_db()
        feedback_session.add(f)
        feedback_session.commit()
        feedback_session.refresh(f)

        assert f.analyst_status == "unverified"
        assert f.analyst_notes is None

    def test_confirm_finding(self, feedback_session):
        """Analyst can confirm a finding."""
        f = make_finding_db()
        feedback_session.add(f)
        feedback_session.commit()

        f.analyst_status = "confirmed"
        f.analyst_notes = "Verified by analyst — C2 confirmed"
        feedback_session.add(f)
        feedback_session.commit()
        feedback_session.refresh(f)

        assert f.analyst_status == "confirmed"
        assert "C2 confirmed" in f.analyst_notes

    def test_mark_false_positive(self, feedback_session):
        """Analyst can mark a finding as false positive."""
        f = make_finding_db()
        feedback_session.add(f)
        feedback_session.commit()

        f.analyst_status = "false_positive"
        f.analyst_notes = "Normal CDN traffic, not C2"
        feedback_session.add(f)
        feedback_session.commit()
        feedback_session.refresh(f)

        assert f.analyst_status == "false_positive"

    def test_status_is_queryable(self, feedback_session):
        """Analyst status is indexed and queryable."""
        from sqlmodel import select

        confirmed = make_finding_db("f-confirmed", analyst_status="confirmed")
        unverified = make_finding_db("f-unverified", analyst_status="unverified")
        false_pos = make_finding_db("f-fp", analyst_status="false_positive")

        feedback_session.add_all([confirmed, unverified, false_pos])
        feedback_session.commit()

        results = feedback_session.exec(
            select(FindingDB).where(FindingDB.analyst_status == "confirmed")
        ).all()
        assert len(results) == 1
        assert results[0].id == "f-confirmed"


class TestFindingVerifyRequest:
    """Validate the schemas for verify requests."""

    def test_valid_request(self):
        from app.schemas import FindingVerifyRequest

        req = FindingVerifyRequest(status="confirmed", notes="Looks legit")
        assert req.status == "confirmed"
        assert req.notes == "Looks legit"

    def test_status_values(self):
        from app.schemas import VALID_ANALYST_STATUSES

        assert "unverified" in VALID_ANALYST_STATUSES
        assert "confirmed" in VALID_ANALYST_STATUSES
        assert "false_positive" in VALID_ANALYST_STATUSES
