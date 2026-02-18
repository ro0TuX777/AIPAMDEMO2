"""Tests for app/core/correlation.py — Campaign Correlator."""

import pytest

from datetime import datetime
from sqlmodel import Session, create_engine, SQLModel

from app.core.correlation import CampaignCorrelator, CorrelationGroup, _extract_ips
from app.db_models import FindingDB


# -------------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------------


def make_finding_db(
    finding_id: str,
    job_id: str,
    mitre: str = "T1071.001",
    hosts: dict = None,
    **kwargs,
) -> FindingDB:
    """Create a FindingDB row for correlation testing."""
    defaults = {
        "id": finding_id,
        "job_id": job_id,
        "mitre_technique_id": mitre,
        "severity": "high",
        "title": f"Finding {finding_id}",
        "description": "Test finding",
        "affected_hosts": hosts or {"192.168.1.100": "victim"},
        "confidence": 0.9,
        "analyzer_source": "test",
        "created_at": datetime(2025, 6, 1),
    }
    defaults.update(kwargs)
    return FindingDB(**defaults)


@pytest.fixture
def correlation_session():
    """In-memory SQLite session for correlation tests."""
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


# -------------------------------------------------------------------------
# Unit: _extract_ips
# -------------------------------------------------------------------------

class TestExtractIPs:
    """IP extraction from FindingDB.affected_hosts variants."""

    def test_dict_keys(self):
        assert _extract_ips({"192.168.1.1": "victim", "10.0.0.1": "c2"}) == {
            "192.168.1.1",
            "10.0.0.1",
        }

    def test_list(self):
        assert _extract_ips(["192.168.1.1", "10.0.0.1"]) == {
            "192.168.1.1",
            "10.0.0.1",
        }

    def test_empty(self):
        assert _extract_ips({}) == set()


# -------------------------------------------------------------------------
# CampaignCorrelator
# -------------------------------------------------------------------------

class TestCampaignCorrelator:
    """Cross-job correlation grouping."""

    def test_correlates_same_technique_same_ip(self, correlation_session):
        """Two jobs with same technique + same IP → correlated."""
        f1 = make_finding_db("f1", "job-A", hosts={"192.168.1.100": "victim"})
        f2 = make_finding_db("f2", "job-B", hosts={"192.168.1.100": "victim"})
        correlation_session.add_all([f1, f2])
        correlation_session.commit()

        groups = CampaignCorrelator.correlate(correlation_session)
        assert len(groups) == 1
        g = groups[0]
        assert g.mitre_technique_id == "T1071.001"
        assert set(g.job_ids) == {"job-A", "job-B"}
        assert "192.168.1.100" in g.common_indicators
        assert g.confidence > 0

    def test_no_correlation_different_techniques(self, correlation_session):
        """Different techniques but same IP → no correlation."""
        f1 = make_finding_db("f1", "job-A", mitre="T1071.001")
        f2 = make_finding_db("f2", "job-B", mitre="T1059")
        correlation_session.add_all([f1, f2])
        correlation_session.commit()

        groups = CampaignCorrelator.correlate(correlation_session)
        # Each technique has only 1 job, so no groups
        assert len(groups) == 0

    def test_no_correlation_different_ips(self, correlation_session):
        """Same technique but different IPs → no correlation."""
        f1 = make_finding_db("f1", "job-A", hosts={"192.168.1.1": "a"})
        f2 = make_finding_db("f2", "job-B", hosts={"10.0.0.1": "b"})
        correlation_session.add_all([f1, f2])
        correlation_session.commit()

        groups = CampaignCorrelator.correlate(correlation_session)
        assert len(groups) == 0

    def test_no_correlation_same_job(self, correlation_session):
        """Two findings in same job don't form a cross-job group."""
        f1 = make_finding_db("f1", "job-A")
        f2 = make_finding_db("f2", "job-A")
        correlation_session.add_all([f1, f2])
        correlation_session.commit()

        groups = CampaignCorrelator.correlate(correlation_session)
        assert len(groups) == 0

    def test_correlate_for_job(self, correlation_session):
        """correlate_for_job filters groups by job_id."""
        f1 = make_finding_db("f1", "job-A")
        f2 = make_finding_db("f2", "job-B")
        f3 = make_finding_db("f3", "job-C", mitre="T1059")
        correlation_session.add_all([f1, f2, f3])
        correlation_session.commit()

        groups = CampaignCorrelator.correlate_for_job(
            correlation_session, "job-A"
        )
        assert len(groups) == 1
        assert "job-A" in groups[0].job_ids

        # job-C has a different technique, so no correlation
        groups_c = CampaignCorrelator.correlate_for_job(
            correlation_session, "job-C"
        )
        assert len(groups_c) == 0

    def test_three_job_correlation(self, correlation_session):
        """Three jobs with same technique + same IP → one group."""
        for i, jid in enumerate(["job-A", "job-B", "job-C"]):
            f = make_finding_db(f"f{i}", jid, hosts={"10.0.0.5": "c2"})
            correlation_session.add(f)
        correlation_session.commit()

        groups = CampaignCorrelator.correlate(correlation_session)
        assert len(groups) == 1
        assert len(groups[0].job_ids) == 3
        # Higher confidence with more jobs
        assert groups[0].confidence >= 0.9
