"""Tests for app/core/guardrails.py — anti-hallucination validation."""

import pytest

from datetime import datetime

from sqlmodel import Session, create_engine, SQLModel

from backend.app.core.interfaces import Finding
from backend.app.core.guardrails import FlowExistenceGuardrail
from backend.app.db_models import FlowDB


# -------------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------------


def make_finding(**overrides):
    """Create a test Finding."""
    defaults = {
        "mitre_technique_id": "T1071.001",
        "confidence_score": 0.85,
        "raw_evidence_snippet": "TCP 192.168.1.100 → 10.0.0.1:443",
        "rationale": "Suspicious TLS traffic",
        "severity": "high",
        "cited_flow_ids": [],
    }
    defaults.update(overrides)
    return Finding(**defaults)


def make_flow(flow_id: str, **overrides):
    """Create a FlowDB row with all required fields."""
    defaults = {
        "id": flow_id,
        "job_id": "job",
        "src_ip": "192.168.1.100",
        "src_port": 49152,
        "dst_ip": "10.0.0.1",
        "dst_port": 443,
        "transport_proto": "TCP",
        "app_proto": "TLS",
        "start_time": datetime(2025, 1, 1, 0, 0, 0),
        "end_time": datetime(2025, 1, 1, 0, 1, 0),
        "duration_sec": 60.0,
        "bytes_from_src": 1024,
        "bytes_from_dst": 2048,
        "packets_from_src": 10,
        "packets_from_dst": 15,
    }
    defaults.update(overrides)
    return FlowDB(**defaults)


@pytest.fixture
def in_memory_session():
    """Create an in-memory SQLite session with FlowDB table."""
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


# -------------------------------------------------------------------------
# FlowExistenceGuardrail
# -------------------------------------------------------------------------

class TestFlowExistenceGuardrail:
    """Anti-hallucination: verify cited flow IDs exist in FlowDB."""

    def test_valid_flow_ids_pass(self, in_memory_session):
        """Findings citing real flow IDs pass without flag."""
        in_memory_session.add(make_flow("job:CdHxBc1234abcde"))
        in_memory_session.commit()

        finding = make_finding(cited_flow_ids=["job:CdHxBc1234abcde"])
        guardrail = FlowExistenceGuardrail()
        result = guardrail.validate(finding, in_memory_session)

        assert result.requires_review is False
        assert result.review_reason is None

    def test_hallucinated_flow_ids_flagged(self, in_memory_session):
        """Findings citing non-existent flow IDs are flagged for review."""
        finding = make_finding(
            cited_flow_ids=["fake:DOES_NOT_EXIST_123"]
        )
        guardrail = FlowExistenceGuardrail()
        result = guardrail.validate(finding, in_memory_session)

        assert result.requires_review is True
        assert "DOES_NOT_EXIST_123" in result.review_reason

    def test_mixed_valid_and_hallucinated(self, in_memory_session):
        """Partially hallucinated citations still flag for review."""
        in_memory_session.add(make_flow("job:RealFlow1234abcd"))
        in_memory_session.commit()

        finding = make_finding(
            cited_flow_ids=["job:RealFlow1234abcd", "job:FakeFlow9999xxxx"]
        )
        guardrail = FlowExistenceGuardrail()
        result = guardrail.validate(finding, in_memory_session)

        assert result.requires_review is True
        assert "FakeFlow9999xxxx" in result.review_reason

    def test_no_cited_ids_passes(self, in_memory_session):
        """Findings without any cited flow IDs pass through unchanged."""
        finding = make_finding(cited_flow_ids=[])
        guardrail = FlowExistenceGuardrail()
        result = guardrail.validate(finding, in_memory_session)

        assert result.requires_review is False

    def test_no_session_fails_open(self):
        """Without a DB session, the guardrail is skipped (fail-open)."""
        finding = make_finding(
            cited_flow_ids=["maybe:HallucinatedID"]
        )
        guardrail = FlowExistenceGuardrail()
        result = guardrail.validate(finding, session=None)

        # Fail-open: not flagged without a session
        assert result.requires_review is False
