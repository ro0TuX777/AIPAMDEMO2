"""Tests for Evidence Store schema (FlowDB, AlertDB, EvidenceDB) and helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from app.db_models import AlertDB, EvidenceDB, FindingDB, FlowDB
from app.domain.evidence_store import link_evidence, persist_alerts, persist_flows
from app.models import AlertRecord, FlowRecord


@pytest.fixture
def db_session():
    """In-memory SQLite session for isolated testing."""
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture
def sample_flows() -> List[FlowRecord]:
    now = datetime.now(timezone.utc)
    return [
        FlowRecord(
            id="uid-001",
            src_ip="192.168.1.100", src_port=49152,
            dst_ip="185.70.40.20", dst_port=443,
            transport_proto="TCP", app_proto="TLS",
            start_time=now, end_time=now,
            duration_sec=120.5,
            bytes_from_src=15000, bytes_from_dst=250000,
            packets_from_src=150, packets_from_dst=200,
            tcp_flags_summary="ShADadFf",
            state="SF",
            extra={"missed_bytes": "0"},
        ),
        FlowRecord(
            id="uid-002",
            src_ip="192.168.1.100", src_port=50000,
            dst_ip="8.8.8.8", dst_port=53,
            transport_proto="UDP", app_proto="DNS",
            start_time=now, end_time=now,
            duration_sec=0.05,
            bytes_from_src=60, bytes_from_dst=200,
            packets_from_src=1, packets_from_dst=1,
            extra={},
        ),
    ]


@pytest.fixture
def sample_alerts() -> List[AlertRecord]:
    now = datetime.now(timezone.utc)
    return [
        AlertRecord(
            id="alert-001",
            timestamp=now,
            src_ip="192.168.1.100", dst_ip="185.70.40.20",
            src_port=49152, dst_port=443,
            alert_source="SURICATA",
            signature_id="2034636",
            signature_name="ET MALWARE IcedID Request Cookie",
            severity="high",
            category="A Network Trojan was Detected",
            extra={},
        ),
    ]


class TestFlowDB:
    def test_persist_flows_creates_rows(self, db_session, sample_flows):
        count = persist_flows(db_session, "job-001", sample_flows)
        assert count == 2

        rows = db_session.exec(select(FlowDB)).all()
        assert len(rows) == 2

    def test_flow_ids_are_composite(self, db_session, sample_flows):
        persist_flows(db_session, "job-001", sample_flows)
        row = db_session.get(FlowDB, "job-001:uid-001")
        assert row is not None
        assert row.src_ip == "192.168.1.100"
        assert row.dst_ip == "185.70.40.20"

    def test_flow_queryable_by_job(self, db_session, sample_flows):
        persist_flows(db_session, "job-001", sample_flows)
        persist_flows(db_session, "job-002", sample_flows)

        job1_flows = db_session.exec(
            select(FlowDB).where(FlowDB.job_id == "job-001")
        ).all()
        assert len(job1_flows) == 2

    def test_flow_queryable_by_dst_ip(self, db_session, sample_flows):
        persist_flows(db_session, "job-001", sample_flows)
        c2_flows = db_session.exec(
            select(FlowDB).where(FlowDB.dst_ip == "185.70.40.20")
        ).all()
        assert len(c2_flows) == 1
        assert c2_flows[0].dst_port == 443


class TestAlertDB:
    def test_persist_alerts_creates_rows(self, db_session, sample_alerts):
        count = persist_alerts(db_session, "job-001", sample_alerts)
        assert count == 1

    def test_alert_queryable_by_severity(self, db_session, sample_alerts):
        persist_alerts(db_session, "job-001", sample_alerts)
        high = db_session.exec(
            select(AlertDB).where(AlertDB.severity == "high")
        ).all()
        assert len(high) == 1
        assert "IcedID" in high[0].signature_name

    def test_alert_queryable_by_signature(self, db_session, sample_alerts):
        persist_alerts(db_session, "job-001", sample_alerts)
        rows = db_session.exec(
            select(AlertDB).where(AlertDB.signature_id == "2034636")
        ).all()
        assert len(rows) == 1


class TestEvidenceDB:
    def test_link_evidence_creates_rows(self, db_session, sample_flows):
        # Create a flow and a finding first
        persist_flows(db_session, "job-001", sample_flows)
        finding = FindingDB(
            id="finding-001",
            job_id="job-001",
            mitre_technique_id="T1071.001",
            severity="critical",
            title="C2 Communication",
            description="IcedID C2 over TLS",
            evidence={},
            affected_hosts={},
            confidence=0.92,
            analyzer_source="ollama",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(finding)
        db_session.commit()

        count = link_evidence(
            db_session,
            finding_id="finding-001",
            flow_ids=["job-001:uid-001"],
            relationship="supports",
            snippet="TCP 192.168.1.100:49152 → 185.70.40.20:443",
        )
        assert count == 1

        links = db_session.exec(
            select(EvidenceDB).where(EvidenceDB.finding_id == "finding-001")
        ).all()
        assert len(links) == 1
        assert links[0].flow_id == "job-001:uid-001"
        assert links[0].relationship == "supports"

    def test_many_to_many_multiple_flows(self, db_session, sample_flows):
        persist_flows(db_session, "job-001", sample_flows)
        finding = FindingDB(
            id="finding-002",
            job_id="job-001",
            mitre_technique_id="T1071.004",
            severity="medium",
            title="DNS Exfiltration",
            description="Suspicious DNS queries",
            evidence={},
            affected_hosts={},
            confidence=0.7,
            analyzer_source="ollama",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(finding)
        db_session.commit()

        count = link_evidence(
            db_session,
            finding_id="finding-002",
            flow_ids=["job-001:uid-001", "job-001:uid-002"],
        )
        assert count == 2
