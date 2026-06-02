"""Phase 3 tests — TelemetryCorrelator, EvidenceGraph extension, CorrelationPipeline.

Tests run against in-memory SQLite with the V2 schema.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session

from backend.app.database_v2 import Base, _set_sqlite_pragmas
from backend.app.models.job import Job
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.parsers.base import ParserResult
from backend.app.schemas.common import EvidenceStatus, NormalizedEventType, SourceType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _uid() -> str:
    return str(uuid.uuid4())


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@pytest.fixture()
def db():
    """In-memory V2 database session."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)
    yield session
    session.close()
    engine.dispose()


@pytest.fixture()
def job(db):
    """Insert a sample job."""
    j = Job(
        job_id=_uid(),
        job_name="Correlation Test",
        status="queued",
        execution_profile="standard",
        priority="normal",
        pcap_filename="test.pcap",
        pcap_size_bytes=0,
        pcap_sha256="abc",
        created_at=_now(),
    )
    db.add(j)
    db.commit()
    return j


def _make_result(
    event_type=NormalizedEventType.auth,
    source_system="sysmon",
    hostname="WS01",
    username="alice",
    src_ip="10.0.0.5",
    dest_ip=None,
    community_id=None,
    process_guid=None,
) -> ParserResult:
    return ParserResult(
        event_type=event_type,
        timestamp=datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        data={"detail": "test"},
        source_type=SourceType.log_bundle,
        source_system=source_system,
        parser_name=f"{source_system}_parser",
        parser_version="0.1.0",
        evidence_status=EvidenceStatus.observed,
        hostname=hostname,
        username=username,
        src_ip=src_ip,
        dest_ip=dest_ip,
        community_id=community_id,
        process_guid=process_guid,
    )


# ---------------------------------------------------------------------------
# TelemetryCorrelator — persistence
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_parser_result_to_db_basic(self, db, job):
        from backend.app.services.telemetry_correlator import parser_result_to_db
        r = _make_result()
        row = parser_result_to_db(r, job.job_id)
        assert row.event_id.startswith("NE-")
        assert row.event_type == "auth"
        assert row.source_system == "sysmon"
        assert row.hostname == "WS01"
        assert row.evidence_status == "observed"

    def test_persist_parser_results(self, db, job):
        from backend.app.services.telemetry_correlator import persist_parser_results
        results = [_make_result(), _make_result(username="bob")]
        rows = persist_parser_results(results, job.job_id, db)
        assert len(rows) == 2
        # Verify in DB
        count = db.execute(
            select(NormalizedEvent).where(NormalizedEvent.job_id == job.job_id)
        ).scalars().all()
        assert len(count) == 2

    def test_correlation_keys_json_populated(self, db, job):
        from backend.app.services.telemetry_correlator import parser_result_to_db
        r = _make_result(src_ip="192.168.1.1", hostname="MYHOST")
        row = parser_result_to_db(r, job.job_id)
        keys = json.loads(row.correlation_keys_json)
        assert keys["src_ip"] == "192.168.1.1"
        assert keys["hostname"] == "MYHOST"


# ---------------------------------------------------------------------------
# Correlation clusters
# ---------------------------------------------------------------------------

class TestCorrelationClusters:
    def test_cluster_by_shared_ip(self, db, job):
        from backend.app.services.telemetry_correlator import (
            build_correlation_clusters,
            persist_parser_results,
        )
        results = [
            _make_result(source_system="sysmon", src_ip="10.0.0.5"),
            _make_result(source_system="linux_auth", src_ip="10.0.0.5"),
        ]
        rows = persist_parser_results(results, job.job_id, db)
        clusters = build_correlation_clusters(rows)
        # Both events share src_ip so should form one cluster
        assert len(clusters) >= 1
        big = clusters[0]
        assert big["size"] == 2
        assert len(big["sources"]) == 2
        assert "src_ip" in big["shared_keys"]

    def test_no_cluster_for_disjoint(self, db, job):
        from backend.app.services.telemetry_correlator import (
            build_correlation_clusters,
            persist_parser_results,
        )
        results = [
            _make_result(source_system="sysmon", src_ip="10.0.0.5", hostname="A", username="alice"),
            _make_result(source_system="linux_auth", src_ip="10.0.0.99", hostname="B", username="bob"),
        ]
        rows = persist_parser_results(results, job.job_id, db)
        clusters = build_correlation_clusters(rows)
        # Each in its own cluster — no shared keys
        multi = [c for c in clusters if c["size"] > 1]
        assert len(multi) == 0

    def test_cluster_by_community_id(self, db, job):
        from backend.app.services.telemetry_correlator import (
            build_correlation_clusters,
            persist_parser_results,
        )
        cid = "1:aabbccdd/12345"
        results = [
            _make_result(source_system="zeek", community_id=cid, src_ip="1.1.1.1"),
            _make_result(source_system="suricata", community_id=cid, src_ip="2.2.2.2"),
        ]
        rows = persist_parser_results(results, job.job_id, db)
        clusters = build_correlation_clusters(rows)
        big = [c for c in clusters if c["size"] == 2]
        assert len(big) >= 1
        assert "community_id" in big[0]["shared_keys"]

    def test_cluster_score_increases_with_keys(self, db, job):
        from backend.app.services.telemetry_correlator import (
            build_correlation_clusters,
            persist_parser_results,
        )
        # Two events sharing many keys = higher score
        results = [
            _make_result(
                source_system="sysmon", src_ip="10.0.0.5", hostname="WS01",
                username="alice", process_guid="PG-123",
            ),
            _make_result(
                source_system="evtx", src_ip="10.0.0.5", hostname="WS01",
                username="alice", process_guid="PG-123",
            ),
        ]
        rows = persist_parser_results(results, job.job_id, db)
        clusters = build_correlation_clusters(rows)
        big = clusters[0]
        assert big["score"] > 0.3  # multiple shared keys → higher score


# ---------------------------------------------------------------------------
# Corroboration upgrade
# ---------------------------------------------------------------------------

class TestCorroborationUpgrade:
    def test_upgrade_multi_source(self, db, job):
        from backend.app.services.telemetry_correlator import (
            correlate_and_upgrade,
            persist_parser_results,
        )
        results = [
            _make_result(source_system="sysmon", src_ip="10.0.0.5"),
            _make_result(source_system="linux_auth", src_ip="10.0.0.5"),
        ]
        persist_parser_results(results, job.job_id, db)
        stats = correlate_and_upgrade(job.job_id, db)
        assert stats["corroborated"] >= 2
        # Check DB
        events = db.execute(
            select(NormalizedEvent).where(NormalizedEvent.job_id == job.job_id)
        ).scalars().all()
        statuses = {e.evidence_status for e in events}
        assert "corroborated" in statuses

    def test_no_upgrade_single_source(self, db, job):
        from backend.app.services.telemetry_correlator import (
            correlate_and_upgrade,
            persist_parser_results,
        )
        results = [
            _make_result(source_system="sysmon", src_ip="10.0.0.5"),
            _make_result(source_system="sysmon", src_ip="10.0.0.5"),
        ]
        persist_parser_results(results, job.job_id, db)
        stats = correlate_and_upgrade(job.job_id, db)
        # Same source system — no corroboration
        assert stats["corroborated"] == 0

    def test_empty_job(self, db, job):
        from backend.app.services.telemetry_correlator import correlate_and_upgrade
        stats = correlate_and_upgrade(job.job_id, db)
        assert stats["total_events"] == 0
        assert stats["clusters"] == 0




# ---------------------------------------------------------------------------
# EvidenceGraph telemetry extension
# ---------------------------------------------------------------------------

class TestEvidenceGraphTelemetry:
    def test_graph_includes_telemetry_nodes(self, db, job):
        from backend.app.services.evidence_graph import build_evidence_graph, NODE_TELEMETRY
        from backend.app.services.telemetry_correlator import persist_parser_results
        results = [_make_result(source_system="sysmon", src_ip="10.0.0.5")]
        persist_parser_results(results, job.job_id, db)
        db.flush()
        graph = build_evidence_graph(db, job.job_id, include_types={NODE_TELEMETRY})
        tel_nodes = [n for n in graph["nodes"] if n["type"] == "telemetry"]
        assert len(tel_nodes) == 1
        assert "auth" in tel_nodes[0]["label"]

    def test_graph_telemetry_host_edge(self, db, job):
        from backend.app.models.host import Host
        from backend.app.services.evidence_graph import (
            NODE_HOST,
            NODE_TELEMETRY,
            build_evidence_graph,
        )
        from backend.app.services.telemetry_correlator import persist_parser_results
        # Create a host node
        h = Host(job_id=job.job_id, ip="10.0.0.5", role="internal", conn_count=1)
        db.add(h)
        db.flush()
        # Create telemetry event pointing to that host
        results = [_make_result(source_system="sysmon", src_ip="10.0.0.5")]
        persist_parser_results(results, job.job_id, db)
        db.flush()
        graph = build_evidence_graph(db, job.job_id, include_types={NODE_HOST, NODE_TELEMETRY})
        edges = [e for e in graph["edges"] if e["type"] == "observed_on"]
        assert len(edges) >= 1

    def test_graph_without_telemetry(self, db, job):
        from backend.app.services.evidence_graph import (
            NODE_HOST,
            build_evidence_graph,
        )
        from backend.app.services.telemetry_correlator import persist_parser_results
        results = [_make_result()]
        persist_parser_results(results, job.job_id, db)
        db.flush()
        graph = build_evidence_graph(db, job.job_id, include_types={NODE_HOST})
        tel_nodes = [n for n in graph["nodes"] if n["type"] == "telemetry"]
        assert len(tel_nodes) == 0  # excluded


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------

class TestTelemetryPipeline:
    def test_pipeline_no_manifest(self, db, job, tmp_path):
        from backend.app.pipeline.telemetry_pipeline import run_telemetry_pipeline
        result = run_telemetry_pipeline(job.job_id, tmp_path, db)
        assert result["error"] == "no_manifest"

    def test_pipeline_with_fixture_files(self, db, job, tmp_path):
        """End-to-end: write fixture files + manifest, run pipeline."""
        from backend.app.pipeline.telemetry_pipeline import run_telemetry_pipeline
        from backend.app.schemas.telemetry import SourceEntry, SourceManifest

        # Set up job directory structure
        tel_dir = tmp_path / "input" / "telemetry"
        tel_dir.mkdir(parents=True)

        # Copy a fixture file (use sysmon sample)
        fixture = Path(__file__).parent / "fixtures" / "telemetry" / "windows" / "sample_sysmon.json"
        if not fixture.exists():
            pytest.skip("Sysmon fixture not found")
        import shutil
        dest = tel_dir / "sample_sysmon.json"
        shutil.copy(fixture, dest)

        # Write manifest
        manifest = SourceManifest(
            job_id=job.job_id,
            created_at=datetime.now(timezone.utc),
            entries=[
                SourceEntry(
                    filename="sample_sysmon.json",
                    source_type=SourceType.log_bundle,
                    source_system="sysmon",
                    parser_hint="sysmon",
                ),
            ],
        )
        manifest_path = tmp_path / "source_manifest.json"
        manifest_path.write_text(manifest.model_dump_json(indent=2))

        result = run_telemetry_pipeline(job.job_id, tmp_path, db)
        assert result["files_parsed"] >= 1
        assert result["events_total"] >= 1

    def test_pipeline_skips_missing_file(self, db, job, tmp_path):
        from backend.app.pipeline.telemetry_pipeline import run_telemetry_pipeline
        from backend.app.schemas.telemetry import SourceEntry, SourceManifest

        manifest = SourceManifest(
            job_id=job.job_id,
            created_at=datetime.now(timezone.utc),
            entries=[
                SourceEntry(
                    filename="nonexistent.log",
                    source_type=SourceType.log_bundle,
                ),
            ],
        )
        manifest_path = tmp_path / "source_manifest.json"
        manifest_path.write_text(manifest.model_dump_json(indent=2))

        result = run_telemetry_pipeline(job.job_id, tmp_path, db)
        assert result["files_skipped"] == 1
        assert result["events_total"] == 0