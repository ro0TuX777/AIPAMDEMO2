"""Tests for the Evidence Graph: node/edge generation, API, and chat bundle."""

import json
import uuid
from datetime import datetime, timezone

import pytest

from backend.app.models.alert import Alert
from backend.app.models.context_annotation import ContextAnnotation
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.slice import IncidentSlice
from backend.app.models.theory import Theory
from backend.app.services.evidence_graph import (
    NODE_ALERT,
    NODE_ANNOTATION,
    NODE_FINDING,
    NODE_HOST,
    NODE_IOC,
    NODE_SLICE,
    NODE_THEORY,
    _parse_json_list,
    _sev,
    build_evidence_graph,
    graph_summary,
)

AUTH_HEADER = {"Authorization": "Bearer test-token-v2"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _uid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Unit: helpers
# ---------------------------------------------------------------------------


class TestParseJsonList:
    def test_valid_list(self):
        assert _parse_json_list('["a", "b"]') == ["a", "b"]

    def test_none(self):
        assert _parse_json_list(None) == []

    def test_empty_string(self):
        assert _parse_json_list("") == []

    def test_invalid_json(self):
        assert _parse_json_list("not-json") == []

    def test_non_list_json(self):
        assert _parse_json_list('{"key": "val"}') == []


class TestSev:
    def test_known_severity(self):
        assert _sev("critical") == "critical"
        assert _sev("high") == "high"

    def test_unknown_severity(self):
        assert _sev("weird") == "info"

    def test_none(self):
        assert _sev(None) == "info"


# ---------------------------------------------------------------------------
# Fixture: rich job with all entity types
# ---------------------------------------------------------------------------


@pytest.fixture()
def rich_job(db_session, sample_job, sample_host):
    """Populate a job with hosts, alerts, findings, theories, slices, IOCs, and annotations."""
    jid = sample_job.job_id

    # Alert
    db_session.add(Alert(
        job_id=jid, alert_id="A-001", host_ip="10.0.0.5",
        severity="high", signature="ET MALWARE CobaltStrike",
        community_id="1:abc", category="malware", ts=_now(),
    ))

    # Finding
    db_session.add(Finding(
        job_id=jid, finding_id="F-001", sensor="suricata",
        severity="critical", title="C2 Beaconing Detected",
        community_id="1:abc", confidence=0.9,
    ))

    # IOC
    db_session.add(Ioc(
        job_id=jid, ioc_id="IOC-001", ioc_type="ip",
        value="10.0.0.5", severity="high", confidence=0.85,
    ))

    # Theory
    db_session.add(Theory(
        job_id=jid, theory_id="TH-001", label="C2 Hypothesis",
        hypothesis_type="c2", score=0.85, confidence="high",
        scope_type="host", scope_id="10.0.0.5",
        supporting_evidence_json=json.dumps(["F-001", "A-001"]),
        rank=1, created_at=_now(),
    ))

    # Slice
    db_session.add(IncidentSlice(
        job_id=jid, slice_id="SL-001", label="C2 Attack Thread",
        slice_type="c2_session", severity="high", confidence=0.8,
        host_ips_json=json.dumps(["10.0.0.5"]),
        alert_ids_json=json.dumps(["A-001"]),
        finding_ids_json=json.dumps(["F-001"]),
        ioc_ids_json=json.dumps(["IOC-001"]),
        rank=1, created_at=_now(),
    ))

    # Annotation
    db_session.add(ContextAnnotation(
        job_id=jid, annotation_id="ANN-001", host_ip="10.0.0.5",
        metric_name="conn_count", metric_category="traffic",
        observed_value=500.0, baseline_value=50.0,
        deviation_factor=45.0, severity="high",
        title="Unusually High Connection Count",
        description="Host 10.0.0.5 made 500 connections",
        why_unusual="Average host made 50 connections",
        related_alert_ids_json=json.dumps(["A-001"]),
        related_finding_ids_json=json.dumps(["F-001"]),
        created_at=_now(),
    ))

    db_session.commit()
    return sample_job



# ---------------------------------------------------------------------------
# Graph builder tests
# ---------------------------------------------------------------------------


class TestBuildEvidenceGraph:
    def test_nonexistent_job_raises(self, db_session):
        with pytest.raises(ValueError, match="not found"):
            build_evidence_graph(db_session, "nonexistent-id")

    def test_empty_job_returns_no_nodes(self, db_session, sample_job):
        graph = build_evidence_graph(db_session, sample_job.job_id)
        # Only the host from sample_host fixture isn't present (sample_job has no host)
        assert graph["nodes"] == []
        assert graph["edges"] == []

    def test_all_node_types_present(self, db_session, rich_job):
        graph = build_evidence_graph(db_session, rich_job.job_id)
        types = {n["type"] for n in graph["nodes"]}
        assert NODE_HOST in types
        assert NODE_ALERT in types
        assert NODE_FINDING in types
        assert NODE_THEORY in types
        assert NODE_SLICE in types
        assert NODE_IOC in types
        assert NODE_ANNOTATION in types

    def test_node_count(self, db_session, rich_job):
        graph = build_evidence_graph(db_session, rich_job.job_id)
        # 1 host + 1 alert + 1 finding + 1 theory + 1 slice + 1 ioc + 1 annotation = 7
        assert len(graph["nodes"]) == 7

    def test_edges_created(self, db_session, rich_job):
        graph = build_evidence_graph(db_session, rich_job.job_id)
        edge_types = {e["type"] for e in graph["edges"]}
        # Expected edge types based on our data
        assert "triggered_on" in edge_types  # alert → host
        assert "about_host" in edge_types    # theory → host
        assert "contains" in edge_types       # slice → alerts/findings/iocs
        assert "annotates" in edge_types     # annotation → host

    def test_include_filter(self, db_session, rich_job):
        graph = build_evidence_graph(
            db_session, rich_job.job_id,
            include_types={NODE_HOST, NODE_ALERT}
        )
        types = {n["type"] for n in graph["nodes"]}
        assert types == {NODE_HOST, NODE_ALERT}
        assert NODE_FINDING not in types

    def test_node_meta_populated(self, db_session, rich_job):
        graph = build_evidence_graph(db_session, rich_job.job_id)
        theories = [n for n in graph["nodes"] if n["type"] == NODE_THEORY]
        assert len(theories) == 1
        assert theories[0]["meta"]["hypothesis_type"] == "c2"
        assert theories[0]["meta"]["score"] == 0.85

    def test_correlated_edges(self, db_session, rich_job):
        """Finding and alert share community_id → should have correlated edge."""
        graph = build_evidence_graph(db_session, rich_job.job_id)
        correlated = [e for e in graph["edges"] if e["type"] == "correlated"]
        assert len(correlated) >= 1

    def test_ioc_ip_indicates_host(self, db_session, rich_job):
        """IOC with type=ip matching a host IP → indicates edge."""
        graph = build_evidence_graph(db_session, rich_job.job_id)
        indicates = [e for e in graph["edges"] if e["type"] == "indicates"]
        assert len(indicates) >= 1
        assert indicates[0]["source"] == "ioc:IOC-001"
        assert indicates[0]["target"] == "host:10.0.0.5"

    def test_slice_contains_members(self, db_session, rich_job):
        """Slice should have contains edges to its members."""
        graph = build_evidence_graph(db_session, rich_job.job_id)
        contains = [e for e in graph["edges"] if e["type"] == "contains"
                    and e["source"] == "slice:SL-001"]
        targets = {e["target"] for e in contains}
        assert "alert:A-001" in targets
        assert "finding:F-001" in targets
        assert "ioc:IOC-001" in targets


# ---------------------------------------------------------------------------
# Graph summary tests
# ---------------------------------------------------------------------------


class TestGraphSummary:
    def test_summary_format(self, db_session, rich_job):
        summary = graph_summary(db_session, rich_job.job_id)
        assert "Evidence Graph:" in summary
        assert "7 nodes" in summary
        assert "Node types:" in summary

    def test_empty_job_summary(self, db_session, sample_job):
        summary = graph_summary(db_session, sample_job.job_id)
        assert "0 nodes" in summary


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


class TestEvidenceGraphAPI:
    def _seed(self, db):
        """Seed a full job with all entity types via the app_client db session."""
        from backend.app.models.job import Job
        jid = _uid()
        job = Job(
            job_id=jid, job_name="Graph Test", status="queued",
            execution_profile="standard", priority="normal",
            pcap_filename="test.pcap", pcap_size_bytes=1024,
            pcap_sha256="abc123", created_at=_now(),
        )
        db.add(job)
        db.flush()
        db.add(Host(job_id=jid, ip="10.0.0.5", role="internal",
                     conn_count=10, alert_count=1, finding_count=1,
                     first_seen=_now(), last_seen=_now()))
        db.add(Alert(job_id=jid, alert_id="A-001", host_ip="10.0.0.5",
                      severity="high", signature="ET MALWARE CobaltStrike",
                      community_id="1:abc", category="malware", ts=_now()))
        db.add(Finding(job_id=jid, finding_id="F-001", sensor="suricata",
                        severity="critical", title="C2 Beaconing",
                        community_id="1:abc", confidence=0.9))
        db.commit()
        return job

    def test_get_evidence_graph(self, app_client):
        client, db = app_client
        job = self._seed(db)
        resp = client.get(f"/api/v1/jobs/{job.job_id}/evidence-graph",
                          headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["node_count"] >= 3  # host + alert + finding
        assert data["edge_count"] >= 1

    def test_evidence_graph_with_filter(self, app_client):
        client, db = app_client
        job = self._seed(db)
        resp = client.get(
            f"/api/v1/jobs/{job.job_id}/evidence-graph?include=host,alert",
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        data = resp.json()
        types = {n["type"] for n in data["nodes"]}
        assert types == {"host", "alert"}

    def test_evidence_graph_404(self, app_client):
        client, _ = app_client
        resp = client.get("/api/v1/jobs/nonexistent/evidence-graph",
                          headers=AUTH_HEADER)
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Chat bundle tests
# ---------------------------------------------------------------------------


class TestEvidenceGraphBundle:
    def test_bundle_contains_summary(self, db_session, rich_job):
        from backend.app.services.evidence_bundles import build_scoped_bundle
        bundle = build_scoped_bundle(db_session, rich_job.job_id, "evidence_graph", "")
        ctx = bundle.to_context()
        assert "Evidence Graph:" in ctx
        assert "7 nodes" in ctx

    def test_bundle_empty_job(self, db_session, sample_job):
        from backend.app.services.evidence_bundles import build_scoped_bundle
        bundle = build_scoped_bundle(db_session, sample_job.job_id, "evidence_graph", "")
        ctx = bundle.to_context()
        assert "0 nodes" in ctx

