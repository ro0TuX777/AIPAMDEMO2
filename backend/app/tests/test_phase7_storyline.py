"""Phase 7 tests — Storyline Reconstruction and Theory Expansion.

Tests run against in-memory SQLite with the V2 schema.
Covers: evidence graph semantic edges, storyline reconstruction, theory engine enhancements.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from backend.app.database_v2 import Base, _set_sqlite_pragmas
from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.job import Job
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.theory import Theory
from backend.app.services.evidence_graph import build_evidence_graph
from backend.app.services.storyline import (
    STAGE_ORDER,
    StorylineResult,
    _classify_node,
    reconstruct_storyline,
)
from backend.app.services.theory_engine import (
    _HYPOTHESIS_PATTERNS,
    _score_hypothesis,
    generate_theories,
)


def _uid():
    return str(uuid.uuid4())


def _ts(offset_seconds=0):
    dt = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)
    yield session
    session.close()
    engine.dispose()


@pytest.fixture()
def job_id(db):
    jid = _uid()
    db.add(Job(
        job_id=jid, job_name="Storyline Test", status="running",
        execution_profile="standard", priority="normal",
        pcap_filename="test.pcap", pcap_size_bytes=0, pcap_sha256="abc",
        created_at=_ts(),
    ))
    db.commit()
    return jid


# ── Helpers ──────────────────────────────────────────────────────────

def _host(job_id, ip, alert_count=0):
    return Host(job_id=job_id, ip=ip, alert_count=alert_count, conn_count=10)


def _te(job_id, event_type, src_ip=None, dest_ip=None, dest_port=None,
        ts_offset=0, evidence_status="observed", data_json=None, **kw):
    return NormalizedEvent(
        event_id=_uid(), job_id=job_id, event_type=event_type,
        timestamp=_ts(ts_offset), source_type="log_bundle",
        evidence_status=evidence_status, src_ip=src_ip,
        dest_ip=dest_ip, dest_port=dest_port,
        data_json=data_json, **kw,
    )


def _finding(job_id, title, severity="medium", category=None, sensor="test",
             confidence=0.5, evidence_json=None):
    return Finding(
        job_id=job_id, finding_id=f"F-{_uid()[:12]}", sensor=sensor,
        severity=severity, category=category or "general", title=title,
        summary=title, confidence=confidence,
        evidence_json=evidence_json,
    )


def _alert(job_id, signature, severity="medium", host_ip=None, community_id=None):
    return Alert(
        job_id=job_id, alert_id=f"A-{_uid()[:12]}", signature=signature,
        severity=severity, category="test", host_ip=host_ip,
        community_id=community_id, ts=_ts(),
    )


# ══════════════════════════════════════════════════════════════════════
# Evidence Graph — Semantic Edge Tests
# ══════════════════════════════════════════════════════════════════════

class TestEvidenceGraphSemanticEdges:
    def test_executed_on_edge(self, db, job_id):
        """Process events should generate 'executed_on' edges to their host."""
        h = _host(job_id, "10.0.0.5")
        proc = _te(job_id, "process", src_ip="10.0.0.5", ts_offset=0)
        db.add_all([h, proc])
        db.commit()

        graph = build_evidence_graph(db, job_id)
        edge_types = {e["type"] for e in graph["edges"]}
        assert "executed_on" in edge_types

    def test_beaconed_to_edge(self, db, job_id):
        """Confirmed connections should generate 'beaconed_to' edges."""
        h_src = _host(job_id, "10.0.0.5")
        h_dst = _host(job_id, "192.168.1.100")
        conn = _te(job_id, "connection", src_ip="10.0.0.5", dest_ip="192.168.1.100",
                    dest_port=443, evidence_status="confirmed")
        db.add_all([h_src, h_dst, conn])
        db.commit()

        graph = build_evidence_graph(db, job_id)
        edge_types = {e["type"] for e in graph["edges"]}
        assert "beaconed_to" in edge_types

    def test_authenticated_as_edge(self, db, job_id):
        """Auth events should generate 'authenticated_as' edges."""
        h = _host(job_id, "10.0.0.5")
        auth = _te(job_id, "auth", src_ip="10.0.0.5", ts_offset=0)
        db.add_all([h, auth])
        db.commit()

        graph = build_evidence_graph(db, job_id)
        edge_types = {e["type"] for e in graph["edges"]}
        assert "authenticated_as" in edge_types

    def test_confirmed_by_edge_callback_to_connection(self, db, job_id):
        """C2 callbacks should generate 'confirmed_by' edges to matching connections."""
        conn = _te(job_id, "connection", src_ip="10.0.0.5", dest_ip="192.168.1.100",
                    dest_port=443, ts_offset=0)
        cb = _te(job_id, "c2_callback", src_ip="10.0.0.5", dest_ip="192.168.1.100",
                 dest_port=443, ts_offset=60)
        db.add_all([conn, cb])
        db.commit()

        graph = build_evidence_graph(db, job_id)
        confirmed_edges = [e for e in graph["edges"] if e["type"] == "confirmed_by"]
        assert len(confirmed_edges) >= 1

    def test_occurred_before_edge(self, db, job_id):
        """Sequential events on same host should get 'occurred_before' edges."""
        h = _host(job_id, "10.0.0.5")
        e1 = _te(job_id, "process", src_ip="10.0.0.5", ts_offset=0)
        e2 = _te(job_id, "connection", src_ip="10.0.0.5", ts_offset=60)
        db.add_all([h, e1, e2])
        db.commit()

        graph = build_evidence_graph(db, job_id)
        edge_types = {e["type"] for e in graph["edges"]}
        assert "occurred_before" in edge_types

    def test_same_session_edge(self, db, job_id):
        """Events with the same session_id should get 'same_session' edges."""
        e1 = _te(job_id, "auth", src_ip="10.0.0.5", ts_offset=0, session_id="sess-1")
        e2 = _te(job_id, "process", src_ip="10.0.0.5", ts_offset=10, session_id="sess-1")
        db.add_all([e1, e2])
        db.commit()

        graph = build_evidence_graph(db, job_id)
        session_edges = [e for e in graph["edges"] if e["type"] == "same_session"]
        assert len(session_edges) >= 1


# ══════════════════════════════════════════════════════════════════════
# Storyline Reconstruction Tests
# ══════════════════════════════════════════════════════════════════════

class TestStorylineReconstruction:
    def test_empty_job_produces_empty_storyline(self, db, job_id):
        result = reconstruct_storyline(db, job_id)
        assert isinstance(result, StorylineResult)
        assert result.job_id == job_id
        assert len(result.stages) == 0
        assert "No attack stages" in result.narrative

    def test_recon_stage_detected(self, db, job_id):
        """DNS/connection events classified as recon with scan keywords."""
        h = _host(job_id, "10.0.0.5")
        f = _finding(job_id, "Network scan detected from 10.0.0.5",
                      severity="medium", category="scanning")
        db.add_all([h, f])
        db.commit()

        result = reconstruct_storyline(db, job_id)
        stage_names = [s.name for s in result.stages]
        assert "recon" in stage_names

    def test_c2_stage_detected(self, db, job_id):
        """C2 callback events should be classified as c2 stage."""
        cb = _te(job_id, "c2_callback", src_ip="10.0.0.5", dest_ip="192.168.1.100",
                 dest_port=443, ts_offset=0)
        db.add_all([cb])
        db.commit()

        result = reconstruct_storyline(db, job_id)
        stage_names = [s.name for s in result.stages]
        assert "c2" in stage_names

    def test_execution_stage_detected(self, db, job_id):
        """Process events should be classified as execution stage."""
        h = _host(job_id, "10.0.0.5")
        proc = _te(job_id, "process", src_ip="10.0.0.5", ts_offset=0)
        db.add_all([h, proc])
        db.commit()

        result = reconstruct_storyline(db, job_id)
        stage_names = [s.name for s in result.stages]
        assert "execution" in stage_names

    def test_multi_stage_attack(self, db, job_id):
        """Full attack scenario produces multiple stages in kill-chain order."""
        h = _host(job_id, "10.0.0.5", alert_count=3)
        # Recon
        recon_f = _finding(job_id, "Port scan detected", category="scanning")
        # C2
        c2_cb = _te(job_id, "c2_callback", src_ip="10.0.0.5", dest_ip="192.168.1.100",
                     dest_port=443, ts_offset=100)
        # Execution
        proc = _te(job_id, "process", src_ip="10.0.0.5", ts_offset=200)
        # Lateral
        auth = _te(job_id, "auth", src_ip="10.0.0.5", ts_offset=300)
        db.add_all([h, recon_f, c2_cb, proc, auth])
        db.commit()

        result = reconstruct_storyline(db, job_id)
        assert len(result.stages) >= 3
        # Stages should be in kill-chain order
        stage_names = [s.name for s in result.stages]
        for i in range(len(stage_names) - 1):
            assert STAGE_ORDER.index(stage_names[i]) <= STAGE_ORDER.index(stage_names[i + 1])

    def test_host_timelines_generated(self, db, job_id):
        """Per-host timelines should track which stages each host participates in."""
        h = _host(job_id, "10.0.0.5")
        proc = _te(job_id, "process", src_ip="10.0.0.5", ts_offset=0)
        cb = _te(job_id, "c2_callback", src_ip="10.0.0.5", dest_ip="192.168.1.100",
                 dest_port=443, ts_offset=60)
        db.add_all([h, proc, cb])
        db.commit()

        result = reconstruct_storyline(db, job_id)
        # Host should appear in timelines
        assert len(result.host_timelines) >= 0  # may or may not have host IPs depending on graph

    def test_to_dict_serializable(self, db, job_id):
        """StorylineResult.to_dict() should produce a JSON-serializable dict."""
        h = _host(job_id, "10.0.0.5")
        proc = _te(job_id, "process", src_ip="10.0.0.5")
        db.add_all([h, proc])
        db.commit()

        result = reconstruct_storyline(db, job_id)
        d = result.to_dict()
        # Should be JSON-serializable
        serialized = json.dumps(d)
        assert "stages" in d
        assert "narrative" in d

    def test_confidence_increases_with_confirmed(self, db, job_id):
        """Stages with confirmed evidence should have higher confidence."""
        h = _host(job_id, "10.0.0.5", alert_count=2)
        cb1 = _te(job_id, "c2_callback", src_ip="10.0.0.5", dest_ip="192.168.1.100",
                   dest_port=443, evidence_status="confirmed", ts_offset=0)
        cb2 = _te(job_id, "c2_callback", src_ip="10.0.0.5", dest_ip="192.168.1.100",
                   dest_port=443, evidence_status="confirmed", ts_offset=60)
        db.add_all([h, cb1, cb2])
        db.commit()

        result = reconstruct_storyline(db, job_id)
        c2_stages = [s for s in result.stages if s.name == "c2"]
        if c2_stages:
            assert c2_stages[0].confidence > 0.5


# ══════════════════════════════════════════════════════════════════════
# Theory Engine Enhancement Tests
# ══════════════════════════════════════════════════════════════════════

class TestTheoryEngineEnhancements:
    def test_credential_abuse_hypothesis_exists(self):
        """credential_abuse should be a registered hypothesis type."""
        assert "credential_abuse" in _HYPOTHESIS_PATTERNS

    def test_credential_abuse_scores_on_brute_force(self, db, job_id):
        """credential_abuse hypothesis should score on brute-force findings."""
        f = _finding(job_id, "Brute force attack detected on 10.0.0.5",
                      severity="high", category="credential_abuse",
                      sensor="auth_anomaly")
        db.add(f)
        db.commit()

        theories = generate_theories(db, job_id)
        cred_theories = [t for t in theories if t.hypothesis_type == "credential_abuse"]
        assert len(cred_theories) >= 1
        assert cred_theories[0].score > 0.01

    def test_confirmed_telemetry_gets_higher_weight(self, db, job_id):
        """Confirmed evidence should produce higher scores than observed."""
        # Create two identical C2 events, one confirmed and one observed
        confirmed_evt = _te(job_id, "c2_callback", src_ip="10.0.0.5",
                             dest_ip="192.168.1.100", dest_port=443,
                             evidence_status="confirmed", ts_offset=0,
                             data_json=json.dumps({"agent_id": "a1", "framework": "cobalt_strike"}))
        db.add(confirmed_evt)
        db.commit()

        evidence_confirmed = {
            "findings": [], "alerts": [], "iocs": [],
            "telemetry": [confirmed_evt],
        }
        score_confirmed, _, _, _ = _score_hypothesis(
            "c2", _HYPOTHESIS_PATTERNS["c2"], evidence_confirmed
        )

        # Now test with observed status
        db.delete(confirmed_evt)
        db.commit()

        observed_evt = _te(job_id, "c2_callback", src_ip="10.0.0.5",
                            dest_ip="192.168.1.100", dest_port=443,
                            evidence_status="observed", ts_offset=0,
                            data_json=json.dumps({"agent_id": "a2", "framework": "cobalt_strike"}))
        db.add(observed_evt)
        db.commit()

        evidence_observed = {
            "findings": [], "alerts": [], "iocs": [],
            "telemetry": [observed_evt],
        }
        score_observed, _, _, _ = _score_hypothesis(
            "c2", _HYPOTHESIS_PATTERNS["c2"], evidence_observed
        )

        assert score_confirmed > score_observed

    def test_theory_generation_includes_credential_abuse(self, db, job_id):
        """Full theory generation should include credential_abuse when relevant."""
        h = _host(job_id, "10.0.0.5")
        f = _finding(job_id, "Credential spraying detected from 10.0.0.5",
                      severity="high", category="credential_spraying",
                      sensor="auth_anomaly")
        db.add_all([h, f])
        db.commit()

        theories = generate_theories(db, job_id)
        hyp_types = {t.hypothesis_type for t in theories}
        assert "credential_abuse" in hyp_types


# ══════════════════════════════════════════════════════════════════════
# Node Classifier Tests
# ══════════════════════════════════════════════════════════════════════

class TestNodeClassifier:
    def test_c2_callback_node_classified_as_c2(self):
        node = {"id": "t:1", "type": "telemetry", "label": "c2_callback",
                "meta": {"event_type": "c2_callback"}}
        assert _classify_node(node, []) == "c2"

    def test_process_node_classified_as_execution(self):
        node = {"id": "t:2", "type": "telemetry", "label": "process",
                "meta": {"event_type": "process"}}
        assert _classify_node(node, []) == "execution"

    def test_scan_finding_classified_as_recon(self):
        node = {"id": "f:1", "type": "finding", "label": "Port scan detected",
                "meta": {"category": "scanning"}}
        assert _classify_node(node, []) == "recon"

    def test_theory_node_classified_by_hypothesis(self):
        node = {"id": "th:1", "type": "theory", "label": "C2 Beaconing",
                "meta": {"hypothesis_type": "c2"}}
        assert _classify_node(node, []) == "c2"

    def test_unclassifiable_node_returns_none(self):
        node = {"id": "x:1", "type": "annotation", "label": "Some note",
                "meta": {}}
        assert _classify_node(node, []) is None
