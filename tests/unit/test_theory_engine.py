"""Tests for the Theory of the Case engine: scoring, generation, API, and evidence bundles."""

import json
import uuid
from datetime import datetime, timezone

import pytest

from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.ioc import Ioc
from backend.app.models.theory import Theory
from backend.app.services.theory_engine import (
    _confidence_label,
    _gather_evidence,
    _score_benign,
    _score_hypothesis,
    generate_all_theories,
    generate_theories,
)

AUTH_HEADER = {"Authorization": "Bearer test-token-v2"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _uid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Unit: confidence labels
# ---------------------------------------------------------------------------

class TestConfidenceLabel:
    def test_high(self):
        assert _confidence_label(0.6) == "high"
        assert _confidence_label(0.9) == "high"
        assert _confidence_label(1.0) == "high"

    def test_medium(self):
        assert _confidence_label(0.3) == "medium"
        assert _confidence_label(0.5) == "medium"
        assert _confidence_label(0.59) == "medium"

    def test_low(self):
        assert _confidence_label(0.0) == "low"
        assert _confidence_label(0.1) == "low"
        assert _confidence_label(0.29) == "low"


# ---------------------------------------------------------------------------
# Fixtures: populate job with evidence
# ---------------------------------------------------------------------------

@pytest.fixture()
def c2_job(db_session, sample_job):
    """Job with C2 beacon evidence: alerts + findings + IOC."""
    job_id = sample_job.job_id
    # C2-related alert
    db_session.add(Alert(
        job_id=job_id, alert_id="A-001", host_ip="10.0.0.5",
        severity="high", signature="ET MALWARE CobaltStrike Beacon Detected",
        category="c2", ts=_now(),
    ))
    # C2-related finding
    db_session.add(Finding(
        job_id=job_id, finding_id="F-001", sensor="suricata",
        severity="critical", title="Command and Control Beaconing Detected",
        summary="Periodic callback to known C2 server", confidence=0.9,
    ))
    # Benign finding (contradicts malicious)
    db_session.add(Finding(
        job_id=job_id, finding_id="F-002", sensor="zeek",
        severity="info", title="Normal DNS resolution",
        summary="Standard DNS traffic", confidence=0.8,
    ))
    # C2-related IOC
    db_session.add(Ioc(
        job_id=job_id, ioc_id="IOC-001", ioc_type="ip",
        value="198.51.100.1", severity="high", confidence=0.85,
        context="Known C2 server infrastructure",
    ))
    db_session.commit()
    return sample_job


@pytest.fixture()
def benign_job(db_session, sample_job):
    """Job with only low/info severity evidence — should score benign high."""
    job_id = sample_job.job_id
    db_session.add(Finding(
        job_id=job_id, finding_id="F-010", sensor="zeek",
        severity="info", title="Normal HTTP browsing",
        summary="Standard web traffic", confidence=0.5,
    ))
    db_session.add(Alert(
        job_id=job_id, alert_id="A-010", host_ip="10.0.0.5",
        severity="low", signature="SURICATA HTTP unable to match response to request",
        category="protocol", ts=_now(),
    ))
    db_session.commit()
    return sample_job


@pytest.fixture()
def recon_job(db_session, sample_job):
    """Job with reconnaissance / scanning evidence."""
    job_id = sample_job.job_id
    db_session.add(Alert(
        job_id=job_id, alert_id="A-020", host_ip="10.0.0.5",
        severity="medium", signature="ET SCAN Potential Port Scan Detected",
        category="scan", ts=_now(),
    ))
    db_session.add(Finding(
        job_id=job_id, finding_id="F-020", sensor="zeek",
        severity="medium", title="Network Scan Activity",
        summary="Host scanning multiple ports on target", confidence=0.7,
    ))
    db_session.commit()
    return sample_job


# ---------------------------------------------------------------------------
# Unit: _score_hypothesis
# ---------------------------------------------------------------------------

class TestScoreHypothesis:
    def test_c2_matches_beacon_finding(self, db_session, c2_job):
        evidence = _gather_evidence(db_session, c2_job.job_id)
        patterns = [r"beacon", r"command.and.control", r"c2", r"cobalt.?strike"]
        score, supporting, contradicting, breakdown = _score_hypothesis("c2", patterns, evidence)
        assert score > 0.0
        assert "F-001" in supporting
        assert "A-001" in supporting
        assert "IOC-001" in supporting

    def test_c2_contradicting_evidence(self, db_session, c2_job):
        evidence = _gather_evidence(db_session, c2_job.job_id)
        patterns = [r"beacon", r"command.and.control", r"c2", r"cobalt.?strike"]
        _, _, contradicting, _ = _score_hypothesis("c2", patterns, evidence)
        # F-002 is info severity with confidence > 0.7 → contradicts malicious
        assert "F-002" in contradicting

    def test_no_match_yields_zero(self, db_session, benign_job):
        evidence = _gather_evidence(db_session, benign_job.job_id)
        patterns = [r"beacon", r"command.and.control", r"c2"]
        score, supporting, _, _ = _score_hypothesis("c2", patterns, evidence)
        assert score == 0.0
        assert supporting == []

    def test_recon_matches_scan_evidence(self, db_session, recon_job):
        evidence = _gather_evidence(db_session, recon_job.job_id)
        patterns = [r"scan", r"recon", r"enumerat", r"port.?scan"]
        score, supporting, _, _ = _score_hypothesis("recon", patterns, evidence)
        assert score > 0.0
        assert "A-020" in supporting
        assert "F-020" in supporting


# ---------------------------------------------------------------------------
# Unit: _score_benign
# ---------------------------------------------------------------------------

class TestScoreBenign:
    def test_benign_high_when_no_threats(self, db_session, benign_job):
        evidence = _gather_evidence(db_session, benign_job.job_id)
        score, supporting, contradicting, _ = _score_benign(evidence)
        assert score == 0.7
        assert contradicting == []

    def test_benign_low_when_threats_present(self, db_session, c2_job):
        evidence = _gather_evidence(db_session, c2_job.job_id)
        score, _, contradicting, _ = _score_benign(evidence)
        assert score <= 0.3
        assert len(contradicting) > 0


# ---------------------------------------------------------------------------
# Integration: generate_theories
# ---------------------------------------------------------------------------

class TestGenerateTheories:
    def test_generates_theories_for_c2_job(self, db_session, c2_job):
        theories = generate_theories(db_session, c2_job.job_id)
        assert len(theories) >= 2  # at least c2 + benign
        # First theory should be c2 (highest score given the evidence)
        assert theories[0].hypothesis_type == "c2"
        assert theories[0].rank == 1
        assert theories[0].score > 0
        assert theories[0].confidence in ("low", "medium", "high")

    def test_generates_theories_for_benign_job(self, db_session, benign_job):
        theories = generate_theories(db_session, benign_job.job_id)
        # Benign should rank highest since there's no malicious evidence
        benign_theories = [t for t in theories if t.hypothesis_type == "benign"]
        assert len(benign_theories) == 1
        assert benign_theories[0].score == 0.7

    def test_regeneration_replaces_existing(self, db_session, c2_job):
        theories1 = generate_theories(db_session, c2_job.job_id)
        theories2 = generate_theories(db_session, c2_job.job_id)
        # Old theories should be deleted, new ones created
        assert len(theories1) == len(theories2)
        # Theory IDs should be different (new UUIDs)
        ids1 = {t.theory_id for t in theories1}
        ids2 = {t.theory_id for t in theories2}
        assert ids1 != ids2

    def test_theories_ranked_by_score(self, db_session, c2_job):
        theories = generate_theories(db_session, c2_job.job_id)
        scores = [t.score for t in theories]
        assert scores == sorted(scores, reverse=True)

    def test_theories_have_correct_scope(self, db_session, c2_job):
        theories = generate_theories(db_session, c2_job.job_id)
        for t in theories:
            assert t.scope_type == "job"
            assert t.scope_id == c2_job.job_id
            assert t.job_id == c2_job.job_id

    def test_host_scoped_theories(self, db_session, c2_job, sample_host):
        theories = generate_theories(db_session, c2_job.job_id, host_ip="10.0.0.5")
        assert len(theories) >= 1
        for t in theories:
            assert t.scope_type == "host"
            assert t.scope_id == "10.0.0.5"

    def test_supporting_evidence_json(self, db_session, c2_job):
        theories = generate_theories(db_session, c2_job.job_id)
        c2_theory = next(t for t in theories if t.hypothesis_type == "c2")
        supporting = json.loads(c2_theory.supporting_evidence_json)
        assert isinstance(supporting, list)
        assert len(supporting) > 0

    def test_inconclusive_fallback(self, db_session, sample_job):
        """Empty job should still produce theories (benign + inconclusive)."""
        theories = generate_theories(db_session, sample_job.job_id)
        types = {t.hypothesis_type for t in theories}
        assert "benign" in types


# ---------------------------------------------------------------------------
# Integration: generate_all_theories (job + per-host)
# ---------------------------------------------------------------------------

class TestGenerateAllTheories:
    def test_generates_job_and_host_theories(self, db_session, c2_job, sample_host):
        counts = generate_all_theories(db_session, c2_job.job_id)
        assert counts["job"] >= 2
        assert counts["hosts"] >= 1
        assert counts["total"] == counts["job"] + counts["hosts"]


# ---------------------------------------------------------------------------
# API: /jobs/{job_id}/theories endpoints
# ---------------------------------------------------------------------------

class TestTheoriesAPI:
    def test_list_theories_empty(self, app_client):
        client, db = app_client
        from backend.app.models.job import Job
        job = Job(
            job_id=_uid(), job_name="API Test", status="completed",
            execution_profile="standard", priority="normal",
            pcap_filename="test.pcap", pcap_size_bytes=1024,
            pcap_sha256="abc", created_at=_now(),
        )
        db.add(job)
        db.commit()
        r = client.get(f"/api/v1/jobs/{job.job_id}/theories", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["items"] == []
        assert body["scope_type"] == "job"
        assert body["schema_version"] == "1.0"

    def test_list_theories_with_data(self, app_client):
        client, db = app_client
        from backend.app.models.job import Job
        job = Job(
            job_id=_uid(), job_name="API Test 2", status="completed",
            execution_profile="standard", priority="normal",
            pcap_filename="test.pcap", pcap_size_bytes=1024,
            pcap_sha256="abc2", created_at=_now(),
        )
        db.add(job)
        db.commit()
        # Add a theory directly
        theory = Theory(
            job_id=job.job_id, theory_id="TH-test001",
            scope_type="job", scope_id=job.job_id,
            label="C2 Beaconing", hypothesis_type="c2",
            score=0.75, confidence="high", rank=1,
            supporting_evidence_json=json.dumps(["F-001"]),
            created_at=_now(),
        )
        db.add(theory)
        db.commit()
        r = client.get(f"/api/v1/jobs/{job.job_id}/theories", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert len(body["items"]) == 1
        item = body["items"][0]
        assert item["theory_id"] == "TH-test001"
        assert item["hypothesis_type"] == "c2"
        assert item["score"] == 0.75
        assert len(item["supporting_evidence"]) == 1
        assert item["supporting_evidence"][0]["id"] == "F-001"
        assert item["supporting_evidence"][0]["type"] == "unknown"  # F-001 not seeded as entity

    def test_list_theories_404_bad_job(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/jobs/nonexistent/theories", headers=AUTH_HEADER)
        assert r.status_code == 404

    def test_generate_theories_endpoint(self, app_client):
        client, db = app_client
        from backend.app.models.job import Job
        job = Job(
            job_id=_uid(), job_name="Gen Test", status="completed",
            execution_profile="standard", priority="normal",
            pcap_filename="test.pcap", pcap_size_bytes=1024,
            pcap_sha256="abc3", created_at=_now(),
        )
        db.add(job)
        db.commit()
        r = client.post(f"/api/v1/jobs/{job.job_id}/theories/generate", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert len(body["items"]) >= 1  # at least benign
        assert body["scope_type"] == "job"

    def test_host_theories_endpoint(self, app_client):
        client, db = app_client
        from backend.app.models.job import Job
        job = Job(
            job_id=_uid(), job_name="Host Theory Test", status="completed",
            execution_profile="standard", priority="normal",
            pcap_filename="test.pcap", pcap_size_bytes=1024,
            pcap_sha256="abc4", created_at=_now(),
        )
        db.add(job)
        db.commit()
        # Add host-scoped theory
        theory = Theory(
            job_id=job.job_id, theory_id="TH-host001",
            scope_type="host", scope_id="10.0.0.5",
            label="Recon", hypothesis_type="recon",
            score=0.4, confidence="medium", rank=1,
            created_at=_now(),
        )
        db.add(theory)
        db.commit()
        r = client.get(
            f"/api/v1/jobs/{job.job_id}/hosts/10.0.0.5/theories",
            headers=AUTH_HEADER,
        )
        assert r.status_code == 200
        body = r.json()
        assert len(body["items"]) == 1
        assert body["scope_type"] == "host"
        assert body["scope_id"] == "10.0.0.5"


# ---------------------------------------------------------------------------
# Evidence bundle: theory scope
# ---------------------------------------------------------------------------

class TestTheoryEvidenceBundle:
    def test_theory_bundle_with_valid_id(self, db_session, c2_job):
        theories = generate_theories(db_session, c2_job.job_id)
        from backend.app.services.evidence_bundles import build_scoped_bundle
        bundle = build_scoped_bundle(db_session, c2_job.job_id, "theory", theories[0].theory_id)
        ctx = bundle.to_context()
        assert "Theory:" in ctx
        assert theories[0].label in ctx

    def test_theory_bundle_fallback_for_unknown_id(self, db_session, c2_job):
        generate_theories(db_session, c2_job.job_id)
        from backend.app.services.evidence_bundles import build_scoped_bundle
        bundle = build_scoped_bundle(db_session, c2_job.job_id, "theory", "nonexistent-id")
        ctx = bundle.to_context()
        # Should still return job-level theories as fallback
        assert "theories" in ctx.lower() or ctx == ""

    def test_parse_context_hint_theory(self):
        from backend.app.services.evidence_bundles import parse_context_hint
        scope_type, scope_id = parse_context_hint("theory:TH-abc12345")
        assert scope_type == "theory"
        assert scope_id == "TH-abc12345"
