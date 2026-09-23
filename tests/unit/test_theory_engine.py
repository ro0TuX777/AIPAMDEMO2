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

    def test_regeneration_preserves_identity(self, db_session, c2_job):
        theories1 = generate_theories(db_session, c2_job.job_id)
        theories2 = generate_theories(db_session, c2_job.job_id)
        # Regeneration updates the same semantic theories
        assert len(theories1) == len(theories2)
        # IDs are stable across regeneration
        ids1 = {t.theory_id for t in theories1}
        ids2 = {t.theory_id for t in theories2}
        assert ids1 == ids2

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


# Task 6: relevance, bounded database work, and durable review identity.
from sqlalchemy import event, select, func
from backend.app.models.host import Host
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.services import theory_engine as engine


def _host(db, job, ip, phase=None):
    db.add(Host(job_id=job, ip=ip, conn_count=100, pcap_label=phase))


def _alert(db, job, ip, phase=None):
    db.add(Alert(job_id=job, alert_id=_uid(), host_ip=ip, severity="high",
                 signature="C2 beacon", ts=_now(), pcap_label=phase))


def _finding(db, job, **kw):
    db.add(Finding(job_id=job, finding_id=_uid(), sensor="test", severity="high",
                   title="C2 beacon", **kw))


def _telemetry(db, job, ip, status, phase=None):
    db.add(NormalizedEvent(job_id=job, event_id=_uid(), event_type="c2",
        timestamp=_now(), source_type="log", src_ip=ip, evidence_status=status,
        pcap_label=phase))


def test_connection_only_host_gets_no_host_theory(db_session, sample_job):
    job = sample_job.job_id
    _host(db_session, job, "10.0.0.1")
    _host(db_session, job, "10.0.0.2")
    _alert(db_session, job, "10.0.0.2")
    db_session.commit()
    result = generate_all_theories(db_session, job)
    assert result["relevant_hosts"] == 1
    assert result["discovered_hosts"] == 2
    assert result["skipped_benign_hosts"] == 1
    assert result["theory_scopes"] == 2
    assert result["duration_ms"] >= 0
    assert set(db_session.execute(select(Theory.scope_type, Theory.scope_id))) == {
        ("job", job), ("host", "10.0.0.2")}


def test_exact_structured_relevance_and_phase_filters(db_session, sample_job):
    job = sample_job.job_id
    for ip in ["10.0.0.1", "10.0.0.10", "10.0.0.3", "10.0.0.4", "10.0.0.5",
               "10.0.0.6", "10.0.0.7", "10.0.0.8", "2001:db8::1", "10.0.0.9"]:
        _host(db_session, job, ip, "before")
    _alert(db_session, job, "10.0.0.10", "before")
    _finding(db_session, job, src_ip="10.0.0.3", dest_ip="10.0.0.4", pcap_label="before")
    _finding(db_session, job, evidence_json=json.dumps({"nested": ["10.0.0.5", "text 10.0.0.1"]}), pcap_label="before")
    _finding(db_session, job, summary="10.0.0.1", evidence_json='bad json 10.0.0.1', pcap_label="before")
    _telemetry(db_session, job, "10.0.0.6", "observed", "before")
    _telemetry(db_session, job, "10.0.0.7", "corroborated", "before")
    _telemetry(db_session, job, "10.0.0.8", "confirmed", "before")
    db_session.add(Ioc(job_id=job, ioc_id=_uid(), ioc_type="ipv6",
        value="2001:0db8:0:0:0:0:0:1", pcap_label="before"))
    db_session.add(Ioc(job_id=job, ioc_id=_uid(), ioc_type="domain",
        value="10.0.0.1", context="10.0.0.1", pcap_label="before"))
    for phase in ["after", None]:
        _alert(db_session, job, "10.0.0.9", phase)
        _finding(db_session, job, src_ip="10.0.0.9", pcap_label=phase)
        _telemetry(db_session, job, "10.0.0.9", "confirmed", phase)
        db_session.add(Ioc(job_id=job, ioc_id=_uid(), ioc_type="ip", value="10.0.0.9", pcap_label=phase))
    db_session.commit()
    result = generate_all_theories(db_session, job, pcap_label="before")
    assert result["relevant_hosts"] == 7
    assert set(db_session.scalars(select(Theory.scope_id).where(Theory.scope_type == "host"))) == {
        "10.0.0.10", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.7", "10.0.0.8", "2001:db8::1"}
    assert not _gather_evidence(db_session, job, "10.0.0.1", "before")["findings"]
    assert not _gather_evidence(db_session, job, "10.0.0.9", "before")["iocs"]
    assert not _gather_evidence(db_session, job, "10.0.0.9", "before")["telemetry"]


@pytest.mark.parametrize("count", [1, 200])
def test_evidence_loading_query_count_is_constant(db_session, sample_job, count):
    job = sample_job.job_id
    for i in range(count):
        ip = f"10.0.{i // 250}.{i % 250 + 1}"
        _host(db_session, job, ip)
        _alert(db_session, job, ip)
    db_session.commit()
    calls = {"selects": 0, "commits": 0, "flushes": 0}
    def sql(conn, cursor, statement, *args):
        if statement.lstrip().upper().startswith("SELECT"):
            calls["selects"] += 1
    def commit(session):
        calls["commits"] += 1
    def flush(*args):
        calls["flushes"] += 1
    event.listen(db_session.get_bind(), "before_cursor_execute", sql)
    event.listen(db_session, "before_commit", commit)
    event.listen(db_session, "after_flush", flush)
    try:
        result = generate_all_theories(db_session, job)
    finally:
        event.remove(db_session.get_bind(), "before_cursor_execute", sql)
        event.remove(db_session, "before_commit", commit)
        event.remove(db_session, "after_flush", flush)
    assert calls["selects"] <= 8
    assert calls["commits"] == 1
    assert calls["flushes"] == (count + 100) // 100
    assert result["relevant_hosts"] == count
    assert result["theory_scopes"] == count + 1


def test_candidate_reordering_keeps_theory_identity_and_review(db_session, c2_job, monkeypatch):
    job = c2_job.job_id
    rows = generate_theories(db_session, job)
    row = next(t for t in rows if t.hypothesis_type == "c2")
    row.theory_id = "TH-legacy-random"
    row.analyst_status = "confirmed"
    row.analyst_notes = "analyst-confirmed"
    row.reviewed_at = "2026-09-22T10:00:00Z"
    row.reviewer_id = "analyst-test"
    db_session.commit()
    monkeypatch.setattr(engine, "_score_benign", lambda evidence: (1.0, [], [], {}))
    generate_theories(db_session, job)
    row = db_session.scalar(select(Theory).where(Theory.hypothesis_type == "c2"))
    assert row.theory_id == "TH-legacy-random"
    assert row.theory_key == "c2"
    assert row.rank > 1
    assert (row.analyst_status, row.analyst_notes, row.reviewed_at, row.reviewer_id) == (
        "confirmed", "analyst-confirmed", "2026-09-22T10:00:00Z", "analyst-test")


def test_semantic_ids_are_full_deterministic_and_unique():
    make_id = getattr(engine, "semantic_theory_id", None)
    assert callable(make_id), "semantic_theory_id must replace eight random hex characters"
    ids = {make_id(f"job-{i // 100}", None, "host", f"scope-{i}", "c2") for i in range(100_000)}
    assert len(ids) == 100_000
    assert all(len(value) == 39 and uuid.UUID(value[3:]).version == 5 for value in ids)
    assert make_id("job", None, "host", "10.0.0.1", "c2") == make_id("job", "", "host", "10.0.0.1", "c2")
    assert make_id("job", "before", "host", "10.0.0.1", "c2") != make_id("job", "after", "host", "10.0.0.1", "c2")
    assert make_id("a|b", None, "host", "c", "d") != make_id("a", "b", "host", "c", "d")


def test_regeneration_removes_stale_scopes_and_keys(db_session, sample_job):
    job = sample_job.job_id
    _host(db_session, job, "10.0.0.2")
    _alert(db_session, job, "10.0.0.2")
    db_session.commit()
    generate_all_theories(db_session, job)
    reviewed = db_session.scalar(select(Theory).where(
        Theory.scope_type == "job", Theory.theory_key == "c2"))
    reviewed_id = reviewed.theory_id
    reviewed.analyst_status = "confirmed"
    reviewed.analyst_notes = "keep"
    db_session.commit()
    db_session.query(Alert).filter(Alert.job_id == job).delete()
    db_session.commit()
    generate_all_theories(db_session, job)
    assert not db_session.scalar(select(Theory).where(Theory.scope_type == "host"))
    assert not db_session.scalar(select(Theory).where(Theory.theory_key == "c2"))
    # Once evidence restores the branch, its deterministic identity returns.
    _alert(db_session, job, "10.0.0.2")
    db_session.commit()
    generate_all_theories(db_session, job)
    restored = db_session.scalar(select(Theory).where(
        Theory.scope_type == "job", Theory.theory_key == "c2"))
    assert restored.theory_id == reviewed_id


def test_legacy_null_job_scope_keeps_review_on_regeneration(db_session, sample_job):
    job = sample_job.job_id
    legacy = Theory(job_id=job, theory_id="TH-legacy-null-scope", scope_type="job",
        scope_id=None, phase_key="", scope_id_key="", theory_key="benign",
        label="Old benign", hypothesis_type="benign", score=0.2,
        confidence="low", rank=1, created_at=_now(),
        analyst_status="confirmed", analyst_notes="keep review")
    db_session.add(legacy)
    db_session.commit()
    generate_all_theories(db_session, job)
    db_session.refresh(legacy)
    assert legacy.theory_id == "TH-legacy-null-scope"
    assert legacy.scope_id is None
    assert (legacy.analyst_status, legacy.analyst_notes) == ("confirmed", "keep review")
    assert db_session.scalar(select(func.count()).select_from(Theory).where(
        Theory.job_id == job, Theory.theory_key == "benign")) == 1


@pytest.mark.parametrize("entrypoint", ["all", "single"])
def test_coexisting_job_scope_keys_keep_reviewed_legacy_row(db_session, sample_job, entrypoint):
    job = sample_job.job_id
    common = dict(job_id=job, scope_type="job", phase_key="", theory_key="benign",
                  label="Old benign", hypothesis_type="benign", score=0.2,
                  confidence="low", rank=1, created_at=_now())
    legacy = Theory(**common, theory_id="TH-reviewed-legacy", scope_id=None,
                    scope_id_key="", analyst_status="confirmed",
                    analyst_notes="analyst decision", reviewed_at="2026-09-22T10:00:00Z",
                    reviewer_id="reviewer-a")
    current = Theory(**common, theory_id="TH-unreviewed-current", scope_id=job,
                     scope_id_key=job, analyst_status="unreviewed")
    db_session.add_all([legacy, current])
    db_session.commit()
    if entrypoint == "all":
        generate_all_theories(db_session, job)
    else:
        generate_theories(db_session, job)
    rows = list(db_session.scalars(select(Theory).where(
        Theory.job_id == job, Theory.scope_type == "job", Theory.theory_key == "benign")))
    assert len(rows) == 1
    assert rows[0].id == legacy.id
    assert rows[0].theory_id == "TH-reviewed-legacy"
    assert (rows[0].analyst_status, rows[0].analyst_notes, rows[0].reviewed_at, rows[0].reviewer_id) == (
        "confirmed", "analyst decision", "2026-09-22T10:00:00Z", "reviewer-a")


def test_coexisting_job_scope_keys_merge_latest_nonnull_review_fields(db_session, sample_job):
    job = sample_job.job_id
    common = dict(job_id=job, scope_type="job", phase_key="", theory_key="benign",
                  label="Old benign", hypothesis_type="benign", score=0.2,
                  confidence="low", rank=1, created_at=_now())
    legacy = Theory(**common, theory_id="TH-reviewed-legacy", scope_id=None,
                    scope_id_key="", analyst_status="confirmed", analyst_notes="old note",
                    reviewed_at="2026-09-21T10:00:00Z", reviewer_id="reviewer-a")
    current = Theory(**common, theory_id="TH-reviewed-current", scope_id=job,
                     scope_id_key=job, analyst_status="false_positive", analyst_notes="new note",
                     reviewed_at="2026-09-22T10:00:00Z")
    db_session.add_all([legacy, current])
    db_session.commit()
    generate_all_theories(db_session, job)
    rows = list(db_session.scalars(select(Theory).where(
        Theory.job_id == job, Theory.scope_type == "job", Theory.theory_key == "benign")))
    assert len(rows) == 1
    assert rows[0].theory_id == "TH-reviewed-legacy"
    assert (rows[0].analyst_status, rows[0].analyst_notes, rows[0].reviewed_at, rows[0].reviewer_id) == (
        "false_positive", "new note", "2026-09-22T10:00:00Z", "reviewer-a")


def test_cancel_after_final_flush_rolls_back_theories(db_engine, monkeypatch):
    from sqlalchemy.orm import Session
    from backend.app.models.job import Job
    from backend.app.pipeline.runtime_control import JobCancellationRequested
    with Session(db_engine) as db:
        db.add(Job(job_id="cancel-final", status="running", execution_profile="standard", created_at=_now()))
        db.commit()
        cancelled = {"requested": False}
        def request_after_flush(*args):
            cancelled["requested"] = True
        def cancellation_checkpoint():
            if cancelled["requested"]:
                raise JobCancellationRequested()
        event.listen(db, "after_flush", request_after_flush)
        monkeypatch.setattr(engine, "checkpoint", cancellation_checkpoint)
        try:
            with pytest.raises(JobCancellationRequested):
                generate_all_theories(db, "cancel-final")
        finally:
            event.remove(db, "after_flush", request_after_flush)
        assert db.is_active
        assert db.scalar(select(func.count()).select_from(Theory)) == 0
    with Session(db_engine) as observer:
        assert observer.scalar(select(func.count()).select_from(Theory)) == 0


def test_random_prefix_collision_cannot_break_generation(db_session, c2_job, monkeypatch):
    # The old random generator issued the same truncated prefix on retries.
    monkeypatch.setattr(engine, "uuid4", lambda: uuid.UUID("12345678-1111-4111-8111-111111111111"), raising=False)
    rows = generate_theories(db_session, c2_job.job_id)
    assert len({row.theory_id for row in rows}) == len(rows)


def test_flush_failure_rolls_back_all_scopes(db_engine, monkeypatch):
    from sqlalchemy.orm import Session
    from backend.app.models.job import Job
    with Session(db_engine) as db:
        db.add(Job(job_id="rollback", status="running", execution_profile="standard", created_at=_now()))
        db.commit()
        for i in range(110):
            ip = f"10.0.0.{i + 1}"
            _host(db, "rollback", ip)
            _alert(db, "rollback", ip)
        db.commit()
        flush = db.flush
        batches = []
        def fail_second_flush(*args, **kwargs):
            if db.new or db.dirty:
                batches.append(len(db.new))
                if len(batches) == 2:
                    raise RuntimeError("injected flush failure")
            return flush(*args, **kwargs)
        monkeypatch.setattr(db, "flush", fail_second_flush)
        with pytest.raises(RuntimeError, match="injected flush failure"):
            generate_all_theories(db, "rollback")
        monkeypatch.setattr(db, "flush", flush)
        assert db.scalar(select(func.count()).select_from(Theory)) == 0
        assert db.is_active
    with Session(db_engine) as observer:
        assert observer.scalar(select(func.count()).select_from(Theory)) == 0
