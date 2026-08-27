"""End-to-end: staged source → scanners → canonical → score → Finding rows.

Drives the real orchestrator branch with a stub scanner, so the seam, the
scoring, the persistence, and the triage ledger are exercised together without
requiring Semgrep to be installed.
"""

import json
import tarfile
import io
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app.bluescrub import service as bs_service
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import DetectorClass, IssueFamily, Pillar, RiskClass
from backend.app.bluescrub.scanners.base import ScannerOutcome, ScannerSpec
from backend.app.database_v2 import Base
from backend.app.models.bluescrub import (
    BlueScrubJobLineage,
    BlueScrubProject,
    BlueScrubScoreHistory,
    BlueScrubTriageLedger,
)
from backend.app.models.finding import Finding
from backend.app.models.job import Job

PROJECT = "proj-1111-2222"


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'t.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture()
def job_dir(tmp_path):
    root = tmp_path / "jobs" / "job-1"
    (root / "input" / "source" / "src").mkdir(parents=True)
    (root / "input" / "source" / "src" / "agent.py").write_text(
        "import os\nos.system(cmd)\n"
    )
    return root


def _stub_finding(rule_id="stub.exec", sensor="semgrep", severity="ERROR",
                  family=IssueFamily.command_injection, pillar=Pillar.vulnerability,
                  line=2, confidence=0.85):
    return RawFinding(
        sensor=sensor, sensor_version="9.9.9", rule_id=rule_id,
        issue_family=family, pillar_hint=pillar,
        detector_class=DetectorClass.ast_pattern, raw_severity=severity,
        confidence=confidence, source_facet="source",
        title="dangerous exec", description="os.system detected",
        matched_tokens="os.system(cmd)", cwe=["CWE-78"],
        location=Location(kind="source", file="src/agent.py",
                          start_line=line, start_column=0, symbol="main"),
    )


@pytest.fixture()
def stub_registry(monkeypatch):
    """Replace the registry with a deterministic in-process scanner."""
    findings: list[RawFinding] = [_stub_finding()]

    def _run(source_root: Path, output_dir: Path) -> ScannerOutcome:
        return ScannerOutcome(
            sensor="semgrep", status="completed", findings=list(findings),
            version="9.9.9", ruleset_version="stub-pack", duration_ms=5,
        )

    spec = ScannerSpec(
        name="semgrep", run=_run,
        pillars=(Pillar.vulnerability, Pillar.co_optability),
        risk_class=RiskClass.parse_only,
    )
    monkeypatch.setattr(bs_service, "scanners_for", lambda profile: [spec])
    monkeypatch.setattr(bs_service, "required_for",
                        lambda pillar, profile: ["semgrep"])
    return findings


def test_pipeline_persists_findings_and_scores(db, job_dir, stub_registry):
    metrics = bs_service.analyze_and_persist(
        db, "job-1", job_dir, profile="triage",
    )["dacv"]

    rows = db.scalars(select(Finding).where(Finding.job_id == "job-1")).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.category == Pillar.vulnerability.value
    assert row.severity == "high"           # ERROR calibrated onto the ladder
    assert row.analyst_status == "unreviewed"
    assert row.finding_id.startswith("bs-vulnerability-semgrep-")

    evidence = json.loads(row.evidence_json)
    assert evidence["schema"] == "bluescrub/2"
    assert evidence["fingerprint_scheme"] == "fp/2"
    assert evidence["cwe"] == ["CWE-78"]
    assert evidence["issue_family"] == "command-injection"

    assert metrics["pillars"]["Vulnerability"]["score"] is not None
    assert metrics["pillars"]["Attribution"]["status"] == "not_assessed"
    assert metrics["pillars"]["Attribution"]["score"] is None
    assert metrics["overall"]["grade"] is None      # triage never completes all 5
    assert metrics["scoped"]["pillars_assessed"] == 1
    assert metrics["files_scanned"] == 1


def test_rescan_updates_in_place_and_preserves_triage(db, job_dir, stub_registry):
    bs_service.analyze_and_persist(db, "job-1", job_dir, profile="triage")

    row = db.scalars(select(Finding)).one()
    row.analyst_status = "false_positive"
    row.analyst_notes = "test fixture, not shipped"
    db.commit()

    # Re-persist the same job: scanner columns refresh, analyst columns do not.
    bs_service.analyze_and_persist(db, "job-1", job_dir, profile="triage")

    rows = db.scalars(select(Finding)).all()
    assert len(rows) == 1, "re-scan must upsert, not duplicate"
    assert rows[0].analyst_status == "false_positive"
    assert rows[0].analyst_notes == "test fixture, not shipped"


def test_triage_carries_forward_from_the_ledger(db, job_dir, stub_registry):
    """The ledger, not a prior job's rows — those are deleted by retention."""
    db.add(BlueScrubProject(project_id=PROJECT, display_name="agent",
                            created_at="2026-08-01T00:00:00Z"))
    db.commit()

    first = bs_service.analyze_and_persist(
        db, "job-1", job_dir, profile="triage", project_id=PROJECT,
    )
    finding_id = db.scalars(select(Finding.finding_id)).first()

    db.add(BlueScrubTriageLedger(
        project_id=PROJECT, finding_id=finding_id, status="false_positive",
        fingerprint_scheme="fp/2", decided_at="2026-08-02T00:00:00Z",
        origin_job_id="job-1",
    ))
    db.commit()

    # Delete the first job's findings entirely, as retention would.
    db.query(Finding).delete()
    db.commit()

    bs_service.analyze_and_persist(
        db, "job-2", job_dir, profile="triage", project_id=PROJECT,
    )
    row = db.scalars(select(Finding).where(Finding.job_id == "job-2")).one()

    assert row.analyst_status == "false_positive"
    carry = json.loads(row.evidence_json)["triage_carry"]
    assert carry["match"] == "exact"
    assert carry["origin_job_id"] == "job-1"
    assert first is not None


def test_lineage_and_history_recorded(db, job_dir, stub_registry):
    db.add(BlueScrubProject(project_id=PROJECT, display_name="agent",
                            created_at="2026-08-01T00:00:00Z"))
    db.commit()

    bs_service.analyze_and_persist(
        db, "job-1", job_dir, profile="deep", project_id=PROJECT,
    )

    lineage = db.get(BlueScrubJobLineage, "job-1")
    assert lineage.project_id == PROJECT
    assert lineage.analysis_kind == "source_audit"
    assert lineage.compatibility_signature.startswith("sha256:")

    history = db.scalars(select(BlueScrubScoreHistory)).all()
    assert len(history) == 1
    assert history[0].scoring_model == "dacvr/1.1"


def test_ad_hoc_job_writes_no_history(db, job_dir, stub_registry):
    bs_service.analyze_and_persist(db, "job-1", job_dir, profile="triage")
    assert db.scalars(select(BlueScrubScoreHistory)).all() == []


def test_scanner_crash_degrades_pillar_without_failing_the_job(db, job_dir, monkeypatch):
    def _boom(source_root, output_dir):
        raise RuntimeError("parser exploded on hostile input")

    spec = ScannerSpec(name="semgrep", run=_boom,
                       pillars=(Pillar.vulnerability,), risk_class=RiskClass.parse_only)
    monkeypatch.setattr(bs_service, "scanners_for", lambda profile: [spec])
    monkeypatch.setattr(bs_service, "required_for", lambda pillar, profile: ["semgrep"])

    metrics = bs_service.analyze_and_persist(
        db, "job-1", job_dir, profile="triage",
    )["dacv"]

    assert metrics["partial"] is True
    assert metrics["pillars"]["Vulnerability"]["status"] == "not_assessed"
    assert metrics["pillars"]["Vulnerability"]["score"] is None
    assert metrics["partial_reasons"][0]["sensor"] == "semgrep"


def test_orchestrator_branch_routes_code_artifact(db, tmp_path, stub_registry, monkeypatch):
    """The seam itself: a code_artifact job must never touch the PCAP path."""
    from backend.app.pipeline import orchestrator

    job_root = tmp_path / "jobs"
    (job_root / "job-x" / "input" / "source").mkdir(parents=True)
    (job_root / "job-x" / "input" / "source" / "a.py").write_text("import os\n")

    job = Job(
        job_id="job-x", status="queued", execution_profile="triage",
        priority="normal", source_type="code_artifact",
        created_at="2026-08-09T00:00:00Z",
    )
    db.add(job)
    db.commit()

    monkeypatch.setattr(orchestrator, "_emit", lambda *a, **kw: None)

    status = orchestrator._run_code_artifact_pipeline(
        "job-x", job, db, job_root=job_root, upload_root=tmp_path / "uploads",
    )

    assert status in ("completed", "completed_with_errors")
    assert job.metrics_json is not None
    assert json.loads(job.metrics_json)["dacv"]["analysis_kind"] == "source_audit"


def test_missing_source_fails_cleanly(db, tmp_path, monkeypatch):
    from backend.app.pipeline import orchestrator

    job_root = tmp_path / "jobs"
    (job_root / "job-y").mkdir(parents=True)
    job = Job(job_id="job-y", status="queued", execution_profile="triage",
              priority="normal", source_type="code_artifact",
              created_at="2026-08-09T00:00:00Z")
    db.add(job)
    db.commit()
    monkeypatch.setattr(orchestrator, "_emit", lambda *a, **kw: None)

    assert orchestrator._run_code_artifact_pipeline(
        "job-y", job, db, job_root=job_root, upload_root=tmp_path,
    ) == "failed"
    assert "No staged source" in (job.error_summary or "")
