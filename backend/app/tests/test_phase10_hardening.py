"""Phase 10 tests — Operational Hardening.

Covers:
  - Pipeline diagnostics (FileDiagnostic, PipelineDiagnostics)
  - telemetry_diagnostics.json persistence
  - Error budget enforcement
  - Bundle upload size guardrails (preflight)
  - Support bundle telemetry enrichment
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from backend.app.database_v2 import Base, _set_sqlite_pragmas
from backend.app.models.job import Job
from backend.app.pipeline.preflight import (
    PreflightResult,
    check_disk_space,
    check_disk_thresholds,
    check_job_quota,
)
from backend.app.pipeline.telemetry_pipeline import (
    FileDiagnostic,
    PipelineDiagnostics,
    _parse_entry,
    _save_diagnostics,
    run_telemetry_pipeline,
)
from backend.app.schemas.common import SourceType


def _uid():
    return str(uuid.uuid4())


def _ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)
    yield session
    session.close()
    engine.dispose()


# ── FileDiagnostic ──────────────────────────────────────────────────


class TestFileDiagnostic:
    def test_defaults(self):
        d = FileDiagnostic(filename="test.json")
        assert d.status == "skipped"
        assert d.events_produced == 0
        assert d.parser_name is None
        assert d.error is None

    def test_ok_status(self):
        d = FileDiagnostic(filename="alerts.json", parser_name="zeek_json", status="ok", events_produced=42)
        assert d.status == "ok"
        assert d.events_produced == 42


# ── PipelineDiagnostics ────────────────────────────────────────────


class TestPipelineDiagnostics:
    def test_aggregation_properties(self):
        diag = PipelineDiagnostics(job_id="j1")
        diag.files.append(FileDiagnostic(filename="a.json", status="ok"))
        diag.files.append(FileDiagnostic(filename="b.json", status="error", error="bad"))
        diag.files.append(FileDiagnostic(filename="c.json", status="skipped"))
        diag.files.append(FileDiagnostic(filename="d.json", status="ok"))
        assert diag.files_ok == 2
        assert diag.files_error == 1
        assert diag.files_skipped == 1

    def test_to_dict(self):
        diag = PipelineDiagnostics(job_id="j2")
        diag.files.append(FileDiagnostic(filename="x.log", status="ok", events_produced=5))
        d = diag.to_dict()
        assert d["job_id"] == "j2"
        assert d["files_ok"] == 1
        assert d["files_error"] == 0
        assert isinstance(d["files"], list)
        assert d["files"][0]["filename"] == "x.log"

    def test_phase_durations(self):
        diag = PipelineDiagnostics(job_id="j3")
        diag.phase_durations_ms["parse"] = 123.4
        diag.phase_durations_ms["correlate"] = 56.7
        d = diag.to_dict()
        assert d["phase_durations_ms"]["parse"] == 123.4


# ── _save_diagnostics ──────────────────────────────────────────────


def test_save_diagnostics(tmp_path):
    diag = PipelineDiagnostics(job_id="j-save")
    diag.files.append(FileDiagnostic(filename="a.log", status="ok", events_produced=10))
    _save_diagnostics(tmp_path, diag)
    out = tmp_path / "telemetry_diagnostics.json"
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["job_id"] == "j-save"
    assert data["files_ok"] == 1


# ── _parse_entry returns diagnostic ───────────────────────────────


def test_parse_entry_no_parser(tmp_path):
    """When no parser matches, _parse_entry returns skipped diagnostic."""
    f = tmp_path / "unknown.xyz"
    f.write_text("data")
    results, diag = _parse_entry(f, job_id="j1", source_type=SourceType.log_bundle)
    assert results == []
    assert diag.status == "skipped"
    assert diag.parser_name is None
    assert "No parser" in (diag.error or "")


# ── Preflight guardrails ──────────────────────────────────────────


def test_check_disk_space_passes(tmp_path):
    result = check_disk_space(1024, tmp_path, preflight_multiplier=2)
    assert result.ok is True


def test_check_disk_thresholds(tmp_path):
    warn, crit, pct = check_disk_thresholds(tmp_path, warn_pct=0, critical_pct=0)
    assert warn is True  # 0% threshold always exceeded
    assert crit is True
    assert pct >= 0


def test_check_job_quota_under(tmp_path):
    (tmp_path / "file.bin").write_bytes(b"x" * 100)
    assert check_job_quota(tmp_path, max_job_disk_bytes=1000) is False


def test_check_job_quota_over(tmp_path):
    (tmp_path / "file.bin").write_bytes(b"x" * 2000)
    assert check_job_quota(tmp_path, max_job_disk_bytes=1000) is True


# ── Pipeline integration with diagnostics ─────────────────────────


def _make_job_dir(tmp_path, manifest_entries, create_files=True):
    """Create a minimal job directory with manifest and optional files."""
    job_dir = tmp_path / "job1"
    job_dir.mkdir()
    tel_dir = job_dir / "input" / "telemetry"
    tel_dir.mkdir(parents=True)

    manifest = {
        "job_id": "j-test",
        "created_at": _ts(),
        "entries": manifest_entries,
    }
    (job_dir / "source_manifest.json").write_text(json.dumps(manifest))

    if create_files:
        for entry in manifest_entries:
            (tel_dir / entry["filename"]).write_text('{"test": true}')

    return job_dir


def test_pipeline_writes_diagnostics_file(tmp_path, db):
    """Pipeline should write telemetry_diagnostics.json even with no parsers."""
    job_id = _uid()
    job = Job(
        job_id=job_id,
        job_name="diag-test",
        status="running",
        execution_profile="full",
        created_at=_ts(),
    )
    db.add(job)
    db.commit()

    job_dir = _make_job_dir(tmp_path, [
        {"filename": "unknown.xyz", "source_type": "log_bundle"},
    ])

    result = run_telemetry_pipeline(job_id, job_dir, db)
    diag_path = job_dir / "telemetry_diagnostics.json"
    assert diag_path.exists(), "telemetry_diagnostics.json should be created"

    data = json.loads(diag_path.read_text())
    assert data["job_id"] == job_id
    assert data["files_skipped"] >= 1
    assert "phase_durations_ms" in data
    assert "parse" in data["phase_durations_ms"]


def test_pipeline_no_manifest_still_writes_diagnostics(tmp_path, db):
    """Even when manifest is missing, diagnostics should be saved."""
    job_dir = tmp_path / "job_empty"
    job_dir.mkdir()

    result = run_telemetry_pipeline("j-none", job_dir, db)
    assert result["error"] == "no_manifest"
    diag_path = job_dir / "telemetry_diagnostics.json"
    assert diag_path.exists()


def test_pipeline_missing_file_creates_skipped_diagnostic(tmp_path, db):
    """Files listed in manifest but missing on disk should be 'skipped'."""
    job_id = _uid()
    job = Job(
        job_id=job_id,
        job_name="missing-file-test",
        status="running",
        execution_profile="full",
        created_at=_ts(),
    )
    db.add(job)
    db.commit()

    job_dir = _make_job_dir(tmp_path, [
        {"filename": "ghost.log", "source_type": "log_bundle"},
    ], create_files=False)

    result = run_telemetry_pipeline(job_id, job_dir, db)
    diag_path = job_dir / "telemetry_diagnostics.json"
    data = json.loads(diag_path.read_text())
    assert data["files_skipped"] >= 1
    assert data["files"][0]["status"] == "skipped"
    assert "not found" in data["files"][0]["error"].lower()


# ── Error budget ──────────────────────────────────────────────────


def test_error_budget_in_summary(tmp_path, db):
    """Pipeline summary should include files_error count."""
    job_id = _uid()
    job = Job(
        job_id=job_id,
        job_name="budget-test",
        status="running",
        execution_profile="full",
        created_at=_ts(),
    )
    db.add(job)
    db.commit()

    job_dir = _make_job_dir(tmp_path, [
        {"filename": "ok.json", "source_type": "log_bundle"},
    ])

    result = run_telemetry_pipeline(job_id, job_dir, db)
    # files_error should be present in the summary
    assert "files_error" in result
    # phase_durations_ms should be present
    assert "phase_durations_ms" in result

