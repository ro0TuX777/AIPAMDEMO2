"""Job lifecycle service contracts for cancel, rerun, and phase re-analysis."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.app.config_v2 import Settings
from backend.app.database_v2 import Base
from backend.app.models.job import Job
from backend.app.models.job_pcap import JobPcap
from backend.app.models.upload import Upload
from backend.app.services.job_lifecycle import (
    JobLifecycleError,
    cancel_job,
    reanalyze_job,
    rerun_job,
)


@pytest.fixture
def lifecycle(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'lifecycle.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    settings = Settings(
        aipam_api_token="lifecycle-test",
        aipam_job_root=tmp_path / "jobs",
        aipam_upload_root=tmp_path / "uploads",
    )
    settings.aipam_job_root.mkdir()
    yield engine, settings
    engine.dispose()


def seed_job(db: Session, status="queued", job_id="job"):
    job = Job(
        job_id=job_id,
        job_name="Original",
        notes="Original notes",
        status=status,
        execution_profile="deep",
        priority="high",
        source_type="pcap+logs",
        exercise_id="exercise",
        upload_id="upload",
        pcap_filename="2 PCAPs",
        pcap_size_bytes=99,
        pcap_sha256=None,
        source_manifest_json='{"entries": []}',
        error_summary="previous error",
        created_at="2026-09-20T00:00:00.000000Z",
    )
    db.add(job)
    db.flush()
    return job


@pytest.mark.parametrize("status", ["queued", "running"])
def test_cancel_transitions_an_active_job_to_canceled(lifecycle, status):
    engine, _ = lifecycle
    with Session(engine) as db:
        job = seed_job(db, status=status)
        db.commit()
        cancel_job(job, db)
        assert job.status == "canceled"
        assert job.completed_at.endswith("Z")
    with Session(engine) as db:
        assert db.get(Job, "job").status == "canceled"


@pytest.mark.parametrize("status", ["completed", "completed_with_errors", "failed", "canceled", "deleted"])
def test_cancel_rejects_non_active_jobs(lifecycle, status):
    engine, _ = lifecycle
    with Session(engine) as db:
        job = seed_job(db, status=status)
        db.commit()
        with pytest.raises(JobLifecycleError) as exc:
            cancel_job(job, db)
        assert (exc.value.status_code, exc.value.detail) == (409, f"Cannot cancel job in '{status}' state")


def test_rerun_copies_pcap_metadata_and_preserves_source_context(lifecycle):
    engine, settings = lifecycle
    with Session(engine) as db:
        old = seed_job(db, status="completed")
        db.add_all([
            JobPcap(job_id=old.job_id, upload_id="before", label="before", filename="before.pcap", ordinal=0, size_bytes=40, sha256="a"),
            JobPcap(job_id=old.job_id, upload_id="after", label="after", filename="after.pcap", ordinal=1, size_bytes=59, sha256="b"),
        ])
        db.commit()
        response = rerun_job(old, db, settings, job_id_factory=lambda: "rerun")
        assert response.job_id == "rerun"
        assert (settings.aipam_job_root / "rerun").is_dir()
    with Session(engine) as db:
        rerun = db.get(Job, "rerun")
        assert rerun.artifact_layout_version == 2
        assert (rerun.job_name, rerun.notes, rerun.status) == ("Rerun of Original", "Rerun of job job", "queued")
        assert (rerun.execution_profile, rerun.priority) == ("deep", "high")
        # Preserve the route's existing rerun contract: source-specific context
        # is not copied, so the model defaults to a PCAP job.
        assert (rerun.source_type, rerun.exercise_id, rerun.source_manifest_json) == ("pcap", None, None)
        pcaps = db.scalars(select(JobPcap).where(JobPcap.job_id == "rerun").order_by(JobPcap.ordinal)).all()
        assert [(p.upload_id, p.label, p.filename, p.ordinal, p.size_bytes, p.sha256) for p in pcaps] == [
            ("before", "before", "before.pcap", 0, 40, "a"),
            ("after", "after", "after.pcap", 1, 59, "b"),
        ]


def test_rerun_commits_before_dispatch_can_observe_the_new_job(lifecycle):
    engine, settings = lifecycle
    with Session(engine) as db:
        old = seed_job(db, status="completed")
        db.commit()
        rerun_job(old, db, settings, job_id_factory=lambda: "rerun")
    with Session(engine) as db:
        assert db.get(Job, "rerun") is not None


@pytest.mark.parametrize("status", ["completed", "completed_with_errors", "failed"])
def test_reanalysis_queues_and_dispatches_only_the_requested_label(lifecycle, status):
    engine, _ = lifecycle
    dispatched = []
    with Session(engine) as db:
        job = seed_job(db, status=status)
        db.add_all([
            JobPcap(job_id=job.job_id, upload_id="before", label="before", filename="before.pcap", ordinal=0),
            JobPcap(job_id=job.job_id, upload_id="after", label="after", filename="after.pcap", ordinal=1),
        ])
        db.commit()

        def dispatch(job_id, label):
            with Session(engine) as observer:
                assert observer.get(Job, job_id).status == "queued"
            dispatched.append((job_id, label))

        result = reanalyze_job(job, db, "after", dispatch)
        assert result == {"job_id": "job", "pcap_label": "after", "status": "queued", "pcap_count": 1}
        assert dispatched == [("job", "after")]
    with Session(engine) as db:
        job = db.get(Job, "job")
        assert (job.status, job.error_summary) == ("queued", None)


@pytest.mark.parametrize("status", ["queued", "running", "canceled", "deleted"])
def test_reanalysis_rejects_invalid_lifecycle_state_without_dispatch(lifecycle, status):
    engine, _ = lifecycle
    with Session(engine) as db:
        job = seed_job(db, status=status)
        db.add(JobPcap(job_id=job.job_id, upload_id="after", label="after", filename="after.pcap", ordinal=0))
        db.commit()
        with pytest.raises(JobLifecycleError) as exc:
            reanalyze_job(job, db, "after", lambda *_: pytest.fail("must not dispatch"))
        assert exc.value.status_code == 409
        assert job.status == status


def test_reanalysis_rejects_an_unknown_label_without_dispatch(lifecycle):
    engine, _ = lifecycle
    with Session(engine) as db:
        job = seed_job(db, status="completed")
        db.commit()
        with pytest.raises(JobLifecycleError) as exc:
            reanalyze_job(job, db, "after", lambda *_: pytest.fail("must not dispatch"))
        assert (exc.value.status_code, exc.value.detail) == (400, "No PCAPs with label 'after' found for this job")
        assert job.status == "completed"


def test_reanalysis_does_not_write_terminal_state_if_dispatch_callback_fails(lifecycle):
    engine, _ = lifecycle
    with Session(engine) as db:
        job = seed_job(db, status="completed")
        db.add(JobPcap(job_id=job.job_id, upload_id="after", label="after", filename="after.pcap", ordinal=0))
        db.commit()
        with pytest.raises(JobLifecycleError) as exc:
            reanalyze_job(job, db, "after", lambda *_: (_ for _ in ()).throw(RuntimeError("Queue unavailable")))
        assert (exc.value.status_code, exc.value.detail) == (500, "Failed to dispatch re-analysis task")
    with Session(engine) as db:
        failed = db.get(Job, "job")
        assert failed.status == "queued"
        assert failed.error_summary is None


def test_routes_preserve_lifecycle_statuses_headers_and_phase_dispatch(app_client, monkeypatch):
    """Route wrappers keep the service contract visible at the public API."""
    from backend.app.api import jobs

    client, db = app_client
    db.add(Upload(
        upload_id="after",
        filename="after.pcap",
        size_bytes=1,
        sha256="after-sha",
        created_at="2026-09-20T00:00:00.000000Z",
    ))
    db.flush()
    completed = seed_job(db, status="completed", job_id="completed")
    db.flush()
    db.add(JobPcap(
        job_id=completed.job_id,
        upload_id="after",
        label="after",
        filename="after.pcap",
        ordinal=0,
    ))
    db.commit()
    dispatched = []
    monkeypatch.setattr(jobs, "dispatch_job_phase", lambda job_id, label: dispatched.append((job_id, label)))
    headers = {"Authorization": "Bearer test-token-v2", "X-Request-Id": "lifecycle-request"}

    canceled = client.post("/api/v1/jobs/completed/cancel", headers=headers)
    assert canceled.status_code == 409
    assert canceled.headers["X-Request-Id"] == "lifecycle-request"

    rerun = client.post("/api/v1/jobs/completed/rerun", headers=headers)
    assert rerun.status_code == 201
    assert rerun.headers["X-Request-Id"] == "lifecycle-request"
    assert rerun.json()["schema_version"] == "1.0"

    reanalysis = client.post(
        "/api/v1/jobs/completed/reanalyze",
        json={"pcap_label": "after"},
        headers=headers,
    )
    assert reanalysis.status_code == 202
    assert reanalysis.headers["X-Request-Id"] == "lifecycle-request"
    assert reanalysis.json() == {
        "job_id": "completed", "pcap_label": "after", "status": "queued", "pcap_count": 1,
    }
    assert dispatched == [("completed", "after")]
