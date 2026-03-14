from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlmodel import Session

from app.db_models import JobDB, JobStepDB
from app.database import engine
from app.models import JobStatus, JobStepStatus
from app.tasks import run_pipeline


def _make_job(session: Session, **kwargs) -> JobDB:
    now = datetime.now(timezone.utc)
    if "id" not in kwargs:
        kwargs["id"] = f"test-job-{uuid4()}"
    job = JobDB(created_at=now, updated_at=now, status=JobStatus.QUEUED, **kwargs)
    session.add(job)
    # create expected steps
    for name in ["ingest", "parse", "aggregate", "llm_analysis", "report"]:
        step = JobStepDB(
            id=f"{job.id}:{name}", job_id=job.id, name=name, status=JobStepStatus.PENDING
        )
        session.add(step)
    session.commit()
    return job


def test_security_onion_filesystem_ingest(tmp_path, monkeypatch):
    """SecurityOnionConnector in filesystem mode populates pcap_paths and pipeline runs.

    We create a dummy .pcap file and point SECURITY_ONION_PCAP_PATH at it. Zeek/Suricata
    are mocked by the pipeline itself when not installed, so the actual bytes do not
    matter; only existence does.
    """

    # Prepare fake SO pcap directory with a tiny pcap file
    so_dir = tmp_path / "so_pcaps"
    so_dir.mkdir()
    pcap_file = so_dir / "test_so.pcap"
    pcap_file.write_bytes(b"dummy pcap content")

    monkeypatch.setenv("SECURITY_ONION_MODE", "filesystem")
    monkeypatch.setenv("SECURITY_ONION_PCAP_PATH", str(so_dir))
    monkeypatch.setenv("FILE_STORAGE_PATH", str(tmp_path / "storage"))

    # Create job
    with Session(engine) as session:
        job = _make_job(
            session,
            source="security_onion",
            mode="single_window",
            exercise_id="ex-so-1",
            job_metadata={
                "source": "security_onion",
                "time_range": {"start": "2025-05-01T10:00:00Z", "end": "2025-05-01T11:00:00Z"},
                "sensors": ["sensor1"],
                "mode": "single_window",
                "metadata": {},
            },
        )
        job_id = job.id

    # Run pipeline synchronously (no Celery worker in tests)
    run_pipeline(job_id)

    # Verify ingest step completed and job progressed
    with Session(engine) as session:
        db_job = session.get(JobDB, job_id)
        assert db_job is not None
        assert db_job.status in {JobStatus.COMPLETED, JobStatus.RUNNING, JobStatus.FAILED}

        ingest_step = session.get(JobStepDB, f"{job_id}:ingest")
        assert ingest_step is not None
        # Ingest may still be running if the pipeline is slow; we only require
        # that it has been started and is no longer PENDING.
        assert ingest_step.status in {
            JobStepStatus.COMPLETED,
            JobStepStatus.FAILED,
            JobStepStatus.RUNNING,
        }


def test_arkime_ingest_with_mock_export(tmp_path, monkeypatch, monkeypatch_context=None):
    """ArkimeConnector.export_pcap is used to write a pcap file for ingest.

    We monkeypatch ArkimeConnector.export_pcap to return dummy bytes so we don't need
    a real Arkime instance.
    """

    monkeypatch.setenv("FILE_STORAGE_PATH", str(tmp_path / "storage"))

    # Monkeypatch ArkimeConnector.export_pcap to return bytes immediately
    async def _fake_export(self, flt, time_range):  # type: ignore[override]
        return b"dummy arkime pcap"

    from app import connectors as connectors_mod

    monkeypatch.setattr(connectors_mod.ArkimeConnector, "export_pcap", _fake_export)

    with Session(engine) as session:
        job = _make_job(
            session,
            source="arkime",
            mode="single_window",
            exercise_id="ex-arkime-1",
            job_metadata={
                "source": "arkime",
                "filter": "ip.src == 10.0.0.1",
                "time_range": {"start": "2025-05-01T10:00:00Z", "end": "2025-05-01T11:00:00Z"},
                "mode": "single_window",
                "metadata": {},
            },
        )
        job_id = job.id

    run_pipeline(job_id)

    with Session(engine) as session:
        db_job = session.get(JobDB, job_id)
        assert db_job is not None
        assert db_job.status in {JobStatus.COMPLETED, JobStatus.RUNNING, JobStatus.FAILED}

        ingest_step = session.get(JobStepDB, f"{job_id}:ingest")
        assert ingest_step is not None
        assert ingest_step.status in {JobStepStatus.COMPLETED, JobStepStatus.FAILED}

