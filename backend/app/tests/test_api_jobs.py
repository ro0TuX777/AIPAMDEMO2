"""Tests for V1 Jobs API.

NOTE: These tests depend on the V1 tasks module (run_pipeline) which was
removed in V2. Skipped until ported to V2 worker.run_job.
"""
from __future__ import annotations

import json
from typing import Any, Dict

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

pytestmark = pytest.mark.skip(
    reason="V1 tasks module removed — tests reference tasks.run_pipeline"
)

from backend.app.main_v2 import create_app

real_app = create_app()
from backend.app import database as database_mod
from backend.app.db_models import JobDB, JobStepDB
from backend.app.domain_models import JobStatus, JobStepStatus


def _create_test_app(file_storage_path: str, reports_path: str) -> FastAPI:
    # Create a new FastAPI instance that mirrors the main app configuration
    # but uses a temporary reports directory to avoid filesystem coupling in tests.
    test_app = FastAPI(title="AIPAM API", version="0.1.0")

    # Mount a safe temporary reports directory
    from fastapi.staticfiles import StaticFiles

    test_app.mount("/reports", StaticFiles(directory=reports_path), name="reports")

    # Include the same routes as the real app
    for route in real_app.routes:
        test_app.router.routes.append(route)

    return test_app


@pytest_asyncio.fixture
async def client():
    transport = httpx.ASGITransport(app=real_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


def _get_job(job_id: str) -> JobDB | None:
    from sqlmodel import Session

    with Session(database_mod.engine) as session:
        return session.get(JobDB, job_id)


def _get_steps(job_id: str) -> list[JobStepDB]:
    from sqlmodel import Session, select

    with Session(database_mod.engine) as session:
        return session.exec(select(JobStepDB).where(JobStepDB.job_id == job_id)).all()


@pytest.mark.asyncio
async def test_create_upload_job_triggers_pipeline(monkeypatch, tmp_path, client):
    # Avoid touching the real DB file by pointing DATABASE_URL at a tmp sqlite DB
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test_api_jobs.db")

    # Reinitialize engine and tables for this test DB
    from sqlmodel import SQLModel, create_engine

    test_engine = create_engine(f"sqlite:///{tmp_path}/test_api_jobs.db", echo=False)
    SQLModel.metadata.create_all(test_engine)

    # Monkeypatch engine used by the app to the test engine
    database_mod.engine = test_engine

    # Monkeypatch run_pipeline.delay so we don't need a Celery worker
    called: Dict[str, Any] = {}

    def _fake_delay(job_id: str) -> None:  # type: ignore[override]
        called["job_id"] = job_id

    from app import tasks as tasks_mod

    monkeypatch.setattr(tasks_mod.run_pipeline, "delay", _fake_delay)

    # Prepare a tiny in-memory pcap upload
    files = {
        "pcap_files": ("test.pcap", b"dummy pcap content", "application/octet-stream"),
    }
    data = {
        "mode": "single_window",
        "metadata": json.dumps({"exercise_id": "ex-upload-1"}),
    }

    resp = await client.post("/api/v1/jobs", data=data, files=files)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    job_id = body["job_id"]

    # Celery task scheduled with correct job_id
    assert called.get("job_id") == job_id

    # Job and steps exist in DB
    job = _get_job(job_id)
    assert job is not None
    assert job.source == "upload"
    assert job.mode == "single_window"
    assert job.job_metadata.get("exercise_id") == "ex-upload-1"

    steps = _get_steps(job_id)
    step_names = {s.name for s in steps}
    assert step_names == {"ingest", "parse", "aggregate", "llm_analysis", "report"}


@pytest.mark.asyncio
async def test_create_security_onion_job_triggers_pipeline(monkeypatch, tmp_path, client):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test_api_jobs_so.db")

    from sqlmodel import SQLModel, create_engine

    test_engine = create_engine(f"sqlite:///{tmp_path}/test_api_jobs_so.db", echo=False)
    SQLModel.metadata.create_all(test_engine)

    database_mod.engine = test_engine

    called: Dict[str, Any] = {}

    def _fake_delay(job_id: str) -> None:  # type: ignore[override]
        called["job_id"] = job_id

    from app import tasks as tasks_mod

    monkeypatch.setattr(tasks_mod.run_pipeline, "delay", _fake_delay)

    payload = {
        "source": "security_onion",
        "time_range": {"start": "2025-05-01T10:00:00Z", "end": "2025-05-01T11:00:00Z"},
        "sensors": ["sensor1"],
        "mode": "single_window",
        "metadata": {"exercise_id": "ex-so-1"},
    }

    resp = await client.post("/api/v1/jobs/from_security_onion", json=payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    job_id = body["job_id"]

    assert called.get("job_id") == job_id

    job = _get_job(job_id)
    assert job is not None
    assert job.source == "security_onion"
    assert job.mode == "single_window"
    assert job.job_metadata["source"] == "security_onion"
    assert job.job_metadata["metadata"].get("exercise_id") == "ex-so-1"


@pytest.mark.asyncio
async def test_get_job_status_returns_steps(monkeypatch, tmp_path, client):
    """Job status endpoint returns overall status and per-step statuses."""

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test_api_jobs_status.db")

    from sqlmodel import SQLModel, create_engine

    test_engine = create_engine(f"sqlite:///{tmp_path}/test_api_jobs_status.db", echo=False)
    SQLModel.metadata.create_all(test_engine)
    database_mod.engine = test_engine

    called: Dict[str, Any] = {}

    def _fake_delay(job_id: str) -> None:  # type: ignore[override]
        called["job_id"] = job_id

    from app import tasks as tasks_mod

    monkeypatch.setattr(tasks_mod.run_pipeline, "delay", _fake_delay)

    payload = {
        "source": "arkime",
        "filter": "ip.src == 10.0.0.1",
        "time_range": {"start": "2025-05-01T10:00:00Z", "end": "2025-05-01T11:00:00Z"},
        "mode": "single_window",
        "metadata": {"exercise_id": "ex-arkime-status"},
    }

    # Create job via API
    resp = await client.post("/api/v1/jobs/from_arkime", json=payload)
    assert resp.status_code == 201, resp.text
    job_id = resp.json()["job_id"]

    # Mark some steps as started/completed to make status interesting
    from sqlmodel import Session, select

    with Session(database_mod.engine) as session:
        job = session.get(JobDB, job_id)
        assert job is not None
        job.status = JobStatus.RUNNING
        session.add(job)

        steps = session.exec(select(JobStepDB).where(JobStepDB.job_id == job_id)).all()
        for step in steps:
            if step.name == "ingest":
                step.status = JobStepStatus.COMPLETED
                step.message = "ingest done"
            elif step.name == "parse":
                step.status = JobStepStatus.RUNNING
            session.add(step)
        session.commit()

    # Call status endpoint
    status_resp = await client.get(f"/api/v1/jobs/{job_id}")
    assert status_resp.status_code == 200, status_resp.text
    body = status_resp.json()
    assert body["job_id"] == job_id
    assert body["status"] == JobStatus.RUNNING

    steps = {s["name"]: s for s in body["steps"]}
    assert steps["ingest"]["status"] == JobStepStatus.COMPLETED
    assert steps["ingest"]["message"] == "ingest done"
    assert steps["parse"]["status"] == JobStepStatus.RUNNING


@pytest.mark.asyncio
async def test_get_job_result_requires_completed_status(monkeypatch, tmp_path, client):
    """Result endpoint returns 409 if job is not completed and 200 when it is."""

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test_api_jobs_result.db")

    from sqlmodel import SQLModel, create_engine, Session

    test_engine = create_engine(f"sqlite:///{tmp_path}/test_api_jobs_result.db", echo=False)
    SQLModel.metadata.create_all(test_engine)
    database_mod.engine = test_engine

    called: Dict[str, Any] = {}

    def _fake_delay(job_id: str) -> None:  # type: ignore[override]
        called["job_id"] = job_id

    from app import tasks as tasks_mod

    monkeypatch.setattr(tasks_mod.run_pipeline, "delay", _fake_delay)

    payload = {
        "source": "arkime",
        "filter": "ip.src == 10.0.0.1",
        "time_range": {"start": "2025-05-01T10:00:00Z", "end": "2025-05-01T11:00:00Z"},
        "mode": "single_window",
        "metadata": {"exercise_id": "ex-arkime-result"},
    }

    # Create job via API (QUEUED initially)
    resp = await client.post("/api/v1/jobs/from_arkime", json=payload)
    assert resp.status_code == 201, resp.text
    job_id = resp.json()["job_id"]

    # Not completed yet -> expect 409
    resp_early = await client.get(f"/api/v1/jobs/{job_id}/result")
    assert resp_early.status_code == 409

    # Now mark job as COMPLETED and insert a JobResultDB row
    from backend.app.db_models import JobResultDB

    with Session(database_mod.engine) as session:
        job = session.get(JobDB, job_id)
        assert job is not None
        job.status = JobStatus.COMPLETED
        session.add(job)

        result = {
            "job_id": job_id,
            "status": JobStatus.COMPLETED,
            "summary": {
                "classification": None,
                "severity": "low",
                "key_findings": [],
                "mitre_techniques": [],
            },
            "hosts": [],
            "raw": {
                "alerts": [],
                "llm_analysis_raw": {
                    "chunks": [],
                    "summary": {
                        "classification": None,
                        "severity": "low",
                        "key_findings": [],
                        "mitre_techniques": [],
                    },
                },
            },
            "report_urls": {"html": "http://example/report.html", "markdown": ""},
        }
        row = JobResultDB(job_id=job_id, result=result)
        session.add(row)
        session.commit()

    # Now result should be available
    resp_ok = await client.get(f"/api/v1/jobs/{job_id}/result")
    assert resp_ok.status_code == 200, resp_ok.text
    body = resp_ok.json()
    assert body["job_id"] == job_id
    assert body["status"] == JobStatus.COMPLETED
    assert body["summary"]["severity"] == "low"
    # The raw LLM summary should mirror the top-level AnalysisSummary returned.
    assert body["raw"]["llm_analysis_raw"]["summary"]["severity"] == body["summary"]["severity"]
    assert body["raw"]["llm_analysis_raw"]["summary"] == body["summary"]


@pytest.mark.asyncio
async def test_create_arkime_job_triggers_pipeline(monkeypatch, tmp_path, client):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test_api_jobs_arkime.db")

    from sqlmodel import SQLModel, create_engine

    test_engine = create_engine(f"sqlite:///{tmp_path}/test_api_jobs_arkime.db", echo=False)
    SQLModel.metadata.create_all(test_engine)

    database_mod.engine = test_engine

    called: Dict[str, Any] = {}

    def _fake_delay(job_id: str) -> None:  # type: ignore[override]
        called["job_id"] = job_id

    from app import tasks as tasks_mod

    monkeypatch.setattr(tasks_mod.run_pipeline, "delay", _fake_delay)

    payload = {
        "source": "arkime",
        "filter": "ip.src == 10.0.0.1",
        "time_range": {"start": "2025-05-01T10:00:00Z", "end": "2025-05-01T11:00:00Z"},
        "mode": "single_window",
        "metadata": {"exercise_id": "ex-arkime-1"},
    }

    resp = await client.post("/api/v1/jobs/from_arkime", json=payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    job_id = body["job_id"]

    assert called.get("job_id") == job_id

    job = _get_job(job_id)
    assert job is not None
    assert job.source == "arkime"
    assert job.mode == "single_window"
    assert job.job_metadata["source"] == "arkime"
    assert job.job_metadata["metadata"].get("exercise_id") == "ex-arkime-1"
