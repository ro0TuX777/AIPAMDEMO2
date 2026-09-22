"""Creation contracts: persisted inputs, response metadata, and commit-before-dispatch."""

import hashlib
import io
import json
import sys
import zipfile
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.app.api import jobs
from backend.app.api.deps import get_db
from backend.app.config_v2 import Settings, get_settings
from backend.app.database_v2 import Base
from backend.app.models.bluescrub import BlueScrubJobLineage, BlueScrubProject
from backend.app.models.job import Job
from backend.app.models.job_log_source import JobLogSource
from backend.app.models.job_pcap import JobPcap
from backend.app.models.upload import Upload

AUTH = {"Authorization": "Bearer creation-test", "X-Request-Id": "creation-request"}


@pytest.fixture
def creation(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'creation.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    settings = Settings(
        aipam_api_token="creation-test",
        aipam_job_root=tmp_path / "jobs",
        aipam_upload_root=tmp_path / "uploads",
    )
    settings.aipam_job_root.mkdir()
    settings.aipam_upload_root.mkdir()
    app = FastAPI()
    app.include_router(jobs.router, prefix="/api/v1")

    def database():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_settings] = lambda: settings
    dispatched = []

    def dispatch(job_id):
        # A separate connection can only see records that were committed.
        with Session(engine) as db:
            job = db.get(Job, job_id)
            assert job is not None
            assert job.status == "queued"
            dispatched.append({
                "job_id": job_id,
                "pcaps": len(db.scalars(select(JobPcap).where(JobPcap.job_id == job_id)).all()),
                "logs": len(db.scalars(select(JobLogSource).where(JobLogSource.job_id == job_id)).all()),
                "lineage": db.get(BlueScrubJobLineage, job_id) is not None,
            })

    worker = SimpleNamespace(run_job=SimpleNamespace(delay=dispatch))
    monkeypatch.setitem(sys.modules, "backend.app.worker", worker)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield SimpleNamespace(client=client, engine=engine, settings=settings, dispatched=dispatched, worker=worker)
    engine.dispose()


def upload(ctx, name="capture.pcap", content=b"pcap", artifact_class="pcap", size=None):
    upload_id = name.replace(".", "-")
    directory = ctx.settings.aipam_upload_root / upload_id
    directory.mkdir()
    (directory / name).write_bytes(content)
    with Session(ctx.engine) as db:
        db.add(Upload(
            upload_id=upload_id, filename=name, size_bytes=len(content) if size is None else size,
            sha256=hashlib.sha256(content).hexdigest(), artifact_class=artifact_class, created_at="2026-09-20T00:00:00Z",
        ))
        db.commit()
    return upload_id


def post_job(ctx, **body):
    return ctx.client.post("/api/v1/jobs", json={"execution_profile": "standard", **body}, headers=AUTH)


def assert_created(ctx, response, *, pcaps=0, logs=0, lineage=False):
    assert response.status_code == 201, response.text
    assert response.headers["X-Request-Id"] == "creation-request"
    assert set(response.json()) == {"schema_version", "job_id"}
    assert response.json()["schema_version"] == "1.0"
    job_id = response.json()["job_id"]
    assert ctx.dispatched == [{"job_id": job_id, "pcaps": pcaps, "logs": logs, "lineage": lineage}]
    return job_id


@pytest.mark.parametrize("multiple", [False, True])
def test_pcap_creation_preserves_metadata_and_commits_before_dispatch(creation, multiple):
    first = upload(creation)
    body = {"upload_id": first}
    if multiple:
        second = upload(creation, "after.pcap", b"after")
        body = {"uploads": [{"upload_id": first, "label": "before"}, {"upload_id": second, "label": "after"}]}
    response = post_job(creation, **body, job_name="Investigation", notes="Notes", priority="high", exercise_id="exercise")
    job_id = assert_created(creation, response, pcaps=2 if multiple else 1)
    with Session(creation.engine) as db:
        job = db.get(Job, job_id)
        assert (job.job_name, job.notes, job.priority, job.exercise_id) == ("Investigation", "Notes", "high", "exercise")
        assert job.source_type == "pcap"
        assert job.upload_id == first
        assert job.pcap_filename == ("2 PCAPs" if multiple else "capture.pcap")
        assert job.pcap_size_bytes == (9 if multiple else 4)
        assert job.pcap_sha256 == (None if multiple else hashlib.sha256(b"pcap").hexdigest())
        rows = db.scalars(select(JobPcap).where(JobPcap.job_id == job_id).order_by(JobPcap.ordinal)).all()
        assert [row.label for row in rows] == (["before", "after"] if multiple else [None])


def test_binary_creation_stages_input_before_dispatch(creation):
    upload_id = upload(creation, "sample.exe", b"MZbinary", "binary")
    job_id = assert_created(creation, post_job(creation, upload_id=upload_id))
    assert (creation.settings.aipam_job_root / job_id / "input" / "sample.exe").read_bytes() == b"MZbinary"
    with Session(creation.engine) as db:
        job = db.get(Job, job_id)
        assert (job.source_type, job.job_name, job.pcap_filename) == ("binary", "Binary analysis: sample.exe", None)


@pytest.mark.parametrize("source_type", ["log_bundle", "c2_bundle", "netflow_bundle", "exercise_bundle"])
def test_bundle_only_creation_stages_manifest_and_traceability(creation, source_type):
    upload_id = upload(creation, "auth.log", b"event\n", "log")
    job_id = assert_created(creation, post_job(creation, upload_id=upload_id, source_type=source_type), logs=1)
    with Session(creation.engine) as db:
        job = db.get(Job, job_id)
        assert job.source_type == source_type
        assert job.job_name == f"{source_type} analysis"
        manifest = json.loads(job.source_manifest_json)
        assert len(manifest["entries"]) == 1
        log = db.scalars(select(JobLogSource).where(JobLogSource.job_id == job_id)).one()
        assert log.upload_id == upload_id
        assert log.filename == "auth.log"
    assert (creation.settings.aipam_job_root / job_id / "source_manifest.json").is_file()


def test_hybrid_creation_merges_labeled_log_sources(creation):
    pcap = upload(creation)
    logs = [upload(creation, "before.log", b"before", "log"), upload(creation, "after.log", b"after", "log")]
    job_id = assert_created(creation, post_job(
        creation, upload_id=pcap,
        bundle_uploads=[{"upload_id": logs[0], "label": "before"}, {"upload_id": logs[1], "label": "after"}],
    ), pcaps=1, logs=2)
    with Session(creation.engine) as db:
        job = db.get(Job, job_id)
        assert job.source_type == "pcap+logs"
        rows = db.scalars(select(JobLogSource).where(JobLogSource.job_id == job_id).order_by(JobLogSource.ordinal)).all()
        assert [row.label for row in rows] == ["before", "after"]
        assert all(row.upload_id is None for row in rows)
        persisted = json.loads((creation.settings.aipam_job_root / job_id / "source_manifest.json").read_text())
        assert persisted == json.loads(job.source_manifest_json)


@pytest.mark.parametrize("bound", [False, True])
def test_code_artifact_creation_binds_lineage_before_dispatch(creation, bound):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("main.py", "print('example')\n")
    upload_id = upload(creation, "source.zip", archive.getvalue(), "archive")
    if bound:
        with Session(creation.engine) as db:
            db.add(BlueScrubProject(project_id="project", display_name="Example", created_at="2026-09-19T00:00:00Z"))
            db.add(Job(job_id="parent", status="completed", source_type="code_artifact", execution_profile="standard", created_at="2026-09-19T00:00:00Z", completed_at="2026-09-19T01:00:00Z"))
            db.add(BlueScrubJobLineage(job_id="parent", project_id="project", compatibility_signature="prior"))
            db.commit()
    job_id = assert_created(creation, post_job(creation, upload_id=upload_id, source_type="code_artifact", project_id="project" if bound else None), lineage=True)
    with Session(creation.engine) as db:
        lineage = db.get(BlueScrubJobLineage, job_id)
        assert lineage.project_id == ("project" if bound else None)
        assert lineage.lineage_parent_job_id == ("parent" if bound else None)
        assert db.get(Job, job_id).source_type == "code_artifact"
    assert (creation.settings.aipam_job_root / job_id / "input" / "source" / "main.py").is_file()


@pytest.mark.parametrize("body,detail", [
    ({}, "Provide upload_id or uploads[]"),
    ({"upload_id": "missing"}, "Upload missing not found"),
    ({"source_type": "code_artifact"}, "code_artifact job requires an upload"),
    ({"source_type": "log_bundle"}, "upload_id required for bundle jobs"),
    ({"uploads": [{"upload_id": "missing"}] * 11}, "Max 10 PCAPs per job"),
])
def test_invalid_creation_never_dispatches(creation, body, detail):
    response = post_job(creation, **body)
    assert response.status_code == 400, response.text
    assert response.json()["detail"] == detail
    assert creation.dispatched == []
    with Session(creation.engine) as db:
        assert db.scalars(select(Job)).all() == []


def test_log_budget_rejects_before_staging(creation, monkeypatch):
    pcap = upload(creation)
    log = upload(creation, "large.log", b"small", "log", size=11 * 1024**3)
    from backend.app.pipeline import bundle_stager

    def unexpected_staging(**kwargs):
        pytest.fail("Rejected log bundles must not be staged")

    monkeypatch.setattr(bundle_stager, "stage_bundle", unexpected_staging)
    response = post_job(creation, upload_id=pcap, bundle_uploads=[{"upload_id": log}])
    assert response.status_code == 400
    assert "over the 10 GB per-job limit" in response.json()["detail"]
    assert creation.dispatched == []


def test_commit_failure_never_dispatches(creation, monkeypatch):
    upload_id = upload(creation)

    def fail_commit(self):
        raise RuntimeError("Commit failed")

    monkeypatch.setattr(Session, "commit", fail_commit)
    response = post_job(creation, upload_id=upload_id)
    assert response.status_code == 500
    assert creation.dispatched == []
    with Session(creation.engine) as db:
        assert db.scalars(select(Job)).all() == []


def test_dispatch_failure_keeps_committed_job_and_existing_201_response(creation, caplog):
    upload_id = upload(creation)

    def unavailable(job_id):
        raise RuntimeError("Queue unavailable")

    creation.worker.run_job.delay = unavailable
    response = post_job(creation, upload_id=upload_id)
    assert response.status_code == 201
    with Session(creation.engine) as db:
        assert db.get(Job, response.json()["job_id"]).status == "queued"
    assert "Failed to dispatch job" in caplog.text


@pytest.mark.parametrize("provider,connector_name,prefix", [
    ("arkime", "ArkimeConnector", "arkime_export_"),
    ("security_onion", "SecurityOnionConnector", "so_export_"),
])
@pytest.mark.parametrize("outcome", ["success", "disabled", "empty", "error"])
def test_connector_creation_preserves_import_and_error_contracts(creation, monkeypatch, provider, connector_name, prefix, outcome):
    from backend.app import connectors

    calls = []

    async def export_pcap(*args):
        calls.append(args)
        if outcome == "error":
            raise RuntimeError("Export unavailable")
        return b"" if outcome == "empty" else b"exported pcap"

    monkeypatch.setattr(connectors, connector_name, lambda: SimpleNamespace(enabled=outcome != "disabled", export_pcap=export_pcap))
    time_range = {"start": "2026-09-19T00:00:00Z", "end": "2026-09-19T01:00:00Z"}
    body = {"time_range": time_range, "metadata": {"exercise_id": "Imported investigation", "notes": "Imported notes"}}
    if provider == "arkime":
        body["filter"] = "ip == 192.0.2.1"
    else:
        body.update(sensors=["sensor-a"], filter_fields={"protocol": "tcp"})
    response = creation.client.post(f"/api/v1/jobs/from_{provider}", json=body, headers=AUTH)
    if outcome != "success":
        assert response.status_code == {"disabled": 400, "empty": 404, "error": 502}[outcome], response.text
        assert creation.dispatched == []
        with Session(creation.engine) as db:
            assert db.scalars(select(Job)).all() == []
            assert db.scalars(select(Upload)).all() == []
        return
    job_id = assert_created(creation, response)
    assert calls == ([(body["filter"], time_range)] if provider == "arkime" else [(time_range, ["sensor-a"], {"protocol": "tcp"})])
    with Session(creation.engine) as db:
        job = db.get(Job, job_id)
        record = db.get(Upload, job.upload_id)
        assert job.job_name == "Imported investigation"
        assert job.notes == "Imported notes"
        assert job.execution_profile == "standard"
        assert job.priority == "normal"
        assert record.filename == f"{prefix}{job_id[:8]}.pcap"
        assert record.sha256 == job.pcap_sha256 == hashlib.sha256(b"exported pcap").hexdigest()
        assert (creation.settings.aipam_upload_root / record.upload_id / record.filename).read_bytes() == b"exported pcap"
