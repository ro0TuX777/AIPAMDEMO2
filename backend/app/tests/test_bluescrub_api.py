"""BlueScrub API — projects and retroactive binding.

The UI tells operators an ad-hoc scan can be bound to a project later without
re-scanning. These tests hold that promise to account.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app.api.deps import get_db, verify_token
from backend.app.database_v2 import Base
from backend.app.main_v2 import create_app
from backend.app.models.bluescrub import BlueScrubAudit, BlueScrubJobLineage
from backend.app.models.job import Job


@pytest.fixture()
def client(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'api.db'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    app = create_app()

    def _db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[verify_token] = lambda: "test-token"

    with TestClient(app) as c:
        c.session_factory = Session
        yield c


def _job(client, job_id="job-a", source_type="code_artifact", status="completed"):
    s = client.session_factory()
    s.add(Job(job_id=job_id, status=status, execution_profile="triage",
              priority="normal", source_type=source_type,
              created_at="2026-08-09T00:00:00Z",
              completed_at="2026-08-09T00:01:00Z"))
    s.add(BlueScrubJobLineage(job_id=job_id, analysis_kind="source_audit",
                              compatibility_signature="sha256:" + "0" * 64))
    s.commit()
    s.close()


def test_create_and_list_projects(client):
    created = client.post("/api/v1/bluescrub/projects",
                          json={"display_name": "cs-loader-v3"})
    assert created.status_code == 201
    project_id = created.json()["project_id"]

    listed = client.get("/api/v1/bluescrub/projects")
    assert listed.status_code == 200
    assert [p["project_id"] for p in listed.json()] == [project_id]


def test_bind_adhoc_job_to_existing_project(client):
    _job(client)
    project_id = client.post("/api/v1/bluescrub/projects",
                             json={"display_name": "agent"}).json()["project_id"]

    res = client.put(f"/api/v1/bluescrub/jobs/job-a/project",
                     json={"project_id": project_id, "actor": "operator-1"})

    assert res.status_code == 200
    body = res.json()
    assert body["project_id"] == project_id
    assert body["carry_forward_enabled"] is True

    s = client.session_factory()
    assert s.get(BlueScrubJobLineage, "job-a").project_id == project_id
    audit = s.scalars(select(BlueScrubAudit)).all()
    assert len(audit) == 1
    assert audit[0].action == "project.bind"
    assert audit[0].actor == "operator-1"
    s.close()


def test_bind_creates_project_from_display_name(client):
    _job(client)
    res = client.put("/api/v1/bluescrub/jobs/job-a/project",
                     json={"display_name": "brand-new"})

    assert res.status_code == 200
    projects = client.get("/api/v1/bluescrub/projects").json()
    assert [p["display_name"] for p in projects] == ["brand-new"]


def test_bind_resolves_lineage_parent(client):
    """The parent is fixed at bind time, not re-derived by later readers."""
    project_id = client.post("/api/v1/bluescrub/projects",
                             json={"display_name": "p"}).json()["project_id"]
    _job(client, "job-old")
    client.put("/api/v1/bluescrub/jobs/job-old/project",
               json={"project_id": project_id})

    _job(client, "job-new")
    res = client.put("/api/v1/bluescrub/jobs/job-new/project",
                     json={"project_id": project_id})

    assert res.json()["lineage_parent_job_id"] == "job-old"


def test_rebinding_is_rejected(client):
    _job(client)
    pid = client.post("/api/v1/bluescrub/projects",
                      json={"display_name": "one"}).json()["project_id"]
    client.put("/api/v1/bluescrub/jobs/job-a/project", json={"project_id": pid})

    again = client.put("/api/v1/bluescrub/jobs/job-a/project",
                       json={"display_name": "two"})
    assert again.status_code == 409


def test_bind_rejects_non_code_artifact_job(client):
    _job(client, "job-pcap", source_type="pcap")
    res = client.put("/api/v1/bluescrub/jobs/job-pcap/project",
                     json={"display_name": "x"})
    assert res.status_code == 400
    # The app wraps plain string details into its ErrorResponse shape.
    assert "not a code_artifact job" in res.json()["error"]


def test_bind_requires_a_project_reference(client):
    _job(client)
    assert client.put("/api/v1/bluescrub/jobs/job-a/project", json={}).status_code == 400


def test_bind_unknown_project(client):
    _job(client)
    res = client.put("/api/v1/bluescrub/jobs/job-a/project",
                     json={"project_id": "nope"})
    assert res.status_code == 404


def test_report_requires_completed_analysis(client):
    _job(client)
    assert client.get("/api/v1/bluescrub/report/job-a").status_code == 409


def test_report_returns_metrics_and_lineage(client):
    _job(client)
    s = client.session_factory()
    job = s.get(Job, "job-a")
    job.metrics_json = '{"dacv": {"scoped": {"grade": "B"}}}'
    s.commit()
    s.close()

    body = client.get("/api/v1/bluescrub/report/job-a").json()
    assert body["dacv"]["scoped"]["grade"] == "B"
    assert body["lineage"]["analysis_kind"] == "source_audit"
