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


# ── baselines ─────────────────────────────────────────────────────────────

import json as _json  # noqa: E402

from backend.app.bluescrub.pillars import Pillar  # noqa: E402
from backend.app.bluescrub.scoring import (  # noqa: E402
    digest_payload,
    signature_payload,
)
from backend.app.models.finding import Finding  # noqa: E402

AUTH: dict = {}


def _fields(**overrides):
    base = dict(profile="deep", scanner_manifest_digest="sha256:aa",
                ruleset_versions_digest="sha256:bb",
                required_scanners=["semgrep"],
                pillar_scope=[Pillar.attribution], config_hash="sha256:cc")
    base.update(overrides)
    return signature_payload(**base)


def _scanned_job(client, job_id, *, project_id, findings, fields=None):
    """A completed, project-bound job with persisted findings."""
    fields = fields or _fields()
    s = client.session_factory()
    s.add(Job(job_id=job_id, status="completed", execution_profile="deep",
              priority="normal", source_type="code_artifact",
              created_at="2026-08-09T00:00:00Z",
              completed_at="2026-08-09T00:01:00Z",
              metrics_json=_json.dumps({"dacv": {
                  "schema": "bluescrub/2",
                  "compatibility_signature": digest_payload(fields),
              }})))
    s.add(BlueScrubJobLineage(
        job_id=job_id, project_id=project_id, analysis_kind="source_audit",
        compatibility_signature=digest_payload(fields),
        signature_fields_json=_json.dumps(fields),
    ))
    for finding_id, severity in findings:
        s.add(Finding(job_id=job_id, finding_id=finding_id, sensor="dirty_word",
                      severity=severity, category="Attribution",
                      title="t", summary="s",
                      evidence_json=_json.dumps({"rule_id": "dirty_word.codename"})))
    s.commit()
    s.close()


def _project(client, name="loader"):
    return client.post("/api/v1/bluescrub/projects",
                       json={"display_name": name}).json()["project_id"]


def test_setting_a_baseline_records_what_was_frozen(client):
    project = _project(client)
    _scanned_job(client, "job-1", project_id=project,
                 findings=[("bs-a", "high"), ("bs-b", "medium")])

    res = client.put("/api/v1/bluescrub/jobs/job-1/baseline",
                     json={"label": "accepted-v1", "actor": "operator-1"})

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["findings"] == 2 and body["label"] == "accepted-v1"
    assert "incomparable" in body["note"]


def test_a_later_scan_diffs_against_the_baseline(client):
    project = _project(client)
    _scanned_job(client, "job-1", project_id=project,
                 findings=[("bs-keep", "high"), ("bs-gone", "medium"),
                           ("bs-worse", "low")])
    client.put("/api/v1/bluescrub/jobs/job-1/baseline", json={})

    _scanned_job(client, "job-2", project_id=project,
                 findings=[("bs-keep", "high"), ("bs-worse", "critical"),
                           ("bs-new", "high")])
    body = client.get("/api/v1/bluescrub/jobs/job-2/baseline-diff").json()

    assert body["status"] == "comparable"
    assert [f["finding_id"] for f in body["new"]] == ["bs-new"]
    assert [f["finding_id"] for f in body["fixed"]] == ["bs-gone"]
    assert [f["finding_id"] for f in body["regressed"]] == ["bs-worse"]
    assert body["regressed"][0]["was"] == "low"
    assert body["counts"]["unchanged"] == 1


def test_an_incomparable_scan_names_the_field_over_the_api(client):
    """"Incomparable" without a reason is an error message users cannot act
    on, and the API is where a user actually reads it."""
    project = _project(client)
    _scanned_job(client, "job-1", project_id=project, findings=[("bs-a", "high")])
    client.put("/api/v1/bluescrub/jobs/job-1/baseline", json={})

    _scanned_job(client, "job-2", project_id=project, findings=[("bs-a", "high")],
                 fields=_fields(profile="triage"))
    body = client.get("/api/v1/bluescrub/jobs/job-2/baseline-diff").json()

    assert body["status"] == "incomparable"
    assert "profile" in body["reason"]
    assert body["differing_fields"][0]["baseline"] == "deep"
    assert body["differing_fields"][0]["current"] == "triage"
    assert "new" not in body, "a refusal must not carry a diff"


def test_an_unbound_job_cannot_be_a_baseline(client):
    """A baseline is a property of a project. An ad-hoc scan has no project to
    be the reference for, and inferring one would bind it by side effect.

    The job is otherwise complete, so this reaches the binding check rather
    than tripping the earlier "analysis has not completed" one."""
    _scanned_job(client, "job-x", project_id=None, findings=[("bs-a", "high")])

    res = client.put("/api/v1/bluescrub/jobs/job-x/baseline", json={})
    assert res.status_code == 409
    # The app wraps HTTPException detail under `error`.
    assert "not bound to a project" in res.json()["error"]


def test_an_unbound_job_cannot_be_diffed_either(client):
    _scanned_job(client, "job-y", project_id=None, findings=[("bs-a", "high")])
    assert client.get(
        "/api/v1/bluescrub/jobs/job-y/baseline-diff").status_code == 409


def test_an_incomplete_job_cannot_be_a_baseline(client):
    project = _project(client)
    s = client.session_factory()
    s.add(Job(job_id="job-r", status="running", execution_profile="deep",
              priority="normal", source_type="code_artifact",
              created_at="2026-08-09T00:00:00Z"))
    s.add(BlueScrubJobLineage(job_id="job-r", project_id=project,
                              analysis_kind="source_audit",
                              compatibility_signature="sha256:" + "0" * 64))
    s.commit()
    s.close()

    assert client.put("/api/v1/bluescrub/jobs/job-r/baseline",
                      json={}).status_code == 409


def test_setting_a_baseline_is_audited(client):
    project = _project(client)
    _scanned_job(client, "job-1", project_id=project, findings=[("bs-a", "high")])
    client.put("/api/v1/bluescrub/jobs/job-1/baseline",
               json={"label": "v1", "actor": "operator-1"})

    s = client.session_factory()
    rows = s.scalars(select(BlueScrubAudit).where(
        BlueScrubAudit.action == "baseline.set")).all()
    assert len(rows) == 1 and rows[0].actor == "operator-1"
    s.close()


def test_replacing_a_baseline_records_the_one_it_superseded(client):
    project = _project(client)
    _scanned_job(client, "job-1", project_id=project, findings=[("bs-a", "high")])
    client.put("/api/v1/bluescrub/jobs/job-1/baseline", json={"label": "v1"})
    _scanned_job(client, "job-2", project_id=project, findings=[("bs-b", "high")])
    client.put("/api/v1/bluescrub/jobs/job-2/baseline", json={"label": "v2"})

    s = client.session_factory()
    rows = sorted(s.scalars(select(BlueScrubAudit).where(
        BlueScrubAudit.action == "baseline.set")).all(), key=lambda r: r.id)
    superseded = _json.loads(rows[-1].old_json)
    assert superseded["label"] == "v1" and superseded["job_id"] == "job-1"
    s.close()


def test_a_diff_with_no_baseline_says_so(client):
    project = _project(client)
    _scanned_job(client, "job-1", project_id=project, findings=[("bs-a", "high")])

    body = client.get("/api/v1/bluescrub/jobs/job-1/baseline-diff").json()
    assert body["status"] == "incomparable"
    assert "no active baseline" in body["reason"]
