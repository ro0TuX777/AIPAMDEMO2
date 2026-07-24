"""Binary auto-trigger tests (Follow-up A).

Verifies that a single upload classified as ``binary`` is routed to a
binary/YARA analysis job on creation, and that the pipeline runs YARA
analysis (persisting File + Findings) on job start, idempotently.
"""

from sqlalchemy import select

from backend.app.binalysis import yara_available
from backend.app.models.file import File
from backend.app.models.finding import Finding
from backend.app.models.job import Job
from backend.app.pipeline.orchestrator import run_pipeline

AUTH_HEADER = {"Authorization": "Bearer test-token-v2"}
OCTET = {"Content-Type": "application/octet-stream"}

PE_BYTES = b"MZ" + b"\x00" * 58 + b"PE\x00\x00" + b"\x00" * 64


def _upload_binary(client, name="evil.exe", body=PE_BYTES):
    return client.post(
        f"/api/v1/uploads/artifact?filename={name}",
        content=body, headers={**AUTH_HEADER, **OCTET},
    )


def _create_job(client, upload_id):
    return client.post(
        "/api/v1/jobs",
        json={"upload_id": upload_id, "execution_profile": "standard"},
        headers=AUTH_HEADER,
    )


class TestBinaryJobRouting:
    def test_binary_upload_creates_binary_job(self, app_client, tmp_dirs):
        client, db = app_client
        up = _upload_binary(client)
        assert up.status_code == 201
        assert up.json()["artifact_class"] == "binary"
        upload_id = up.json()["upload_id"]

        jr = _create_job(client, upload_id)
        assert jr.status_code == 201
        job_id = jr.json()["job_id"]

        job = db.get(Job, job_id)
        assert job is not None
        assert job.source_type == "binary"

        # Artifact copied into the job input directory at creation time.
        assert (tmp_dirs["job_root"] / job_id / "input" / "evil.exe").exists()

    def test_log_upload_does_not_route_to_binary(self, app_client):
        client, db = app_client
        up = client.post(
            "/api/v1/uploads/artifact?filename=auth.log",
            content=b"Jan 1 00:00:00 host sshd[1]: Accepted password\n" * 3,
            headers={**AUTH_HEADER, **OCTET},
        )
        assert up.json()["artifact_class"] == "log"
        # A non-binary artifact must not be routed to the binary pipeline; it
        # follows the default PCAP path (source_type stays "pcap").
        jr = _create_job(client, up.json()["upload_id"])
        assert jr.status_code == 201
        job = db.get(Job, jr.json()["job_id"])
        assert job.source_type != "binary"


class TestBinaryPipeline:
    def test_pipeline_runs_yara_and_persists(self, app_client, tmp_dirs):
        client, db = app_client
        upload_id = _upload_binary(client).json()["upload_id"]
        job_id = _create_job(client, upload_id).json()["job_id"]

        status = run_pipeline(
            job_id=job_id, db=db, docker_client=None,
            job_root=tmp_dirs["job_root"], upload_root=tmp_dirs["upload_root"],
        )
        assert status == "completed"

        files = db.scalars(select(File).where(File.job_id == job_id)).all()
        assert len(files) == 1
        assert files[0].source == "yara"

        if yara_available():
            findings = db.scalars(
                select(Finding).where(Finding.job_id == job_id, Finding.sensor == "yara")
            ).all()
            assert len(findings) >= 1

    def test_pipeline_is_idempotent(self, app_client, tmp_dirs):
        client, db = app_client
        upload_id = _upload_binary(client).json()["upload_id"]
        job_id = _create_job(client, upload_id).json()["job_id"]

        run_pipeline(job_id=job_id, db=db, docker_client=None,
                     job_root=tmp_dirs["job_root"], upload_root=tmp_dirs["upload_root"])
        findings_first = db.scalars(
            select(Finding).where(Finding.job_id == job_id)
        ).all()

        run_pipeline(job_id=job_id, db=db, docker_client=None,
                     job_root=tmp_dirs["job_root"], upload_root=tmp_dirs["upload_root"])

        files = db.scalars(select(File).where(File.job_id == job_id)).all()
        findings_second = db.scalars(
            select(Finding).where(Finding.job_id == job_id)
        ).all()
        assert len(files) == 1
        assert len(findings_second) == len(findings_first)
