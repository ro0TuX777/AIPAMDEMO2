"""Acceptance boundaries for immutable execution output and published artifacts."""
import io
import json
import os
import subprocess
import tarfile
import uuid
import zipfile
from types import SimpleNamespace

import pytest

from backend.app.pipeline.run_artifacts import (
    RunManifestEntry, build_accepted_manifest, cleanup_unaccepted_runs,
    create_run_output_dir, resolve_accepted_run_dirs, resolve_published_artifact_dir,
    safe_artifact_path,
)


def token():
    return str(uuid.uuid4())


def link_directory(link, target):
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        # Junctions exercise the equivalent Windows directory-escape boundary.
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)


@pytest.fixture
def job():
    return SimpleNamespace(job_id=token(), status="completed", artifact_layout_version=2,
                           accepted_run_manifest_json=None, run_token=None)


def accept(job, root, label=None):
    run = create_run_output_dir(root, job.job_id, token())
    job.accepted_run_manifest_json = build_accepted_manifest(
        job.accepted_run_manifest_json, run.name, label)
    return run


def test_readers_resolve_only_manifest_entries(tmp_path, job):
    accepted = accept(job, tmp_path)
    abandoned = create_run_output_dir(tmp_path, job.job_id, token())
    (accepted / "metrics" / "job_metrics.json").write_text("{}")
    (abandoned / "metrics" / "job_metrics.json").write_text('{"bad":true}')
    assert resolve_accepted_run_dirs(job, tmp_path) == [accepted]
    with pytest.raises(FileExistsError):
        create_run_output_dir(tmp_path, job.job_id, accepted.name)


def test_phase_acceptance_replaces_only_same_phase(job):
    base, before, old, new = [token() for _ in range(4)]
    current = [{"run_token": old, "phase_label": "after"},
               {"run_token": before, "phase_label": "before"},
               {"run_token": base, "phase_label": None}]
    expected = [{"run_token": base, "phase_label": None},
                {"run_token": new, "phase_label": "after"},
                {"run_token": before, "phase_label": "before"}]
    assert build_accepted_manifest(current, new, "after") == json.dumps(expected, separators=(",", ":"))
    assert RunManifestEntry(new, "after", "a" * 64).bundle_sha256 == "a" * 64


@pytest.mark.parametrize("bad", ["../escape", "..\\escape", "/tmp/escape", "run-a", ""])
def test_reject_invalid_tokens(tmp_path, job, bad):
    with pytest.raises(ValueError):
        create_run_output_dir(tmp_path, job.job_id, bad)
    with pytest.raises(ValueError):
        build_accepted_manifest(None, bad, None)


@pytest.mark.parametrize("manifest", [None, "", "[]", "{}", "null", "invalid", '[{"run_token":"../escape","phase_label":null}]'])
def test_layout2_missing_or_malformed_manifest_fails_closed(tmp_path, job, manifest):
    job.accepted_run_manifest_json = manifest
    (tmp_path / job.job_id / "sensors").mkdir(parents=True)
    assert resolve_accepted_run_dirs(job, tmp_path) == []


@pytest.mark.parametrize("status", ["completed", "completed_with_errors", "failed", "canceled"])
def test_terminal_layout1_compatibility_is_read_only(tmp_path, job, status):
    job.artifact_layout_version, job.status = 1, status
    root = tmp_path / job.job_id
    root.mkdir()
    assert resolve_accepted_run_dirs(job, tmp_path) == [root]
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("status", ["queued", "running", "cancel_requested", "canceling"])
def test_active_layout1_cannot_expose_historical_output(tmp_path, job, status):
    job.artifact_layout_version, job.status = 1, status
    assert resolve_accepted_run_dirs(job, tmp_path) == []


def test_cleanup_preserves_accepted_and_active_tokens(tmp_path, job):
    accepted = accept(job, tmp_path)
    active = create_run_output_dir(tmp_path, job.job_id, token())
    job.run_token = active.name
    abandoned = create_run_output_dir(tmp_path, job.job_id, token())
    cleanup_unaccepted_runs(job, tmp_path)
    assert accepted.exists() and active.exists()
    assert not abandoned.exists()


def test_cleanup_does_nothing_for_corrupt_manifest(tmp_path, job):
    run = accept(job, tmp_path)
    job.accepted_run_manifest_json = "invalid"
    cleanup_unaccepted_runs(job, tmp_path)
    assert run.exists()


def test_symlink_escape_fails_closed(tmp_path, job):
    run = accept(job, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("abandoned")
    link_directory(run / "escape", outside)
    with pytest.raises(ValueError):
        safe_artifact_path(run, "escape/secret")
    with pytest.raises(ValueError):
        safe_artifact_path(run, "../secret")


def test_published_artifact_requires_terminal_and_valid_uuid(tmp_path, job):
    artifact_id = token()
    assert resolve_published_artifact_dir(job, tmp_path, artifact_id) == tmp_path / job.job_id / "published" / artifact_id
    with pytest.raises(ValueError):
        resolve_published_artifact_dir(job, tmp_path, "../escape")
    job.status = "running"
    with pytest.raises(ValueError):
        resolve_published_artifact_dir(job, tmp_path, artifact_id)


@pytest.fixture
def isolated_job(app_client, tmp_dirs):
    from backend.app.models.job import Job
    client, db = app_client
    job = Job(job_id=token(), status="completed", execution_profile="standard", priority="normal",
              created_at="2026-09-23T00:00:00Z", artifact_layout_version=2)
    db.add(job)
    db.commit()
    root = tmp_dirs["job_root"]
    accepted = accept(job, root)
    abandoned = create_run_output_dir(root, job.job_id, token())
    stable = root / job.job_id
    for directory, marker in [(accepted, "accepted"), (abandoned, "abandoned"), (stable, "stable-decoy")]:
        for relative, body in {
            "metrics/job_metrics.json": json.dumps({"total_runtime_sec": 1 if marker == "accepted" else 99999}),
            "telemetry_diagnostics.json": json.dumps({"files": [{"filename": "events.log", "status": "ok", "parser_name": marker, "events_produced": 3}]}),
            "sensors/zeek/raw/extract_files/Ftest": marker,
            "sensors/zeek/sensor.results.jsonl": json.dumps({"marker": marker}),
            "sensors/zeek/container.log": marker,
            "report/result.txt": marker,
            "artifacts/evidence.zip": marker,
        }.items():
            path = directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
    db.commit()
    return client, db, job, accepted, abandoned, stable


AUTH = {"Authorization": "Bearer test-token-v2"}


def test_zip_export_reads_only_accepted_execution_files(isolated_job):
    from backend.app.services.job_service import create_export_zip
    client, db, job, accepted, abandoned, stable = isolated_job
    for content in [create_export_zip(db, job, stable), client.get(f"/api/v1/jobs/{job.job_id}/export", headers=AUTH).content]:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            payload = b"".join(zf.read(n) for n in zf.namelist())
            assert b"accepted" in payload
            assert b"abandoned" not in payload and b"stable-decoy" not in payload
            assert any(accepted.name in n for n in zf.namelist())


def test_extracted_download_respects_phase_and_accepted_manifest(isolated_job):
    from backend.app.models.file import File
    client, db, job, accepted, abandoned, stable = isolated_job
    db.add(File(job_id=job.job_id, file_id="Ftest", sha256="a" * 64, size_bytes=14, pcap_label="after"))
    phase = accept(job, stable.parent, "after")
    path = phase / "sensors/zeek/raw/extract_files/Ftest"
    path.parent.mkdir(parents=True)
    path.write_text("accepted-after")
    db.commit()
    url = f"/api/v1/jobs/{job.job_id}/files/Ftest/download"
    assert client.get(url, headers=AUTH).content == b"accepted-after"
    job.accepted_run_manifest_json = None
    db.commit()
    assert client.get(url, headers=AUTH).status_code == 404


def test_diagnostics_uses_accepted_output(isolated_job, monkeypatch):
    from backend.app.models.job_log_source import JobLogSource
    from backend.app import config_v2
    client, db, job, accepted, abandoned, stable = isolated_job
    db.add(JobLogSource(job_id=job.job_id, filename="events.log", ordinal=0))
    db.commit()
    monkeypatch.setattr(config_v2, "get_settings", lambda: SimpleNamespace(aipam_job_root=stable.parent))
    response = client.get(f"/api/v1/jobs/{job.job_id}", headers=AUTH)
    assert response.status_code == 200
    assert response.json()["job"]["log_sources"][0]["parse_parser"] == "accepted"


def test_published_packages_are_immutable_across_manifest_changes(isolated_job):
    client, db, job, accepted, abandoned, stable = isolated_job
    url = f"/api/v1/jobs/{job.job_id}/artifacts/evidence-package"
    first = client.post(url, headers=AUTH).json()["artifact_id"]
    first_url = f"/api/v1/artifacts/{first}/download"
    original = client.get(first_url, headers=AUTH).content
    job.job_name = "second package"
    db.commit()
    second = client.post(url, headers=AUTH).json()["artifact_id"]
    updated = client.get(f"/api/v1/artifacts/{second}/download", headers=AUTH).content
    assert original != updated
    job.accepted_run_manifest_json = build_accepted_manifest(None, abandoned.name, None)
    db.commit()
    assert client.get(first_url, headers=AUTH).content == original
    assert client.get(f"/api/v1/artifacts/{second}/download", headers=AUTH).content == updated
    assert len(list((stable / "published").glob("*/*.zip"))) == 2


@pytest.mark.parametrize("endpoint", ["artifacts/evidence-package", "binary?filename=test.bin"])
def test_active_jobs_reject_api_artifact_writes(isolated_job, endpoint):
    client, db, job, accepted, abandoned, stable = isolated_job
    job.status = "running"
    db.commit()
    assert client.post(f"/api/v1/jobs/{job.job_id}/{endpoint}", content=b"binary", headers=AUTH).status_code == 409


def test_active_pipeline_sensor_receives_separate_input_and_output(tmp_path):
    from backend.app.pipeline.sensor_runner import run_sensor
    from backend.app.sensors.registry import SensorDef
    input_root, output = tmp_path / "job", tmp_path / "run"
    (input_root / "input").mkdir(parents=True)
    (input_root / "input" / "source.txt").write_text("input")

    def handler(input_root, run_output_dir, sensor_output_dir, **kwargs):
        text = (input_root / "input" / "source.txt").read_text()
        (sensor_output_dir / "sensor.results.jsonl").write_text(text)
        assert run_output_dir == output

    sensor = SensorDef(name="test", type="sensor", handler=handler)
    result = run_sensor(sensor, input_root=input_root, run_output_dir=output, job_id=token(), execution_profile="standard")
    assert result.status == "completed"
    assert (output / "sensors/test/sensor.results.jsonl").read_text() == "input"
    assert not (input_root / "sensors").exists()


def test_telemetry_diagnostics_are_written_to_owned_output(tmp_path, db_session):
    from backend.app.pipeline.telemetry_pipeline import run_telemetry_pipeline
    stable, output = tmp_path / "job", tmp_path / "run"
    stable.mkdir()
    output.mkdir()
    run_telemetry_pipeline(token(), input_root=stable, run_output_dir=output, db=db_session)
    assert (output / "telemetry_diagnostics.json").is_file()
    assert not (stable / "telemetry_diagnostics.json").exists()


def test_sbom_writer_uses_owned_output(tmp_path):
    pytest.importorskip("resource", reason="BlueScrub sandbox requires Unix resource module")
    from backend.app.bluescrub.scanners.sbom import write_sbom
    output = tmp_path / "run"
    path = write_sbom({"artifacts": []}, run_output_dir=output)
    assert path == output / "report" / "sbom.syft.json"


def test_bluescrub_scanner_output_is_owned(tmp_path, db_session, monkeypatch):
    pytest.importorskip("resource", reason="BlueScrub sandbox requires Unix resource module")
    from backend.app.bluescrub import service
    from backend.app.bluescrub.pillars import Pillar
    stable, output = tmp_path / "job", tmp_path / "run"
    source = stable / "input/source"
    source.mkdir(parents=True)

    def scanner(source_root, output_dir):
        assert source_root == source
        output_dir.mkdir(parents=True)
        (output_dir / "marker").write_text("scan")
        raise RuntimeError("test scanner stops after output")

    spec = SimpleNamespace(name="owned-test", pillars=tuple(Pillar), optional=False, run=scanner)
    monkeypatch.setattr(service, "scanners_for", lambda profile: [spec])
    # The assertion concerns scanner IO, before downstream scoring/persistence.
    with pytest.raises(RuntimeError, match="stop before scoring"):
        monkeypatch.setattr(service, "score_job", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("stop before scoring")))
        service.analyze_and_persist(db_session, token(), input_root=stable, run_output_dir=output)
    assert (output / "sensors/owned-test/marker").read_text() == "scan"
    assert not (stable / "sensors").exists()


@pytest.fixture
def cli_isolated_job(isolated_job, tmp_path, monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from backend.app.database_v2 import Base
    from backend.app.models.job import Job
    client, db, job, accepted, abandoned, stable = isolated_job
    db_path = tmp_path / "cli.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Job(**{c.name: getattr(job, c.name) for c in Job.__table__.columns}))
        session.commit()
    engine.dispose()
    monkeypatch.setenv("AIPAM_DB_PATH", str(db_path))
    monkeypatch.setenv("AIPAM_JOB_ROOT", str(stable.parent))
    monkeypatch.setenv("AIPAM_LOG_DIR", str(tmp_path / "no-system-logs"))
    return job, accepted, stable


def test_cli_support_bundle_includes_only_accepted_run_files(cli_isolated_job, tmp_path):
    from backend.app.cli import cmd_support_bundle
    job, accepted, stable = cli_isolated_job
    output = tmp_path / "support.tar.gz"
    cmd_support_bundle(SimpleNamespace(job=job.job_id, all_recent=False, output=str(output)))
    with tarfile.open(output) as tar:
        payload = b"".join(tar.extractfile(member).read() for member in tar.getmembers() if member.isfile())
        assert b"accepted" in payload
        assert b"abandoned" not in payload and b"stable-decoy" not in payload
        assert any(accepted.name in name for name in tar.getnames())


def test_cli_performance_gate_uses_accepted_metrics(cli_isolated_job, capsys):
    from backend.app.cli import cmd_perf_gate
    job, accepted, stable = cli_isolated_job
    with pytest.raises(SystemExit) as exc:
        cmd_perf_gate(SimpleNamespace(job_root=str(stable.parent)))
    assert exc.value.code == 0
    assert "runtime=1s" in capsys.readouterr().out


@pytest.mark.parametrize("manifest", [None, "invalid", '{}', '[{"run_token":"../escape","phase_label":null}]'])
def test_api_readers_fail_closed_for_invalid_manifests(isolated_job, manifest, monkeypatch):
    from backend.app import config_v2
    from backend.app.models.file import File
    from backend.app.models.artifact import Artifact
    from backend.app.models.job_log_source import JobLogSource
    client, db, job, accepted, abandoned, stable = isolated_job
    artifact_id = token()
    db.add(Artifact(job_id=job.job_id, artifact_id=artifact_id, type="evidence_package", status="available", filename="evidence.zip", created_at=job.created_at))
    db.add(File(job_id=job.job_id, file_id="Ftest", sha256="a" * 64, size_bytes=8))
    db.add(JobLogSource(job_id=job.job_id, filename="events.log", ordinal=0))
    job.accepted_run_manifest_json = manifest
    db.commit()
    monkeypatch.setattr(config_v2, "get_settings", lambda: SimpleNamespace(aipam_job_root=stable.parent))
    assert client.get(f"/api/v1/jobs/{job.job_id}/files/Ftest/download", headers=AUTH).status_code == 404
    assert client.get(f"/api/v1/artifacts/{artifact_id}/download", headers=AUTH).status_code == 404
    detail = client.get(f"/api/v1/jobs/{job.job_id}", headers=AUTH).json()["job"]
    assert detail["log_sources"][0]["parse_parser"] is None
    response = client.get(f"/api/v1/jobs/{job.job_id}/export", headers=AUTH)
    with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
        payload = b"".join(zf.read(n) for n in zf.namelist())
        assert b"accepted" not in payload and b"abandoned" not in payload and b"stable-decoy" not in payload


def test_execution_artifact_download_uses_accepted_run(isolated_job):
    from backend.app.models.artifact import Artifact
    client, db, job, accepted, abandoned, stable = isolated_job
    artifact_id = token()
    db.add(Artifact(job_id=job.job_id, artifact_id=artifact_id, type="evidence_package", status="available", filename="evidence.zip", created_at=job.created_at))
    db.commit()
    assert client.get(f"/api/v1/artifacts/{artifact_id}/download", headers=AUTH).content == b"accepted"


def test_binary_upload_is_stable_and_separate_from_inputs(isolated_job):
    client, db, job, accepted, abandoned, stable = isolated_job
    (stable / "input").mkdir()
    original = stable / "input/test.bin"
    original.write_bytes(b"source material")
    for payload in (b"binary one", b"binary two"):
        response = client.post(f"/api/v1/jobs/{job.job_id}/binary?filename=test.bin", content=payload, headers=AUTH)
        assert response.status_code == 201
    assert original.read_bytes() == b"source material"
    assert sorted(p.read_bytes() for p in (stable / "api-artifacts/binary").glob("*/test.bin")) == [b"binary one", b"binary two"]
    assert resolve_accepted_run_dirs(job, stable.parent) == [accepted]


@pytest.mark.parametrize("filename", ["../escape", "..%5Cescape", "/absolute", "nested/file"])
def test_binary_upload_rejects_path_names(isolated_job, filename):
    client, db, job, accepted, abandoned, stable = isolated_job
    assert client.post(f"/api/v1/jobs/{job.job_id}/binary?filename={filename}", content=b"binary", headers=AUTH).status_code == 400


def test_layout2_pipeline_requires_owned_output_before_status_mutation(isolated_job):
    from backend.app.pipeline.orchestrator import run_pipeline
    client, db, job, accepted, abandoned, stable = isolated_job
    with pytest.raises(ValueError, match="owned run_output_dir"):
        run_pipeline(job.job_id, db, docker_client=None, job_root=stable.parent, upload_root=stable.parent)
    assert job.status == "completed"


def test_sensor_container_mounts_only_owned_output_and_stable_inputs(tmp_path, monkeypatch):
    from unittest.mock import MagicMock
    from backend.app.pipeline.sensor_runner import run_sensor
    from backend.app.sensors.registry import SensorDef
    stable, output = tmp_path / "job", tmp_path / "run"
    (stable / "input").mkdir(parents=True)
    docker = MagicMock()
    docker.containers.run.return_value.wait.return_value = {"StatusCode": 0}
    docker.containers.run.return_value.logs.return_value = b""
    sensor = SensorDef(name="test", type="sensor", image="aipam/test:1.0")
    monkeypatch.setattr("backend.app.pipeline.sensor_runner.validate_image_allowlist", lambda image: True)
    run_sensor(sensor, stable, token(), "standard", docker, run_output_dir=output)
    mounts = docker.containers.run.call_args.kwargs["volumes"]
    assert str(stable) not in mounts
    assert mounts[str(stable / "input")] == {"bind": "/input/input", "mode": "ro"}
    assert mounts[str(output)] == {"bind": "/input", "mode": "ro"}


def test_active_helpers_require_explicit_output(tmp_path, db_session):
    from backend.app.pipeline.job_dir import create_job_directory
    from backend.app.pipeline.sensor_runner import run_sensor
    from backend.app.pipeline.sensor_handlers import handle_zeek
    from backend.app.pipeline.telemetry_pipeline import run_telemetry_pipeline
    from backend.app.sensors.registry import SensorDef
    sensor = SensorDef(name="test", type="sensor", handler=lambda **kw: None)
    with pytest.raises(TypeError, match="run_output_dir"):
        run_sensor(sensor, tmp_path, token(), "standard")
    with pytest.raises(TypeError, match="run_output_dir"):
        handle_zeek(tmp_path, tmp_path, token(), "standard")
    with pytest.raises(TypeError, match="run_output_dir"):
        run_telemetry_pipeline(token(), tmp_path, db_session)
    with pytest.raises(TypeError, match="run_output_dir"):
        create_job_directory(tmp_path, token())
    with pytest.raises(TypeError, match="input_root"):
        run_sensor(sensor, job_id=token(), execution_profile="standard", run_output_dir=tmp_path)


def test_manifest_run_directory_symlink_fails_closed(tmp_path, job):
    outside = tmp_path / "outside"
    outside.mkdir()
    run_token = token()
    runs = tmp_path / job.job_id / ".runs"
    runs.mkdir(parents=True)
    link_directory(runs / run_token, outside)
    job.accepted_run_manifest_json = build_accepted_manifest(None, run_token, None)
    assert resolve_accepted_run_dirs(job, tmp_path) == []
    with pytest.raises(ValueError):
        create_run_output_dir(tmp_path, job.job_id, run_token)
    cleanup_unaccepted_runs(job, tmp_path)
    assert outside.is_dir()


def test_accepted_tree_cannot_link_to_abandoned_bytes(isolated_job):
    client, db, job, accepted, abandoned, stable = isolated_job
    link_directory(accepted / "sensors/linked", abandoned / "sensors/zeek")
    response = client.get(f"/api/v1/jobs/{job.job_id}/export", headers=AUTH)
    with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
        assert not any("linked" in name for name in zf.namelist())
        assert b"abandoned" not in b"".join(zf.read(name) for name in zf.namelist())


def test_private_runtime_fields_remain_absent_from_public_job(isolated_job):
    client, db, job, accepted, abandoned, stable = isolated_job
    detail = client.get(f"/api/v1/jobs/{job.job_id}", headers=AUTH).json()["job"]
    assert not {"run_token", "accepted_run_manifest_json", "worker_id", "executor_pid", "artifact_layout_version"}.intersection(detail)


def test_alerts_and_findings_keep_stable_arkime_state(isolated_job, monkeypatch):
    from unittest.mock import MagicMock
    from backend.app.models.alert import Alert
    from backend.app.models.finding import Finding
    client, db, job, accepted, abandoned, stable = isolated_job
    db.add(Alert(job_id=job.job_id, alert_id="alert", host_ip="10.0.0.1", engine="suricata", signature="accepted alert", severity="high", ts=job.created_at))
    db.add(Finding(job_id=job.job_id, finding_id="finding", title="accepted finding", severity="high", category="network", sensor="suricata"))
    db.commit()
    connector = MagicMock()
    connector.enabled = True
    connector.build_pivot_url.return_value = ("http://arkime/sessions", "community_id")
    connector.get_import_status.side_effect = lambda directory: {"status": "imported" if directory == stable else "wrong-root"}
    monkeypatch.setattr("backend.app.connectors.ArkimeConnector", lambda: connector)
    monkeypatch.setattr("backend.app.config_v2.get_settings", lambda: SimpleNamespace(aipam_job_root=stable.parent))
    for endpoint in ["alerts/alert", "findings/finding"]:
        detail = client.get(f"/api/v1/jobs/{job.job_id}/{endpoint}", headers=AUTH)
        assert detail.status_code == 200
        assert "abandoned" not in detail.text and "stable-decoy" not in detail.text
        pivot = client.get(f"/api/v1/jobs/{job.job_id}/{endpoint}/arkime-link", headers=AUTH)
        assert pivot.json()["import_status"] == "imported"
