"""Regression tests for hidden-PCAP restoration in the re-analysis path.

Single-phase re-analysis hides the non-target PCAPs (renames them to
``*.hidden``) so sensors only see the phase under analysis, then restores them
once sensors finish. The restore must survive a mid-pipeline failure — a stage
returning ``failed`` or a sensor raising — otherwise evidence PCAPs are left
renamed on disk permanently. These tests drive both failure paths and assert the
originals are put back.
"""

import uuid

import pytest

from backend.app.models.job import Job
from backend.app.models.job_pcap import JobPcap
from backend.app.models.upload import Upload
from backend.app.pipeline import orchestrator
from backend.app.pipeline.sensor_runner import SensorResult


def _iso() -> str:
    return "2026-01-01T00:00:00.000000Z"


def _seed_two_phase_job(db_session, upload_root):
    """Create a pcap job with two labelled PCAPs ("before", "after")."""
    job_id = uuid.uuid4().hex
    job = Job(
        job_id=job_id,
        job_name="reanalysis",
        status="queued",
        execution_profile="standard",
        priority="normal",
        source_type="pcap",
        pcap_filename="before.pcap",
        pcap_size_bytes=32,
        created_at=_iso(),
    )
    db_session.add(job)

    pcaps = []
    for ordinal, label in enumerate(("before", "after")):
        upload_id = uuid.uuid4().hex
        up_dir = upload_root / upload_id
        up_dir.mkdir(parents=True)
        # Minimal non-empty PCAP-ish file — content is irrelevant, run_sensor is mocked.
        (up_dir / f"{label}.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 28)
        db_session.add(Upload(
            upload_id=upload_id,
            filename=f"{label}.pcap",
            size_bytes=32,
            sha256=f"sha-{label}",
            created_at=_iso(),
        ))
        pcaps.append((upload_id, label, ordinal))
    # Commit parents (jobs, uploads) before the child rows so the FK holds.
    db_session.commit()

    for upload_id, label, ordinal in pcaps:
        db_session.add(JobPcap(
            job_id=job_id,
            upload_id=upload_id,
            label=label,
            filename=f"{label}.pcap",
            ordinal=ordinal,
        ))
    db_session.commit()
    return job_id


@pytest.fixture()
def one_stage(monkeypatch):
    """Force the pipeline to run exactly one stage and no sensors."""
    class _Stage:
        name = "zeek"

    monkeypatch.setattr(orchestrator, "get_stages_for_profile", lambda _p: [_Stage()])
    monkeypatch.setattr(orchestrator, "get_sensors_for_profile", lambda _p: [])


def _run(db_session, tmp_path):
    job_root = tmp_path / "jobs"
    upload_root = tmp_path / "uploads"
    job_root.mkdir()
    upload_root.mkdir()
    job_id = _seed_two_phase_job(db_session, upload_root)

    # Simulate a completed prior full run: both phases are already linked into the
    # job's input dir. Re-analysing one phase (pcap_label="after") then hides the
    # other ("before.pcap") for the duration of the sensor run.
    prior_input = job_root / job_id / "input"
    prior_input.mkdir(parents=True)
    for label in ("before", "after"):
        (prior_input / f"{label}.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 28)

    status = orchestrator.run_pipeline(
        job_id,
        db_session,
        docker_client=object(),
        job_root=job_root,
        upload_root=upload_root,
        pcap_label="after",  # analyse "after" → "before.pcap" gets hidden
    )
    input_dir = job_root / job_id / "input"
    return status, input_dir


def test_hidden_pcap_restored_when_stage_fails(db_session, tmp_path, monkeypatch, one_stage):
    """A failed stage must still restore hidden PCAPs.

    A stage failure is no longer fatal — Suricata and the uploaded-log pipeline
    do not depend on Zeek — so the job runs to completion and reports
    ``completed_with_errors`` rather than aborting on the spot.
    """
    monkeypatch.setattr(
        orchestrator, "run_sensor",
        lambda **_kw: SensorResult(sensor="zeek", status="failed", error="boom", started_at=_iso()),
    )

    status, input_dir = _run(db_session, tmp_path)

    assert status == "completed_with_errors"
    assert (input_dir / "before.pcap").exists(), "non-target PCAP was not restored after stage failure"
    assert not (input_dir / "before.pcap.hidden").exists(), "PCAP left hidden on disk"


def test_hidden_pcap_restored_when_sensor_raises(db_session, tmp_path, monkeypatch, one_stage):
    """An exception mid-pipeline must still restore hidden PCAPs (finally, not just early-return)."""
    def _boom(**_kw):
        raise RuntimeError("docker exploded")

    monkeypatch.setattr(orchestrator, "run_sensor", _boom)

    with pytest.raises(RuntimeError):
        _run(db_session, tmp_path)

    # run_pipeline raised, but the finally must have restored the original.
    job_dir = next((tmp_path / "jobs").iterdir())
    input_dir = job_dir / "input"
    assert (input_dir / "before.pcap").exists(), "non-target PCAP was not restored after crash"
    assert not (input_dir / "before.pcap.hidden").exists(), "PCAP left hidden on disk"


# ── Stage failure isolation ─────────────────────────────────────────────────

def test_failed_stage_does_not_abort_the_remaining_stages(db_session, tmp_path, monkeypatch):
    """Zeek dying must not take Suricata down with it.

    The two stages are independent, and the uploaded-log telemetry pipeline
    needs neither. Aborting on the first failure threw away every other piece
    of evidence in the job — including logs the analyst uploaded specifically
    to corroborate the detections.
    """
    class _Stage:
        def __init__(self, name):
            self.name = name

    monkeypatch.setattr(
        orchestrator, "get_stages_for_profile",
        lambda _p: [_Stage("zeek"), _Stage("suricata")],
    )
    monkeypatch.setattr(orchestrator, "get_sensors_for_profile", lambda _p: [])

    ran = []

    def _run_sensor(*, sensor_def, **_kw):
        ran.append(sensor_def.name)
        status = "failed" if sensor_def.name == "zeek" else "completed"
        return SensorResult(
            sensor=sensor_def.name, status=status,
            error="boom" if status == "failed" else None,
            started_at=_iso(),
        )

    monkeypatch.setattr(orchestrator, "run_sensor", _run_sensor)

    status, _ = _run(db_session, tmp_path)

    assert ran == ["zeek", "suricata"], "suricata was skipped after zeek failed"
    assert status == "completed_with_errors"


def test_sensors_needing_a_failed_stage_are_skipped(db_session, tmp_path, monkeypatch):
    """Dependents must not run against a failed stage's empty output directory."""
    class _Stage:
        name = "zeek"

    class _Sensor:
        name = "beaconing"
        skip_if_missing_inputs = True
        inputs_required = ("zeek",)

    class _Independent:
        name = "yara"
        skip_if_missing_inputs = True
        inputs_required = ()

    monkeypatch.setattr(orchestrator, "get_stages_for_profile", lambda _p: [_Stage()])
    monkeypatch.setattr(orchestrator, "get_sensors_for_profile", lambda _p: [_Sensor(), _Independent()])

    ran = []

    def _run_sensor(*, sensor_def, **_kw):
        ran.append(sensor_def.name)
        status = "failed" if sensor_def.name == "zeek" else "completed"
        return SensorResult(
            sensor=sensor_def.name, status=status,
            error="boom" if status == "failed" else None,
            started_at=_iso(),
        )

    monkeypatch.setattr(orchestrator, "run_sensor", _run_sensor)

    _run(db_session, tmp_path)

    assert "beaconing" not in ran, "sensor ran against a failed upstream stage"
    assert "yara" in ran, "independent sensor was wrongly skipped"
