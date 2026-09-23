"""
Pipeline Orchestrator (§7) — sequences stages and sensors for a job.

Execution order (mandatory):
  1. Validate inputs + compute PCAP hash
  2. Run Zeek stage
  3. Run Suricata stage
  4. File Extraction stage
  5. Run sensors in deterministic order based on profile
  6. Normalize/merge results
  7. Score + summarize (LLM)
  8. Persist to DB
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.bluescrub import BlueScrubJobLineage
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.job import Job
from backend.app.models.job_pcap import JobPcap
from backend.app.models.sensor import JobSensor
from backend.app.pipeline.job_dir import (
    create_job_directory,
    create_sensor_output_dir,
    link_pcap,
    link_pcap_labeled,
    write_input_meta,
)
from backend.app.pipeline.preflight import check_disk_space, check_job_quota
from backend.app.pipeline.sensor_runner import SensorResult, run_sensor
from backend.app.sensors.registry import (
    Profile,
    SensorDef,
    get_sensors_for_profile,
    get_stages_for_profile,
)
from backend.app.events import publish_job_event
from backend.app.pipeline.outcomes import PipelineOutcome, StageFailure, derive_outcome, stage_failure, public_failure
from backend.app.pipeline.run_artifacts import build_accepted_manifest

logger = logging.getLogger("aipam.orchestrator")


def _emit(job_id: str, event_type: str, **payload: Any) -> None:
    """Fire-and-forget event publish (never fails the pipeline)."""
    try:
        publish_job_event(job_id, event_type, {"job_id": job_id, **payload})
    except Exception:
        pass


def _publish_partial_result(
    job_id: str,
    stage: str,
    data: dict[str, Any],
    completed_stages: list[str],
    current_stage: str | None = None,
) -> None:
    """Persist partial results and emit SSE event (fire-and-forget).

    Called after each major pipeline stage to give the frontend early data.
    """
    try:
        from backend.app.partial_results import save_partial_result

        partial_payload: dict[str, Any] = {
            "completed_stages": completed_stages,
            "current_stage": current_stage,
        }
        # Merge stage-specific data under partial_data
        partial_payload.setdefault("partial_data", {})
        partial_payload["partial_data"].update(data)

        # Read existing partial to accumulate across stages
        from backend.app.partial_results import get_partial_result
        existing = get_partial_result(job_id)
        if existing and "partial_data" in existing:
            merged = existing["partial_data"]
            merged.update(data)
            partial_payload["partial_data"] = merged

        partial_payload["completed_stages"] = completed_stages
        partial_payload["current_stage"] = current_stage
        save_partial_result(job_id, partial_payload)

        # Emit SSE event so frontend updates immediately
        _emit(job_id, "partial_result", stage=stage, partial_data=data,
              completed_stages=completed_stages, current_stage=current_stage)
    except Exception as exc:
        logger.debug("Failed to publish partial result for job %s stage %s: %s",
                      job_id, stage, public_failure(exc))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _finish_outcome(
    job: Job, run_output_dir: Path, *, required=(), optional=(),
    metrics: dict[str, Any] | None = None, pcap_label: str | None = None,
) -> PipelineOutcome:
    """Build the candidate manifest; only the worker may accept it."""
    required = list(required)
    manifest = "[]"
    try:
        if run_output_dir.parent.name == ".runs":
            manifest = build_accepted_manifest(job.accepted_run_manifest_json,
                                               run_output_dir.name, pcap_label)
        elif job.artifact_layout_version != 1:
            raise ValueError("Layout 2 requires an owned run directory")
    except Exception as exc:
        required.append(stage_failure("manifest", exc))
    return derive_outcome(required=required, optional=optional, metrics=metrics,
                          accepted_manifest_json=manifest)


def _run_binary_pipeline(
    job_id: str, job: Job, db: Session, *, input_root: Path,
    run_output_dir: Path, upload_root: Path,
) -> PipelineOutcome:
    """Analyze a staged binary and return its persistence/sensor outcome."""
    from backend.app.binalysis.service import analyze_and_persist

    def first_file(directory: Path) -> Path | None:
        if not directory.exists():
            return None
        return next((p for p in sorted(directory.iterdir()) if p.is_file()), None)

    target = first_file(input_root / "input")
    if target is None and job.upload_id:
        target = first_file(upload_root / job.upload_id)
    if target is None:
        return _finish_outcome(job, run_output_dir, required=[StageFailure("input", "No binary artifact found for job")])
    try:
        _emit(job_id, "stage.status", stage="binary", status="running")
        analysis, _, created = analyze_and_persist(db, job_id, target, target.name)
        metrics = {"artifact_class": analysis.artifact_class, "format": analysis.format,
                   "yara_available": analysis.yara_available, "yara_matches": len(analysis.yara_matches),
                   "findings_created": created}
        _emit(job_id, "stage.status", stage="binary", status="completed")
        optional = [] if analysis.yara_available else [StageFailure("yara", "YARA unavailable")]
        return _finish_outcome(job, run_output_dir, metrics=metrics, optional=optional)
    except Exception as exc:
        return _finish_outcome(job, run_output_dir, required=[stage_failure("binary", exc)])


def _run_code_artifact_pipeline(
    job_id: str, job: Job, db: Session, *, input_root: Path,
    run_output_dir: Path, upload_root: Path,
) -> PipelineOutcome:
    """Return BlueScrub scanner coverage without writing lifecycle state."""
    from backend.app.bluescrub.service import analyze_and_persist

    source_root = input_root / "input" / "source"
    if not source_root.exists() or not any(source_root.rglob("*")):
        return _finish_outcome(job, run_output_dir, required=[StageFailure("input", "No staged source found for job")])
    try:
        lineage = db.get(BlueScrubJobLineage, job_id)
        def progress(sensor: str, status: str, message: str | None = None) -> None:
            _emit(job_id, "stage.status", stage=sensor, status=status, message=message or "")

        metrics = analyze_and_persist(
            db, job_id, input_root, run_output_dir=run_output_dir,
            profile=job.execution_profile or "standard",
            project_id=lineage.project_id if lineage else None,
            analysis_kind=lineage.analysis_kind if lineage else "source_audit",
            progress=progress,
        )
        dacv = metrics["dacv"]
        optional = [StageFailure(item.get("sensor", "bluescrub"), "analysis_failed")
                    for item in dacv.get("partial_reasons", [])] if dacv.get("partial") else []
        if dacv.get("partial") and not optional:
            optional.append(StageFailure("bluescrub", "Partial scanner coverage"))
        return _finish_outcome(job, run_output_dir, metrics=metrics, optional=optional)
    except Exception as exc:
        return _finish_outcome(job, run_output_dir, required=[stage_failure("bluescrub", exc)])


def _record_sensor_result(db: Session, job_id: str, result: SensorResult) -> None:
    """Persist a SensorResult into the job_sensors table (upsert on re-analysis)."""
    from sqlalchemy import select as sa_select

    existing = db.execute(
        sa_select(JobSensor).where(
            JobSensor.job_id == job_id,
            JobSensor.sensor == result.sensor,
        )
    ).scalar_one_or_none()

    if existing:
        existing.status = result.status
        existing.started_at = result.started_at
        existing.completed_at = result.completed_at
        existing.duration_ms = result.duration_ms
        existing.error = public_failure(result.error) if result.error else None
        existing.error_code = result.error_code
    else:
        sensor_row = JobSensor(
            job_id=job_id,
            sensor=result.sensor,
            status=result.status,
            started_at=result.started_at,
            completed_at=result.completed_at,
            duration_ms=result.duration_ms,
            error=public_failure(result.error) if result.error else None,
            error_code=result.error_code,
        )
        db.add(sensor_row)
    db.commit()


def _write_job_metrics(
    job_dir: Path,
    job: Job,
    stages: list[SensorDef],
    sensor_results: list[SensorResult],
    corr_counts: dict[str, int] | None,
) -> None:
    """Write job_metrics.json per §20 of the implementation plan."""
    try:
        started = datetime.fromisoformat(job.started_at) if job.started_at else None
        completed = datetime.now(timezone.utc)
        total_runtime_sec = (
            int((completed - started).total_seconds()) if started and completed else 0
        )

        # Gather stage runtimes from sensor.meta.json files
        stage_runtimes: dict[str, float] = {}
        for stage_def in stages:
            meta_path = job_dir / "sensors" / stage_def.name / "sensor.meta.json"
            if meta_path.exists():
                meta = json.loads(meta_path.read_text())
                stage_runtimes[stage_def.name] = meta.get("duration_ms", 0) / 1000.0

        # Gather sensor runtimes from results
        sensor_runtimes: dict[str, float] = {}
        for r in sensor_results:
            if r.duration_ms is not None:
                sensor_runtimes[r.sensor] = r.duration_ms / 1000.0

        # Count artifacts from correlation results
        flow_count = (corr_counts or {}).get("flows", 0)
        alert_count = (corr_counts or {}).get("alerts", 0)
        finding_count = (corr_counts or {}).get("findings", 0)

        # Count extracted files
        file_count = 0
        ft_results = job_dir / "sensors" / "file_triage" / "sensor.results.jsonl"
        if ft_results.exists():
            for line in ft_results.read_text().splitlines():
                if line.strip():
                    try:
                        rec = json.loads(line)
                        if rec.get("type") == "extracted_file":
                            file_count += 1
                    except json.JSONDecodeError:
                        pass

        # PCAP size
        pcap_size = job.pcap_size_bytes or 0

        # Disk usage
        disk_used_bytes = sum(f.stat().st_size for f in job_dir.rglob("*") if f.is_file())

        metrics_data = {
            "total_runtime_sec": total_runtime_sec,
            "pcap_size_bytes": pcap_size,
            "flow_count": flow_count,
            "alert_count": alert_count,
            "file_count": file_count,
            "finding_count": finding_count,
            "stage_runtimes": stage_runtimes,
            "sensor_runtimes": sensor_runtimes,
            "disk_used_bytes": disk_used_bytes,
        }

        metrics_dir = job_dir / "metrics"
        metrics_dir.mkdir(parents=True, exist_ok=True)
        metrics_path = metrics_dir / "job_metrics.json"
        metrics_path.write_text(json.dumps(metrics_data, indent=2), encoding="utf-8")
        logger.info("Wrote job_metrics.json for job %s", job.job_id)
    except Exception as exc:
        logger.warning("Failed to write job_metrics.json: %s", public_failure(exc))


def _write_extraction_manifest(job_dir: Path) -> None:
    """Write extracted_files/manifest.json per §3.3 from file_triage results."""
    try:
        ft_results = job_dir / "sensors" / "file_triage" / "sensor.results.jsonl"
        if not ft_results.exists():
            return

        entries: list[dict] = []
        for line in ft_results.read_text().splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("type") != "extracted_file":
                continue
            data = rec.get("data", {})
            entries.append({
                "file_id": data.get("file_id"),
                "filename": data.get("filename"),
                "sha256": data.get("sha256"),
                "size_bytes": data.get("size_bytes"),
                "mime": data.get("mime"),
                "file_type": data.get("file_type"),
                "suspicious": data.get("suspicious", False),
                "yara_matches": data.get("yara_matches", []),
                "src_ip": data.get("src_ip"),
                "dst_ip": data.get("dst_ip"),
                "pcap_label": data.get("pcap_label"),
            })

        if not entries:
            return

        manifest_dir = job_dir / "extracted_files"
        manifest_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "schema_version": "1.0",
            "file_count": len(entries),
            "files": entries,
        }
        manifest_path = manifest_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        logger.info("Wrote extracted_files/manifest.json with %d entries", len(entries))
    except Exception as exc:
        logger.warning("Failed to write extraction manifest: %s", public_failure(exc))


def run_pipeline(
    job_id: str,
    db: Session,
    *,
    docker_client: Any,
    job_root: Path,
    upload_root: Path,
    sensor_config_dir: Path | None = None,
    max_job_disk_bytes: int = 53_687_091_200,
    preflight_multiplier: int = 4,
    pcap_label: str | None = None,
    input_root: Path | None = None,
    run_output_dir: Path | None = None,
) -> PipelineOutcome:
    """Execute the full analysis pipeline for a job.

    Args:
        job_id: The job to process.
        db: SQLAlchemy session.
        docker_client: Docker SDK client.
        job_root: Root path for job directories.
        upload_root: Root path for uploaded PCAPs.
        sensor_config_dir: Sensor-specific config directory.
        max_job_disk_bytes: Per-job disk quota.
        preflight_multiplier: Multiplier for preflight disk check.
        pcap_label: If set, only process PCAPs with this label (temporal re-analysis).

    Returns:
        One outcome for the worker to finalize under durable ownership.
    """
    job: Job | None = db.get(Job, job_id)
    if job is None:
        raise ValueError(f"Job {job_id} not found")

    if input_root is None:
        input_root = job_root / job_id
    if run_output_dir is None:
        if job.artifact_layout_version != 1:
            raise ValueError("Layout 2 requires an owned run_output_dir")
        run_output_dir = input_root

    logger.info("Starting pipeline for job %s (profile=%s, source_type=%s)",
                job_id, job.execution_profile, job.source_type)
    required_failures: list[StageFailure] = []
    optional_failures: list[StageFailure] = []

    # --- Binary artifact job: run YARA/binary analysis and finalize ---
    if (job.source_type or "") == "binary":
        return _run_binary_pipeline(job_id, job, db, input_root=input_root, run_output_dir=run_output_dir, upload_root=upload_root)

    if (job.source_type or "") == "code_artifact":
        return _run_code_artifact_pipeline(
            job_id, job, db, input_root=input_root, run_output_dir=run_output_dir, upload_root=upload_root
        )

    profile: Profile = job.execution_profile  # type: ignore[assignment]

    # Determine what this job contains
    _source_type = job.source_type or "pcap"
    has_pcaps = _source_type in ("pcap", "pcap+logs")
    # NB: these must be SourceType *values* — "c2_export"/"netflow" were stale
    # spellings that never matched, so C2/NetFlow bundles silently skipped the
    # telemetry stage unless the on-disk manifest fallback below rescued them.
    has_telemetry_bundle = _source_type in (
        "pcap+logs", "log_bundle", "c2_bundle", "netflow_bundle", "exercise_bundle",
    )
    # Also check for manifest on disk (fallback for hybrid jobs)
    _manifest_check_deferred = has_telemetry_bundle

    # --- Step 1: Setup job directory ---
    try:
        create_job_directory(input_root.parent, input_root.name, run_output_dir=run_output_dir)

        if has_pcaps:
            from sqlalchemy import select as sa_select
            from backend.app.pipeline.job_dir import compute_pcap_sha256

            # Look up JobPcap records for multi-PCAP support
            pcap_query = sa_select(JobPcap).where(JobPcap.job_id == job_id)
            if pcap_label:
                pcap_query = pcap_query.where(JobPcap.label == pcap_label)
            pcap_query = pcap_query.order_by(JobPcap.ordinal)
            pcap_records = db.execute(pcap_query).scalars().all()

            total_pcap_size = 0

            if pcap_records:
                # Multi-PCAP path: link each PCAP with its label
                for rec in pcap_records:
                    upload_dir = upload_root / rec.upload_id
                    found = list(upload_dir.glob("*.pcap")) + list(upload_dir.glob("*.pcapng"))
                    if not found:
                        raise FileNotFoundError(f"No PCAP found in {upload_dir} for upload {rec.upload_id}")
                    pcap_source = found[0]
                    total_pcap_size += pcap_source.stat().st_size
                    label = rec.label or "before"
                    # Ordinal disambiguates captures sharing a phase label.
                    link_pcap_labeled(input_root, pcap_source, label, rec.ordinal or 0)
                staged = len(list((input_root / "input").glob("*.pcap*")))
                logger.info(
                    "Linked %d/%d PCAPs for job %s", staged, len(pcap_records), job_id,
                )
            else:
                # Fallback: single-PCAP legacy path
                upload_dir = upload_root / (job.upload_id or "")
                pcap_files = list(upload_dir.glob("*.pcap")) + list(upload_dir.glob("*.pcapng"))
                if not pcap_files:
                    if has_telemetry_bundle:
                        # Hybrid job but no PCAPs found — degrade to bundle-only
                        logger.warning("No PCAPs found for hybrid job %s — running bundle-only", job_id)
                        has_pcaps = False
                    else:
                        raise FileNotFoundError(f"No PCAP found in {upload_dir}")
                else:
                    pcap_source = pcap_files[0]
                    total_pcap_size = pcap_source.stat().st_size
                    link_pcap(input_root, pcap_source)

            if has_pcaps:
                # Preflight disk check
                preflight = check_disk_space(
                    pcap_size_bytes=total_pcap_size,
                    job_root=job_root,
                    preflight_multiplier=preflight_multiplier,
                )
                if not preflight.ok:
                    return _finish_outcome(job, run_output_dir, required=[StageFailure("input", "insufficient_disk")], pcap_label=pcap_label)

                # Compute SHA of the first PCAP for backward compat
                first_pcap = list((input_root / "input").glob("*.pcap")) + list((input_root / "input").glob("*.pcapng"))
                if first_pcap:
                    pcap_sha = compute_pcap_sha256(first_pcap[0])
                    job.pcap_sha256 = pcap_sha
                    db.commit()

                    write_input_meta(
                        input_root,
                        job_id=job_id,
                        pcap_filename=job.pcap_filename or first_pcap[0].name,
                        pcap_sha256=pcap_sha,
                        execution_profile=profile,
                    )

    except Exception as exc:
        logger.error("Pipeline setup failed for job %s: %s", job_id, public_failure(exc))
        return _finish_outcome(job, run_output_dir, required=[stage_failure("input", exc)], pcap_label=pcap_label)

    # --- Re-analysis isolation (PCAP only) ---
    _hidden_pcaps: list[tuple[Path, Path]] = []
    stages: list[Any] = []
    sensors: list[Any] = []
    sensor_results: list[SensorResult] = []

    def _restore_hidden_pcaps() -> None:
        """Un-hide PCAPs hidden for single-phase re-analysis isolation.

        Idempotent (pops as it restores) so it is safe to call from the
        ``finally`` below whether the pipeline finished normally, returned
        early on a stage failure, or raised. Without this a mid-pipeline
        failure would leave evidence PCAPs renamed to ``*.hidden`` on disk
        permanently.
        """
        while _hidden_pcaps:
            hidden, original = _hidden_pcaps.pop()
            if hidden.exists():
                try:
                    hidden.rename(original)
                    logger.info("Restored hidden PCAP %s", original.name)
                except OSError as exc:
                    logger.warning(
                        "Failed to restore hidden PCAP %s: %s", original.name, public_failure(exc)
                    )

    if has_pcaps:
        # When re-analysing a single phase:
        #   1. Hide non-target PCAPs so sensors only process the target file
        #   2. Clean old sensor output dirs so the correlator doesn't re-ingest
        #      "before" data that's already persisted in the DB
        if pcap_label:
            import shutil as _shutil

            input_dir = input_root / "input"
            safe_label = "".join(c if c.isalnum() or c in "-_" else "_" for c in pcap_label)
            for p in sorted(input_dir.iterdir()):
                if p.is_symlink():
                    continue
                if p.suffix.lower() in (".pcap", ".pcapng") and p.stem != safe_label:
                    hidden = p.with_suffix(p.suffix + ".hidden")
                    p.rename(hidden)
                    _hidden_pcaps.append((hidden, p))
                    logger.info("Hid non-target PCAP %s during re-analysis", p.name)

            # Clean old sensor output directories so correlator only sees new data
            sensors_dir = run_output_dir / "sensors"
            if sensors_dir.exists():
                for sd in sensors_dir.iterdir():
                    if sd.is_dir():
                        _shutil.rmtree(sd)
                        logger.info("Cleaned old sensor output: %s", sd.name)

    try:
        # --- Step 2-3: Run stages (Zeek, Suricata) — PCAP only ---
        stages = get_stages_for_profile(profile) if has_pcaps else []
        sensors = get_sensors_for_profile(profile) if has_pcaps else []
        # +6 for telemetry + correlate + index + theories + slices + annotations
        total_steps = len(stages) + len(sensors) + 6
        step_num = 0
        failed_stages: set[str] = set()
        for stage_def in stages:
            step_num += 1
            logger.info("Running stage %s for job %s", stage_def.name, job_id)
            _emit(job_id, "stage.status", stage=stage_def.name, status="running",
                  step=step_num, total_steps=total_steps)
            create_sensor_output_dir(run_output_dir, stage_def.name)

            # Stages are run as Docker containers just like sensors
            result = run_sensor(
                sensor_def=stage_def,
                input_root=input_root,
                run_output_dir=run_output_dir,
                job_id=job_id,
                execution_profile=profile,
                docker_client=docker_client,
                sensor_config_dir=sensor_config_dir,
            )
            _record_sensor_result(db, job_id, result)
            _emit(job_id, "stage.status", stage=stage_def.name, status=result.status,
                  step=step_num, total_steps=total_steps,
                  duration_ms=result.duration_ms)

            if result.status in ("failed", "timeout") or (stage_def.required and result.status != "completed"):
                # Not fatal. Zeek and Suricata are independent of each other, and
                # neither is needed by the uploaded-log telemetry pipeline — so a
                # Zeek timeout used to throw away perfectly good Suricata alerts,
                # every uploaded log, and all downstream correlation. Record the
                # failure, skip only what genuinely depended on this stage, and
                # let the rest of the job produce what it still can.
                failed_stages.add(stage_def.name)
                (required_failures if stage_def.required else optional_failures).append(StageFailure(stage_def.name, result.error or result.status))
                logger.error(
                    "Stage %s %s for job %s — continuing without it: %s",
                    stage_def.name, result.status, job_id, public_failure(result.error),
                )

        # --- Publish partial result: ingest/parse stage data ---
        _completed_stages: list[str] = [s.name for s in stages]
        _pcap_stats: dict[str, Any] = {}
        try:
            # Gather PCAP stats from input files
            input_dir = input_root / "input"
            pcap_files_on_disk = list(input_dir.glob("*.pcap")) + list(input_dir.glob("*.pcapng"))
            _pcap_stats = {
                "file_count": len(pcap_files_on_disk),
                "total_bytes": sum(f.stat().st_size for f in pcap_files_on_disk if f.exists()),
            }
            # Try to read Zeek conn.log for top hosts
            _top_hosts: list[dict[str, Any]] = []
            _protocol_dist: dict[str, int] = {}
            conn_log = run_output_dir / "sensors" / "zeek" / "conn.log"
            if conn_log.exists():
                host_bytes: dict[str, int] = {}
                for line in conn_log.read_text().splitlines():
                    if line.startswith("#"):
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 10:
                        src, dst = parts[2], parts[4]
                        proto = parts[6] if len(parts) > 6 else "unknown"
                        bsrc = int(parts[9]) if parts[9].isdigit() else 0
                        host_bytes[src] = host_bytes.get(src, 0) + bsrc
                        host_bytes[dst] = host_bytes.get(dst, 0) + bsrc
                        _protocol_dist[proto] = _protocol_dist.get(proto, 0) + 1
                _top_hosts = [
                    {"ip": ip, "total_bytes": b}
                    for ip, b in sorted(host_bytes.items(), key=lambda x: -x[1])[:10]
                ]

            # Try to read Suricata alert summary
            _alert_summary: dict[str, Any] = {"total": 0, "by_severity": {}}
            eve_json = run_output_dir / "sensors" / "suricata" / "eve.json"
            if eve_json.exists():
                sev_counts: dict[str, int] = {}
                alert_total = 0
                for line in eve_json.read_text().splitlines():
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                        if rec.get("event_type") == "alert":
                            alert_total += 1
                            sev = str(rec.get("alert", {}).get("severity", "unknown"))
                            sev_counts[sev] = sev_counts.get(sev, 0) + 1
                            # Emit early_alert for high severity (1 = highest in Suricata)
                            if sev in ("1", "2"):
                                sig_name = rec.get("alert", {}).get("signature", "Unknown alert")
                                _emit(job_id, "early_alert",
                                      title=sig_name,
                                      severity="critical" if sev == "1" else "high",
                                      src_ip=rec.get("src_ip"),
                                      dst_ip=rec.get("dest_ip"))
                    except json.JSONDecodeError:
                        pass
                _alert_summary = {"total": alert_total, "by_severity": sev_counts}

            _publish_partial_result(
                job_id, "parse",
                {
                    "pcap_stats": _pcap_stats,
                    "top_hosts": _top_hosts,
                    "protocol_distribution": _protocol_dist,
                    "alert_summary": _alert_summary,
                },
                completed_stages=_completed_stages,
                current_stage="sensors",
            )
        except Exception as exc:
            logger.debug("Failed to publish parse partial result: %s", public_failure(exc))

        # --- Step 4: File extraction manifest ---
        # The actual extraction happens in file_triage sensor (Step 5).
        # We write the manifest after sensors complete (see below).

        # --- Step 5: Run sensors in deterministic order (PCAP only) ---
        for sensor_def in sensors:
            # Check skip conditions — resolve required inputs to sensor output dirs
            if sensor_def.skip_if_missing_inputs:
                missing = False
                reason = "Required inputs missing"
                # A stage that failed still has an output directory — it is
                # created before the stage runs — so directory existence alone
                # would let dependents run against empty or partial input.
                broken = sorted(set(sensor_def.inputs_required) & failed_stages)
                if broken:
                    missing = True
                    reason = f"Upstream stage(s) did not complete: {', '.join(broken)}"
                for req in sensor_def.inputs_required:
                    # Requirements refer to a previously-run sensor whose output lives
                    # under  run_output_dir / "sensors" / <req>  (e.g. "zeek", "suricata").
                    req_dir = run_output_dir / "sensors" / req
                    if not req_dir.exists():
                        missing = True
                        break
                if missing:
                    logger.info(
                        "Skipping sensor %s for job %s: %s",
                        sensor_def.name, job_id, reason,
                    )
                    skip_result = SensorResult(
                        sensor=sensor_def.name, status="skipped",
                        error=reason,
                        started_at=_now_iso(),
                    )
                    _record_sensor_result(db, job_id, skip_result)
                    sensor_results.append(skip_result)
                    if sensor_def.required:
                        required_failures.append(StageFailure(sensor_def.name, reason))
                    continue

            step_num += 1
            logger.info("Running sensor %s for job %s", sensor_def.name, job_id)
            _emit(job_id, "sensor.status", sensor=sensor_def.name, status="running",
                  step=step_num, total_steps=total_steps)
            create_sensor_output_dir(run_output_dir, sensor_def.name)

            result = run_sensor(
                sensor_def=sensor_def,
                input_root=input_root,
                run_output_dir=run_output_dir,
                job_id=job_id,
                execution_profile=profile,
                docker_client=docker_client,
                sensor_config_dir=sensor_config_dir,
            )
            _record_sensor_result(db, job_id, result)
            sensor_results.append(result)
            _emit(job_id, "sensor.status", sensor=sensor_def.name, status=result.status,
                  step=step_num, total_steps=total_steps,
                  duration_ms=result.duration_ms)

            if result.status in ("failed", "timeout") or (sensor_def.required and result.status != "completed"):
                (required_failures if sensor_def.required else optional_failures).append(StageFailure(sensor_def.name, result.error or result.status))
                logger.warning(
                    "Sensor %s %s for job %s: %s",
                    sensor_def.name, result.status, job_id, public_failure(result.error),
                )

            # Check job disk quota
            if check_job_quota(input_root, max_job_disk_bytes):
                logger.warning("Job %s exceeded disk quota", job_id)
                required_failures.append(StageFailure("quota", "quota_exceeded"))
                break

    finally:
        _restore_hidden_pcaps()

    # --- Write extraction manifest (§3.3) ---
    _write_extraction_manifest(run_output_dir)

    # --- Publish partial result: sensor completion summary ---
    _completed_stages.append("sensors")
    try:
        sensor_summary = {
            "total": len(sensor_results),
            "completed": sum(1 for r in sensor_results if r.status == "completed"),
            "failed": sum(1 for r in sensor_results if r.status == "failed"),
            "skipped": sum(1 for r in sensor_results if r.status == "skipped"),
            "sensors": [
                {"name": r.sensor, "status": r.status, "duration_ms": r.duration_ms}
                for r in sensor_results
            ],
        }
        _publish_partial_result(
            job_id, "sensors",
            {"sensor_summary": sensor_summary},
            completed_stages=_completed_stages,
            current_stage="correlate",
        )
    except Exception as exc:
        logger.debug("Failed to publish sensor partial result: %s", public_failure(exc))

    # --- Step 5b: Telemetry pipeline (log bundles) ---
    # Runs for hybrid (pcap+logs) and bundle-only jobs when a source_manifest.json exists.
    _manifest_path = input_root / "input" / "telemetry" / "source_manifest.json"
    if not _manifest_path.exists():
        # Also check alternate location
        _manifest_path = input_root / "source_manifest.json"
    if has_telemetry_bundle or _manifest_path.exists():
        step_num += 1
        _emit(job_id, "stage.status", stage="telemetry", status="running",
              step=step_num, total_steps=total_steps)
        try:
            from backend.app.pipeline.telemetry_pipeline import run_telemetry_pipeline

            telemetry_result = run_telemetry_pipeline(
                job_id=job_id,
                input_root=input_root,
                run_output_dir=run_output_dir,
                db=db,
                exercise_id=job.exercise_id,
            )
            telemetry_failed = bool(telemetry_result.get("error"))
            telemetry_partial = any(telemetry_result.get(key, 0) for key in (
                "files_error", "files_skipped", "files_unprocessed", "enrichment_errors"
            )) or bool(telemetry_result.get("partial"))
            if telemetry_failed:
                required_failures.append(StageFailure("input", "input_invalid"))
            elif telemetry_partial:
                optional_failures.append(StageFailure("telemetry", "telemetry_partial"))
            logger.info("Telemetry stage returned for job %s", job_id)
            parsed = telemetry_result.get("files_parsed", 0)
            events = telemetry_result.get("events_total", 0)
            corroborated = telemetry_result.get("corroborated", 0)
            telemetry_status = "failed" if telemetry_failed else (
                "completed_with_errors" if telemetry_partial else "completed"
            )
            _emit(job_id, "stage.status", stage="telemetry", status=telemetry_status,
                  step=step_num, total_steps=total_steps,
                  message=f"files={parsed} events={events} corroborated={corroborated}")
            _completed_stages.append("telemetry")
        except Exception as exc:
            logger.error("Telemetry pipeline failed for job %s: %s", job_id, public_failure(exc))
            optional_failures.append(stage_failure("telemetry", exc))
            _emit(job_id, "stage.status", stage="telemetry", status="failed",
                  step=step_num, total_steps=total_steps, message=public_failure(exc))

    # --- Step 6-8: Normalize, Correlate, Persist ---
    step_num += 1
    _emit(job_id, "stage.status", stage="correlate", status="running",
          step=step_num, total_steps=total_steps)
    corr_counts: dict[str, int] | None = None
    try:
        from backend.app.normalize.correlate import correlate_job

        corr_counts = correlate_job(job_id, run_output_dir, db)
        logger.info("Correlation results for job %s: %s", job_id, corr_counts)
        _emit(job_id, "stage.status", stage="correlate", status="completed",
              step=step_num, total_steps=total_steps,
              message=f"findings={corr_counts.get('findings', 0)}")

    except Exception as exc:
        logger.error("Correlation failed for job %s: %s", job_id, public_failure(exc))
        required_failures.append(stage_failure("correlate", exc))

    # Cross-job host enrichment is optional; correlation persistence above is required.
    if corr_counts is not None:
        try:
            from backend.app.normalize.post_process import update_global_host_stats
            update_global_host_stats(db, job_id)
        except Exception as exc:
            optional_failures.append(stage_failure("host_stats", exc))

    # Populate the Raw Events explorer for PCAP jobs by normalizing zeek flows/
    # events and suricata alerts into normalized_events. The telemetry pipeline
    # above only runs for log sources, so without this a plain PCAP capture has
    # an empty Raw Events view despite the rich per-connection sensor data.
    if has_pcaps:
        try:
            from backend.app.normalize.network_events import normalize_network_events
            n_events = normalize_network_events(job_id, run_output_dir, db)
            logger.info("Raw network events for job %s: %d", job_id, n_events)
        except Exception as exc:
            optional_failures.append(stage_failure("network_events", exc))
            logger.warning("PCAP network-event normalization failed for job %s", job_id)

    # --- Publish partial result: correlation / aggregate data ---
    _completed_stages.append("correlate")
    try:
        _corr_data: dict[str, Any] = {}
        if corr_counts:
            _corr_data["correlation_counts"] = corr_counts
            # Query early finding/alert counts from DB
            from sqlalchemy import func as sa_func
            _corr_data["finding_count"] = db.scalar(
                select(sa_func.count()).select_from(Finding).where(Finding.job_id == job_id)
            ) or 0
            _corr_data["alert_count"] = db.scalar(
                select(sa_func.count()).select_from(Alert).where(Alert.job_id == job_id)
            ) or 0
            _corr_data["host_count"] = db.scalar(
                select(sa_func.count()).select_from(Host).where(Host.job_id == job_id)
            ) or 0

        _publish_partial_result(
            job_id, "correlate",
            _corr_data,
            completed_stages=_completed_stages,
            current_stage="index",
        )
    except Exception as exc:
        logger.debug("Failed to publish correlate partial result: %s", public_failure(exc))

    # --- Step: Cross-source temporal correlation (logs ↔ PCAPs) ───────
    if has_pcaps and has_telemetry_bundle:
        step_num += 1
        _emit(job_id, "stage.status", stage="temporal_correlate", status="running",
              step=step_num, total_steps=total_steps)
        try:
            from backend.app.services.temporal_correlator import correlate_temporal
            tc_result = correlate_temporal(db, job_id)
            logger.info("Temporal correlation for job %s: %s", job_id, tc_result)
            _emit(job_id, "stage.status", stage="temporal_correlate", status="completed",
                  step=step_num, total_steps=total_steps,
                  message=f"matches={tc_result.get('matches', 0)} upgraded={tc_result.get('upgraded_events', 0)}")
        except Exception as exc:
            optional_failures.append(stage_failure("temporal_correlate", exc))
            logger.error("Temporal correlation failed for job %s: %s", job_id, public_failure(exc))
            _emit(job_id, "stage.status", stage="temporal_correlate", status="failed",
                  step=step_num, total_steps=total_steps, message=public_failure(exc))

    # --- Step 9: Auto-index pipeline outputs for RAG ───────────────
    step_num += 1
    _emit(job_id, "stage.status", stage="index", status="running",
          step=step_num, total_steps=total_steps)
    try:
        import asyncio
        from backend.app.config_v2 import get_settings as _get_settings
        from backend.app.services.embedding_models import (
            get_embedding_model_service,
            get_runtime_ollama_url,
        )
        from backend.app.services.kb_service import auto_index_job

        _settings = _get_settings()
        _ollama_url = get_runtime_ollama_url(_settings.aipam_ollama_url)
        _persist_dir = str(_settings.aipam_db_path).replace("aipam.db", "vector_store")
        _embedding_config = get_embedding_model_service(_ollama_url).get_active()
        if _embedding_config is None:
            logger.info("Skipping job %s vector indexing: no embedding model selected", job_id)
            _emit(job_id, "stage.status", stage="index", status="completed",
                  step=step_num, total_steps=total_steps, message="index skipped: select an embedding model")
        else:
            index_counts = asyncio.run(auto_index_job(
                db_session=db,
                job_id=job_id,
                ollama_url=_ollama_url,
                embedding_config=_embedding_config,
                persist_dir=_persist_dir,
            ))
            logger.info("Auto-indexed job %s outputs: %s", job_id, index_counts)
            _emit(job_id, "stage.status", stage="index", status="completed",
                  step=step_num, total_steps=total_steps)

    except Exception as exc:
        optional_failures.append(stage_failure("index", exc))
        logger.warning("Auto-indexing failed for job %s (non-fatal): %s", job_id, public_failure(exc))
        _emit(job_id, "stage.status", stage="index", status="failed",
              step=step_num, total_steps=total_steps, message="index failed (non-fatal)")

    # --- Step 10: Generate Theory of the Case ───────────────────────
    step_num += 1
    _emit(job_id, "stage.status", stage="theories", status="running",
          step=step_num, total_steps=total_steps)
    try:
        from backend.app.services.theory_engine import generate_all_theories

        theory_counts = generate_all_theories(db, job_id, pcap_label=pcap_label)
        logger.info("Theory generation for job %s: %s", job_id, theory_counts)
        _emit(job_id, "stage.status", stage="theories", status="completed",
              step=step_num, total_steps=total_steps,
              message=f"theories={theory_counts.get('total', 0)}")
    except Exception as exc:
        optional_failures.append(stage_failure("theories", exc))
        logger.warning("Theory generation failed for job %s (non-fatal): %s", job_id, public_failure(exc))
        _emit(job_id, "stage.status", stage="theories", status="failed",
              step=step_num, total_steps=total_steps, message="theories failed (non-fatal)")

    # --- Step 11: Generate Incident Slices ──────────────────────────
    step_num += 1
    _emit(job_id, "stage.status", stage="slices", status="running",
          step=step_num, total_steps=total_steps)
    try:
        from backend.app.services.slicer import generate_slices

        slices = generate_slices(db, job_id, pcap_label=pcap_label)
        logger.info("Slice generation for job %s: %d slices", job_id, len(slices))
        _emit(job_id, "stage.status", stage="slices", status="completed",
              step=step_num, total_steps=total_steps,
              message=f"slices={len(slices)}")
    except Exception as exc:
        optional_failures.append(stage_failure("slices", exc))
        logger.warning("Slice generation failed for job %s (non-fatal): %s", job_id, public_failure(exc))
        _emit(job_id, "stage.status", stage="slices", status="failed",
              step=step_num, total_steps=total_steps, message="slices failed (non-fatal)")

    # --- Step 12: Generate Context Annotations (Why Unusual?) ─────
    step_num += 1
    _emit(job_id, "stage.status", stage="annotations", status="running",
          step=step_num, total_steps=total_steps)
    try:
        from backend.app.services.contextualizer import generate_annotations

        anns = generate_annotations(db, job_id, pcap_label=pcap_label)
        logger.info("Annotation generation for job %s: %d annotations", job_id, len(anns))
        _emit(job_id, "stage.status", stage="annotations", status="completed",
              step=step_num, total_steps=total_steps,
              message=f"annotations={len(anns)}")
    except Exception as exc:
        optional_failures.append(stage_failure("annotations", exc))
        logger.warning("Annotation generation failed for job %s (non-fatal): %s", job_id, public_failure(exc))
        _emit(job_id, "stage.status", stage="annotations", status="failed",
              step=step_num, total_steps=total_steps, message="annotations failed (non-fatal)")

    # Store metrics
    metrics = {
        "total_sensors": len(sensor_results),
        "completed": sum(1 for r in sensor_results if r.status == "completed"),
        "failed": sum(1 for r in sensor_results if r.status == "failed"),
        "timeout": sum(1 for r in sensor_results if r.status == "timeout"),
        "skipped": sum(1 for r in sensor_results if r.status == "skipped"),
    }

    # --- Write job_metrics.json (§20) ---
    _write_job_metrics(run_output_dir, job, stages, sensor_results, corr_counts)

    # --- Clean up partial results (full results now available) ---
    try:
        from backend.app.partial_results import delete_partial_result
        delete_partial_result(job_id)
    except Exception:
        pass

    return _finish_outcome(job, run_output_dir, required=required_failures, optional=optional_failures, metrics=metrics, pcap_label=pcap_label)
