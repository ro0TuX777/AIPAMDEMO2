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

from sqlalchemy.orm import Session

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

logger = logging.getLogger("aipam.orchestrator")


def _emit(job_id: str, event_type: str, **payload: Any) -> None:
    """Fire-and-forget event publish (never fails the pipeline)."""
    try:
        publish_job_event(job_id, event_type, {"job_id": job_id, **payload})
    except Exception:
        pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _update_job_status(db: Session, job: Job, status: str, error: str | None = None) -> None:
    """Update job status in DB."""
    job.status = status
    if error:
        job.error_summary = error
    if status in ("completed", "completed_with_errors", "failed", "canceled"):
        job.completed_at = _now_iso()
    db.commit()


def _record_sensor_result(db: Session, job_id: str, result: SensorResult) -> None:
    """Persist a SensorResult into the job_sensors table."""
    sensor_row = JobSensor(
        job_id=job_id,
        sensor=result.sensor,
        status=result.status,
        started_at=result.started_at,
        completed_at=result.completed_at,
        duration_ms=result.duration_ms,
        error=result.error,
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
        completed = datetime.fromisoformat(job.completed_at) if job.completed_at else None
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
        logger.warning("Failed to write job_metrics.json: %s", exc)


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
        logger.warning("Failed to write extraction manifest: %s", exc)


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
) -> str:
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

    Returns:
        Final job status string.
    """
    job: Job | None = db.get(Job, job_id)
    if job is None:
        raise ValueError(f"Job {job_id} not found")

    logger.info("Starting pipeline for job %s (profile=%s)", job_id, job.execution_profile)
    _update_job_status(db, job, "running")
    job.started_at = _now_iso()
    db.commit()

    profile: Profile = job.execution_profile  # type: ignore[assignment]

    # --- Step 1: Setup job directory ---
    try:
        job_dir = create_job_directory(job_root, job_id)

        from sqlalchemy import select as sa_select
        from backend.app.pipeline.job_dir import compute_pcap_sha256

        # Look up JobPcap records for multi-PCAP support
        pcap_records = db.execute(
            sa_select(JobPcap).where(JobPcap.job_id == job_id).order_by(JobPcap.ordinal)
        ).scalars().all()

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
                label = rec.label or rec.filename.rsplit(".", 1)[0] or f"pcap_{rec.ordinal}"
                link_pcap_labeled(job_dir, pcap_source, label)
            logger.info("Linked %d PCAPs for job %s", len(pcap_records), job_id)
        else:
            # Fallback: single-PCAP legacy path
            upload_dir = upload_root / (job.upload_id or "")
            pcap_files = list(upload_dir.glob("*.pcap")) + list(upload_dir.glob("*.pcapng"))
            if not pcap_files:
                raise FileNotFoundError(f"No PCAP found in {upload_dir}")
            pcap_source = pcap_files[0]
            total_pcap_size = pcap_source.stat().st_size
            link_pcap(job_dir, pcap_source)

        # Preflight disk check
        preflight = check_disk_space(
            pcap_size_bytes=total_pcap_size,
            job_root=job_root,
            preflight_multiplier=preflight_multiplier,
        )
        if not preflight.ok:
            _update_job_status(db, job, "failed", preflight.message)
            return "failed"

        # Compute SHA of the first PCAP for backward compat
        first_pcap = list((job_dir / "input").glob("*.pcap")) + list((job_dir / "input").glob("*.pcapng"))
        if first_pcap:
            pcap_sha = compute_pcap_sha256(first_pcap[0])
            job.pcap_sha256 = pcap_sha
            db.commit()

            write_input_meta(
                job_dir,
                job_id=job_id,
                pcap_filename=job.pcap_filename or first_pcap[0].name,
                pcap_sha256=pcap_sha,
                execution_profile=profile,
            )

    except Exception as exc:
        logger.error("Pipeline setup failed for job %s: %s", job_id, exc)
        _update_job_status(db, job, "failed", str(exc))
        return "failed"

    # --- Step 2-3: Run stages (Zeek, Suricata) ---
    stages = get_stages_for_profile(profile)
    total_steps = len(stages) + len(get_sensors_for_profile(profile)) + 5  # +5 for correlate + index + theories + slices + annotations
    step_num = 0
    for stage_def in stages:
        step_num += 1
        logger.info("Running stage %s for job %s", stage_def.name, job_id)
        _emit(job_id, "stage.status", stage=stage_def.name, status="running",
              step=step_num, total_steps=total_steps)
        create_sensor_output_dir(job_dir, stage_def.name)

        # Stages are run as Docker containers just like sensors
        result = run_sensor(
            sensor_def=stage_def,
            job_dir=job_dir,
            job_id=job_id,
            execution_profile=profile,
            docker_client=docker_client,
            sensor_config_dir=sensor_config_dir,
        )
        _record_sensor_result(db, job_id, result)
        _emit(job_id, "stage.status", stage=stage_def.name, status=result.status,
              step=step_num, total_steps=total_steps,
              duration_ms=result.duration_ms)

        if result.status == "failed":
            logger.error("Stage %s failed for job %s: %s", stage_def.name, job_id, result.error)
            _update_job_status(db, job, "failed", f"Stage {stage_def.name} failed: {result.error}")
            return "failed"

    # --- Step 4: File extraction manifest ---
    # The actual extraction happens in file_triage sensor (Step 5).
    # We write the manifest after sensors complete (see below).

    # --- Step 5: Run sensors in deterministic order ---
    sensors = get_sensors_for_profile(profile)
    sensor_results: list[SensorResult] = []
    has_errors = False

    for sensor_def in sensors:
        # Check skip conditions — resolve required inputs to sensor output dirs
        if sensor_def.skip_if_missing_inputs:
            missing = False
            for req in sensor_def.inputs_required:
                # Requirements refer to a previously-run sensor whose output lives
                # under  job_dir / "sensors" / <req>  (e.g. "zeek", "suricata").
                req_dir = job_dir / "sensors" / req
                if not req_dir.exists():
                    missing = True
                    break
            if missing:
                skip_result = SensorResult(
                    sensor=sensor_def.name, status="skipped",
                    error="Required inputs missing",
                    started_at=_now_iso(),
                )
                _record_sensor_result(db, job_id, skip_result)
                sensor_results.append(skip_result)
                continue

        step_num += 1
        logger.info("Running sensor %s for job %s", sensor_def.name, job_id)
        _emit(job_id, "sensor.status", sensor=sensor_def.name, status="running",
              step=step_num, total_steps=total_steps)
        create_sensor_output_dir(job_dir, sensor_def.name)

        result = run_sensor(
            sensor_def=sensor_def,
            job_dir=job_dir,
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

        if result.status in ("failed", "timeout"):
            has_errors = True
            logger.warning(
                "Sensor %s %s for job %s: %s",
                sensor_def.name, result.status, job_id, result.error,
            )

        # Check job disk quota
        if check_job_quota(job_dir, max_job_disk_bytes):
            logger.warning("Job %s exceeded disk quota", job_id)
            has_errors = True
            break

    # --- Write extraction manifest (§3.3) ---
    _write_extraction_manifest(job_dir)

    # --- Step 6-8: Normalize, Correlate, Persist ---
    step_num += 1
    _emit(job_id, "stage.status", stage="correlate", status="running",
          step=step_num, total_steps=total_steps)
    corr_counts: dict[str, int] | None = None
    try:
        from backend.app.normalize.correlate import correlate_job

        corr_counts = correlate_job(job_id, job_dir, db)
        logger.info("Correlation results for job %s: %s", job_id, corr_counts)
        _emit(job_id, "stage.status", stage="correlate", status="completed",
              step=step_num, total_steps=total_steps,
              message=f"findings={corr_counts.get('findings', 0)}")

        # Update global host registry for cross-job forensics
        from backend.app.normalize.post_process import update_global_host_stats
        update_global_host_stats(db, job_id)
    except Exception as exc:
        logger.error("Correlation failed for job %s: %s", job_id, exc, exc_info=True)
        has_errors = True

    # --- Step 9: Auto-index pipeline outputs for RAG ───────────────
    step_num += 1
    _emit(job_id, "stage.status", stage="index", status="running",
          step=step_num, total_steps=total_steps)
    try:
        import asyncio
        from backend.app.config_v2 import get_settings as _get_settings
        from backend.app.services.kb_service import auto_index_job

        _settings = _get_settings()
        _ollama_url = _settings.aipam_ollama_url.rstrip("/")
        _persist_dir = str(_settings.aipam_db_path).replace("aipam.db", "vector_store")

        index_counts = asyncio.run(auto_index_job(
            db_session=db,
            job_id=job_id,
            ollama_url=_ollama_url,
            persist_dir=_persist_dir,
        ))
        logger.info("Auto-indexed job %s outputs: %s", job_id, index_counts)
        _emit(job_id, "stage.status", stage="index", status="completed",
              step=step_num, total_steps=total_steps)
    except Exception as exc:
        logger.warning("Auto-indexing failed for job %s (non-fatal): %s", job_id, exc)
        _emit(job_id, "stage.status", stage="index", status="completed",
              step=step_num, total_steps=total_steps, message="index failed (non-fatal)")

    # --- Step 10: Generate Theory of the Case ───────────────────────
    step_num += 1
    _emit(job_id, "stage.status", stage="theories", status="running",
          step=step_num, total_steps=total_steps)
    try:
        from backend.app.services.theory_engine import generate_all_theories

        theory_counts = generate_all_theories(db, job_id)
        logger.info("Theory generation for job %s: %s", job_id, theory_counts)
        _emit(job_id, "stage.status", stage="theories", status="completed",
              step=step_num, total_steps=total_steps,
              message=f"theories={theory_counts.get('total', 0)}")
    except Exception as exc:
        logger.warning("Theory generation failed for job %s (non-fatal): %s", job_id, exc)
        _emit(job_id, "stage.status", stage="theories", status="completed",
              step=step_num, total_steps=total_steps, message="theories failed (non-fatal)")

    # --- Step 11: Generate Incident Slices ──────────────────────────
    step_num += 1
    _emit(job_id, "stage.status", stage="slices", status="running",
          step=step_num, total_steps=total_steps)
    try:
        from backend.app.services.slicer import generate_slices

        slices = generate_slices(db, job_id)
        logger.info("Slice generation for job %s: %d slices", job_id, len(slices))
        _emit(job_id, "stage.status", stage="slices", status="completed",
              step=step_num, total_steps=total_steps,
              message=f"slices={len(slices)}")
    except Exception as exc:
        logger.warning("Slice generation failed for job %s (non-fatal): %s", job_id, exc)
        _emit(job_id, "stage.status", stage="slices", status="completed",
              step=step_num, total_steps=total_steps, message="slices failed (non-fatal)")

    # --- Step 12: Generate Context Annotations (Why Unusual?) ─────
    step_num += 1
    _emit(job_id, "stage.status", stage="annotations", status="running",
          step=step_num, total_steps=total_steps)
    try:
        from backend.app.services.contextualizer import generate_annotations

        anns = generate_annotations(db, job_id)
        logger.info("Annotation generation for job %s: %d annotations", job_id, len(anns))
        _emit(job_id, "stage.status", stage="annotations", status="completed",
              step=step_num, total_steps=total_steps,
              message=f"annotations={len(anns)}")
    except Exception as exc:
        logger.warning("Annotation generation failed for job %s (non-fatal): %s", job_id, exc)
        _emit(job_id, "stage.status", stage="annotations", status="completed",
              step=step_num, total_steps=total_steps, message="annotations failed (non-fatal)")

    # --- Frontier Knowledge Distillation v2 (non-blocking) ---
    try:
        from backend.app.distillation import reload_teacher_config, distill_v2
        teacher = reload_teacher_config()  # reload from shared JSON on disk
        if teacher.enabled and teacher.is_configured():
            logger.info(
                "[PIPELINE] Frontier distillation v2 enabled — distilling job %s via %s",
                job_id, teacher.model,
            )
            import asyncio
            from backend.app.database_v2 import get_session_factory
            distill_stats = asyncio.run(
                distill_v2(
                    db_session_factory=get_session_factory(),
                    job_id=job_id,
                    teacher=teacher,
                )
            )
            logger.info("[PIPELINE] Distillation v2 result: %s", distill_stats)
        else:
            logger.debug("[PIPELINE] Distillation v2 skipped (not configured or disabled)")
    except Exception as distill_exc:
        # Distillation failure must never fail the analysis job
        logger.warning(
            "[PIPELINE] Frontier distillation failed (continuing): %s",
            distill_exc,
        )

    # --- Final status ---
    final_status = "completed_with_errors" if has_errors else "completed"
    _update_job_status(db, job, final_status)
    _emit(job_id, "job.complete", status=final_status)

    # Store metrics
    metrics = {
        "total_sensors": len(sensor_results),
        "completed": sum(1 for r in sensor_results if r.status == "completed"),
        "failed": sum(1 for r in sensor_results if r.status == "failed"),
        "timeout": sum(1 for r in sensor_results if r.status == "timeout"),
        "skipped": sum(1 for r in sensor_results if r.status == "skipped"),
    }
    job.metrics_json = json.dumps(metrics)
    db.commit()

    # --- Write job_metrics.json (§20) ---
    _write_job_metrics(job_dir, job, stages, sensor_results, corr_counts)

    logger.info("Pipeline completed for job %s: status=%s, metrics=%s", job_id, final_status, metrics)
    return final_status
