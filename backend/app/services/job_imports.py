"""Create jobs from external PCAP exports; dispatch remains an API concern."""

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from backend.app.config_v2 import Settings
from backend.app.models.job import Job
from backend.app.models.upload import Upload
from backend.app.schemas.job import ArkimeJobRequest, JobCreateResponse, SecurityOnionJobRequest
from backend.app.services.job_creation import JobCreationError

_logger = logging.getLogger("aipam.api.jobs")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")



async def create_job_from_arkime(
    body: ArkimeJobRequest,
    db: Session,
    settings: Settings,
) -> JobCreateResponse:
    from backend.app.connectors import ArkimeConnector
    connector = ArkimeConnector()

    if not connector.enabled:
        raise JobCreationError(status_code=400, detail="Arkime integration is not enabled. Set ARKIME_ENABLED=true.")

    # Export PCAP from Arkime Viewer
    try:
        pcap_data = await connector.export_pcap(body.filter, body.time_range)
    except Exception as exc:
        _logger.error("Arkime PCAP export failed: %s", exc)
        raise JobCreationError(status_code=502, detail=f"Failed to export PCAP from Arkime: {exc}")

    if not pcap_data:
        raise JobCreationError(status_code=404, detail="No matching sessions found in Arkime for the given filter/time range.")

    job_id = str(uuid.uuid4())
    upload_id = str(uuid.uuid4())
    pcap_filename = f"arkime_export_{job_id[:8]}.pcap"
    pcap_sha256 = hashlib.sha256(pcap_data).hexdigest()

    # Save the exported PCAP to the upload staging area so the
    # pipeline can find it via the standard upload_id lookup.
    upload_dir: Path = settings.aipam_upload_root / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    (upload_dir / pcap_filename).write_bytes(pcap_data)

    # Create an Upload DB record
    upload = Upload(
        upload_id=upload_id,
        filename=pcap_filename,
        size_bytes=len(pcap_data),
        sha256=pcap_sha256,
        is_valid=1,
        format="pcap",
        created_at=_now_iso(),
    )
    db.add(upload)

    # Create the Job record linked to the upload
    job = Job(
        job_id=job_id,
        job_name=body.metadata.get("exercise_id", f"Arkime: {body.filter[:60]}"),
        notes=body.metadata.get("notes", ""),
        status="queued",
        execution_profile="standard",
        priority="normal",
        upload_id=upload_id,
        pcap_filename=pcap_filename,
        pcap_size_bytes=len(pcap_data),
        pcap_sha256=pcap_sha256,
        created_at=_now_iso(),
    )
    db.add(job)
    db.commit()


    return JobCreateResponse(schema_version="1.0", job_id=job_id)



async def create_job_from_security_onion(
    body: SecurityOnionJobRequest,
    db: Session,
    settings: Settings,
) -> JobCreateResponse:
    from backend.app.connectors import SecurityOnionConnector
    connector = SecurityOnionConnector()

    if not connector.enabled:
        raise JobCreationError(status_code=400, detail="Security Onion integration is not enabled. Set SECURITY_ONION_ENABLED=true.")

    # Export PCAP from Security Onion
    try:
        pcap_data = await connector.export_pcap(body.time_range, body.sensors, body.filter_fields)
    except Exception as exc:
        _logger.error("Security Onion PCAP export failed: %s", exc)
        raise JobCreationError(status_code=502, detail=f"Failed to export PCAP from Security Onion: {exc}")

    if not pcap_data:
        raise JobCreationError(status_code=404, detail="No matching packets found in Security Onion for the given time range/sensors.")

    job_id = str(uuid.uuid4())
    upload_id = str(uuid.uuid4())
    pcap_filename = f"so_export_{job_id[:8]}.pcap"
    pcap_sha256 = hashlib.sha256(pcap_data).hexdigest()

    # Save the exported PCAP to the upload staging area
    upload_dir: Path = settings.aipam_upload_root / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    (upload_dir / pcap_filename).write_bytes(pcap_data)

    # Create an Upload DB record
    upload = Upload(
        upload_id=upload_id,
        filename=pcap_filename,
        size_bytes=len(pcap_data),
        sha256=pcap_sha256,
        is_valid=1,
        format="pcap",
        created_at=_now_iso(),
    )
    db.add(upload)

    # Create the Job record linked to the upload
    sensor_names = ", ".join(body.sensors) if body.sensors else "all"
    job = Job(
        job_id=job_id,
        job_name=body.metadata.get("exercise_id", f"SO: {sensor_names}"),
        notes=body.metadata.get("notes", ""),
        status="queued",
        execution_profile="standard",
        priority="normal",
        upload_id=upload_id,
        pcap_filename=pcap_filename,
        pcap_size_bytes=len(pcap_data),
        pcap_sha256=pcap_sha256,
        created_at=_now_iso(),
    )
    db.add(job)
    db.commit()


    return JobCreateResponse(schema_version="1.0", job_id=job_id)
