"""
Artifacts endpoints (§3.7).

GET  /jobs/{jobId}/artifacts                    – list artifacts
POST /jobs/{jobId}/artifacts/evidence-package   – create evidence package
GET  /artifacts/{artifactId}/download           – download artifact
"""

import hashlib
import json
import logging
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.config_v2 import Settings, get_settings
from backend.app.models.alert import Alert
from backend.app.models.artifact import Artifact
from backend.app.models.connection import Connection
from backend.app.models.dns import DnsQuery
from backend.app.models.file import File
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.models.timeline import TimelineEvent
from backend.app.models.tls import TlsSession
from backend.app.schemas.artifact import (
    ArtifactItem,
    ArtifactListResponse,
    EvidencePackageCreateResponse,
)

logger = logging.getLogger("aipam.artifacts")

router = APIRouter(tags=["Artifacts"], dependencies=[Depends(verify_token)])


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/jobs/{job_id}/artifacts", response_model=ArtifactListResponse)
async def list_artifacts(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    rows = db.execute(
        select(Artifact).where(Artifact.job_id == job_id).order_by(Artifact.created_at.desc())
    ).scalars().all()

    return ArtifactListResponse(
        items=[ArtifactItem.model_validate(a) for a in rows],
    )


def _query_to_dicts(db: Session, model, job_id: str, limit: int = 10000) -> list[dict]:
    """Query all rows for a job and return as list of dicts."""
    rows = db.execute(
        select(model).where(model.job_id == job_id).limit(limit)
    ).scalars().all()
    result = []
    for r in rows:
        d = {c.name: getattr(r, c.name) for c in r.__table__.columns if c.name != "id"}
        result.append(d)
    return result


def _build_evidence_zip(
    db: Session, job_id: str, job: Job, artifact_dir: Path,
) -> tuple[Path, int, str]:
    """Build a ZIP evidence package and return (path, size_bytes, sha256)."""
    artifact_dir.mkdir(parents=True, exist_ok=True)
    zip_name = f"evidence-{job_id[:8]}.zip"
    zip_path = artifact_dir / zip_name

    manifest = {
        "job_id": job_id,
        "job_name": job.job_name,
        "pcap_filename": job.pcap_filename,
        "status": job.status,
        "created_at": job.created_at,
        "completed_at": job.completed_at,
        "generated_at": _now_iso(),
    }

    sections = {
        "hosts.json": _query_to_dicts(db, Host, job_id),
        "connections.json": _query_to_dicts(db, Connection, job_id),
        "alerts.json": _query_to_dicts(db, Alert, job_id),
        "dns_queries.json": _query_to_dicts(db, DnsQuery, job_id),
        "tls_sessions.json": _query_to_dicts(db, TlsSession, job_id),
        "findings.json": _query_to_dicts(db, Finding, job_id),
        "iocs.json": _query_to_dicts(db, Ioc, job_id),
        "files.json": _query_to_dicts(db, File, job_id),
        "timeline.json": _query_to_dicts(db, TimelineEvent, job_id),
    }

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))
        for fname, data in sections.items():
            zf.writestr(fname, json.dumps(data, indent=2, default=str))

    size = zip_path.stat().st_size
    sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    return zip_path, size, sha


@router.post("/jobs/{job_id}/artifacts/evidence-package", response_model=EvidencePackageCreateResponse)
async def create_evidence_package(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Create an evidence package artifact (ZIP with all job data)."""
    job = _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    artifact_id = str(uuid.uuid4())
    artifact = Artifact(
        job_id=job_id,
        artifact_id=artifact_id,
        type="evidence_package",
        status="generating",
        created_at=_now_iso(),
    )
    db.add(artifact)
    db.commit()

    try:
        artifact_dir = settings.aipam_job_root / job_id / "artifacts"
        zip_path, size_bytes, sha256 = _build_evidence_zip(db, job_id, job, artifact_dir)

        artifact.status = "available"
        artifact.filename = zip_path.name
        artifact.size_bytes = size_bytes
        artifact.sha256 = sha256
        db.commit()

        logger.info("Evidence package created for job %s: %s (%d bytes)", job_id, zip_path.name, size_bytes)
        return EvidencePackageCreateResponse(artifact_id=artifact_id, status="available")

    except Exception as exc:
        logger.error("Evidence package generation failed for job %s: %s", job_id, exc, exc_info=True)
        db.rollback()
        artifact = db.execute(
            select(Artifact).where(Artifact.artifact_id == artifact_id)
        ).scalar_one_or_none()
        if artifact:
            artifact.status = "failed"
            artifact.error = str(exc)[:500]
            db.commit()
        raise HTTPException(status_code=500, detail=f"Evidence package generation failed: {exc}")


@router.get("/artifacts/{artifact_id}/download")
async def download_artifact(
    artifact_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Download an artifact file."""
    response.headers["X-Request-Id"] = request_id

    artifact = db.execute(
        select(Artifact).where(Artifact.artifact_id == artifact_id)
    ).scalar_one_or_none()
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")

    if artifact.status != "available":
        raise HTTPException(status_code=409, detail=f"Artifact status is '{artifact.status}', not available")

    # Build the file path
    artifact_path = settings.aipam_job_root / artifact.job_id / "artifacts" / (artifact.filename or artifact_id)
    if not artifact_path.exists():
        raise HTTPException(status_code=404, detail="Artifact file not found on disk")

    return FileResponse(
        path=str(artifact_path),
        filename=artifact.filename or f"{artifact_id}.zip",
        media_type="application/octet-stream",
    )

