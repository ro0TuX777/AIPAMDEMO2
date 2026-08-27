"""
Upload endpoints (§1.2).

POST /uploads          – stream-save a PCAP file
POST /uploads/bundle   – stream-save a log/C2/netflow bundle (zip/tar.gz)
POST /uploads/{id}/validate – validate PCAP header (capinfos)
"""

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.config_v2 import Settings, get_settings
from backend.app.models.upload import Upload
from backend.app.pipeline.artifact_classifier import classify_artifact
from backend.app.schemas.upload import (
    ArtifactClassifyResponse,
    ArtifactUploadResponse,
    UploadCreateResponse,
    UploadValidateResponse,
)

router = APIRouter(tags=["Uploads"], dependencies=[Depends(verify_token)])

# PCAP magic bytes: standard (0xa1b2c3d4), nano (0xa1b23c4d), pcapng (0x0a0d0d0a)
_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",  # pcap big-endian
    b"\xd4\xc3\xb2\xa1",  # pcap little-endian
    b"\xa1\xb2\x3c\x4d",  # pcap nanosecond big-endian
    b"\x4d\x3c\xb2\xa1",  # pcap nanosecond little-endian
    b"\x0a\x0d\x0d\x0a",  # pcapng section header
}


@router.post(
    "/uploads",
    status_code=status.HTTP_201_CREATED,
    response_model=UploadCreateResponse,
)
async def create_upload(
    request: Request,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Stream-save an uploaded PCAP to disk and register it in the DB."""
    response.headers["X-Request-Id"] = request_id

    # Read filename from query param, Content-Disposition header, or fallback to UUID
    filename = request.query_params.get("filename")
    if not filename:
        cd = request.headers.get("content-disposition", "")
        # Parse filename="..." from Content-Disposition header
        if 'filename="' in cd:
            filename = cd.split('filename="', 1)[1].rstrip('"')
        elif "filename=" in cd:
            filename = cd.split("filename=", 1)[1].strip().strip('"')
    if not filename:
        filename = f"{uuid.uuid4()}.pcap"

    upload_id = str(uuid.uuid4())
    upload_dir: Path = settings.aipam_upload_root / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    dest = upload_dir / filename

    sha = hashlib.sha256()
    size = 0

    # Stream body to disk in 256 KB chunks
    with open(dest, "wb") as f:
        async for chunk in request.stream():
            f.write(chunk)
            sha.update(chunk)
            size += len(chunk)

    # Guard: reject empty uploads
    if size == 0:
        dest.unlink(missing_ok=True)
        upload_dir.rmdir()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty upload body",
        )

    upload = Upload(
        upload_id=upload_id,
        filename=filename,
        size_bytes=size,
        sha256=sha.hexdigest(),
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    )
    db.add(upload)
    db.commit()
    db.refresh(upload)

    return UploadCreateResponse.model_validate(upload)


@router.post(
    "/uploads/{upload_id}/validate",
    response_model=UploadValidateResponse,
)
async def validate_upload(
    upload_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Validate the uploaded PCAP: check magic bytes, count packets."""
    response.headers["X-Request-Id"] = request_id

    upload: Upload | None = db.get(Upload, upload_id)
    if upload is None:
        raise HTTPException(status_code=404, detail="Upload not found")

    file_path = settings.aipam_upload_root / upload_id / upload.filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Upload file missing from disk")

    # Check magic bytes
    with open(file_path, "rb") as f:
        magic = f.read(4)

    is_valid = magic in _PCAP_MAGICS
    fmt = None
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
        fmt = "pcap"
    elif magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
        fmt = "pcap_nanosecond"
    elif magic == b"\x0a\x0d\x0d\x0a":
        fmt = "pcapng"

    # Update DB record
    upload.is_valid = 1 if is_valid else 0
    upload.format = fmt
    db.commit()

    warnings: list[str] = []
    if not is_valid:
        warnings.append("File does not appear to be a valid PCAP/PcapNG capture")

    return UploadValidateResponse(
        is_valid=is_valid,
        format=fmt,
        packet_count=upload.packet_count,
        capture_duration_seconds=upload.capture_duration_seconds,
        warnings=warnings,
    )



# Allowed bundle extensions — archives and raw log files
_BUNDLE_ARCHIVE_EXTENSIONS = {".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar"}
_BUNDLE_RAW_LOG_EXTENSIONS = {".json", ".jsonl", ".evtx", ".log", ".csv", ".xml", ".txt", ".ndjson"}
_BUNDLE_EXTENSIONS = _BUNDLE_ARCHIVE_EXTENSIONS | _BUNDLE_RAW_LOG_EXTENSIONS

# Generic artifact size limit (binaries, PCAPs, anything unclassified) — 2 GB
MAX_BUNDLE_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024

# Log uploads are bounded by size, never by count: analysts routinely bring
# dozens of perspectives (C2 operator logs, EVTX, router/firewall syslog) and
# capping the file count is what stops them correlating. 512 MB is already an
# enormous single text log, and the per-job aggregate in api/jobs.py is what
# actually protects the disk.
MAX_LOG_FILE_BYTES = 512 * 1024 * 1024


@router.post(
    "/uploads/bundle",
    status_code=status.HTTP_201_CREATED,
    response_model=UploadCreateResponse,
)
async def create_bundle_upload(
    request: Request,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Stream-save an uploaded log/C2/netflow bundle (archive or raw log file) to disk."""
    response.headers["X-Request-Id"] = request_id

    # Read filename from query param or Content-Disposition header
    filename = request.query_params.get("filename")
    if not filename:
        cd = request.headers.get("content-disposition", "")
        if 'filename="' in cd:
            filename = cd.split('filename="', 1)[1].rstrip('"')
        elif "filename=" in cd:
            filename = cd.split("filename=", 1)[1].strip().strip('"')
    if not filename:
        filename = f"{uuid.uuid4()}.zip"

    # Validate extension
    lower = filename.lower()
    if not any(lower.endswith(ext) for ext in _BUNDLE_EXTENSIONS):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported bundle format. Accepted: {', '.join(sorted(_BUNDLE_EXTENSIONS))}",
        )

    upload_id = str(uuid.uuid4())
    upload_dir: Path = settings.aipam_upload_root / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    dest = upload_dir / filename

    # Check Content-Length header early (advisory — can be absent or wrong)
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_LOG_FILE_BYTES:
        upload_dir.rmdir()
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Log file too large ({int(content_length):,} bytes). Max: {MAX_LOG_FILE_BYTES:,} bytes per file",
        )

    # Preflight disk-space check
    from backend.app.pipeline.preflight import check_disk_space
    preflight = check_disk_space(
        pcap_size_bytes=int(content_length) if content_length else MAX_LOG_FILE_BYTES,
        job_root=settings.aipam_upload_root,
        preflight_multiplier=settings.aipam_preflight_multiplier,
    )
    if not preflight.ok:
        upload_dir.rmdir()
        raise HTTPException(
            status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
            detail=preflight.message,
        )

    sha = hashlib.sha256()
    size = 0

    # Stream body to disk in 256 KB chunks — enforce size limit during streaming
    with open(dest, "wb") as f:
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_LOG_FILE_BYTES:
                f.close()
                dest.unlink(missing_ok=True)
                upload_dir.rmdir()
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Log file exceeds the {MAX_LOG_FILE_BYTES:,} byte per-file limit",
                )
            f.write(chunk)
            sha.update(chunk)

    # Guard: reject empty uploads
    if size == 0:
        dest.unlink(missing_ok=True)
        upload_dir.rmdir()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty upload body",
        )

    upload = Upload(
        upload_id=upload_id,
        filename=filename,
        size_bytes=size,
        sha256=sha.hexdigest(),
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    )
    db.add(upload)
    db.commit()
    db.refresh(upload)

    return UploadCreateResponse.model_validate(upload)



@router.post(
    "/uploads/artifact",
    status_code=status.HTTP_201_CREATED,
    response_model=ArtifactUploadResponse,
)
async def create_artifact_upload(
    request: Request,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Stream-save any artifact (pcap/log/binary/archive) and auto-classify it.

    Unlike /uploads (PCAP) and /uploads/bundle (logs/archives), this accepts
    any file type and records a detected ``artifact_class`` so the caller can
    route the job to the correct analysis pipeline.
    """
    response.headers["X-Request-Id"] = request_id

    filename = request.query_params.get("filename")
    if not filename:
        cd = request.headers.get("content-disposition", "")
        if 'filename="' in cd:
            filename = cd.split('filename="', 1)[1].rstrip('"')
        elif "filename=" in cd:
            filename = cd.split("filename=", 1)[1].strip().strip('"')
    if not filename:
        filename = str(uuid.uuid4())

    upload_id = str(uuid.uuid4())
    upload_dir: Path = settings.aipam_upload_root / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    dest = upload_dir / filename

    sha = hashlib.sha256()
    size = 0
    with open(dest, "wb") as f:
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_BUNDLE_UPLOAD_BYTES:
                f.close()
                dest.unlink(missing_ok=True)
                upload_dir.rmdir()
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Artifact exceeds {MAX_BUNDLE_UPLOAD_BYTES:,} byte limit",
                )
            f.write(chunk)
            sha.update(chunk)

    if size == 0:
        dest.unlink(missing_ok=True)
        upload_dir.rmdir()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty upload body",
        )

    classification = classify_artifact(dest, filename)

    upload = Upload(
        upload_id=upload_id,
        filename=filename,
        size_bytes=size,
        sha256=sha.hexdigest(),
        format=classification.format,
        artifact_class=classification.artifact_class,
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    )
    db.add(upload)
    db.commit()
    db.refresh(upload)

    return ArtifactUploadResponse(
        upload_id=upload.upload_id,
        filename=upload.filename,
        size_bytes=upload.size_bytes,
        sha256=upload.sha256,
        artifact_class=classification.artifact_class,
        format=classification.format,
    )


@router.post(
    "/uploads/{upload_id}/classify",
    response_model=ArtifactClassifyResponse,
)
async def classify_upload(
    upload_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Classify an already-uploaded artifact and persist its artifact_class."""
    response.headers["X-Request-Id"] = request_id

    upload: Upload | None = db.get(Upload, upload_id)
    if upload is None:
        raise HTTPException(status_code=404, detail="Upload not found")

    file_path = settings.aipam_upload_root / upload_id / upload.filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Upload file missing from disk")

    classification = classify_artifact(file_path, upload.filename)
    upload.artifact_class = classification.artifact_class
    if upload.format is None:
        upload.format = classification.format
    db.commit()

    return ArtifactClassifyResponse(
        upload_id=upload_id,
        artifact_class=classification.artifact_class,
        format=classification.format,
        detail=classification.detail,
    )
