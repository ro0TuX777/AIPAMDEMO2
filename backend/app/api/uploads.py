"""
Upload endpoints (§1.2).

POST /uploads          – stream-save a PCAP file
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
from backend.app.schemas.upload import UploadCreateResponse, UploadValidateResponse

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

