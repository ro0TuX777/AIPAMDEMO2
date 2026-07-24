"""
Binary / YARA analysis endpoints (first-class binary analysis).

POST /jobs/{jobId}/binary    – upload a binary into the job, run hash/entropy/
                               format/YARA analysis, persist File + Findings
GET  /jobs/{jobId}/binary    – list persisted binary analyses for the job
POST /binary/inspect         – stateless: analyze an uploaded file, persist nothing
"""

from __future__ import annotations

import json
import logging
import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.binalysis import (
    BINARY_SENSOR,
    BinaryAnalysis,
    analyze_file,
    compile_yara_rules,
    default_rules_dir,
    persist_analysis,
    yara_available,
)
from backend.app.config_v2 import Settings, get_settings
from backend.app.models.file import File
from backend.app.models.job import Job
from backend.app.schemas.binary import (
    BinaryAnalysisItem,
    BinaryAnalysisListResponse,
    BinaryAnalysisResponse,
    BinaryInspectResponse,
    YaraMatchItem,
)

logger = logging.getLogger("aipam.binary")

router = APIRouter(tags=["Binary"], dependencies=[Depends(verify_token)])

MAX_BINARY_UPLOAD_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _filename_from_request(request: Request, default_ext: str = "") -> str:
    filename = request.query_params.get("filename")
    if not filename:
        cd = request.headers.get("content-disposition", "")
        if 'filename="' in cd:
            filename = cd.split('filename="', 1)[1].rstrip('"')
        elif "filename=" in cd:
            filename = cd.split("filename=", 1)[1].strip().strip('"')
    return filename or f"{uuid.uuid4()}{default_ext}"


async def _stream_to_disk(request: Request, dest: Path) -> int:
    """Stream the request body into ``dest``; return byte count. Enforces limit."""
    size = 0
    with open(dest, "wb") as f:
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_BINARY_UPLOAD_BYTES:
                f.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Binary exceeds {MAX_BINARY_UPLOAD_BYTES:,} byte limit",
                )
            f.write(chunk)
    return size


def _analysis_to_item(a: BinaryAnalysis, file_id: str) -> BinaryAnalysisItem:
    return BinaryAnalysisItem(
        file_id=file_id,
        filename=a.filename,
        size_bytes=a.size_bytes,
        sha256=a.sha256,
        md5=a.md5,
        sha1=a.sha1,
        entropy=a.entropy,
        format=a.format,
        artifact_class=a.artifact_class,
        yara_matches=[
            YaraMatchItem(rule=m.rule, tags=m.tags, meta=m.meta, strings=m.strings)
            for m in a.yara_matches
        ],
    )


def _file_to_item(f: File) -> BinaryAnalysisItem:
    matches: list[YaraMatchItem] = []
    if f.yara_matches_json:
        try:
            for m in json.loads(f.yara_matches_json):
                if isinstance(m, dict):
                    matches.append(YaraMatchItem(**m))
                elif isinstance(m, str):
                    matches.append(YaraMatchItem(rule=m))
        except (json.JSONDecodeError, TypeError):
            pass
    return BinaryAnalysisItem(
        file_id=f.file_id,
        filename=f.filename,
        size_bytes=f.size_bytes,
        sha256=f.sha256,
        md5=f.md5,
        entropy=f.entropy,
        format=f.mime,
        artifact_class=f.source,
        yara_matches=matches,
    )


@router.post("/jobs/{job_id}/binary", status_code=status.HTTP_201_CREATED,
             response_model=BinaryAnalysisResponse)
async def upload_and_analyze_binary(
    job_id: str,
    request: Request,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Stream-save an uploaded binary into the job and run full analysis."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    filename = _filename_from_request(request)
    input_dir = settings.aipam_job_root / job_id / "input"
    input_dir.mkdir(parents=True, exist_ok=True)
    dest = input_dir / filename
    size = await _stream_to_disk(request, dest)
    if size == 0:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty upload body")

    compiled = compile_yara_rules(default_rules_dir())
    analysis = analyze_file(dest, compiled, filename)
    file_row, created = persist_analysis(db, job_id, analysis, dest)

    return BinaryAnalysisResponse(
        yara_available=yara_available(),
        rules_compiled=compiled is not None,
        findings_created=created,
        analysis=_analysis_to_item(analysis, file_row.file_id),
    )


@router.get("/jobs/{job_id}/binary", response_model=BinaryAnalysisListResponse)
async def list_binary_analyses(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """List binary analyses persisted for this job."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    rows = db.scalars(
        select(File).where(File.job_id == job_id, File.source == BINARY_SENSOR)
    ).all()
    items = [_file_to_item(f) for f in rows]
    return BinaryAnalysisListResponse(items=items, total=len(items))


@router.post("/binary/inspect", response_model=BinaryInspectResponse)
async def inspect_binary(
    request: Request,
    response: Response,
    request_id: str = Depends(get_request_id),
):
    """Analyze an uploaded file without persisting anything (stateless triage)."""
    response.headers["X-Request-Id"] = request_id
    filename = _filename_from_request(request)

    with tempfile.TemporaryDirectory() as td:
        dest = Path(td) / filename
        size = await _stream_to_disk(request, dest)
        if size == 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty upload body")
        compiled = compile_yara_rules(default_rules_dir())
        analysis = analyze_file(dest, compiled, filename)
        return BinaryInspectResponse(
            yara_available=yara_available(),
            rules_compiled=compiled is not None,
            analysis=_analysis_to_item(analysis, analysis.sha256),
        )
