"""
Theory of the Case API endpoints.

GET  /jobs/{jobId}/theories              – list job-level theories
GET  /jobs/{jobId}/hosts/{ip}/theories   – list host-level theories
POST /jobs/{jobId}/theories/generate     – trigger theory generation
"""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.models.theory import Theory
from backend.app.schemas.theory import EvidenceRef, TheoryItem, TheoryListResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Theories"], dependencies=[Depends(verify_token)])


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _resolve_evidence_ids(db: Session, job_id: str, ids: list[str]) -> list[EvidenceRef]:
    """Resolve a list of evidence IDs into labelled EvidenceRef objects."""
    if not ids:
        return []

    # Batch-lookup all three entity types for this job
    alerts = {a.alert_id: a for a in db.execute(
        select(Alert).where(Alert.job_id == job_id, Alert.alert_id.in_(ids))
    ).scalars().all()}
    findings = {f.finding_id: f for f in db.execute(
        select(Finding).where(Finding.job_id == job_id, Finding.finding_id.in_(ids))
    ).scalars().all()}
    iocs = {i.ioc_id: i for i in db.execute(
        select(Ioc).where(Ioc.job_id == job_id, Ioc.ioc_id.in_(ids))
    ).scalars().all()}

    refs: list[EvidenceRef] = []
    for eid in ids:
        if eid in alerts:
            refs.append(EvidenceRef(id=eid, type="alert", label=alerts[eid].signature))
        elif eid in findings:
            refs.append(EvidenceRef(id=eid, type="finding", label=findings[eid].title))
        elif eid in iocs:
            ioc = iocs[eid]
            refs.append(EvidenceRef(id=eid, type="ioc", label=f"{ioc.ioc_type}: {ioc.value}"))
        else:
            refs.append(EvidenceRef(id=eid, type="unknown", label=eid))
    return refs


def _theory_to_item(t: Theory, db: Session) -> TheoryItem:
    """Convert a Theory ORM object to a TheoryItem schema with resolved evidence labels."""
    supporting_ids: list[str] = []
    if t.supporting_evidence_json:
        try:
            supporting_ids = json.loads(t.supporting_evidence_json)
        except Exception:
            pass
    contradicting_ids: list[str] = []
    if t.contradicting_evidence_json:
        try:
            contradicting_ids = json.loads(t.contradicting_evidence_json)
        except Exception:
            pass
    next_steps: list[str] = []
    if t.next_steps_json:
        try:
            next_steps = json.loads(t.next_steps_json)
        except Exception:
            pass

    return TheoryItem(
        theory_id=t.theory_id,
        scope_type=t.scope_type,
        scope_id=t.scope_id,
        label=t.label,
        hypothesis_type=t.hypothesis_type,
        score=t.score,
        confidence=t.confidence,
        rank=t.rank,
        supporting_evidence=_resolve_evidence_ids(db, t.job_id, supporting_ids),
        contradicting_evidence=_resolve_evidence_ids(db, t.job_id, contradicting_ids),
        explanation=t.explanation,
        next_steps=next_steps,
        created_at=t.created_at,
    )


@router.get("/jobs/{job_id}/theories", response_model=TheoryListResponse)
async def list_job_theories(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """List job-level theories (ranked hypotheses)."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    theories = db.execute(
        select(Theory)
        .where(Theory.job_id == job_id, Theory.scope_type == "job")
        .order_by(Theory.rank.asc())
    ).scalars().all()

    return TheoryListResponse(
        items=[_theory_to_item(t, db) for t in theories],
        job_id=job_id,
        scope_type="job",
    )


@router.get("/jobs/{job_id}/hosts/{ip}/theories", response_model=TheoryListResponse)
async def list_host_theories(
    job_id: str,
    ip: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """List host-level theories for a specific IP."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    theories = db.execute(
        select(Theory)
        .where(Theory.job_id == job_id, Theory.scope_type == "host", Theory.scope_id == ip)
        .order_by(Theory.rank.asc())
    ).scalars().all()

    return TheoryListResponse(
        items=[_theory_to_item(t, db) for t in theories],
        job_id=job_id,
        scope_type="host",
        scope_id=ip,
    )


@router.post("/jobs/{job_id}/theories/generate", response_model=TheoryListResponse)
async def generate_theories_endpoint(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Manually trigger theory generation for a job (re-generates all)."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    from backend.app.services.theory_engine import generate_all_theories

    counts = generate_all_theories(db, job_id)
    logger.info("Generated theories for job %s: %s", job_id, counts)

    # Return job-level theories
    theories = db.execute(
        select(Theory)
        .where(Theory.job_id == job_id, Theory.scope_type == "job")
        .order_by(Theory.rank.asc())
    ).scalars().all()

    return TheoryListResponse(
        items=[_theory_to_item(t, db) for t in theories],
        job_id=job_id,
        scope_type="job",
    )

