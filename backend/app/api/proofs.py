"""
Proof Builder API endpoints.

POST   /jobs/{jobId}/proofs                       – create a proof
GET    /jobs/{jobId}/proofs                       – list proofs for a job
GET    /jobs/{jobId}/proofs/{proofId}             – get a single proof
PATCH  /jobs/{jobId}/proofs/{proofId}             – update proof metadata
DELETE /jobs/{jobId}/proofs/{proofId}             – delete a proof

POST   /jobs/{jobId}/proofs/{proofId}/items       – add an item
GET    /jobs/{jobId}/proofs/{proofId}/items       – list items
PATCH  /jobs/{jobId}/proofs/{proofId}/items/{itemId} – update item
DELETE /jobs/{jobId}/proofs/{proofId}/items/{itemId} – remove item

POST   /jobs/{jobId}/proofs/{proofId}/narrative   – render narrative
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.models.job import Job
from backend.app.schemas.proof import (
    ProofCreate,
    ProofDetailResponse,
    ProofExportResponse,
    ProofItemCreate,
    ProofItemDetailResponse,
    ProofItemListResponse,
    ProofItemOut,
    ProofItemUpdate,
    ProofListResponse,
    ProofNarrativeResponse,
    ProofOut,
    ProofUpdate,
)
from backend.app.services.proof_builder import (
    add_item,
    create_proof,
    delete_proof,
    export_proof,
    get_proof,
    list_items,
    list_proofs,
    remove_item,
    render_narrative,
    update_item,
    update_proof,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Proofs"], dependencies=[Depends(verify_token)])


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _require_proof(db: Session, proof_id: str):
    proof = get_proof(db, proof_id)
    if not proof:
        raise HTTPException(status_code=404, detail="Proof not found")
    return proof


# ── Proof CRUD ────────────────────────────────────────────────────────────


@router.post("/jobs/{job_id}/proofs", response_model=ProofDetailResponse, status_code=201)
async def create_proof_endpoint(
    job_id: str, body: ProofCreate, response: Response,
    request_id: str = Depends(get_request_id), db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    proof = create_proof(db, job_id, title=body.title, conclusion=body.conclusion,
                         severity=body.severity, confidence=body.confidence,
                         mode=body.mode)
    return ProofDetailResponse(item=ProofOut.model_validate(proof), job_id=job_id)


@router.get("/jobs/{job_id}/proofs", response_model=ProofListResponse)
async def list_proofs_endpoint(
    job_id: str, response: Response,
    request_id: str = Depends(get_request_id), db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    proofs = list_proofs(db, job_id)
    return ProofListResponse(items=[ProofOut.model_validate(p) for p in proofs], job_id=job_id)


@router.get("/jobs/{job_id}/proofs/{proof_id}", response_model=ProofDetailResponse)
async def get_proof_endpoint(
    job_id: str, proof_id: str, response: Response,
    request_id: str = Depends(get_request_id), db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    proof = _require_proof(db, proof_id)
    return ProofDetailResponse(item=ProofOut.model_validate(proof), job_id=job_id)


@router.patch("/jobs/{job_id}/proofs/{proof_id}", response_model=ProofDetailResponse)
async def update_proof_endpoint(
    job_id: str, proof_id: str, body: ProofUpdate, response: Response,
    request_id: str = Depends(get_request_id), db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    _require_proof(db, proof_id)
    proof = update_proof(db, proof_id, **body.model_dump(exclude_none=True))
    return ProofDetailResponse(item=ProofOut.model_validate(proof), job_id=job_id)


@router.delete("/jobs/{job_id}/proofs/{proof_id}", status_code=204)
async def delete_proof_endpoint(
    job_id: str, proof_id: str, response: Response,
    request_id: str = Depends(get_request_id), db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    _require_proof(db, proof_id)
    delete_proof(db, proof_id)


# ── Item CRUD ─────────────────────────────────────────────────────────────


@router.post("/jobs/{job_id}/proofs/{proof_id}/items",
             response_model=ProofItemDetailResponse, status_code=201)
async def add_item_endpoint(
    job_id: str, proof_id: str, body: ProofItemCreate, response: Response,
    request_id: str = Depends(get_request_id), db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    _require_proof(db, proof_id)
    try:
        item = add_item(db, proof_id, entity_type=body.entity_type,
                        entity_id=body.entity_id, role=body.role,
                        analyst_note=body.analyst_note)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ProofItemDetailResponse(item=ProofItemOut.model_validate(item), proof_id=proof_id)


@router.get("/jobs/{job_id}/proofs/{proof_id}/items",
            response_model=ProofItemListResponse)
async def list_items_endpoint(
    job_id: str, proof_id: str, response: Response,
    request_id: str = Depends(get_request_id), db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    _require_proof(db, proof_id)
    items = list_items(db, proof_id)
    return ProofItemListResponse(
        items=[ProofItemOut.model_validate(i) for i in items], proof_id=proof_id)


@router.patch("/jobs/{job_id}/proofs/{proof_id}/items/{item_id}",
              response_model=ProofItemDetailResponse)
async def update_item_endpoint(
    job_id: str, proof_id: str, item_id: str, body: ProofItemUpdate,
    response: Response,
    request_id: str = Depends(get_request_id), db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    _require_proof(db, proof_id)
    try:
        item = update_item(db, item_id, **body.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return ProofItemDetailResponse(item=ProofItemOut.model_validate(item), proof_id=proof_id)


@router.delete("/jobs/{job_id}/proofs/{proof_id}/items/{item_id}", status_code=204)
async def remove_item_endpoint(
    job_id: str, proof_id: str, item_id: str, response: Response,
    request_id: str = Depends(get_request_id), db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    _require_proof(db, proof_id)
    try:
        remove_item(db, item_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ── Narrative ─────────────────────────────────────────────────────────────


@router.post("/jobs/{job_id}/proofs/{proof_id}/narrative",
             response_model=ProofNarrativeResponse)
async def render_narrative_endpoint(
    job_id: str, proof_id: str, response: Response,
    request_id: str = Depends(get_request_id), db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    _require_proof(db, proof_id)
    result = render_narrative(db, proof_id)
    return ProofNarrativeResponse(
        proof_id=proof_id,
        narrative_markdown=result["narrative"],
        warnings=result.get("warnings", []),
    )


# ── Export ───────────────────────────────────────────────────────────────


@router.get("/jobs/{job_id}/proofs/{proof_id}/export",
            response_model=ProofExportResponse)
async def export_proof_endpoint(
    job_id: str, proof_id: str, response: Response,
    fmt: str = "markdown",
    request_id: str = Depends(get_request_id), db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    _require_proof(db, proof_id)
    result = export_proof(db, proof_id, fmt=fmt)
    return ProofExportResponse(
        content=result["content"],
        filename=result["filename"],
    )
