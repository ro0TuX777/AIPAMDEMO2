"""
Knowledge Base API endpoints for RAG — per-job scoped.

POST   /jobs/{job_id}/kb/documents          — upload a new KB document for a job
GET    /jobs/{job_id}/kb/documents          — list KB documents for a job
GET    /jobs/{job_id}/kb/documents/{doc_id} — get document detail (with content)
DELETE /jobs/{job_id}/kb/documents/{doc_id} — delete a document and its embeddings
POST   /jobs/{job_id}/kb/search             — search job's KB by query text
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, verify_token
from backend.app.config_v2 import Settings, get_settings
from backend.app.models.job import Job
from backend.app.models.knowledge_base import KBDocument
from backend.app.schemas.knowledge_base import (
    KBDocumentCreate,
    KBDocumentDetail,
    KBDocumentListOut,
    KBDocumentOut,
)
from backend.app.services.kb_service import (
    delete_document as kb_delete_document,
    index_document as kb_index_document,
    retrieve as kb_retrieve,
)

logger = logging.getLogger("aipam.api.kb")

router = APIRouter(dependencies=[Depends(verify_token)], tags=["knowledge-base"])


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _require_job(db: Session, job_id: str) -> Job:
    """Validate the job exists, raise 404 otherwise."""
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


@router.post("/jobs/{job_id}/kb/documents", response_model=KBDocumentOut, status_code=201)
async def create_document(
    job_id: str,
    body: KBDocumentCreate,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Upload and index a new knowledge base document for a job."""
    _require_job(db, job_id)
    doc_id = str(uuid.uuid4())
    now = _now_iso()

    doc = KBDocument(
        id=doc_id,
        job_id=job_id,
        name=body.name,
        doc_type=body.doc_type,
        description=body.description,
        content=body.content,
        status="pending",
        created_at=now,
        updated_at=now,
    )
    db.add(doc)
    db.commit()

    # Index: embed + store in ChromaDB with job_id metadata
    try:
        ollama_url = settings.aipam_ollama_url.rstrip("/")
        chunk_count = await kb_index_document(
            doc_id=doc_id,
            content=body.content,
            doc_name=body.name,
            doc_type=body.doc_type,
            job_id=job_id,
            ollama_url=ollama_url,
            embedding_model="nomic-embed-text",
            persist_dir=str(settings.aipam_db_path).replace("aipam.db", "vector_store"),
        )
        doc.chunk_count = chunk_count
        doc.status = "indexed"
        doc.updated_at = _now_iso()
    except Exception as exc:
        logger.exception("Failed to index KB document %s", doc_id)
        doc.status = "error"
        doc.error_message = str(exc)[:500]
        doc.updated_at = _now_iso()

    db.commit()
    db.refresh(doc)
    return KBDocumentOut.model_validate(doc)


@router.get("/jobs/{job_id}/kb/documents", response_model=KBDocumentListOut)
async def list_documents(
    job_id: str,
    doc_type: str | None = None,
    db: Session = Depends(get_db),
):
    """List knowledge base documents for a specific job."""
    _require_job(db, job_id)
    query = select(KBDocument).where(KBDocument.job_id == job_id).order_by(KBDocument.created_at.desc())
    if doc_type:
        query = query.where(KBDocument.doc_type == doc_type)

    docs = db.execute(query).scalars().all()
    return KBDocumentListOut(
        items=[KBDocumentOut.model_validate(d) for d in docs],
        total=len(docs),
    )


@router.get("/jobs/{job_id}/kb/documents/{doc_id}", response_model=KBDocumentDetail)
async def get_document(
    job_id: str,
    doc_id: str,
    db: Session = Depends(get_db),
):
    """Get a knowledge base document with full content."""
    _require_job(db, job_id)
    doc = db.get(KBDocument, doc_id)
    if not doc or doc.job_id != job_id:
        raise HTTPException(status_code=404, detail="Document not found")
    return KBDocumentDetail.model_validate(doc)


@router.delete("/jobs/{job_id}/kb/documents/{doc_id}", status_code=204)
async def delete_document(
    job_id: str,
    doc_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Delete a knowledge base document and its vector embeddings."""
    _require_job(db, job_id)
    doc = db.get(KBDocument, doc_id)
    if not doc or doc.job_id != job_id:
        raise HTTPException(status_code=404, detail="Document not found")

    # Delete from ChromaDB
    try:
        persist_dir = str(settings.aipam_db_path).replace("aipam.db", "vector_store")
        await kb_delete_document(doc_id=doc_id, persist_dir=persist_dir)
    except Exception as exc:
        logger.warning("Failed to delete KB embeddings for %s: %s", doc_id, exc)

    db.delete(doc)
    db.commit()
    return None


class KBSearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000)
    n_results: int = Field(default=5, ge=1, le=20)
    doc_type: str | None = None


class KBSearchResult(BaseModel):
    text: str
    doc_name: str
    doc_type: str
    doc_id: str
    score: float


class KBSearchResponse(BaseModel):
    results: list[KBSearchResult]
    query: str


@router.post("/jobs/{job_id}/kb/search", response_model=KBSearchResponse)
async def search_kb(
    job_id: str,
    body: KBSearchRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Search a job's knowledge base by semantic similarity."""
    _require_job(db, job_id)
    ollama_url = settings.aipam_ollama_url.rstrip("/")
    persist_dir = str(settings.aipam_db_path).replace("aipam.db", "vector_store")

    results = await kb_retrieve(
        query=body.query,
        n_results=body.n_results,
        doc_type_filter=body.doc_type,
        job_id=job_id,
        ollama_url=ollama_url,
        embedding_model="nomic-embed-text",
        persist_dir=persist_dir,
    )

    return KBSearchResponse(
        results=[KBSearchResult(**r) for r in results],
        query=body.query,
    )