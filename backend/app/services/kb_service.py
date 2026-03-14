"""
Knowledge Base RAG service — chunking, embedding, storage, retrieval.

Uses ChromaDB for vector storage and Ollama's embedding API (mxbai-embed-large).
"""

from __future__ import annotations

import logging
import re
import uuid
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("aipam.kb")

# ── Chunking parameters ─────────────────────────────────────────────────
_CHUNK_SIZE = 512      # chars per chunk
_CHUNK_OVERLAP = 64    # overlap between consecutive chunks


def chunk_text(text: str, chunk_size: int = _CHUNK_SIZE, overlap: int = _CHUNK_OVERLAP) -> list[str]:
    """Split text into overlapping chunks for embedding."""
    text = text.strip()
    if not text:
        return []
    if len(text) <= chunk_size:
        return [text]

    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        if chunk.strip():
            chunks.append(chunk.strip())
        start += chunk_size - overlap
    return chunks


# ── Ollama Embedding Client ─────────────────────────────────────────────

async def get_embeddings(
    texts: list[str],
    ollama_url: str = "http://ollama:11434",
    model: str = "mxbai-embed-large",
) -> list[list[float]]:
    """Get embeddings from Ollama's embedding API.

    Uses the /api/embed endpoint (Ollama >= 0.4).
    Falls back to a simple hash-based embedding if Ollama is unavailable,
    so the system degrades gracefully.
    """
    embeddings: list[list[float]] = []
    async with httpx.AsyncClient(timeout=120.0) as client:
        for text in texts:
            try:
                resp = await client.post(
                    f"{ollama_url}/api/embed",
                    json={"model": model, "input": text},
                )
                resp.raise_for_status()
                data = resp.json()
                # /api/embed returns {"embeddings": [[...], ...]}
                emb_list = data.get("embeddings", [])
                if emb_list and len(emb_list[0]) > 0:
                    embeddings.append(emb_list[0])
                else:
                    logger.warning("Empty embedding returned for chunk")
                    embeddings.append(_fallback_embedding(text))
            except Exception as exc:
                logger.warning("Ollama embedding failed, using fallback: %s", exc)
                embeddings.append(_fallback_embedding(text))
    return embeddings


def _fallback_embedding(text: str, dim: int = 1024) -> list[float]:
    """Deterministic hash-based embedding for fallback (low quality but functional)."""
    import hashlib
    h = hashlib.sha256(text.encode()).digest()
    # Expand hash to fill dimension
    result = []
    for i in range(dim):
        byte_val = h[i % len(h)]
        result.append((byte_val / 255.0) - 0.5)  # normalize to [-0.5, 0.5]
    return result


# ── ChromaDB Vector Store ────────────────────────────────────────────────

_chroma_client = None
_collection = None
_COLLECTION_NAME = "aipam_knowledge_base"


def _get_collection(persist_dir: str | Path | None = None):
    """Get or create the ChromaDB collection (lazy singleton)."""
    global _chroma_client, _collection
    if _collection is not None:
        return _collection

    import chromadb

    if persist_dir:
        persist_dir = str(persist_dir)
        _chroma_client = chromadb.PersistentClient(path=persist_dir)
    else:
        _chroma_client = chromadb.Client()  # in-memory fallback

    _collection = _chroma_client.get_or_create_collection(
        name=_COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )
    logger.info("ChromaDB collection '%s' ready (%d items)", _COLLECTION_NAME, _collection.count())
    return _collection


def reset_collection() -> None:
    """Reset the singleton collection (for testing)."""
    global _chroma_client, _collection
    _chroma_client = None
    _collection = None


async def index_document(
    doc_id: str,
    content: str,
    doc_name: str,
    doc_type: str,
    job_id: str = "",
    ollama_url: str = "http://ollama:11434",
    embedding_model: str = "mxbai-embed-large",
    persist_dir: str | Path | None = None,
) -> int:
    """Chunk a document, embed it, and store in ChromaDB.

    Returns the number of chunks indexed.
    """
    chunks = chunk_text(content)
    if not chunks:
        return 0

    embeddings = await get_embeddings(chunks, ollama_url=ollama_url, model=embedding_model)

    collection = _get_collection(persist_dir)

    ids = [f"{doc_id}_chunk_{i}" for i in range(len(chunks))]
    metadatas = [
        {
            "doc_id": doc_id,
            "doc_name": doc_name,
            "doc_type": doc_type,
            "job_id": job_id,
            "chunk_index": i,
        }
        for i in range(len(chunks))
    ]

    try:
        collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=chunks,
            metadatas=metadatas,
        )
    except Exception as exc:
        # Handle dimension mismatch (e.g. switching from 768-dim fallback to 1024-dim real embeddings)
        if "dimensionality" in str(exc).lower() or "dimension" in str(exc).lower():
            logger.warning("Embedding dimension mismatch — recreating ChromaDB collection: %s", exc)
            global _collection
            if _chroma_client:
                _chroma_client.delete_collection(_COLLECTION_NAME)
            _collection = None
            collection = _get_collection(persist_dir)
            collection.upsert(
                ids=ids,
                embeddings=embeddings,
                documents=chunks,
                metadatas=metadatas,
            )
        else:
            raise

    logger.info("Indexed %d chunks for document %s (%s) job=%s", len(chunks), doc_name, doc_id, job_id)
    return len(chunks)


async def retrieve(
    query: str,
    n_results: int = 5,
    doc_type_filter: str | None = None,
    job_id: str | None = None,
    ollama_url: str = "http://ollama:11434",
    embedding_model: str = "mxbai-embed-large",
    persist_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Retrieve the most relevant KB chunks for a query.

    If job_id is provided, only chunks belonging to that job are returned.
    Returns a list of dicts with keys: text, doc_name, doc_type, score, doc_id.
    """
    collection = _get_collection(persist_dir)
    if collection.count() == 0:
        return []

    query_embedding = await get_embeddings([query], ollama_url=ollama_url, model=embedding_model)
    if not query_embedding:
        return []

    # Build where filter combining job_id and optional doc_type
    where_clauses: list[dict] = []
    if job_id:
        where_clauses.append({"job_id": job_id})
    if doc_type_filter:
        where_clauses.append({"doc_type": doc_type_filter})

    where_filter = None
    if len(where_clauses) == 1:
        where_filter = where_clauses[0]
    elif len(where_clauses) > 1:
        where_filter = {"$and": where_clauses}

    results = collection.query(
        query_embeddings=query_embedding,
        n_results=min(n_results, collection.count()),
        where=where_filter,
        include=["documents", "metadatas", "distances"],
    )

    items: list[dict[str, Any]] = []
    if results and results["documents"]:
        for i, doc in enumerate(results["documents"][0]):
            meta = results["metadatas"][0][i] if results["metadatas"] else {}
            distance = results["distances"][0][i] if results["distances"] else 1.0
            # ChromaDB cosine distance: 0 = identical, 2 = opposite
            # Convert to similarity score: 1 - (distance / 2)
            score = 1.0 - (distance / 2.0)
            items.append({
                "text": doc,
                "doc_name": meta.get("doc_name", ""),
                "doc_type": meta.get("doc_type", ""),
                "doc_id": meta.get("doc_id", ""),
                "score": round(score, 4),
            })

    return items


async def delete_document(
    doc_id: str,
    persist_dir: str | Path | None = None,
) -> int:
    """Delete all chunks for a document from ChromaDB.

    Returns the number of chunks deleted.
    """
    collection = _get_collection(persist_dir)

    # Find all chunks for this document
    try:
        existing = collection.get(
            where={"doc_id": doc_id},
            include=[],
        )
        chunk_ids = existing["ids"] if existing else []
    except Exception:
        chunk_ids = []

    if chunk_ids:
        collection.delete(ids=chunk_ids)
        logger.info("Deleted %d chunks for document %s", len(chunk_ids), doc_id)

    return len(chunk_ids)


def extract_ips_from_context(context_json: str) -> list[str]:
    """Extract unique IP addresses from the PCAP context JSON for RAG queries."""
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    ips = set(ip_pattern.findall(context_json))
    # Filter out obvious non-routable/broadcast
    filtered = {ip for ip in ips if not ip.startswith("0.") and ip != "255.255.255.255"}
    return sorted(filtered)


# ── Auto-indexing of pipeline outputs ────────────────────────────────────

def _format_host_summary(host) -> str:
    """Format a Host DB record into a rich text summary for vector indexing."""
    import json as _json

    parts = [
        f"Host: {host.ip}",
        f"Role: {host.role or 'unknown'}",
        f"Active: {host.first_seen or '?'} – {host.last_seen or '?'}",
        f"Connections: {host.conn_count or 0}",
        f"Bytes sent: {host.bytes_sent or 0}, received: {host.bytes_recv or 0}",
        f"Alerts: {host.alert_count or 0}, Findings: {host.finding_count or 0}",
        f"DNS queries: {host.dns_query_count or 0}",
    ]
    if host.top_services_json:
        try:
            svcs = _json.loads(host.top_services_json)
            if svcs:
                parts.append(f"Services: {', '.join(svcs[:8])}")
        except Exception:
            pass
    if host.alerts_by_severity_json:
        try:
            sev = _json.loads(host.alerts_by_severity_json)
            if sev:
                parts.append(f"Alert severity breakdown: {sev}")
        except Exception:
            pass
    if host.top_domains_json:
        try:
            doms = _json.loads(host.top_domains_json)
            if doms:
                parts.append(f"Top domains: {', '.join(doms[:10])}")
        except Exception:
            pass
    return "\n".join(parts)


def _format_alert_summary(alert) -> str:
    """Format an Alert DB record into text for vector indexing."""
    parts = [
        f"Alert: {alert.signature}",
        f"Severity: {alert.severity}",
        f"Source: {alert.src_ip}:{alert.src_port or '?'} → Dest: {alert.dest_ip}:{alert.dest_port or '?'}",
        f"Protocol: {alert.proto or '?'}",
        f"Time: {alert.ts}",
    ]
    if alert.category:
        parts.append(f"Category: {alert.category}")
    return "\n".join(parts)


def _format_finding_summary(finding) -> str:
    """Format a Finding DB record into text for vector indexing."""
    conf = getattr(finding, "confidence", 0.0) or 0.0
    conf_label = "high" if conf >= 0.7 else "medium" if conf >= 0.4 else "low"
    parts = [
        f"Finding: {finding.title}",
        f"Severity: {finding.severity}",
        f"Confidence: {round(conf * 100)}% ({conf_label})",
        f"Sensor: {finding.sensor}",
    ]
    if finding.category:
        parts.append(f"Category: {finding.category}")
    if finding.summary:
        parts.append(f"Summary: {finding.summary[:500]}")
    return "\n".join(parts)


async def auto_index_job(
    db_session,
    job_id: str,
    ollama_url: str = "http://ollama:11434",
    persist_dir: str | Path | None = None,
    embedding_model: str = "mxbai-embed-large",
) -> dict[str, int]:
    """Auto-index all pipeline outputs for a job into the vector store.

    Indexes host profiles, alerts, and findings so that RAG retrieval
    can find them when an analyst asks questions about this job.

    Returns a dict with counts: {hosts, alerts, findings, total_chunks}.
    """
    from sqlalchemy import select

    from backend.app.models.alert import Alert
    from backend.app.models.finding import Finding
    from backend.app.models.host import Host

    counts = {"hosts": 0, "alerts": 0, "findings": 0, "total_chunks": 0}

    # ── Index host profiles ──────────────────────────────────────────
    hosts = db_session.execute(
        select(Host).where(Host.job_id == job_id)
        .order_by(Host.alert_count.desc(), Host.conn_count.desc())
    ).scalars().all()

    for host in hosts:
        content = _format_host_summary(host)
        doc_id = f"job_{job_id}_host_{host.ip}"
        n = await index_document(
            doc_id=doc_id,
            content=content,
            doc_name=f"Host {host.ip}",
            doc_type="host_profile",
            job_id=job_id,
            ollama_url=ollama_url,
            embedding_model=embedding_model,
            persist_dir=persist_dir,
        )
        counts["hosts"] += 1
        counts["total_chunks"] += n

    # ── Index alerts (high/medium severity prioritized) ──────────────
    alerts = db_session.execute(
        select(Alert).where(Alert.job_id == job_id)
        .order_by(Alert.severity.asc())  # 1=high first
        .limit(100)
    ).scalars().all()

    # Group alerts by signature to avoid redundant embeddings
    sig_groups: dict[str, list] = {}
    for alert in alerts:
        sig = alert.signature or "unknown"
        sig_groups.setdefault(sig, []).append(alert)

    for sig, group in sig_groups.items():
        # Combine alerts with the same signature into one document
        parts = [f"Alert signature: {sig} (×{len(group)})"]
        for a in group[:5]:  # max 5 examples per signature
            parts.append(_format_alert_summary(a))
        content = "\n---\n".join(parts)
        doc_id = f"job_{job_id}_alert_{uuid.uuid4().hex[:12]}"
        n = await index_document(
            doc_id=doc_id,
            content=content,
            doc_name=f"Alert: {sig[:80]}",
            doc_type="alert",
            job_id=job_id,
            ollama_url=ollama_url,
            embedding_model=embedding_model,
            persist_dir=persist_dir,
        )
        counts["alerts"] += len(group)
        counts["total_chunks"] += n

    # ── Index findings ───────────────────────────────────────────────
    findings = db_session.execute(
        select(Finding).where(Finding.job_id == job_id)
    ).scalars().all()

    for finding in findings:
        content = _format_finding_summary(finding)
        doc_id = f"job_{job_id}_finding_{finding.finding_id}"
        n = await index_document(
            doc_id=doc_id,
            content=content,
            doc_name=f"Finding: {finding.title[:80]}",
            doc_type="finding",
            job_id=job_id,
            ollama_url=ollama_url,
            embedding_model=embedding_model,
            persist_dir=persist_dir,
        )
        counts["findings"] += 1
        counts["total_chunks"] += n

    logger.info(
        "Auto-indexed job %s: %d hosts, %d alerts, %d findings → %d chunks",
        job_id, counts["hosts"], counts["alerts"], counts["findings"], counts["total_chunks"],
    )
    return counts

