"""
Knowledge Base RAG service — chunking, embedding, storage, retrieval.

Uses ChromaDB for vector storage and Ollama's embedding API (nomic-embed-text).
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
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
    model: str = "nomic-embed-text",
) -> list[list[float]]:
    """Get embeddings from Ollama's embedding API.

    Falls back to a simple hash-based embedding if Ollama is unavailable,
    so the system degrades gracefully.
    """
    embeddings: list[list[float]] = []
    async with httpx.AsyncClient(timeout=120.0) as client:
        for text in texts:
            try:
                resp = await client.post(
                    f"{ollama_url}/api/embeddings",
                    json={"model": model, "prompt": text},
                )
                resp.raise_for_status()
                data = resp.json()
                embedding = data.get("embedding", [])
                if embedding:
                    embeddings.append(embedding)
                else:
                    logger.warning("Empty embedding returned for chunk")
                    embeddings.append(_fallback_embedding(text))
            except Exception as exc:
                logger.warning("Ollama embedding failed, using fallback: %s", exc)
                embeddings.append(_fallback_embedding(text))
    return embeddings


def _fallback_embedding(text: str, dim: int = 768) -> list[float]:
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
    embedding_model: str = "nomic-embed-text",
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

    collection.upsert(
        ids=ids,
        embeddings=embeddings,
        documents=chunks,
        metadatas=metadatas,
    )

    logger.info("Indexed %d chunks for document %s (%s) job=%s", len(chunks), doc_name, doc_id, job_id)
    return len(chunks)


async def retrieve(
    query: str,
    n_results: int = 5,
    doc_type_filter: str | None = None,
    job_id: str | None = None,
    ollama_url: str = "http://ollama:11434",
    embedding_model: str = "nomic-embed-text",
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

