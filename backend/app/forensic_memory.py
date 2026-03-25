"""Forensic Memory — Global cross-job vector memory via ChromaDB.

Provides semantic search across all confirmed findings from all
completed cases.  Used by the Chat service to give the L1 Generalist
"experience recall" — the ability to reference similar malware,
techniques, and IOCs from previous investigations.

Designed to coexist with the per-job LanceDB RAG in ``rag_index.py``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Lazy-loaded globals
_chroma_client = None
_collection = None

DEFAULT_CHROMADB_PATH = os.path.expanduser("~/.aipam/forensic_memory")
DEFAULT_COLLECTION = "aipam_forensic_findings"


# ── ChromaDB Lifecycle ─────────────────────────────────────────────────

def get_memory_collection(
    db_path: Optional[str] = None,
    collection_name: Optional[str] = None,
):
    """Lazy-init the global ChromaDB collection.

    Returns the collection object, or None if ChromaDB is unavailable.
    """
    global _chroma_client, _collection

    if _collection is not None:
        return _collection

    try:
        import chromadb
    except ImportError:
        logger.warning("chromadb not installed — forensic memory disabled")
        return None

    path = db_path or DEFAULT_CHROMADB_PATH
    name = collection_name or DEFAULT_COLLECTION

    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        _chroma_client = chromadb.PersistentClient(path=path)
        _collection = _chroma_client.get_or_create_collection(
            name=name,
            metadata={"description": "AIPAM confirmed forensic findings"},
        )
        logger.info("Forensic memory collection initialized: %s (%d docs)", name,
                     _collection.count())
        return _collection
    except Exception as exc:
        logger.error("Failed to initialize forensic memory: %s", exc)
        return None


def store_findings(
    job_id: str,
    project_id: str,
    findings: List[Dict[str, Any]],
    embeddings: Optional[List[List[float]]] = None,
) -> int:
    """Index confirmed findings into the global memory.

    Args:
        job_id: Source job ID
        project_id: Source project ID
        findings: List of confirmed finding dicts
        embeddings: Optional pre-computed embeddings

    Returns:
        Number of findings indexed
    """
    collection = get_memory_collection()
    if collection is None:
        return 0

    # HITL gate: only index findings with analyst_status == "confirmed"
    confirmed_findings = [
        f for f in findings
        if f.get("analyst_status") == "confirmed"
    ]
    if not confirmed_findings and findings:
        logger.info(
            "Forensic memory: %d findings skipped (none confirmed by analyst)",
            len(findings),
        )

    indexed = 0
    for i, finding in enumerate(confirmed_findings):
        doc_text = _finding_to_text(finding)
        doc_id = f"{job_id}-{i}"
        metadata = {
            "job_id": job_id,
            "project_id": project_id,
            "mitre_technique_id": finding.get("mitre_technique_id", ""),
            "severity": finding.get("severity", ""),
            "confidence_score": float(finding.get("confidence_score", 0)),
            "classification": finding.get("classification", ""),
        }

        try:
            kwargs: Dict[str, Any] = {
                "ids": [doc_id],
                "documents": [doc_text],
                "metadatas": [metadata],
            }
            if embeddings and i < len(embeddings):
                kwargs["embeddings"] = [embeddings[i]]

            collection.upsert(**kwargs)
            indexed += 1
        except Exception as exc:
            logger.warning("Failed to index finding %s: %s", doc_id, exc)

    return indexed


def query_memory(
    query: str,
    top_k: int = 5,
    where_filter: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Semantic search across all cases in forensic memory.

    Args:
        query: Natural language query
        top_k: Max results
        where_filter: Optional ChromaDB where clause

    Returns:
        List of dicts with keys: document, metadata, distance
    """
    collection = get_memory_collection()
    if collection is None:
        return []

    if collection.count() == 0:
        return []

    try:
        kwargs: Dict[str, Any] = {
            "query_texts": [query],
            "n_results": min(top_k, collection.count()),
        }
        if where_filter:
            kwargs["where"] = where_filter

        results = collection.query(**kwargs)

        hits = []
        if results and results.get("documents"):
            docs = results["documents"][0]
            metas = results.get("metadatas", [[]])[0]
            distances = results.get("distances", [[]])[0]

            for j, doc in enumerate(docs):
                hits.append({
                    "document": doc,
                    "metadata": metas[j] if j < len(metas) else {},
                    "distance": distances[j] if j < len(distances) else 1.0,
                    "relevance": max(0, 1.0 - (distances[j] if j < len(distances) else 1.0)),
                })

        return hits
    except Exception as exc:
        logger.error("Forensic memory query failed: %s", exc)
        return []


def get_memory_stats() -> Dict[str, Any]:
    """Return stats about the forensic memory store."""
    collection = get_memory_collection()
    if collection is None:
        return {"available": False, "count": 0}

    return {
        "available": True,
        "count": collection.count(),
        "collection_name": DEFAULT_COLLECTION,
        "path": DEFAULT_CHROMADB_PATH,
    }


# ── Internal Helpers ───────────────────────────────────────────────────

def _finding_to_text(finding: Dict[str, Any]) -> str:
    """Convert a finding dict to indexable text."""
    parts = []
    if finding.get("mitre_technique_id"):
        parts.append(f"MITRE: {finding['mitre_technique_id']}")
    if finding.get("classification"):
        parts.append(f"Classification: {finding['classification']}")
    if finding.get("severity"):
        parts.append(f"Severity: {finding['severity']}")

    desc = finding.get("rationale") or finding.get("description", "")
    if desc:
        parts.append(desc)

    evidence = finding.get("raw_evidence_snippet") or finding.get("evidence_snippet", "")
    if evidence:
        parts.append(f"Evidence: {evidence}")

    hosts = finding.get("affected_hosts", [])
    if hosts:
        parts.append(f"Hosts: {', '.join(str(h) for h in hosts)}")

    return "\n".join(parts)
