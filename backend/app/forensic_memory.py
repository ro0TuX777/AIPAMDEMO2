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


# ── Behavioral Fingerprint Storage ────────────────────────────────────

BEHAVIORAL_COLLECTION = "aipam_behavioral_fingerprints"
_behavioral_collection = None


def get_behavioral_collection(
    db_path: Optional[str] = None,
    collection_name: Optional[str] = None,
):
    """Lazy-init the behavioral fingerprint ChromaDB collection."""
    global _behavioral_collection

    if _behavioral_collection is not None:
        return _behavioral_collection

    try:
        import chromadb
    except ImportError:
        logger.warning("chromadb not installed — behavioral memory disabled")
        return None

    path = db_path or DEFAULT_CHROMADB_PATH
    name = collection_name or BEHAVIORAL_COLLECTION

    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        # Reuse or create client
        global _chroma_client
        if _chroma_client is None:
            _chroma_client = chromadb.PersistentClient(path=path)
        _behavioral_collection = _chroma_client.get_or_create_collection(
            name=name,
            metadata={"description": "AIPAM behavioral fingerprints from confirmed investigations"},
        )
        logger.info("Behavioral memory collection initialized: %s (%d docs)", name,
                     _behavioral_collection.count())
        return _behavioral_collection
    except Exception as exc:
        logger.error("Failed to initialize behavioral memory: %s", exc)
        return None


def store_behavioral_fingerprints(
    job_id: str,
    project_id: str,
    fingerprints: List[Dict[str, Any]],
    *,
    confirmed_only: bool = True,
) -> int:
    """Index behavioral fingerprints into the global memory.

    Args:
        job_id: Source job ID
        project_id: Source project ID
        fingerprints: List of BehavioralFingerprint.to_dict() results
        confirmed_only: If True (default), only index fingerprints with
                        confidence >= 0.5. This is the contamination guard.

    Returns:
        Number of fingerprints indexed
    """
    collection = get_behavioral_collection()
    if collection is None:
        return 0

    # Contamination guard: filter low-confidence fingerprints
    if confirmed_only:
        valid = [fp for fp in fingerprints if fp.get("confidence", 0) >= 0.5]
        skipped = len(fingerprints) - len(valid)
        if skipped:
            logger.info(
                "Behavioral memory: %d fingerprints skipped (below confidence threshold)",
                skipped,
            )
    else:
        valid = list(fingerprints)

    indexed = 0
    for i, fp in enumerate(valid):
        doc_id = f"{job_id}-fp-{i}"
        doc_text = fp.get("text", "")
        if not doc_text:
            continue

        metadata = {
            "job_id": job_id,
            "project_id": project_id,
            "fingerprint_type": fp.get("fingerprint_type", ""),
            "label": fp.get("label", ""),
            "confidence": float(fp.get("confidence", 0)),
            "exercise_id": fp.get("source_exercise_id", ""),
        }

        try:
            collection.upsert(
                ids=[doc_id],
                documents=[doc_text],
                metadatas=[metadata],
            )
            indexed += 1
        except Exception as exc:
            logger.warning("Failed to index fingerprint %s: %s", doc_id, exc)

    logger.info(
        "Behavioral memory: indexed %d/%d fingerprints for job %s",
        indexed, len(valid), job_id,
    )
    return indexed


def query_behavioral_memory(
    query: str,
    top_k: int = 5,
    fingerprint_type: Optional[str] = None,
    exercise_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Semantic search across behavioral fingerprints.

    Args:
        query: Natural language query or behavioral description
        top_k: Max results
        fingerprint_type: Optional filter by type (beacon_profile, auth_abuse, etc.)
        exercise_id: Optional filter by exercise

    Returns:
        List of dicts with keys: document, metadata, distance, relevance
    """
    collection = get_behavioral_collection()
    if collection is None:
        return []

    if collection.count() == 0:
        return []

    where_filter: Optional[Dict[str, Any]] = None
    if fingerprint_type and exercise_id:
        where_filter = {
            "$and": [
                {"fingerprint_type": fingerprint_type},
                {"exercise_id": exercise_id},
            ]
        }
    elif fingerprint_type:
        where_filter = {"fingerprint_type": fingerprint_type}
    elif exercise_id:
        where_filter = {"exercise_id": exercise_id}

    try:
        kwargs: Dict[str, Any] = {
            "query_texts": [query],
            "n_results": min(top_k, collection.count()),
        }
        if where_filter:
            kwargs["where"] = where_filter

        results = collection.query(**kwargs)

        hits: List[Dict[str, Any]] = []
        if results and results.get("documents"):
            docs = results["documents"][0]
            metas = results.get("metadatas", [[]])[0]
            distances = results.get("distances", [[]])[0]

            for j, doc in enumerate(docs):
                dist = distances[j] if j < len(distances) else 1.0
                hits.append({
                    "document": doc,
                    "metadata": metas[j] if j < len(metas) else {},
                    "distance": dist,
                    "relevance": max(0, 1.0 - dist),
                })

        return hits
    except Exception as exc:
        logger.error("Behavioral memory query failed: %s", exc)
        return []


def get_behavioral_memory_stats() -> Dict[str, Any]:
    """Return stats about the behavioral fingerprint store."""
    collection = get_behavioral_collection()
    if collection is None:
        return {"available": False, "count": 0}

    return {
        "available": True,
        "count": collection.count(),
        "collection_name": BEHAVIORAL_COLLECTION,
        "path": DEFAULT_CHROMADB_PATH,
    }


def reset_behavioral_collection() -> None:
    """Reset the behavioral collection (for testing)."""
    global _behavioral_collection
    _behavioral_collection = None
