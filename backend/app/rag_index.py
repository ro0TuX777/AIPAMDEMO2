"""
RAG indexing module for PCAP analysis chat.

This module provides vector embeddings and semantic search over normalized
analysis summaries (hosts, host-pairs, alerts, time windows) using ChromaDB
and sentence-transformers.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

from .settings_runtime import get_effective_settings

logger = logging.getLogger(__name__)

# Lazy-loaded globals to avoid import overhead when RAG not needed
_embedding_model = None
_chroma_client = None


@dataclass
class RAGDocument:
    """A document chunk for RAG indexing."""
    id: str
    content: str
    doc_type: str  # "host", "host_pair", "alert", "finding", "change"
    metadata: Dict[str, Any]
    anomaly_score: float = 0.0  # Higher = more anomalous/interesting


@dataclass
class RAGSearchResult:
    """A search result from the RAG index."""
    document: RAGDocument
    score: float
    rank: int


def _get_embedding_model():
    """Lazy-load the sentence-transformers embedding model."""
    global _embedding_model
    if _embedding_model is None:
        try:
            from sentence_transformers import SentenceTransformer
            settings = get_effective_settings()
            model_name = getattr(settings, 'embedding_model_name', None) or "sentence-transformers/all-MiniLM-L6-v2"
            model_path = getattr(settings, 'embedding_model_path', None)

            # Use CPU by default - embeddings are fast enough and don't compete with GPU training
            device = "cpu"

            if model_path and Path(model_path).exists():
                _embedding_model = SentenceTransformer(model_path, device=device)
                logger.info(f"Loaded embedding model from local path: {model_path} (device={device})")
            else:
                _embedding_model = SentenceTransformer(model_name, device=device)
                logger.info(f"Loaded embedding model: {model_name} (device={device})")
        except Exception as e:
            logger.error(f"Failed to load embedding model: {e}")
            raise
    return _embedding_model


def _get_chroma_client():
    """Lazy-load the ChromaDB client with persistent storage."""
    global _chroma_client
    if _chroma_client is None:
        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings
            
            settings = get_effective_settings()
            vector_store_path = getattr(settings, 'vector_store_path', None)
            if not vector_store_path:
                vector_store_path = settings.file_storage_path / "vector_store"
            
            vector_store_path = Path(vector_store_path)
            vector_store_path.mkdir(parents=True, exist_ok=True)
            
            _chroma_client = chromadb.PersistentClient(
                path=str(vector_store_path),
                settings=ChromaSettings(anonymized_telemetry=False)
            )
            logger.info(f"Initialized ChromaDB at: {vector_store_path}")
        except Exception as e:
            logger.error(f"Failed to initialize ChromaDB: {e}")
            raise
    return _chroma_client


def _get_collection_name(job_id: str) -> str:
    """Get the ChromaDB collection name for a job."""
    # ChromaDB collection names must be 3-63 chars, alphanumeric with underscores/hyphens
    safe_id = job_id.replace("-", "_")[:50]
    return f"job_{safe_id}"


def _calculate_anomaly_score(doc_type: str, metadata: Dict[str, Any]) -> float:
    """Calculate anomaly score for ranking (higher = more interesting)."""
    score = 0.0
    
    if doc_type == "alert":
        severity = metadata.get("severity", "").lower()
        if severity == "critical":
            score = 1.0
        elif severity == "high":
            score = 0.8
        elif severity == "medium":
            score = 0.5
        else:
            score = 0.2
        # Boost TrafficLLM alerts
        if metadata.get("source") == "TRAFFICLLM":
            score = min(1.0, score + 0.2)
    
    elif doc_type == "host":
        # Score based on role and alert count
        role = metadata.get("role", "").lower()
        if role in ("attacker", "c2"):
            score = 0.9
        elif role == "victim":
            score = 0.7
        elif role == "infrastructure":
            score = 0.5
        else:
            score = 0.3
        # Boost by alert count
        alert_count = metadata.get("alert_count", 0)
        score = min(1.0, score + (alert_count * 0.05))
    
    elif doc_type == "finding":
        score = 0.8  # Key findings are important
    
    elif doc_type == "change":
        # Changes from baseline are interesting
        score = 0.6
    
    return score


def build_documents_from_job_result(job_id: str, job_result: Dict[str, Any]) -> List[RAGDocument]:
    """Build RAG documents from a job result for indexing."""
    documents: List[RAGDocument] = []
    
    # 1. Index host findings
    hosts = job_result.get("hosts", [])
    for i, host in enumerate(hosts):
        ip = host.get("ip", f"unknown_{i}")
        role = host.get("role", "unknown")
        findings = host.get("findings", [])
        
        content = f"Host: {ip}\nRole: {role}\n"
        if findings:
            content += "Findings:\n" + "\n".join(f"- {f}" for f in findings)
        
        metadata = {
            "ip": ip,
            "role": role,
            "finding_count": len(findings),
            "job_id": job_id,
        }
        
        doc = RAGDocument(
            id=f"{job_id}_host_{ip}",
            content=content,
            doc_type="host",
            metadata=metadata,
            anomaly_score=_calculate_anomaly_score("host", metadata),
        )
        documents.append(doc)

    # 2. Index alerts from raw data
    raw = job_result.get("raw", {})
    alerts = raw.get("alerts", [])
    for i, alert in enumerate(alerts[:100]):  # Limit to top 100 alerts
        if isinstance(alert, dict):
            sig = alert.get("signature_name") or alert.get("signature", "Unknown")
            severity = alert.get("severity", "unknown")
            src = alert.get("src_ip", "")
            dst = alert.get("dst_ip", "")
            source = alert.get("alert_source", "Suricata")

            content = f"Alert: {sig}\nSeverity: {severity}\n"
            if src:
                content += f"Source IP: {src}\n"
            if dst:
                content += f"Destination IP: {dst}\n"
            content += f"Source: {source}"

            metadata = {
                "signature": sig,
                "severity": severity,
                "src_ip": src,
                "dst_ip": dst,
                "source": source,
                "job_id": job_id,
            }

            doc = RAGDocument(
                id=f"{job_id}_alert_{i}",
                content=content,
                doc_type="alert",
                metadata=metadata,
                anomaly_score=_calculate_anomaly_score("alert", metadata),
            )
            documents.append(doc)

    # 3. Index key findings from summary
    summary = job_result.get("summary", {})
    key_findings = summary.get("key_findings", [])
    for i, finding in enumerate(key_findings):
        if isinstance(finding, dict):
            finding_text = finding.get("description", str(finding))
        else:
            finding_text = str(finding)

        content = f"Key Finding: {finding_text}"

        mitre = summary.get("mitre_techniques", [])
        if mitre:
            techniques = [f"{t.get('id', '')} {t.get('name', '')}" for t in mitre if isinstance(t, dict)]
            content += f"\nMITRE ATT&CK: {', '.join(techniques)}"

        metadata = {
            "finding_index": i,
            "severity": summary.get("severity", "unknown"),
            "job_id": job_id,
        }

        doc = RAGDocument(
            id=f"{job_id}_finding_{i}",
            content=content,
            doc_type="finding",
            metadata=metadata,
            anomaly_score=_calculate_anomaly_score("finding", metadata),
        )
        documents.append(doc)

    # 4. Index overall summary
    if summary:
        severity = summary.get("severity", "unknown")
        content = f"Analysis Summary\nOverall Severity: {severity}\n"

        mitre = summary.get("mitre_techniques", [])
        if mitre:
            techniques = [f"{t.get('id', '')} ({t.get('name', '')})" for t in mitre if isinstance(t, dict)]
            content += f"MITRE ATT&CK Techniques: {', '.join(techniques)}\n"

        metadata = {"severity": severity, "job_id": job_id}

        doc = RAGDocument(
            id=f"{job_id}_summary",
            content=content,
            doc_type="summary",
            metadata=metadata,
            anomaly_score=0.7,  # Summary is always relevant
        )
        documents.append(doc)

    return documents


def index_job_result(job_id: str, job_result: Dict[str, Any]) -> int:
    """Index a job result into ChromaDB for RAG retrieval.

    Returns the number of documents indexed.
    """
    documents = build_documents_from_job_result(job_id, job_result)
    if not documents:
        logger.warning(f"No documents to index for job {job_id}")
        return 0

    try:
        client = _get_chroma_client()
        model = _get_embedding_model()

        collection_name = _get_collection_name(job_id)

        # Delete existing collection if it exists (for reindexing)
        try:
            client.delete_collection(collection_name)
        except Exception:
            pass  # Collection doesn't exist, which is fine

        collection = client.create_collection(
            name=collection_name,
            metadata={"job_id": job_id, "hnsw:space": "cosine"}
        )

        # Prepare data for ChromaDB
        ids = [doc.id for doc in documents]
        contents = [doc.content for doc in documents]
        metadatas = [
            {
                **doc.metadata,
                "doc_type": doc.doc_type,
                "anomaly_score": doc.anomaly_score,
            }
            for doc in documents
        ]

        # Generate embeddings
        embeddings = model.encode(contents, show_progress_bar=False).tolist()

        # Add to collection
        collection.add(
            ids=ids,
            embeddings=embeddings,
            documents=contents,
            metadatas=metadatas,
        )

        logger.info(f"Indexed {len(documents)} documents for job {job_id}")
        return len(documents)

    except Exception as e:
        logger.error(f"Failed to index job {job_id}: {e}")
        raise


def search_job_index(
    job_id: str,
    query: str,
    top_k: int = 8,
    doc_types: Optional[List[str]] = None,
    rerank_by_anomaly: bool = True,
) -> List[RAGSearchResult]:
    """Search the RAG index for a job.

    Args:
        job_id: The job to search
        query: The search query
        top_k: Maximum number of results to return
        doc_types: Optional filter for document types
        rerank_by_anomaly: Whether to re-rank results by anomaly score

    Returns:
        List of search results, ranked by relevance (and optionally anomaly score)
    """
    try:
        client = _get_chroma_client()
        model = _get_embedding_model()

        collection_name = _get_collection_name(job_id)

        try:
            collection = client.get_collection(collection_name)
        except Exception:
            logger.warning(f"No index found for job {job_id}")
            return []

        # Generate query embedding
        query_embedding = model.encode([query], show_progress_bar=False).tolist()[0]

        # Build filter if doc_types specified
        where_filter = None
        if doc_types:
            where_filter = {"doc_type": {"$in": doc_types}}

        # Query ChromaDB - get more results than needed for re-ranking
        fetch_k = top_k * 2 if rerank_by_anomaly else top_k
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=min(fetch_k, collection.count()),
            where=where_filter,
            include=["documents", "metadatas", "distances"],
        )

        # Build result objects
        search_results: List[RAGSearchResult] = []

        if results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                content = results["documents"][0][i] if results["documents"] else ""
                metadata = results["metadatas"][0][i] if results["metadatas"] else {}
                distance = results["distances"][0][i] if results["distances"] else 1.0

                # Convert distance to similarity score (ChromaDB uses L2 or cosine distance)
                similarity = 1.0 - (distance / 2.0)  # Normalize cosine distance

                doc = RAGDocument(
                    id=doc_id,
                    content=content,
                    doc_type=metadata.get("doc_type", "unknown"),
                    metadata=metadata,
                    anomaly_score=metadata.get("anomaly_score", 0.0),
                )

                search_results.append(RAGSearchResult(
                    document=doc,
                    score=similarity,
                    rank=i + 1,
                ))

        # Re-rank by combining similarity and anomaly score
        if rerank_by_anomaly and search_results:
            for result in search_results:
                # Combined score: 70% similarity + 30% anomaly
                result.score = (0.7 * result.score) + (0.3 * result.document.anomaly_score)

            search_results.sort(key=lambda r: r.score, reverse=True)

            # Update ranks
            for i, result in enumerate(search_results):
                result.rank = i + 1

        return search_results[:top_k]

    except Exception as e:
        logger.error(f"Failed to search job {job_id}: {e}")
        return []


def delete_job_index(job_id: str) -> bool:
    """Delete the RAG index for a job."""
    try:
        client = _get_chroma_client()
        collection_name = _get_collection_name(job_id)
        client.delete_collection(collection_name)
        logger.info(f"Deleted index for job {job_id}")
        return True
    except Exception as e:
        logger.warning(f"Failed to delete index for job {job_id}: {e}")
        return False


def job_has_index(job_id: str) -> bool:
    """Check if a job has an existing RAG index."""
    try:
        client = _get_chroma_client()
        collection_name = _get_collection_name(job_id)
        client.get_collection(collection_name)
        return True
    except Exception:
        return False

