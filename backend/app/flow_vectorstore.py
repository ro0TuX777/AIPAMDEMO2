"""
Flow vectorstore for semantic retrieval of network flows.

Uses LanceDB to store flow records with vector embeddings so the LLM
analysis pipeline can retrieve the *most relevant* flows for a given
analysis query instead of taking the first N.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import pyarrow as pa
import lancedb

from .models import FlowRecord, AlertRecord
from .settings_runtime import get_effective_settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singletons (lazy)
# ---------------------------------------------------------------------------

_lance_db: Optional[lancedb.DBConnection] = None
_embedding_model = None


def _get_lance_db() -> lancedb.DBConnection:
    """Return a shared LanceDB connection, creating it on first call."""
    global _lance_db
    if _lance_db is None:
        settings = get_effective_settings()
        vector_store_path = getattr(settings, "vector_store_path", None)
        if not vector_store_path:
            vector_store_path = settings.file_storage_path / "lance_store"
        vector_store_path = Path(vector_store_path)
        vector_store_path.mkdir(parents=True, exist_ok=True)
        _lance_db = lancedb.connect(str(vector_store_path))
        logger.info("LanceDB connected at %s", vector_store_path)
    return _lance_db


def _get_embedding_model():
    """Lazy-load the sentence-transformers embedding model."""
    global _embedding_model
    if _embedding_model is None:
        try:
            from sentence_transformers import SentenceTransformer

            settings = get_effective_settings()
            model_name = (
                getattr(settings, "embedding_model_name", None)
                or "sentence-transformers/all-MiniLM-L6-v2"
            )
            model_path = getattr(settings, "embedding_model_path", None)
            device = "cpu"

            if model_path and Path(model_path).exists():
                _embedding_model = SentenceTransformer(str(model_path), device=device)
                logger.info("Loaded embedding model from %s", model_path)
            else:
                _embedding_model = SentenceTransformer(model_name, device=device)
                logger.info("Loaded embedding model: %s", model_name)
        except Exception as e:
            logger.error("Failed to load embedding model: %s", e)
            raise
    return _embedding_model


# ---------------------------------------------------------------------------
# Text serialization
# ---------------------------------------------------------------------------


def flow_to_text(flow: FlowRecord, related_alerts: Optional[List[AlertRecord]] = None) -> str:
    """Deterministic text representation of a flow for embedding.

    Format is designed so that similar traffic patterns (same proto/port/
    behaviour) cluster together in the embedding space.
    """
    direction = f"{flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}"
    proto = flow.transport_proto.upper()
    app = flow.app_proto or "unknown"

    # Human-readable byte sizes
    sent = _humanize_bytes(flow.bytes_from_src)
    recv = _humanize_bytes(flow.bytes_from_dst)

    parts = [
        f"{proto} {direction}",
        f"app={app}",
        f"sent={sent} recv={recv}",
        f"duration={flow.duration_sec:.1f}s",
    ]

    if flow.tcp_flags_summary:
        parts.append(f"flags={flow.tcp_flags_summary}")
    if flow.state:
        parts.append(f"state={flow.state}")
    if flow.tags:
        parts.append(f"tags={','.join(flow.tags)}")

    text = " | ".join(parts)

    # Append alert context so that flows with alerts cluster near
    # forensic/security queries.
    if related_alerts:
        alert_texts = []
        for a in related_alerts[:3]:  # cap to avoid massive strings
            alert_texts.append(
                f"[{a.severity}] {a.signature_name or 'alert'}"
            )
        text += " | ALERTS: " + "; ".join(alert_texts)

    return text


def _humanize_bytes(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f}KB"
    else:
        return f"{n / (1024 * 1024):.1f}MB"


# ---------------------------------------------------------------------------
# Embedding + storage
# ---------------------------------------------------------------------------

_TABLE_PREFIX = "flows_"


def _table_name(job_id: str) -> str:
    safe = job_id.replace("-", "_")[:50]
    return f"{_TABLE_PREFIX}{safe}"


def embed_flows(
    job_id: str,
    flows: List[FlowRecord],
    alerts: Optional[List[AlertRecord]] = None,
) -> int:
    """Embed all flows and store in LanceDB.

    Returns the number of flows indexed.
    """
    if not flows:
        return 0

    db = _get_lance_db()
    model = _get_embedding_model()

    # Build a lookup: IP → matching alerts
    alert_map: Dict[str, List[AlertRecord]] = {}
    for a in (alerts or []):
        for ip in (a.src_ip, a.dst_ip):
            if ip:
                alert_map.setdefault(ip, []).append(a)

    # Serialize and embed
    texts: List[str] = []
    rows: List[Dict[str, Any]] = []

    for flow in flows:
        related = []
        for ip in (flow.src_ip, flow.dst_ip):
            related.extend(alert_map.get(ip, []))
        text = flow_to_text(flow, related or None)
        texts.append(text)

    logger.info("Embedding %d flows for job %s …", len(texts), job_id)
    vectors = model.encode(texts, show_progress_bar=False, batch_size=256)

    for i, flow in enumerate(flows):
        rows.append(
            {
                "id": flow.id,
                "vector": vectors[i].tolist(),
                "text": texts[i],
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "transport_proto": flow.transport_proto,
                "app_proto": flow.app_proto or "",
                "bytes_from_src": flow.bytes_from_src,
                "bytes_from_dst": flow.bytes_from_dst,
                "packets_from_src": flow.packets_from_src,
                "packets_from_dst": flow.packets_from_dst,
                "duration_sec": flow.duration_sec,
                "state": flow.state or "",
                "tcp_flags": flow.tcp_flags_summary or "",
                "start_time": flow.start_time.isoformat(),
                "end_time": flow.end_time.isoformat(),
                "has_alerts": bool(alert_map.get(flow.src_ip) or alert_map.get(flow.dst_ip)),
                "job_id": job_id,
            }
        )

    tbl_name = _table_name(job_id)

    # Drop existing table if present (for re-indexing)
    try:
        db.drop_table(tbl_name)
    except Exception:
        pass

    db.create_table(tbl_name, data=rows)
    logger.info("Indexed %d flows into LanceDB table '%s'", len(rows), tbl_name)
    return len(rows)


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------


def retrieve_relevant_flows(
    job_id: str,
    query: str,
    top_k: int = 200,
    filters: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve flows most semantically similar to *query*.

    Args:
        job_id: The job whose flows to search.
        query: Natural-language analysis question (e.g. "C2 beaconing").
        top_k: Maximum number of flows to return.
        filters: Optional SQL-like filter expression applied *before*
                 vector ranking.  Examples:
                 ``"dst_port = 443"``
                 ``"app_proto = 'dns' AND bytes_from_src > 500"``
                 ``"has_alerts = true"``

    Returns:
        List of flow dicts ordered by descending relevance.
    """
    db = _get_lance_db()
    model = _get_embedding_model()

    tbl_name = _table_name(job_id)
    try:
        table = db.open_table(tbl_name)
    except Exception:
        logger.warning("No flow index for job %s", job_id)
        return []

    query_vec = model.encode([query], show_progress_bar=False)[0].tolist()

    search = table.search(query_vec).limit(top_k)
    if filters:
        search = search.where(filters)

    results = search.to_pandas()

    # Convert to list of dicts and drop the vector column
    if "vector" in results.columns:
        results = results.drop(columns=["vector"])

    return results.to_dict(orient="records")


# ---------------------------------------------------------------------------
# Lifecycle helpers
# ---------------------------------------------------------------------------


def delete_flow_index(job_id: str) -> bool:
    """Delete the flow vector table for a job."""
    try:
        db = _get_lance_db()
        db.drop_table(_table_name(job_id))
        logger.info("Deleted flow index for job %s", job_id)
        return True
    except Exception as e:
        logger.warning("Failed to delete flow index for job %s: %s", job_id, e)
        return False


def job_has_flow_index(job_id: str) -> bool:
    """Check if a job has an existing flow vector index."""
    try:
        db = _get_lance_db()
        db.open_table(_table_name(job_id))
        return True
    except Exception:
        return False
