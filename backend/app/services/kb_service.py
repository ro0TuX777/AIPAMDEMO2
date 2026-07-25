"""
Knowledge Base RAG service — chunking, embedding, storage, retrieval.

Uses ChromaDB for vector storage and Ollama's embedding API (mxbai-embed-large).
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import csv
import io

import httpx

logger = logging.getLogger("aipam.kb")


@dataclass
class IndexResult:
    """Outcome of indexing one document."""
    chunk_count: int
    degraded: bool = False  # True when any chunk fell back to hash embeddings

# ── Chunking parameters ─────────────────────────────────────────────────
_CHUNK_SIZE = 1024     # chars per chunk
_CHUNK_OVERLAP = 128   # overlap between consecutive chunks

# Vector-store metadata value used for job-less "global library" documents.
# The DB stores job_id=NULL for these; ChromaDB metadata needs a scalar, so we
# tag their chunks with this sentinel and union it into per-job retrieval.
GLOBAL_JOB_SENTINEL = "__global__"


def _looks_like_csv(text: str) -> bool:
    """Heuristic: does the text look like CSV/TSV data?"""
    lines = text.strip().split("\n", 10)
    if len(lines) < 2:
        return False
    # Check if most lines have a consistent delimiter count
    for delim in (",", "\t"):
        counts = [line.count(delim) for line in lines[:8] if line.strip()]
        if counts and min(counts) >= 2 and max(counts) - min(counts) <= 2:
            return True
    return False


def _infer_column_name(data_rows: list[list[str]], col_idx: int) -> str:
    """Infer a meaningful column name from data values when the header cell is empty.

    Samples up to 10 data values and checks for common patterns:
    - IP addresses → "IP Address"
    - MAC addresses → "MAC Address"
    - Status keywords (Online/Offline/Active/Inactive/Up/Down) → "Status"
    - Numeric-only → "Value"
    - Date-like → "Date"
    Falls back to "Column_N" if no pattern matches.
    """
    _IP_RE = re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
    _MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")
    _STATUS_WORDS = {"online", "offline", "active", "inactive", "up", "down",
                     "enabled", "disabled", "running", "stopped", "unknown"}
    _DATE_RE = re.compile(
        r"^[0-9]{1,4}[/\-][0-9]{1,2}[/\-][0-9]{1,4}$"
    )

    samples = []
    for row in data_rows[:10]:
        if col_idx < len(row) and row[col_idx].strip():
            samples.append(row[col_idx].strip())

    if not samples:
        return f"Column_{col_idx + 1}"

    ip_count = sum(1 for s in samples if _IP_RE.match(s))
    if ip_count >= len(samples) * 0.6:
        return "IP Address"

    mac_count = sum(1 for s in samples if _MAC_RE.match(s))
    if mac_count >= len(samples) * 0.6:
        return "MAC Address"

    status_count = sum(1 for s in samples if s.lower() in _STATUS_WORDS)
    if status_count >= len(samples) * 0.6:
        return "Status"

    date_count = sum(1 for s in samples if _DATE_RE.match(s))
    if date_count >= len(samples) * 0.6:
        return "Date"

    numeric_count = sum(1 for s in samples if s.replace(".", "", 1).replace("-", "", 1).isdigit())
    if numeric_count >= len(samples) * 0.6:
        return "Value"

    return f"Column_{col_idx + 1}"


def _enrich_csv_to_natural_language(text: str, doc_name: str = "") -> str:
    """Convert CSV/TSV rows into natural-language sentences for better embedding.

    Each row becomes a sentence like:
      'Asset record — Hostname: tea-Platform-2, IP Address: 10.16.167.41, Vendor: VMware, Status: Online'
    This embeds much better for semantic search than raw CSV text.
    """
    text = text.strip()
    lines = text.split("\n")
    if len(lines) < 2:
        return text

    # Detect delimiter
    delim = ","
    if lines[0].count("\t") > lines[0].count(","):
        delim = "\t"

    try:
        reader = csv.reader(io.StringIO(text), delimiter=delim)
        rows = list(reader)
    except Exception:
        return text

    if len(rows) < 2:
        return text

    # Find header row — first row with mostly non-empty cells
    header_idx = 0
    headers = [h.strip() for h in rows[0]]
    # If first row looks empty or like a title, try the next
    non_empty = [h for h in headers if h]
    if len(non_empty) < 2 and len(rows) > 2:
        headers = [h.strip() for h in rows[1]]
        header_idx = 1

    # Detect column count mismatch: data rows may have more columns than
    # the header row when text.strip() removed a leading delimiter.
    data_rows = rows[header_idx + 1:]
    if data_rows:
        max_data_cols = max(len(r) for r in data_rows[:10])
        if max_data_cols > len(headers):
            # Pad headers at the front with empty strings so indices align
            pad = max_data_cols - len(headers)
            headers = [""] * pad + headers

    # Clean up headers: infer names for empty header cells from data patterns
    clean_headers = []
    for i, h in enumerate(headers):
        if h:
            clean_headers.append(h)
        else:
            inferred = _infer_column_name(data_rows, i)
            clean_headers.append(inferred)

    enriched_lines = []
    prefix = f"Asset record from '{doc_name}'" if doc_name else "Asset record"

    for row in rows[header_idx + 1:]:
        if not any(cell.strip() for cell in row):
            continue  # skip empty rows
        parts = []
        for i, cell in enumerate(row):
            cell = cell.strip()
            if not cell:
                continue
            col_name = clean_headers[i] if i < len(clean_headers) else f"Column_{i + 1}"
            parts.append(f"{col_name}: {cell}")
        if parts:
            enriched_lines.append(f"{prefix} — " + ", ".join(parts))

    if not enriched_lines:
        return text

    return "\n".join(enriched_lines)


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


# ── Structure-aware chunking ─────────────────────────────────────────────

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*$")
# Page / Sheet / Slide markers emitted by the binary extractors.
_MARKER_RE = re.compile(r"^---\s*(Page|Sheet|Slide)\b.*?---\s*$", re.IGNORECASE)


def _split_into_sections(text: str) -> list[tuple[str, str]]:
    """Split text into (breadcrumb_label, section_text) by structure.

    Recognises Markdown headings — nested headings build a breadcrumb like
    ``Setup › Payload options`` — and the ``--- Page/Sheet/Slide … ---`` markers
    the extractors emit. Text with no such structure returns one ('', text).
    """
    sections: list[tuple[str, str]] = []
    heading_stack: list[tuple[int, str]] = []
    label = ""
    buf: list[str] = []

    def flush() -> None:
        if any(ln.strip() for ln in buf):
            sections.append((label, "\n".join(buf).strip()))

    for line in text.split("\n"):
        stripped = line.strip()
        heading = _HEADING_RE.match(stripped)
        marker = _MARKER_RE.match(stripped)
        if heading:
            flush()
            buf = []
            level = len(heading.group(1))
            title = heading.group(2).strip()
            heading_stack[:] = [(lv, t) for lv, t in heading_stack if lv < level]
            heading_stack.append((level, title))
            label = " › ".join(t for _, t in heading_stack)
            buf.append(line)
        elif marker:
            flush()
            buf = []
            heading_stack.clear()
            label = stripped.strip("- ").strip()
            buf.append(line)
        else:
            buf.append(line)
    flush()
    return sections or [("", text.strip())]


def _pack_paragraphs(body: str, chunk_size: int, overlap: int) -> list[str]:
    """Pack a section's paragraphs into <= chunk_size pieces, keeping boundaries."""
    paras = [p for p in re.split(r"\n\s*\n", body) if p.strip()]
    pieces: list[str] = []
    cur = ""
    for para in paras:
        if len(para) > chunk_size:
            # Oversized single paragraph → fall back to char windows.
            if cur.strip():
                pieces.append(cur.strip())
            cur = ""
            pieces.extend(chunk_text(para, chunk_size, overlap))
            continue
        if cur and len(cur) + len(para) + 2 > chunk_size:
            pieces.append(cur.strip())
            cur = ""
        cur = f"{cur}\n\n{para}" if cur else para
    if cur.strip():
        pieces.append(cur.strip())
    return pieces


def chunk_structured(
    text: str, chunk_size: int = _CHUNK_SIZE, overlap: int = _CHUNK_OVERLAP,
) -> list[tuple[str, str]]:
    """Chunk a document along its structure → (chunk, section_label) pairs.

    Sections come from headings/markers; long sections are packed by paragraph so
    chunks don't split mid-sentence, mid-table, or mid-heading (which blind
    fixed-size windows do). The label is a heading breadcrumb or page/slide
    marker, kept for retrieval context and citations.
    """
    text = text.strip()
    if not text:
        return []
    out: list[tuple[str, str]] = []
    for label, body in _split_into_sections(text):
        if not body.strip():
            continue
        if len(body) <= chunk_size:
            out.append((body, label))
        else:
            out.extend((piece, label) for piece in _pack_paragraphs(body, chunk_size, overlap))
    return out


# ── Ollama Embedding Client ─────────────────────────────────────────────

# Chunks per /api/embed request. Ollama accepts an array of inputs and returns
# one embedding per input, so batching cuts a many-hundred-chunk manual from
# hundreds of sequential round-trips down to a handful.
_EMBED_BATCH = 64


async def _embed_one(client: httpx.AsyncClient, ollama_url: str, model: str, text: str) -> list[float] | None:
    """Embed a single text; return None on failure (caller falls back)."""
    try:
        resp = await client.post(f"{ollama_url}/api/embed", json={"model": model, "input": text})
        resp.raise_for_status()
        emb_list = resp.json().get("embeddings", [])
        if emb_list and emb_list[0]:
            return emb_list[0]
    except Exception as exc:
        logger.warning("Ollama embedding failed for one chunk: %s", exc)
    return None


async def get_embeddings(
    texts: list[str],
    ollama_url: str = "http://ollama:11434",
    model: str = "mxbai-embed-large",
    _stats: dict | None = None,
) -> list[list[float]]:
    """Get embeddings from Ollama's /api/embed endpoint (Ollama >= 0.4).

    Sends texts in batches for speed, retrying a failed batch item-by-item.
    Any chunk that still can't be embedded falls back to a deterministic
    hash-based vector so the system degrades gracefully instead of failing —
    but that vector is semantically meaningless. When a ``_stats`` dict is
    passed, the number of such fallbacks is recorded under ``_stats['fallback']``
    so callers can flag the document as degraded (embedding model unavailable).
    """
    embeddings: list[list[float]] = []
    fallback = 0
    async with httpx.AsyncClient(timeout=120.0) as client:
        for i in range(0, len(texts), _EMBED_BATCH):
            batch = texts[i:i + _EMBED_BATCH]
            got: list[list[float]] | None = None
            try:
                resp = await client.post(f"{ollama_url}/api/embed", json={"model": model, "input": batch})
                resp.raise_for_status()
                embs = resp.json().get("embeddings", [])
                if len(embs) == len(batch) and all(embs):
                    got = embs
            except Exception as exc:
                logger.warning("Ollama batch embed failed (%s) — retrying per-item", exc)

            if got is not None:
                embeddings.extend(got)
                continue

            # Batch failed or came back incomplete — try each item, then hash.
            for text in batch:
                one = await _embed_one(client, ollama_url, model, text)
                if one is None:
                    embeddings.append(_fallback_embedding(text))
                    fallback += 1
                else:
                    embeddings.append(one)

    if _stats is not None:
        _stats["fallback"] = _stats.get("fallback", 0) + fallback
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
) -> IndexResult:
    """Chunk a document, embed it, and store in ChromaDB.

    Returns an IndexResult (chunk count + degraded flag). ``degraded`` is True
    when the embedding model was unavailable and hash fallbacks were used, so
    the caller can mark the document for re-indexing.
    If the content looks like CSV/TSV data, it is first enriched into
    natural-language sentences so that semantic search works well.
    """
    # CSV/TSV is enriched into per-row natural-language sentences and chunked
    # by size; everything else is chunked along its structure (headings, pages,
    # slides) so chunks keep a section label and don't split mid-section.
    if _looks_like_csv(content):
        logger.info("Detected CSV/TSV content in '%s' — enriching for embedding", doc_name)
        enriched = _enrich_csv_to_natural_language(content, doc_name=doc_name)
        chunk_pairs = [(c, "") for c in chunk_text(enriched)]
    else:
        chunk_pairs = chunk_structured(content)
    if not chunk_pairs:
        return IndexResult(chunk_count=0)

    chunks = [c for c, _ in chunk_pairs]
    sections = [s for _, s in chunk_pairs]
    # Embed each chunk together with its section breadcrumb so the section
    # context contributes to the vector (helps retrieval on long manuals).
    embed_inputs = [f"{s}\n{c}" if s else c for c, s in chunk_pairs]

    stats: dict = {"fallback": 0}
    embeddings = await get_embeddings(embed_inputs, ollama_url=ollama_url, model=embedding_model, _stats=stats)

    collection = _get_collection(persist_dir)

    ids = [f"{doc_id}_chunk_{i}" for i in range(len(chunks))]
    metadatas = [
        {
            "doc_id": doc_id,
            "doc_name": doc_name,
            "doc_type": doc_type,
            "job_id": job_id,
            "chunk_index": i,
            "section": sections[i],
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

    degraded = stats["fallback"] > 0
    logger.info(
        "Indexed %d chunks for document %s (%s) job=%s%s",
        len(chunks), doc_name, doc_id, job_id,
        f" [DEGRADED: {stats['fallback']} hash fallbacks]" if degraded else "",
    )
    return IndexResult(chunk_count=len(chunks), degraded=degraded)


async def retrieve(
    query: str,
    n_results: int = 5,
    doc_type_filter: str | None = None,
    job_id: str | None = None,
    include_global: bool = True,
    ollama_url: str = "http://ollama:11434",
    embedding_model: str = "mxbai-embed-large",
    persist_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Retrieve the most relevant KB chunks for a query.

    Job scoping (via the ``job_id`` metadata on each chunk):
      - job_id set,  include_global=True   → that job's chunks ∪ global library
      - job_id set,  include_global=False  → that job's chunks only
      - job_id None, include_global=True   → global library only
      - job_id None, include_global=False  → no job filter (every chunk; legacy)

    Returns a list of dicts with keys: text, doc_name, doc_type, score, doc_id.
    """
    collection = _get_collection(persist_dir)
    if collection.count() == 0:
        return []

    query_embedding = await get_embeddings([query], ollama_url=ollama_url, model=embedding_model)
    if not query_embedding:
        return []

    # Build where filter combining job scope and optional doc_type
    where_clauses: list[dict] = []
    scopes: list[str] = []
    if job_id:
        scopes.append(job_id)
    if include_global:
        scopes.append(GLOBAL_JOB_SENTINEL)
    if len(scopes) == 1:
        where_clauses.append({"job_id": scopes[0]})
    elif len(scopes) > 1:
        where_clauses.append({"job_id": {"$in": scopes}})
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
                "section": meta.get("section", ""),
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
        res = await index_document(
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
        counts["total_chunks"] += res.chunk_count

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
        res = await index_document(
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
        counts["total_chunks"] += res.chunk_count

    # ── Index findings ───────────────────────────────────────────────
    findings = db_session.execute(
        select(Finding).where(Finding.job_id == job_id)
    ).scalars().all()

    for finding in findings:
        content = _format_finding_summary(finding)
        doc_id = f"job_{job_id}_finding_{finding.finding_id}"
        res = await index_document(
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
        counts["total_chunks"] += res.chunk_count

    logger.info(
        "Auto-indexed job %s: %d hosts, %d alerts, %d findings → %d chunks",
        job_id, counts["hosts"], counts["alerts"], counts["findings"], counts["total_chunks"],
    )
    return counts

