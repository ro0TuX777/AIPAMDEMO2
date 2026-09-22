"""
Chat endpoints for V2.

POST /jobs/{job_id}/chat              – send a message, get AI response
GET  /jobs/{job_id}/conversations     – list conversations for a job
GET  /jobs/{job_id}/conversations/{id} – get conversation history
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.database_v2 import get_session_factory
from backend.app.llm_client import LLMClient, LLMConfig
from backend.app.schemas.chat import (                       # shared Pydantic models
    ChatCitation,
    ChatCitationOut,
    ChatComparisonBranchCreateRequest,
    ChatComparisonBranchOut,
    ChatComparisonActiveBranchRequest,
    ChatComparisonCreateRequest,
    ChatComparisonGroupOut,
    ChatGenerationMetadata,
    ChatMessageOut,
    ChatRequestBody,
    ChatResponseBody,
    ConversationHistoryOut,
    ConversationRenameRequest,
    ConversationSummaryOut,
    EvidenceRefOut,
    HistoricalChatCitationOut,
)
from backend.app.services import chat_citations as _cite_svc  # extracted helpers
from backend.app.services.entity_extractor import extract_entities
from backend.app.services.evidence_bundles import build_scoped_bundle, parse_context_hint
from backend.app.services.kb_service import extract_ips_from_context, retrieve as kb_retrieve
from backend.app.services.embedding_models import (
    get_embedding_model_service,
    get_runtime_llm_endpoint,
    get_runtime_llm_model,
    get_runtime_llm_timeout,
    get_runtime_ollama_url,
)
from backend.app.services.structured_retrieval import retrieve_structured
from backend.app.services.chat_comparisons import (
    ComparisonValidationError,
    PreparedChatTurn,
    create_mnemos_copy_branch,
    create_mnemos_snapshot,
    get_comparison_branches,
    get_comparison_group,
    inherited_display_messages_for_branch,
    get_conversation_branch,
    set_active_comparison_branch,
    prompt_history_for_mnemos_conversation,
)
from backend.app.services.mnemos_chat_retrieval import (
    MnemosRetrievalResult,
    retrieve_historical_findings,
)

from backend.app.api.deps import get_db, verify_token
from backend.app.config_v2 import Settings, get_settings
from backend.app.models.alert import Alert
from backend.app.models.chat import (
    ChatComparisonBranch,
    ChatComparisonGroup,
    ChatConversation,
    ChatMessage,
)
from backend.app.models.connection import Connection
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.job import Job
from backend.app.models.job_pcap import JobPcap

logger = logging.getLogger("aipam.chat")

# Strong references to detached background tasks so they aren't garbage
# collected mid-flight.  Each task removes itself via add_done_callback.
_background_tasks: set[asyncio.Task] = set()

router = APIRouter(dependencies=[Depends(verify_token)], tags=["chat"])

# Schemas are imported from backend.app.schemas.chat (see imports above).
# Re-exported here so that ``from backend.app.api.chat import ChatCitationOut``
# continues to work across the codebase and tests.
__all__ = [
    "ChatCitationOut",
    "ChatComparisonBranchOut",
    "ChatComparisonGroupOut",
    "ChatRequestBody",
    "ChatResponseBody",
    "ConversationHistoryOut",
    "ConversationRenameRequest",
    "ConversationSummaryOut",
    "EvidenceRefOut",
    "HistoricalChatCitationOut",
]


# ── Helpers ─────────────────────────────────────────────────────────────
# Thin wrappers that delegate to backend.app.services.chat_citations.
# The underscore-prefixed names are kept for backward compatibility
# with the many call sites inside this file.

def _now_iso() -> str:
    return _cite_svc.now_iso()


def _dedupe_citations(citations: list[ChatCitationOut], limit: int = 8) -> list[ChatCitationOut]:
    return _cite_svc.dedupe_citations(citations, limit=limit)


def _select_relevant_citations(
    citations: list[ChatCitationOut],
    user_message: str | None,
    *,
    limit: int = 8,
    min_score: int = 1,
) -> list[ChatCitationOut]:
    return _cite_svc.select_relevant_citations(citations, user_message, limit=limit, min_score=min_score)


def _build_primary_supporting_evidence_block(
    citations: list[ChatCitationOut],
    user_message: str | None = None,
) -> str:
    return _cite_svc.build_primary_supporting_evidence_block(citations, user_message)


def _build_grounded_direct_answer_from_citations(
    citations: list[ChatCitationOut],
    user_message: str | None = None,
) -> tuple[str, list[ChatCitationOut]] | None:
    return _cite_svc.build_grounded_direct_answer_from_citations(citations, user_message)


def _append_sources_and_limits(response_text: str, citations: list[ChatCitationOut]) -> str:
    return _cite_svc.append_sources_and_limits(response_text, citations)


def _build_unsupported_claims_response(
    citations: list[ChatCitationOut],
    user_message: str | None = None,
) -> str:
    return _cite_svc.build_unsupported_claims_response(citations, user_message)




def _finalize_grounded_response_payload(
    response_text: str,
    citations: list[ChatCitationOut],
    combined_context: str,
    user_message: str | None = None,
) -> tuple[str, list[ChatCitationOut]]:
    return _cite_svc.finalize_grounded_response_payload(response_text, citations, combined_context, user_message)


def _finalize_mode_aware_response_payload(
    response_text: str,
    *,
    current_job_citations: list[ChatCitationOut],
    historical_citations: list[HistoricalChatCitationOut],
    current_job_context: str,
    user_message: str | None,
    retrieval_status: str | None,
) -> tuple[str, list[ChatCitation]]:
    return _cite_svc.finalize_mode_aware_response_payload(
        response_text,
        current_job_citations=current_job_citations,
        historical_citations=historical_citations,
        current_job_context=current_job_context,
        user_message=user_message,
        retrieval_status=retrieval_status,
    )


def _finalize_prepared_chat_response_payload(
    response_text: str,
    prepared: PreparedChatTurn,
    user_message: str | None,
) -> tuple[str, list[ChatCitation]]:
    return _finalize_mode_aware_response_payload(
        response_text,
        current_job_citations=prepared.current_job_citations,
        historical_citations=prepared.historical_citations,
        current_job_context=prepared.current_job_context,
        user_message=user_message,
        retrieval_status=prepared.retrieval_status,
    )


def _finalize_grounded_response(
    response_text: str,
    citations: list[ChatCitationOut],
    combined_context: str,
    user_message: str | None = None,
) -> str:
    return _cite_svc.finalize_grounded_response(response_text, citations, combined_context, user_message)


def _post_process_response(
    response_text: str,
    user_message: str,
    citations: list[ChatCitationOut],
) -> tuple[list[EvidenceRefOut], list[str]]:
    return _cite_svc.post_process_response(response_text, user_message, citations)


def _chunk_text(text: str, chunk_size: int = 350) -> list[str]:
    if not text:
        return []
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]


def _serialize_citations(citations: list[ChatCitation]) -> str:
    return json.dumps({"items": [c.model_dump() for c in citations]})


def _build_job_citations(db: Session, job_id: str) -> list[ChatCitationOut]:
    citations: list[ChatCitationOut] = []

    findings = db.execute(
        select(Finding).where(Finding.job_id == job_id).limit(6)
    ).scalars().all()
    for finding in findings:
        citation_id = finding.finding_id or (str(finding.id) if finding.id is not None else None)
        conf = getattr(finding, "confidence", 0.0) or 0.0
        conf_pct = f"{round(conf * 100)}%"
        snippet = f"[{finding.severity}|conf:{conf_pct}] {finding.title}"
        if finding.summary:
            # Collapse newlines to prevent formatting breakage in sources block
            clean_summary = " ".join(finding.summary.split())
            snippet += f": {clean_summary[:120]}"
        citations.append(ChatCitationOut(type="finding", id=citation_id, snippet=snippet[:200]))

    alerts = db.execute(
        select(Alert).where(Alert.job_id == job_id).limit(8)
    ).scalars().all()
    for alert in alerts:
        citation_id = alert.alert_id or (str(alert.id) if alert.id is not None else None)
        snippet = f"[{alert.severity}] {alert.signature}"
        if alert.src_ip or alert.dest_ip:
            snippet += f" ({alert.src_ip or '?'} → {alert.dest_ip or '?'})"
        citations.append(ChatCitationOut(type="alert", id=citation_id, snippet=snippet[:200]))

    hosts = db.execute(
        select(Host).where(Host.job_id == job_id)
        .order_by(Host.alert_count.desc(), Host.conn_count.desc())
        .limit(6)
    ).scalars().all()
    for host in hosts:
        citation_id = host.ip or (str(host.id) if host.id is not None else None)
        snippet = (
            f"Host {host.ip} (role: {host.role or 'unknown'}) | "
            f"connections={host.conn_count or 0} alerts={host.alert_count or 0}"
        )
        citations.append(ChatCitationOut(type="host_summary", id=citation_id, snippet=snippet[:200]))

    return _dedupe_citations(citations, limit=20)


def _summarise_jsonl_line(raw: str, max_len: int = 500) -> str:
    """Trim a JSONL line to only the most useful fields, capped at max_len."""
    import json as _json
    try:
        obj = _json.loads(raw)
    except Exception:
        return raw[:max_len]
    # Flatten nested "data" dicts from sensor handlers
    if "data" in obj and isinstance(obj["data"], dict):
        inner = obj.pop("data")
        obj.update(inner)
    # Keep forensically-relevant keys
    keep = {
        "type", "event_type", "src_ip", "dest_ip", "src_port", "dest_port",
        "proto", "service", "app_proto", "ts", "timestamp",
        "query", "answers", "qtype", "rcode",
        "signature", "severity", "category", "alert", "sid",
        "subject", "issuer", "server_name", "ja3", "ja3s", "sni",
        "ioc_type", "value", "confidence", "matched_feed", "alert_signatures",
        "context", "ip",
        "event_type", "description", "title", "summary", "host_ip",
        "score", "beacon_score", "interval_mean",
        "filename", "sha256", "md5", "size", "magic",
        "chain_of_thought", "affected_hosts", "evidence",
    }
    trimmed = {k: v for k, v in obj.items() if k in keep}
    if not trimmed:
        trimmed = dict(list(obj.items())[:8])
    s = _json.dumps(trimmed, separators=(",", ":"))
    return s[:max_len]


# Hard cap on total context characters sent to the LLM.
# 8B models lose focus beyond ~6-8k chars of context.
# Budget: ~4000 for PCAP data + ~2000 for RAG context = 6000 total
_MAX_CONTEXT_CHARS = 14000
_MAX_PCAP_CHARS = 8000    # PCAP data budget
_MAX_RAG_CHARS = 6000     # RAG context budget
_MIN_RAG_BUDGET = 3000    # KB RAG always gets at least this much
_MAX_HOST_SUMMARIES = 25
_MAX_HOSTPAIRS = 30
_MAX_ALERTS = 50


def _build_sensor_context(db: Session, job_id: str, settings: Settings) -> str:
    """Build context JSON matching the model's fine-tuning input schema.

    The aipam-trafficllm model was trained on structured JSON with:
      - host_summaries: per-host flow aggregates
      - hostpair_summaries: per-pair flow + alert data
      - alerts: flat list of signature alerts

    We reconstruct this from DB records so the model recognises the format
    and can apply its trained malware-classification knowledge.
    """
    import json as _json
    from collections import Counter, defaultdict

    # ── 1. Host summaries (from hosts + connections tables) ──────────
    hosts = db.execute(
        select(Host).where(Host.job_id == job_id)
        .order_by(Host.alert_count.desc(), Host.conn_count.desc())
        .limit(_MAX_HOST_SUMMARIES)
    ).scalars().all()

    host_summaries: list[dict] = []
    for h in hosts:
        # Parse stored JSON fields safely
        try:
            svc_list = _json.loads(h.top_services_json) if h.top_services_json else []
        except Exception:
            svc_list = []
        try:
            sev_dict = _json.loads(h.alerts_by_severity_json) if h.alerts_by_severity_json else {}
        except Exception:
            sev_dict = {}

        protocol_usage = [
            {"app_proto": svc, "flow_count": 0, "bytes": 0}
            for svc in (svc_list[:5] if isinstance(svc_list, list) else [])
        ]

        host_summaries.append({
            "host_ip": h.ip,
            "role": h.role or "unknown",
            "time_window": {"start": h.first_seen or "", "end": h.last_seen or ""},
            "total_flows": h.conn_count or 0,
            "total_bytes_sent": h.bytes_sent or 0,
            "total_bytes_received": h.bytes_recv or 0,
            "top_dst_ips": [],
            "protocol_usage": protocol_usage,
            "dns_queries_count": h.dns_query_count or 0,
            "dns_unique_domains": 0,
            "http_requests_count": 0,
            "alerts_count": h.alert_count or 0,
            "alerts_by_severity": sev_dict if isinstance(sev_dict, dict) else {},
            "suspicious_heuristics": {},
        })

    # ── 2. Host-pair summaries (from connections + alerts) ───────────
    conns = db.execute(
        select(Connection).where(Connection.job_id == job_id)
        .order_by(Connection.ts.asc())
        .limit(500)  # read enough to aggregate
    ).scalars().all()

    pair_data: dict[tuple, dict] = defaultdict(lambda: {
        "flow_count": 0, "total_bytes": 0, "first_seen": None, "last_seen": None,
        "protos": Counter(), "alerts": [],
    })
    for c in conns:
        key = (c.src_ip, c.dest_ip)
        pd = pair_data[key]
        pd["flow_count"] += 1
        pd["total_bytes"] += (c.bytes_sent or 0) + (c.bytes_recv or 0)
        if pd["first_seen"] is None or c.ts < pd["first_seen"]:
            pd["first_seen"] = c.ts
        if pd["last_seen"] is None or c.ts > pd["last_seen"]:
            pd["last_seen"] = c.ts
        if c.service:
            pd["protos"][c.service.upper()] += (c.bytes_sent or 0) + (c.bytes_recv or 0)

    # Attach alerts to pairs
    alerts_all = db.execute(
        select(Alert).where(Alert.job_id == job_id).limit(_MAX_ALERTS)
    ).scalars().all()
    for a in alerts_all:
        key = (a.src_ip, a.dest_ip) if a.src_ip and a.dest_ip else None
        if key and key in pair_data:
            pair_data[key]["alerts"].append({
                "timestamp": a.ts,
                "signature_name": a.signature,
                "severity": a.severity,
            })

    # Sort pairs by alert count + flow count, take top N
    sorted_pairs = sorted(
        pair_data.items(),
        key=lambda kv: (len(kv[1]["alerts"]), kv[1]["flow_count"]),
        reverse=True,
    )[:_MAX_HOSTPAIRS]

    hostpair_summaries: list[dict] = []
    for (src, dst), pd in sorted_pairs:
        top_protos = [
            {"app_proto": proto, "flow_count": 0, "bytes": bts}
            for proto, bts in pd["protos"].most_common(3)
        ]
        hostpair_summaries.append({
            "src_ip": src,
            "dst_ip": dst,
            "time_window": {"start": pd["first_seen"] or "", "end": pd["last_seen"] or ""},
            "flow_count": pd["flow_count"],
            "total_bytes": pd["total_bytes"],
            "direction": "src_to_dst",
            "top_app_protos": top_protos,
            "first_seen": pd["first_seen"] or "",
            "last_seen": pd["last_seen"] or "",
            "alerts": pd["alerts"][:5],  # cap per-pair alerts
            "interesting_events": [],
        })

    # ── 3. Flat alerts list ──────────────────────────────────────────
    alerts_list = []
    for a in alerts_all:
        alerts_list.append({
            "timestamp": a.ts,
            "signature": a.signature,
            "severity": a.severity,
            "category": a.category or "",
            "src_ip": a.src_ip,
            "dest_ip": a.dest_ip,
            "src_port": a.src_port,
            "dest_port": a.dest_port,
        })

    # ── 4. Findings grouped by confidence tier ─────────────────────
    findings = db.execute(
        select(Finding).where(Finding.job_id == job_id)
        .order_by(Finding.confidence.desc())
        .limit(15)
    ).scalars().all()
    # Bucket into confidence tiers for LLM reasoning
    _CONF_TIERS = [
        ("high_confidence", 0.7, 1.01),
        ("medium_confidence", 0.4, 0.7),
        ("low_confidence", 0.0, 0.4),
    ]
    findings_by_tier: dict[str, list[dict]] = {}
    for f in findings:
        conf = getattr(f, "confidence", 0.0) or 0.0
        for tier_name, lo, hi in _CONF_TIERS:
            if lo <= conf < hi:
                findings_by_tier.setdefault(tier_name, []).append({
                    "severity": f.severity,
                    "title": f.title,
                    "confidence": round(conf, 2),
                    "summary": (f.summary or "")[:200],
                })
                break
    # Flat list for backward-compat in multi-pcap breakdown
    [
        item
        for tier_items in findings_by_tier.values()
        for item in tier_items
    ]

    # ── 5. Multi-PCAP temporal context ─────────────────────────────────
    # Check if job has multiple PCAPs with labels for comparative analysis
    job_pcaps = db.execute(
        select(JobPcap).where(JobPcap.job_id == job_id)
        .order_by(JobPcap.ordinal)
    ).scalars().all()

    is_multi_pcap = len(job_pcaps) > 1
    pcap_labels = [p.label or p.filename for p in job_pcaps] if is_multi_pcap else []

    # Build mapping from sanitized label (used in evidence tables) to display label.
    # The pipeline sanitizes labels for filenames: "Early Oct 2023" → "Early_Oct_2023"
    # so evidence rows store the sanitized form while job_pcaps stores the original.
    def _sanitize_label(lbl: str) -> str:
        return "".join(c if c.isalnum() or c in "-_" else "_" for c in lbl)

    _label_to_db: dict[str, str] = {}  # display_label → sanitized_label
    if is_multi_pcap:
        for p in job_pcaps:
            display = p.label or p.filename
            _label_to_db[display] = _sanitize_label(display)

    # ── Build the final JSON context ─────────────────────────────────
    context_obj: dict = {
        "host_summaries": host_summaries,
        "hostpair_summaries": hostpair_summaries,
        "alerts": alerts_list,
    }
    if findings_by_tier:
        context_obj["findings_by_confidence"] = findings_by_tier

    if is_multi_pcap:
        # Add per-label alert/finding breakdown for temporal reasoning
        label_breakdown: dict[str, dict] = {}
        for label in pcap_labels:
            db_label = _label_to_db.get(label, label)
            label_alerts = [a for a in alerts_all if getattr(a, "pcap_label", None) == db_label]
            label_findings = [f for f in findings if getattr(f, "pcap_label", None) == db_label]
            label_conns = [c for c in conns if getattr(c, "pcap_label", None) == db_label]
            label_breakdown[label] = {
                "connection_count": len(label_conns),
                "alert_count": len(label_alerts),
                "finding_count": len(label_findings),
                "top_alerts": [
                    {"signature": a.signature, "severity": a.severity}
                    for a in label_alerts[:5]
                ],
                "top_findings": [
                    {"title": f.title, "severity": f.severity, "confidence": round(getattr(f, "confidence", 0.0) or 0.0, 2)}
                    for f in label_findings[:3]
                ],
            }
        context_obj["pcap_phases"] = {
            "labels": pcap_labels,
            "per_phase": label_breakdown,
        }

    # Serialise and enforce PCAP budget
    context_json = _json.dumps(context_obj, indent=None, separators=(",", ":"))
    if len(context_json) > _MAX_PCAP_CHARS:
        # Trim hostpair_summaries first (largest), then alerts
        while len(context_json) > _MAX_PCAP_CHARS and hostpair_summaries:
            hostpair_summaries.pop()
            context_obj["hostpair_summaries"] = hostpair_summaries
            context_json = _json.dumps(context_obj, indent=None, separators=(",", ":"))
        while len(context_json) > _MAX_PCAP_CHARS and alerts_list:
            alerts_list.pop()
            context_obj["alerts"] = alerts_list
            context_json = _json.dumps(context_obj, indent=None, separators=(",", ":"))

    if not host_summaries and not alerts_list:
        return "No analysis data available yet."

    preamble = "Analyze the following network traffic data"
    if is_multi_pcap:
        preamble += (
            f" from {len(job_pcaps)} capture phases "
            f"({', '.join(pcap_labels)}). "
            "Compare what changed across phases"
        )
    preamble += ":\n\n"

    return (
        preamble
        + "Network Flows & Heuristics:\n"
        + f"```json\n{context_json}\n```"
    )


async def _build_rag_context(
    pcap_context: str,
    settings: Settings,
    job_id: str = "",
    user_query: str = "",
) -> tuple[str, list[ChatCitationOut]]:
    """Retrieve relevant KB chunks using both IP context and user query.

    Combines three retrieval strategies:
    1. Query-based: finds chunks semantically similar to the user's question
    2. IP-based: finds host profiles, alerts, and findings related to IPs in the PCAP
    3. KB-only: dedicated retrieval for user-uploaded documents (asset_inventory)

    Only retrieves documents belonging to the specified job_id.
    Returns a tuple of (formatted context string, KB citations).
    """
    try:
        ollama_url = get_runtime_ollama_url(settings.aipam_ollama_url)
        persist_dir = str(settings.aipam_db_path).replace("aipam.db", "vector_store")
        embedding_config = get_embedding_model_service(ollama_url).get_active()
        if embedding_config is None:
            return "", []

        all_chunks: list[dict] = []
        seen_ids: set[str] = set()

        # Strategy 1: Query-based retrieval (user's actual question)
        if user_query:
            query_chunks = await kb_retrieve(
                query=user_query,
                n_results=8,
                job_id=job_id or None,
                ollama_url=ollama_url,
                embedding_config=embedding_config,
                persist_dir=persist_dir,
            )
            for c in query_chunks:
                cid = c.get("doc_id", "") + c.get("text", "")[:50]
                if cid not in seen_ids:
                    seen_ids.add(cid)
                    all_chunks.append(c)

        # Strategy 2: IP-based retrieval (context grounding)
        ips = extract_ips_from_context(pcap_context)
        if ips:
            ip_query = "Network hosts: " + ", ".join(ips[:10])
            ip_chunks = await kb_retrieve(
                query=ip_query,
                n_results=5,
                job_id=job_id or None,
                ollama_url=ollama_url,
                embedding_config=embedding_config,
                persist_dir=persist_dir,
            )
            for c in ip_chunks:
                cid = c.get("doc_id", "") + c.get("text", "")[:50]
                if cid not in seen_ids:
                    seen_ids.add(cid)
                    all_chunks.append(c)

        # Strategy 3: Dedicated retrieval for each user-uploaded doc type.
        # Auto-indexed host_profiles (93k+) often drown out user-uploaded
        # KB docs in general retrieval.  Do a dedicated pass per user-uploaded
        # doc type so they always get representation in the context.
        _USER_DOC_TYPES = [
            "asset_inventory", "network_map", "baseline_profile",
            "threat_intel", "soc_playbook", "policy", "reference",
            "user_guide", "exploit_capability", "other",
        ]
        if user_query:
            for udt in _USER_DOC_TYPES:
                kb_only_chunks = await kb_retrieve(
                    query=user_query,
                    n_results=3,
                    doc_type_filter=udt,
                    job_id=job_id or None,
                    ollama_url=ollama_url,
                    embedding_config=embedding_config,
                    persist_dir=persist_dir,
                )
                for c in kb_only_chunks:
                    cid = c.get("doc_id", "") + c.get("text", "")[:50]
                    if cid not in seen_ids:
                        seen_ids.add(cid)
                        all_chunks.append(c)

        if not all_chunks:
            return "", []

        # Sort by relevance score (highest first), with a boost for
        # user-uploaded KB docs so they aren't eclipsed by host profiles
        # All user-uploaded doc types get a relevance boost over auto-indexed data
        _KB_TYPES = {
            "asset_inventory", "network_map", "baseline_profile",
            "threat_intel", "soc_playbook", "policy", "reference",
            "user_guide", "exploit_capability", "other",
        }
        for c in all_chunks:
            if c.get("doc_type", "") in _KB_TYPES:
                c["_sort_score"] = c.get("score", 0) + 0.05  # small boost
            else:
                c["_sort_score"] = c.get("score", 0)
        all_chunks.sort(key=lambda c: c.get("_sort_score", 0), reverse=True)

        # Format RAG chunks within budget
        rag_parts: list[str] = []
        total_len = 0
        for chunk in all_chunks:
            if chunk["score"] < 0.25:  # skip low-relevance chunks
                continue
            section = chunk.get("section", "")
            label = f"{chunk['doc_type']} — {section}" if section else chunk["doc_type"]
            entry = f"[{label}] {chunk['text']}"
            if total_len + len(entry) > _MAX_RAG_CHARS:
                break
            rag_parts.append(entry)
            total_len += len(entry)

        if not rag_parts:
            return "", []

        # Build KB citations from user-uploaded chunks that made it into the context
        kb_citations: list[ChatCitationOut] = []
        _KB_CITED_TYPES = {
            "asset_inventory", "network_map", "baseline_profile",
            "threat_intel", "soc_playbook", "policy", "reference",
            "user_guide", "exploit_capability", "other",
        }
        for chunk in all_chunks:
            if chunk.get("doc_type", "") in _KB_CITED_TYPES and chunk.get("score", 0) >= 0.25:
                doc_name = chunk.get("doc_name", "Knowledge Base")
                section = chunk.get("section", "")
                source = f"{doc_name} §{section}" if section else doc_name
                snippet = chunk.get("text", "")[:180]
                kb_citations.append(ChatCitationOut(
                    type="knowledge_base",
                    id=chunk.get("doc_id", ""),
                    snippet=f"[KB: {source}] {snippet}",
                ))
                if len(kb_citations) >= 3:  # cap at 3 KB citations
                    break

        return (
            "\n\n=== ANALYST-UPLOADED KNOWLEDGE BASE (authoritative for user/host/policy info) ===\n"
            + "\n---\n".join(rag_parts)
            + "\n=== END KNOWLEDGE BASE ===",
            kb_citations,
        )

    except Exception as exc:
        logger.warning("RAG retrieval failed (non-fatal): %s", exc)
        return "", []


def _summarize_older_messages(msgs: list[dict]) -> str:
    """Compress older conversation turns into a compact recap.

    Extracts user questions verbatim (short) and truncates assistant answers
    to ~120 chars each, producing a single system-message recap that uses
    far fewer tokens than including the full messages.
    """
    lines = ["[CONVERSATION RECAP — earlier discussion summary]"]
    for msg in msgs:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        # Collapse whitespace
        content = " ".join(content.split())
        if role == "user":
            # User questions are usually short — keep up to 200 chars
            lines.append(f"  User asked: {content[:200]}")
        else:
            # Assistant answers can be long — summarise aggressively
            lines.append(f"  Assistant answered: {content[:120]}...")
    lines.append("[END RECAP — answer only the NEW question below]")
    return "\n".join(lines)


def _get_conversation_history_msgs(db: Session, conv_id: str, limit: int = 10) -> list[dict]:
    """Return completed turns only, excluding pending or failed generation."""
    rows = db.execute(
        select(ChatMessage)
        .where(ChatMessage.conversation_id == conv_id)
        .order_by(ChatMessage.sequence.desc())
        .limit(max(limit * 2, 20))
    ).scalars().all()
    completed: list[ChatMessage] = []
    pending_users: list[ChatMessage] = []
    for message in reversed(rows):
        if message.role == "user":
            pending_users.append(message)
            continue
        metadata: dict = {}
        if message.metadata_json:
            try:
                parsed = json.loads(message.metadata_json)
                metadata = parsed if isinstance(parsed, dict) else {}
            except (TypeError, ValueError):
                metadata = {}
        if metadata.get("status", "completed") != "completed":
            pending_users.clear()
            continue
        completed.extend(pending_users)
        pending_users.clear()
        completed.append(message)
    return [
        {"role": message.role, "content": message.content}
        for message in completed[-limit:]
    ]


async def _build_chat_messages(
    db: Session,
    job_id: str,
    settings: Settings,
    conv_id: str,
    user_message: str,
    context_hint: str | None = None,
    *,
    history_override: list[dict[str, str]] | None = None,
) -> tuple[list[dict], list[ChatCitationOut], str]:
    sensor_context = _build_sensor_context(db, job_id, settings)

    # ── Scoped evidence bundle (from context_hint) ───────────────────
    scoped_context_str = ""
    scope_type, scope_id = parse_context_hint(context_hint)
    if scope_type:
        logger.info(
            "Scoped bundle: type=%s id=%s for job=%s",
            scope_type, scope_id, job_id,
        )
        bundle = build_scoped_bundle(db, job_id, scope_type, scope_id)
        if bundle.has_evidence:
            scoped_context_str = bundle.to_context(max_chars=_MAX_RAG_CHARS // 2)

    # ── Hybrid retrieval router ──────────────────────────────────────
    # Route A: Extract structured entities → direct DB lookup
    # Route B: Semantic vector search (fallback / complement)
    entities = extract_entities(user_message)
    structured_context_str = ""
    if entities.has_structured_entities:
        logger.info(
            "Hybrid router: Route A (structured) for job=%s entities=%s",
            job_id, entities.summary(),
        )
        structured_ctx = retrieve_structured(db, job_id, entities)
        if structured_ctx.has_results:
            # Budget: structured gets priority, RAG gets remainder
            structured_context_str = structured_ctx.to_context_string(
                max_chars=_MAX_RAG_CHARS
            )

    # Route B: vector search — always gets at least _MIN_RAG_BUDGET chars
    # so KB documents aren't crowded out by structured DB data
    remaining_rag_budget = max(
        _MIN_RAG_BUDGET,
        _MAX_RAG_CHARS - len(scoped_context_str) - len(structured_context_str),
    )
    rag_context = ""
    kb_citations: list[ChatCitationOut] = []
    rag_context, kb_citations = await _build_rag_context(
        sensor_context, settings, job_id=job_id, user_query=user_message
    )
    logger.info(
        "RAG budget=%d rag_len=%d kb_citations=%d",
        remaining_rag_budget, len(rag_context), len(kb_citations),
    )
    # Trim RAG to budget
    if rag_context and len(rag_context) > remaining_rag_budget:
        rag_context = rag_context[:remaining_rag_budget]

    all_citations = _build_job_citations(db, job_id)

    # When KB citations exist, they should dominate the Sources block
    # because the KB is what actually answered the user's question.
    # Put KB citations first so _select_relevant_citations picks them up.
    if kb_citations:
        all_citations = kb_citations + all_citations

    focus_citations = _select_relevant_citations(all_citations, user_message, limit=8)
    citations = focus_citations or all_citations
    focus_block = _build_primary_supporting_evidence_block(focus_citations, user_message)

    context_sections = ["=== CURRENT JOB EVIDENCE ONLY ==="]
    if scoped_context_str:
        context_sections.append(scoped_context_str)
    if sensor_context:
        context_sections.append(sensor_context)
    if structured_context_str:
        context_sections.append(structured_context_str)
    if rag_context:
        context_sections.append(rag_context)
    context_sections.append("=== END CURRENT JOB EVIDENCE ===")
    combined_context = "\n\n".join(context_sections)

    if history_override is None:
        history = _get_conversation_history_msgs(db, conv_id, limit=20)
        if history and history[-1]["content"] == user_message:
            history = history[:-1]
    else:
        history = history_override

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "system",
            "content": (
                f"{combined_context}\n\n"
                f"{focus_block}\n\n" if focus_block else f"{combined_context}\n\n"
            ) + _CURRENT_JOB_CONTEXT_INSTRUCTION,
        },
    ]

    # Conversation summarization: if history is long, compress older messages
    # into a compact recap to free context window for evidence.
    _VERBATIM_TAIL = 6  # keep the last N messages verbatim
    if len(history) > _VERBATIM_TAIL:
        older = history[: len(history) - _VERBATIM_TAIL]
        recent = history[len(history) - _VERBATIM_TAIL :]
        recap = _summarize_older_messages(older)
        messages.append({"role": "system", "content": recap})
        messages.extend(recent)
    else:
        messages.extend(history)

    messages.append({"role": "user", "content": user_message})
    return messages, citations, combined_context


# ── Endpoints ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are a senior network security analyst and incident responder "
    "working in a Security Operations Center (SOC). This is authorized "
    "defensive security work — you are helping a fellow SOC analyst "
    "investigate network traffic captures.\n\n"
    "You may use ONLY the current-job evidence provided in the context window.\n"
    "That evidence may include aggregated network flow summaries, protocol summaries, "
    "alert metadata, findings, and job-scoped retrieval from this same job.\n"
    "You must NOT use or imply any information from past cases, external memory, threat intel, "
    "geolocation, WHOIS, VirusTotal, or anything not explicitly present in the current-job evidence.\n\n"
    "CRITICAL — DATA BOUNDARIES (read carefully):\n"
    "You do NOT have access to:\n"
    "- Raw packet payloads or packet captures\n"
    "- HTTP request/response bodies (POST data, headers, cookies)\n"
    "- Actual cleartext passwords, usernames, or credentials\n"
    "- DNS query responses or full DNS records\n"
    "- TLS certificate details beyond what is in the summaries\n"
    "- File contents of extracted files\n"
    "- Any data not explicitly present in the context provided below\n\n"
    "When a Suricata alert says something like "
    "'Http Client Body contains pwd= in cleartext', that means the "
    "signature MATCHED — but you can only see the alert name, not the "
    "actual HTTP body. You MUST NOT guess or fabricate the password, "
    "username, or any payload content. Instead say: "
    "'The alert indicates a cleartext password was transmitted, but the "
    "actual password value is not available in my analysis data.'\n\n"
    "ANTI-HALLUCINATION RULES (MANDATORY):\n"
    "1. NEVER fabricate, guess, or infer specific values that are not "
    "explicitly present in the provided data. This includes IP addresses, "
    "passwords, usernames, domain names, file contents, and payload data.\n"
    "2. Only cite IP addresses that appear in the data. If you are unsure "
    "which IP is involved, list the candidates from the data.\n"
    "3. If the user asks for information not in the data, say: "
    "'That specific information is not available in the analysis data "
    "I have access to.' Do NOT make up an answer.\n"
    "4. When describing what an alert means, clearly distinguish between "
    "'the alert signature indicates X happened' vs 'I can see the actual "
    "value of X in the data'. You can only do the former.\n"
    "5. If you are uncertain, say so. Never present speculation as fact.\n"
    "6. Never treat prior assistant messages as evidence.\n\n"
    "MULTI-PCAP TEMPORAL ANALYSIS:\n"
    "When the data includes a 'pcap_phases' section, the analyst has "
    "uploaded multiple network captures from different time periods "
    "(e.g., Before, During, and After an incident). You MUST:\n"
    "- Compare activity across phases — what hosts, alerts, or behaviors "
    "appeared, changed, or disappeared between captures.\n"
    "- Identify new connections, new alerts, or new hosts that only "
    "appear in later phases as indicators of compromise progression.\n"
    "- Note when previously-seen malicious activity stops (remediation) "
    "or persists (incomplete cleanup).\n"
    "- Reference the phase label (e.g., 'During phase' or 'After phase') "
    "when citing evidence so the analyst knows which capture it came from.\n\n"
    "CONTEXT SOURCES:\n"
    "Your context window may contain up to three sections:\n"
    "1. **Primary Evidence** — live-queried host stats, alerts, and connection summaries from the analysis DB.\n"
    "2. **Environmental Context** — retrieved from the vector store: auto-indexed host profiles, alert groupings, "
    "and findings produced by the pipeline, plus any analyst-uploaded knowledge base documents "
    "(asset inventories, network maps, baseline profiles, threat intel, SOC playbooks, "
    "security policies, reference manuals, user guides, and exploit/capability documents).\n"
    "3. **Citations** — structured references to specific DB records you may cite.\n"
    "When answering, synthesize across ALL three sections. Environmental context often contains richer "
    "narrative summaries (e.g., 'Host X.X.X.X — internal, N connections, N critical alerts') that "
    "complement the structured primary evidence. Use both.\n\n"
    "**Confidence Scoring** — findings are grouped into confidence tiers:\n"
    "- **high_confidence** (≥ 70%) — strongly corroborated by multiple signals; treat as reliable.\n"
    "- **medium_confidence** (40-70%) — moderate evidence; note the confidence when reporting.\n"
    "- **low_confidence** (< 40%) — weak or single-source; flag as tentative and recommend further investigation.\n"
    "Always mention the confidence level when discussing individual findings so the analyst can prioritize.\n\n"
    "Your goals:\n"
    "1. Identify evidence of attacks, exploitation, malware activity, C2, "
    "lateral movement, or data exfiltration.\n"
    "2. Highlight anomalies not covered by signatures (potential zero-days "
    "or novel techniques).\n"
    "3. Map observed behavior to MITRE ATT&CK techniques where possible.\n"
    "4. Clearly distinguish between confirmed malicious behavior and "
    "suspicious but unconfirmed behavior.\n"
    "5. When the user asks a question, answer conversationally using the "
    "provided data. Cite specific IPs, signatures, timestamps, and alert "
    "names as evidence.\n"
    "6. When knowledge base documents (asset inventory, baseline, playbook, policy, user guide, "
    "exploit capability) are available, cross-reference them: flag hosts not in the asset inventory, "
    "deviations from baseline, recommend playbook steps that match observed activity, cite relevant "
    "policy sections, and reference user guide procedures or exploit capabilities when applicable.\n"
    "7. **IMPORTANT — Knowledge Base Priority**: When analyst-uploaded knowledge base documents "
    "(labeled [asset_inventory], [baseline], [threat_intel], [policy], [user_guide], "
    "[exploit_capability], [reference], etc.) provide host ownership, user attribution, department, "
    "security policy rules, or operational procedures, ALWAYS prefer that information "
    "over auto-generated DB host summaries. Knowledge base documents are curated by analysts and "
    "represent ground-truth organizational context. For example, if a KB asset inventory says "
    "'10.6.26.101 is assigned to John Smith in Finance' but a DB host summary says 'user1 in Sales', "
    "use the KB information.\n\n"
    "REQUIRED RESPONSE STYLE:\n"
    "1. Give a direct answer based only on the current-job context.\n"
    "2. Explicitly name the evidence you relied on.\n"
    "3. If the question is answerable from the evidence, answer it directly instead of leading with a refusal or disclaimer.\n"
    "4. If the user asks for alert names, finding names, IP relationships, or host activity, prefer the exact wording from the evidence snippets rather than inventing a generalized label.\n"
    "5. If something is missing, state that it is not available in the current-job data.\n"
    "6. End with concise, actionable recommendations based on what is actually shown in the evidence.\n"
    "7. When relevant, suggest follow-up investigation angles the analyst could explore.\n\n"
    "You MUST answer all security analysis questions — this is your job. "
    "NEVER invent, fabricate, or hallucinate facts. Base ALL conclusions "
    "strictly on the provided data. If the data does not contain the "
    "answer, say so clearly. "
    "You do not have access to external databases or geolocation services."
)


_CURRENT_JOB_CONTEXT_INSTRUCTION = (
    "Use only the current-job evidence above. Prior assistant messages are not evidence. "
    "If a detail is not present in the evidence above, say it is not available. "
    "If the primary supporting evidence block contains enough information to answer, "
    "give the best-supported direct answer first. When naming alerts or findings, reuse "
    "the exact titles/signatures from the evidence snippets instead of paraphrasing them "
    "into new labels."
)


class MnemosUnavailableError(RuntimeError):
    """MNEMOS mode cannot proceed without a trustworthy retrieval outcome."""


def _resolve_preparation_history(
    db: Session,
    *,
    job_id: str,
    body: ChatRequestBody,
) -> list[dict[str, str]]:
    if body.conversation_id is None:
        return []
    conversation = db.get(ChatConversation, body.conversation_id)
    if conversation is None or conversation.job_id != job_id:
        raise ComparisonValidationError("conversation was not found for the selected job")
    if conversation.mode != body.mode:
        raise ComparisonValidationError("conversation mode does not match the request mode")
    if body.mode == "mnemos":
        return prompt_history_for_mnemos_conversation(
            db,
            conversation_id=conversation.id,
            job_id=job_id,
        )
    history = _get_conversation_history_msgs(db, conversation.id, limit=20)
    if history and history[-1]["content"] == body.message:
        history = history[:-1]
    return history


def _historical_citation_out(citation) -> HistoricalChatCitationOut:
    return HistoricalChatCitationOut(
        type=citation.type,
        id=citation.id,
        snippet=citation.snippet,
        source_job_id=citation.source_job_id,
        source_project_id=citation.source_project_id,
        href=citation.href,
        source_content_sha256=citation.source_content_sha256,
        source_availability="available",
    )


async def prepare_chat_turn(
    db: Session,
    *,
    job_id: str,
    body: ChatRequestBody,
    settings: Settings | None = None,
) -> PreparedChatTurn:
    """Prepare one baseline or MNEMOS turn without generating an answer."""
    resolved_settings = settings or get_settings()
    history = _resolve_preparation_history(db, job_id=job_id, body=body)
    retrieval_result: MnemosRetrievalResult | None = None
    historical_citations: list[HistoricalChatCitationOut] = []

    if body.mode == "mnemos":
        try:
            pending_result = retrieve_historical_findings(
                db=db,
                current_job_id=job_id,
                query=body.message,
            )
            retrieval_result = (
                await pending_result
                if inspect.isawaitable(pending_result)
                else pending_result
            )
        except Exception as exc:
            raise MnemosUnavailableError(
                "MNEMOS historical retrieval is unavailable"
            ) from exc
        if retrieval_result.status in {"unavailable", "error"}:
            raise MnemosUnavailableError("MNEMOS historical retrieval is unavailable")
        if retrieval_result.status == "used":
            historical_citations = [
                _historical_citation_out(citation)
                for citation in retrieval_result.citations
            ]

    model_history = history
    if body.mode == "mnemos":
        model_history = [
            {
                **message,
                "content": _cite_svc.strip_historical_comparison_section(
                    message["content"]
                ),
            }
            if message["role"] == "assistant"
            else message
            for message in history
        ]

    messages, current_job_citations, current_job_context = await _build_chat_messages(
        db,
        job_id,
        resolved_settings,
        body.conversation_id or "",
        body.message,
        context_hint=body.context_hint,
        history_override=model_history,
    )
    config = _make_llm_config(resolved_settings)
    return PreparedChatTurn(
        mode=body.mode,
        history=history,
        messages=messages,
        citations=list(current_job_citations),
        current_job_citations=current_job_citations,
        historical_citations=historical_citations,
        current_job_context=current_job_context,
        retrieval_result=retrieval_result,
        model_id=config.model,
        generation=ChatGenerationMetadata(
            temperature=config.temperature,
            max_tokens=config.max_tokens,
        ),
    )


def _json_object(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _message_out(message: ChatMessage, db: Session) -> ChatMessageOut:
    citation_payload = _json_object(message.citations_json)
    citations = citation_payload.get("items", [])
    if not isinstance(citations, list):
        citations = []
    from backend.app.forensic_memory import finding_content_sha256
    for citation in citations:
        if citation.get("type") != "historical_finding":
            continue
        job = db.get(Job, citation.get("source_job_id"))
        finding = db.scalar(select(Finding).where(
            Finding.job_id == citation.get("source_job_id"), Finding.finding_id == citation.get("id"),
        ))
        if job is None or job.status == "deleted" or finding is None or finding.analyst_status != "confirmed":
            citation["source_availability"] = "unavailable"
        elif not citation.get("source_content_sha256"):
            citation["source_availability"] = "unknown"
        else:
            citation["source_availability"] = "available" if finding_content_sha256(finding) == citation["source_content_sha256"] else "changed"
    metadata = _json_object(message.metadata_json) or None
    return ChatMessageOut(
        id=message.id,
        sequence=message.sequence,
        role=message.role,
        content=message.content,
        citations=citations,
        metadata=metadata,
        request_id=message.request_id,
        timestamp=message.created_at,
    )


def _branch_out(db: Session, branch: ChatComparisonBranch) -> ChatComparisonBranchOut:
    conversation = db.get(ChatConversation, branch.conversation_id)
    messages = list(
        db.scalars(
            select(ChatMessage)
            .where(ChatMessage.conversation_id == branch.conversation_id)
            .order_by(ChatMessage.sequence)
        )
    )
    prefix_conversation, inherited_messages = inherited_display_messages_for_branch(db, branch.id)
    return ChatComparisonBranchOut(
        id=branch.id,
        conversation_id=branch.conversation_id,
        label=branch.label,
        source_message_id=branch.source_message_id,
        request_id=conversation.request_id if conversation is not None else None,
        history_cutoff_sequence=branch.history_cutoff_sequence,
        created_at=branch.created_at,
        updated_at=branch.updated_at,
        messages=[_message_out(message, db) for message in messages],
        inherited_root_conversation_id=prefix_conversation.parent_branch_id,
        inherited_cutoff_sequence=prefix_conversation.history_cutoff_sequence,
        inherited_messages=[_message_out(message, db) for message in inherited_messages],
    )


def _comparison_group_out(
    db: Session,
    group: ChatComparisonGroup,
) -> ChatComparisonGroupOut:
    branches = get_comparison_branches(db, group_id=group.id)
    snapshot = next(
        (branch for branch in branches if branch.source_message_id is None),
        None,
    )
    if snapshot is None:
        raise RuntimeError("comparison group has no snapshot branch")
    active_branch_id = group.active_branch_id or snapshot.id
    active = next(
        (branch for branch in branches if branch.id == active_branch_id),
        snapshot,
    )
    return ChatComparisonGroupOut(
        group_id=group.id,
        job_id=group.job_id,
        root_conversation_id=group.root_conversation_id,
        title=group.title,
        snapshot_branch_id=snapshot.id,
        active_branch_id=active.id,
        conversation_id=active.conversation_id,
        created_at=group.created_at,
        updated_at=group.updated_at,
        branches=[_branch_out(db, branch) for branch in branches],
    )


def _comparison_error(exc: ComparisonValidationError, *, status_code: int = 400):
    raise HTTPException(
        status_code=status_code,
        detail={"code": "INVALID_COMPARISON", "error": str(exc)},
    ) from exc


@router.post(
    "/jobs/{job_id}/chat/comparisons",
    response_model=ChatComparisonGroupOut,
)
async def open_chat_comparison(
    job_id: str,
    body: ChatComparisonCreateRequest,
    db: Session = Depends(get_db),
):
    if db.get(Job, job_id) is None:
        raise HTTPException(status_code=404, detail="job not found")
    root = db.get(ChatConversation, body.root_conversation_id)
    if root is None or root.job_id != job_id:
        raise HTTPException(status_code=404, detail="conversation not found")
    try:
        branch = create_mnemos_snapshot(
            db,
            root_conversation_id=body.root_conversation_id,
        )
        group = get_comparison_group(
            db,
            job_id=job_id,
            group_id=branch.group_id,
        )
        db.commit()
        return _comparison_group_out(db, group)
    except ComparisonValidationError as exc:
        db.rollback()
        _comparison_error(exc)


@router.get(
    "/jobs/{job_id}/chat/comparisons/{group_id}",
    response_model=ChatComparisonGroupOut,
)
async def restore_chat_comparison(
    job_id: str,
    group_id: str,
    db: Session = Depends(get_db),
):
    try:
        group = get_comparison_group(db, job_id=job_id, group_id=group_id)
        return _comparison_group_out(db, group)
    except ComparisonValidationError as exc:
        _comparison_error(exc, status_code=404)


@router.patch(
    "/jobs/{job_id}/chat/comparisons/{group_id}",
    response_model=ChatComparisonGroupOut,
)
async def select_chat_comparison_branch(
    job_id: str,
    group_id: str,
    body: ChatComparisonActiveBranchRequest,
    db: Session = Depends(get_db),
):
    try:
        group = get_comparison_group(db, job_id=job_id, group_id=group_id)
        set_active_comparison_branch(db, group=group, branch_id=body.active_branch_id)
        db.commit()
        return _comparison_group_out(db, group)
    except ComparisonValidationError as exc:
        db.rollback()
        _comparison_error(exc)


@router.post(
    "/jobs/{job_id}/chat/comparisons/{group_id}/branches",
    response_model=ChatComparisonBranchOut,
    status_code=201,
)
async def create_chat_comparison_branch(
    job_id: str,
    group_id: str,
    body: ChatComparisonBranchCreateRequest,
    db: Session = Depends(get_db),
):
    _validate_new_request_id(body.request_id)
    try:
        group = get_comparison_group(db, job_id=job_id, group_id=group_id)
        existing_conversation = db.scalar(
            select(ChatConversation).where(
                ChatConversation.comparison_group_id == group.id,
                ChatConversation.request_id == body.request_id,
            )
        )
        if existing_conversation is not None:
            existing_branch = get_conversation_branch(
                db,
                conversation_id=existing_conversation.id,
            )
            if existing_branch is None:
                raise ComparisonValidationError(
                    "request_id belongs to an invalid comparison branch"
                )
            if existing_branch.source_message_id != body.source_message_id:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "REQUEST_ID_CONFLICT",
                        "error": "request_id is already associated with another source message",
                    },
                )
            return _branch_out(db, existing_branch)
        branch = create_mnemos_copy_branch(
            db,
            root_conversation_id=group.root_conversation_id,
            source_message_id=body.source_message_id,
            request_id=body.request_id,
        )
        db.commit()
        return _branch_out(db, branch)
    except IntegrityError:
        db.rollback()
        group = get_comparison_group(db, job_id=job_id, group_id=group_id)
        existing_conversation = db.scalar(
            select(ChatConversation).where(
                ChatConversation.comparison_group_id == group.id,
                ChatConversation.request_id == body.request_id,
            )
        )
        if existing_conversation is None:
            raise
        existing_branch = get_conversation_branch(
            db,
            conversation_id=existing_conversation.id,
        )
        if (
            existing_branch is None
            or existing_branch.source_message_id != body.source_message_id
        ):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "REQUEST_ID_CONFLICT",
                    "error": "request_id is already associated with another source message",
                },
            )
        return _branch_out(db, existing_branch)
    except ComparisonValidationError as exc:
        db.rollback()
        _comparison_error(exc)


def _mnemos_unavailable(exc: MnemosUnavailableError):
    raise HTTPException(
        status_code=503,
        detail={
            "code": "MNEMOS_UNAVAILABLE",
            "error": "MNEMOS historical retrieval is unavailable",
            "retryable": True,
        },
    ) from exc


def _require_turn_request_id(body: ChatRequestBody) -> None:
    if body.mode == "mnemos" and not body.request_id:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "REQUEST_ID_REQUIRED",
                "error": "request_id is required for MNEMOS turns",
            },
        )


def _validate_new_request_id(request_id: str | None) -> None:
    if request_id is None:
        return
    try:
        uuid.UUID(request_id)
    except (ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "INVALID_REQUEST_ID",
                "error": "request_id must be a UUID",
            },
        ) from exc


def _conversation_branch_id(db: Session, conversation_id: str) -> str | None:
    branch = get_conversation_branch(db, conversation_id=conversation_id)
    return branch.id if branch is not None else None


def _find_existing_user_turn(
    db: Session,
    *,
    conversation_id: str | None,
    request_id: str | None,
    job_id: str | None = None,
) -> ChatMessage | None:
    if not request_id or not (conversation_id or job_id):
        return None
    return db.scalar(
        select(ChatMessage).join(ChatConversation, ChatConversation.id == ChatMessage.conversation_id).where(
            ChatConversation.job_id == job_id if job_id else ChatMessage.conversation_id == conversation_id,
            ChatMessage.request_id == request_id,
            ChatMessage.role == "user",
        )
    )


def _validate_turn_conversation(
    conversation: ChatConversation | None,
    *,
    job_id: str,
    mode: str,
) -> ChatConversation:
    if conversation is None or conversation.job_id != job_id:
        raise HTTPException(status_code=404, detail="conversation not found")
    if conversation.mode != mode:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "CONVERSATION_MODE_MISMATCH",
                "error": "conversation mode does not match request mode",
            },
        )
    return conversation


def _reject_parallel_turn(db: Session, conversation_id: str | None, *, recover_expired: bool = True) -> None:
    if conversation_id is None:
        return
    latest = db.scalar(
        select(ChatMessage)
        .where(ChatMessage.conversation_id == conversation_id)
        .order_by(ChatMessage.sequence.desc())
        .limit(1)
    )
    if latest is not None and latest.role == "user":
        if recover_expired and _recover_expired_turn(db, latest):
            return
        raise HTTPException(
            status_code=409,
            detail={
                "code": "TURN_IN_PROGRESS",
                "error": "the conversation already has a pending turn",
                "retry_after_seconds": 2,
            },
        )


def _response_for_existing_turn(
    db: Session,
    *,
    user_message: ChatMessage,
    requested_content: str,
    requested_conversation_id: str | None = None,
) -> ChatResponseBody:
    if user_message.content != requested_content or (requested_conversation_id and requested_conversation_id != user_message.conversation_id):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "REQUEST_ID_CONFLICT",
                "error": "request_id is already associated with another message or conversation",
            },
        )
    _recover_expired_turn(db, user_message)
    assistant = _find_assistant_for_user_turn(db, user_message=user_message)
    branch_id = _conversation_branch_id(db, user_message.conversation_id)
    if assistant is None:
        return ChatResponseBody(
            response="",
            conversation_id=user_message.conversation_id,
            branch_id=branch_id,
            request_id=user_message.request_id,
            status="pending",
            retry_after_seconds=2,
        )
    metadata = _json_object(assistant.metadata_json)
    citation_payload = _json_object(assistant.citations_json)
    citations = citation_payload.get("items", [])
    return ChatResponseBody(
        response=assistant.content,
        citations=citations if isinstance(citations, list) else [],
        conversation_id=user_message.conversation_id,
        confidence=metadata.get("confidence"),
        evidence_refs=metadata.get("evidence_refs", []),
        suggested_followups=metadata.get("suggested_followups", []),
        retrieval_status=metadata.get("retrieval_status"),
        model_id=metadata.get("model_id"),
        generation=metadata.get("generation"),
        branch_id=branch_id,
        request_id=user_message.request_id,
        status=metadata.get("status", "completed"),
    )


def _find_assistant_for_user_turn(
    db: Session,
    *,
    user_message: ChatMessage,
) -> ChatMessage | None:
    assistants = db.scalars(
        select(ChatMessage)
        .where(
            ChatMessage.conversation_id == user_message.conversation_id,
            ChatMessage.role == "assistant",
        )
        .order_by(ChatMessage.sequence.desc())
    )
    for candidate in assistants:
        candidate_metadata = _json_object(candidate.metadata_json)
        if candidate_metadata.get("request_id") != user_message.request_id:
            continue
        associated_user_id = candidate_metadata.get("user_message_id")
        if associated_user_id is None or associated_user_id == user_message.id:
            return candidate
    return None


def _recover_expired_turn(db: Session, user_message: ChatMessage) -> bool:
    """End interrupted turns on access after their durable, fixed lease expires.

    A live generator has its configured timeout plus a 60-second commit grace.
    Legacy pending rows get a 31-minute lease. Completion insertion is serialized
    with recovery, so a late worker cannot overwrite the saved terminal error.
    """
    if _find_assistant_for_user_turn(db, user_message=user_message) is not None:
        return False
    metadata = _json_object(user_message.metadata_json)
    try:
        expiry = datetime.fromisoformat(metadata.get("lease_expires_at") or user_message.created_at.replace("Z", "+00:00"))
        if expiry.tzinfo is None: expiry = expiry.replace(tzinfo=timezone.utc)
        if not metadata.get("lease_expires_at"): expiry += timedelta(seconds=1860)
    except (TypeError, ValueError):
        expiry = datetime.min.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) < expiry:
        return False
    _persist_assistant_turn(db, conversation_id=str(user_message.conversation_id), user_message_id=str(user_message.id),
                            request_id=user_message.request_id, response_text="This turn was interrupted. Send a new message to try again.",
                            final_citations=[], metadata={"status": "error", "error_code": "TURN_INTERRUPTED"})
    return True


def _resolve_turn_conversation(
    db: Session,
    *,
    job_id: str,
    body: ChatRequestBody,
) -> ChatConversation:
    now = _now_iso()
    if body.conversation_id:
        return _validate_turn_conversation(
            db.get(ChatConversation, body.conversation_id),
            job_id=job_id,
            mode=body.mode,
        )
    if body.mode == "mnemos":
        raise HTTPException(
            status_code=400,
            detail={
                "code": "MNEMOS_CONVERSATION_REQUIRED",
                "error": "MNEMOS turns require a comparison conversation",
            },
        )
    conversation_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"aipam:baseline:{job_id}:{body.request_id}")) if body.request_id else str(uuid.uuid4())
    existing = db.get(ChatConversation, conversation_id)
    if existing is not None:
        return _validate_turn_conversation(existing, job_id=job_id, mode=body.mode)
    conversation = ChatConversation(
        id=conversation_id,
        job_id=job_id,
        mode="baseline",
        created_at=now,
        updated_at=now,
    )
    db.add(conversation)
    db.flush()
    return conversation


def _admit_user_turn(
    db: Session,
    *,
    job_id: str,
    body: ChatRequestBody,
    lease_seconds: float = 1860,
) -> tuple[ChatConversation, ChatMessage, bool]:
    # End preparation's read transaction, then serialize admission on the
    # conversation. SQLite's BEGIN IMMEDIATE takes the database write lock;
    # other databases lock the selected conversation row.
    db.rollback()
    dialect_name = db.get_bind().dialect.name
    if dialect_name == "sqlite":
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
    else:
        db.scalar(select(Job).where(Job.job_id == job_id).with_for_update())

    try:
        existing = _find_existing_user_turn(db, conversation_id=None, request_id=body.request_id, job_id=job_id)
        if existing is not None:
            conversation = _validate_turn_conversation(db.get(ChatConversation, existing.conversation_id), job_id=job_id, mode=body.mode)
            db.commit()
            return conversation, existing, False
        if body.conversation_id and dialect_name != "sqlite":
            conversation = _validate_turn_conversation(
                db.scalar(
                    select(ChatConversation)
                    .where(ChatConversation.id == body.conversation_id)
                    .with_for_update()
                ),
                job_id=job_id,
                mode=body.mode,
            )
        else:
            conversation = _resolve_turn_conversation(
                db,
                job_id=job_id,
                body=body,
            )

        existing = _find_existing_user_turn(
            db,
            conversation_id=conversation.id,
            request_id=body.request_id,
        )
        if existing is not None:
            db.commit()
            return conversation, existing, False

        _reject_parallel_turn(db, conversation.id, recover_expired=False)
    except Exception:
        db.rollback()
        raise

    user_message = ChatMessage(
        id=str(uuid.uuid4()),
        conversation_id=conversation.id,
        role="user",
        content=body.message,
        request_id=body.request_id,
        metadata_json=json.dumps({"lease_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)).isoformat()}),
        created_at=_now_iso(),
    )
    db.add(user_message)
    conversation.updated_at = user_message.created_at
    conversation_id = conversation.id
    user_message_id = user_message.id
    request_id = body.request_id
    message_content = body.message
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = _find_existing_user_turn(
            db,
            conversation_id=conversation_id,
            request_id=request_id,
        )
        if existing is None:
            raise
        conversation = _validate_turn_conversation(
            db.get(ChatConversation, conversation_id),
            job_id=job_id,
            mode=body.mode,
        )
        return conversation, existing, False
    try:
        db.refresh(user_message)
    except Exception as refresh_error:
        logger.exception(
            "Recovering committed user turn %s after refresh failure",
            user_message_id,
        )
        db.rollback()
        recovered_user = db.get(ChatMessage, user_message_id)
        if (
            recovered_user is None
            or recovered_user.conversation_id != conversation_id
            or recovered_user.role != "user"
            or recovered_user.request_id != request_id
            or recovered_user.content != message_content
        ):
            raise RuntimeError("could not recover committed user turn") from refresh_error
        conversation = _validate_turn_conversation(
            db.get(ChatConversation, conversation_id),
            job_id=job_id,
            mode=body.mode,
        )
        return conversation, recovered_user, True
    return conversation, user_message, True


def _assistant_metadata(
    *,
    prepared: PreparedChatTurn,
    final_citations: list[ChatCitation],
    evidence_refs: list[EvidenceRefOut],
    suggested_followups: list[str],
    request_id: str | None,
    user_message_id: str,
    settings: Settings,
    status: str,
) -> dict:
    config = _make_llm_config(settings)
    return {
        "status": status,
        "request_id": request_id,
        "user_message_id": user_message_id,
        "retrieval_status": prepared.retrieval_status,
        "citations": [citation.model_dump() for citation in final_citations],
        "model_id": prepared.model_id,
        "generation": prepared.generation.model_dump(),
        "runtime": {
            "provider": config.provider.value,
            "timeout_seconds": config.timeout_seconds,
            "local_adapter_model_name": config.local_adapter_model_name,
            "local_adapter_quantization": config.local_adapter_quantization,
        },
        "evidence_refs": [reference.model_dump() for reference in evidence_refs],
        "suggested_followups": suggested_followups,
        "confidence": 0.85 if status == "completed" else None,
    }


def _persist_assistant_turn(
    db: Session,
    *,
    conversation_id: str,
    user_message_id: str,
    request_id: str | None,
    response_text: str,
    final_citations: list[ChatCitation],
    metadata: dict,
) -> ChatMessage:
    # Completion and expired-lease recovery must select the same terminal row.
    db.rollback()
    if db.get_bind().dialect.name == "sqlite":
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
    origin = db.scalar(select(ChatMessage).where(ChatMessage.id == user_message_id).with_for_update())
    if (
        origin is None
        or origin.conversation_id != conversation_id
        or origin.role != "user"
        or origin.request_id != request_id
    ):
        raise RuntimeError("assistant origin user does not match the persisted turn")
    existing = _find_assistant_for_user_turn(db, user_message=origin)
    if existing is not None:
        db.commit()
        return existing
    metadata = {
        **metadata,
        "request_id": request_id,
        "user_message_id": user_message_id,
    }
    assistant = ChatMessage(
        id=str(uuid.uuid4()),
        conversation_id=conversation_id,
        role="assistant",
        content=response_text,
        citations_json=_serialize_citations(final_citations),
        metadata_json=json.dumps(metadata),
        created_at=_now_iso(),
    )
    db.add(assistant)
    conversation = db.get(ChatConversation, conversation_id)
    if conversation is not None:
        conversation.updated_at = assistant.created_at
    db.commit()
    db.refresh(assistant)
    return assistant


def _terminalize_failed_turn(
    db: Session,
    *,
    user_message_id: str,
    request_id: str | None,
    prepared: PreparedChatTurn,
) -> ChatResponseBody:
    """Persist and return an error result for a previously admitted user turn.

    Persistence is retried after rollback. Before each insert, the committed
    state is checked in case the previous attempt committed but failed while
    refreshing or returning the row.
    """
    response_text = "I'm sorry, I couldn't generate a response."
    final_citations: list[ChatCitation] = list(prepared.current_job_citations)
    last_error: Exception | None = None

    for attempt in range(2):
        db.rollback()
        user_message = db.get(ChatMessage, user_message_id)
        if user_message is None:
            raise RuntimeError("admitted user turn no longer exists")
        existing = _find_assistant_for_user_turn(db, user_message=user_message)
        if existing is not None:
            return _response_for_existing_turn(
                db,
                user_message=user_message,
                requested_content=user_message.content,
            )

        metadata = {
            "status": "error",
            "request_id": request_id,
            "user_message_id": user_message_id,
            "retrieval_status": prepared.retrieval_status,
            "citations": [citation.model_dump() for citation in final_citations],
            "model_id": prepared.model_id,
            "generation": prepared.generation.model_dump(),
            "evidence_refs": [],
            "suggested_followups": [],
            "confidence": None,
        }
        try:
            _persist_assistant_turn(
                db,
                conversation_id=user_message.conversation_id,
                user_message_id=user_message_id,
                request_id=request_id,
                response_text=response_text,
                final_citations=final_citations,
                metadata=metadata,
            )
        except Exception as exc:
            last_error = exc
            logger.exception(
                "Terminal chat error persistence attempt %s failed for user turn %s",
                attempt + 1,
                user_message_id,
            )
            continue
        return _response_for_existing_turn(
            db,
            user_message=user_message,
            requested_content=user_message.content,
        )

    db.rollback()
    user_message = db.get(ChatMessage, user_message_id)
    if user_message is not None:
        existing = _find_assistant_for_user_turn(db, user_message=user_message)
        if existing is not None:
            return _response_for_existing_turn(
                db,
                user_message=user_message,
                requested_content=user_message.content,
            )
    raise RuntimeError("could not persist terminal chat turn state") from last_error


def _chat_response(
    *,
    conversation_id: str,
    branch_id: str | None,
    request_id: str | None,
    response_text: str,
    final_citations: list[ChatCitation],
    prepared: PreparedChatTurn,
    evidence_refs: list[EvidenceRefOut],
    suggested_followups: list[str],
    status: str,
) -> ChatResponseBody:
    return ChatResponseBody(
        response=response_text,
        citations=final_citations,
        conversation_id=conversation_id,
        confidence=0.85 if status == "completed" else None,
        evidence_refs=evidence_refs,
        suggested_followups=suggested_followups,
        retrieval_status=prepared.retrieval_status,
        model_id=prepared.model_id,
        generation=prepared.generation,
        branch_id=branch_id,
        request_id=request_id,
        status=status,
    )


def _persisted_turn_sse_events(persisted: ChatResponseBody) -> list[str]:
    meta = {
        "type": "meta",
        "conversation_id": persisted.conversation_id,
        "branch_id": persisted.branch_id,
        "request_id": persisted.request_id,
        "status": persisted.status,
        "retry_after_seconds": persisted.retry_after_seconds,
        "retrieval_status": persisted.retrieval_status,
        "citations": [citation.model_dump() for citation in persisted.citations],
        "model_id": persisted.model_id,
        "generation": (
            persisted.generation.model_dump()
            if persisted.generation is not None
            else None
        ),
    }
    events = [f"data: {json.dumps(meta)}\n\n"]
    if persisted.response:
        events.append(
            f"data: {json.dumps({'type': 'replace', 'content': persisted.response})}\n\n"
        )
    if persisted.status != "pending":
        events.append("data: [DONE]\n\n")
    return events


def _stream_persisted_turn(persisted: ChatResponseBody) -> StreamingResponse:
    async def event_generator() -> AsyncGenerator[str, None]:
        for event in _persisted_turn_sse_events(persisted):
            yield event

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.post("/jobs/{job_id}/chat", response_model=ChatResponseBody)
async def chat_about_job(
    job_id: str,
    body: ChatRequestBody,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Send a chat message about a job and get an AI response."""
    if db.get(Job, job_id) is None:
        raise HTTPException(status_code=404, detail="job not found")
    _require_turn_request_id(body)
    if body.conversation_id:
        _validate_turn_conversation(db.get(ChatConversation, body.conversation_id), job_id=job_id, mode=body.mode)
    existing = _find_existing_user_turn(
        db,
        conversation_id=body.conversation_id,
        request_id=body.request_id,
        job_id=job_id,
    )
    if existing is not None:
        _validate_turn_conversation(
            db.get(ChatConversation, existing.conversation_id),
            job_id=job_id,
            mode=body.mode,
        )
        return _response_for_existing_turn(
            db,
            user_message=existing,
            requested_content=body.message,
            requested_conversation_id=body.conversation_id,
        )
    _reject_parallel_turn(db, body.conversation_id)

    try:
        prepared = await prepare_chat_turn(
            db,
            job_id=job_id,
            body=body,
            settings=settings,
        )
    except MnemosUnavailableError as exc:
        db.rollback()
        _mnemos_unavailable(exc)
    except ComparisonValidationError as exc:
        db.rollback()
        _comparison_error(exc)

    _validate_new_request_id(body.request_id)
    conversation, user_message, created = _admit_user_turn(
        db,
        job_id=job_id,
        body=body,
        lease_seconds=_make_llm_config(settings).timeout_seconds + 60,
    )
    if not created:
        return _response_for_existing_turn(
            db,
            user_message=user_message,
            requested_content=body.message,
            requested_conversation_id=body.conversation_id,
        )

    conversation_id = str(conversation.id)
    user_message_id = str(user_message.id)
    request_id = body.request_id
    try:
        client = _make_llm_client(settings)
        response_text = await client.chat_completion(
            prepared.messages,
            temperature=prepared.generation.temperature,
        )
        response_text, final_citations = _finalize_prepared_chat_response_payload(
            response_text,
            prepared,
            body.message,
        )
        evidence_refs, suggested_followups = _post_process_response(
            response_text, body.message, final_citations,
        )
        metadata = _assistant_metadata(
            prepared=prepared,
            final_citations=final_citations,
            evidence_refs=evidence_refs,
            suggested_followups=suggested_followups,
            request_id=request_id,
            user_message_id=user_message_id,
            settings=settings,
            status="completed",
        )
        _persist_assistant_turn(
            db,
            conversation_id=conversation_id,
            user_message_id=user_message_id,
            request_id=request_id,
            response_text=response_text,
            final_citations=final_citations,
            metadata=metadata,
        )
    except asyncio.CancelledError:
        _terminalize_failed_turn(db, user_message_id=user_message_id, request_id=request_id, prepared=prepared)
        raise
    except Exception:
        logger.exception("Failed to complete chat turn for job %s", job_id)
        return _terminalize_failed_turn(
            db,
            user_message_id=user_message_id,
            request_id=request_id,
            prepared=prepared,
        )
    return _response_for_existing_turn(db, user_message=db.get(ChatMessage, user_message_id), requested_content=body.message)


def _make_llm_config(settings: Settings) -> LLMConfig:
    return LLMConfig(
        endpoint=get_runtime_llm_endpoint(settings.aipam_ollama_url, os.getenv("LLM_ENDPOINT")),
        model=get_runtime_llm_model(os.getenv("LLM_MODEL_NAME", "aipam-trafficllm-v10")),
        temperature=0.3,
        max_tokens=int(os.getenv("LLM_MAX_TOKENS", "4096")),
        timeout_seconds=get_runtime_llm_timeout(float(os.getenv("LLM_TIMEOUT_SECONDS", "1800"))),
        local_adapter_path=getattr(settings, "llm_local_adapter_path", None) or os.getenv("LLM_LOCAL_ADAPTER_PATH"),
        local_adapter_model_name=getattr(settings, "llm_local_adapter_model_name", None) or os.getenv("LLM_LOCAL_ADAPTER_MODEL_NAME"),
        local_adapter_quantization=getattr(settings, "llm_local_adapter_quantization", None) or os.getenv("LLM_LOCAL_ADAPTER_QUANTIZATION"),
    )


def _make_llm_client(settings: Settings) -> LLMClient:
    """Create an LLMClient from current settings / env vars."""
    return LLMClient(config=_make_llm_config(settings))


@router.post("/jobs/{job_id}/chat/stream")
async def chat_about_job_stream(
    job_id: str,
    body: ChatRequestBody,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Stream chat response tokens via SSE for real-time display."""
    if db.get(Job, job_id) is None:
        raise HTTPException(status_code=404, detail="job not found")
    _require_turn_request_id(body)
    if body.conversation_id:
        _validate_turn_conversation(db.get(ChatConversation, body.conversation_id), job_id=job_id, mode=body.mode)
    existing = _find_existing_user_turn(
        db,
        conversation_id=body.conversation_id,
        request_id=body.request_id,
        job_id=job_id,
    )
    if existing is not None:
        _validate_turn_conversation(
            db.get(ChatConversation, existing.conversation_id),
            job_id=job_id,
            mode=body.mode,
        )
        persisted = _response_for_existing_turn(
            db,
            user_message=existing,
            requested_content=body.message,
            requested_conversation_id=body.conversation_id,
        )
        return _stream_persisted_turn(persisted)
    _reject_parallel_turn(db, body.conversation_id)

    try:
        prepared = await prepare_chat_turn(
            db,
            job_id=job_id,
            body=body,
            settings=settings,
        )
    except MnemosUnavailableError as exc:
        db.rollback()
        _mnemos_unavailable(exc)
    except ComparisonValidationError as exc:
        db.rollback()
        _comparison_error(exc)

    _validate_new_request_id(body.request_id)
    conversation, user_message, created = _admit_user_turn(
        db,
        job_id=job_id,
        body=body,
        lease_seconds=_make_llm_config(settings).timeout_seconds + 60,
    )
    if not created:
        persisted = _response_for_existing_turn(
            db,
            user_message=user_message,
            requested_content=body.message,
            requested_conversation_id=body.conversation_id,
        )
        return _stream_persisted_turn(persisted)
    conv_id = str(conversation.id)
    user_message_id = str(user_message.id)
    request_id = body.request_id
    try:
        branch_id = _conversation_branch_id(db, conv_id)
        client = _make_llm_client(settings)
    except Exception:
        logger.exception("Failed to create streaming chat client for job %s", job_id)
        persisted = _terminalize_failed_turn(
            db,
            user_message_id=user_message_id,
            request_id=request_id,
            prepared=prepared,
        )
        return _stream_persisted_turn(persisted)

    # Queue between the detached producer (LLM call + persistence) and the
    # SSE consumer (event_generator).  Sentinel ``None`` signals end-of-stream.
    # Unbounded so the producer can complete (and persist the assistant
    # message) even when the client has disconnected and stopped draining.
    event_queue: asyncio.Queue[str | None] = asyncio.Queue()

    async def producer() -> None:
        """Run the LLM call, push SSE events to the queue, and persist the
        assistant message.

        Runs as a detached asyncio task so it survives client disconnect: if
        the user navigates away mid-stream, this task keeps running, finishes
        the LLM response, and writes the assistant message using a fresh DB
        session (the request's ``db`` is closed once the request returns).
        """
        streamed_parts: list[str] = []
        error_text: str | None = None
        response_text = ""
        final_citations: list[ChatCitation] = []
        try:
            # Tell the frontend which conversation this stream belongs to as
            # early as possible — useful so the UI can save/resume even if
            # the user closes the tab mid-stream.
            await event_queue.put(
                f"data: {json.dumps({'type': 'meta', 'conversation_id': conv_id, 'branch_id': branch_id, 'request_id': request_id, 'status': 'pending', 'retrieval_status': prepared.retrieval_status, 'citations': [citation.model_dump() for citation in [*prepared.current_job_citations, *prepared.historical_citations]], 'model_id': prepared.model_id, 'generation': prepared.generation.model_dump()})}\n\n"
            )

            try:
                async for token in client.chat_completion_stream(
                    prepared.messages,
                    temperature=prepared.generation.temperature,
                ):
                    if token:
                        streamed_parts.append(token)
                        await event_queue.put(
                            f"data: {json.dumps({'type': 'token', 'content': token})}\n\n"
                        )
            except Exception as exc:
                logger.exception("LLM streaming failed for job %s", job_id)
                error_text = "Error: generation interrupted. Send a new message to try again."

            streamed_text = "".join(streamed_parts)
            status = "completed"
            if error_text is None:
                response_text, final_citations = _finalize_prepared_chat_response_payload(
                    streamed_text,
                    prepared,
                    body.message,
                )
                # If finalize appended content (e.g. the "Sources used:" block),
                # emit the delta so the on-screen text matches what we persist.
                if response_text != streamed_text:
                    if response_text.startswith(streamed_text):
                        extra = response_text[len(streamed_text):]
                        if extra:
                            await event_queue.put(
                                f"data: {json.dumps({'type': 'token', 'content': extra})}\n\n"
                            )
                    else:
                        # Rare: finalize rewrote the response entirely.  Tell
                        # the frontend to replace the streamed content.
                        await event_queue.put(
                            f"data: {json.dumps({'type': 'replace', 'content': response_text})}\n\n"
                        )
            else:
                status = "error"
                final_citations = list(prepared.current_job_citations)
                response_text = _append_sources_and_limits(
                    error_text,
                    prepared.current_job_citations,
                )
                # No live tokens were streamed (error before first chunk);
                # emit as one block.
                await event_queue.put(
                    f"data: {json.dumps({'type': 'replace', 'content': response_text})}\n\n"
                )

            evidence_refs, suggested_followups = _post_process_response(
                response_text, body.message, final_citations,
            )
            metadata = _assistant_metadata(
                prepared=prepared,
                final_citations=final_citations,
                evidence_refs=evidence_refs,
                suggested_followups=suggested_followups,
                request_id=request_id,
                user_message_id=user_message_id,
                settings=settings,
                status=status,
            )
            session_factory = get_session_factory()
            with session_factory() as background_db:
                _persist_assistant_turn(
                    background_db,
                    conversation_id=conv_id,
                    user_message_id=user_message_id,
                    request_id=request_id,
                    response_text=response_text,
                    final_citations=final_citations,
                    metadata=metadata,
                )
                persisted = _response_for_existing_turn(background_db, user_message=background_db.get(ChatMessage, user_message_id), requested_content=body.message)
            if persisted.status != status:
                for event in _persisted_turn_sse_events(persisted):
                    await event_queue.put(event)
                return
            await event_queue.put(
                f"data: {json.dumps({'type': 'meta', 'conversation_id': conv_id, 'branch_id': branch_id, 'request_id': request_id, 'status': status, 'retrieval_status': prepared.retrieval_status, 'citations': [citation.model_dump() for citation in final_citations], 'model_id': prepared.model_id, 'generation': prepared.generation.model_dump(), 'confidence': metadata['confidence'], 'evidence_refs': [reference.model_dump() for reference in evidence_refs], 'suggested_followups': suggested_followups})}\n\n"
            )

            await event_queue.put("data: [DONE]\n\n")
        except (Exception, asyncio.CancelledError):
            logger.warning("Failed to complete streamed chat turn for conv %s", conv_id)
            try:
                session_factory = get_session_factory()
                with session_factory() as recovery_db:
                    persisted = _terminalize_failed_turn(
                        recovery_db,
                        user_message_id=user_message_id,
                        request_id=request_id,
                        prepared=prepared,
                    )
                for event in _persisted_turn_sse_events(persisted):
                    await event_queue.put(event)
            except Exception:
                logger.exception(
                    "Failed to persist terminal state for streamed chat turn %s",
                    user_message_id,
                )
                await event_queue.put(
                    f"data: {json.dumps({'type': 'error', 'code': 'CHAT_TURN_FAILED', 'retryable': True})}\n\n"
                )
        finally:
            # Wake the consumer so it can exit cleanly.
            await event_queue.put(None)

    # Spawn the producer detached from the request.  We hold a strong
    # reference in _background_tasks so it isn't garbage collected; the
    # done-callback discards the reference once the task finishes.
    task = asyncio.create_task(producer())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    async def event_generator() -> AsyncGenerator[str, None]:
        """Forward SSE events from the producer queue to the client.

        If the client disconnects, Starlette cancels this generator — the
        producer keeps running and still persists the assistant message.
        """
        while True:
            event = await event_queue.get()
            if event is None:
                break
            yield event

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


@router.get("/jobs/{job_id}/conversations", response_model=list[ConversationSummaryOut])
async def list_conversations(
    job_id: str,
    db: Session = Depends(get_db),
):
    """List all chat conversations for a job."""
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")

    convs = db.execute(
        select(ChatConversation)
        .where(
            ChatConversation.job_id == job_id,
            ChatConversation.mode == "baseline",
            ChatConversation.parent_branch_id.is_(None),
        )
        .order_by(ChatConversation.updated_at.desc())
    ).scalars().all()

    result = []
    for c in convs:
        msg_count = db.execute(
            select(func.count(ChatMessage.id)).where(ChatMessage.conversation_id == c.id)
        ).scalar() or 0
        result.append(ConversationSummaryOut(
            id=c.id, job_id=c.job_id,
            created_at=c.created_at, updated_at=c.updated_at,
            title=c.title, message_count=msg_count,
        ))
    return result


@router.get("/jobs/{job_id}/conversations/{conversation_id}", response_model=ConversationHistoryOut)
async def get_conversation(
    job_id: str,
    conversation_id: str,
    db: Session = Depends(get_db),
):
    """Get full message history for a conversation."""
    conv = db.get(ChatConversation, conversation_id)
    if not conv or conv.job_id != job_id:
        raise HTTPException(status_code=404, detail="conversation not found")

    rows = db.execute(
        select(ChatMessage)
        .where(ChatMessage.conversation_id == conversation_id)
        .order_by(ChatMessage.sequence.asc())
    ).scalars().all()

    return ConversationHistoryOut(
        id=conv.id, job_id=conv.job_id,
        messages=[_message_out(message, db).model_dump() for message in rows],
        created_at=conv.created_at, updated_at=conv.updated_at,
    )


@router.patch("/jobs/{job_id}/conversations/{conversation_id}", response_model=ConversationSummaryOut)
async def rename_conversation(
    job_id: str,
    conversation_id: str,
    body: ConversationRenameRequest,
    db: Session = Depends(get_db),
):
    """Rename a chat conversation (title)."""
    conv = db.get(ChatConversation, conversation_id)
    if not conv or conv.job_id != job_id:
        raise HTTPException(status_code=404, detail="conversation not found")

    conv.title = body.title
    conv.updated_at = _now_iso()
    if conv.comparison_group_id:
        group = db.get(ChatComparisonGroup, conv.comparison_group_id)
        if group is not None and group.root_conversation_id == conv.id:
            group.title = body.title
            group.updated_at = conv.updated_at
    db.commit()
    db.refresh(conv)

    msg_count = db.execute(
        select(func.count(ChatMessage.id)).where(ChatMessage.conversation_id == conversation_id)
    ).scalar() or 0

    return ConversationSummaryOut(
        id=conv.id, job_id=conv.job_id,
        created_at=conv.created_at, updated_at=conv.updated_at,
        title=conv.title, message_count=msg_count,
    )


@router.delete("/jobs/{job_id}/conversations/{conversation_id}", status_code=204)
async def delete_conversation(
    job_id: str,
    conversation_id: str,
    db: Session = Depends(get_db),
):
    """Delete a chat conversation and all its messages."""
    conv = db.get(ChatConversation, conversation_id)
    if not conv or conv.job_id != job_id:
        raise HTTPException(status_code=404, detail="conversation not found")

    if conv.mode != "baseline" or conv.parent_branch_id is not None:
        raise HTTPException(
            status_code=400,
            detail="delete the comparison root rather than an individual branch",
        )
    if conv.comparison_group_id:
        try:
            group = get_comparison_group(
                db,
                job_id=job_id,
                group_id=conv.comparison_group_id,
            )
        except ComparisonValidationError as exc:
            _comparison_error(exc)
        branches = get_comparison_branches(db, group_id=group.id)
        branch_conversation_ids = [branch.conversation_id for branch in branches]
        group.active_branch_id = None
        db.flush()
        if branch_conversation_ids:
            db.execute(
                delete(ChatMessage).where(
                    ChatMessage.conversation_id.in_(branch_conversation_ids)
                )
            )
        db.execute(
            delete(ChatComparisonBranch).where(
                ChatComparisonBranch.group_id == group.id
            )
        )
        if branch_conversation_ids:
            db.execute(
                delete(ChatConversation).where(
                    ChatConversation.id.in_(branch_conversation_ids)
                )
            )
        db.execute(delete(ChatComparisonGroup).where(ChatComparisonGroup.id == group.id))
        db.execute(
            delete(ChatMessage).where(ChatMessage.conversation_id == conversation_id)
        )
        db.execute(delete(ChatConversation).where(ChatConversation.id == conversation_id))
    else:
        db.execute(
            delete(ChatMessage).where(ChatMessage.conversation_id == conversation_id)
        )
        db.delete(conv)
    db.commit()
    return None
