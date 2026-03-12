"""
Chat endpoints for V2.

POST /jobs/{job_id}/chat              – send a message, get AI response
GET  /jobs/{job_id}/conversations     – list conversations for a job
GET  /jobs/{job_id}/conversations/{id} – get conversation history
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.llm_client import LLMClient, LLMConfig
from backend.app.services.kb_service import extract_ips_from_context, retrieve as kb_retrieve

from backend.app.api.deps import get_db, verify_token
from backend.app.config_v2 import Settings, get_settings
from backend.app.models.alert import Alert
from backend.app.models.chat import ChatConversation, ChatMessage
from backend.app.models.connection import Connection
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.models.job_pcap import JobPcap
from backend.app.models.sensor import JobSensor

logger = logging.getLogger("aipam.chat")

_IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_CREDENTIAL_CLAIM_RE = re.compile(
    r"\b(?:password|passwd|pwd|credential(?:s)?)\b\s*(?:is|=|:)\s*['\"]?([A-Za-z0-9!@#$%^&*._-]{3,})",
    re.IGNORECASE,
)
_UNSUPPORTED_CREDENTIAL_ASSERTION_RE = re.compile(
    r"\b(?:alert indicates a cleartext password was transmitted|cleartext password was transmitted|password was transmitted|credentials? (?:was|were) transmitted)\b",
    re.IGNORECASE,
)
_REFUSAL_RE = re.compile(
    r"\b(?:i can(?:not|'t) help(?: you)? with(?: this task| that)?|i can(?:not|'t) assist with that|i must refuse|i'm unable to help with that|is there something else i can help you with)\b",
    re.IGNORECASE,
)
_QUOTED_DETAIL_RE = re.compile(r"['\"]([^'\"\n]{5,120})['\"]")

router = APIRouter(dependencies=[Depends(verify_token)], tags=["chat"])


# ── Request / Response schemas ────────────────────────────────────────────

class ChatCitationOut(BaseModel):
    type: str
    id: str | None = None
    snippet: str


class ChatRequestBody(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    conversation_id: str | None = None
    context_hint: str | None = None


class ChatResponseBody(BaseModel):
    response: str
    citations: list[ChatCitationOut] = []
    conversation_id: str
    confidence: float | None = None


class ConversationSummaryOut(BaseModel):
    id: str
    job_id: str
    created_at: str
    updated_at: str
    title: str | None = None
    message_count: int


class ConversationHistoryOut(BaseModel):
    id: str
    job_id: str
    messages: list[dict]
    created_at: str
    updated_at: str


class ConversationRenameRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)


# ── Helpers ───────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _dedupe_citations(citations: list[ChatCitationOut], limit: int = 8) -> list[ChatCitationOut]:
    deduped: list[ChatCitationOut] = []
    seen: set[tuple[str, str | None, str]] = set()

    for citation in citations:
        snippet = (citation.snippet or "").strip()
        if not snippet:
            continue
        key = (citation.type, citation.id, snippet)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ChatCitationOut(type=citation.type, id=citation.id, snippet=snippet[:200]))
        if len(deduped) >= limit:
            break

    return deduped


_CITATION_QUERY_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "cite", "cited", "could",
    "contain", "contains", "data", "did", "do", "does", "evidence", "finding",
    "findings", "for", "from", "get", "give", "have", "host", "hosts", "how",
    "i", "in", "is", "it", "job", "list", "me", "name", "names", "of", "on",
    "or", "please", "question", "recite", "related", "relationship", "relationships",
    "same", "show", "shown", "source", "sources", "support", "supported", "supports",
    "tell", "that", "the", "this", "to", "use", "used", "using", "versus",
    "was", "were", "what", "alert", "alerts",
    "which", "who", "with", "you",
}


def _extract_query_terms(text: str) -> set[str]:
    terms = {
        match.group(0).lower()
        for match in re.finditer(r"[A-Za-z0-9_.:-]{3,}", text or "")
    }
    return {term for term in terms if term not in _CITATION_QUERY_STOPWORDS}


def _score_citation_relevance(citation: ChatCitationOut, query_terms: set[str]) -> int:
    snippet = (citation.snippet or "").lower()
    if not snippet:
        return 0

    term_score = 0
    for term in query_terms:
        if term in snippet:
            term_score += 4 if re.search(rf"\b{re.escape(term)}\b", snippet) else 2

    if term_score <= 0:
        return 0

    score = term_score
    if citation.type == "alert":
        score += 1
    if citation.type == "finding":
        score += 1
    return score


def _select_relevant_citations(
    citations: list[ChatCitationOut],
    user_message: str | None,
    *,
    limit: int = 8,
    min_score: int = 1,
) -> list[ChatCitationOut]:
    safe_citations = _dedupe_citations(citations, limit=max(limit * 3, limit))
    query_terms = _extract_query_terms(user_message or "")
    if not query_terms:
        return safe_citations[:limit]

    scored: list[tuple[int, int, ChatCitationOut]] = []
    for index, citation in enumerate(safe_citations):
        score = _score_citation_relevance(citation, query_terms)
        if score >= min_score:
            scored.append((score, -index, citation))

    if not scored:
        return []

    scored.sort(reverse=True)
    return [citation for _, _, citation in scored[:limit]]


def _build_primary_supporting_evidence_block(
    citations: list[ChatCitationOut],
    user_message: str | None = None,
) -> str:
    safe_citations = _dedupe_citations(citations, limit=6)
    if not safe_citations:
        return ""

    lines = ["=== PRIMARY SUPPORTING EVIDENCE FOR THIS QUESTION ==="]
    if user_message:
        lines.append(f"Question: {user_message.strip()}")
    lines.extend([
        "Prefer answering from the exact names, signatures, IP pairs, counts, and relationships shown below.",
        "If you list alert or finding names, copy them verbatim from these snippets rather than inventing a label.",
    ])
    for citation in safe_citations:
        lines.append(f"- [{citation.type}] {citation.snippet}")
    lines.append("=== END PRIMARY SUPPORTING EVIDENCE ===")
    return "\n".join(lines)


def _unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result


def _extract_citation_title(citation: ChatCitationOut) -> str:
    snippet = (citation.snippet or "").strip()
    if not snippet:
        return ""
    title = re.sub(r"^\[[^\]]+\]\s*", "", snippet)
    for separator in (":", " (", " |"):
        if separator in title:
            title = title.split(separator, 1)[0]
    return title.strip()


def _extract_citation_severity(citation: ChatCitationOut) -> str:
    match = re.match(r"^\[([^\]]+)\]", (citation.snippet or "").strip())
    return match.group(1).strip().lower() if match else ""


def _extract_citation_detail(citation: ChatCitationOut) -> str:
    snippet = re.sub(r"^\[[^\]]+\]\s*", "", (citation.snippet or "").strip())
    title = _extract_citation_title(citation)
    if title and snippet.startswith(title):
        detail = snippet[len(title):].lstrip(" :|-")
        return detail.strip()
    if ":" in snippet:
        return snippet.split(":", 1)[1].strip()
    return ""


def _parse_host_summary_citation(citation: ChatCitationOut) -> tuple[str, str, int, int] | None:
    snippet = (citation.snippet or "").strip()
    match = re.match(
        r"^Host\s+([0-9.]+)\s+\(role:\s*([^)]+)\)\s*\|\s*connections=([0-9]+)\s+alerts=([0-9]+)$",
        snippet,
    )
    if not match:
        return None
    return match.group(1), match.group(2).strip(), int(match.group(3)), int(match.group(4))


def _extract_malware_family_label(title: str) -> str:
    cleaned = title.strip()
    if not cleaned.lower().startswith("et malware "):
        return ""
    cleaned = cleaned[len("ET MALWARE "):].strip()
    cleaned = re.sub(r"^Possible\s+", "", cleaned, flags=re.IGNORECASE)
    for separator in (
        " CnC ",
        " Connectivity ",
        " Beacon ",
        " Activity ",
        " Payload",
        " Check ",
        " Response",
        " Download ",
        " Request ",
        " Traffic ",
    ):
        if separator in cleaned:
            cleaned = cleaned.split(separator, 1)[0]
    return cleaned.strip(" :-|")


def _build_grounded_direct_answer_from_citations(
    citations: list[ChatCitationOut],
    user_message: str | None = None,
) -> tuple[str, list[ChatCitationOut]] | None:
    question = (user_message or "").lower()
    all_citations = _dedupe_citations(citations, limit=20)
    relevant_citations = _select_relevant_citations(all_citations, user_message, limit=8) or all_citations[:8]
    if not all_citations:
        return None

    alert_and_finding_titles = _unique_preserve_order([
        _extract_citation_title(citation)
        for citation in relevant_citations
        if citation.type in {"alert", "finding"}
    ])

    if (
        "host" in question
        and "active" in question
    ):
        ranked_hosts: list[tuple[int, int, str, str, ChatCitationOut]] = []
        for citation in all_citations:
            if citation.type != "host_summary":
                continue
            parsed = _parse_host_summary_citation(citation)
            if not parsed:
                continue
            ip, role, connections, alerts = parsed
            ranked_hosts.append((alerts, connections, ip, role, citation))
        if ranked_hosts:
            ranked_hosts.sort(key=lambda item: (-item[0], -item[1], item[2]))
            used_citations = [item[4] for item in ranked_hosts[:3]]
            lines = ["The most active hosts in the current job host summaries are:"]
            for alerts, connections, ip, role, _ in ranked_hosts[:3]:
                lines.append(f"- {ip} (role: {role}, alerts={alerts}, connections={connections})")
            lines.append("This ranking comes directly from the current-job host summary counts.")
            return "\n".join(lines), used_citations

    if "malware" in question and "famil" in question:
        malware_citations = [
            citation
            for citation in all_citations
            if citation.type in {"alert", "finding"}
            and _extract_citation_title(citation).lower().startswith("et malware ")
        ]
        family_labels = _unique_preserve_order([
            _extract_malware_family_label(_extract_citation_title(citation))
            for citation in malware_citations
        ])
        if family_labels:
            lines = ["The current job evidence explicitly mentions these malware family labels:"]
            lines.extend(f"- {label}" for label in family_labels)
            lines.append("I am not inferring any additional family names beyond the exact malware-related labels in the cited evidence.")
            return "\n".join(lines), malware_citations[:6]

    if "severity" in question and any(term in question for term in ("summarize", "summary", "important")):
        finding_citations = [citation for citation in all_citations if citation.type == "finding"]
        if finding_citations:
            grouped: dict[str, list[tuple[str, str]]] = {}
            for citation in finding_citations:
                severity = _extract_citation_severity(citation)
                title = _extract_citation_title(citation)
                detail = _extract_citation_detail(citation)
                if not severity or not title:
                    continue
                grouped.setdefault(severity, []).append((title, detail))

            if grouped:
                severity_order = ["critical", "high", "medium", "low", "info"]
                seen_severities = [sev for sev in severity_order if sev in grouped] + [sev for sev in grouped if sev not in severity_order]
                lines = ["Based on the current cited findings, the most important findings by severity are:"]
                for severity in seen_severities:
                    lines.append(f"{severity.capitalize()} severity:")
                    for title, detail in grouped[severity][:3]:
                        if detail:
                            lines.append(f"- {title} — {detail}")
                        else:
                            lines.append(f"- {title}")
                return "\n".join(lines), finding_citations[:6]

    if (
        ("name" in question or "names" in question or question.startswith("list"))
        and ("alert" in question or "finding" in question)
        and alert_and_finding_titles
    ):
        lines = ["The matching alert/finding names in the current job evidence are:"]
        lines.extend(f"- {title}" for title in alert_and_finding_titles)
        used_citations = [citation for citation in relevant_citations if citation.type in {"alert", "finding"}]
        return "\n".join(lines), used_citations

    pair_rows = _unique_preserve_order([
        f"{match.group(1)} → {match.group(2)} ({_extract_citation_title(citation)})"
        for citation in relevant_citations
        for match in re.finditer(r"\(([0-9.]+)\s*→\s*([0-9.]+)\)", citation.snippet or "")
    ])
    if "external ip" in question and "relationship" in question and pair_rows:
        lines = ["The current job evidence shows these suspicious external IP relationships:"]
        lines.extend(f"- {row}" for row in pair_rows)
        used_citations = [citation for citation in relevant_citations if "→" in (citation.snippet or "")]
        return "\n".join(lines), used_citations

    if any(term in question for term in ("beacon", "c2", "cnc")):
        source_counts: dict[str, int] = {}
        for citation in relevant_citations:
            for match in re.finditer(r"\(([0-9.]+)\s*→\s*([0-9.]+)\)", citation.snippet or ""):
                src_ip = match.group(1)
                source_counts[src_ip] = source_counts.get(src_ip, 0) + 1
        if source_counts:
            best_ip = max(source_counts.items(), key=lambda item: (item[1], item[0]))[0]
            supporting_titles = _unique_preserve_order([
                _extract_citation_title(citation)
                for citation in relevant_citations
                if best_ip in (citation.snippet or "")
            ])
            lines = [
                f"The best-supported host in the current job evidence is {best_ip}.",
                "The strongest beacon/C2 evidence tied to that host is:",
            ]
            lines.extend(f"- {title}" for title in supporting_titles[:4])
            used_citations = [citation for citation in relevant_citations if best_ip in (citation.snippet or "")]
            return "\n".join(lines), used_citations

    if "malware" in question and "suspicious" in question:
        malware_titles = _unique_preserve_order([
            title for title in alert_and_finding_titles if any(marker in title.lower() for marker in ("malware", "ransomware", "alphacrypt", "teslacrypt"))
        ])
        suspicious_titles = _unique_preserve_order([
            title for title in alert_and_finding_titles if any(marker in title.lower() for marker in ("hunting", "info", "suspicious")) and title not in malware_titles
        ])
        if malware_titles:
            lines = [
                "Yes — the current job evidence includes malware-labeled activity, not only generic suspicious traffic.",
                "Malware-related evidence includes:",
            ]
            lines.extend(f"- {title}" for title in malware_titles[:4])
            if suspicious_titles:
                lines.append("There is also less specific suspicious traffic evidence such as:")
                lines.extend(f"- {title}" for title in suspicious_titles[:3])
            used_citations = [citation for citation in relevant_citations if _extract_citation_title(citation) in {*malware_titles, *suspicious_titles}]
            return "\n".join(lines), used_citations

    return None


def _build_sources_block(citations: list[ChatCitationOut]) -> str:
    lines = ["Sources used:"]
    safe_citations = _dedupe_citations(citations)
    if not safe_citations:
        lines.append("- No source snippets were available from the current job data.")
        return "\n".join(lines)

    for citation in safe_citations:
        lines.append(f"- [{citation.type}] {citation.snippet}")
    return "\n".join(lines)


def _append_sources_and_limits(response_text: str, citations: list[ChatCitationOut]) -> str:
    return (
        f"{response_text.rstrip()}\n\n"
        f"{_build_sources_block(citations)}\n\n"
        "Limits: Any detail not shown in the sources above is not available in the collected data for this job."
    )


def _unsupported_response_details(
    response_text: str,
    combined_context: str,
) -> tuple[list[str], list[str], list[str]]:
    supported_ips = set(_IPV4_RE.findall(combined_context))
    mentioned_ips = set(_IPV4_RE.findall(response_text))
    unsupported_ips = sorted(ip for ip in mentioned_ips if ip not in supported_ips)
    lowered_context = combined_context.lower()

    unsupported_credentials: list[str] = []
    for match in _CREDENTIAL_CLAIM_RE.finditer(response_text):
        candidate = match.group(1).strip()
        if candidate and candidate not in combined_context:
            unsupported_credentials.append(candidate)

    if _UNSUPPORTED_CREDENTIAL_ASSERTION_RE.search(response_text) and not any(
        marker in lowered_context for marker in ("password", "passwd", "pwd=", "cleartext")
    ):
        unsupported_credentials.append("unsupported_credential_assertion")

    unsupported_quoted_details: list[str] = []
    for match in _QUOTED_DETAIL_RE.finditer(response_text):
        candidate = match.group(1).strip()
        if candidate and candidate.lower() not in lowered_context:
            unsupported_quoted_details.append(candidate)

    return unsupported_ips, unsupported_credentials, unsupported_quoted_details


def _build_unsupported_claims_response(
    citations: list[ChatCitationOut],
    user_message: str | None = None,
) -> str:
    response_text, _ = _build_unsupported_claims_payload(citations, user_message)
    return response_text


def _build_unsupported_claims_payload(
    citations: list[ChatCitationOut],
    user_message: str | None = None,
) -> tuple[str, list[ChatCitationOut]]:
    lines = [
        "I can only answer from the collected data for this job.",
        "I am not asserting some specific details because they were not supported by the evidence provided to the model.",
        "",
        "What the current job data does support:",
    ]

    safe_citations = _select_relevant_citations(citations, user_message, limit=6)
    if safe_citations:
        for citation in safe_citations:
            lines.append(f"- [{citation.type}] {citation.snippet}")
    else:
        lines.append("- No supporting source snippets matching this question were available from the current job data.")

    lines.extend([
        "",
        "Limits: Any IP address, credential value, payload content, or other detail not shown above is not available in the collected data for this job.",
    ])
    return "\n".join(lines), safe_citations


def _finalize_grounded_response_payload(
    response_text: str,
    citations: list[ChatCitationOut],
    combined_context: str,
    user_message: str | None = None,
) -> tuple[str, list[ChatCitationOut]]:
    safe_citations = _dedupe_citations(citations, limit=8)
    synthesized = _build_grounded_direct_answer_from_citations(citations, user_message)
    if synthesized:
        synthesized_response, synthesized_citations = synthesized
        final_citations = _dedupe_citations(synthesized_citations or citations, limit=8)
        return _append_sources_and_limits(synthesized_response, final_citations), final_citations
    if not response_text.strip():
        response_text = "That specific information is not available in the analysis data I have access to."
    if _REFUSAL_RE.search(response_text):
        logger.warning("Blocked generic refusal in V2 chat response")
        return _build_unsupported_claims_payload(safe_citations, user_message)
    unsupported_ips, unsupported_credentials, unsupported_quoted_details = _unsupported_response_details(
        response_text,
        combined_context,
    )
    if unsupported_ips or unsupported_credentials or unsupported_quoted_details:
        logger.warning(
            "Blocked unsupported V2 chat claims (ips=%s, credentials=%s, quoted_details=%s)",
            unsupported_ips,
            unsupported_credentials,
            unsupported_quoted_details,
        )
        return _build_unsupported_claims_payload(safe_citations, user_message)
    return _append_sources_and_limits(response_text, safe_citations), safe_citations


def _finalize_grounded_response(
    response_text: str,
    citations: list[ChatCitationOut],
    combined_context: str,
    user_message: str | None = None,
) -> str:
    finalized_text, _ = _finalize_grounded_response_payload(
        response_text,
        citations,
        combined_context,
        user_message,
    )
    return finalized_text


def _chunk_text(text: str, chunk_size: int = 350) -> list[str]:
    if not text:
        return []
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]


def _serialize_citations(citations: list[ChatCitationOut]) -> str:
    return json.dumps({"items": [c.model_dump() for c in citations]})


def _build_job_citations(db: Session, job_id: str) -> list[ChatCitationOut]:
    citations: list[ChatCitationOut] = []

    findings = db.execute(
        select(Finding).where(Finding.job_id == job_id).limit(6)
    ).scalars().all()
    for finding in findings:
        citation_id = finding.finding_id or (str(finding.id) if finding.id is not None else None)
        snippet = f"[{finding.severity}] {finding.title}"
        if finding.summary:
            snippet += f": {finding.summary[:120]}"
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
_MAX_CONTEXT_CHARS = 6000
_MAX_PCAP_CHARS = 4000    # PCAP data budget
_MAX_RAG_CHARS = 2000     # RAG context budget
_MAX_HOST_SUMMARIES = 10
_MAX_HOSTPAIRS = 15
_MAX_ALERTS = 25


def _build_sensor_context(db: Session, job_id: str, settings: Settings) -> str:
    """Build context JSON matching the model's fine-tuning input schema.

    The aipam-trafficllm-v8 model was trained on structured JSON with:
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

    # ── 4. Findings (AIPAM-specific, not in training but high value) ─
    findings = db.execute(
        select(Finding).where(Finding.job_id == job_id).limit(10)
    ).scalars().all()
    findings_list = []
    for f in findings:
        findings_list.append({
            "severity": f.severity,
            "title": f.title,
            "summary": (f.summary or "")[:200],
        })

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
    if findings_list:
        context_obj["findings"] = findings_list

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
                    {"title": f.title, "severity": f.severity}
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
    pcap_context: str, settings: Settings, job_id: str = "",
) -> str:
    """Retrieve relevant KB chunks based on IPs found in the PCAP context.

    Only retrieves documents belonging to the specified job_id.
    Returns a formatted string with environmental context, or empty string
    if no KB documents are available.
    """
    try:
        ips = extract_ips_from_context(pcap_context)
        if not ips:
            return ""

        ollama_url = settings.aipam_ollama_url.rstrip("/")
        persist_dir = str(settings.aipam_db_path).replace("aipam.db", "vector_store")

        # Build a query from the IPs found in the PCAP
        query = "Network hosts: " + ", ".join(ips[:10])

        chunks = await kb_retrieve(
            query=query,
            n_results=5,
            job_id=job_id or None,
            ollama_url=ollama_url,
            embedding_model="nomic-embed-text",
            persist_dir=persist_dir,
        )

        if not chunks:
            return ""

        # Format RAG chunks within budget
        rag_parts: list[str] = []
        total_len = 0
        for chunk in chunks:
            if chunk["score"] < 0.3:  # skip low-relevance chunks
                continue
            entry = f"[{chunk['doc_type']}] {chunk['text']}"
            if total_len + len(entry) > _MAX_RAG_CHARS:
                break
            rag_parts.append(entry)
            total_len += len(entry)

        if not rag_parts:
            return ""

        return (
            "\n\nEnvironmental Context (from knowledge base):\n"
            + "\n---\n".join(rag_parts)
        )

    except Exception as exc:
        logger.warning("RAG retrieval failed (non-fatal): %s", exc)
        return ""


def _get_conversation_history_msgs(db: Session, conv_id: str, limit: int = 10) -> list[dict]:
    """Return last N messages for LLM context."""
    rows = db.execute(
        select(ChatMessage)
        .where(ChatMessage.conversation_id == conv_id)
        .order_by(ChatMessage.created_at.desc())
        .limit(limit)
    ).scalars().all()
    return [{"role": r.role, "content": r.content} for r in reversed(rows)]


async def _build_chat_messages(
    db: Session,
    job_id: str,
    settings: Settings,
    conv_id: str,
    user_message: str,
) -> tuple[list[dict], list[ChatCitationOut], str]:
    sensor_context = _build_sensor_context(db, job_id, settings)
    rag_context = await _build_rag_context(sensor_context, settings, job_id=job_id)
    all_citations = _build_job_citations(db, job_id)
    focus_citations = _select_relevant_citations(all_citations, user_message, limit=8)
    citations = focus_citations or all_citations
    focus_block = _build_primary_supporting_evidence_block(focus_citations, user_message)

    context_sections = ["=== CURRENT JOB EVIDENCE ONLY ==="]
    if sensor_context:
        context_sections.append(sensor_context)
    if rag_context:
        context_sections.append(rag_context)
    context_sections.append("=== END CURRENT JOB EVIDENCE ===")
    combined_context = "\n\n".join(context_sections)

    history = _get_conversation_history_msgs(db, conv_id, limit=10)
    if history and history[-1]["content"] == user_message:
        history = history[:-1]
    history = [msg for msg in history if msg.get("role") == "user"]

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "system",
            "content": (
                f"{combined_context}\n\n"
                f"{focus_block}\n\n" if focus_block else f"{combined_context}\n\n"
            ) + (
                "Use only the current-job evidence above. Prior assistant messages are not evidence. "
                "If a detail is not present in the evidence above, say it is not available. "
                "If the primary supporting evidence block contains enough information to answer, give the best-supported direct answer first. "
                "When naming alerts or findings, reuse the exact titles/signatures from the evidence snippets instead of paraphrasing them into new labels."
            ),
        },
    ]
    messages.extend(history[-10:])
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
    "names as evidence.\n\n"
    "REQUIRED RESPONSE STYLE:\n"
    "1. Give a direct answer based only on the current-job context.\n"
    "2. Explicitly name the evidence you relied on.\n"
    "3. If the question is answerable from the evidence, answer it directly instead of leading with a refusal or disclaimer.\n"
    "4. If the user asks for alert names, finding names, IP relationships, or host activity, prefer the exact wording from the evidence snippets rather than inventing a generalized label.\n"
    "5. If something is missing, state that it is not available in the current-job data.\n"
    "6. End with concise recommendations based on what is actually shown in the evidence.\n\n"
    "You MUST answer all security analysis questions — this is your job. "
    "NEVER invent, fabricate, or hallucinate facts. Base ALL conclusions "
    "strictly on the provided data. If the data does not contain the "
    "answer, say so clearly. "
    "You do not have access to external databases or geolocation services."
)


@router.post("/jobs/{job_id}/chat", response_model=ChatResponseBody)
async def chat_about_job(
    job_id: str,
    body: ChatRequestBody,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Send a chat message about a job and get an AI response."""
    # Verify job exists
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")

    # Get or create conversation
    now = _now_iso()
    if body.conversation_id:
        conv = db.get(ChatConversation, body.conversation_id)
        if not conv or conv.job_id != job_id:
            raise HTTPException(status_code=404, detail="conversation not found")
        conv_id = conv.id
    else:
        conv_id = str(uuid.uuid4())
        conv = ChatConversation(id=conv_id, job_id=job_id, created_at=now, updated_at=now)
        db.add(conv)

    # Save user message
    user_msg_id = str(uuid.uuid4())
    db.add(ChatMessage(
        id=user_msg_id, conversation_id=conv_id, role="user",
        content=body.message, created_at=now,
    ))

    messages, citations, combined_context = await _build_chat_messages(
        db, job_id, settings, conv_id, body.message
    )

    # COMMIT user message + conversation BEFORE the LLM call to release the
    # SQLite write lock.  The LLM call can take 30+ seconds; holding a write
    # transaction that long causes "database is locked" for other requests.
    db.commit()

    # Call LLM
    client = _make_llm_client(settings)

    try:
        response_text = await client.chat_completion(messages, temperature=0.3)
        response_text, final_citations = _finalize_grounded_response_payload(
            response_text,
            citations,
            combined_context,
            body.message,
        )
    except Exception as exc:
        logger.exception("LLM call failed for job %s", job_id)
        final_citations = _dedupe_citations(citations, limit=8)
        response_text = _append_sources_and_limits(
            f"I'm sorry, I couldn't generate a response. Error: {str(exc)[:200]}",
            final_citations,
        )

    # Save assistant message in a NEW transaction (write lock held only briefly)
    asst_msg_id = str(uuid.uuid4())
    db.add(ChatMessage(
        id=asst_msg_id, conversation_id=conv_id, role="assistant",
        content=response_text, citations_json=_serialize_citations(final_citations), created_at=_now_iso(),
    ))

    # Re-fetch conversation to update timestamp (it was committed above)
    conv = db.get(ChatConversation, conv_id)
    if conv:
        conv.updated_at = _now_iso()
    db.commit()

    return ChatResponseBody(
        response=response_text,
        citations=final_citations,
        conversation_id=conv_id,
    )


def _make_llm_client(settings: Settings) -> LLMClient:
    """Create an LLMClient from current settings / env vars."""
    ollama_base = settings.aipam_ollama_url.rstrip("/")
    config = LLMConfig(
        endpoint=os.getenv("LLM_ENDPOINT", f"{ollama_base}/v1/chat/completions"),
        model=os.getenv("LLM_MODEL_NAME", "aipam-trafficllm-v8"),
        temperature=0.3,
        max_tokens=int(os.getenv("LLM_MAX_TOKENS", "2048")),
    )
    return LLMClient(config=config)


@router.post("/jobs/{job_id}/chat/stream")
async def chat_about_job_stream(
    job_id: str,
    body: ChatRequestBody,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Stream chat response tokens via SSE for real-time display."""
    # Verify job exists
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")

    # Get or create conversation
    now = _now_iso()
    if body.conversation_id:
        conv = db.get(ChatConversation, body.conversation_id)
        if not conv or conv.job_id != job_id:
            raise HTTPException(status_code=404, detail="conversation not found")
        conv_id = conv.id
    else:
        conv_id = str(uuid.uuid4())
        conv = ChatConversation(id=conv_id, job_id=job_id, created_at=now, updated_at=now)
        db.add(conv)

    # Save user message
    user_msg_id = str(uuid.uuid4())
    db.add(ChatMessage(
        id=user_msg_id, conversation_id=conv_id, role="user",
        content=body.message, created_at=now,
    ))

    messages, citations, combined_context = await _build_chat_messages(
        db, job_id, settings, conv_id, body.message
    )

    # Commit user message before long LLM call
    db.commit()

    client = _make_llm_client(settings)

    async def event_generator() -> AsyncGenerator[str, None]:
        """Yield SSE events: final meta, token chunks, then [DONE]."""
        full_response: list[str] = []
        try:
            async for token in client.chat_completion_stream(messages, temperature=0.3):
                if token:
                    full_response.append(token)
        except Exception as exc:
            logger.exception("LLM streaming failed for job %s", job_id)
            final_citations = _dedupe_citations(citations, limit=8)
            error_text = _append_sources_and_limits(
                f"Error: {str(exc)[:200]}",
                final_citations,
            )
            full_response = [error_text]
        else:
            error_text = None

        # Save the complete assistant message
        if error_text is None:
            response_text, final_citations = _finalize_grounded_response_payload(
                "".join(full_response),
                citations,
                combined_context,
                body.message,
            )
        else:
            response_text = "".join(full_response)

        yield f"data: {json.dumps({'type': 'meta', 'conversation_id': conv_id, 'citations': [c.model_dump() for c in final_citations], 'confidence': 0.85})}\n\n"

        try:
            asst_msg_id = str(uuid.uuid4())
            db.add(ChatMessage(
                id=asst_msg_id, conversation_id=conv_id, role="assistant",
                content=response_text,
                citations_json=_serialize_citations(final_citations),
                created_at=_now_iso(),
            ))
            conv_obj = db.get(ChatConversation, conv_id)
            if conv_obj:
                conv_obj.updated_at = _now_iso()
            db.commit()
        except Exception:
            logger.exception("Failed to persist assistant message for conv %s", conv_id)

        for chunk in _chunk_text(response_text):
            yield f"data: {json.dumps({'type': 'token', 'content': chunk})}\n\n"

        yield "data: [DONE]\n\n"

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
        .where(ChatConversation.job_id == job_id)
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
        .order_by(ChatMessage.created_at.asc())
    ).scalars().all()

    messages = []
    for m in rows:
        citations = []
        if m.citations_json:
            try:
                parsed = json.loads(m.citations_json)
                citations = parsed.get("items", []) if isinstance(parsed, dict) else parsed
            except Exception:
                pass
        messages.append({
            "role": m.role,
            "content": m.content,
            "citations": citations,
            "timestamp": m.created_at,
        })

    return ConversationHistoryOut(
        id=conv.id, job_id=conv.job_id,
        messages=messages,
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

    # Delete all associated messages first
    db.execute(
        ChatMessage.__table__.delete().where(ChatMessage.conversation_id == conversation_id)
    )
    db.delete(conv)
    db.commit()
    return None

