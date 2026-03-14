"""
Chat service for interactive Q&A about PCAP analysis findings.

This module provides RAG-based context retrieval and LLM-powered chat functionality
for asking follow-up questions about analysis results. Supports conversation
persistence, anomaly-aware retrieval ranking, and cross-job forensic memory.

Phase 5: Three-source context injection:
    1. Current case RAG / job result (per-job LanceDB)
    2. Forensic narrative + campaign correlation (DAWN artifacts)
    3. Global forensic memory (cross-job ChromaDB)
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from uuid import uuid4

from sqlmodel import Session, select

from .schemas import ChatCitation, ChatResponse
from .llm_client import LLMClient, LLMConfig
from .settings_runtime import get_effective_settings
from . import database
from .db_models import ConversationDB, ChatMessageDB

logger = logging.getLogger(__name__)

_IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_CREDENTIAL_CLAIM_RE = re.compile(
    r"\b(?:password|passwd|pwd|credential(?:s)?)\b\s*(?:is|=|:)\s*['\"]?([A-Za-z0-9!@#$%^&*._-]{3,})",
    re.IGNORECASE,
)


def _dedupe_citations(citations: List[ChatCitation], limit: int = 8) -> List[ChatCitation]:
    """Keep citation order stable while removing duplicates and empty snippets."""
    deduped: List[ChatCitation] = []
    seen: set[tuple[str, Optional[str], str]] = set()

    for citation in citations:
        snippet = (citation.snippet or "").strip()
        if not snippet:
            continue
        key = (citation.type, citation.id, snippet)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ChatCitation(type=citation.type, id=citation.id, snippet=snippet[:200]))
        if len(deduped) >= limit:
            break

    return deduped


def _build_sources_block(citations: List[ChatCitation]) -> str:
    """Render a deterministic source list from current-job citations."""
    lines = ["Sources used:"]
    safe_citations = _dedupe_citations(citations)

    if not safe_citations:
        lines.append("- No source snippets were available from the current job data.")
        return "\n".join(lines)

    for citation in safe_citations:
        lines.append(f"- [{citation.type}] {citation.snippet}")
    return "\n".join(lines)


def _append_sources_and_limits(response_text: str, citations: List[ChatCitation]) -> str:
    """Append deterministic source and limits sections to the assistant response."""
    return (
        f"{response_text.rstrip()}\n\n"
        f"{_build_sources_block(citations)}\n\n"
        "Limits: Any detail not shown in the sources above is not available in the collected data for this job."
    )


def _unsupported_response_details(response_text: str, combined_context: str) -> tuple[List[str], List[str]]:
    """Find IPs or credential-like values mentioned in a response that are absent from evidence."""
    supported_ips = set(_IPV4_RE.findall(combined_context))
    mentioned_ips = set(_IPV4_RE.findall(response_text))
    unsupported_ips = sorted(ip for ip in mentioned_ips if ip not in supported_ips)

    unsupported_credentials: List[str] = []
    for match in _CREDENTIAL_CLAIM_RE.finditer(response_text):
        candidate = match.group(1).strip()
        if candidate and candidate not in combined_context:
            unsupported_credentials.append(candidate)

    return unsupported_ips, unsupported_credentials


def _build_unsupported_claims_response(citations: List[ChatCitation]) -> str:
    """Fallback response when the model produced unsupported specifics."""
    lines = [
        "I can only answer from the collected data for this job.",
        "I am not asserting some specific details because they were not supported by the evidence provided to the model.",
        "",
        "What the current job data does support:",
    ]

    safe_citations = _dedupe_citations(citations, limit=6)
    if safe_citations:
        for citation in safe_citations:
            lines.append(f"- [{citation.type}] {citation.snippet}")
    else:
        lines.append("- No supporting source snippets were available from the current job data.")

    lines.extend(
        [
            "",
            "Limits: Any IP address, credential value, payload content, or other detail not shown above is not available in the collected data for this job.",
        ]
    )
    return "\n".join(lines)


def _finalize_grounded_response(
    response_text: str,
    citations: List[ChatCitation],
    combined_context: str,
) -> str:
    """Ensure the final answer stays inside current-job evidence boundaries."""
    safe_citations = _dedupe_citations(citations, limit=8)
    if not response_text.strip():
        response_text = "That specific information is not available in the analysis data I have access to."
    unsupported_ips, unsupported_credentials = _unsupported_response_details(response_text, combined_context)

    if unsupported_ips or unsupported_credentials:
        logger.warning(
            "Blocked unsupported chat claims (ips=%s, credentials=%s)",
            unsupported_ips,
            unsupported_credentials,
        )
        return _build_unsupported_claims_response(safe_citations)

    return _append_sources_and_limits(response_text, safe_citations)


def _chunk_text(text: str, chunk_size: int = 350) -> List[str]:
    """Split a response into UI-friendly chunks for SSE delivery."""
    if not text:
        return []
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]


def build_context_from_job_result(
    job_result: Dict[str, Any],
    context_hint: Optional[str] = None,
) -> tuple[str, List[ChatCitation]]:
    """
    Build relevant context from a job result for the chat LLM.

    Returns a tuple of (context_string, citations).
    """
    citations: List[ChatCitation] = []
    context_parts: List[str] = []

    # 1. Include overall summary
    summary = job_result.get("summary", {})
    if summary:
        classification = summary.get("classification")
        severity = summary.get("severity", "unknown")
        key_findings = summary.get("key_findings", [])
        mitre = summary.get("mitre_techniques", [])

        header = "## Analysis Summary"
        context_parts.append(header)
        if classification:
            context_parts.append(f"- Classification: {classification}")
        context_parts.append(f"- Severity: {severity}")
        citations.append(
            ChatCitation(
                type="analysis_summary",
                id="summary",
                snippet=f"Classification: {classification or 'unknown'} | Severity: {severity}"[:200],
            )
        )

        if key_findings:
            context_parts.append("### Key Findings:")
            for i, finding in enumerate(key_findings):
                # Handle both string findings and dict findings
                if isinstance(finding, dict):
                    finding_text = finding.get("description", str(finding))
                else:
                    finding_text = str(finding)
                context_parts.append(f"- {finding_text}")
                citations.append(ChatCitation(
                    type="finding",
                    id=f"finding-{i}",
                    snippet=finding_text[:200]
                ))

        if mitre:
            mitre_list = ", ".join([
                f"{t.get('id', 'Unknown')} ({t.get('name', '')})"
                for t in mitre if isinstance(t, dict)
            ])
            context_parts.append(f"### MITRE ATT&CK Techniques: {mitre_list}")

    # 2. Include host findings
    hosts = job_result.get("hosts", [])
    if hosts:
        context_parts.append("\n## Host Analysis")
        for host in hosts:
            ip = host.get("ip", "unknown")
            role = host.get("role", "unknown")
            findings = host.get("findings", [])

            context_parts.append(f"\n### Host: {ip} (Role: {role})")
            for finding in findings:
                context_parts.append(f"- {finding}")
            host_snippet = f"Host {ip} (role: {role})"
            if findings:
                host_snippet += f": {' | '.join(str(f) for f in findings[:2])}"
            citations.append(ChatCitation(
                type="host_summary",
                id=ip,
                snippet=host_snippet[:200],
            ))

    # 3. Include raw alerts if available
    raw = job_result.get("raw", {})
    alerts = raw.get("alerts", [])
    if alerts and len(alerts) > 0:
        context_parts.append("\n## Alerts")
        # Limit to most relevant alerts
        shown_alerts = alerts[:20]  # Limit to prevent context overflow
        for alert in shown_alerts:
            if isinstance(alert, dict):
                sig = alert.get("signature", alert.get("signature_name", "Unknown"))
                sev = alert.get("severity", "unknown")
                src = alert.get("src_ip", "")
                dst = alert.get("dst_ip", "")
                alert_text = f"[{sev}] {sig}"
                if src or dst:
                    alert_text += f" ({src} → {dst})"
                context_parts.append(f"- {alert_text}")
                citations.append(ChatCitation(
                    type="alert",
                    id=alert.get("id", str(uuid4())[:8]),
                    snippet=alert_text[:200],
                ))

    # 4. Include detailed forensic anomalies (SSIs)
    # Access chunks via raw -> llm_analysis_raw
    llm_raw = job_result.get("raw", {}).get("llm_analysis_raw", {})
    chunks = llm_raw.get("chunks", []) if isinstance(llm_raw, dict) else []
    
    if chunks:
        context_parts.append("\n## Detailed Forensic Anomalies (SSIs)")
        seen_anomalies = set()
        for chunk in chunks:
            if isinstance(chunk, dict) and chunk.get("anomalies"):
                for a in chunk["anomalies"]:
                    desc = a.get('description', 'Anomaly')
                    if desc in seen_anomalies:
                        continue
                    seen_anomalies.add(desc)
                    
                    reason = a.get('reason', '')
                    hosts = ", ".join(a.get('related_hosts', []))
                    anomaly_text = f"[{desc}] Reason: {reason} (Hosts: {hosts})"
                    context_parts.append(f"- {anomaly_text}")
                    
                    citations.append(ChatCitation(
                        type="forensic_anomaly",
                        id=f"anomaly-{len(seen_anomalies)}",
                        snippet=anomaly_text
                    ))

    return "\n".join(context_parts), citations


def build_context_from_job_metadata(
    job_id: str,
    job_source: Optional[str] = None,
    job_mode: Optional[str] = None,
    exercise_id: Optional[str] = None,
    job_metadata: Optional[Dict[str, Any]] = None,
) -> tuple[str, List[ChatCitation]]:
    """Build a small, always-present context header so the model knows this chat
    is anchored to a completed analysis job (and usually one or more PCAPs).

    This is the main guardrail against the model claiming no file was uploaded.
    """

    md = job_metadata or {}
    citations: List[ChatCitation] = []

    lines: List[str] = []
    lines.append("## Job / PCAP Metadata")
    lines.append(f"- Job ID: {job_id}")

    if job_source:
        lines.append(f"- Source: {job_source}")
    if job_mode:
        lines.append(f"- Mode: {job_mode}")
    if exercise_id:
        lines.append(f"- Exercise ID: {exercise_id}")

    pcap_paths = md.get("pcap_paths")
    if isinstance(pcap_paths, list) and pcap_paths:
        # Prefer basenames so we don't leak full filesystem paths into prompts.
        try:
            from pathlib import Path

            names = [Path(str(p)).name for p in pcap_paths if p]
        except Exception:
            names = [str(p) for p in pcap_paths if p]

        names = [n for n in names if n]
        if names:
            shown = names[:10]
            more = "" if len(names) <= 10 else f" (+{len(names) - 10} more)"
            lines.append(f"- PCAP(s): {', '.join(shown)}{more}")
            citations.append(
                ChatCitation(
                    type="job_metadata",
                    id=job_id,
                    snippet=("PCAP(s): " + ", ".join(shown))[:200],
                )
            )

    return "\n".join(lines), citations


def build_context_from_rag(
    job_id: str,
    query: str,
    top_k: int = 8,
) -> tuple[str, List[ChatCitation]]:
    """
    Build context using RAG retrieval from the vector index.

    Returns a tuple of (context_string, citations).
    Falls back to empty if no index exists.
    """
    try:
        from .rag_index import search_job_index, job_has_index

        if not job_has_index(job_id):
            logger.info(f"No RAG index for job {job_id}, using fallback context")
            return "", []

        results = search_job_index(job_id, query, top_k=top_k, rerank_by_anomaly=True)

        if not results:
            return "", []

        citations: List[ChatCitation] = []
        context_parts: List[str] = []

        context_parts.append("## Retrieved Analysis Data (ranked by relevance)")

        for result in results:
            doc = result.document
            context_parts.append(f"\n### [{doc.doc_type.upper()}] (relevance: {result.score:.2f})")
            context_parts.append(doc.content)

            citations.append(ChatCitation(
                type=doc.doc_type,
                id=doc.id,
                snippet=doc.content[:200],
            ))

        return "\n".join(context_parts), citations

    except ImportError:
        logger.warning("RAG index module not available")
        return "", []
    except Exception as e:
        logger.error(f"RAG retrieval failed: {e}")
        return "", []


# ---------------------------------------------------------------------------
# Phase 5: Cross-job context sources
# ---------------------------------------------------------------------------

def _load_forensic_narrative(job_id: str) -> str:
    """Load the aipam.forensic.narrative markdown for the current case.

    Looks in the DAWN project sandbox or the file storage path.
    """
    try:
        effective = get_effective_settings()
        job_dir = effective.file_storage_path / job_id

        # Try DAWN artifact path first
        for candidate in [
            job_dir / "artifacts" / "forensic_narrative.md",
            job_dir / "forensic_narrative.md",
        ]:
            if candidate.exists():
                text = candidate.read_text()
                if text.strip():
                    logger.info("Loaded forensic narrative (%d chars) for job %s",
                                len(text), job_id)
                    return text
    except Exception as exc:
        logger.debug("Forensic narrative not available for %s: %s", job_id, exc)
    return ""


def _load_campaign_correlation(job_id: str) -> str:
    """Load campaign correlation data for cross-case links."""
    try:
        import json as _json
        effective = get_effective_settings()
        job_dir = effective.file_storage_path / job_id

        for candidate in [
            job_dir / "artifacts" / "campaign_correlation.json",
            job_dir / "campaign_correlation.json",
        ]:
            if candidate.exists():
                with open(candidate) as f:
                    data = _json.load(f)
                # Format for context
                parts = ["## Campaign Correlations (linked cases)"]
                campaigns = data.get("campaigns", [])
                for c in campaigns:
                    name = c.get("campaign_name", "Unknown")
                    shared = c.get("shared_iocs", [])
                    projects = c.get("linked_projects", [])
                    parts.append(f"\n### Campaign: {name}")
                    parts.append(f"Linked cases: {', '.join(str(p) for p in projects)}")
                    if shared:
                        parts.append(f"Shared IOCs: {', '.join(str(i) for i in shared[:10])}")
                return "\n".join(parts)
    except Exception as exc:
        logger.debug("Campaign correlation not available for %s: %s", job_id, exc)
    return ""


def _query_forensic_memory(
    query: str,
    top_k: int = 5,
) -> tuple[str, List[ChatCitation]]:
    """Query the global ChromaDB forensic memory for cross-case recall."""
    try:
        from .forensic_memory import query_memory

        hits = query_memory(query, top_k=top_k)
        if not hits:
            return "", []

        citations: List[ChatCitation] = []
        parts = ["## Forensic Memory (similar findings from past cases)"]

        for hit in hits:
            meta = hit.get("metadata", {})
            doc = hit.get("document", "")
            relevance = hit.get("relevance", 0)
            job = meta.get("job_id", "unknown")
            project = meta.get("project_id", "unknown")
            mitre = meta.get("mitre_technique_id", "")

            parts.append(
                f"\n### [Past Case: {project}] (relevance: {relevance:.0%})\n"
                f"Job: {job} | MITRE: {mitre}\n"
                f"{doc}"
            )
            citations.append(ChatCitation(
                type="forensic_memory",
                id=f"memory-{job[:8]}",
                snippet=doc[:200],
            ))

        return "\n".join(parts), citations

    except ImportError:
        logger.debug("forensic_memory module not available")
        return "", []
    except Exception as exc:
        logger.error("Forensic memory query failed: %s", exc)
        return "", []


# Conversation persistence functions

def get_or_create_conversation(
    job_id: str,
    conversation_id: Optional[str] = None,
) -> str:
    """Get existing conversation or create a new one."""
    with Session(database.engine) as session:
        if conversation_id:
            conv = session.get(ConversationDB, conversation_id)
            if conv and conv.job_id == job_id:
                return conversation_id

        # Create new conversation
        new_id = str(uuid4())
        now = datetime.now(timezone.utc)
        conv = ConversationDB(
            id=new_id,
            job_id=job_id,
            created_at=now,
            updated_at=now,
        )
        session.add(conv)
        session.commit()
        return new_id


def save_chat_message(
    conversation_id: str,
    role: str,
    content: str,
    citations: Optional[List[ChatCitation]] = None,
) -> str:
    """Save a chat message to the database."""
    with Session(database.engine) as session:
        msg_id = str(uuid4())
        msg = ChatMessageDB(
            id=msg_id,
            conversation_id=conversation_id,
            role=role,
            content=content,
            citations={"items": [c.model_dump() for c in (citations or [])]},
            created_at=datetime.now(timezone.utc),
        )
        session.add(msg)

        # Update conversation timestamp
        conv = session.get(ConversationDB, conversation_id)
        if conv:
            conv.updated_at = datetime.now(timezone.utc)
            session.add(conv)

        session.commit()
        return msg_id


def get_conversation_history(
    conversation_id: str,
    limit: int = 10,
) -> List[Dict[str, str]]:
    """Get conversation history as a list of messages for the LLM."""
    with Session(database.engine) as session:
        messages = session.exec(
            select(ChatMessageDB)
            .where(ChatMessageDB.conversation_id == conversation_id)
            .order_by(ChatMessageDB.created_at.desc())
            .limit(limit)
        ).all()

        # Reverse to get chronological order
        messages = list(reversed(messages))

        return [{"role": msg.role, "content": msg.content} for msg in messages]


CHAT_SYSTEM_PROMPT = """You are a Lead Forensic Investigator helping a user understand PCAP analysis results.

You may use ONLY the current job evidence provided in the context window:
1. Job / PCAP metadata for this job
2. Findings, alerts, IOCs, host summaries, and per-job retrieval results from this same job

You must NOT use or imply any information from past cases, campaign correlation, external memory,
threat intel, geolocation, WHOIS, VirusTotal, or anything else that is not explicitly present in
the current-job context.

CRITICAL — DATA BOUNDARIES (read carefully):
You do NOT have access to:
- Raw packet payloads or packet captures
- HTTP request/response bodies (POST data, headers, cookies)
- Actual cleartext passwords, usernames, or credentials
- DNS query responses or full DNS records
- TLS certificate details beyond what is in the summaries
- File contents of extracted files
- Any data not explicitly present in the context provided below

When a Suricata alert says something like 'Http Client Body contains pwd= in cleartext',
that means the signature MATCHED — but you can only see the alert name, severity, and
src/dst IPs. You MUST NOT guess or fabricate the password, username, or any payload content.
Instead say: 'The alert indicates a cleartext password was transmitted, but the actual
password value is not available in my analysis data.'

YOUR JOB:
- Answer the user's questions thoroughly using ONLY the data in the context below.
- When asked to show evidence, QUOTE the specific current-job alerts, findings, IPs, signatures, and timestamps from the context.
- Be helpful. If the context has relevant data, USE it to answer — do not refuse.

ANTI-HALLUCINATION RULES (MANDATORY):
1. NEVER fabricate, guess, or infer specific values not explicitly in the context.
   This includes IP addresses, passwords, usernames, domain names, file contents, and payload data.
2. Only cite IP addresses that ACTUALLY APPEAR in the provided data.
3. If the user asks for information not in the data, say: 'That specific information is
   not available in the analysis data I have access to.' Do NOT make up an answer.
4. When describing what an alert means, clearly distinguish between 'the alert signature
   indicates X happened' vs 'I can see the actual value of X in the data'.
5. If you are uncertain, say so. Never present speculation as fact.

ADDITIONAL RULES:
- You do NOT have access to external databases, geolocation, WHOIS, or VirusTotal. Do not claim otherwise.
- If asked about info NOT in the context (e.g., geolocation), say it's not available and suggest an external service.

REQUIRED RESPONSE STYLE:
1. Give a direct answer based only on the current-job context.
2. Explicitly name the evidence you relied on.
3. If something is missing, state that it is not available in the current-job data.
4. Never treat prior assistant messages as evidence.
5. **End with specific recommendations** based on what IS in the analysis.

Be thorough but honest. If something is not in the context, say so instead of guessing."""

async def _build_chat_context_and_messages(
    job_id: str,
    job_result: Dict[str, Any],
    user_message: str,
    conv_id: str,
    context_hint: Optional[str] = None,
    use_rag: bool = True,
    job_metadata: Optional[Dict[str, Any]] = None,
    job_source: Optional[str] = None,
    job_mode: Optional[str] = None,
    exercise_id: Optional[str] = None,
) -> tuple[List[Dict[str, str]], List[ChatCitation], float, str]:
    """Assemble an evidence-only current-job context window and messages for the LLM."""
    # Get conversation history for context
    history = get_conversation_history(conv_id, limit=10)
    # Remove the message we just added (it will be added as current message)
    if history and history[-1]["content"] == user_message:
        history = history[:-1]
    history = [msg for msg in history if msg.get("role") == "user"]

    metadata_context, metadata_citations = build_context_from_job_metadata(
        job_id=job_id,
        job_source=job_source,
        job_mode=job_mode,
        exercise_id=exercise_id,
        job_metadata=job_metadata,
    )

    # ── Current-job evidence: Per-job RAG / direct context ─────────
    rag_context = ""
    rag_citations: List[ChatCitation] = []

    if use_rag:
        rag_context, rag_citations = build_context_from_rag(job_id, user_message, top_k=8)

    if not rag_context:
        case_context, case_citations = build_context_from_job_result(job_result, context_hint)
    else:
        case_context = rag_context
        case_citations = rag_citations

    citations = _dedupe_citations([*metadata_citations, *case_citations], limit=12)

    # ── Assemble the current-job-only context window ──────────────
    context_sections = []

    if metadata_context:
        context_sections.append(f"## Source 1: Job Metadata (Current Job)\n\n{metadata_context}")
    if case_context:
        context_sections.append(f"## Source 2: Current Job Evidence\n\n{case_context}")

    combined_context = "\n\n---\n\n".join(context_sections) if context_sections else "No analysis data available."

    # Build the conversation messages
    messages = [{"role": "system", "content": CHAT_SYSTEM_PROMPT}]

    # Add only current-job evidence as a system message
    messages.append({
        "role": "system",
        "content": (
            "=== CURRENT JOB EVIDENCE ONLY ===\n\n"
            f"{combined_context}\n\n"
            "=== END CURRENT JOB EVIDENCE ===\n\n"
            "Use only the current-job evidence above. Conversation history contains prior user questions only and is not evidence. "
            "If a detail is not present in the current-job evidence above, say it is not available."
        ),
    })

    # Add conversation history if available
    if history:
        for msg in history[-10:]:  # Limit history to last 10 messages
            messages.append(msg)

    # Add the current user message
    messages.append({"role": "user", "content": user_message})

    # Calculate confidence based on RAG results
    confidence = 0.85
    if rag_citations:
        # Higher confidence if we have RAG results with good scores
        avg_relevance = sum(c.snippet is not None for c in rag_citations) / max(len(rag_citations), 1)
        confidence = min(0.95, 0.7 + (avg_relevance * 0.25))

    return messages, citations, confidence, combined_context


async def generate_chat_response(
    job_id: str,
    job_result: Dict[str, Any],
    user_message: str,
    context_hint: Optional[str] = None,
    conversation_id: Optional[str] = None,
    use_rag: bool = True,
    job_metadata: Optional[Dict[str, Any]] = None,
    job_source: Optional[str] = None,
    job_mode: Optional[str] = None,
    exercise_id: Optional[str] = None,
) -> ChatResponse:
    """
    Generate a chat response about the analysis findings.
    """
    # Get or create conversation for persistence
    conv_id = get_or_create_conversation(job_id, conversation_id)

    # Save user message
    save_chat_message(conv_id, "user", user_message)

    messages, citations, confidence, combined_context = await _build_chat_context_and_messages(
        job_id,
        job_result,
        user_message,
        conv_id,
        context_hint,
        use_rag,
        job_metadata,
        job_source,
        job_mode,
        exercise_id,
    )

    # Get LLM configuration
    effective = get_effective_settings()
    routing_msg = (
        f"Chat LLM routing: endpoint={effective.llm_endpoint} model={effective.llm_model_name} "
        f"(job_id={job_id})"
    )
    logger.info(routing_msg)
    print(routing_msg, flush=True)
    config = LLMConfig(
        endpoint=effective.llm_endpoint,
        model=effective.llm_model_name,
        temperature=0.3,  # Lower temperature for more focused responses
        max_tokens=effective.llm_max_tokens,
    )

    client = LLMClient(config=config)

    try:
        # Call LLM (not using JSON mode for chat)
        response_text = await client.chat_completion(messages)
        response_text = _finalize_grounded_response(response_text, citations, combined_context)

        response = ChatResponse(
            response=response_text,
            citations=citations,
            conversation_id=conv_id,
            confidence=confidence,
        )

        # Save assistant response
        save_chat_message(conv_id, "assistant", response_text, citations)

        return response

    except Exception as e:
        logger.error(f"Chat response generation failed: {e}")
        error_response = ChatResponse(
            response=_append_sources_and_limits(
                f"I encountered an error while processing your question: {str(e)}",
                citations,
            ),
            citations=citations,
            conversation_id=conv_id,
            confidence=0.0,
        )
        save_chat_message(conv_id, "assistant", error_response.response, citations)
        return error_response


async def generate_chat_response_stream(
    job_id: str,
    job_result: Dict[str, Any],
    user_message: str,
    context_hint: Optional[str] = None,
    conversation_id: Optional[str] = None,
    use_rag: bool = True,
    job_metadata: Optional[Dict[str, Any]] = None,
    job_source: Optional[str] = None,
    job_mode: Optional[str] = None,
    exercise_id: Optional[str] = None,
):
    """
    Generate a streaming chat response about the analysis findings, sending SSE chunks.
    """
    import json
    # Get or create conversation for persistence
    conv_id = get_or_create_conversation(job_id, conversation_id)

    # Save user message
    save_chat_message(conv_id, "user", user_message)

    messages, citations, confidence, combined_context = await _build_chat_context_and_messages(
        job_id,
        job_result,
        user_message,
        conv_id,
        context_hint,
        use_rag,
        job_metadata,
        job_source,
        job_mode,
        exercise_id,
    )

    # First, send metadata/citations before generating text
    meta_payload = {
        "conversation_id": conv_id,
        "citations": [c.model_dump() for c in citations],
        "confidence": confidence
    }
    yield f"data: {json.dumps(meta_payload)}\n\n"

    # Get LLM configuration
    effective = get_effective_settings()
    config = LLMConfig(
        endpoint=effective.llm_endpoint,
        model=effective.llm_model_name,
        temperature=0.3,
        max_tokens=effective.llm_max_tokens,
    )
    client = LLMClient(config=config)

    full_response = ""
    try:
        async for chunk in client.chat_completion_stream(messages):
            if chunk:
                full_response += chunk
        final_response = _finalize_grounded_response(full_response, citations, combined_context)

        # Save assistant response to database when complete
        if final_response:
            save_chat_message(conv_id, "assistant", final_response, citations)
            for chunk in _chunk_text(final_response):
                data_payload = {"type": "token", "content": chunk}
                yield f"data: {json.dumps(data_payload)}\n\n"

    except Exception as e:
        logger.error(f"Chat stream generation failed: {e}")
        error_response = _append_sources_and_limits(
            f"I encountered an error while processing your question: {str(e)}",
            citations,
        )
        save_chat_message(conv_id, "assistant", error_response, citations)
        for chunk in _chunk_text(error_response):
            data_payload = {"type": "token", "content": chunk}
            yield f"data: {json.dumps(data_payload)}\n\n"
        
    yield "data: [DONE]\n\n"

