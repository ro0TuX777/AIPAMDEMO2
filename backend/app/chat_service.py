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
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from uuid import uuid4

from sqlmodel import Session, select

from .models import AnalysisSummary, HostFinding, JobResult
from .schemas import ChatCitation, ChatResponse
from .llm_client import LLMClient, LLMConfig
from .settings_runtime import get_effective_settings
from .database import engine
from .db_models import ConversationDB, ChatMessageDB

logger = logging.getLogger(__name__)


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
        severity = summary.get("severity", "unknown")
        key_findings = summary.get("key_findings", [])
        mitre = summary.get("mitre_techniques", [])

        context_parts.append(f"## Analysis Summary\n- Severity: {severity}")

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

            # If context_hint mentions this IP, prioritize it
            is_relevant = context_hint and ip in context_hint

            context_parts.append(f"\n### Host: {ip} (Role: {role})")
            for finding in findings:
                context_parts.append(f"- {finding}")
                if is_relevant:
                    citations.append(ChatCitation(
                        type="host_summary",
                        id=ip,
                        snippet=finding[:200]
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

                # Add citation if relevant to hint
                if context_hint and (src in context_hint or dst in context_hint):
                    citations.append(ChatCitation(
                        type="alert",
                        id=alert.get("id", str(uuid4())[:8]),
                        snippet=alert_text
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
    with Session(engine) as session:
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
    with Session(engine) as session:
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
    with Session(engine) as session:
        messages = session.exec(
            select(ChatMessageDB)
            .where(ChatMessageDB.conversation_id == conversation_id)
            .order_by(ChatMessageDB.created_at.desc())
            .limit(limit)
        ).all()

        # Reverse to get chronological order
        messages = list(reversed(messages))

        return [{"role": msg.role, "content": msg.content} for msg in messages]


CHAT_SYSTEM_PROMPT = """You are a Lead Forensic Investigator with access to three intelligence sources:

1. **Current Case Analysis** — Findings, alerts, and host data from this job
2. **Campaign Correlations** — Linked cases sharing IOCs or techniques
3. **Forensic Memory** — Confirmed findings from ALL past investigations

IMPORTANT: Blend your expert knowledge with the SPECIFIC analysis data. Reference actual IPs, malware names, and findings. When citing past cases, be specific (e.g., "similar to what we observed in Case-002 last week").

Response style — be conversational and analytical:

1. **Start with your expert knowledge** — Explain the technique/concept briefly (include MITRE ATT&CK ID).

2. **Then explicitly analyze the findings** — Use natural language like:
   - "I see evidence of this in the analysis: [quote specific finding]"
   - "I don't see direct evidence of [X] in this analysis. However, I do see [Y]..."
   - "This traffic looks like [malware], similar to what we saw in [past case]."

3. **Connect the dots** — Explain relationships between current and historical findings.

4. **Cite your sources** — Label whether you are drawing from [Current Case], [Campaign Correlation], or [Forensic Memory].

5. **End with specific recommendations** based on what IS in the analysis.

Be thorough but conversational. Reference the actual hosts, malware types, and findings by name."""


async def generate_chat_response(
    job_id: str,
    job_result: Dict[str, Any],
    user_message: str,
    context_hint: Optional[str] = None,
    conversation_id: Optional[str] = None,
    use_rag: bool = True,
) -> ChatResponse:
    """
    Generate a chat response about the analysis findings.

    Uses RAG retrieval when available, with fallback to direct context injection.
    Supports conversation persistence for follow-up questions.

    Args:
        job_id: The job ID for RAG lookup and conversation persistence
        job_result: The complete job result data
        user_message: The user's question
        context_hint: Optional hint about what the question relates to
        conversation_id: Optional conversation ID for follow-up questions
        use_rag: Whether to use RAG retrieval (falls back to direct context if no index)

    Returns:
        ChatResponse with the AI response and citations
    """
    # Get or create conversation for persistence
    conv_id = get_or_create_conversation(job_id, conversation_id)

    # Save user message
    save_chat_message(conv_id, "user", user_message)

    # Get conversation history for context
    history = get_conversation_history(conv_id, limit=10)
    # Remove the message we just added (it will be added as current message)
    if history and history[-1]["content"] == user_message:
        history = history[:-1]

    # ── Source 1: Per-job RAG / direct context ─────────────────────
    rag_context = ""
    rag_citations: List[ChatCitation] = []

    if use_rag:
        rag_context, rag_citations = build_context_from_rag(job_id, user_message, top_k=8)

    if not rag_context:
        fallback_context, fallback_citations = build_context_from_job_result(job_result, context_hint)
        case_context = fallback_context
        citations = fallback_citations
    else:
        case_context = rag_context
        citations = rag_citations

    # ── Source 2: Forensic narrative + campaign correlation ────────
    narrative_context = _load_forensic_narrative(job_id)
    correlation_context = _load_campaign_correlation(job_id)

    # ── Source 3: Global forensic memory (cross-job ChromaDB) ─────
    memory_context, memory_citations = _query_forensic_memory(user_message, top_k=5)
    citations.extend(memory_citations)

    # ── Assemble the three-source context window ──────────────────
    context_sections = []

    if case_context:
        context_sections.append(
            f"## Source 1: Current Case Analysis\n\n{case_context}"
        )
    if narrative_context:
        context_sections.append(
            f"## Source 2: Forensic Narrative (Current Case)\n\n{narrative_context[:3000]}"
        )
    if correlation_context:
        context_sections.append(
            f"## Source 3: Campaign Correlations\n\n{correlation_context}"
        )
    if memory_context:
        context_sections.append(
            f"## Source 4: Forensic Memory (Past Cases)\n\n{memory_context}"
        )

    combined_context = "\n\n---\n\n".join(context_sections) if context_sections else "No analysis data available."

    # Build the conversation messages
    messages = [
        {"role": "system", "content": CHAT_SYSTEM_PROMPT},
    ]

    # Add the three-source context as a system message
    messages.append({
        "role": "system",
        "content": f"""=== FORENSIC INTELLIGENCE CONTEXT (cite sources in your response) ===

{combined_context}

=== END OF FORENSIC INTELLIGENCE ===

When answering, reference specific items from the context above. Label your sources as [Current Case], [Campaign Correlation], or [Forensic Memory]. If you find similar patterns across cases, highlight them explicitly."""
    })

    # Add conversation history if available
    if history:
        for msg in history[-10:]:  # Limit history to last 10 messages
            messages.append(msg)

    # Add the current user message
    messages.append({"role": "user", "content": user_message})

    # Get LLM configuration
    effective = get_effective_settings()
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

        # Calculate confidence based on RAG results
        confidence = 0.85
        if rag_citations:
            # Higher confidence if we have RAG results with good scores
            avg_relevance = sum(c.snippet is not None for c in rag_citations) / max(len(rag_citations), 1)
            confidence = min(0.95, 0.7 + (avg_relevance * 0.25))

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
            response=f"I encountered an error while processing your question: {str(e)}",
            citations=[],
            conversation_id=conv_id,
            confidence=0.0,
        )
        save_chat_message(conv_id, "assistant", error_response.response)
        return error_response

