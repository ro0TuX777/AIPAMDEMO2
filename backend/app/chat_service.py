"""
Chat service for interactive Q&A about PCAP analysis findings.

This module provides RAG-based context retrieval and LLM-powered chat functionality
for asking follow-up questions about analysis results. Supports conversation
persistence and anomaly-aware retrieval ranking.
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


CHAT_SYSTEM_PROMPT = """You are a cybersecurity expert helping analyze PCAP findings. You have deep knowledge of MITRE ATT&CK, malware, and incident response.

IMPORTANT: Blend your expert knowledge with the SPECIFIC analysis data. Reference actual IPs, malware names, and findings.

Response style - be conversational and analytical:

1. **Start with your expert knowledge** - Explain the technique/concept briefly (include MITRE ATT&CK ID).

2. **Then explicitly analyze the findings** - Use natural language like:
   - "I see evidence of this in the analysis: [quote specific finding]"
   - "I don't see direct evidence of [X] in this analysis. However, I do see [Y] which could indicate..."
   - "The [specific malware/activity] detected here is often associated with..."

3. **Connect the dots** - Explain relationships between what was asked and what's present. Example: "While T1003 (Credential Dumping) is not directly detected, the lateral movement (T1021) between hosts suggests credentials may have been compromised through other means."

4. **End with specific recommendations** based on what IS in the analysis.

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

    # Try RAG retrieval first if enabled
    rag_context = ""
    rag_citations: List[ChatCitation] = []

    if use_rag:
        rag_context, rag_citations = build_context_from_rag(job_id, user_message, top_k=8)

    # Fallback to direct context if RAG didn't return results
    if not rag_context:
        fallback_context, fallback_citations = build_context_from_job_result(job_result, context_hint)
        context = fallback_context
        citations = fallback_citations
    else:
        context = rag_context
        citations = rag_citations

    # Build the conversation messages
    messages = [
        {"role": "system", "content": CHAT_SYSTEM_PROMPT},
    ]

    # Add context as a system message with clear formatting
    messages.append({
        "role": "system",
        "content": f"""=== PCAP ANALYSIS DATA (Reference this in your response) ===

{context}

=== END OF ANALYSIS DATA ===

When answering, you MUST reference specific items from the analysis data above (IPs, malware types, findings, alerts). If the user asks about something not in the data, explain what IS in the data that's related."""
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

