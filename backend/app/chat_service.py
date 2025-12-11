"""
Chat service for interactive Q&A about PCAP analysis findings.

This module provides context retrieval and LLM-powered chat functionality
for asking follow-up questions about analysis results.
"""

from typing import List, Optional, Dict, Any
from uuid import uuid4

from .models import AnalysisSummary, HostFinding, JobResult
from .schemas import ChatCitation, ChatResponse
from .llm_client import LLMClient, LLMConfig
from .settings_runtime import get_effective_settings


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

    return "\n".join(context_parts), citations


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
    job_result: Dict[str, Any],
    user_message: str,
    context_hint: Optional[str] = None,
    conversation_history: Optional[List[Dict[str, str]]] = None,
) -> ChatResponse:
    """
    Generate a chat response about the analysis findings.

    Args:
        job_result: The complete job result data
        user_message: The user's question
        context_hint: Optional hint about what the question relates to
        conversation_history: Previous messages in this conversation

    Returns:
        ChatResponse with the AI response and citations
    """
    # Build context from job result
    context, citations = build_context_from_job_result(job_result, context_hint)

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

    # Add conversation history if provided
    if conversation_history:
        for msg in conversation_history[-10:]:  # Limit history to last 10 messages
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

        return ChatResponse(
            response=response_text,
            citations=citations,
            conversation_id=str(uuid4()),
            confidence=0.85,  # TODO: Calculate actual confidence
        )
    except Exception as e:
        return ChatResponse(
            response=f"I encountered an error while processing your question: {str(e)}",
            citations=[],
            conversation_id=str(uuid4()),
            confidence=0.0,
        )

