import asyncio

import pytest

from backend.app import chat_service
from backend.app.schemas import ChatCitation


def test_build_context_from_job_result_includes_host_and_alert_citations() -> None:
    job_result = {
        "summary": {
            "classification": "malicious",
            "severity": "high",
            "key_findings": ["Suspicious outbound HTTP observed"],
        },
        "hosts": [
            {"ip": "10.12.27.101", "role": "suspected_client", "findings": ["Issued HTTP POST requests"]}
        ],
        "raw": {
            "alerts": [
                {
                    "id": "alert-1",
                    "signature": "ET WEB_SERVER Http Client Body contains pwd= in cleartext",
                    "severity": "high",
                    "src_ip": "10.12.27.101",
                    "dst_ip": "198.51.100.20",
                }
            ]
        },
    }

    context, citations = chat_service.build_context_from_job_result(job_result)

    citation_types = {citation.type for citation in citations}
    assert "analysis_summary" in citation_types
    assert "host_summary" in citation_types
    assert "alert" in citation_types
    assert "10.12.27.101" in context


def test_finalize_grounded_response_blocks_unsupported_ip_and_password_claims() -> None:
    citations = [
        ChatCitation(
            type="alert",
            id="alert-1",
            snippet="[high] ET WEB_SERVER Http Client Body contains pwd= in cleartext (10.12.27.101 → 198.51.100.20)",
        )
    ]
    combined_context = "\n".join(
        [
            "## Source 2: Current Job Evidence",
            "- [high] ET WEB_SERVER Http Client Body contains pwd= in cleartext (10.12.27.101 → 198.51.100.20)",
        ]
    )

    response = chat_service._finalize_grounded_response(
        "The attacker at 192.168.1.100 used password=12345678 against 198.51.100.20.",
        citations,
        combined_context,
    )

    assert "192.168.1.100" not in response
    assert "12345678" not in response
    assert "I can only answer from the collected data for this job." in response
    assert "[alert]" in response


def test_finalize_grounded_response_appends_sources_for_supported_answer() -> None:
    citations = [
        ChatCitation(
            type="alert",
            id="alert-1",
            snippet="[high] Suspicious login alert (10.12.27.101 → 198.51.100.20)",
        )
    ]
    combined_context = "[high] Suspicious login alert (10.12.27.101 → 198.51.100.20)"

    response = chat_service._finalize_grounded_response(
        "The alert shows traffic from 10.12.27.101 to 198.51.100.20.",
        citations,
        combined_context,
    )

    assert "Sources used:" in response
    assert "Limits:" in response
    assert "10.12.27.101" in response


def test_build_chat_context_and_messages_uses_current_job_sources_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        chat_service,
        "get_conversation_history",
        lambda conv_id, limit=10: [
            {"role": "assistant", "content": "Hallucinated host 192.168.1.100"},
            {"role": "user", "content": "What happened previously?"},
        ],
    )
    monkeypatch.setattr(
        chat_service,
        "build_context_from_rag",
        lambda job_id, query, top_k=8: (
            "## Retrieved Analysis Data\n- [high] Test alert (10.12.27.101 → 198.51.100.20)",
            [
                ChatCitation(
                    type="alert",
                    id="alert-1",
                    snippet="[high] Test alert (10.12.27.101 → 198.51.100.20)",
                )
            ],
        ),
    )

    messages, citations, confidence, combined_context = asyncio.run(
        chat_service._build_chat_context_and_messages(
            job_id="job-123",
            job_result={"summary": {}, "hosts": [], "raw": {}},
            user_message="What happened?",
            conv_id="conv-123",
            use_rag=True,
            job_metadata={"pcap_paths": ["/tmp/sample.pcap"]},
            job_source="upload",
            job_mode="single_window",
        )
    )

    assert "Job Metadata (Current Job)" in combined_context
    assert "Current Job Evidence" in combined_context
    assert "Campaign Correlations" not in combined_context
    assert "Forensic Memory" not in combined_context
    assert all(message["role"] != "assistant" for message in messages[2:-1])
    assert any(citation.type == "alert" for citation in citations)
    assert confidence > 0