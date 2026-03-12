from backend.app.api import chat


def test_finalize_grounded_response_blocks_unsupported_ip_and_password_claims() -> None:
    citations = [
        chat.ChatCitationOut(
            type="alert",
            id="alert-1",
            snippet="[high] ET WEB_SERVER Http Client Body contains pwd= in cleartext (10.12.27.101 → 198.51.100.20)",
        )
    ]
    combined_context = "\n".join([
        "=== CURRENT JOB EVIDENCE ONLY ===",
        "- [high] ET WEB_SERVER Http Client Body contains pwd= in cleartext (10.12.27.101 → 198.51.100.20)",
    ])

    response = chat._finalize_grounded_response(
        "The attacker at 192.168.1.100 used password=12345678 against 198.51.100.20.",
        citations,
        combined_context,
    )

    assert "192.168.1.100" not in response
    assert "12345678" not in response
    assert "I can only answer from the collected data for this job." in response
    assert "[alert]" in response


def test_finalize_grounded_response_appends_sources_and_limits() -> None:
    citations = [
        chat.ChatCitationOut(
            type="host_summary",
            id="host-1",
            snippet="Host 10.12.27.101 (role: suspected_client) | connections=4 alerts=1",
        )
    ]

    response = chat._finalize_grounded_response(
        "The observed host in the collected data is 10.12.27.101.",
        citations,
        "Host 10.12.27.101 (role: suspected_client)",
    )

    assert "Sources used:" in response
    assert "Limits:" in response
    assert "10.12.27.101" in response


def test_finalize_grounded_response_blocks_unsupported_cleartext_assertion() -> None:
    response = chat._finalize_grounded_response(
        "That specific information is not available in the analysis data I have access to. The alert indicates a cleartext password was transmitted, but the actual password value is not available in my analysis data.",
        [],
        "=== CURRENT JOB EVIDENCE ONLY ===\n[high] ET MALWARE AlphaCrypt CnC Beacon 5 (192.168.122.249 → 79.96.20.98)",
        "What password was used in cleartext?",
    )

    assert "cleartext password was transmitted" not in response.lower()
    assert "I can only answer from the collected data for this job." in response


def test_finalize_grounded_response_blocks_generic_refusal() -> None:
    response = chat._finalize_grounded_response(
        "I can't help you with this task. Is there something else I can assist you with?",
        [],
        "=== CURRENT JOB EVIDENCE ONLY ===\nHost 192.168.122.249 observed in job data",
        "Which host was involved?",
    )

    assert "can't help you with this task" not in response.lower()
    assert "I can only answer from the collected data for this job." in response


def test_finalize_grounded_response_replaces_unsupported_quoted_detail_with_grounded_answer() -> None:
    citations = [
        chat.ChatCitationOut(
            type="finding",
            id="f1",
            snippet="[high] ET MALWARE AlphaCrypt CnC Beacon 5: Alert fired 4 time(s). Hosts involved: 192.168.122.249, 79.96.20.98",
        )
    ]

    response = chat._finalize_grounded_response(
        "The alert name 'AlphaCrypt Malware Detection' is present in this job.",
        citations,
        "=== CURRENT JOB EVIDENCE ONLY ===\n[high] ET MALWARE AlphaCrypt CnC Beacon 5: Alert fired 4 time(s). Hosts involved: 192.168.122.249, 79.96.20.98",
        "List the alert or finding names in this job that contain AlphaCrypt.",
    )

    assert "AlphaCrypt Malware Detection" not in response
    assert "The matching alert/finding names in the current job evidence are:" in response
    assert "ET MALWARE AlphaCrypt CnC Beacon 5" in response
    assert "Sources used:" in response
    assert "I can only answer from the collected data for this job." not in response


def test_finalize_grounded_response_blocks_refusal_variant() -> None:
    response = chat._finalize_grounded_response(
        "I can't help you with that. Is there something else I can help you with?",
        [],
        "=== CURRENT JOB EVIDENCE ONLY ===\nHost 192.168.122.249 observed in job data",
        "Which host was involved?",
    )

    assert "can't help you with that" not in response.lower()
    assert "I can only answer from the collected data for this job." in response


def test_chunk_text_splits_large_text() -> None:
    chunks = chat._chunk_text("abcdef", chunk_size=2)
    assert chunks == ["ab", "cd", "ef"]


def test_select_relevant_citations_prefers_matching_terms() -> None:
    citations = [
        chat.ChatCitationOut(type="finding", id="f1", snippet="[high] AlphaCrypt CnC Beacon 5 involving 192.168.122.249 and 79.96.20.98"),
        chat.ChatCitationOut(type="alert", id="a1", snippet="[medium] External IP Check myexternalip.com (192.168.122.249 → 78.47.139.102)"),
        chat.ChatCitationOut(type="host_summary", id="h1", snippet="Host 192.168.122.110 (role: peer) | connections=2 alerts=0"),
    ]

    selected = chat._select_relevant_citations(
        citations,
        "Which host contacted 79.96.20.98 and what beacon evidence supports it?",
        limit=2,
    )

    assert len(selected) == 1
    assert selected[0].id == "f1"


def test_select_relevant_citations_for_name_listing_ignores_generic_terms() -> None:
    citations = [
        chat.ChatCitationOut(type="finding", id="f1", snippet="[high] ET MALWARE AlphaCrypt CnC Beacon 5 involving 192.168.122.249 and 79.96.20.98"),
        chat.ChatCitationOut(type="alert", id="a1", snippet="[high] ET MALWARE AlphaCrypt Connectivity Check 1 (192.168.122.249 → 78.47.139.102)"),
        chat.ChatCitationOut(type="alert", id="a2", snippet="[medium] External IP Check myexternalip.com (192.168.122.249 → 78.47.139.102)"),
    ]

    selected = chat._select_relevant_citations(
        citations,
        "List the alert or finding names in this job that contain AlphaCrypt, and cite your sources.",
        limit=4,
    )

    assert [citation.id for citation in selected] == ["f1", "a1"]


def test_build_primary_supporting_evidence_block_uses_exact_snippets() -> None:
    block = chat._build_primary_supporting_evidence_block(
        [
            chat.ChatCitationOut(
                type="finding",
                id="f1",
                snippet="[high] ET MALWARE AlphaCrypt CnC Beacon 5: Alert fired 4 time(s).",
            )
        ],
        "List the alert or finding names in this job that contain AlphaCrypt.",
    )

    assert "PRIMARY SUPPORTING EVIDENCE" in block
    assert "Question: List the alert or finding names in this job that contain AlphaCrypt." in block
    assert "copy them verbatim" in block
    assert "ET MALWARE AlphaCrypt CnC Beacon 5" in block


def test_finalize_grounded_response_uses_citation_synthesis_for_name_listing() -> None:
    citations = [
        chat.ChatCitationOut(type="finding", id="f1", snippet="[high] ET MALWARE AlphaCrypt CnC Beacon 5: Alert fired 4 time(s)."),
        chat.ChatCitationOut(type="alert", id="a1", snippet="[high] ET MALWARE AlphaCrypt Connectivity Check 1 (192.168.122.249 → 78.47.139.102)"),
    ]

    response = chat._finalize_grounded_response(
        "The alert name 'AlphaCrypt Malware Detection' is present in this job.",
        citations,
        "=== CURRENT JOB EVIDENCE ONLY ===\n[high] ET MALWARE AlphaCrypt CnC Beacon 5\n[high] ET MALWARE AlphaCrypt Connectivity Check 1",
        "List the alert or finding names in this job that contain AlphaCrypt, and cite your sources.",
    )

    assert response.startswith("The matching alert/finding names in the current job evidence are:")
    assert "ET MALWARE AlphaCrypt CnC Beacon 5" in response
    assert "ET MALWARE AlphaCrypt Connectivity Check 1" in response
    assert "Sources used:" in response
    assert "I can only answer from the collected data for this job." not in response


def test_finalize_grounded_response_prefers_citation_synthesis_for_name_listing_even_without_block() -> None:
    citations = [
        chat.ChatCitationOut(type="finding", id="f1", snippet="[high] ET MALWARE AlphaCrypt CnC Beacon 5: Alert fired 4 time(s)."),
        chat.ChatCitationOut(type="alert", id="a1", snippet="[high] ET MALWARE AlphaCrypt Connectivity Check 1 (192.168.122.249 → 78.47.139.102)"),
    ]

    response = chat._finalize_grounded_response(
        "You can find alerts related to AlphaCrypt under the following names: alpha_crypt, AlphaCrypt Malware Detection.",
        citations,
        "=== CURRENT JOB EVIDENCE ONLY ===\n[high] ET MALWARE AlphaCrypt CnC Beacon 5\n[high] ET MALWARE AlphaCrypt Connectivity Check 1",
        "List the alert or finding names in this job that contain AlphaCrypt, and cite your sources.",
    )

    assert response.startswith("The matching alert/finding names in the current job evidence are:")
    assert "AlphaCrypt Malware Detection" not in response
    assert "ET MALWARE AlphaCrypt Connectivity Check 1" in response
    assert "Sources used:" in response


def test_finalize_grounded_response_uses_citation_synthesis_for_external_ip_relationships() -> None:
    citations = [
        chat.ChatCitationOut(type="alert", id="a1", snippet="[medium] ET INFO External IP Check myexternalip.com (192.168.122.249 → 78.47.139.102)"),
    ]

    response = chat._finalize_grounded_response(
        "The relevant field appears under 'external_ip' and 'ipaddr'.",
        citations,
        "=== CURRENT JOB EVIDENCE ONLY ===\n[medium] ET INFO External IP Check myexternalip.com (192.168.122.249 → 78.47.139.102)",
        "What suspicious external IP relationships are shown in this job? Cite your sources.",
    )

    assert response.startswith("The current job evidence shows these suspicious external IP relationships:")
    assert "192.168.122.249 → 78.47.139.102" in response
    assert "Sources used:" in response
    assert "I can only answer from the collected data for this job." not in response


def test_finalize_grounded_response_uses_citation_synthesis_for_beacon_host_question() -> None:
    citations = [
        chat.ChatCitationOut(type="finding", id="f1", snippet="[high] ET MALWARE AlphaCrypt CnC Beacon 5: Alert fired 4 time(s). Hosts involved: 172.16.25.128, 182.50.130.156, 192.168.122.249, 79.96.20.98"),
        chat.ChatCitationOut(type="alert", id="a1", snippet="[high] ET MALWARE AlphaCrypt CnC Beacon 5 (192.168.122.249 → 79.96.20.98)"),
    ]

    response = chat._finalize_grounded_response(
        "The C2 host is 10.1.29.101 and it also contacted 23.198.136.197.",
        citations,
        "=== CURRENT JOB EVIDENCE ONLY ===\n[high] ET MALWARE AlphaCrypt CnC Beacon 5 (192.168.122.249 → 79.96.20.98)",
        "Which host shows the strongest beacon or C2 evidence in this job? Cite your sources.",
    )

    assert response.startswith("The best-supported host in the current job evidence is 192.168.122.249.")
    assert "ET MALWARE AlphaCrypt CnC Beacon 5" in response
    assert "Sources used:" in response
    assert "I can only answer from the collected data for this job." not in response


def test_finalize_grounded_response_uses_host_summaries_for_most_active_hosts() -> None:
    citations = [
        chat.ChatCitationOut(type="finding", id="f1", snippet="[medium] ET INFO HTTP Request to a *.ga domain: Alert fired 11 time(s). Hosts involved: 162.247.14.156, 178.62.143.149, 192.168.122.110, 192.168.122.249"),
        chat.ChatCitationOut(type="host_summary", id="h1", snippet="Host 192.168.122.249 (role: suspected_client) | connections=42 alerts=7"),
        chat.ChatCitationOut(type="host_summary", id="h2", snippet="Host 162.247.14.156 (role: external) | connections=19 alerts=5"),
        chat.ChatCitationOut(type="host_summary", id="h3", snippet="Host 178.62.143.149 (role: external) | connections=18 alerts=4"),
    ]

    response = chat._finalize_grounded_response(
        "Based on the evidence, the most active hosts are 192.168.122.249, 162.247.14.156, and 178.62.143.149.",
        citations,
        "=== CURRENT JOB EVIDENCE ONLY ===\nHost 192.168.122.249 (role: suspected_client) | connections=42 alerts=7",
        "Which hosts were most active?",
    )

    assert response.startswith("The most active hosts in the current job host summaries are:")
    assert "192.168.122.249 (role: suspected_client, alerts=7, connections=42)" in response
    assert "Sources used:" in response
    assert "current-job host summary counts" in response


def test_finalize_grounded_response_uses_exact_malware_family_labels() -> None:
    citations = [
        chat.ChatCitationOut(type="finding", id="f1", snippet="[high] ET MALWARE AlphaCrypt CnC Beacon 5: Alert fired 4 time(s)."),
        chat.ChatCitationOut(type="finding", id="f2", snippet="[high] ET MALWARE Alphacrypt/TeslaCrypt Ransomware CnC Beacon Response: Alert fired 4 time(s)."),
    ]

    response = chat._finalize_grounded_response(
        "The malware families are AlphaCrypt and TeslaCrypt.",
        citations,
        "=== CURRENT JOB EVIDENCE ONLY ===\n[high] ET MALWARE AlphaCrypt CnC Beacon 5\n[high] ET MALWARE Alphacrypt/TeslaCrypt Ransomware CnC Beacon Response",
        "What malware families are indicated?",
    )

    assert response.startswith("The current job evidence explicitly mentions these malware family labels:")
    assert "- AlphaCrypt" in response
    assert "- Alphacrypt/TeslaCrypt Ransomware" in response
    assert "I am not inferring any additional family names" in response
    assert "Sources used:" in response


def test_finalize_grounded_response_summarizes_findings_by_severity_without_extra_narrative() -> None:
    citations = [
        chat.ChatCitationOut(type="finding", id="f1", snippet="[high] ET MALWARE AlphaCrypt CnC Beacon 5: Alert fired 4 time(s). Hosts involved: 192.168.122.249, 79.96.20.98"),
        chat.ChatCitationOut(type="finding", id="f2", snippet="[medium] ET INFO External IP Check myexternalip.com: Alert fired 2 time(s). Hosts involved: 172.16.25.128, 192.168.122.249, 78.47.139.102"),
    ]

    response = chat._finalize_grounded_response(
        "This looks like a ransomware attack and possible Nuclear EK exploitation.",
        citations,
        "=== CURRENT JOB EVIDENCE ONLY ===\n[high] ET MALWARE AlphaCrypt CnC Beacon 5\n[medium] ET INFO External IP Check myexternalip.com",
        "Summarize the most important findings by severity",
    )

    assert response.startswith("Based on the current cited findings, the most important findings by severity are:")
    assert "High severity:" in response
    assert "Medium severity:" in response
    assert "ET MALWARE AlphaCrypt CnC Beacon 5 — Alert fired 4 time(s). Hosts involved: 192.168.122.249, 79.96.20.98" in response
    assert "possible Nuclear EK exploitation" not in response
    assert "Sources used:" in response


def test_unsupported_claims_response_uses_question_relevant_citations_only() -> None:
    citations = [
        chat.ChatCitationOut(type="finding", id="f1", snippet="[high] AlphaCrypt CnC Beacon 5 involving 192.168.122.249 and 79.96.20.98"),
        chat.ChatCitationOut(type="alert", id="a1", snippet="[medium] External IP Check myexternalip.com (192.168.122.249 → 78.47.139.102)"),
    ]

    response = chat._build_unsupported_claims_response(
        citations,
        "What password was used in cleartext? Cite your sources.",
    )

    assert "matching this question" in response
    assert "AlphaCrypt CnC Beacon" not in response
    assert "External IP Check" not in response


def test_finalize_grounded_response_payload_returns_question_relevant_citations() -> None:
    citations = [
        chat.ChatCitationOut(type="finding", id="f1", snippet="[high] AlphaCrypt CnC Beacon 5 involving 192.168.122.249 and 79.96.20.98"),
        chat.ChatCitationOut(type="alert", id="a1", snippet="[medium] External IP Check myexternalip.com (192.168.122.249 → 78.47.139.102)"),
    ]

    response, final_citations = chat._finalize_grounded_response_payload(
        "I can't help you with that. Is there something else I can help you with?",
        citations,
        "=== CURRENT JOB EVIDENCE ONLY ===\nHost 192.168.122.249 observed in job data",
        "What password was used in cleartext? Cite your sources.",
    )

    assert "matching this question" in response
    assert final_citations == []