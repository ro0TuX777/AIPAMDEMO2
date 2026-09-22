"""Citation processing helpers extracted from api/chat.py.

Pure functions for deduplicating, scoring, selecting, and formatting
citations.  No database access — only operates on ChatCitationOut lists.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from backend.app.schemas.chat import (
    ChatCitation,
    ChatCitationOut,
    EvidenceRefOut,
    HistoricalChatCitationOut,
)

logger = logging.getLogger("aipam.chat")

HISTORICAL_COMPARISON_HEADING = "=== Historical comparison ==="

# ── Compiled regexes ──────────────────────────────────────────────────────

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
_IP_IN_RESPONSE_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_FINDING_IN_RESPONSE_RE = re.compile(r"\bF-[0-9a-fA-F-]{1,36}\b", re.IGNORECASE)
_MITRE_IN_RESPONSE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

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


# ── Helpers ───────────────────────────────────────────────────────────────


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def dedupe_citations(
    citations: list[ChatCitation],
    limit: int = 8,
) -> list[ChatCitation]:
    deduped: list[ChatCitation] = []
    seen: set[tuple[str, str | None, str]] = set()

    for citation in citations:
        snippet = (citation.snippet or "").strip()
        if not snippet:
            continue
        key = (citation.type, citation.id, snippet)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(citation.model_copy(update={"snippet": snippet[:200]}))
        if len(deduped) >= limit:
            break

    return deduped


def extract_query_terms(text: str) -> set[str]:
    terms = {
        match.group(0).lower()
        for match in re.finditer(r"[A-Za-z0-9_.:-]{3,}", text or "")
    }
    return {term for term in terms if term not in _CITATION_QUERY_STOPWORDS}


def score_citation_relevance(citation: ChatCitation, query_terms: set[str]) -> int:
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
    if citation.type == "knowledge_base":
        score += 6
    if citation.type == "alert":
        score += 1
    if citation.type == "finding":
        score += 1
    return score


def select_relevant_citations(
    citations: list[ChatCitation],
    user_message: str | None,
    *,
    limit: int = 8,
    min_score: int = 1,
) -> list[ChatCitation]:
    safe_citations = dedupe_citations(citations, limit=max(limit * 3, limit))
    query_terms = extract_query_terms(user_message or "")
    if not query_terms:
        return safe_citations[:limit]

    scored: list[tuple[int, int, ChatCitation]] = []
    for index, citation in enumerate(safe_citations):
        score = score_citation_relevance(citation, query_terms)
        if score >= min_score:
            scored.append((score, -index, citation))

    if not scored:
        return []

    scored.sort(reverse=True)
    return [citation for _, _, citation in scored[:limit]]


def build_primary_supporting_evidence_block(
    citations: list[ChatCitationOut],
    user_message: str | None = None,
) -> str:
    safe_citations = dedupe_citations(citations, limit=6)
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


def unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result


def extract_citation_title(citation: ChatCitationOut) -> str:
    snippet = (citation.snippet or "").strip()
    if not snippet:
        return ""
    title = re.sub(r"^\[[^\]]+\]\s*", "", snippet)
    for separator in (":", " (", " |"):
        if separator in title:
            title = title.split(separator, 1)[0]
    return title.strip()


def extract_citation_severity(citation: ChatCitationOut) -> str:
    match = re.match(r"^\[([^\]]+)\]", (citation.snippet or "").strip())
    return match.group(1).strip().lower() if match else ""


def extract_citation_detail(citation: ChatCitationOut) -> str:
    snippet = re.sub(r"^\[[^\]]+\]\s*", "", (citation.snippet or "").strip())
    title = extract_citation_title(citation)
    if title and snippet.startswith(title):
        detail = snippet[len(title):].lstrip(" :|-")
        return detail.strip()
    if ":" in snippet:
        return snippet.split(":", 1)[1].strip()
    return ""


def parse_host_summary_citation(citation: ChatCitationOut) -> tuple[str, str, int, int] | None:
    snippet = (citation.snippet or "").strip()
    match = re.match(
        r"^Host\s+([0-9.]+)\s+\(role:\s*([^)]+)\)\s*\|\s*connections=([0-9]+)\s+alerts=([0-9]+)$",
        snippet,
    )
    if not match:
        return None
    return match.group(1), match.group(2).strip(), int(match.group(3)), int(match.group(4))


def extract_malware_family_label(title: str) -> str:
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



def build_grounded_direct_answer_from_citations(
    citations: list[ChatCitationOut],
    user_message: str | None = None,
) -> tuple[str, list[ChatCitationOut]] | None:
    question = (user_message or "").lower()
    all_citations = dedupe_citations(citations, limit=20)
    relevant_citations = select_relevant_citations(all_citations, user_message, limit=8) or all_citations[:8]
    if not all_citations:
        return None

    alert_and_finding_titles = unique_preserve_order([
        extract_citation_title(citation)
        for citation in relevant_citations
        if citation.type in {"alert", "finding"}
    ])

    if "host" in question and "active" in question:
        ranked_hosts: list[tuple[int, int, str, str, ChatCitationOut]] = []
        for citation in all_citations:
            if citation.type != "host_summary":
                continue
            parsed = parse_host_summary_citation(citation)
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
            and extract_citation_title(citation).lower().startswith("et malware ")
        ]
        family_labels = unique_preserve_order([
            extract_malware_family_label(extract_citation_title(citation))
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
                severity = extract_citation_severity(citation)
                title = extract_citation_title(citation)
                detail = extract_citation_detail(citation)
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

    pair_rows = unique_preserve_order([
        f"{match.group(1)} → {match.group(2)} ({extract_citation_title(citation)})"
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
            supporting_titles = unique_preserve_order([
                extract_citation_title(citation)
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
        malware_titles = unique_preserve_order([
            title for title in alert_and_finding_titles if any(marker in title.lower() for marker in ("malware", "ransomware", "alphacrypt", "teslacrypt"))
        ])
        suspicious_titles = unique_preserve_order([
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
            used_citations = [citation for citation in relevant_citations if extract_citation_title(citation) in {*malware_titles, *suspicious_titles}]
            return "\n".join(lines), used_citations

    return None


def build_sources_block(citations: list[ChatCitation]) -> str:
    lines = ["Sources used:"]
    current_citations = [
        citation for citation in citations if isinstance(citation, ChatCitationOut)
    ]
    safe_citations = dedupe_citations(current_citations, limit=8)
    if not safe_citations:
        lines.append("- No source snippets were available from the current job data.")
        return "\n".join(lines)

    for citation in safe_citations:
        clean_snippet = " ".join((citation.snippet or "").split())
        lines.append(f"- [{citation.type}] {clean_snippet}")
    return "\n".join(lines)


def append_sources_and_limits(response_text: str, citations: list[ChatCitation]) -> str:
    limits = (
        "Limits: Any detail not shown in the sources above is not available in the "
        "collected data for this job."
    )
    return (
        f"{response_text.rstrip()}\n\n"
        f"{build_sources_block(citations)}\n\n"
        f"{limits}"
    )


def unsupported_response_details(
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
    normalized_context = re.sub(r"[._\-]", " ", lowered_context)
    for match in _QUOTED_DETAIL_RE.finditer(response_text):
        candidate = match.group(1).strip()
        if not candidate:
            continue
        candidate_lower = candidate.lower()
        candidate_normalized = re.sub(r"[._\-]", " ", candidate_lower)
        if candidate_lower not in lowered_context and candidate_normalized not in normalized_context:
            unsupported_quoted_details.append(candidate)

    return unsupported_ips, unsupported_credentials, unsupported_quoted_details


def build_unsupported_claims_response(
    citations: list[ChatCitationOut],
    user_message: str | None = None,
) -> str:
    response_text, _ = build_unsupported_claims_payload(citations, user_message)
    return response_text


def build_unsupported_claims_payload(
    citations: list[ChatCitationOut],
    user_message: str | None = None,
) -> tuple[str, list[ChatCitationOut]]:
    lines = [
        "I can only answer from the collected data for this job.",
        "I am not asserting some specific details because they were not supported by the evidence provided to the model.",
        "",
        "What the current job data does support:",
    ]

    current_job_citations = [
        citation for citation in citations if citation.type != "historical_finding"
    ]
    safe_citations = select_relevant_citations(
        current_job_citations, user_message, limit=6
    )
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


def finalize_grounded_response_payload(
    response_text: str,
    citations: list[ChatCitation],
    combined_context: str,
    user_message: str | None = None,
) -> tuple[str, list[ChatCitation]]:
    current_input = [
        citation for citation in citations if isinstance(citation, ChatCitationOut)
    ]
    relevant_current = select_relevant_citations(
        current_input,
        user_message,
        limit=8,
    )
    current_job_citations = relevant_current or dedupe_citations(
        current_input,
        limit=8,
    )
    synthesized = build_grounded_direct_answer_from_citations(
        current_job_citations, user_message
    )
    if synthesized:
        synthesized_response, synthesized_citations = synthesized
        final_current = dedupe_citations(
            synthesized_citations or current_job_citations,
            limit=8,
        )
        return append_sources_and_limits(synthesized_response, final_current), final_current
    if not response_text.strip():
        response_text = "That specific information is not available in the analysis data I have access to."
    if _REFUSAL_RE.search(response_text):
        logger.warning("Blocked generic refusal in V2 chat response")
        return build_unsupported_claims_payload(current_job_citations, user_message)
    unsupported_ips, unsupported_credentials, unsupported_quoted_details = unsupported_response_details(
        response_text,
        combined_context,
    )
    if unsupported_ips or unsupported_credentials:
        logger.warning(
            "Blocked unsupported V2 chat claims (ips=%s, credentials=%s)",
            unsupported_ips,
            unsupported_credentials,
        )
        return build_unsupported_claims_payload(current_job_citations, user_message)
    if unsupported_quoted_details:
        logger.info(
            "Allowing response with minor quoted detail mismatches: %s",
            unsupported_quoted_details,
        )
    return (
        append_sources_and_limits(response_text, current_job_citations),
        current_job_citations,
    )


def build_historical_comparison_section(
    citations: list[HistoricalChatCitationOut],
    retrieval_status: str | None,
    user_message: str | None = None,
) -> tuple[str, list[HistoricalChatCitationOut]]:
    """Render history outside the model-authored, current-job answer."""
    if retrieval_status == "no_matches":
        return (
            f"{HISTORICAL_COMPARISON_HEADING}\n\n"
            "No relevant historical confirmed findings were found.",
            [],
        )
    if retrieval_status != "used":
        return "", []

    relevant_citations = select_relevant_citations(
        citations,
        user_message,
        limit=8,
    )
    safe_citations = relevant_citations or dedupe_citations(citations, limit=8)
    lines = [
        HISTORICAL_COMPARISON_HEADING,
        "",
        "Historical confirmed findings are supporting context and are not evidence "
        "of the current job.",
    ]
    for citation in safe_citations:
        snippet = " ".join(citation.snippet.split())
        project = citation.source_project_id or "No project assigned"
        lines.append(
            f"- [historical_finding] project={project} "
            f"job={citation.source_job_id} finding={citation.id} "
            f"link={citation.href}: {snippet}"
        )
    return "\n".join(lines), safe_citations


def strip_historical_comparison_section(response_text: str) -> str:
    """Remove the deterministic history appendix before reusing chat history."""
    marker = f"\n\n{HISTORICAL_COMPARISON_HEADING}"
    if marker in response_text:
        return response_text.split(marker, 1)[0].rstrip()
    if response_text.startswith(HISTORICAL_COMPARISON_HEADING):
        return ""
    return response_text


def finalize_mode_aware_response_payload(
    response_text: str,
    *,
    current_job_citations: list[ChatCitationOut],
    historical_citations: list[HistoricalChatCitationOut],
    current_job_context: str,
    user_message: str | None,
    retrieval_status: str | None,
) -> tuple[str, list[ChatCitation]]:
    """Finalize current evidence first, then append server-rendered history."""
    grounded_text, final_current = finalize_grounded_response_payload(
        response_text,
        current_job_citations,
        current_job_context,
        user_message,
    )
    historical_section, final_historical = build_historical_comparison_section(
        historical_citations,
        retrieval_status,
        user_message,
    )
    if historical_section:
        grounded_text = f"{grounded_text.rstrip()}\n\n{historical_section}"
    return grounded_text, [*final_current, *final_historical]


def finalize_grounded_response(
    response_text: str,
    citations: list[ChatCitationOut],
    combined_context: str,
    user_message: str | None = None,
) -> str:
    finalized_text, _ = finalize_grounded_response_payload(
        response_text,
        citations,
        combined_context,
        user_message,
    )
    return finalized_text


def extract_evidence_refs(
    response_text: str,
    citations: list[ChatCitationOut],
) -> list[EvidenceRefOut]:
    """Extract structured evidence references from the LLM response and citations."""
    refs: list[EvidenceRefOut] = []
    seen: set[str] = set()

    for match in _IP_IN_RESPONSE_RE.finditer(response_text):
        ip = match.group(0)
        if ip not in seen and not ip.startswith("0.") and not ip.startswith("255."):
            seen.add(ip)
            refs.append(EvidenceRefOut(type="host", id=ip, label=f"Host {ip}"))

    for match in _FINDING_IN_RESPONSE_RE.finditer(response_text):
        fid = match.group(0)
        key = fid.upper()
        if key not in seen:
            seen.add(key)
            refs.append(EvidenceRefOut(type="finding", id=fid, label=f"Finding {fid}"))

    for c in citations[:8]:
        if c.type == "finding" and c.id and c.id.upper() not in seen:
            seen.add(c.id.upper())
            title = (c.snippet or "").split(":", 1)[-1].strip()[:60] if ":" in (c.snippet or "") else c.id
            refs.append(EvidenceRefOut(type="finding", id=c.id, label=f"Finding: {title}"))

    return refs[:10]


def generate_dynamic_followups(
    response_text: str,
    user_message: str,
    citations: list[ChatCitationOut],
) -> list[str]:
    """Generate 2-4 context-aware follow-up questions based on entities in the response."""
    followups: list[str] = []
    response_lower = response_text.lower()
    question_lower = user_message.lower()

    ips = list(dict.fromkeys(_IP_IN_RESPONSE_RE.findall(response_text)))[:5]
    finding_ids = list(dict.fromkeys(_FINDING_IN_RESPONSE_RE.findall(response_text)))[:5]
    mitre_ids = list(dict.fromkeys(_MITRE_IN_RESPONSE_RE.findall(response_text)))[:3]

    if ips and "lateral" not in question_lower:
        followups.append(f"Check for signs of lateral movement involving {ips[0]}")

    if ips and len(ips) >= 2 and "relationship" not in question_lower:
        followups.append(f"What is the relationship between {ips[0]} and {ips[1]}?")

    if any(kw in response_lower for kw in ("c2", "c&c", "command and control", "beacon")):
        if "timeline" not in question_lower:
            followups.append("Show the timeline of C2 communication activity")

    if any(kw in response_lower for kw in ("dns", "domain", "resolution")):
        if "dns" not in question_lower:
            followups.append("What suspicious DNS activity was observed?")

    if any(kw in response_lower for kw in ("exfiltration", "data transfer", "upload")):
        if "exfiltration" not in question_lower:
            followups.append("Quantify the potential data exfiltration — how much data was sent?")

    if finding_ids and "finding" not in question_lower:
        followups.append(f"Explain finding {finding_ids[0]} in detail")

    if mitre_ids and "mitre" not in question_lower and "technique" not in question_lower:
        followups.append(f"What evidence supports MITRE technique {mitre_ids[0]}?")

    if ips and "host" not in question_lower and "role" not in question_lower:
        ip = ips[1] if len(ips) > 1 else ips[0]
        followups.append(f"What is the role and behavior of host {ip}?")

    if any(kw in response_lower for kw in ("critical", "high severity", "high-severity")):
        if "remediation" not in question_lower and "recommend" not in question_lower:
            followups.append("What remediation actions do you recommend?")

    unique: list[str] = []
    seen_followups: set[str] = set()
    for q in followups:
        key = q.lower().strip()
        if key not in seen_followups:
            seen_followups.add(key)
            unique.append(q)
    return unique[:4]


def post_process_response(
    response_text: str,
    user_message: str,
    citations: list[ChatCitationOut],
) -> tuple[list[EvidenceRefOut], list[str]]:
    """Post-process the LLM response to extract evidence refs and generate follow-ups."""
    evidence_refs = extract_evidence_refs(response_text, citations)
    followups = generate_dynamic_followups(response_text, user_message, citations)
    return evidence_refs, followups
