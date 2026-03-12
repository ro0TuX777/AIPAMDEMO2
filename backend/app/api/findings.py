"""
Findings endpoints (§3.6).

GET  /jobs/{jobId}/findings                   – list findings
POST /jobs/{jobId}/findings/{findingId}/explain – grounded explain
"""

import asyncio
import json
import os
from time import perf_counter
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.api._state import (
    increment_explain_response_count,
    release_explain_llm_slot,
    try_acquire_explain_llm_slot,
)
from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.api.pagination import paginate
from backend.app.config_v2 import Settings, get_settings
from backend.app.llm_client import LLMClient, LLMConfig
from backend.app.models.finding import Finding
from backend.app.models.job import Job
from backend.app.schemas.common import Severity
from backend.app.schemas.finding import (
    FindingExplainFeedbackRequest,
    FindingExplainFeedbackResponse,
    FindingExplainEvidenceItem,
    FindingExplainRequest,
    FindingExplainResponse,
    FindingExplainSection,
    FindingFeedbackRequest,
    FindingItem,
    FindingListResponse,
)

router = APIRouter(tags=["Findings"], dependencies=[Depends(verify_token)])

_MAX_EXPLAIN_EVIDENCE_ITEMS = 8
_MAX_LLM_PROMPT_EVIDENCE_ITEMS = 5
_EXPLAIN_BUSY_RETRY_AFTER_SECONDS = 2
_EXPLAIN_QUEUE_FULL_RETRY_AFTER_SECONDS = 5
_EXPLAIN_QUEUE_WAIT_SECONDS = 1.0
_EXPLAIN_MAX_QUEUE_WAITERS = 1


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


async def _acquire_explain_llm_slot_or_raise() -> bool:
    outcome = await asyncio.to_thread(
        try_acquire_explain_llm_slot,
        wait_timeout_seconds=_EXPLAIN_QUEUE_WAIT_SECONDS,
        max_waiters=_EXPLAIN_MAX_QUEUE_WAITERS,
    )
    if outcome == "acquired":
        return True

    if outcome == "busy":
        raise HTTPException(
            status_code=429,
            detail={
                "error": "LLM busy, retry shortly.",
                "code": "LLM_BUSY",
                "details": {"retry_after": _EXPLAIN_BUSY_RETRY_AFTER_SECONDS},
            },
            headers={"Retry-After": str(_EXPLAIN_BUSY_RETRY_AFTER_SECONDS)},
        )

    raise HTTPException(
        status_code=503,
        detail={
            "error": "Analysis queue full, retry shortly.",
            "code": "LLM_QUEUE_FULL",
            "details": {"retry_after": _EXPLAIN_QUEUE_FULL_RETRY_AFTER_SECONDS},
        },
        headers={"Retry-After": str(_EXPLAIN_QUEUE_FULL_RETRY_AFTER_SECONDS)},
    )


def _finding_to_item(f: Finding) -> FindingItem:
    evidence = _parse_finding_evidence(f)
    return FindingItem(
        finding_id=f.finding_id,
        title=f.title,
        severity=f.severity,
        category=f.category,
        sensor=f.sensor,
        pcap_label=f.pcap_label,
        summary=f.summary,
        evidence=evidence,
        feedback=f.feedback,
    )


def _parse_finding_evidence(finding: Finding) -> Any | None:
    if not finding.evidence_json:
        return None
    try:
        return json.loads(finding.evidence_json)
    except (json.JSONDecodeError, TypeError):
        return None


def _normalize_explain_format(value: str | None) -> str:
    return "text" if value == "text" else "markdown"


def _humanize_key(key: str) -> str:
    return key.replace("_", " ").strip().capitalize()


def _stringify_scalar(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _summarize_mapping(value: dict[str, Any], max_pairs: int = 4) -> str:
    pairs: list[str] = []
    for idx, (key, item) in enumerate(value.items()):
        if idx >= max_pairs:
            break
        pairs.append(f"{_humanize_key(key)}={_stringify_scalar(item)}")
    if len(value) > max_pairs:
        pairs.append(f"… +{len(value) - max_pairs} more")
    return "; ".join(pairs)


def _summarize_sequence(value: list[Any], max_items: int = 6) -> str:
    if not value:
        return "none"
    if all(not isinstance(item, (dict, list)) for item in value):
        rendered = ", ".join(_stringify_scalar(item) for item in value[:max_items])
        if len(value) > max_items:
            rendered += f", … +{len(value) - max_items} more"
        return rendered

    preview: list[str] = []
    for item in value[:max_items]:
        if isinstance(item, dict):
            preview.append(f"{{{_summarize_mapping(item, max_pairs=2)}}}")
        else:
            preview.append(_stringify_scalar(item))
    if len(value) > max_items:
        preview.append(f"… +{len(value) - max_items} more")
    return ", ".join(preview)


def _format_evidence_lines(evidence: Any) -> list[str]:
    evidence_items = _build_evidence_items(evidence)
    return [f"- {item.label}: {item.value}" for item in evidence_items]


def _format_llm_prompt_evidence_lines(evidence: Any) -> list[str]:
    if evidence is None:
        return ["- No structured evidence was stored for this finding."]
    if isinstance(evidence, dict):
        items = list(evidence.items())
        lines = [
            f"- {_humanize_key(key)}: {_summarize_evidence_value(value)} (citation: finding.evidence.{key})"
            for key, value in items[:_MAX_LLM_PROMPT_EVIDENCE_ITEMS]
        ]
        omitted = len(items) - _MAX_LLM_PROMPT_EVIDENCE_ITEMS
        if omitted > 0:
            lines.append(
                f"- Additional evidence fields omitted from prompt: {omitted}. "
                "Base the explanation only on the listed evidence and metadata."
            )
        return lines
    return [f"- Evidence: {_summarize_evidence_value(evidence)} (citation: finding.evidence)"]


def _build_evidence_items(evidence: Any) -> list[FindingExplainEvidenceItem]:
    if evidence is None:
        return []
    if isinstance(evidence, dict):
        items: list[FindingExplainEvidenceItem] = []
        for idx, (key, value) in enumerate(evidence.items()):
            if idx >= _MAX_EXPLAIN_EVIDENCE_ITEMS:
                items.append(
                    FindingExplainEvidenceItem(
                        label="Additional evidence fields omitted",
                        value=str(len(evidence) - idx),
                        citation="finding.evidence",
                    )
                )
                break
            items.append(
                FindingExplainEvidenceItem(
                    label=_humanize_key(key),
                    value=_summarize_evidence_value(value),
                    citation=f"finding.evidence.{key}",
                )
            )
        return items
    if isinstance(evidence, list):
        return [
            FindingExplainEvidenceItem(
                label="Evidence",
                value=_summarize_sequence(evidence),
                citation="finding.evidence",
            )
        ]
    return [
        FindingExplainEvidenceItem(
            label="Evidence",
            value=_stringify_scalar(evidence),
            citation="finding.evidence",
        )
    ]


def _summarize_evidence_value(value: Any) -> str:
    if isinstance(value, dict):
        return _summarize_mapping(value)
    if isinstance(value, list):
        return _summarize_sequence(value)
    return _stringify_scalar(value)


def _unique_citations(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def _build_section_citation_map(
    finding: Finding,
    evidence_items: list[FindingExplainEvidenceItem],
) -> dict[str, list[str]]:
    evidence_citations = [item.citation for item in evidence_items]

    assessment_citations = ["finding.severity", "finding.sensor"]
    if finding.category:
        assessment_citations.append("finding.category")
    if finding.summary:
        assessment_citations.append("finding.summary")

    why_citations = evidence_citations[:2]
    if not why_citations:
        why_citations = ["finding.summary"] if finding.summary else ["finding.title", "finding.severity"]

    next_steps_citations = [
        citation
        for citation in [
            "finding.evidence.affected_hosts",
            "finding.evidence.sample_ts",
            "finding.evidence.alert_count",
        ]
        if citation in evidence_citations
    ]
    if finding.pcap_label:
        next_steps_citations.append("finding.pcap_label")
    if not next_steps_citations:
        next_steps_citations = evidence_citations[:1] or ["finding.title"]

    return {
        "assessment": _unique_citations(assessment_citations),
        "why_it_matters": _unique_citations(why_citations),
        "recommended_next_steps": _unique_citations(next_steps_citations),
    }


def _build_allowed_llm_citations(
    finding: Finding,
    evidence_items: list[FindingExplainEvidenceItem],
) -> list[str]:
    citations = [
        "finding.title",
        "finding.severity",
        "finding.sensor",
    ]
    if finding.category:
        citations.append("finding.category")
    if finding.summary:
        citations.append("finding.summary")
    if finding.pcap_label:
        citations.append("finding.pcap_label")
    citations.extend(item.citation for item in evidence_items)
    return _unique_citations(citations)


def _attach_section_citations(
    sections: list[FindingExplainSection],
    finding: Finding,
    evidence_items: list[FindingExplainEvidenceItem],
) -> list[FindingExplainSection]:
    citation_map = _build_section_citation_map(finding, evidence_items)
    return [
        FindingExplainSection(
            id=section.id,
            title=section.title,
            body=section.body,
            bullets=list(section.bullets),
            citations=_unique_citations(list(section.citations) or citation_map.get(section.id, [])),
        )
        for section in sections
    ]


def _build_explanation_sections(
    finding: Finding,
    evidence: Any,
    evidence_items: list[FindingExplainEvidenceItem],
) -> list[FindingExplainSection]:
    evidence_lines = [f"- {item.label}: {item.value}" for item in evidence_items]
    assessment = _build_assessment_line(finding)
    why_it_matters = _build_why_it_matters_line(finding, evidence_lines)
    next_steps = _build_next_steps(finding, evidence)
    sections = [
        FindingExplainSection(
            id="assessment",
            title="Assessment",
            body=assessment,
        ),
        FindingExplainSection(
            id="why_it_matters",
            title="Why this matters",
            body=why_it_matters,
        ),
        FindingExplainSection(
            id="recommended_next_steps",
            title="Recommended next steps",
            bullets=next_steps,
        ),
    ]
    return _attach_section_citations(sections, finding, evidence_items)


def _render_explanation_content(
    finding: Finding,
    explain_format: str,
    sections: list[FindingExplainSection],
    evidence_items: list[FindingExplainEvidenceItem],
) -> str:
    if explain_format == "text":
        lines = [
            f"Finding: {finding.title}",
            f"Severity: {finding.severity}",
            f"Sensor: {finding.sensor or 'unknown'}",
        ]
        if finding.category:
            lines.append(f"Category: {finding.category}")
        if finding.pcap_label:
            lines.append(f"PCAP: {finding.pcap_label}")
        for section in sections:
            lines.extend(["", f"{section.title}:"])
            if section.body:
                lines.append(section.body)
            lines.extend(f"- {bullet}" for bullet in section.bullets)
        lines.extend(["", "Supporting evidence:"])
        lines.extend(
            [f"- {item.label}: {item.value}" for item in evidence_items]
            or ["- No structured evidence was stored for this finding."]
        )
        return "\n".join(lines)

    lines = [
        f"# {finding.title}",
        "",
        f"**Severity:** {finding.severity}",
        f"**Sensor:** {finding.sensor or 'unknown'}",
    ]
    if finding.category:
        lines.append(f"**Category:** {finding.category}")
    if finding.pcap_label:
        lines.append(f"**PCAP:** {finding.pcap_label}")
    for section in sections:
        lines.extend(["", f"## {section.title}"])
        if section.body:
            lines.append(section.body)
        lines.extend(f"- {bullet}" for bullet in section.bullets)
    lines.extend(["", "## Supporting evidence"])
    lines.extend(
        [f"- {item.label}: {item.value}" for item in evidence_items]
        or ["- No structured evidence was stored for this finding."]
    )
    return "\n".join(lines)


def _build_assessment_line(finding: Finding) -> str:
    sensor = finding.sensor or "unknown sensor"
    category = finding.category or "uncategorized activity"
    if finding.summary:
        return (
            f"This finding records a {finding.severity} severity observation from {sensor} "
            f"in category {category}. Stored summary: {finding.summary}"
        )
    return (
        f"This finding records a {finding.severity} severity observation from {sensor} "
        f"in category {category}. No additional analyst summary was stored with it."
    )


def _build_why_it_matters_line(finding: Finding, evidence_lines: list[str]) -> str:
    if evidence_lines:
        first_fact = evidence_lines[0].removeprefix("- ")
        return (
            f"The stored evidence supports triage of this item and currently shows: {first_fact}. "
            "This explanation is limited to the saved finding metadata and evidence for this job."
        )
    return (
        "No structured evidence was stored with this finding, so the explanation is limited to the "
        "title, severity, sensor, and summary fields."
    )


def _build_next_steps(finding: Finding, evidence: Any) -> list[str]:
    steps = [
        "Review the underlying job timeline, alerts, and connections that align with this finding.",
        "Compare this item with other findings from the same job before deciding whether to confirm it or mark it as a false positive.",
    ]
    if isinstance(evidence, dict):
        if evidence.get("affected_hosts"):
            steps.append("Pivot into the listed affected hosts to confirm who initiated or received the activity.")
        if evidence.get("sample_ts"):
            steps.append(f"Inspect surrounding packets, flows, and alerts near {evidence['sample_ts']} for additional context.")
        if evidence.get("alert_count"):
            steps.append(f"Validate whether all {evidence['alert_count']} alert occurrences reflect the same behavior or multiple related events.")
    if finding.pcap_label:
        steps.append(f"Use the PCAP label {finding.pcap_label} to isolate the capture that produced this finding.")
    return steps[:4]


def _render_deterministic_explanation(finding: Finding, explain_format: str) -> str:
    evidence = _parse_finding_evidence(finding)
    evidence_items = _build_evidence_items(evidence)
    sections = _build_explanation_sections(finding, evidence, evidence_items)
    return _render_explanation_content(finding, explain_format, sections, evidence_items)


def _strip_code_fences(content: str) -> str:
    stripped = content.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if len(lines) >= 3 and lines[-1].startswith("```"):
        return "\n".join(lines[1:-1]).strip()
    return stripped


def _parse_llm_section_citations(
    payload: dict[str, Any],
    allowed_citations: list[str],
) -> dict[str, list[str]] | None:
    raw = payload.get("section_citations")
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        return None

    valid_section_ids = {"assessment", "why_it_matters", "recommended_next_steps"}
    if any(key not in valid_section_ids for key in raw):
        return None

    allowed_set = set(allowed_citations)
    parsed: dict[str, list[str]] = {}
    for section_id, values in raw.items():
        if not isinstance(values, list):
            return None
        cleaned: list[str] = []
        for value in values:
            if not isinstance(value, str):
                return None
            normalized = value.strip()
            if not normalized:
                continue
            if normalized not in allowed_set:
                return None
            cleaned.append(normalized)
        parsed[section_id] = _unique_citations(cleaned)
    return parsed


def _parse_llm_explanation_sections(
    content: str,
    *,
    allowed_citations: list[str],
) -> list[FindingExplainSection] | None:
    try:
        payload = json.loads(_strip_code_fences(content))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None

    allowed_keys = {
        "assessment",
        "why_it_matters",
        "recommended_next_steps",
        "section_citations",
    }
    if any(key not in allowed_keys for key in payload):
        return None

    assessment = payload.get("assessment")
    why_it_matters = payload.get("why_it_matters")
    next_steps = payload.get("recommended_next_steps")
    if not isinstance(assessment, str) or not assessment.strip():
        return None
    if not isinstance(why_it_matters, str) or not why_it_matters.strip():
        return None
    if not isinstance(next_steps, list):
        return None

    bullets = [item.strip() for item in next_steps if isinstance(item, str) and item.strip()][:4]
    if not bullets:
        return None

    section_citations = _parse_llm_section_citations(payload, allowed_citations)
    if section_citations is None:
        return None

    return [
        FindingExplainSection(
            id="assessment",
            title="Assessment",
            body=assessment.strip(),
            citations=section_citations.get("assessment", []),
        ),
        FindingExplainSection(
            id="why_it_matters",
            title="Why this matters",
            body=why_it_matters.strip(),
            citations=section_citations.get("why_it_matters", []),
        ),
        FindingExplainSection(
            id="recommended_next_steps",
            title="Recommended next steps",
            bullets=bullets,
            citations=section_citations.get("recommended_next_steps", []),
        ),
    ]


def _build_llm_prompt(
    finding: Finding,
    explain_format: str,
    allowed_citations: list[str],
) -> list[dict[str, str]]:
    evidence = _parse_finding_evidence(finding)
    evidence_lines = _format_llm_prompt_evidence_lines(evidence)
    context_lines = [
        f"Job ID: {finding.job_id}",
        f"Finding ID: {finding.finding_id}",
        f"Title: {finding.title}",
        f"Severity: {finding.severity}",
        f"Sensor: {finding.sensor or 'unknown'}",
        f"Category: {finding.category or 'none'}",
        f"PCAP label: {finding.pcap_label or 'none'}",
        f"Summary: {finding.summary or 'none'}",
        "Evidence:",
        *evidence_lines,
        "Allowed citations:",
        *[f"- {citation}" for citation in allowed_citations],
    ]
    return [
        {
            "role": "system",
            "content": (
                "You explain one AIPAM finding using only the provided finding bundle. "
                "Do not invent malware families, ATT&CK techniques, IPs, domains, files, or packet details. "
                "If the evidence is limited, say so clearly. Keep the answer concise and analyst-focused. "
                "Some evidence may be omitted from the prompt for brevity; if so, rely only on the listed evidence and say the evidence is limited rather than speculating. "
                "Return valid JSON only with these keys: assessment, why_it_matters, recommended_next_steps, and optional section_citations. "
                "recommended_next_steps must be an array of short strings. "
                "If section_citations is present, it must be an object keyed by assessment, why_it_matters, and recommended_next_steps, "
                "and every citation must come exactly from the allowed citations list supplied by the user. "
                "Do not wrap the JSON in markdown fences."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Prepare a grounded explanation bundle for {explain_format} rendering. "
                "Use only the provided metadata and evidence.\n\n"
                + "\n".join(context_lines)
            ),
        },
    ]


def _make_llm_client(settings: Settings) -> LLMClient:
    ollama_base = settings.aipam_ollama_url.rstrip("/")
    config = LLMConfig(
        endpoint=os.getenv("LLM_ENDPOINT", f"{ollama_base}/v1/chat/completions"),
        model=os.getenv("LLM_MODEL_NAME", "aipam-trafficllm-v8"),
        temperature=0.2,
        max_tokens=int(os.getenv("LLM_MAX_TOKENS", "1024")),
        timeout_seconds=float(os.getenv("LLM_TIMEOUT_SECONDS", "20")),
    )
    return LLMClient(config=config)


def _llm_explain_enabled() -> bool:
    return os.getenv("AIPAM_EXPLAIN_FINDING_USE_LLM", "").strip().lower() in {"1", "true", "yes", "on"}


async def _generate_finding_explanation(
    finding: Finding,
    explain_format: str,
    settings: Settings,
) -> tuple[str, str, str | None, list[FindingExplainSection], list[FindingExplainEvidenceItem]]:
    evidence = _parse_finding_evidence(finding)
    evidence_items = _build_evidence_items(evidence)
    allowed_citations = _build_allowed_llm_citations(finding, evidence_items)
    fallback_sections = _build_explanation_sections(finding, evidence, evidence_items)
    fallback = _render_explanation_content(finding, explain_format, fallback_sections, evidence_items)
    if not _llm_explain_enabled():
        return fallback, "deterministic", None, fallback_sections, evidence_items

    try:
        client = _make_llm_client(settings)
        response = await client.chat_completion(
            _build_llm_prompt(finding, explain_format, allowed_citations),
            temperature=0.2,
        )
    except Exception:
        return (
            fallback,
            "fallback",
            "LLM response unavailable; returned deterministic grounded explanation.",
            fallback_sections,
            evidence_items,
        )

    content = response.strip()
    if not content:
        return (
            fallback,
            "fallback",
            "LLM returned empty content; returned deterministic grounded explanation.",
            fallback_sections,
            evidence_items,
        )

    llm_sections = _parse_llm_explanation_sections(content, allowed_citations=allowed_citations)
    if not llm_sections:
        return (
            fallback,
            "fallback",
            "LLM returned invalid structured content; returned deterministic grounded explanation.",
            fallback_sections,
            evidence_items,
        )

    llm_sections = _attach_section_citations(llm_sections, finding, evidence_items)

    return (
        _render_explanation_content(finding, explain_format, llm_sections, evidence_items),
        "llm",
        None,
        llm_sections,
        evidence_items,
    )


@router.get("/jobs/{job_id}/findings", response_model=FindingListResponse)
async def list_findings(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    severity: Severity | None = Query(None),
    category: str | None = Query(None),
    sensor: str | None = Query(None),
    search: str | None = Query(None, alias="q"),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    stmt = select(Finding).where(Finding.job_id == job_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity.value)
    if category:
        stmt = stmt.where(Finding.category == category)
    if sensor:
        stmt = stmt.where(Finding.sensor == sensor)
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Finding.title.ilike(pattern),
                Finding.summary.ilike(pattern),
                Finding.category.ilike(pattern),
                Finding.sensor.ilike(pattern),
                Finding.pcap_label.ilike(pattern),
            )
        )

    items, page = paginate(db, stmt, Finding.id, Finding.id, cursor, limit)
    return FindingListResponse(
        items=[_finding_to_item(f) for f in items],
        page=page,
    )


@router.post("/jobs/{job_id}/findings/{finding_id}/explain", response_model=FindingExplainResponse)
async def explain_finding(
    job_id: str,
    finding_id: str,
    body: FindingExplainRequest,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Generate a grounded explanation of a finding with safe fallback behavior."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    finding = db.execute(
        select(Finding).where(Finding.job_id == job_id, Finding.finding_id == finding_id)
    ).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    explain_format = _normalize_explain_format(body.format)
    llm_slot_acquired = False
    if _llm_explain_enabled():
        llm_slot_acquired = await _acquire_explain_llm_slot_or_raise()

    started_at = perf_counter()
    try:
        content, source, warning, sections, evidence_items = await _generate_finding_explanation(
            finding,
            explain_format,
            settings,
        )
    finally:
        if llm_slot_acquired:
            release_explain_llm_slot()

    duration_ms = max(0, round((perf_counter() - started_at) * 1000))
    increment_explain_response_count(source, duration_ms=duration_ms)
    return FindingExplainResponse(
        format=explain_format,
        content=content,
        duration_ms=duration_ms,
        source=source,
        warning=warning,
        explanation_feedback=finding.explanation_feedback,
        sections=sections,
        evidence_items=evidence_items,
    )


@router.patch(
    "/jobs/{job_id}/findings/{finding_id}/explain/feedback",
    response_model=FindingExplainFeedbackResponse,
)
async def update_finding_explain_feedback(
    job_id: str,
    finding_id: str,
    body: FindingExplainFeedbackRequest,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Update analyst feedback for a generated finding explanation."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    finding = db.execute(
        select(Finding).where(Finding.job_id == job_id, Finding.finding_id == finding_id)
    ).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.explanation_feedback = body.explanation_feedback
    db.add(finding)
    db.commit()
    db.refresh(finding)

    return FindingExplainFeedbackResponse(
        explanation_feedback=finding.explanation_feedback,
    )


@router.patch("/jobs/{job_id}/findings/{finding_id}/feedback", response_model=FindingItem)
async def update_finding_feedback(
    job_id: str,
    finding_id: str,
    body: FindingFeedbackRequest,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Update the user feedback for a finding (§12.5)."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    finding = db.execute(
        select(Finding).where(Finding.job_id == job_id, Finding.finding_id == finding_id)
    ).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.feedback = body.feedback
    db.add(finding)
    db.commit()
    db.refresh(finding)

    return _finding_to_item(finding)
