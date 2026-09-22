"""Validated MNEMOS retrieval for historical chat context."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.forensic_memory import finding_to_text
from backend.app.mnemos_boundary import get_mnemos_client
from backend.app.models.bluescrub import BlueScrubJobLineage
from backend.app.models.finding import Finding
from backend.app.models.job import Job

logger = logging.getLogger(__name__)

_MAX_CONTEXT_CHARS = 4_000
_MAX_SNIPPET_CHARS = 800
_MAX_SEARCH_HITS = 50


@dataclass(frozen=True)
class HistoricalFindingCitation:
    type: Literal["historical_finding"]
    id: str
    snippet: str
    source_job_id: str
    source_project_id: str | None
    href: str


@dataclass(frozen=True)
class MnemosRetrievalResult:
    status: Literal["used", "no_matches", "unavailable", "error"]
    context: str
    citations: list[HistoricalFindingCitation]


def _empty_result(
    status: Literal["no_matches", "unavailable", "error"],
) -> MnemosRetrievalResult:
    return MnemosRetrievalResult(status=status, context="", citations=[])


async def retrieve_historical_findings(
    db: Session,
    *,
    current_job_id: str,
    query: str,
    top_k: int = 5,
) -> MnemosRetrievalResult:
    """Retrieve and revalidate confirmed findings from jobs other than the current one."""
    try:
        client = get_mnemos_client()
    except Exception:
        logger.exception("MNEMOS historical-finding client configuration failed")
        return _empty_result("error")
    if client is None:
        return _empty_result("unavailable")

    search_limit = min(max(top_k * 4, top_k), _MAX_SEARCH_HITS)
    try:
        hits = await asyncio.to_thread(
            client.search,
            query,
            top_k=search_limit,
            filters=None,
        )
    except Exception:
        logger.exception("MNEMOS historical-finding search failed")
        return _empty_result("error")

    if hits is None:
        return _empty_result("unavailable")
    if not hits or top_k <= 0:
        return _empty_result("no_matches")

    context_parts: list[str] = []
    citations: list[HistoricalFindingCitation] = []
    seen: set[tuple[str, str]] = set()
    context_length = 0

    for hit in hits:
        metadata = hit.get("metadata")
        if not isinstance(metadata, dict):
            continue
        job_id = metadata.get("job_id")
        finding_id = metadata.get("finding_id")
        if not isinstance(job_id, str) or not isinstance(finding_id, str):
            continue
        if not job_id or not finding_id or job_id == current_job_id:
            continue

        source_key = (job_id, finding_id)
        if source_key in seen:
            continue
        seen.add(source_key)

        if db.get(Job, job_id) is None:
            continue
        finding = db.scalar(
            select(Finding).where(
                Finding.job_id == job_id,
                Finding.finding_id == finding_id,
            )
        )
        if finding is None or finding.analyst_status != "confirmed":
            continue

        lineage = db.get(BlueScrubJobLineage, job_id)
        project_id = lineage.project_id if lineage and lineage.project_id else None
        project_label = project_id or "No project assigned"
        header = (
            f"Historical finding {finding_id}\n"
            f"Job: {job_id}\n"
            f"Project: {project_label}\n"
        )
        separator_length = 2 if context_parts else 0
        available = _MAX_CONTEXT_CHARS - context_length - separator_length - len(header)
        if available <= 0:
            break

        snippet = finding_to_text(finding)[: min(_MAX_SNIPPET_CHARS, available)]
        if not snippet:
            continue
        entry = header + snippet
        context_parts.append(entry)
        context_length += separator_length + len(entry)
        citations.append(
            HistoricalFindingCitation(
                type="historical_finding",
                id=finding_id,
                snippet=snippet,
                source_job_id=job_id,
                source_project_id=project_id,
                href=f"/jobs/{job_id}/findings/{finding_id}",
            )
        )
        if len(citations) >= top_k:
            break

    if not citations:
        return _empty_result("no_matches")
    return MnemosRetrievalResult(
        status="used",
        context="\n\n".join(context_parts),
        citations=citations,
    )
