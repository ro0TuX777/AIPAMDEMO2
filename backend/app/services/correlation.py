"""
Cross-Job Correlation Service — Sprint 8.

Surfaces prior occurrences of hosts, IOCs, and MITRE technique categories
across all completed jobs, powering "Seen Before?" panels and campaign
detection heuristics.
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.schemas.correlation import (
    CampaignCandidate,
    CorrelationMatch,
    CorrelationQuery,
    CorrelationResponse,
    RelatedJob,
    RelatedJobsResponse,
)

logger = logging.getLogger(__name__)

# ── Tuning constants ──────────────────────────────────────────────────
_MIN_CAMPAIGN_OVERLAP = 2  # Minimum shared entities to form a campaign
_MIN_CAMPAIGN_JOBS = 3     # Minimum jobs in a campaign cluster
_MAX_RESULTS = 100         # Hard upper-bound for any result list

# Relevance-score weights used by get_related_jobs
_WEIGHT_HOST = 0.15
_WEIGHT_IOC = 0.25
_WEIGHT_MITRE = 0.10

# IOC similarity by severity tier
_IOC_SCORE: dict[str | None, float] = {
    "critical": 0.8, "high": 0.8,
    "medium": 0.6, "low": 0.5,
}
_IOC_SCORE_DEFAULT = 0.5

# ── Helpers ───────────────────────────────────────────────────────────

JobMap = dict[str, tuple[str, str | None]]
"""job_id → (job_name, created_at)"""


def _job_lookup(db: Session) -> JobMap:
    """Build an in-memory job_id → (job_name, created_at) map."""
    rows = db.execute(select(Job.job_id, Job.job_name, Job.created_at)).all()
    return {r[0]: (r[1], r[2]) for r in rows}


def _resolve_job(job_map: JobMap, job_id: str) -> tuple[str, str | None]:
    """Resolve a job_id to (name, created_at), falling back to the id itself."""
    return job_map.get(job_id, (job_id, None))


def find_host_matches(
    db: Session, job_id: str, hosts: list[str],
    job_map: JobMap | None = None,
) -> list[CorrelationMatch]:
    """Return matches for *hosts* that also appear in other jobs."""
    if not hosts:
        return []
    if job_map is None:
        job_map = _job_lookup(db)

    matches: list[CorrelationMatch] = []
    seen: set[tuple[str, str]] = set()

    for ip in hosts:
        rows = db.execute(
            select(Host.job_id, Host.ip, Host.alert_count, Host.finding_count)
            .where(Host.ip == ip, Host.job_id != job_id)
        ).all()
        for r in rows:
            key = (r[0], r[1])
            if key in seen:
                continue
            seen.add(key)
            jname, jcreated = _resolve_job(job_map, r[0])
            alert_cnt = r[2] or 0
            finding_cnt = r[3] or 0
            matches.append(CorrelationMatch(
                job_id=r[0], job_name=jname, job_created_at=jcreated,
                match_type="same_host", matched_entity=r[1],
                context=f"Host {r[1]} seen in job {jname} ({alert_cnt} alerts, {finding_cnt} findings)",
                similarity_score=min(1.0, (alert_cnt + finding_cnt) * 0.1 + 0.3),
            ))
    return matches


def find_ioc_matches(
    db: Session, job_id: str,
    ioc_values: list[str] | None = None,
    job_map: JobMap | None = None,
) -> list[CorrelationMatch]:
    """Return matches for IOCs that also appear in other jobs.

    When *ioc_values* is ``None``, all IOCs belonging to *job_id* are used.
    """
    if job_map is None:
        job_map = _job_lookup(db)

    if ioc_values is None:
        own_iocs = db.execute(
            select(Ioc.value).where(Ioc.job_id == job_id)
        ).all()
        ioc_values = [r[0] for r in own_iocs]

    if not ioc_values:
        return []

    matches: list[CorrelationMatch] = []
    seen: set[tuple[str, str]] = set()

    for val in ioc_values:
        rows = db.execute(
            select(Ioc.job_id, Ioc.value, Ioc.ioc_type, Ioc.severity)
            .where(Ioc.value == val, Ioc.job_id != job_id)
        ).all()
        for r in rows:
            key = (r[0], r[1])
            if key in seen:
                continue
            seen.add(key)
            jname, jcreated = _resolve_job(job_map, r[0])
            score = _IOC_SCORE.get(r[3], _IOC_SCORE_DEFAULT)
            matches.append(CorrelationMatch(
                job_id=r[0], job_name=jname, job_created_at=jcreated,
                match_type="same_ioc", matched_entity=r[1],
                context=f"IOC {r[1]} ({r[2]}) also found in job {jname}",
                similarity_score=score,
            ))
    return matches


def find_mitre_matches(
    db: Session, job_id: str,
    job_map: JobMap | None = None,
) -> list[CorrelationMatch]:
    """Return matches for MITRE technique categories shared with other jobs."""
    if job_map is None:
        job_map = _job_lookup(db)

    own = db.execute(
        select(Finding.category).where(
            Finding.job_id == job_id,
            Finding.category.isnot(None),
        ).distinct()
    ).all()
    categories = [r[0] for r in own if r[0]]
    if not categories:
        return []

    matches: list[CorrelationMatch] = []
    seen: set[tuple[str, str]] = set()

    for cat in categories:
        rows = db.execute(
            select(Finding.job_id, Finding.category, Finding.title)
            .where(Finding.category == cat, Finding.job_id != job_id)
            .distinct()
        ).all()
        for r in rows:
            key = (r[0], r[1])
            if key in seen:
                continue
            seen.add(key)
            jname, jcreated = _resolve_job(job_map, r[0])
            matches.append(CorrelationMatch(
                job_id=r[0], job_name=jname, job_created_at=jcreated,
                match_type="same_mitre", matched_entity=r[1],
                matched_title=r[2],
                context=f"Category '{r[1]}' also seen in job {jname}",
                similarity_score=0.6,
            ))
    return matches


_MATCH_TYPE_BUCKET: dict[str, Literal["hosts", "iocs", "mitre"]] = {
    "same_host": "hosts",
    "same_ioc": "iocs",
    "same_mitre": "mitre",
}


def detect_campaigns(
    db: Session, job_id: str, all_matches: list[CorrelationMatch],
) -> list[CampaignCandidate]:
    """Cluster correlation matches into campaign candidates.

    A campaign is emitted when ``_MIN_CAMPAIGN_JOBS``+ jobs share at least
    ``_MIN_CAMPAIGN_OVERLAP`` distinct entities.
    """
    # Bucket entities per related job
    job_entities: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"hosts": set(), "iocs": set(), "mitre": set()}
    )
    for m in all_matches:
        bucket = _MATCH_TYPE_BUCKET.get(m.match_type)
        if bucket:
            job_entities[m.job_id][bucket].add(m.matched_entity)

    if len(job_entities) < (_MIN_CAMPAIGN_JOBS - 1):
        return []

    # Accumulate jobs that meet the overlap threshold
    shared_iocs: set[str] = set()
    shared_hosts: set[str] = set()
    shared_mitre: set[str] = set()
    campaign_jobs: set[str] = {job_id}

    for jid, ents in job_entities.items():
        total_shared = len(ents["hosts"]) + len(ents["iocs"]) + len(ents["mitre"])
        if total_shared >= _MIN_CAMPAIGN_OVERLAP:
            campaign_jobs.add(jid)
            shared_hosts |= ents["hosts"]
            shared_iocs |= ents["iocs"]
            shared_mitre |= ents["mitre"]

    if len(campaign_jobs) < _MIN_CAMPAIGN_JOBS:
        return []

    # Build human-readable label
    label_parts: list[str] = []
    if shared_mitre:
        label_parts.append(", ".join(sorted(shared_mitre)[:2]))
    if shared_iocs:
        label_parts.append(f"{len(shared_iocs)} shared IOCs")
    label = f"Potential campaign: {' + '.join(label_parts)} across {len(campaign_jobs)} jobs"

    # Deterministic campaign ID from constituent job + entity sets
    raw = f"{','.join(sorted(campaign_jobs))}:{','.join(sorted(shared_iocs | shared_hosts))}"
    cid = hashlib.sha256(raw.encode()).hexdigest()[:12]

    confidence = min(
        1.0,
        len(campaign_jobs) * 0.2 + len(shared_iocs) * 0.1 + len(shared_hosts) * 0.05,
    )

    logger.info(
        "Campaign detected: id=%s jobs=%d iocs=%d hosts=%d conf=%.2f",
        cid, len(campaign_jobs), len(shared_iocs), len(shared_hosts), confidence,
    )

    return [CampaignCandidate(
        campaign_id=cid,
        label=label,
        job_ids=sorted(campaign_jobs),
        shared_iocs=sorted(shared_iocs),
        shared_hosts=sorted(shared_hosts),
        shared_mitre_techniques=sorted(shared_mitre),
        confidence=round(confidence, 2),
    )]


def get_correlations(
    db: Session,
    job_id: str,
    item_id: str | None = None,
    host: str | None = None,
    ioc: str | None = None,
    limit: int = 20,
) -> CorrelationResponse:
    """Build the full correlation response for a job.

    The scope can be narrowed by providing *item_id*, *host*, or *ioc*.
    When none are given every entity in the job is checked.
    """
    limit = min(limit, _MAX_RESULTS)
    job_map = _job_lookup(db)

    # Determine which hosts to correlate
    if host:
        hosts = [host]
    elif item_id:
        hosts = _hosts_from_item(db, job_id, item_id)
    else:
        own_hosts = db.execute(select(Host.ip).where(Host.job_id == job_id)).all()
        hosts = [r[0] for r in own_hosts]

    ioc_values = [ioc] if ioc else None  # None → auto-fetch all

    # Collect matches from all three dimensions
    all_matches: list[CorrelationMatch] = []
    all_matches.extend(find_host_matches(db, job_id, hosts, job_map))
    all_matches.extend(find_ioc_matches(db, job_id, ioc_values, job_map))
    if not host and not ioc:
        all_matches.extend(find_mitre_matches(db, job_id, job_map))

    # Rank by similarity then cap
    all_matches.sort(key=lambda m: m.similarity_score, reverse=True)
    all_matches = all_matches[:limit]

    campaigns = detect_campaigns(db, job_id, all_matches)

    return CorrelationResponse(
        query=CorrelationQuery(job_id=job_id, item_id=item_id, host=host, ioc=ioc),
        matches=all_matches,
        campaigns=campaigns,
        total_matches=len(all_matches),
    )


# ── Item-scoped helpers ───────────────────────────────────────────────


def _hosts_from_item(db: Session, job_id: str, item_id: str) -> list[str]:
    """Extract host IPs from a queue-item identifier (``alert:<id>``)."""
    parts = item_id.split(":", 1)
    if len(parts) != 2:
        return []
    item_type, entity_id = parts

    if item_type == "alert":
        row = db.execute(
            select(Alert.host_ip, Alert.src_ip, Alert.dest_ip)
            .where(Alert.job_id == job_id, Alert.alert_id == entity_id)
        ).first()
        if row:
            return [ip for ip in (row[0], row[1], row[2]) if ip]
    # Findings don't carry direct host columns
    return []


# ── Related Jobs ──────────────────────────────────────────────────────


def _primary_overlap_type(overlaps: dict[str, set[str]]) -> str:
    """Pick the most significant overlap category."""
    if overlaps["iocs"]:
        return "shared_iocs"
    if overlaps["hosts"]:
        return "shared_hosts"
    return "shared_mitre"


def get_related_jobs(db: Session, job_id: str) -> RelatedJobsResponse:
    """Return jobs related to *job_id* via shared hosts, IOCs, or MITRE categories.

    Results are ranked by a weighted relevance score and capped at 20.
    """
    job_map = _job_lookup(db)

    own_host_ips = [r[0] for r in db.execute(select(Host.ip).where(Host.job_id == job_id)).all()]
    own_ioc_vals = [r[0] for r in db.execute(select(Ioc.value).where(Ioc.job_id == job_id)).all()]
    own_cats = [
        r[0] for r in db.execute(
            select(Finding.category).where(
                Finding.job_id == job_id, Finding.category.isnot(None),
            ).distinct()
        ).all()
        if r[0]
    ]

    job_overlaps: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"hosts": set(), "iocs": set(), "mitre": set()}
    )

    # Host overlap
    for ip in own_host_ips:
        for r in db.execute(select(Host.job_id).where(Host.ip == ip, Host.job_id != job_id)).all():
            job_overlaps[r[0]]["hosts"].add(ip)

    # IOC overlap
    for val in own_ioc_vals:
        for r in db.execute(select(Ioc.job_id).where(Ioc.value == val, Ioc.job_id != job_id)).all():
            job_overlaps[r[0]]["iocs"].add(val)

    # MITRE category overlap
    for cat in own_cats:
        for r in db.execute(
            select(Finding.job_id).where(Finding.category == cat, Finding.job_id != job_id).distinct()
        ).all():
            job_overlaps[r[0]]["mitre"].add(cat)

    # Assemble ranked list
    related: list[RelatedJob] = []
    for jid, overlaps in job_overlaps.items():
        jname, jcreated = _resolve_job(job_map, jid)
        all_entities = sorted(overlaps["hosts"] | overlaps["iocs"] | overlaps["mitre"])
        score = min(
            1.0,
            len(overlaps["hosts"]) * _WEIGHT_HOST
            + len(overlaps["iocs"]) * _WEIGHT_IOC
            + len(overlaps["mitre"]) * _WEIGHT_MITRE,
        )
        related.append(RelatedJob(
            job_id=jid, job_name=jname, job_created_at=jcreated,
            overlap_type=_primary_overlap_type(overlaps),
            shared_entities=all_entities,
            relevance_score=round(score, 2),
        ))

    related.sort(key=lambda r: r.relevance_score, reverse=True)
    return RelatedJobsResponse(job_id=job_id, related_jobs=related[:20])
