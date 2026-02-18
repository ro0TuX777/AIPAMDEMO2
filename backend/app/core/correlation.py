"""Campaign Correlator — cross-job finding correlation.

Scans ``FindingDB`` for commonalities across different analysis jobs.
When two or more jobs share the same MITRE technique **and** at least
one common affected host IP, they are grouped into a
``CorrelationGroup`` suggesting the same campaign or incident.

Usage::

    from app.core.correlation import CampaignCorrelator

    with get_session() as session:
        groups = CampaignCorrelator.correlate(session)
        for g in groups:
            print(f"Campaign {g.group_id}: {g.mitre_technique_id} "
                  f"via {g.common_indicators} across {g.job_ids}")
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field
from sqlmodel import Session, select

from ..db_models import FindingDB

logger = logging.getLogger(__name__)


class CorrelationGroup(BaseModel):
    """A cluster of findings sharing technique + indicator across jobs.

    Attributes:
        group_id: Deterministic hash of technique + indicator.
        mitre_technique_id: The shared MITRE ATT&CK technique.
        common_indicators: IP addresses shared across multiple jobs.
        job_ids: Distinct job IDs that contribute to this group.
        finding_ids: Individual finding IDs in the group.
        confidence: Heuristic confidence 0.0–1.0.
    """

    group_id: str
    mitre_technique_id: str
    common_indicators: List[str] = Field(default_factory=list)
    job_ids: List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)
    confidence: float = 0.0


def _extract_ips(affected_hosts: Any) -> Set[str]:
    """Extract IP addresses from the affected_hosts JSON field.

    ``affected_hosts`` may be stored as:
    * A ``dict`` mapping IP → role/info (common in AIPAM analysis output)
    * A ``list`` of IP strings
    * A JSON-encoded string of either format
    """
    if isinstance(affected_hosts, str):
        try:
            affected_hosts = json.loads(affected_hosts)
        except (json.JSONDecodeError, TypeError):
            return set()

    if isinstance(affected_hosts, dict):
        return set(affected_hosts.keys())
    if isinstance(affected_hosts, list):
        return {str(ip) for ip in affected_hosts}
    return set()


def _group_id(technique: str, indicator: str) -> str:
    """Deterministic, short hash for a (technique, indicator) pair."""
    raw = f"{technique}:{indicator}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class CampaignCorrelator:
    """Stateless correlator — all state lives in the DB.

    The correlation algorithm:
    1. Load all findings with a non-null ``mitre_technique_id``.
    2. Build an inverted index: ``(technique, ip) → [(job_id, finding_id)]``.
    3. Emit a ``CorrelationGroup`` for each key that spans ≥ 2 distinct jobs.
    """

    @staticmethod
    def correlate(
        session: Session,
        min_jobs: int = 2,
    ) -> List[CorrelationGroup]:
        """Find cross-job correlations across all findings.

        Args:
            session: Active DB session.
            min_jobs: Minimum distinct jobs to form a group (default 2).

        Returns:
            List of CorrelationGroups, sorted by confidence descending.
        """
        findings = session.exec(
            select(FindingDB).where(FindingDB.mitre_technique_id.isnot(None))  # type: ignore[union-attr]
        ).all()

        return CampaignCorrelator._build_groups(findings, min_jobs)

    @staticmethod
    def correlate_for_job(
        session: Session,
        job_id: str,
        min_jobs: int = 2,
    ) -> List[CorrelationGroup]:
        """Return only correlation groups that include ``job_id``.

        Args:
            session: Active DB session.
            job_id: The job to focus on.
            min_jobs: Minimum distinct jobs to form a group (default 2).

        Returns:
            Filtered list of CorrelationGroups involving the given job.
        """
        all_groups = CampaignCorrelator.correlate(session, min_jobs)
        return [g for g in all_groups if job_id in g.job_ids]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_groups(
        findings: List[FindingDB],
        min_jobs: int,
    ) -> List[CorrelationGroup]:
        """Build correlation groups from a list of findings."""
        # Inverted index: (technique, ip) → list of (job_id, finding_id)
        index: Dict[Tuple[str, str], List[Tuple[str, str]]] = defaultdict(list)

        for f in findings:
            if not f.mitre_technique_id:
                continue
            ips = _extract_ips(f.affected_hosts)
            for ip in ips:
                index[(f.mitre_technique_id, ip)].append((f.job_id, f.id))

        groups: List[CorrelationGroup] = []

        # Merge keys that share the same technique across ≥ min_jobs
        # Group by technique first, then aggregate common IPs
        technique_groups: Dict[str, Dict[str, List[Tuple[str, str]]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for (technique, ip), entries in index.items():
            job_ids = {e[0] for e in entries}
            if len(job_ids) >= min_jobs:
                technique_groups[technique][ip].extend(entries)

        for technique, ip_map in technique_groups.items():
            # Aggregate all IPs and entries for this technique
            all_indicators: List[str] = sorted(ip_map.keys())
            all_entries: List[Tuple[str, str]] = []
            for entries in ip_map.values():
                all_entries.extend(entries)

            job_ids = sorted({e[0] for e in all_entries})
            finding_ids = sorted({e[1] for e in all_entries})

            # Confidence heuristic: more jobs + more indicators = higher confidence
            confidence = min(1.0, len(job_ids) * 0.3 + len(all_indicators) * 0.1)

            gid = _group_id(technique, ",".join(all_indicators))

            groups.append(
                CorrelationGroup(
                    group_id=gid,
                    mitre_technique_id=technique,
                    common_indicators=all_indicators,
                    job_ids=job_ids,
                    finding_ids=finding_ids,
                    confidence=round(confidence, 2),
                )
            )

        # Sort by confidence descending
        groups.sort(key=lambda g: g.confidence, reverse=True)

        logger.info(
            "CampaignCorrelator: found %d correlation groups from %d findings",
            len(groups),
            len(findings),
        )

        return groups
