"""Persistence helpers for the Evidence Store.

Converts parsed FlowRecord and AlertRecord Pydantic models into
FlowDB and AlertDB rows for structured database storage.
"""

from __future__ import annotations

import logging
from typing import List
from uuid import uuid4

from sqlmodel import Session

from ..db_models import AlertDB, EvidenceDB, FlowDB
from ..models import AlertRecord, FlowRecord

logger = logging.getLogger(__name__)


def persist_flows(session: Session, job_id: str, flows: List[FlowRecord]) -> int:
    """Persist parsed FlowRecord objects as FlowDB rows.

    Uses a composite key of ``{job_id}:{flow.id}`` to ensure uniqueness
    across jobs (Zeek UIDs can collide between PCAPs).

    Args:
        session: Active SQLModel session.
        job_id: Parent job identifier.
        flows: Parsed FlowRecord objects from parsers.

    Returns:
        Number of rows inserted.
    """
    count = 0
    for flow in flows:
        row = FlowDB(
            id=f"{job_id}:{flow.id}",
            job_id=job_id,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            transport_proto=flow.transport_proto,
            app_proto=flow.app_proto,
            start_time=flow.start_time,
            end_time=flow.end_time,
            duration_sec=flow.duration_sec,
            bytes_from_src=flow.bytes_from_src,
            bytes_from_dst=flow.bytes_from_dst,
            packets_from_src=flow.packets_from_src,
            packets_from_dst=flow.packets_from_dst,
            tcp_flags_summary=flow.tcp_flags_summary,
            state=flow.state,
            extra=flow.extra,
        )
        session.add(row)
        count += 1

    session.commit()
    logger.info("Persisted %d flows for job %s", count, job_id)
    return count


def persist_alerts(session: Session, job_id: str, alerts: List[AlertRecord]) -> int:
    """Persist parsed AlertRecord objects as AlertDB rows.

    Args:
        session: Active SQLModel session.
        job_id: Parent job identifier.
        alerts: Parsed AlertRecord objects from parsers.

    Returns:
        Number of rows inserted.
    """
    count = 0
    for alert in alerts:
        row = AlertDB(
            id=f"{job_id}:{alert.id}",
            job_id=job_id,
            timestamp=alert.timestamp,
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            src_port=alert.src_port,
            dst_port=alert.dst_port,
            alert_source=alert.alert_source,
            signature_id=alert.signature_id,
            signature_name=alert.signature_name,
            severity=alert.severity,
            category=alert.category,
            flow_id=f"{job_id}:{alert.flow_id}" if alert.flow_id else None,
            extra=alert.extra,
        )
        session.add(row)
        count += 1

    session.commit()
    logger.info("Persisted %d alerts for job %s", count, job_id)
    return count


def link_evidence(
    session: Session,
    finding_id: str,
    flow_ids: List[str],
    relationship: str = "supports",
    snippet: str | None = None,
) -> int:
    """Create EvidenceDB links between a Finding and its supporting Flows.

    Args:
        session: Active SQLModel session.
        finding_id: ID of the FindingDB row.
        flow_ids: IDs of FlowDB rows that support this finding.
        relationship: Type of link — "supports", "contradicts", or "context".
        snippet: Optional evidence excerpt for analyst review.

    Returns:
        Number of evidence links created.
    """
    count = 0
    for flow_id in flow_ids:
        row = EvidenceDB(
            id=str(uuid4()),
            finding_id=finding_id,
            flow_id=flow_id,
            relationship=relationship,
            snippet=snippet,
        )
        session.add(row)
        count += 1

    session.commit()
    return count
