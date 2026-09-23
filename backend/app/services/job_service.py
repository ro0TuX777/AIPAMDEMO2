"""Business logic extracted from api/jobs.py.

Keeps route handlers thin — all heavy DB queries, aggregations,
and integration logic live here.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.models.theory import Theory
from backend.app.schemas.host import HostListItem
from backend.app.schemas.ioc import IocItem

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def safe_json_list(raw: str | None) -> list:
    """Parse a JSON-encoded string to a list, returning [] on failure."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


# ---------------------------------------------------------------------------
# Job summary
# ---------------------------------------------------------------------------


def compute_job_summary(db: Session, job_id: str) -> Dict[str, Any]:
    """Compute a high-level summary dict for a completed job.

    Returns a dict with keys matching ``JobSummaryResponse`` fields.
    """
    alert_count = db.scalar(select(func.count()).select_from(Alert).where(Alert.job_id == job_id)) or 0
    finding_count = db.scalar(select(func.count()).select_from(Finding).where(Finding.job_id == job_id)) or 0
    ioc_count = db.scalar(select(func.count()).select_from(Ioc).where(Ioc.job_id == job_id)) or 0
    host_count = db.scalar(select(func.count()).select_from(Host).where(Host.job_id == job_id)) or 0

    # Top hosts by connection count
    top_hosts_rows = db.execute(
        select(Host).where(Host.job_id == job_id).order_by(Host.conn_count.desc()).limit(5)
    ).scalars().all()
    top_hosts = [
        HostListItem(
            ip=h.ip, role=h.role or "unknown", conn_count=h.conn_count or 0,
            bytes_sent=h.bytes_sent, bytes_recv=h.bytes_recv,
            alert_count=h.alert_count or 0, finding_count=h.finding_count or 0,
            top_domains=safe_json_list(h.top_domains_json),
        )
        for h in top_hosts_rows
    ]

    # Top IOCs
    top_iocs_rows = db.execute(
        select(Ioc).where(Ioc.job_id == job_id).limit(5)
    ).scalars().all()
    top_iocs = [
        IocItem(
            ioc_id=i.ioc_id, type=i.ioc_type, value=i.value,
            confidence=i.confidence, sources=safe_json_list(i.sources_json),
        )
        for i in top_iocs_rows
    ]

    # Top signals (high/critical alerts)
    top_alerts = db.execute(
        select(Alert.signature).where(
            Alert.job_id == job_id, Alert.severity.in_(["high", "critical"])
        ).group_by(Alert.signature).order_by(func.count().desc()).limit(5)
    ).scalars().all()

    headline = (
        f"Analysis found {alert_count} alerts, {finding_count} findings, "
        f"{ioc_count} IOCs across {host_count} hosts."
    )

    # Generate recommendations
    from backend.app.services.report_composer import _generate_recommendations

    theories = db.execute(select(Theory).where(Theory.job_id == job_id)).scalars().all()
    findings = db.execute(select(Finding).where(Finding.job_id == job_id)).scalars().all()
    iocs_all = db.execute(select(Ioc).where(Ioc.job_id == job_id)).scalars().all()

    has_critical = db.scalar(
        select(func.count()).select_from(Alert).where(Alert.job_id == job_id, Alert.severity == "critical")
    ) or 0
    has_high = db.scalar(
        select(func.count()).select_from(Alert).where(Alert.job_id == job_id, Alert.severity == "high")
    ) or 0
    threat = "critical" if has_critical else "high" if has_high else "medium"
    recommendations = _generate_recommendations(threat, theories, findings, iocs_all)

    return {
        "job_id": job_id,
        "headline": headline,
        "top_signals": list(top_alerts),
        "top_hosts": top_hosts,
        "top_iocs": top_iocs,
        "recommendations": recommendations,
        "alert_count": alert_count,
        "finding_count": finding_count,
        "ioc_count": ioc_count,
        "host_count": host_count,
    }


# ---------------------------------------------------------------------------
# SSE generator
# ---------------------------------------------------------------------------


async def sse_generator(job_id: str, db_factory):
    """Server-Sent Events generator with Redis pub/sub + DB polling fallback.

    Subscribes to the job's Redis event channel for low-latency pipeline
    events.  Falls back to DB polling every 1 s to detect status changes.
    """
    from backend.app.events import subscribe_job_events

    pubsub = subscribe_job_events(job_id)
    last_status = None
    retry_count = 0
    max_retries = 3600  # ~1 hour at 1 s intervals
    _event_id = 0

    try:
        while retry_count < max_retries:
            # 1. Drain queued Redis messages
            if pubsub is not None:
                try:
                    for _ in range(50):
                        msg = pubsub.get_message(ignore_subscribe_messages=True, timeout=0.0)
                        if msg is None:
                            break
                        if msg["type"] == "message":
                            yield f"data: {msg['data']}\n\n"
                except Exception:
                    pass

            # 2. DB status poll
            try:
                db = db_factory()
                try:
                    job = db.get(Job, job_id)
                    if not job:
                        yield 'event: error\ndata: {"message": "Job not found"}\n\n'
                        return

                    current_status = job.status
                    if current_status != last_status:
                        _event_id += 1
                        envelope = json.dumps({
                            "id": _event_id,
                            "type": "job.status",
                            "ts": job.started_at or "",
                            "data": {
                                "job_id": job_id,
                                "status": current_status,
                                "started_at": job.started_at,
                                "completed_at": job.completed_at,
                                "error_summary": job.error_summary,
                            },
                        })
                        yield f"data: {envelope}\n\n"
                        last_status = current_status

                    if current_status in (
                        "completed", "completed_with_errors", "failed", "canceled", "deleted"
                    ):
                        _event_id += 1
                        done_envelope = json.dumps({
                            "id": _event_id,
                            "type": "job.complete",
                            "ts": job.completed_at or "",
                            "data": {"job_id": job_id, "status": current_status},
                        })
                        yield f"data: {done_envelope}\n\n"
                        return
                finally:
                    db.close()
            except Exception as e:
                yield f'event: error\ndata: {{"message": "{e!s}"}}\n\n'

            await asyncio.sleep(1.0)
            retry_count += 1
    finally:
        if pubsub is not None:
            try:
                pubsub.unsubscribe()
                pubsub.close()
            except Exception:
                pass

    yield 'event: timeout\ndata: {"message": "SSE stream timed out"}\n\n'


# ---------------------------------------------------------------------------
# Export ZIP
# ---------------------------------------------------------------------------


def create_export_zip(db: Session, job: Job, job_dir: Path) -> bytes:
    """Create a ZIP archive of all job artifacts and return the bytes."""
    from backend.app.api.findings import _finding_to_item
    from backend.app.pipeline.run_artifacts import (
        iter_run_files, resolve_accepted_run_dirs, run_archive_prefix, safe_artifact_path,
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # input PCAPs
        for pcap in (job_dir / "input").glob("*"):
            try:
                pcap = safe_artifact_path(job_dir, pcap.relative_to(job_dir))
            except ValueError:
                continue
            if pcap.is_file():
                zf.write(pcap, arcname=f"input/{pcap.name}")

        for run_dir in resolve_accepted_run_dirs(job, job_dir.parent):
            prefix = run_archive_prefix(job, run_dir)
            for path in iter_run_files(run_dir):
                zf.write(path, arcname=prefix + path.relative_to(run_dir).as_posix())

        # findings JSON
        findings_q = select(Finding).where(Finding.job_id == job.job_id)
        findings = db.execute(findings_q).scalars().all()
        findings_data = [_finding_to_item(f).model_dump() for f in findings]
        zf.writestr("findings.json", json.dumps(findings_data, indent=2))

        # metadata
        meta = {
            "job_id": job.job_id,
            "job_name": job.job_name,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "status": job.status,
        }
        zf.writestr("export_metadata.json", json.dumps(meta, indent=2))

    return buf.getvalue()
