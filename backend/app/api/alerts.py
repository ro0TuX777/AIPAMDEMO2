"""
Alerts endpoints.

GET  /jobs/{jobId}/alerts                       – list all alerts for a job
GET  /jobs/{jobId}/alerts/{alertId}             – get a single alert with related data
GET  /jobs/{jobId}/alerts/{alertId}/arkime-link – Arkime pivot link for an alert
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.api.pagination import paginate
from backend.app.models.alert import Alert
from backend.app.models.connection import Connection
from backend.app.models.host import Host
from backend.app.models.job import Job
from backend.app.schemas.alert import AlertItem, AlertListResponse
from backend.app.schemas.arkime import ArkimePivotResponse
from backend.app.schemas.common import Severity

router = APIRouter(tags=["Alerts"], dependencies=[Depends(verify_token)])


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/jobs/{job_id}/alerts", response_model=AlertListResponse)
async def list_alerts(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    severity: Severity | None = Query(None),
    signature: str | None = Query(None),
    src_ip: str | None = Query(None),
    dest_ip: str | None = Query(None),
    pcap_label: str | None = Query(None, description="Filter by PCAP label (before/after)"),
):
    """List all alerts for a job, optionally filtered."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    q = select(Alert).where(Alert.job_id == job_id)
    if pcap_label:
        q = q.where(Alert.pcap_label == pcap_label)
    if severity:
        q = q.where(Alert.severity == severity.value)
    if signature:
        q = q.where(Alert.signature.contains(signature))
    if src_ip:
        q = q.where(Alert.src_ip == src_ip)
    if dest_ip:
        q = q.where(Alert.dest_ip == dest_ip)

    items, page = paginate(db, q, Alert.ts, Alert.id, cursor, limit)
    return AlertListResponse(
        items=[AlertItem.model_validate(a) for a in items],
        page=page,
    )


@router.get("/jobs/{job_id}/alerts/{alert_id}")
async def get_alert(
    job_id: str,
    alert_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Get a single alert with related host and connection info."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    alert = db.execute(
        select(Alert).where(Alert.job_id == job_id, Alert.alert_id == alert_id)
    ).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Gather related host info
    related_hosts = []
    for ip in set(filter(None, [alert.src_ip, alert.dest_ip, alert.host_ip])):
        host = db.execute(
            select(Host).where(Host.job_id == job_id, Host.ip == ip)
        ).scalar_one_or_none()
        if host:
            related_hosts.append({
                "ip": host.ip,
                "role": host.role,
                "conn_count": host.conn_count,
                "alert_count": host.alert_count,
            })

    # Gather related connections by community_id
    related_connections = []
    if alert.community_id:
        conns = db.execute(
            select(Connection).where(
                Connection.job_id == job_id,
                Connection.community_id == alert.community_id,
            ).limit(10)
        ).scalars().all()
        for c in conns:
            related_connections.append({
                "connection_id": c.connection_id,
                "src_ip": c.src_ip,
                "src_port": c.src_port,
                "dest_ip": c.dest_ip,
                "dest_port": c.dest_port,
                "proto": c.proto,
                "service": c.service,
                "ts": c.ts,
            })

    import json
    return {
        "schema_version": "1.0",
        "alert_id": alert.alert_id,
        "ts": alert.ts,
        "severity": alert.severity,
        "engine": alert.engine,
        "signature": alert.signature,
        "category": alert.category,
        "sid": alert.sid,
        "src_ip": alert.src_ip,
        "src_port": alert.src_port,
        "dest_ip": alert.dest_ip,
        "dest_port": alert.dest_port,
        "proto": alert.proto,
        "community_id": alert.community_id,
        "refs": json.loads(alert.refs_json) if alert.refs_json else [],
        "tags": json.loads(alert.tags_json) if alert.tags_json else [],
        "related_hosts": related_hosts,
        "related_connections": related_connections,
    }



# ---------- GET /jobs/{jobId}/alerts/{alertId}/arkime-link ----------

@router.get("/jobs/{job_id}/alerts/{alert_id}/arkime-link", response_model=ArkimePivotResponse)
async def alert_arkime_link(
    job_id: str,
    alert_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Build an Arkime viewer pivot URL for a specific alert.

    Uses community_id (primary) or falls back to 5-tuple correlation.
    """
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    alert = db.execute(
        select(Alert).where(Alert.job_id == job_id, Alert.alert_id == alert_id)
    ).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    from backend.app.connectors import ArkimeConnector
    connector = ArkimeConnector()

    if not connector.enabled:
        return ArkimePivotResponse(
            enabled=False,
            message="Arkime integration is not enabled.",
        )

    url, basis = connector.build_pivot_url(
        community_id=alert.community_id,
        src_ip=alert.src_ip,
        src_port=alert.src_port,
        dest_ip=alert.dest_ip,
        dest_port=alert.dest_port,
        proto=alert.proto,
        ts=alert.ts,
    )

    # Get import status for the job
    from backend.app.config_v2 import get_settings as _get_settings
    settings = _get_settings()
    job_dir = settings.aipam_job_root / job_id
    status_data = connector.get_import_status(job_dir)

    return ArkimePivotResponse(
        enabled=True,
        url=url,
        basis=basis,
        import_status=status_data.get("status", "not_imported"),
        message="PCAPs must be imported into Arkime before pivot links will return sessions." if status_data.get("status") == "not_imported" else None,
    )