"""
Host endpoints (§3.5).

GET /jobs/{jobId}/hosts                  – list hosts
GET /jobs/{jobId}/hosts/{ip}             – host detail
GET /jobs/{jobId}/hosts/{ip}/connections – host connections
GET /jobs/{jobId}/hosts/{ip}/dns         – host DNS queries
GET /jobs/{jobId}/hosts/{ip}/tls         – host TLS sessions
GET /jobs/{jobId}/hosts/{ip}/alerts      – host alerts
GET /jobs/{jobId}/hosts/{ip}/files       – host files
"""

import json

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.api.pagination import paginate
from backend.app.models.alert import Alert
from backend.app.models.connection import Connection
from backend.app.models.dns import DnsQuery
from backend.app.models.file import File
from backend.app.models.global_host import GlobalHost
from backend.app.models.host import Host
from backend.app.models.job import Job
from backend.app.models.tls import TlsSession
from backend.app.schemas.alert import AlertItem, AlertListResponse
from backend.app.schemas.common import PageInfo
from backend.app.schemas.connection import ConnectionItem, ConnectionListResponse
from backend.app.schemas.dns import DnsQueryItem, DnsQueryListResponse
from backend.app.schemas.file import FileItem, FileListResponse
from backend.app.schemas.host import (
    DnsSummary,
    GlobalHostDetail,
    GlobalHostGetResponse,
    GlobalHostListItem,
    GlobalHostListResponse,
    HostDetail,
    HostGetResponse,
    HostListItem,
    HostListResponse,
    TlsSummary,
)
from backend.app.schemas.tls import TlsSessionItem, TlsSessionListResponse

router = APIRouter(tags=["Hosts"], dependencies=[Depends(verify_token)])


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _require_host(db: Session, job_id: str, ip: str) -> Host:
    host = db.execute(
        select(Host).where(Host.job_id == job_id, Host.ip == ip)
    ).scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return host


def _safe_json_list(raw: str | None) -> list:
    if not raw:
        return []
    try:
        result = json.loads(raw)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _host_to_list_item(h: Host) -> HostListItem:
    return HostListItem(
        ip=h.ip,
        role=h.role or "unknown",
        conn_count=h.conn_count or 0,
        bytes_sent=h.bytes_sent,
        bytes_recv=h.bytes_recv,
        alert_count=h.alert_count or 0,
        finding_count=h.finding_count or 0,
        top_domains=_safe_json_list(h.top_domains_json),
    )


@router.get("/jobs/{job_id}/hosts", response_model=HostListResponse)
async def list_hosts(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    order: str = Query("desc"),
    role: str | None = Query(None),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    q = select(Host).where(Host.job_id == job_id)
    if role:
        q = q.where(Host.role == role)

    items, page = paginate(db, q, Host.conn_count, Host.id, cursor, limit, order)
    return HostListResponse(
        items=[_host_to_list_item(h) for h in items],
        page=page,
    )


@router.get("/jobs/{job_id}/hosts/{ip}", response_model=HostGetResponse)
async def get_host(
    job_id: str,
    ip: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    h = _require_host(db, job_id, ip)

    # Build DNS summary
    dns_count = db.scalar(
        select(func.count()).select_from(DnsQuery).where(
            DnsQuery.job_id == job_id, DnsQuery.host_ip == ip
        )
    )
    top_qnames = [r[0] for r in db.execute(
        select(DnsQuery.query)
        .where(DnsQuery.job_id == job_id, DnsQuery.host_ip == ip)
        .group_by(DnsQuery.query)
        .order_by(func.count().desc())
        .limit(10)
    ).all()]

    # Build TLS summary
    tls_count = db.scalar(
        select(func.count()).select_from(TlsSession).where(
            TlsSession.job_id == job_id, TlsSession.host_ip == ip
        )
    )
    top_sni = [r[0] for r in db.execute(
        select(TlsSession.sni)
        .where(TlsSession.job_id == job_id, TlsSession.host_ip == ip, TlsSession.sni.isnot(None))
        .group_by(TlsSession.sni)
        .order_by(func.count().desc())
        .limit(10)
    ).all()]
    top_ja3 = [r[0] for r in db.execute(
        select(TlsSession.ja3)
        .where(TlsSession.job_id == job_id, TlsSession.host_ip == ip, TlsSession.ja3.isnot(None))
        .group_by(TlsSession.ja3)
        .order_by(func.count().desc())
        .limit(10)
    ).all()]

    # Build Global Context
    gh = db.get(GlobalHost, ip)
    global_stats = {}
    global_history = []
    if gh:
        global_stats = {
            "job_count": gh.job_count,
            "total_alerts": gh.total_alerts,
            "total_findings": gh.total_findings,
        }
        global_history = json.loads(gh.history_json or "[]")

    detail = HostDetail(
        **_host_to_list_item(h).model_dump(),
        first_seen=h.first_seen,
        last_seen=h.last_seen,
        alerts_by_severity=json.loads(h.alerts_by_severity_json or "{}"),
        top_services=json.loads(h.top_services_json or "[]"),
        dns_summary=DnsSummary(query_count=dns_count, top_qnames=top_qnames),
        tls_summary=TlsSummary(
            session_count=tls_count, top_sni=top_sni, top_ja3=top_ja3
        ),
        global_stats=global_stats,
        global_history=global_history,
    )
    return HostGetResponse(host=detail)


# ---- Host sub-resource endpoints ----

@router.get("/jobs/{job_id}/hosts/{ip}/connections", response_model=ConnectionListResponse)
async def host_connections(
    job_id: str, ip: str, response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    _require_job(db, job_id)
    _require_host(db, job_id, ip)
    response.headers["X-Request-Id"] = request_id

    q = select(Connection).where(Connection.job_id == job_id, Connection.host_ip == ip)
    items, page = paginate(db, q, Connection.ts, Connection.id, cursor, limit)
    return ConnectionListResponse(
        items=[ConnectionItem.model_validate(c) for c in items],
        page=page,
    )


@router.get("/jobs/{job_id}/hosts/{ip}/dns", response_model=DnsQueryListResponse)
async def host_dns(
    job_id: str, ip: str, response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    _require_job(db, job_id)
    _require_host(db, job_id, ip)
    response.headers["X-Request-Id"] = request_id

    q = select(DnsQuery).where(DnsQuery.job_id == job_id, DnsQuery.host_ip == ip)
    items, page = paginate(db, q, DnsQuery.ts, DnsQuery.id, cursor, limit)
    return DnsQueryListResponse(
        items=[DnsQueryItem.model_validate(d) for d in items],
        page=page,
    )


@router.get("/jobs/{job_id}/hosts/{ip}/tls", response_model=TlsSessionListResponse)
async def host_tls(
    job_id: str, ip: str, response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    _require_job(db, job_id)
    _require_host(db, job_id, ip)
    response.headers["X-Request-Id"] = request_id

    q = select(TlsSession).where(TlsSession.job_id == job_id, TlsSession.host_ip == ip)
    items, page = paginate(db, q, TlsSession.ts, TlsSession.id, cursor, limit)
    return TlsSessionListResponse(
        items=[TlsSessionItem.model_validate(t) for t in items],
        page=page,
    )


@router.get("/jobs/{job_id}/hosts/{ip}/alerts", response_model=AlertListResponse)
async def host_alerts(
    job_id: str, ip: str, response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    _require_job(db, job_id)
    _require_host(db, job_id, ip)
    response.headers["X-Request-Id"] = request_id

    q = select(Alert).where(Alert.job_id == job_id, Alert.host_ip == ip)
    items, page = paginate(db, q, Alert.ts, Alert.id, cursor, limit)
    return AlertListResponse(
        items=[AlertItem.model_validate(a) for a in items],
        page=page,
    )


@router.get("/jobs/{job_id}/hosts/{ip}/files", response_model=FileListResponse)
async def host_files(
    job_id: str, ip: str, response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    _require_job(db, job_id)
    _require_host(db, job_id, ip)
    response.headers["X-Request-Id"] = request_id

    q = select(File).where(File.job_id == job_id, File.host_ip == ip)
    items, page = paginate(db, q, File.id, File.id, cursor, limit)
    return FileListResponse(
        items=[FileItem.model_validate(f) for f in items],
        page=page,
    )


# ---- Global Host endpoints (cross-job forensics) ----


def _gh_to_list_item(gh: GlobalHost) -> GlobalHostListItem:
    return GlobalHostListItem(
        ip=gh.ip,
        hostname=gh.hostname,
        first_seen=gh.first_seen,
        last_seen=gh.last_seen,
        job_count=gh.job_count or 0,
        total_alerts=gh.total_alerts or 0,
        total_findings=gh.total_findings or 0,
        seen_as_internal=gh.seen_as_internal or False,
        roles=_safe_json_list(gh.roles_json),
    )


@router.get("/hosts", response_model=GlobalHostListResponse)
async def list_global_hosts(
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    order: str = Query("desc"),
    internal_only: bool | None = Query(None),
):
    """List all known hosts across all jobs."""
    response.headers["X-Request-Id"] = request_id

    q = select(GlobalHost)
    if internal_only is True:
        q = q.where(GlobalHost.seen_as_internal == True)  # noqa: E712
    elif internal_only is False:
        q = q.where(GlobalHost.seen_as_internal == False)  # noqa: E712

    items, page = paginate(db, q, GlobalHost.job_count, GlobalHost.ip, cursor, limit, order)
    return GlobalHostListResponse(
        items=[_gh_to_list_item(gh) for gh in items],
        page=page,
    )


@router.get("/hosts/{ip}", response_model=GlobalHostGetResponse)
async def get_global_host(
    ip: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Get global host detail with cross-job history."""
    response.headers["X-Request-Id"] = request_id
    gh = db.get(GlobalHost, ip)
    if not gh:
        raise HTTPException(status_code=404, detail="Global host not found")

    detail = GlobalHostDetail(
        **_gh_to_list_item(gh).model_dump(),
        history=_safe_json_list(gh.history_json),
    )
    return GlobalHostGetResponse(host=detail)
