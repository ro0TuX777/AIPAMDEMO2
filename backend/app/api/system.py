"""
System endpoints.

GET /health        – health check
GET /system/config – static configuration
"""

import shutil

from fastapi import APIRouter, Depends, Response

from backend.app.api.deps import get_request_id, verify_token
from backend.app.api._state import get_uptime_seconds
from backend.app.config_v2 import Settings, get_settings
from backend.app.schemas.common import ExecutionProfile
from backend.app.schemas.system import (
    DefaultLimits,
    HealthResponse,
    SystemConfigResponse,
)

router = APIRouter(tags=["System"], dependencies=[Depends(verify_token)])


@router.get("/health", response_model=HealthResponse)
async def health_check(
    response: Response,
    request_id: str = Depends(get_request_id),
    settings: Settings = Depends(get_settings),
):
    """Health check: reports DB, Redis, docker, disk, ollama status."""
    import httpx
    from sqlalchemy import text
    from backend.app.database_v2 import get_engine
    try:
        from backend.app.worker import celery_app
    except ImportError:
        celery_app = None

    response.headers["X-Request-Id"] = request_id

    # Disk check
    try:
        total, used, free = shutil.disk_usage(str(settings.aipam_job_root))
        pct_used = int((used / total) * 100) if total else 100
        disk_ok = pct_used < settings.aipam_disk_critical_pct
    except Exception:
        disk_ok = False

    # DB Check (V2)
    db_ok = False
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            db_ok = True
    except Exception:
        pass

    # Redis Check (via Celery)
    redis_ok = False
    try:
        if celery_app:
            with celery_app.connection() as conn:
                conn.heartbeat_check(2.0)
                redis_ok = True
    except Exception:
        pass
        
    # Docker OK acts as a proxy for the worker containers running
    docker_ok = redis_ok

    # Ollama Check
    ollama_ok = False
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{settings.aipam_ollama_url}/api/tags")
            ollama_ok = resp.status_code == 200
    except Exception:
        pass

    overall = "ok" if (disk_ok and db_ok and redis_ok and ollama_ok) else "degraded"

    return HealthResponse(
        status=overall,
        uptime_seconds=get_uptime_seconds(),
        docker_ok=docker_ok,
        disk_ok=disk_ok,
        ollama_ok=ollama_ok,
        db_ok=db_ok,
        redis_ok=redis_ok,
    )


@router.get("/system/config", response_model=SystemConfigResponse)
async def system_config(
    response: Response,
    request_id: str = Depends(get_request_id),
    settings: Settings = Depends(get_settings),
):
    """Return static system configuration."""
    response.headers["X-Request-Id"] = request_id

    return SystemConfigResponse(
        aipam_version="2.0.0",
        max_upload_bytes=settings.aipam_max_job_disk_bytes,
        profiles_enabled=[
            ExecutionProfile.triage,
            ExecutionProfile.standard,
            ExecutionProfile.deep,
        ],
        default_limits=DefaultLimits(
            sensor_timeout_seconds=600,
            max_extracted_bytes=settings.aipam_max_extracted_bytes,
            max_job_disk_bytes=settings.aipam_max_job_disk_bytes,
        ),
    )

