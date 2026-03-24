"""
AIPAM V2 FastAPI application factory.

Creates the app with:
  - /api/v1 prefix on all routers
  - Bearer-token auth (via deps.verify_token)
  - X-Request-Id middleware
  - CORS disabled (single-VM deployment)
"""

import uuid

from fastapi import FastAPI, Request, Response

from backend.app.api import (
    alerts,
    artifacts,
    chat,
    findings,
    hosts,
    investigation,
    jobs,
    knowledge_base,
    proofs,
    rules,
    annotations,
    reports,
    slices,
    system,
    temporal,
    theories,
    uploads,
)
from backend.app.api._state import get_uptime_seconds  # noqa: F401
from backend.app.database_v2 import init_v2_db

_APP_VERSION = "2.0.0"


def create_app() -> FastAPI:
    """Build and return the AIPAM V2 FastAPI application."""

    # Ensure all V2 tables exist (idempotent — safe to call on every startup).
    # Wrapped in try/except so tests using in-memory SQLite are not affected.
    try:
        init_v2_db()
    except Exception:
        pass  # Tests override the DB; production DB dir may not exist yet

    app = FastAPI(
        title="AIPAM API",
        version=_APP_VERSION,
        docs_url="/api/v1/docs",
        openapi_url="/api/v1/openapi.json",
    )

    from fastapi.responses import JSONResponse
    from fastapi import HTTPException
    from backend.app.schemas.common import ErrorCode, SCHEMA_VERSION

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Global handler to ensure all HTTP errors follow the ErrorResponse schema."""
        detail = exc.detail
        if isinstance(detail, str):
            # Wrap plain string details into the structured format
            return JSONResponse(
                status_code=exc.status_code,
                headers=exc.headers,
                content={
                    "schema_version": SCHEMA_VERSION,
                    "error": detail,
                    "code": ErrorCode.ERR_PIPELINE_CRASH, # Default fallback
                    "details": None
                }
            )
        
        # If already structured (from raise_error), just add schema_version
        if isinstance(detail, dict):
            detail["schema_version"] = SCHEMA_VERSION
            return JSONResponse(status_code=exc.status_code, headers=exc.headers, content=detail)
            
        return JSONResponse(status_code=exc.status_code, headers=exc.headers, content={"error": str(detail)})

    # --- Middleware: X-Request-Id ---
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        request.state.request_id = rid
        response: Response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        return response

    # --- Routers ---
    app.include_router(uploads.router, prefix="/api/v1")
    app.include_router(jobs.router, prefix="/api/v1")
    app.include_router(jobs.sse_router, prefix="/api/v1")
    app.include_router(hosts.router, prefix="/api/v1")
    app.include_router(alerts.router, prefix="/api/v1")
    app.include_router(findings.router, prefix="/api/v1")
    app.include_router(artifacts.router, prefix="/api/v1")
    app.include_router(system.router, prefix="/api/v1")
    app.include_router(chat.router, prefix="/api/v1")
    app.include_router(knowledge_base.router, prefix="/api/v1")
    app.include_router(rules.router, prefix="/api/v1")
    app.include_router(theories.router, prefix="/api/v1")
    app.include_router(slices.router, prefix="/api/v1")
    app.include_router(annotations.router, prefix="/api/v1")
    app.include_router(reports.router, prefix="/api/v1")
    app.include_router(temporal.router, prefix="/api/v1")
    app.include_router(proofs.router, prefix="/api/v1")
    app.include_router(investigation.router, prefix="/api/v1")

    # Training Intelligence routes (V1 — router already has /api/v1/training prefix)
    from backend.app.training_routes import router as training_router
    app.include_router(training_router)

    return app

