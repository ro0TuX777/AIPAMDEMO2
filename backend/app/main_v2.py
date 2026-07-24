"""
AIPAM V2 FastAPI application factory.

Creates the app with:
  - /api/v1 prefix on all routers
  - Bearer-token auth (via deps.verify_token)
  - X-Request-Id middleware
  - CORS disabled (single-VM deployment)
"""

import uuid
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles

from backend.app.api import (
    alerts,
    artifacts,
    binary,
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

    # Also ensure the V1 SettingsDB table exists — it lives in the same SQLite
    # file but is declared via SQLModel, so init_v2_db() does not create it.
    try:
        from sqlmodel import SQLModel
        from backend.app.database import engine
        from backend.app import db_models  # noqa: F401  ensure metadata registered
        SQLModel.metadata.create_all(engine, tables=[db_models.SettingsDB.__table__])
    except Exception:
        pass

    app = FastAPI(
        title="AIPAM API",
        version=_APP_VERSION,
        # Swagger UI is served by a custom route below using locally-vendored
        # assets so /api/v1/docs renders on an air-gapped host (no CDN access).
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
    )

    # --- Self-hosted Swagger UI (air-gapped) ---
    # FastAPI's default docs page pulls swagger-ui-bundle.js / swagger-ui.css from
    # a public CDN, which is unreachable on the offline VM (the page loads as a
    # blank shell). We mount the vendored assets and point the docs page at them.
    _static_dir = Path(__file__).resolve().parent / "static"
    if _static_dir.is_dir():
        app.mount("/api/v1/static", StaticFiles(directory=str(_static_dir)), name="static")

    @app.get("/api/v1/docs", include_in_schema=False)
    async def custom_swagger_ui_html():  # noqa: ANN202
        return get_swagger_ui_html(
            openapi_url=app.openapi_url,
            title=f"{app.title} — Swagger UI",
            swagger_js_url="/api/v1/static/swagger/swagger-ui-bundle.js",
            swagger_css_url="/api/v1/static/swagger/swagger-ui.css",
            swagger_favicon_url="/api/v1/static/swagger/favicon-32x32.png",
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
    app.include_router(binary.router, prefix="/api/v1")

    from backend.app.api import admin, correlation
    app.include_router(admin.router, prefix="/api/v1")
    app.include_router(correlation.router, prefix="/api/v1")

    # Training Intelligence routes (V1 — router already has /api/v1/training prefix)
    from backend.app.training_routes import router as training_router
    app.include_router(training_router)

    return app

