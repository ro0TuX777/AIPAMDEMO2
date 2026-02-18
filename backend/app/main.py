from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import database
from .db_models import JobDB, JobResultDB, JobStepDB, SettingsDB, FindingDB, EvidenceDB
from .models import JobStatus, JobStepStatus
from .schemas import (
    ArkimeJobRequest,
    AvailableModelsResponse,
    CreateJobResponse,
    JobResultResponse,
    JobStatusResponse,
    OllamaModelInfo,
    SecurityOnionJobRequest,
    Settings,
    SetupStatusResponse,
    TrafficLLMClassifyRequest,
    TrafficLLMClassifyResponse,
    TrafficLLMBatchClassifyRequest,
    TrafficLLMBatchClassifyResponse,
    TrafficLLMStatusResponse,
    ChatRequest,
    ChatResponse,
    FindingVerifyRequest,
    FindingResponse,
    CorrelationGroupResponse,
    ExportRuleResponse,
    MitreStatusResponse,
    MitreStatusItem,
    MitreTechniqueResponse,
    VALID_ANALYST_STATUSES,
)
from .schemas_effective import EffectiveSettingsResponse
from .database import get_session
from .llm_client import LLMClient, LLMConfig, classify_traffic_with_trafficllm
from .chat_service import generate_chat_response
from .settings_runtime import get_effective_settings
from .logging_config import configure_logging, get_logger, set_log_context
import os
import shutil
from pathlib import Path

configure_logging(component="api")
logger = get_logger(__name__)


def _get_bzar_techniques(session, job_id: str) -> set[str]:
    result_row = session.get(JobResultDB, job_id)
    if not result_row or not isinstance(result_row.result, dict):
        return set()
    raw = result_row.result.get("raw", {})
    if not isinstance(raw, dict):
        return set()
    bzar = raw.get("bzar") or {}
    if not isinstance(bzar, dict):
        return set()
    return set(bzar.get("technique_ids", []) or [])

@asynccontextmanager
async def lifespan(_: FastAPI):
    # Ensure storage and reports directories exist, using the same
    # resolution logic as the worker. Initialize the database first so
    # the SettingsDB table exists before we attempt to read from it.
    database.init_db()
    effective = get_effective_settings()
    base_dir = effective.file_storage_path
    base_dir.mkdir(parents=True, exist_ok=True)
    effective.reports_path.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title="AIPAM API", version="0.1.0", lifespan=lifespan)

# Training Intelligence routes (Phase 6 dashboard)
from .training_routes import router as training_router
app.include_router(training_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://localhost:5175", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request, call_next):
    import time
    job_id = None
    try:
        job_id = request.path_params.get("job_id")
    except Exception:
        job_id = None
    set_log_context(job_id=job_id, step="api")
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "API request failed",
            extra={"method": request.method, "path": request.url.path},
        )
        raise
    duration_ms = (time.perf_counter() - start) * 1000.0
    logger.info(
        "API request completed",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_ms": round(duration_ms, 2),
        },
    )
    return response

# Mount reports directory if it exists; this uses the same logic as the
# worker so operators can rely on a single source of truth.
try:
    _effective_for_mount = get_effective_settings()
    if _effective_for_mount.reports_path.exists():
        app.mount("/reports", StaticFiles(directory=_effective_for_mount.reports_path), name="reports")
except Exception:
    # On first boot the DB or settings row may not exist yet; mounting is
    # best-effort only and will be retried logically on the next process
    # restart after settings are initialized.
    pass


@app.get("/healthz")
async def healthz():  # type: ignore[valid-type]
    return {"status": "ok"}


@app.get("/api/v1/jobs", response_model=list[JobStatusResponse])
async def list_jobs() -> list[JobStatusResponse]:
    from sqlmodel import select

    with get_session() as session:
        # Sort by created_at desc
        jobs = session.exec(select(JobDB).order_by(JobDB.created_at.desc())).all()

        # For each job, fetch steps (this is N+1 but acceptable for low volume v1)
        responses = []
        for job in jobs:
            steps = session.exec(select(JobStepDB).where(JobStepDB.job_id == job.id)).all()
            step_schemas = [
                {
                    "name": s.name,
                    "status": s.status,
                    "message": s.message,
                }
                for s in steps
            ]
            responses.append(
                JobStatusResponse(
                    job_id=job.id,
                    status=job.status,
                    created_at=job.created_at,
                    updated_at=job.updated_at,
                    steps=step_schemas, # type: ignore[arg-type]
                    error_message=job.error_message,
                )
            )

    return responses


@app.post("/api/v1/jobs", response_model=CreateJobResponse, status_code=201)
async def create_job_upload(
    mode: str = Form(...),
    metadata: str | None = Form(None),
    pcap_files: list[UploadFile] = File(...),
) -> CreateJobResponse:
    # NOTE: Stub implementation – full pipeline wiring will be added next.
    if not pcap_files:
        raise HTTPException(status_code=400, detail="pcap_files are required")
    if mode not in {"single_window", "baseline_vs_exploit"}:
        raise HTTPException(status_code=400, detail="invalid mode")

    from uuid import uuid4
    from datetime import datetime, timezone
    import json

    job_id = str(uuid4())
    now = datetime.now(timezone.utc)

    # Create storage directory for this job, honoring persisted settings when present.
    effective = get_effective_settings()
    job_dir = effective.file_storage_path / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    saved_files = []
    for file in pcap_files:
        file_path = job_dir / (file.filename or "unknown.pcap")
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        saved_files.append(str(file_path))

    # Update metadata with file paths
    parsed_metadata = {}
    if metadata:
        try:
            parsed_metadata = json.loads(metadata)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="invalid metadata JSON")

    parsed_metadata["pcap_paths"] = saved_files

    with get_session() as session:
        job = JobDB(
            id=job_id,
            source="upload",
            mode=mode,
            exercise_id=parsed_metadata.get("exercise_id"),
            created_at=now,
            updated_at=now,
            status=JobStatus.QUEUED,
            job_metadata=parsed_metadata,
            error_message=None,
        )
        session.add(job)

        # Initialize steps
        steps = ["ingest", "parse", "aggregate", "llm_analysis", "report"]
        for step_name in steps:
            step = JobStepDB(
                id=f"{job_id}:{step_name}",
                job_id=job_id,
                name=step_name,
                status=JobStepStatus.PENDING,
            )
            session.add(step)

        session.commit()

    # Trigger pipeline (lazy import to avoid circular imports at startup)
    from .tasks import run_pipeline

    run_pipeline.delay(job_id)

    return CreateJobResponse(job_id=job_id, status=JobStatus.QUEUED)


@app.post("/api/v1/jobs/from_security_onion", response_model=CreateJobResponse, status_code=201)
async def create_job_from_security_onion(body: SecurityOnionJobRequest) -> CreateJobResponse:
    from uuid import uuid4
    from datetime import datetime, timezone

    if body.mode not in {"single_window", "baseline_vs_exploit"}:
        raise HTTPException(status_code=400, detail="invalid mode")

    job_id = str(uuid4())
    now = datetime.now(timezone.utc)

    with get_session() as session:
        job = JobDB(
            id=job_id,
            source="security_onion",
            mode=body.mode,
            exercise_id=body.metadata.get("exercise_id") if body.metadata else None,
            created_at=now,
            updated_at=now,
            status=JobStatus.QUEUED,
            job_metadata=body.model_dump(),
            error_message=None,
        )
        session.add(job)

        # Initialize steps
        steps = ["ingest", "parse", "aggregate", "llm_analysis", "report"]
        for step_name in steps:
            step = JobStepDB(
                id=f"{job_id}:{step_name}",
                job_id=job_id,
                name=step_name,
                status=JobStepStatus.PENDING,
            )
            session.add(step)

        session.commit()

    # Trigger pipeline (lazy import to avoid circular imports at startup)
    from .tasks import run_pipeline

    run_pipeline.delay(job_id)

    return CreateJobResponse(job_id=job_id, status=JobStatus.QUEUED)


@app.post("/api/v1/jobs/from_arkime", response_model=CreateJobResponse, status_code=201)
async def create_job_from_arkime(body: ArkimeJobRequest) -> CreateJobResponse:
    from uuid import uuid4
    from datetime import datetime, timezone

    if body.mode not in {"single_window", "baseline_vs_exploit"}:
        raise HTTPException(status_code=400, detail="invalid mode")

    job_id = str(uuid4())
    now = datetime.now(timezone.utc)

    with get_session() as session:
        job = JobDB(
            id=job_id,
            source="arkime",
            mode=body.mode,
            exercise_id=body.metadata.get("exercise_id") if body.metadata else None,
            created_at=now,
            updated_at=now,
            status=JobStatus.QUEUED,
            job_metadata=body.model_dump(),
            error_message=None,
        )
        session.add(job)

        # Initialize steps
        steps = ["ingest", "parse", "aggregate", "llm_analysis", "report"]
        for step_name in steps:
            step = JobStepDB(
                id=f"{job_id}:{step_name}",
                job_id=job_id,
                name=step_name,
                status=JobStepStatus.PENDING,
            )
            session.add(step)

        session.commit()

    # Trigger pipeline (lazy import to avoid circular imports at startup)
    from .tasks import run_pipeline

    run_pipeline.delay(job_id)

    return CreateJobResponse(job_id=job_id, status=JobStatus.QUEUED)


@app.get("/api/v1/settings", response_model=Settings)
async def get_settings() -> Settings:
    with get_session() as session:
        settings = session.get(SettingsDB, 1)
        if not settings:
            # Return empty/default settings – caller can fill and PUT later.
            return Settings()
        # Coerce stored dict into Settings schema (extra keys ignored by default)
        return Settings(**settings.values)


@app.put("/api/v1/settings", response_model=Settings)
async def put_settings(body: Settings) -> Settings:
    # Basic validation hook: restrict known enum-like fields
    if body.security_onion_mode and body.security_onion_mode not in {"filesystem", "api"}:
        raise HTTPException(status_code=400, detail="invalid security_onion_mode")

    with get_session() as session:
        settings = session.get(SettingsDB, 1)
        if not settings:
            settings = SettingsDB(id=1, values={})
            session.add(settings)

        # Persist only non-null fields; leave others as-is
        current = dict(settings.values or {})
        update_data = {k: v for k, v in body.model_dump().items() if v is not None}
        current.update(update_data)
        settings.values = current
        session.add(settings)
        session.commit()
        session.refresh(settings)

        # Sync model role assignments to models.conf so SmartModelSelector
        # picks them up automatically on its next reload.
        model_conf_updates = {}
        if body.forensic_model_name:
            model_conf_updates["forensic_model"] = body.forensic_model_name
            model_conf_updates["classification_model"] = body.forensic_model_name
        if body.general_model_name:
            model_conf_updates["general_model"] = body.general_model_name
        if model_conf_updates:
            try:
                from .core_engines.config.model_config_manager import get_model_config_manager
                mgr = get_model_config_manager()
                mgr.save_config(model_conf_updates)
                # Reload the SmartModelSelector so it picks up new config
                try:
                    from .core_engines.selection.smart_model_selector import get_model_selector
                    get_model_selector().reload_config()
                except Exception:
                    pass  # Non-critical
            except Exception as exc:
                import logging
                logging.getLogger(__name__).warning("Failed to sync models.conf: %s", exc)

        return Settings(**settings.values)


@app.post("/api/v1/settings/test_llm")
async def test_llm_connection(body: Settings) -> dict:
    """Lightweight LLM connectivity check.

    Uses provided settings (if present) or falls back to the same effective
    resolution logic used by the worker.
    """

    # Start from effective settings so we respect any persisted configuration.
    effective = get_effective_settings()

    endpoint = body.llm_endpoint or effective.llm_endpoint
    model = body.llm_model_name or effective.llm_model_name
    temperature = body.llm_temperature or effective.llm_temperature
    max_tokens = body.llm_max_tokens or effective.llm_max_tokens

    config = LLMConfig(
        endpoint=endpoint,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
    )

    client = LLMClient(config=config)

    try:
        # Single empty bundle is enough to validate connectivity and auth.
        await client.analyze_chunk({})
        return {"ok": True}
    except Exception as exc:  # pragma: no cover - extreme edge
        return {"ok": False, "error": str(exc)}



@app.get("/api/v1/settings/setup_status", response_model=SetupStatusResponse)
async def get_setup_status() -> SetupStatusResponse:
    """Check whether a model has been configured (first-boot check).

    The frontend calls this on load to decide whether to show the
    model-selection modal.
    """
    with get_session() as session:
        row = session.get(SettingsDB, 1)
        if not row or not row.values:
            return SetupStatusResponse(model_configured=False, llm_model_name=None)
        vals = row.values
        configured = bool(vals.get("model_configured", False))
        model = vals.get("llm_model_name") or None
        return SetupStatusResponse(model_configured=configured, llm_model_name=model)


@app.get("/api/v1/models/available", response_model=AvailableModelsResponse)
async def get_available_models() -> AvailableModelsResponse:
    """List LLM models available in the local Ollama instance.

    Tries multiple URL sources to be deployment-agnostic (bare metal, Docker,
    any OS).  Priority:
      1. User-configured LLM endpoint from saved settings (strip path suffix)
      2. LLM_ENDPOINT / OLLAMA_HOST environment variables
      3. models.conf api_url
      4. Common defaults (localhost, host.docker.internal)
    """
    import httpx
    import logging
    log = logging.getLogger(__name__)

    # -- Build ordered list of candidate base URLs --------------------------
    candidate_urls: list[str] = []

    # 1. From user-saved settings
    try:
        with get_session() as session:
            settings = session.get(SettingsDB, 1)
            if settings and settings.values:
                ep = settings.values.get("llm_endpoint", "")
                if ep:
                    # Strip common path suffixes to get the Ollama base URL
                    for suffix in ("/v1/chat/completions", "/v1", "/api"):
                        if ep.rstrip("/").endswith(suffix):
                            ep = ep.rstrip("/")[: -len(suffix)]
                            break
                    candidate_urls.append(ep.rstrip("/"))
    except Exception:
        pass

    # 2. From environment variables (works in Docker, bare metal, any OS)
    for env_key in ("LLM_ENDPOINT", "OLLAMA_HOST"):
        env_val = os.environ.get(env_key, "")
        if env_val:
            base = env_val
            for suffix in ("/v1/chat/completions", "/v1", "/api"):
                if base.rstrip("/").endswith(suffix):
                    base = base.rstrip("/")[: -len(suffix)]
                    break
            candidate_urls.append(base.rstrip("/"))

    # 3. From models.conf
    try:
        from .core_engines.config.model_config_manager import get_model_config_manager
        conf = get_model_config_manager().load_config()
        conf_url = conf.get("api_url", "")
        if conf_url:
            candidate_urls.append(conf_url.rstrip("/"))
    except Exception:
        pass

    # 4. Common defaults
    candidate_urls.extend([
        "http://localhost:11434",
        "http://host.docker.internal:11434",
        "http://127.0.0.1:11434",
    ])

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_urls: list[str] = []
    for u in candidate_urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    # -- Try each URL until one succeeds ------------------------------------
    for base_url in unique_urls:
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{base_url}/api/tags")
            if resp.status_code != 200:
                continue
            data = resp.json()
            raw_models = data.get("models", [])
            models = [
                OllamaModelInfo(
                    name=m.get("name", ""),
                    size=m.get("size", 0),
                    family=m.get("details", {}).get("family", "Unknown"),
                    parameter_size=m.get("details", {}).get("parameter_size", "N/A"),
                    quantization=m.get("details", {}).get("quantization_level", "Unknown"),
                )
                for m in raw_models
            ]
            log.info("Found %d models from Ollama at %s", len(models), base_url)
            return AvailableModelsResponse(models=models)
        except Exception:
            continue

    log.warning("Could not reach Ollama at any of: %s", unique_urls)
    return AvailableModelsResponse(models=[])


@app.get("/api/v1/admin/effective_settings", response_model=EffectiveSettingsResponse)
async def get_effective_settings_admin() -> EffectiveSettingsResponse:
    """Return the effective runtime settings the worker will use.

    Paths are serialized as strings for easier consumption by operators.
    """

    eff = get_effective_settings()

    # Resolve model role names from models.conf
    forensic_model = None
    general_model = None
    try:
        from .core_engines.config.model_config_manager import get_model_config_manager
        conf = get_model_config_manager().load_config()
        forensic_model = conf.get("forensic_model")
        general_model = conf.get("general_model")
    except Exception:
        pass

    return EffectiveSettingsResponse(
        llm_endpoint=eff.llm_endpoint,
        llm_model_name=eff.llm_model_name,
        llm_max_tokens=eff.llm_max_tokens,
        llm_temperature=eff.llm_temperature,
        forensic_model_name=forensic_model,
        general_model_name=general_model,
        file_storage_path=str(eff.file_storage_path),
        reports_path=str(eff.reports_path),
        security_onion_mode=eff.security_onion_mode,
        security_onion_base_pcap_path=str(eff.security_onion_base_pcap_path),
        security_onion_zeek_log_path=str(eff.security_onion_zeek_log_path),
        security_onion_suricata_log_path=str(eff.security_onion_suricata_log_path),
        security_onion_api_url=eff.security_onion_api_url,
        security_onion_api_token=eff.security_onion_api_token,
        arkime_api_url=eff.arkime_api_url,
        arkime_api_username=eff.arkime_api_username,
        arkime_api_password=eff.arkime_api_password,
    )


@app.get("/api/v1/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str) -> JobStatusResponse:
    from sqlmodel import select

    with get_session() as session:
        job = session.get(JobDB, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job not found")

        steps = session.exec(select(JobStepDB).where(JobStepDB.job_id == job_id)).all()

    step_schemas = [
        {
            "name": s.name,
            "status": s.status,
            "message": s.message,
        }
        for s in steps
    ]

    return JobStatusResponse(
        job_id=job.id,
        status=job.status,
        created_at=job.created_at,
        updated_at=job.updated_at,
        steps=step_schemas,  # type: ignore[arg-type]
        error_message=job.error_message,
    )


@app.get("/api/v1/jobs/{job_id}/result", response_model=JobResultResponse)
async def get_job_result(job_id: str) -> JobResultResponse:
    from sqlmodel import select

    with get_session() as session:
        job = session.get(JobDB, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job not found")
        if job.status != JobStatus.COMPLETED:
            raise HTTPException(status_code=409, detail="job not yet completed")

        result_row = session.exec(
            select(JobResultDB).where(JobResultDB.job_id == job_id)
        ).one_or_none()

    if not result_row:
        raise HTTPException(status_code=500, detail="result missing for completed job")

    return JobResultResponse.model_validate(result_row.result)


@app.get("/api/v1/jobs/{job_id}/partial_result")
async def get_partial_result(job_id: str):
    """Return intermediate pipeline results available before LLM analysis completes.

    Includes: flow/alert counts, top alerts, host summaries, anomaly detection,
    and TrafficLLM classifications.  Returns 404 if not yet available.
    """
    from .partial_results import get_partial_result as _get

    with get_session() as session:
        job = session.get(JobDB, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job not found")

    data = _get(job_id)
    if data is None:
        raise HTTPException(status_code=404, detail="partial result not yet available")

    return data


@app.delete("/api/v1/jobs/{job_id}", status_code=204)
async def delete_job(job_id: str):
    """Delete a job and all associated data (results, files, RAG index).

    Only completed or failed jobs can be deleted.
    """
    from sqlmodel import select
    import shutil

    with get_session() as session:
        job = session.get(JobDB, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        # Only allow deletion of completed or failed jobs
        if job.status not in (JobStatus.COMPLETED, JobStatus.FAILED):
            raise HTTPException(
                status_code=409,
                detail=f"Cannot delete job with status '{job.status}'. Only completed or failed jobs can be deleted."
            )

        # Delete job result if exists
        result_row = session.exec(
            select(JobResultDB).where(JobResultDB.job_id == job_id)
        ).one_or_none()
        if result_row:
            session.delete(result_row)

        # Delete job steps
        from .db_models import JobStepDB
        steps = session.exec(
            select(JobStepDB).where(JobStepDB.job_id == job_id)
        ).all()
        for step in steps:
            session.delete(step)

        # Delete chat conversations and messages
        try:
            from .db_models import ChatConversationDB, ChatMessageDB
            conversations = session.exec(
                select(ChatConversationDB).where(ChatConversationDB.job_id == job_id)
            ).all()
            for conv in conversations:
                messages = session.exec(
                    select(ChatMessageDB).where(ChatMessageDB.conversation_id == conv.id)
                ).all()
                for msg in messages:
                    session.delete(msg)
                session.delete(conv)
        except Exception:
            pass  # Chat tables may not exist

        # Delete RAG index
        try:
            from .rag_index import delete_job_index
            delete_job_index(job_id)
        except Exception:
            pass  # RAG may not be available

        # Delete flow vector index
        try:
            from .flow_vectorstore import delete_flow_index
            delete_flow_index(job_id)
        except Exception:
            pass  # Flow vectorstore may not be available

        # Delete files from storage
        settings = get_effective_settings()
        job_storage_path = settings.file_storage_path / job_id
        if job_storage_path.exists():
            shutil.rmtree(job_storage_path)

        # Delete the job itself
        session.delete(job)
        session.commit()

    return None


# ============================================================================
# Chat API Endpoints (Phase 1: Interactive PCAP Chat)
# ============================================================================

@app.post("/api/v1/jobs/{job_id}/chat", response_model=ChatResponse)
async def chat_about_job(job_id: str, body: ChatRequest) -> ChatResponse:
    """Ask questions about a completed job's analysis findings.

    This endpoint allows analysts to have an interactive conversation
    about the findings from a PCAP analysis. The LLM uses the job's
    results as context to provide relevant, evidence-backed answers.

    Args:
        job_id: The job ID to ask questions about
        body: The chat request containing the user's message

    Returns:
        ChatResponse with the AI's answer and citations
    """
    from sqlmodel import select

    set_log_context(job_id=job_id, step="chat")
    logger.info(
        "Chat request received",
        extra={"conversation_id": body.conversation_id},
    )

    # Fetch the job and verify it's completed
    with get_session() as session:
        job = session.get(JobDB, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job not found")
        if job.status != JobStatus.COMPLETED:
            raise HTTPException(status_code=409, detail="job not yet completed")

        result_row = session.exec(
            select(JobResultDB).where(JobResultDB.job_id == job_id)
        ).one_or_none()

    if not result_row:
        raise HTTPException(status_code=500, detail="result missing for completed job")

    # Generate the chat response using the job result as context
    job_result = result_row.result
    response = await generate_chat_response(
        job_id=job_id,
        job_result=job_result,
        user_message=body.message,
        context_hint=body.context_hint,
        conversation_id=body.conversation_id,
        use_rag=True,
    )

    logger.info(
        "Chat response generated",
        extra={"conversation_id": response.conversation_id},
    )
    return response


@app.get("/api/v1/jobs/{job_id}/conversations")
async def list_job_conversations(job_id: str) -> list:
    """List all conversations for a job.

    Args:
        job_id: The job ID to get conversations for

    Returns:
        List of conversation summaries
    """
    from sqlmodel import select, func
    from .db_models import ConversationDB, ChatMessageDB
    from .schemas import ConversationSummary

    with get_session() as session:
        # Check job exists
        job = session.get(JobDB, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job not found")

        # Get conversations with message counts
        convs = session.exec(
            select(ConversationDB)
            .where(ConversationDB.job_id == job_id)
            .order_by(ConversationDB.updated_at.desc())
        ).all()

        result = []
        for conv in convs:
            msg_count = session.exec(
                select(func.count(ChatMessageDB.id))
                .where(ChatMessageDB.conversation_id == conv.id)
            ).one()
            result.append(ConversationSummary(
                id=conv.id,
                job_id=conv.job_id,
                created_at=conv.created_at,
                updated_at=conv.updated_at,
                title=conv.title,
                message_count=msg_count,
            ))

        return result


@app.get("/api/v1/jobs/{job_id}/conversations/{conversation_id}")
async def get_conversation_history(job_id: str, conversation_id: str):
    """Get the full message history for a conversation.

    Args:
        job_id: The job ID
        conversation_id: The conversation ID

    Returns:
        Full conversation with all messages
    """
    from sqlmodel import select
    from .db_models import ConversationDB, ChatMessageDB
    from .schemas import ConversationHistory, ChatMessage, ChatCitation

    with get_session() as session:
        # Get conversation
        conv = session.get(ConversationDB, conversation_id)
        if not conv or conv.job_id != job_id:
            raise HTTPException(status_code=404, detail="conversation not found")

        # Get messages
        messages = session.exec(
            select(ChatMessageDB)
            .where(ChatMessageDB.conversation_id == conversation_id)
            .order_by(ChatMessageDB.created_at.asc())
        ).all()

        chat_messages = []
        for msg in messages:
            citations = []
            if msg.citations and "items" in msg.citations:
                for c in msg.citations["items"]:
                    citations.append(ChatCitation(
                        type=c.get("type", ""),
                        id=c.get("id"),
                        snippet=c.get("snippet", ""),
                    ))
            chat_messages.append(ChatMessage(
                role=msg.role,
                content=msg.content,
                citations=citations,
                timestamp=msg.created_at,
            ))

        return ConversationHistory(
            id=conv.id,
            job_id=conv.job_id,
            messages=chat_messages,
            created_at=conv.created_at,
            updated_at=conv.updated_at,
        )


@app.post("/api/v1/jobs/{job_id}/simulation")
async def generate_simulation(job_id: str) -> JSONResponse:
    """Generate a Purple Team adversary emulation script from job findings.

    Returns the generated Python/Scapy script that replicates the
    detected network behaviors for security sensor testing.
    """
    from sqlmodel import select

    with get_session() as session:
        job = session.get(JobDB, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job not found")
        if job.status != JobStatus.COMPLETED:
            raise HTTPException(status_code=409, detail="job not yet completed")

        result_row = session.exec(
            select(JobResultDB).where(JobResultDB.job_id == job_id)
        ).one_or_none()

    if not result_row:
        raise HTTPException(status_code=500, detail="result missing for completed job")

    job_result = result_row.result

    # Build findings from job result
    findings = []

    # Extract from summary
    summary = job_result.get("summary", {})
    mitre_techniques = summary.get("mitre_techniques", [])
    key_findings = summary.get("key_findings", [])

    # Extract from forensic anomalies (SSIs)
    llm_raw = job_result.get("raw", {}).get("llm_analysis_raw", {})
    chunks = llm_raw.get("chunks", []) if isinstance(llm_raw, dict) else []

    for i, tech in enumerate(mitre_techniques):
        finding_desc = key_findings[i] if i < len(key_findings) else ""
        if isinstance(finding_desc, dict):
            finding_desc = finding_desc.get("description", str(finding_desc))

        findings.append({
            "mitre_technique_id": tech.get("id", "T0000"),
            "severity": summary.get("severity", "medium"),
            "classification": tech.get("name", ""),
            "description": str(finding_desc),
            "rationale": str(finding_desc),
            "raw_evidence_snippet": str(finding_desc)[:200],
            "affected_hosts": [h.get("ip", "") for h in job_result.get("hosts", [])[:3]],
            "requires_review": False,
        })

    # Add anomaly-based findings
    seen = set()
    for chunk in chunks:
        for anomaly in (chunk.get("anomalies") or []):
            desc = anomaly.get("description", "")
            if desc and desc not in seen:
                seen.add(desc)
                findings.append({
                    "mitre_technique_id": "T0000",
                    "severity": "medium",
                    "classification": "Behavioral Anomaly",
                    "description": desc,
                    "rationale": anomaly.get("reason", desc),
                    "raw_evidence_snippet": f"{desc}: {anomaly.get('reason', '')}",
                    "affected_hosts": anomaly.get("related_hosts", []),
                    "requires_review": False,
                })

    if not findings:
        raise HTTPException(status_code=404, detail="No findings available for simulation generation")

    # Generate script using simulate.traffic_pattern logic
    try:
        import importlib
        import tempfile
        from pathlib import Path

        dawn_link = Path(__file__).resolve().parents[2] / "DAWN" / "dawn" / "links" / "simulate.traffic_pattern"
        if str(dawn_link) not in sys.path:
            sys.path.insert(0, str(dawn_link))

        sim_module = importlib.import_module("run")

        # Build mock context
        sandbox_dir = Path(tempfile.mkdtemp(prefix="sim_"))
        findings_path = sandbox_dir / "findings.json"
        with open(findings_path, "w") as f:
            import json
            json.dump({"job_id": job_id, "findings": findings}, f)

        flow_path = sandbox_dir / "flow_ir.json"
        with open(flow_path, "w") as f:
            json.dump({"flows": []}, f)

        class _Sandbox:
            def __init__(self):
                self.artifacts = {}
            def publish(self, artifact, filename, obj, schema="json"):
                out = sandbox_dir / filename
                if schema == "text":
                    out.write_text(str(obj))
                else:
                    with open(out, "w") as fh:
                        json.dump(obj, fh, indent=2, default=str)
                self.artifacts[artifact] = {"path": str(out)}

        class _Ledger:
            def log_event(self, **kw): pass

        ctx = {
            "project_id": job_id,
            "pipeline_id": "api_simulation",
            "artifact_store": {
                "aipam.findings.reviewed": {"path": str(findings_path), "schema": "json"},
                "aipam.findings.ir": {"path": str(findings_path), "schema": "json"},
                "aipam.flow.ir": {"path": str(flow_path), "schema": "json"},
            },
            "sandbox": _Sandbox(),
            "ledger": _Ledger(),
            "run_id": f"api-{job_id[:8]}",
        }

        config = {"spec": {"config": {
            "model_name": "llama3.1:8b",
            "llm_endpoint": "http://localhost:11434",
            "safe_mode": True,
            "max_findings": 10,
        }}}

        result = sim_module.run(ctx, config)

        # Read generated script
        sim_artifact = ctx["sandbox"].artifacts.get("aipam.simulation.py")
        if sim_artifact:
            script_content = Path(sim_artifact["path"]).read_text()
            return JSONResponse({
                "status": "ok",
                "script": script_content,
                "filename": f"aipam_simulation_{job_id[:8]}.py",
                "simulations": result.get("metrics", {}).get("simulations", 0),
            })
        else:
            raise HTTPException(status_code=500, detail="Failed to generate simulation script")

    except Exception as e:
        logger.exception("Simulation generation failed")
        raise HTTPException(status_code=500, detail=f"Simulation generation failed: {str(e)}")


@app.post("/api/v1/jobs/{job_id}/reindex")
async def reindex_job(job_id: str) -> dict:
    """Rebuild the RAG index for a completed job.

    Use this endpoint to regenerate embeddings without re-running the full analysis.
    Useful after model updates or if the index was corrupted.

    Args:
        job_id: The job ID to reindex

    Returns:
        Status message with document count
    """
    from sqlmodel import select
    from .rag_index import index_job_result

    # Fetch the job and verify it's completed
    with get_session() as session:
        job = session.get(JobDB, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job not found")
        if job.status != JobStatus.COMPLETED:
            raise HTTPException(status_code=409, detail="job not yet completed")

        result_row = session.exec(
            select(JobResultDB).where(JobResultDB.job_id == job_id)
        ).one_or_none()

    if not result_row:
        raise HTTPException(status_code=500, detail="result missing for completed job")

    try:
        doc_count = index_job_result(job_id, result_row.result)
        return {
            "status": "success",
            "job_id": job_id,
            "documents_indexed": doc_count,
        }
    except Exception as e:
        logger.exception("Job reindex failed")
        raise HTTPException(status_code=500, detail=f"Indexing failed: {str(e)}")


# ============================================================================
# TrafficLLM API Endpoints
# ============================================================================

@app.get("/api/v1/trafficllm/status", response_model=TrafficLLMStatusResponse)
async def trafficllm_status() -> TrafficLLMStatusResponse:
    """Check if TrafficLLM is available and return its status."""
    import httpx

    effective = get_effective_settings()
    endpoint = getattr(effective, 'trafficllm_endpoint', None) or os.getenv(
        "TRAFFICLLM_ENDPOINT", "http://localhost:8001/v1/chat/completions"
    )

    # Try to connect to TrafficLLM
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Just check if the endpoint is reachable
            resp = await client.post(
                endpoint,
                json={
                    "model": "trafficllm",
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                }
            )
            available = resp.status_code == 200
    except Exception:
        available = False

    return TrafficLLMStatusResponse(
        available=available,
        endpoint=endpoint if available else None,
        supported_tasks=["MTD", "EVD", "TBD", "BND", "WAD", "AAD"],
    )


@app.post("/api/v1/trafficllm/classify", response_model=TrafficLLMClassifyResponse)
async def trafficllm_classify(body: TrafficLLMClassifyRequest) -> TrafficLLMClassifyResponse:
    """Classify a single packet using TrafficLLM.

    Supported tasks:
    - MTD: Malware Traffic Detection (Zeus, Cridex, Shifu, etc.)
    - EVD: Encrypted VPN Detection (skype, netflix, youtube, etc.)
    - TBD: Tor Behavior Detection (browsing, chat, file, etc.)
    - BND: Botnet Detection (normal, IRC, Neris, RBot, Virut)
    - WAD: Web Attack Detection (malicious/benign)
    - AAD: APT Attack Detection (abnormal/normal)
    """
    # Validate task
    valid_tasks = ["MTD", "EVD", "TBD", "BND", "WAD", "AAD"]
    if body.task.upper() not in valid_tasks:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid task '{body.task}'. Must be one of: {valid_tasks}"
        )

    effective = get_effective_settings()
    endpoint = getattr(effective, 'trafficllm_endpoint', None) or os.getenv(
        "TRAFFICLLM_ENDPOINT", "http://localhost:8001/v1/chat/completions"
    )

    result = await classify_traffic_with_trafficllm(
        packet_hex=body.packet_hex,
        task=body.task.upper(),
        trafficllm_endpoint=endpoint,
    )

    return TrafficLLMClassifyResponse(
        task=result["task"],
        classification=result["classification"],
        success=result["success"],
        error=result.get("error"),
    )


@app.post("/api/v1/trafficllm/classify/batch", response_model=TrafficLLMBatchClassifyResponse)
async def trafficllm_classify_batch(body: TrafficLLMBatchClassifyRequest) -> TrafficLLMBatchClassifyResponse:
    """Classify multiple packets using TrafficLLM.

    This is more efficient than making multiple single requests.
    """
    import asyncio

    effective = get_effective_settings()
    endpoint = getattr(effective, 'trafficllm_endpoint', None) or os.getenv(
        "TRAFFICLLM_ENDPOINT", "http://localhost:8001/v1/chat/completions"
    )

    # Process all packets concurrently
    tasks = [
        classify_traffic_with_trafficllm(
            packet_hex=req.packet_hex,
            task=req.task.upper(),
            trafficllm_endpoint=endpoint,
        )
        for req in body.packets
    ]

    results = await asyncio.gather(*tasks)

    responses = [
        TrafficLLMClassifyResponse(
            task=r["task"],
            classification=r["classification"],
            success=r["success"],
            error=r.get("error"),
        )
        for r in results
    ]

    successful = sum(1 for r in responses if r.success)

    return TrafficLLMBatchClassifyResponse(
        results=responses,
        total=len(responses),
        successful=successful,
    )


@app.post("/api/v1/settings/test_trafficllm")
async def test_trafficllm_connection(body: Settings) -> dict:
    """Test TrafficLLM connectivity.

    Uses provided settings (if present) or falls back to environment/defaults.
    """
    import httpx

    effective = get_effective_settings()
    endpoint = body.trafficllm_endpoint or getattr(effective, 'trafficllm_endpoint', None) or os.getenv(
        "TRAFFICLLM_ENDPOINT", "http://localhost:8001/v1/chat/completions"
    )

    try:
        # Test with a simple classification request
        result = await classify_traffic_with_trafficllm(
            packet_hex="45 00 00 3c",
            task="BND",  # Botnet detection - should return "normal" for simple packets
            trafficllm_endpoint=endpoint,
            timeout_seconds=30.0,
        )

        if result["success"]:
            return {
                "ok": True,
                "endpoint": endpoint,
                "test_result": result["classification"],
            }
        else:
            return {
                "ok": False,
                "error": result.get("error", "Unknown error"),
            }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ============================================================================
# Phase 3: Findings, Correlation & Export Endpoints
# ============================================================================

@app.get("/api/v1/jobs/{job_id}/findings", response_model=list[FindingResponse])
async def list_job_findings(job_id: str) -> list[FindingResponse]:
    """List all findings for a specific job."""
    from sqlmodel import select

    from .cti.lookup import enrich_findings

    with get_session() as session:
        job = session.get(JobDB, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job not found")

        finding_rows = session.exec(
            select(FindingDB)
            .where(FindingDB.job_id == job_id)
            .order_by(FindingDB.created_at.desc())
        ).all()
        findings = enrich_findings(session, finding_rows)
        bzar_techniques = _get_bzar_techniques(session, job_id)

        return [
            FindingResponse(
                id=f.get("id"),
                job_id=f.get("job_id"),
                mitre_technique_id=f.get("mitre_technique_id"),
                mitre_technique_name=f.get("mitre_technique_name"),
                mitre_description=f.get("mitre_description"),
                mitre_tactics=f.get("mitre_tactics") or [],
                mitre_version=f.get("mitre_version"),
                mitre_domain=f.get("mitre_domain"),
                mitre_deprecated=f.get("mitre_deprecated"),
                mitre_revoked=f.get("mitre_revoked"),
                mitre_is_subtechnique=f.get("mitre_is_subtechnique"),
                bzar_techniques=sorted(bzar_techniques),
                bzar_match=bool(bzar_techniques) and f.get("mitre_technique_id") in bzar_techniques,
                classification=f.get("classification"),
                severity=f.get("severity"),
                title=f.get("title"),
                description=f.get("description"),
                evidence=f.get("evidence") or {},
                affected_hosts=f.get("affected_hosts") or {},
                confidence=f.get("confidence") or 0.0,
                analyzer_source=f.get("analyzer_source"),
                attack_chain_stage=f.get("attack_chain_stage"),
                analyst_status=f.get("analyst_status") or "unverified",
                analyst_notes=f.get("analyst_notes"),
                created_at=f.get("created_at"),
            )
            for f in findings
        ]


@app.get("/api/v1/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str) -> FindingResponse:
    """Get a single finding by ID."""
    from .cti.lookup import enrich_findings

    with get_session() as session:
        f_row = session.get(FindingDB, finding_id)
        if not f_row:
            raise HTTPException(status_code=404, detail="finding not found")

        f = enrich_findings(session, [f_row])[0]
        bzar_techniques = _get_bzar_techniques(session, f_row.job_id)
        return FindingResponse(
            id=f.get("id"),
            job_id=f.get("job_id"),
            mitre_technique_id=f.get("mitre_technique_id"),
            mitre_technique_name=f.get("mitre_technique_name"),
            mitre_description=f.get("mitre_description"),
            mitre_tactics=f.get("mitre_tactics") or [],
            mitre_version=f.get("mitre_version"),
            mitre_domain=f.get("mitre_domain"),
            mitre_deprecated=f.get("mitre_deprecated"),
            mitre_revoked=f.get("mitre_revoked"),
            mitre_is_subtechnique=f.get("mitre_is_subtechnique"),
            bzar_techniques=sorted(bzar_techniques),
            bzar_match=bool(bzar_techniques) and f.get("mitre_technique_id") in bzar_techniques,
            classification=f.get("classification"),
            severity=f.get("severity"),
            title=f.get("title"),
            description=f.get("description"),
            evidence=f.get("evidence") or {},
            affected_hosts=f.get("affected_hosts") or {},
            confidence=f.get("confidence") or 0.0,
            analyzer_source=f.get("analyzer_source"),
            attack_chain_stage=f.get("attack_chain_stage"),
            analyst_status=f.get("analyst_status") or "unverified",
            analyst_notes=f.get("analyst_notes"),
            created_at=f.get("created_at"),
        )


@app.post("/api/v1/findings/{finding_id}/verify", response_model=FindingResponse)
async def verify_finding(finding_id: str, body: FindingVerifyRequest) -> FindingResponse:
    """Update the analyst verdict on a finding (confirm or reject)."""
    if body.status not in VALID_ANALYST_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{body.status}'. Must be one of: {sorted(VALID_ANALYST_STATUSES)}",
        )

    with get_session() as session:
        f = session.get(FindingDB, finding_id)
        if not f:
            raise HTTPException(status_code=404, detail="finding not found")

        f.analyst_status = body.status
        if body.notes is not None:
            f.analyst_notes = body.notes
        session.add(f)
        session.commit()
        session.refresh(f)

        from .cti.lookup import enrich_findings

        data = enrich_findings(session, [f])[0]
        bzar_techniques = _get_bzar_techniques(session, f.job_id)
        return FindingResponse(
            id=data.get("id"),
            job_id=data.get("job_id"),
            mitre_technique_id=data.get("mitre_technique_id"),
            mitre_technique_name=data.get("mitre_technique_name"),
            mitre_description=data.get("mitre_description"),
            mitre_tactics=data.get("mitre_tactics") or [],
            mitre_version=data.get("mitre_version"),
            mitre_domain=data.get("mitre_domain"),
            mitre_deprecated=data.get("mitre_deprecated"),
            mitre_revoked=data.get("mitre_revoked"),
            mitre_is_subtechnique=data.get("mitre_is_subtechnique"),
            bzar_techniques=sorted(bzar_techniques),
            bzar_match=bool(bzar_techniques) and data.get("mitre_technique_id") in bzar_techniques,
            classification=data.get("classification"),
            severity=data.get("severity"),
            title=data.get("title"),
            description=data.get("description"),
            evidence=data.get("evidence") or {},
            affected_hosts=data.get("affected_hosts") or {},
            confidence=data.get("confidence") or 0.0,
            analyzer_source=data.get("analyzer_source"),
            attack_chain_stage=data.get("attack_chain_stage"),
            analyst_status=data.get("analyst_status") or "unverified",
            analyst_notes=data.get("analyst_notes"),
            created_at=data.get("created_at"),
        )


@app.get("/api/v1/correlations", response_model=list[CorrelationGroupResponse])
async def get_correlations() -> list[CorrelationGroupResponse]:
    """Find cross-job correlation groups."""
    from .core.correlation import CampaignCorrelator

    with get_session() as session:
        groups = CampaignCorrelator.correlate(session)
        return [
            CorrelationGroupResponse(
                group_id=g.group_id,
                mitre_technique_id=g.mitre_technique_id,
                common_indicators=g.common_indicators,
                job_ids=g.job_ids,
                finding_ids=g.finding_ids,
                confidence=g.confidence,
            )
            for g in groups
        ]


# ============================================================================
# MITRE CTI Endpoints
# ============================================================================


@app.get("/api/v1/mitre/status", response_model=MitreStatusResponse)
async def get_mitre_status() -> MitreStatusResponse:
    """Return MITRE CTI bundle metadata for ingested domains."""
    from sqlmodel import select
    from .db_models import MitreCtiBundleDB

    with get_session() as session:
        rows = session.exec(select(MitreCtiBundleDB)).all()
        items = [
            MitreStatusItem(
                domain=row.domain,
                bundle_version=row.bundle_version,
                bundle_sha256=row.bundle_sha256,
                bundle_modified=row.bundle_modified,
                ingested_at=row.ingested_at,
                source_url=row.source_url,
            )
            for row in rows
        ]
        return MitreStatusResponse(items=items)


@app.get("/api/v1/mitre/techniques/{technique_id}", response_model=MitreTechniqueResponse)
async def get_mitre_technique(technique_id: str) -> MitreTechniqueResponse:
    """Get a MITRE technique (enterprise/mobile/ics)."""
    from .cti.lookup import get_technique

    with get_session() as session:
        row = get_technique(session, technique_id)
        if not row:
            raise HTTPException(status_code=404, detail="technique not found")

        return MitreTechniqueResponse(
            domain=row.domain,
            technique_id=row.technique_id,
            name=row.name,
            description=row.description,
            tactics=row.tactics or [],
            revoked=row.revoked,
            deprecated=row.deprecated,
            is_subtechnique=row.is_subtechnique,
            version=row.version,
            created_at=row.created_at,
            modified_at=row.modified_at,
            source_url=row.source_url,
            bundle_sha256=row.bundle_sha256,
            ingested_at=row.ingested_at,
        )


@app.get("/api/v1/jobs/{job_id}/correlations", response_model=list[CorrelationGroupResponse])
async def get_job_correlations(job_id: str) -> list[CorrelationGroupResponse]:
    """Find correlation groups involving a specific job."""
    from .core.correlation import CampaignCorrelator

    with get_session() as session:
        job = session.get(JobDB, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job not found")

        groups = CampaignCorrelator.correlate_for_job(session, job_id)
        return [
            CorrelationGroupResponse(
                group_id=g.group_id,
                mitre_technique_id=g.mitre_technique_id,
                common_indicators=g.common_indicators,
                job_ids=g.job_ids,
                finding_ids=g.finding_ids,
                confidence=g.confidence,
            )
            for g in groups
        ]


@app.post("/api/v1/findings/{finding_id}/export/suricata", response_model=ExportRuleResponse)
async def export_suricata_rule(finding_id: str) -> ExportRuleResponse:
    """Generate a Suricata IDS rule from a finding."""
    from sqlmodel import select
    from .core.exporters import SuricataExporter
    from .llm.providers.ollama import OllamaProvider

    effective = get_effective_settings()

    with get_session() as session:
        f = session.get(FindingDB, finding_id)
        if not f:
            raise HTTPException(status_code=404, detail="finding not found")

        # Gather evidence snippets
        evidence_rows = session.exec(
            select(EvidenceDB).where(EvidenceDB.finding_id == finding_id)
        ).all()
        snippets = [e.snippet for e in evidence_rows if e.snippet]
        set_log_context(job_id=f.job_id, step="export")
        logger.info("Export Suricata requested", extra={"finding_id": finding_id, "job_id": f.job_id})

    provider = OllamaProvider(
        endpoint=effective.llm_endpoint,
        model=effective.llm_model_name,
    )
    exporter = SuricataExporter(provider=provider)
    result = await exporter.generate(f, snippets)

    logger.info("Export Suricata completed", extra={"finding_id": finding_id, "job_id": f.job_id})
    return ExportRuleResponse(
        rule_type=result.rule_type,
        rule_text=result.rule_text,
        finding_id=result.finding_id,
        description=result.description,
    )


@app.post("/api/v1/findings/{finding_id}/export/sigma", response_model=ExportRuleResponse)
async def export_sigma_rule(finding_id: str) -> ExportRuleResponse:
    """Generate a Sigma detection rule from a finding."""
    from sqlmodel import select
    from .core.exporters import SigmaExporter
    from .llm.providers.ollama import OllamaProvider

    effective = get_effective_settings()

    with get_session() as session:
        f = session.get(FindingDB, finding_id)
        if not f:
            raise HTTPException(status_code=404, detail="finding not found")

        evidence_rows = session.exec(
            select(EvidenceDB).where(EvidenceDB.finding_id == finding_id)
        ).all()
        snippets = [e.snippet for e in evidence_rows if e.snippet]
        set_log_context(job_id=f.job_id, step="export")
        logger.info("Export Sigma requested", extra={"finding_id": finding_id, "job_id": f.job_id})

    provider = OllamaProvider(
        endpoint=effective.llm_endpoint,
        model=effective.llm_model_name,
    )
    exporter = SigmaExporter(provider=provider)
    result = await exporter.generate(f, snippets)

    logger.info("Export Sigma completed", extra={"finding_id": finding_id, "job_id": f.job_id})
    return ExportRuleResponse(
        rule_type=result.rule_type,
        rule_text=result.rule_text,
        finding_id=result.finding_id,
        description=result.description,
    )
