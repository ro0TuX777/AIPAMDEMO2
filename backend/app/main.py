from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import database
from .db_models import JobDB, JobResultDB, JobStepDB, SettingsDB
from .models import JobStatus, JobStepStatus
from .schemas import (
    ArkimeJobRequest,
    CreateJobResponse,
    JobResultResponse,
    JobStatusResponse,
    SecurityOnionJobRequest,
    Settings,
    TrafficLLMClassifyRequest,
    TrafficLLMClassifyResponse,
    TrafficLLMBatchClassifyRequest,
    TrafficLLMBatchClassifyResponse,
    TrafficLLMStatusResponse,
    ChatRequest,
    ChatResponse,
)
from .schemas_effective import EffectiveSettingsResponse
from .database import get_session
from .llm_client import LLMClient, LLMConfig, classify_traffic_with_trafficllm
from .chat_service import generate_chat_response
from .settings_runtime import get_effective_settings
import os
import shutil
from pathlib import Path

app = FastAPI(title="AIPAM API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://localhost:5175", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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


@app.on_event("startup")
async def on_startup() -> None:
    # Ensure storage and reports directories exist, using the same
    # resolution logic as the worker. Initialize the database first so
    # the SettingsDB table exists before we attempt to read from it.
    database.init_db()
    effective = get_effective_settings()
    base_dir = effective.file_storage_path
    base_dir.mkdir(parents=True, exist_ok=True)
    effective.reports_path.mkdir(parents=True, exist_ok=True)


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



@app.get("/api/v1/admin/effective_settings", response_model=EffectiveSettingsResponse)
async def get_effective_settings_admin() -> EffectiveSettingsResponse:
    """Return the effective runtime settings the worker will use.

    Paths are serialized as strings for easier consumption by operators.
    """

    eff = get_effective_settings()
    return EffectiveSettingsResponse(
        llm_endpoint=eff.llm_endpoint,
        llm_model_name=eff.llm_model_name,
        llm_max_tokens=eff.llm_max_tokens,
        llm_temperature=eff.llm_temperature,
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

