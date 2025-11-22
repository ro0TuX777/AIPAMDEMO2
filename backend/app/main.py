from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import database
from .db_models import JobDB, JobResultDB, JobStepDB
from .models import JobStatus, JobStepStatus
from .schemas import (
    ArkimeJobRequest,
    CreateJobResponse,
    JobResultResponse,
    JobStatusResponse,
    SecurityOnionJobRequest,
)
from .database import get_session
from .config import FILE_STORAGE_PATH, REPORTS_PATH
import shutil
from pathlib import Path

app = FastAPI(title="AIPAM API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount reports directory if it exists; tests may import the app before startup
if Path(REPORTS_PATH).exists():
    app.mount("/reports", StaticFiles(directory=REPORTS_PATH), name="reports")


@app.on_event("startup")
async def on_startup() -> None:
    # Ensure storage and reports directories exist
    base_dir = Path(FILE_STORAGE_PATH)
    base_dir.mkdir(parents=True, exist_ok=True)
    Path(REPORTS_PATH).mkdir(parents=True, exist_ok=True)
    database.init_db()


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

    # Create storage directory for this job
    job_dir = Path(FILE_STORAGE_PATH) / job_id
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

