"""
System endpoints.

GET /health        – health check
GET /system/config – static configuration
"""

import os
import shutil

from fastapi import APIRouter, Depends, Response

from backend.app.api.deps import get_request_id, verify_token
from backend.app.api._state import (
    get_explain_latency_ms,
    get_explain_response_counts,
    get_uptime_seconds,
    reset_explain_response_counts,
)
from backend.app.config_v2 import Settings, get_settings
from backend.app.schemas.common import ExecutionProfile
from backend.app.schemas.system import (
    AvailableModelsResponse,
    DefaultLimits,
    ExplainConfiguration,
    ExplainTelemetryResponse,
    HealthResponse,
    LoadedModelInfo,
    OllamaGpuStatusResponse,
    OllamaModelInfo,
    SystemConfigResponse,
)

router = APIRouter(tags=["System"], dependencies=[Depends(verify_token)])


def _explain_llm_enabled() -> bool:
    return os.getenv("AIPAM_EXPLAIN_FINDING_USE_LLM", "").strip().lower() in {"1", "true", "yes", "on"}


def _build_explain_configuration(settings: Settings) -> ExplainConfiguration:
    ollama_base = settings.aipam_ollama_url.rstrip("/")
    llm_enabled = _explain_llm_enabled()
    return ExplainConfiguration(
        mode="llm" if llm_enabled else "deterministic",
        llm_enabled=llm_enabled,
        llm_model_name=os.getenv("LLM_MODEL_NAME", "aipam-trafficllm-v10"),
        llm_endpoint=os.getenv("LLM_ENDPOINT", f"{ollama_base}/v1/chat/completions"),
    )


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
        explain_configuration=_build_explain_configuration(settings),
    )


@router.get("/system/explain-telemetry", response_model=ExplainTelemetryResponse)
async def explain_telemetry(
    response: Response,
    request_id: str = Depends(get_request_id),
):
    """Return lightweight process-local explain response counters and latency summary."""
    response.headers["X-Request-Id"] = request_id
    return ExplainTelemetryResponse(
        explain_response_counts=get_explain_response_counts(),
        explain_latency_ms=get_explain_latency_ms(),
    )


@router.post("/system/explain-telemetry/reset", response_model=ExplainTelemetryResponse)
async def reset_explain_telemetry(
    response: Response,
    request_id: str = Depends(get_request_id),
):
    """Reset process-local explain response counters and latency summary."""
    response.headers["X-Request-Id"] = request_id
    reset_explain_response_counts()
    return ExplainTelemetryResponse(
        explain_response_counts=get_explain_response_counts(),
        explain_latency_ms=get_explain_latency_ms(),
    )


@router.get("/models/available", response_model=AvailableModelsResponse)
async def get_available_models(
    response: Response,
    request_id: str = Depends(get_request_id),
    settings: Settings = Depends(get_settings),
):
    """List LLM models available in the local Ollama instance.

    Tries multiple URL sources to be deployment-agnostic (bare metal, Docker,
    any OS).  Priority:
      1. AIPAM_OLLAMA_URL setting
      2. LLM_ENDPOINT / OLLAMA_HOST environment variables (strip path suffix)
      3. Common defaults (localhost, host.docker.internal)
    """
    import httpx
    import logging
    log = logging.getLogger(__name__)

    response.headers["X-Request-Id"] = request_id

    # -- Build ordered list of candidate base URLs --------------------------
    candidate_urls: list[str] = []

    # 1. From settings
    ollama_base = settings.aipam_ollama_url.rstrip("/")
    if ollama_base:
        candidate_urls.append(ollama_base)

    # 2. From environment variables
    for env_key in ("LLM_ENDPOINT", "OLLAMA_HOST"):
        env_val = os.environ.get(env_key, "")
        if env_val:
            base = env_val
            for suffix in ("/v1/chat/completions", "/v1", "/api"):
                if base.rstrip("/").endswith(suffix):
                    base = base.rstrip("/")[: -len(suffix)]
                    break
            candidate_urls.append(base.rstrip("/"))

    # 3. Common defaults
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
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{base_url}/api/tags")
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



@router.get("/system/ollama-status", response_model=OllamaGpuStatusResponse)
async def get_ollama_status(
    response: Response,
    request_id: str = Depends(get_request_id),
    settings: Settings = Depends(get_settings),
):
    """Return Ollama GPU / hardware utilisation status.

    Queries ``/api/ps`` (running models) and ``/api/version`` from the Ollama
    instance.  GPU detection is inferred from the ``size_vram`` field returned
    by ``/api/ps`` — if *any* loaded model has ``size_vram > 0`` the inference
    device is GPU.  The GPU name is extracted from Docker container logs (the
    Ollama startup log line ``using device CUDA0 (…)``).
    """
    import httpx
    import logging
    import re

    log = logging.getLogger(__name__)
    response.headers["X-Request-Id"] = request_id

    ollama_base = settings.aipam_ollama_url.rstrip("/")

    result = OllamaGpuStatusResponse()

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # --- Version ---------------------------------------------------
            try:
                ver_resp = await client.get(f"{ollama_base}/api/version")
                if ver_resp.status_code == 200:
                    result.ollama_version = ver_resp.json().get("version", "unknown")
            except Exception:
                pass

            # --- Running models (GPU detection) ----------------------------
            ps_resp = await client.get(f"{ollama_base}/api/ps")
            if ps_resp.status_code == 200:
                ps_data = ps_resp.json()
                raw_models = ps_data.get("models", [])
                total_vram = 0
                total_size = 0
                loaded: list[LoadedModelInfo] = []
                for m in raw_models:
                    sz = m.get("size", 0)
                    vram = m.get("size_vram", 0)
                    total_size += sz
                    total_vram += vram
                    pct = int(round(vram / sz * 100)) if sz else 0
                    details = m.get("details", {})
                    loaded.append(LoadedModelInfo(
                        name=m.get("name", ""),
                        size=sz,
                        size_vram=vram,
                        parameter_size=details.get("parameter_size", "N/A"),
                        quantization=details.get("quantization_level", "Unknown"),
                        family=details.get("family", "Unknown"),
                        context_length=m.get("context_length", 0),
                        gpu_offload_pct=pct,
                    ))
                result.loaded_models = loaded
                if total_vram > 0:
                    result.gpu_detected = True
                    result.compute_device = "CUDA"
                    result.vram_used_bytes = total_vram

            # --- GPU name from /proc/driver/nvidia/gpus/ --------------------
            # The nvidia driver exposes GPU info via procfs, which is available
            # to containers even without direct device access.
            try:
                from pathlib import Path
                nvidia_proc = Path("/proc/driver/nvidia/gpus")
                if nvidia_proc.exists():
                    for gpu_dir in nvidia_proc.iterdir():
                        info_file = gpu_dir / "information"
                        if info_file.exists():
                            info_text = info_file.read_text()
                            model_match = re.search(r"Model:\s*(.+)", info_text)
                            if model_match:
                                result.gpu_name = model_match.group(1).strip()
                                result.gpu_detected = True
                                result.compute_device = "CUDA"
                            break  # Take first GPU
            except Exception as e:
                log.debug("Could not read /proc/driver/nvidia for GPU info: %s", e)

            # --- VRAM total from Ollama /api/ps is not exposed, try nvidia-smi
            if result.gpu_detected and result.vram_total_bytes == 0:
                try:
                    import subprocess
                    nvsmi = subprocess.check_output(
                        ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
                        timeout=3,
                    ).decode().strip()
                    if nvsmi:
                        result.vram_total_bytes = int(float(nvsmi.split("\n")[0]) * 1024 * 1024)
                except Exception:
                    pass

    except Exception as e:
        log.warning("Failed to query Ollama status: %s", e)

    return result
