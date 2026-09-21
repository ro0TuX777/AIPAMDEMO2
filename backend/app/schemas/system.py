"""System schemas (openapi.yaml: BatchJobsRequest/Response, SystemConfigResponse, HealthResponse, JobSummaryResponse)."""

from typing import Literal

from pydantic import BaseModel

from backend.app.schemas.common import (
    SCHEMA_VERSION,
    ExecutionProfile,
    JobStatus,
)
from backend.app.schemas.host import HostListItem
from backend.app.schemas.ioc import IocItem, IocListResponse


class BatchJobsRequest(BaseModel):
    action: str  # cancel, delete, export_iocs
    job_ids: list[str]


class RejectedJob(BaseModel):
    job_id: str
    reason: str


class BatchJobsResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    accepted: list[str]
    rejected: list[RejectedJob]
    export_iocs: IocListResponse | None = None


class DefaultLimits(BaseModel):
    sensor_timeout_seconds: int | None = None
    max_extracted_bytes: int | None = None
    max_job_disk_bytes: int | None = None


class ExplainConfiguration(BaseModel):
    mode: Literal["deterministic", "llm"]
    llm_enabled: bool
    llm_model_name: str | None = None
    llm_endpoint: str | None = None


class SystemConfigResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    aipam_version: str
    max_upload_bytes: int
    profiles_enabled: list[ExecutionProfile]
    default_limits: DefaultLimits
    explain_configuration: ExplainConfiguration


class HealthResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    status: str  # ok, degraded
    uptime_seconds: int
    docker_ok: bool
    disk_ok: bool
    ollama_ok: bool
    db_ok: bool = True
    redis_ok: bool = True
    current_job_id: str | None = None
    last_job_id: str | None = None
    last_job_status: JobStatus | None = None


class ExplainTelemetryResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    explain_response_counts: dict[str, int]
    explain_latency_ms: "ExplainLatencySummary"


class ExplainLatencySummary(BaseModel):
    count: int = 0
    average_ms: int = 0
    min_ms: int = 0
    max_ms: int = 0
    last_ms: int = 0


class OllamaModelInfo(BaseModel):
    """Information about a model available in Ollama."""
    name: str
    size: int = 0
    family: str = "Unknown"
    parameter_size: str = "N/A"
    quantization: str = "Unknown"


class AvailableModelsResponse(BaseModel):
    """Response listing models available from Ollama."""
    schema_version: str = SCHEMA_VERSION
    models: list[OllamaModelInfo] = []


class EmbeddingModelInfo(BaseModel):
    """An Ollama model which may be selected after embedding validation."""

    name: str
    size: int = 0
    family: str = "Unknown"
    parameter_size: str = "N/A"
    quantization: str = "Unknown"


class EmbeddingModelsResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    models: list[EmbeddingModelInfo] = []


class EmbeddingModelConfigResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    model: str | None = None
    dimension: int | None = None
    collection_name: str | None = None


class EmbeddingModelSelectRequest(BaseModel):
    model: str


class EmbeddingModelPullRequest(BaseModel):
    model: str


class EmbeddingModelPullStatusResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    model: str
    status: str
    completed: int = 0
    total: int = 0
    error: str | None = None


class OllamaRuntimeConfigRequest(BaseModel):
    ollama_url: str


class OllamaRuntimeConfigResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    ollama_url: str


class LoadedModelInfo(BaseModel):
    """Information about a currently loaded model in Ollama."""
    name: str
    size: int = 0
    size_vram: int = 0
    parameter_size: str = "N/A"
    quantization: str = "Unknown"
    family: str = "Unknown"
    context_length: int = 0
    gpu_offload_pct: int = 0  # 0-100


class OllamaGpuStatusResponse(BaseModel):
    """GPU / hardware utilisation status from Ollama."""
    schema_version: str = SCHEMA_VERSION
    ollama_version: str = "unknown"
    gpu_detected: bool = False
    gpu_name: str | None = None
    vram_total_bytes: int = 0
    vram_used_bytes: int = 0
    compute_device: str = "CPU"  # "CPU" or "CUDA" or "ROCm" etc.
    loaded_models: list[LoadedModelInfo] = []


class JobSummaryResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    job_id: str
    headline: str
    top_signals: list[str] = []
    top_hosts: list[HostListItem] = []
    top_iocs: list[IocItem] = []
    recommendations: list[str] = []
    alert_count: int = 0
    finding_count: int = 0
    ioc_count: int = 0
    host_count: int = 0
