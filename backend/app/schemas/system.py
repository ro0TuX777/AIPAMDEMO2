"""System schemas (openapi.yaml: BatchJobsRequest/Response, SystemConfigResponse, HealthResponse, JobSummaryResponse)."""

from pydantic import BaseModel

from backend.app.schemas.common import (
    SCHEMA_VERSION,
    ExecutionProfile,
    JobStatus,
    Severity,
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


class SystemConfigResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    aipam_version: str
    max_upload_bytes: int
    profiles_enabled: list[ExecutionProfile]
    default_limits: DefaultLimits


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

