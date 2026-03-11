"""Job schemas (openapi.yaml: JobCreateRequest/Response, JobListItem, JobGetResponse, etc.)."""

from typing import Any

from pydantic import BaseModel, ConfigDict

from backend.app.schemas.common import (
    SCHEMA_VERSION,
    ExecutionProfile,
    JobStatus,
    PageInfo,
    Priority,
    Severity,
)


class PcapUploadItem(BaseModel):
    """A single PCAP upload to associate with a job."""
    upload_id: str
    label: str | None = None  # optional phase label: "before", "during", "after", or custom


class JobCreateRequest(BaseModel):
    upload_id: str | None = None          # backward-compat: single upload
    uploads: list[PcapUploadItem] | None = None  # multi-PCAP: list of uploads with optional labels
    job_name: str | None = None
    notes: str | None = None
    execution_profile: ExecutionProfile
    priority: Priority = Priority.normal


class JobCreateResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    job_id: str


class JobPcapItem(BaseModel):
    """A PCAP file associated with a job."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    upload_id: str
    label: str | None = None
    filename: str
    ordinal: int
    size_bytes: int | None = None
    sha256: str | None = None


# --- Metrics / Stages / Sensors (embedded in JobGetResponse) ---

class PcapStats(BaseModel):
    packet_count: int | None = None
    capture_duration_seconds: float | None = None


class JobMetrics(BaseModel):
    pcap_stats: PcapStats | None = None
    durations: dict[str, float] = {}


class StageItem(BaseModel):
    stage: str
    status: str
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None
    error_code: str | None = None


class SensorProvenance(BaseModel):
    sensor_name: str
    sensor_version: str | None = None
    image_digest: str | None = None
    host_hostname: str | None = None
    aipam_version: str | None = None
    tool_versions: dict[str, str] = {}


class SensorStats(BaseModel):
    runtime_seconds: float | None = None
    output_bytes: int | None = None
    findings_count: int | None = None


class SensorItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sensor: str
    status: str
    meta: SensorProvenance
    stats: SensorStats | None = None
    started_at: str | None = None
    completed_at: str | None = None
    timeout_seconds: int | None = None
    error: str | None = None
    error_code: str | None = None


class SensorListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[SensorItem]


# --- Job list / detail ---

class JobListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    job_id: str
    job_name: str | None = None
    notes: str | None = None
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    status: JobStatus
    execution_profile: ExecutionProfile
    priority: Priority
    pcap_filename: str | None = None
    pcap_size_bytes: int | None = None
    error_summary: str | None = None


class JobListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[JobListItem]
    page: PageInfo


class JobDetail(JobListItem):
    metrics: JobMetrics | None = None
    stages: list[StageItem] = []
    sensors: list[SensorItem] = []
    pcaps: list[JobPcapItem] = []


class JobGetResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    job: JobDetail


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # host, external, dns, etc.
    severity: str | None = None


class GraphEdge(BaseModel):
    source: str
    target: str
    type: str  # connection, alert, etc.
    weight: int = 1


class JobGraphResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    nodes: list[GraphNode]
    edges: list[GraphEdge]

