"""Job schemas (openapi.yaml: JobCreateRequest/Response, JobListItem, JobGetResponse, etc.)."""

from typing import Any

from pydantic import BaseModel, ConfigDict

from backend.app.schemas.common import (
    SCHEMA_VERSION,
    ExecutionProfile,
    JobStatus,
    PageInfo,
    Priority,
    SourceType,
)


class PcapUploadItem(BaseModel):
    """A single PCAP upload to associate with a job."""
    upload_id: str
    label: str | None = None  # optional phase label: "before", "during", "after", or custom


class BundleUploadItem(BaseModel):
    """A single log bundle upload to attach to a job (with optional phase label)."""
    upload_id: str
    label: str | None = None  # optional phase label: "before", "during", "after", or custom


class BundleSourceEntry(BaseModel):
    """A single file entry within a log/C2/netflow bundle."""
    filename: str
    source_system: str | None = None      # e.g. "sysmon", "paloalto", "cobalt_strike"
    parser_hint: str | None = None        # suggested parser name
    label: str | None = None              # user-supplied tag


class JobCreateRequest(BaseModel):
    upload_id: str | None = None          # backward-compat: single upload
    uploads: list[PcapUploadItem] | None = None  # multi-PCAP: list of uploads with optional labels
    job_name: str | None = None
    notes: str | None = None
    execution_profile: ExecutionProfile
    priority: Priority = Priority.normal
    # --- Telemetry fusion fields ---
    source_type: SourceType = SourceType.pcap
    exercise_id: str | None = None
    bundle_entries: list[BundleSourceEntry] | None = None  # metadata for non-PCAP bundles
    # --- Hybrid job: attach log bundles alongside PCAPs ---
    bundle_uploads: list[BundleUploadItem] | None = None  # labeled log bundles to fuse with PCAPs
    # --- BlueScrub code-artifact jobs ---
    project_id: str | None = None  # optional; unbound jobs scan but do not carry triage forward


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


class JobLogSourceItem(BaseModel):
    """A log file associated with a job (for traceability)."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    upload_id: str | None = None
    label: str | None = None
    filename: str
    source_system: str | None = None
    parser_hint: str | None = None
    ordinal: int
    size_bytes: int | None = None
    sha256: str | None = None

    # Parse diagnostics (populated from telemetry_diagnostics.json)
    parse_status: str | None = None         # "ok" | "skipped" | "error"
    parse_parser: str | None = None         # parser name that handled it
    parse_events: int | None = None         # events produced
    parse_error: str | None = None          # error/skip reason


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
    # --- Telemetry fusion fields ---
    source_type: SourceType = SourceType.pcap
    exercise_id: str | None = None


class JobListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[JobListItem]
    page: PageInfo


class TemporalCorrelationItem(BaseModel):
    """A temporal match between a log event and a PCAP-derived event."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    log_event_id: str
    log_source: str | None = None
    log_source_filename: str | None = None
    log_event_type: str | None = None
    log_timestamp: str
    log_summary: str | None = None
    pcap_entity_type: str              # "alert" | "connection"
    pcap_entity_id: str
    pcap_summary: str | None = None
    pcap_timestamp: str
    shared_ip: str
    time_delta_seconds: float
    match_score: float
    match_type: str
    # Enhanced correlation metadata (optional for backward compatibility)
    community_id: str | None = None
    match_keys: list[str] = []
    log_label: str | None = None
    pcap_label: str | None = None
    clock_offset_seconds: float | None = None
    adjusted_time_delta_seconds: float | None = None
    confidence_band: str | None = None


class JobDetail(JobListItem):
    metrics: JobMetrics | None = None
    stages: list[StageItem] = []
    sensors: list[SensorItem] = []
    pcaps: list[JobPcapItem] = []
    log_sources: list[JobLogSourceItem] = []
    temporal_correlations: list[TemporalCorrelationItem] = []


class TemporalCorrelationsResponse(BaseModel):
    """Paginated list of temporal correlations for a job."""
    schema_version: str = SCHEMA_VERSION
    items: list[TemporalCorrelationItem]
    page: PageInfo
    total: int


class JobGetResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    job: JobDetail


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # host, external, dns, alert, finding, theory, slice, ioc, annotation
    severity: str | None = None
    meta: dict[str, Any] | None = None


class GraphEdge(BaseModel):
    source: str
    target: str
    type: str  # connection, triggered_on, correlated, supported_by, contains, etc.
    weight: int = 1


class JobGraphResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class EvidenceGraphResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    node_count: int = 0
    edge_count: int = 0


# ── Storyline schemas ────────────────────────────────────────────────

class StorylineStage(BaseModel):
    """A single kill-chain stage in the attack storyline."""
    name: str
    display_name: str
    node_count: int = 0
    edge_count: int = 0
    confidence: float = 0.0
    summary: str = ""
    host_ips: list[str] = []
    time_start: str | None = None
    time_end: str | None = None
    node_ids: list[str] = []


class StorylineResponse(BaseModel):
    """Response for GET /jobs/{id}/storyline."""
    schema_version: str = SCHEMA_VERSION
    job_id: str
    stages: list[StorylineStage] = []
    host_timelines: dict[str, list[str]] = {}
    narrative: str = ""
    total_nodes: int = 0
    total_edges: int = 0
    unclassified_count: int = 0

