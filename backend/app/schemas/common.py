"""Common Pydantic schemas shared across API responses."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict


SCHEMA_VERSION = "1.0"


class ExecutionProfile(str, Enum):
    triage = "triage"
    standard = "standard"
    deep = "deep"


class Priority(str, Enum):
    low = "low"
    normal = "normal"
    high = "high"


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    completed_with_errors = "completed_with_errors"
    failed = "failed"
    canceled = "canceled"
    deleting = "deleting"
    deleted = "deleted"


class SensorStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    skipped = "skipped"
    timeout = "timeout"
    canceled = "canceled"


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IocType(str, Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash = "hash"
    ja3 = "ja3"
    ja3s = "ja3s"
    sni = "sni"
    email = "email"
    mutex = "mutex"
    registry = "registry"


class PageInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    next_cursor: str | None = None
    has_more: bool


class SourceType(str, Enum):
    """Job source type — what kind of telemetry the job ingests."""
    pcap = "pcap"
    pcap_logs = "pcap+logs"
    log_bundle = "log_bundle"
    netflow_bundle = "netflow_bundle"
    c2_bundle = "c2_bundle"
    exercise_bundle = "exercise_bundle"
    binary = "binary"
    code_artifact = "code_artifact"   # BlueScrub: source, binaries, build config


class EvidenceStatus(str, Enum):
    """Evidence confidence lifecycle."""
    observed = "observed"        # raw extraction, single source
    inferred = "inferred"        # derived via analysis/heuristic
    corroborated = "corroborated"  # confirmed by 2+ independent sources
    confirmed = "confirmed"      # validated by ground-truth (e.g. C2 logs)


class NormalizedEventType(str, Enum):
    """Canonical event families for multi-source normalization."""
    connection = "connection"
    netflow = "netflow"
    dns = "dns"
    http = "http"
    proxy = "proxy"
    tls = "tls"
    alert = "alert"
    auth = "auth"
    process = "process"
    file = "file"
    config_change = "config_change"
    asset_status = "asset_status"
    interface_event = "interface_event"
    c2_callback = "c2_callback"
    c2_task = "c2_task"
    finding = "finding"
    ioc = "ioc"


class ErrorCode(str, Enum):
    # Foundational Errors
    ERR_DISK_FULL = "ERR_DISK_FULL"
    ERR_OLLAMA_OFFLINE = "ERR_OLLAMA_OFFLINE"
    ERR_DB_OFFLINE = "ERR_DB_OFFLINE"
    ERR_REDIS_OFFLINE = "ERR_REDIS_OFFLINE"
    
    # Pipeline Errors
    ERR_PIPELINE_CRASH = "ERR_PIPELINE_CRASH"
    ERR_SENSOR_TIMEOUT = "ERR_SENSOR_TIMEOUT"
    ERR_PCAP_NOT_FOUND = "ERR_PCAP_NOT_FOUND"
    
    # Generic Errors
    ERR_NOT_FOUND = "ERR_NOT_FOUND"
    ERR_UNAUTHORIZED = "ERR_UNAUTHORIZED"


class ErrorResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    error: str
    code: ErrorCode
    details: dict[str, Any] | None = None

