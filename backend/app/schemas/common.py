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

