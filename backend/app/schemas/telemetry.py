"""Telemetry fusion schemas — source manifests, provenance, and corroboration.

These Pydantic models define the contracts for multi-source ingestion,
parser metadata, and evidence corroboration tracking.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from backend.app.schemas.common import (
    SCHEMA_VERSION,
    EvidenceStatus,
    NormalizedEventType,
    SourceType,
)


# ---------------------------------------------------------------------------
# Source entry — one file/stream within a bundle
# ---------------------------------------------------------------------------


class SourceEntry(BaseModel):
    """A single telemetry source file within an ingestion bundle."""

    filename: str
    source_type: SourceType
    source_system: str | None = None        # e.g. "sysmon", "paloalto", "cobalt_strike"
    parser_hint: str | None = None          # suggested parser name
    size_bytes: int | None = None
    sha256: str | None = None
    label: str | None = None                # user-supplied tag: "before", "during", etc.
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Source manifest — describes the full ingestion bundle for a job
# ---------------------------------------------------------------------------


class SourceManifest(BaseModel):
    """Manifest describing all telemetry sources staged for a job."""

    job_id: str
    exercise_id: str | None = None
    created_at: datetime
    entries: list[SourceEntry] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Parser info — metadata about which parser produced an output
# ---------------------------------------------------------------------------


class ParserInfo(BaseModel):
    """Describes the parser that produced a set of normalized events."""

    parser_name: str                        # e.g. "windows_evtx", "linux_auth"
    parser_version: str = "0.1.0"
    source_system: str | None = None        # e.g. "sysmon", "auditd"
    source_filename: str | None = None
    raw_ref: str | None = None              # path/offset to raw record
    parsed_at: datetime | None = None
    record_count: int | None = None
    error_count: int = 0
    meta: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Provenance — tracks where a normalized event came from
# ---------------------------------------------------------------------------


class Provenance(BaseModel):
    """Tracks the origin of a normalized event for auditability."""

    source_type: SourceType
    source_system: str | None = None
    source_filename: str | None = None
    parser_name: str | None = None
    parser_version: str | None = None
    raw_ref: str | None = None              # pointer to original record
    exercise_id: str | None = None
    ingested_at: datetime | None = None


# ---------------------------------------------------------------------------
# Corroboration — links evidence across sources
# ---------------------------------------------------------------------------


class CorroborationLink(BaseModel):
    """A single link between two pieces of evidence from different sources."""

    source_event_id: str
    target_event_id: str
    correlation_key: str                    # e.g. "community_id", "hostname", "session_id"
    correlation_value: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class Corroboration(BaseModel):
    """Corroboration record — upgrades evidence status when multiple sources agree."""

    event_id: str
    evidence_status: EvidenceStatus = EvidenceStatus.observed
    supporting_sources: list[str] = Field(default_factory=list)
    links: list[CorroborationLink] = Field(default_factory=list)
    corroboration_score: float = Field(ge=0.0, le=1.0, default=0.0)
    rationale: str | None = None


# ---------------------------------------------------------------------------
# Normalized event envelope — common wrapper for all event types
# ---------------------------------------------------------------------------


class NormalizedEventEnvelope(BaseModel):
    """Common envelope wrapping any normalized event for pipeline transport."""

    event_id: str
    job_id: str
    event_type: NormalizedEventType
    timestamp: datetime
    provenance: Provenance
    evidence_status: EvidenceStatus = EvidenceStatus.observed
    correlation_keys: dict[str, str] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# API response wrappers
# ---------------------------------------------------------------------------


class SourceManifestResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    manifest: SourceManifest

