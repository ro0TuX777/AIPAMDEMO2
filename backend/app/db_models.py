from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional, List

from sqlmodel import Field, SQLModel
from sqlalchemy import Column
from sqlalchemy.types import JSON

from .models import JobStatus, JobStepStatus


class JobDB(SQLModel, table=True):
    """Database model for analysis jobs."""

    id: str = Field(primary_key=True, index=True)
    source: str
    mode: str
    exercise_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    status: JobStatus = Field(index=True)
    job_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    error_message: Optional[str] = None


class JobStepDB(SQLModel, table=True):
    """Database model for individual pipeline steps per job."""

    id: str = Field(primary_key=True, index=True)
    job_id: str = Field(foreign_key="jobdb.id", index=True)
    name: str
    status: JobStepStatus
    message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class JobResultDB(SQLModel, table=True):
    """Stores the final aggregated JobResult as a JSON blob per job."""

    job_id: str = Field(primary_key=True, foreign_key="jobdb.id")
    # Store the full JobResult (including summary, hosts, raw, report_urls)
    result: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )


class PartialJobResultDB(SQLModel, table=True):
    """Stores intermediate pipeline results for progressive display.

    Written after the aggregate + anomaly detection steps complete, so
    analysts can see early insights while the LLM analysis is still running.
    Deleted once the full JobResultDB row is written.
    """

    job_id: str = Field(primary_key=True, foreign_key="jobdb.id")
    result: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime



class SettingsDB(SQLModel, table=True):
    """Singleton-style table storing application settings as JSON."""

    id: int = Field(primary_key=True, default=1)
    values: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )


class ConversationDB(SQLModel, table=True):
    """Database model for chat conversations about job analysis."""

    id: str = Field(primary_key=True, index=True)
    job_id: str = Field(foreign_key="jobdb.id", index=True)
    created_at: datetime
    updated_at: datetime
    title: Optional[str] = None  # Optional title/summary of conversation


class ChatMessageDB(SQLModel, table=True):
    """Database model for individual chat messages in a conversation."""

    id: str = Field(primary_key=True, index=True)
    conversation_id: str = Field(foreign_key="conversationdb.id", index=True)
    role: str  # "user" or "assistant"
    content: str
    citations: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    created_at: datetime


class FindingDB(SQLModel, table=True):
    """One row per discrete forensic finding.

    Enables cross-job analytics such as:
    - "Show all jobs that detected T1071"
    - "List all IcedID detections in the last month"
    - Dashboard aggregation by severity, technique, or malware family
    """

    id: str = Field(primary_key=True, index=True)
    job_id: str = Field(foreign_key="jobdb.id", index=True)
    mitre_technique_id: Optional[str] = Field(default=None, index=True)
    mitre_technique_name: Optional[str] = None
    classification: Optional[str] = Field(default=None, index=True)
    severity: str = Field(index=True)
    title: str
    description: str
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    affected_hosts: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    confidence: float = 0.0
    analyzer_source: str  # "ollama", "trafficllm", "heuristic"
    attack_chain_stage: Optional[str] = None
    created_at: datetime

    # Phase 3: Analyst feedback loop
    analyst_status: str = Field(
        default="unverified", index=True
    )  # "unverified" | "confirmed" | "false_positive"
    analyst_notes: Optional[str] = None


class PipelineCheckpointDB(SQLModel, table=True):
    """Saves intermediate pipeline state per step for retry capability.

    After each pipeline step (ingest, parse, aggregate, llm_analysis, report)
    completes, its output is serialized here.  On retry, completed steps are
    skipped and their saved state is restored.
    """

    id: str = Field(primary_key=True)  # "{job_id}:{step_name}"
    job_id: str = Field(foreign_key="jobdb.id", index=True)
    step_name: str  # "ingest", "parse", "aggregate", "llm_analysis", "report"
    state_data: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    completed_at: Optional[datetime] = None


class FlowDB(SQLModel, table=True):
    """One row per normalized network flow (from Zeek conn.log).

    Enables per-flow querying and linking to findings via EvidenceDB.
    Each flow belongs to a single analysis job.
    """

    id: str = Field(primary_key=True)  # Zeek UID (unique per connection)
    job_id: str = Field(foreign_key="jobdb.id", index=True)
    src_ip: str = Field(index=True)
    src_port: int
    dst_ip: str = Field(index=True)
    dst_port: int
    transport_proto: str  # TCP / UDP / ICMP / OTHER
    app_proto: str  # HTTP / TLS / DNS / SSH / SMB / RDP / UNKNOWN
    start_time: datetime
    end_time: datetime
    duration_sec: float
    bytes_from_src: int
    bytes_from_dst: int
    packets_from_src: int
    packets_from_dst: int
    tcp_flags_summary: Optional[str] = None
    state: Optional[str] = None  # Zeek conn_state (SF, S0, REJ, etc.)
    extra: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )


class AlertDB(SQLModel, table=True):
    """One row per IDS/IPS alert (Suricata EVE, TrafficLLM).

    Links to the originating job and optionally to specific flows.
    """

    id: str = Field(primary_key=True)
    job_id: str = Field(foreign_key="jobdb.id", index=True)
    timestamp: datetime
    src_ip: Optional[str] = Field(default=None, index=True)
    dst_ip: Optional[str] = Field(default=None, index=True)
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    alert_source: str  # "SURICATA" / "TRAFFICLLM"
    signature_id: Optional[str] = Field(default=None, index=True)
    signature_name: str
    severity: str = Field(index=True)
    category: Optional[str] = None
    flow_id: Optional[str] = None  # Correlate to FlowDB.id when possible
    extra: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )


class EvidenceDB(SQLModel, table=True):
    """Many-to-many: links a Finding to the specific Flows that prove it.

    Enables queries like "which flows support this C2 finding?" and
    "what findings reference this suspicious flow?"
    """

    id: str = Field(primary_key=True)
    finding_id: str = Field(foreign_key="findingdb.id", index=True)
    flow_id: str = Field(foreign_key="flowdb.id", index=True)
    relationship: str = "supports"  # "supports" / "contradicts" / "context"
    snippet: Optional[str] = None  # Raw evidence excerpt shown to analyst


class MitreCtiBundleDB(SQLModel, table=True):
    """Tracks ingested MITRE CTI bundle metadata per domain."""

    domain: str = Field(primary_key=True)  # enterprise | mobile | ics
    source_url: Optional[str] = None
    bundle_sha256: Optional[str] = None
    bundle_version: Optional[str] = None
    bundle_modified: Optional[datetime] = None
    ingested_at: Optional[datetime] = None


class MitreTechniqueDB(SQLModel, table=True):
    """Canonical MITRE ATT&CK technique metadata (STIX-based)."""

    id: str = Field(primary_key=True)  # "{domain}:{technique_id}"
    domain: str = Field(index=True)
    technique_id: str = Field(index=True)
    name: str
    description: Optional[str] = None
    tactics: List[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    revoked: bool = False
    deprecated: bool = False
    is_subtechnique: bool = False
    version: Optional[str] = None
    created_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    source_url: Optional[str] = None
    bundle_sha256: Optional[str] = None
    ingested_at: Optional[datetime] = None
