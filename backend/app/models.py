from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class FlowRecord(BaseModel):
    id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    transport_proto: str
    app_proto: str
    start_time: datetime
    end_time: datetime
    duration_sec: float
    bytes_from_src: int
    bytes_from_dst: int
    packets_from_src: int
    packets_from_dst: int
    tcp_flags_summary: Optional[str] = None
    num_resets: Optional[int] = 0
    state: Optional[str] = None
    sensor_id: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    extra: Dict[str, str] = Field(default_factory=dict)


class EventRecord(BaseModel):
    id: str
    event_type: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport_proto: str
    sensor_id: Optional[str] = None
    flow_id: Optional[str] = None
    details: Dict[str, object] = Field(default_factory=dict)


class AlertRecord(BaseModel):
    id: str
    timestamp: datetime
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    sensor_id: Optional[str] = None
    alert_source: str
    signature_id: Optional[str] = None
    signature_name: str
    severity: str
    category: Optional[str] = None
    flow_id: Optional[str] = None
    extra: Dict[str, object] = Field(default_factory=dict)


class TimeWindow(BaseModel):
    start: datetime
    end: datetime


class TopDstIP(BaseModel):
    ip: str
    flow_count: int
    bytes: int


class ProtocolUsage(BaseModel):
    app_proto: str
    flow_count: int
    bytes: int


class HostSummary(BaseModel):
    host_ip: str
    role: str
    time_window: TimeWindow
    total_flows: int
    total_bytes_sent: int
    total_bytes_received: int
    top_dst_ips: List[TopDstIP] = Field(default_factory=list)
    protocol_usage: List[ProtocolUsage] = Field(default_factory=list)
    dns_queries_count: int
    dns_unique_domains: int
    http_requests_count: int
    alerts_count: int
    alerts_by_severity: Dict[str, int] = Field(default_factory=dict)
    suspicious_heuristics: Dict[str, object] = Field(default_factory=dict)


class HostPairAlertSummary(BaseModel):
    timestamp: datetime
    signature_name: str
    severity: str


class HostPairSummary(BaseModel):
    src_ip: str
    dst_ip: str
    time_window: TimeWindow
    flow_count: int
    total_bytes: int
    direction: str
    top_app_protos: List[ProtocolUsage] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    alerts: List[HostPairAlertSummary] = Field(default_factory=list)
    interesting_events: List[str] = Field(default_factory=list)


class MetricChange(BaseModel):
    metric: str
    baseline_value: float
    exploit_value: float
    ratio: float


class ChangeSummary(BaseModel):
    entity_type: str
    entity_id: str
    metric_changes: List[MetricChange] = Field(default_factory=list)
    new_protocols: List[str] = Field(default_factory=list)
    new_alert_signatures: List[str] = Field(default_factory=list)


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    FAILED = "failed"
    COMPLETED = "completed"


class JobStepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Job(BaseModel):
    id: str
    source: str
    mode: str
    exercise_id: Optional[str]
    created_at: datetime
    updated_at: datetime
    status: JobStatus
    metadata: Dict[str, object] = Field(default_factory=dict)


class JobStep(BaseModel):
    id: str
    job_id: str
    name: str
    status: JobStepStatus
    message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class AnalysisSummary(BaseModel):
    """High-level analysis summary returned in JobResult.

    Matches the AIPAM_Dev_Package spec where key_findings is a list of
    short human-readable strings.
    """

    classification: Optional[str] = None
    severity: str
    key_findings: List[str]
    mitre_techniques: List[Dict[str, str]]  # {"id": "T1190", "name": "..."}


class HostFinding(BaseModel):
    ip: str
    role: str
    findings: List[str]


# -----------------------
# LLM output data models
# -----------------------


class MitreTechnique(BaseModel):
    id: str
    name: str


class AttackChainItem(BaseModel):
    stage: str
    description: str
    evidence: List[str]
    mitre_techniques: List[MitreTechnique]


class HostFindingLLM(BaseModel):
    ip: str
    role_in_attack: str
    summary: str
    suspicious_behaviors: List[str]


class Anomaly(BaseModel):
    description: str
    related_hosts: List[str]
    confidence: float
    reason: str


class LLMOutput(BaseModel):
    classification: Optional[str] = None
    overall_severity: str
    attack_chain: List[AttackChainItem]
    host_findings: List[HostFindingLLM]
    anomalies: List[Anomaly]
    mitre_techniques_overall: List[MitreTechnique]


class JobResult(BaseModel):
    job_id: str
    status: JobStatus
    summary: AnalysisSummary
    hosts: List[HostFinding]
    # "raw" holds supporting data such as alerts and raw/aggregated LLM JSON.
    # Shape follows the spec: {"alerts": [...], "llm_analysis_raw": {...}}.
    raw: Dict[str, object]
    # "html" and "markdown" URLs, typically under /reports/.
    report_urls: Dict[str, str]


class TrafficLLMResult(BaseModel):
    """TrafficLLM classification results for integration with LLM analysis."""
    malware_detections: int = 0
    botnet_detections: int = 0
    malware_types: List[str] = Field(default_factory=list)
    botnet_types: List[str] = Field(default_factory=list)
    # Skip classifications as it contains complex objects (FlowRecord)
    # The summary (counts + types) is sufficient for the LLM prompt


class LLMInputBundle(BaseModel):
    exercise_id: str
    mode: str
    time_ranges: Dict[str, "TimeWindow"]  # keys: "baseline","exploit" or just "window"
    host_summaries_baseline: List["HostSummary"]
    host_summaries_exploit: List["HostSummary"]
    hostpair_summaries_baseline: List["HostPairSummary"]
    hostpair_summaries_exploit: List["HostPairSummary"]
    change_summaries: List["ChangeSummary"]
    alerts: List["AlertRecord"]
    trafficllm_results: Optional[TrafficLLMResult] = None
    raw_packet_samples: List[str] = Field(default_factory=list)

