"""Temporal analysis schemas — before/after delta comparison."""

from pydantic import BaseModel, Field

from backend.app.schemas.common import SCHEMA_VERSION


# ── Summary sub-models ────────────────────────────────────────────────────

class CountDelta(BaseModel):
    before: int = 0
    after: int = 0
    new: int = 0
    removed: int = 0


class AlertCountDelta(BaseModel):
    before: int = 0
    after: int = 0
    new_signatures: int = 0
    removed_signatures: int = 0


class TrafficSnapshot(BaseModel):
    connections: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0


class TrafficDelta(BaseModel):
    before: TrafficSnapshot = Field(default_factory=TrafficSnapshot)
    after: TrafficSnapshot = Field(default_factory=TrafficSnapshot)


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class PhaseSnapshot(BaseModel):
    host_count: int = 0
    alert_count: int = 0
    finding_count: int = 0
    connection_count: int = 0
    ioc_count: int = 0


class PhaseSummary(BaseModel):
    before: PhaseSnapshot = Field(default_factory=PhaseSnapshot)
    after: PhaseSnapshot = Field(default_factory=PhaseSnapshot)


class SeverityShiftItem(BaseModel):
    before: int = 0
    after: int = 0
    delta: int = 0


class SeverityShift(BaseModel):
    critical: SeverityShiftItem = Field(default_factory=SeverityShiftItem)
    high: SeverityShiftItem = Field(default_factory=SeverityShiftItem)
    medium: SeverityShiftItem = Field(default_factory=SeverityShiftItem)
    low: SeverityShiftItem = Field(default_factory=SeverityShiftItem)


class ContainmentIndicators(BaseModel):
    removed_c2_connections: int = 0
    reduced_alert_categories: list[str] = Field(default_factory=list)
    new_defensive_activity: list[str] = Field(default_factory=list)


class TemporalSummary(BaseModel):
    hosts: CountDelta = Field(default_factory=CountDelta)
    alerts: AlertCountDelta = Field(default_factory=AlertCountDelta)
    findings: CountDelta = Field(default_factory=CountDelta)
    iocs: CountDelta = Field(default_factory=CountDelta)
    dns_domains: CountDelta = Field(default_factory=CountDelta)
    traffic: TrafficDelta = Field(default_factory=TrafficDelta)
    theories: CountDelta = Field(default_factory=CountDelta)
    tls_sessions: CountDelta = Field(default_factory=CountDelta)
    severity_before: SeverityCounts = Field(default_factory=SeverityCounts)
    severity_after: SeverityCounts = Field(default_factory=SeverityCounts)


# ── Diff detail models ────────────────────────────────────────────────────

class HostDiffItem(BaseModel):
    ip: str
    role: str = "unknown"
    conn_count: int = 0
    alert_count: int = 0


class HostChangedItem(BaseModel):
    ip: str
    role: str = "unknown"
    conn_before: int = 0
    conn_after: int = 0
    alert_before: int = 0
    alert_after: int = 0


class HostDiffs(BaseModel):
    added: list[HostDiffItem] = Field(default_factory=list)
    removed: list[HostDiffItem] = Field(default_factory=list)
    changed: list[HostChangedItem] = Field(default_factory=list)


class AlertDiffItem(BaseModel):
    signature: str
    severity: str = "info"
    status: str  # "new", "removed", "changed"
    before_count: int = 0
    after_count: int = 0


class FindingDiffItem(BaseModel):
    title: str
    severity: str = "info"
    sensor: str | None = None
    status: str  # "new", "removed"


class IocDiffs(BaseModel):
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)


class DnsDiffs(BaseModel):
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)


# ── Top-level responses ───────────────────────────────────────────────────

class TemporalDeltaResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    summary: TemporalSummary = Field(default_factory=TemporalSummary)
    phase_summary: PhaseSummary = Field(default_factory=PhaseSummary)
    severity_shift: SeverityShift = Field(default_factory=SeverityShift)
    containment_indicators: ContainmentIndicators = Field(default_factory=ContainmentIndicators)
    hosts: HostDiffs = Field(default_factory=HostDiffs)
    alerts: list[AlertDiffItem] = Field(default_factory=list)
    findings: list[FindingDiffItem] = Field(default_factory=list)
    iocs: IocDiffs = Field(default_factory=IocDiffs)
    dns: DnsDiffs = Field(default_factory=DnsDiffs)


class TemporalFlowItem(BaseModel):
    src_ip: str
    dest_ip: str
    dest_port: int | None = None
    proto: str = "tcp"
    service: str | None = None
    count: int = 1
    total_bytes_sent: int = 0
    total_bytes_recv: int = 0


class TemporalFlowsResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    flows: list[TemporalFlowItem] = Field(default_factory=list)
    total_new_flows: int = 0


class TemporalNarrativeResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    narrative_markdown: str = ""


class TemporalExportResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    content: str = ""
    filename: str = ""

