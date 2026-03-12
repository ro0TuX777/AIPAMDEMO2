"""Host schemas (openapi.yaml: HostListItem, HostDetail, HostListResponse, HostGetResponse)."""

from pydantic import BaseModel, ConfigDict

from backend.app.schemas.common import SCHEMA_VERSION, PageInfo


class HostListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip: str
    role: str = "unknown"
    conn_count: int = 0
    bytes_sent: int | None = None
    bytes_recv: int | None = None
    alert_count: int = 0
    finding_count: int = 0
    top_domains: list[str] = []


class DnsSummary(BaseModel):
    query_count: int | None = None
    top_qnames: list[str] = []


class TlsSummary(BaseModel):
    session_count: int | None = None
    top_sni: list[str] = []
    top_ja3: list[str] = []


class HostDetail(HostListItem):
    first_seen: str | None = None
    last_seen: str | None = None
    alerts_by_severity: dict[str, int] = {}
    top_services: list[str] = []
    dns_summary: DnsSummary | None = None
    tls_summary: TlsSummary | None = None
    
    # Global context
    global_stats: dict[str, int] = {}  # {job_count, total_alerts, total_findings}
    global_history: list[dict] = []  # [{job_id, ts, role, alert_count, finding_count}]


class HostListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[HostListItem]
    page: PageInfo


class HostGetResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    host: HostDetail


# --- Global Host schemas ---


class GlobalHostListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip: str
    hostname: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    job_count: int = 0
    total_alerts: int = 0
    total_findings: int = 0
    seen_as_internal: bool = False
    roles: list[str] = []


class GlobalHostDetail(GlobalHostListItem):
    history: list[dict] = []


class GlobalHostListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[GlobalHostListItem]
    page: PageInfo


class GlobalHostGetResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    host: GlobalHostDetail

