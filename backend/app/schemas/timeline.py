"""Timeline schemas (openapi.yaml: TimelineItem, TimelineListResponse)."""

from pydantic import BaseModel, ConfigDict

from backend.app.schemas.common import SCHEMA_VERSION, PageInfo, Severity


class TimelineEntityFields(BaseModel):
    src_ip: str | None = None
    dest_ip: str | None = None
    src_port: int | None = None
    dest_port: int | None = None
    community_id: str | None = None
    domain: str | None = None


class TimelineRefs(BaseModel):
    alert_id: str | None = None
    finding_id: str | None = None
    ioc_id: str | None = None


class TimelineItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ts: str
    type: str
    title: str
    description: str | None = None
    severity: Severity | None = None
    entities: TimelineEntityFields | None = None
    refs: TimelineRefs | None = None
    evidence_status: str | None = None  # "observed" | "confirmed" | "corroborated"
    sensor: str | None = None           # provenance: which sensor produced this


class TimelineListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[TimelineItem]
    page: PageInfo

