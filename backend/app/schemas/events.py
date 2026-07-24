"""Raw event explorer schemas (search, aggregation, flow visualization)."""

from typing import Any

from pydantic import BaseModel

from backend.app.schemas.common import SCHEMA_VERSION


class RawEventItem(BaseModel):
    """A single normalized event flattened for the explorer."""

    event_id: str
    event_type: str
    timestamp: str
    source_type: str
    source_system: str | None = None
    hostname: str | None = None
    username: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    evidence_status: str | None = None
    tags: list[str] = []
    data: dict[str, Any] = {}


class RawEventListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[RawEventItem]
    total: int
    limit: int
    offset: int


class AggregationBucket(BaseModel):
    value: str | None
    count: int


class EventAggregationResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    field: str
    buckets: list[AggregationBucket]
    total_events: int


class FlowNode(BaseModel):
    id: str
    label: str
    kind: str  # "src" | "host" | "port"


class FlowLink(BaseModel):
    source: int  # index into nodes
    target: int
    value: int


class EventFlowResponse(BaseModel):
    """Source -> dest -> port flow summary for a Sankey diagram."""

    schema_version: str = SCHEMA_VERSION
    nodes: list[FlowNode]
    links: list[FlowLink]
    flows_considered: int
