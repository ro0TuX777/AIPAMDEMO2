"""Alert schemas (openapi.yaml: AlertItem, AlertListResponse)."""

from pydantic import BaseModel, ConfigDict

from backend.app.schemas.common import SCHEMA_VERSION, PageInfo, Severity


class AlertItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    alert_id: str
    ts: str
    severity: Severity
    engine: str | None = None
    signature: str
    category: str | None = None
    sid: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    community_id: str | None = None
    refs: list[str] = []
    tags: list[str] = []


class AlertListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[AlertItem]
    page: PageInfo

