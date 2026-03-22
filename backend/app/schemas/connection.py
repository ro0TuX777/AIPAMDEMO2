"""Connection schemas (openapi.yaml: ConnectionItem, ConnectionListResponse)."""

from pydantic import BaseModel, ConfigDict

from backend.app.schemas.common import SCHEMA_VERSION, PageInfo


class ConnectionItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    connection_id: str
    community_id: str | None = None
    ts: str
    src_ip: str
    src_port: int | None = None
    dest_ip: str
    dest_port: int | None = None
    proto: str
    duration_seconds: float | None = None
    bytes_sent: int | None = None
    bytes_recv: int | None = None
    service: str | None = None
    alerts: list[str] = []
    iocs: list[str] = []
    pcap_label: str | None = None


class ConnectionListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[ConnectionItem]
    page: PageInfo

