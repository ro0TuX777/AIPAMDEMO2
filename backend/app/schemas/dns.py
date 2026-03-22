"""DNS query schemas (openapi.yaml: DnsQueryItem, DnsQueryListResponse)."""

from pydantic import BaseModel, ConfigDict

from backend.app.schemas.common import SCHEMA_VERSION, PageInfo


class DnsQueryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    dns_id: str
    ts: str
    src_ip: str
    query: str
    qtype: str | None = None
    answers: list[str] = []
    rcode: str | None = None
    ttl_seconds: int | None = None
    dest_ip: str | None = None
    community_id: str | None = None
    iocs: list[str] = []
    related_community_ids: list[str] = []
    pcap_label: str | None = None


class DnsQueryListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[DnsQueryItem]
    page: PageInfo

