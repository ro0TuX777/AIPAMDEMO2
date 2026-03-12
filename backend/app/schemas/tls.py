"""TLS session schemas (openapi.yaml: TlsSessionItem, TlsSessionListResponse)."""

from pydantic import BaseModel, ConfigDict

from backend.app.schemas.common import SCHEMA_VERSION, PageInfo


class TlsSessionItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tls_id: str
    ts: str
    src_ip: str
    dest_ip: str
    dest_port: int | None = None
    sni: str | None = None
    ja3: str | None = None
    ja3s: str | None = None
    alpn: str | None = None
    version: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_fingerprint_sha1: str | None = None
    community_id: str | None = None
    iocs: list[str] = []


class TlsSessionListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[TlsSessionItem]
    page: PageInfo

