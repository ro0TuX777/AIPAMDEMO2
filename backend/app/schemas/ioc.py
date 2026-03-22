"""IOC schemas (openapi.yaml: IocItem, IocListResponse)."""

from pydantic import BaseModel, ConfigDict

from backend.app.schemas.common import SCHEMA_VERSION, IocType, PageInfo


class IocItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ioc_id: str
    type: IocType
    value: str
    severity: str | None = None
    confidence: float | None = None
    sources: list[str] = []
    context: str | None = None
    pcap_label: str | None = None


class IocListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[IocItem]
    page: PageInfo

