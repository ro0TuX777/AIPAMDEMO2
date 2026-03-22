"""Incident Slice schemas — grouped attack threads per job."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from backend.app.schemas.common import SCHEMA_VERSION


SliceType = Literal[
    "attack_thread",
    "recon_phase",
    "c2_session",
    "lateral",
    "exfil",
    "misc",
]


class SliceItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    slice_id: str
    label: str
    slice_type: str
    severity: str
    confidence: float
    community_ids: list[str] = Field(default_factory=list)
    host_ips: list[str] = Field(default_factory=list)
    time_start: str | None = None
    time_end: str | None = None
    alert_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    ioc_ids: list[str] = Field(default_factory=list)
    connection_ids: list[str] = Field(default_factory=list)
    summary: str | None = None
    rank: int
    pcap_label: str | None = None
    created_at: str


class SliceListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[SliceItem]
    job_id: str


class SliceDetailResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    item: SliceItem
    job_id: str

