"""Proof schemas — analyst-curated evidence proofs."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from backend.app.schemas.common import SCHEMA_VERSION

ProofStatus = Literal["draft", "final", "archived"]
ProofRole = Literal["supports", "contradicts", "context"]
EntityType = Literal["host", "alert", "finding", "theory", "slice", "ioc", "annotation"]
ProofMode = Literal["soc_handoff", "ir_technical", "executive_summary"]


# ---------------------------------------------------------------------------
# ProofItem
# ---------------------------------------------------------------------------


class ProofItemBase(BaseModel):
    entity_type: EntityType
    entity_id: str
    role: ProofRole = "supports"
    analyst_note: str | None = None


class ProofItemCreate(ProofItemBase):
    """Request body for adding an item to a proof."""
    pass


class ProofItemUpdate(BaseModel):
    """Request body for updating a proof item."""
    role: ProofRole | None = None
    analyst_note: str | None = None
    order: int | None = None


class ProofItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    item_id: str
    proof_id: str
    entity_type: str
    entity_id: str
    role: str
    analyst_note: str | None = None
    order: int = 0
    label: str | None = None
    severity: str | None = None
    created_at: str


# ---------------------------------------------------------------------------
# Proof
# ---------------------------------------------------------------------------


class ProofCreate(BaseModel):
    """Request body for creating a proof."""
    title: str
    conclusion: str | None = None
    severity: str = "info"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    mode: ProofMode = "soc_handoff"


class ProofUpdate(BaseModel):
    """Request body for updating a proof."""
    title: str | None = None
    conclusion: str | None = None
    status: ProofStatus | None = None
    severity: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    mode: ProofMode | None = None
    narrative_markdown: str | None = None


class ProofOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    proof_id: str
    job_id: str
    title: str
    conclusion: str | None = None
    status: str
    severity: str
    confidence: float
    mode: str = "soc_handoff"
    narrative_markdown: str | None = None
    item_count: int = 0
    created_at: str
    updated_at: str


# ---------------------------------------------------------------------------
# Response wrappers
# ---------------------------------------------------------------------------


class ProofListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[ProofOut]
    job_id: str


class ProofDetailResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    item: ProofOut
    job_id: str


class ProofItemListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[ProofItemOut]
    proof_id: str


class ProofItemDetailResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    item: ProofItemOut
    proof_id: str


class ProofNarrativeResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    proof_id: str
    narrative_markdown: str
    warnings: list[str] = []


class ProofExportResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    content: str
    filename: str

