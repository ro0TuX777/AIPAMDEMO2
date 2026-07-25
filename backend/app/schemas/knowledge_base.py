"""Knowledge Base Pydantic schemas for API request/response."""

from typing import Literal

from pydantic import BaseModel, Field


# Valid document types
KBDocType = Literal[
    "asset_inventory",
    "network_map",
    "baseline_profile",
    "threat_intel",
    "soc_playbook",
    "policy",
    "reference",
    "user_guide",
    "exploit_capability",
    "other",
]


class KBDocumentCreate(BaseModel):
    """Request body for creating/uploading a KB document."""
    name: str = Field(..., min_length=1, max_length=255)
    doc_type: KBDocType
    description: str | None = None
    content: str = Field(..., min_length=1, max_length=5_000_000)


class KBDocumentOut(BaseModel):
    """Response schema for a KB document (without full content)."""
    id: str
    job_id: str | None = None      # None = global reference-library document
    is_global: bool = False
    name: str
    doc_type: str
    description: str | None = None
    filename: str | None = None
    chunk_count: int = 0
    status: str = "pending"
    error_message: str | None = None
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


class KBDocumentDetail(KBDocumentOut):
    """Response schema including full content."""
    content: str


class KBDocumentListOut(BaseModel):
    """Paginated list of KB documents."""
    items: list[KBDocumentOut]
    total: int

