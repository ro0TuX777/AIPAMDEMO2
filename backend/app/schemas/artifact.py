"""Artifact schemas (openapi.yaml: ArtifactItem, ArtifactListResponse, EvidencePackageCreateResponse)."""

from pydantic import BaseModel, ConfigDict

from backend.app.schemas.common import SCHEMA_VERSION


class ArtifactItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    artifact_id: str
    type: str
    status: str  # available, generating, failed, purged
    created_at: str
    filename: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    error: str | None = None


class ArtifactListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[ArtifactItem]


class EvidencePackageCreateResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    artifact_id: str
    status: str = "generating"

