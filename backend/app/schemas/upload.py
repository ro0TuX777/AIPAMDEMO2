"""Upload schemas (openapi.yaml: UploadCreateResponse, UploadValidateResponse)."""

from pydantic import BaseModel, ConfigDict

from backend.app.schemas.common import SCHEMA_VERSION


class UploadCreateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    schema_version: str = SCHEMA_VERSION
    upload_id: str
    filename: str
    size_bytes: int
    sha256: str


class EstimatedRuntime(BaseModel):
    triage: float | None = None
    standard: float | None = None
    deep: float | None = None


class UploadValidateResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    is_valid: bool
    format: str | None = None
    linktype: str | None = None
    packet_count: int | None = None
    capture_duration_seconds: float | None = None
    estimated_runtime: EstimatedRuntime | None = None
    warnings: list[str] = []

