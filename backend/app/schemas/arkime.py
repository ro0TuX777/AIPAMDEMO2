"""Arkime integration schemas — import status and pivot link responses."""

from typing import Literal

from pydantic import BaseModel

from backend.app.schemas.common import SCHEMA_VERSION


# --- Import status ---

ArkimeImportState = Literal["not_imported", "queued", "running", "imported", "failed"]


class ArkimeImportResponse(BaseModel):
    """Response after requesting a PCAP import into Arkime."""
    schema_version: str = SCHEMA_VERSION
    job_id: str
    enabled: bool = True
    import_status: ArkimeImportState = "queued"
    message: str | None = None


class ArkimeStatusResponse(BaseModel):
    """Current Arkime import status for a job."""
    schema_version: str = SCHEMA_VERSION
    job_id: str
    enabled: bool
    import_status: ArkimeImportState = "not_imported"
    imported_at: str | None = None
    pcap_count: int = 0
    message: str | None = None


# --- Pivot link ---

ArkimePivotBasis = Literal["community_id", "five_tuple", "none"]


class ArkimePivotResponse(BaseModel):
    """Arkime viewer pivot URL for an alert or finding."""
    schema_version: str = SCHEMA_VERSION
    enabled: bool
    url: str | None = None
    basis: ArkimePivotBasis = "none"
    import_status: ArkimeImportState = "not_imported"
    message: str | None = None

