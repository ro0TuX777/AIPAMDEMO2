"""Binary / YARA analysis schemas (first-class binary analysis)."""

from typing import Any

from pydantic import BaseModel

from backend.app.schemas.common import SCHEMA_VERSION


class YaraMatchItem(BaseModel):
    """One YARA rule match."""

    rule: str
    tags: list[str] = []
    meta: dict[str, Any] = {}
    strings: list[str] = []


class BinaryAnalysisItem(BaseModel):
    """Analysis result for a single analyzed file."""

    file_id: str
    filename: str | None = None
    size_bytes: int
    sha256: str
    md5: str | None = None
    sha1: str | None = None
    entropy: float | None = None
    format: str | None = None
    artifact_class: str | None = None
    yara_matches: list[YaraMatchItem] = []


class BinaryAnalysisResponse(BaseModel):
    """Response for a binary analyze/upload request."""

    schema_version: str = SCHEMA_VERSION
    yara_available: bool
    rules_compiled: bool
    findings_created: int
    analysis: BinaryAnalysisItem


class BinaryAnalysisListResponse(BaseModel):
    """List of persisted binary analyses for a job."""

    schema_version: str = SCHEMA_VERSION
    items: list[BinaryAnalysisItem]
    total: int


class BinaryInspectResponse(BaseModel):
    """Stateless inspection result (nothing persisted)."""

    schema_version: str = SCHEMA_VERSION
    yara_available: bool
    rules_compiled: bool
    analysis: BinaryAnalysisItem
