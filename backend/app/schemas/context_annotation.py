"""Context Annotation schemas — per-host 'why unusual' annotations."""

import json

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.schemas.common import SCHEMA_VERSION


class ContextAnnotationItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    annotation_id: str
    host_ip: str
    metric_name: str
    metric_category: str
    baseline_value: float | None = None
    observed_value: float | None = None
    deviation_factor: float | None = None
    population_size: int | None = None
    severity: str
    confidence: float
    title: str
    description: str
    why_unusual: str
    related_alert_ids: list[str] = Field(default_factory=list)
    related_finding_ids: list[str] = Field(default_factory=list)
    created_at: str

    @field_validator("related_alert_ids", mode="before")
    @classmethod
    def _parse_alert_ids(cls, v):
        if isinstance(v, str):
            return json.loads(v) if v else []
        return v or []

    @field_validator("related_finding_ids", mode="before")
    @classmethod
    def _parse_finding_ids(cls, v):
        if isinstance(v, str):
            return json.loads(v) if v else []
        return v or []


class ContextAnnotationListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[ContextAnnotationItem]
    job_id: str

