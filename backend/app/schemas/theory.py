"""Theory of the Case schemas — ranked hypotheses per job/host."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from backend.app.schemas.common import SCHEMA_VERSION


HypothesisType = Literal[
    "c2",
    "malware_delivery",
    "recon",
    "lateral_movement",
    "exfiltration",
    "admin_tools",
    "benign",
    "inconclusive",
]

Confidence = Literal["low", "medium", "high"]


class EvidenceRef(BaseModel):
    """A resolved reference to a piece of evidence (alert, finding, or IOC)."""
    id: str
    type: str  # "alert", "finding", "ioc"
    label: str  # Human-readable label


class TheoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    theory_id: str
    scope_type: str  # "job" or "host"
    scope_id: str | None = None
    label: str
    hypothesis_type: str
    score: float
    confidence: str
    rank: int
    supporting_evidence: list[EvidenceRef] = Field(default_factory=list)
    contradicting_evidence: list[EvidenceRef] = Field(default_factory=list)
    explanation: str | None = None
    next_steps: list[str] = Field(default_factory=list)
    created_at: str


class TheoryListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[TheoryItem]
    job_id: str
    scope_type: str
    scope_id: str | None = None

