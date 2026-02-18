"""Finding — Atomic forensic analysis result.

Each Finding represents a single discrete observation from analysis:
one MITRE technique detection, one anomaly, one malware classification.
This replaces the monolithic LLMOutput/AnalysisSummary with queryable,
per-technique granularity.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    """Severity levels aligned with AIPAM's existing severity scale."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """An individual forensic finding from analysis.

    Designed to be persisted as one row in FindingDB, enabling
    cross-job analytics like "show all jobs that detected T1071."

    Attributes:
        id: Unique identifier (UUID).
        job_id: Parent analysis job.
        mitre_technique_id: ATT&CK technique ID (e.g. ``"T1071.001"``).
        mitre_technique_name: Human-readable technique name.
        classification: Detected malware family (e.g. ``"IcedID"``).
        severity: Finding severity level.
        title: Short human-readable title.
        description: Detailed description of the finding.
        evidence: Supporting evidence strings.
        affected_hosts: IP addresses involved in this finding.
        confidence: Confidence score 0.0–1.0.
        analyzer_source: Which analyzer produced this (``"ollama"``, ``"trafficllm"``, ``"heuristic"``).
        attack_chain_stage: Kill-chain phase (``"initial_access"``, ``"execution"``, etc.).
        raw_data: Arbitrary additional data from the analyzer.
    """

    id: str
    job_id: str

    # MITRE ATT&CK linkage
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None

    # Classification
    classification: Optional[str] = None  # malware family name
    severity: FindingSeverity

    # Human-readable content
    title: str
    description: str
    evidence: List[str] = Field(default_factory=list)
    affected_hosts: List[str] = Field(default_factory=list)

    # Scoring and provenance
    confidence: float = 0.0
    analyzer_source: str  # "ollama", "trafficllm", "heuristic"
    attack_chain_stage: Optional[str] = None

    # Extensible payload
    raw_data: Dict[str, Any] = Field(default_factory=dict)
