"""Core interfaces for AIPAM forensic analysis.

This module defines the input/output contracts required by the
Lead Architect for all analysis components:

- AnalysisContext: Standardized input containing job metadata,
  paths to extracted logs, and high-priority flow/alert IDs.
- Finding: Required output with MITRE technique ID, confidence,
  raw evidence snippet, and rationale.
- ForensicAnalyzer: ABC that all analysis backends must implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AnalysisContext(BaseModel):
    """Input contract for analysis components.

    Provides everything an analyzer needs to perform forensic analysis:
    job metadata, paths to extracted log files, and pre-selected
    high-priority flow/alert IDs from the Evidence Store.

    Attributes:
        job_id: Unique analysis job identifier.
        exercise_id: Exercise or scenario identifier for context.
        mode: Analysis mode — ``"baseline_vs_exploit"`` or ``"single_window"``.
        zeek_log_path: Path to extracted Zeek conn.log JSON.
        suricata_log_path: Path to extracted Suricata eve.json.
        high_priority_flow_ids: Pre-selected FlowDB IDs scored as interesting.
        alert_ids: AlertDB IDs to include in analysis context.
        metadata: Additional metadata (connector type, time ranges, etc.).
    """

    job_id: str
    exercise_id: str
    mode: str  # "baseline_vs_exploit" | "single_window"

    # Paths to extracted log files
    zeek_log_path: Optional[Path] = None
    suricata_log_path: Optional[Path] = None

    # Pre-selected IDs from the Evidence Store
    high_priority_flow_ids: List[str] = Field(default_factory=list)
    alert_ids: List[str] = Field(default_factory=list)

    # Extensible metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """Output contract — what every analyzer MUST return.

    Each Finding represents one discrete forensic observation with
    mandatory fields for MITRE ATT&CK mapping at granular level.

    Attributes:
        mitre_technique_id: ATT&CK technique ID (e.g. ``"T1071.001"``).
        confidence_score: Analyzer confidence 0.0–1.0.
        raw_evidence_snippet: The actual network data that triggered this finding.
        rationale: Explanation of why this data indicates the technique.
        severity: Severity level (critical/high/medium/low/info).
        affected_hosts: IP addresses involved.
        classification: Malware family name if applicable.
        attack_chain_stage: Kill-chain phase if applicable.
    """

    mitre_technique_id: str  # Required — e.g. "T1071.001"
    confidence_score: float  # Required — 0.0 to 1.0
    raw_evidence_snippet: str  # Required — actual data excerpt
    rationale: str  # Required — LLM's reasoning

    severity: str  # "critical" / "high" / "medium" / "low" / "info"
    affected_hosts: List[str] = Field(default_factory=list)
    classification: Optional[str] = None  # Malware family
    attack_chain_stage: Optional[str] = None  # Kill-chain phase

    # Phase 2 additions for anti-hallucination guardrails
    cited_flow_ids: List[str] = Field(default_factory=list)
    requires_review: bool = False
    review_reason: Optional[str] = None


class ForensicAnalyzer(ABC):
    """Contract every analysis backend must implement.

    Analyzers receive a standardized AnalysisContext and return a list
    of Finding objects.  This enables plug-and-play swapping of AI
    backends (Ollama, TrafficLLM, vLLM, TGI, heuristic engines).

    Example::

        class OllamaForensicAnalyzer(ForensicAnalyzer):
            async def analyze(self, ctx: AnalysisContext) -> List[Finding]:
                # Convert context to LLM prompt, call model, parse response
                ...

            async def health_check(self) -> bool:
                return await self._client.ping()

            @property
            def name(self) -> str:
                return "Ollama Llama 3.1 8B"
    """

    @abstractmethod
    async def analyze(self, ctx: AnalysisContext) -> List[Finding]:
        """Perform forensic analysis using the given context.

        Args:
            ctx: Standardized analysis context with job metadata,
                 log paths, and pre-selected high-priority data.

        Returns:
            A list of Finding objects with all required fields populated.
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check whether the analysis backend is reachable.

        Returns:
            True if the backend is available and ready.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this analyzer."""
        ...
