"""ForensicData — Unified Internal Representation (IR) for forensic analysis.

This schema normalizes inputs from any source (Zeek, Suricata, PCAP,
Security Onion, Arkime) into a single structured object that any
analyzer can consume without knowing the data's origin.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ..models import (
    AlertRecord,
    AnomalyReportModel,
    ChangeSummary,
    EventRecord,
    FlowRecord,
    HostPairSummary,
    HostSummary,
    TimeWindow,
    TrafficLLMResult,
)


class ForensicData(BaseModel):
    """Unified internal representation for forensic analysis.

    Replaces the ad-hoc dictionary bundles previously passed between
    tasks.py, llm_chunking.py, and llm_client.py.  Every analyzer
    receives this single object regardless of the upstream data source.

    Attributes:
        job_id: The unique identifier for the analysis job.
        exercise_id: Combined exercise/PCAP identifier for context.
        mode: Analysis mode — ``"baseline_vs_exploit"`` or ``"single_window"``.
        flows: Parsed network flow records (from Zeek conn.log or similar).
        alerts: IDS/IPS alert records (from Suricata EVE or TrafficLLM).
        events: Protocol-level event records (DNS queries, HTTP requests, etc.).
        host_summaries_baseline: Per-host aggregated metrics for the baseline period.
        host_summaries_exploit: Per-host aggregated metrics for the exploit period.
        hostpair_summaries_baseline: Host-pair communication metrics (baseline).
        hostpair_summaries_exploit: Host-pair communication metrics (exploit).
        change_summaries: Deltas between baseline and exploit periods.
        time_ranges: Named time windows (``"baseline"``, ``"exploit"``, ``"window"``).
        raw_packet_samples: Scapy-extracted packet field strings matching training format.
        trafficllm_results: Optional classification results from TrafficLLM.
        anomaly_report: Optional heuristic zero-day anomaly detection report.
        pcap_filename: Stem of the primary PCAP file (used for refinement hints).
        source_metadata: Arbitrary metadata from the originating connector.
    """

    job_id: str
    exercise_id: str
    mode: str  # "baseline_vs_exploit" | "single_window"

    # Core parsed records
    flows: List[FlowRecord] = Field(default_factory=list)
    alerts: List[AlertRecord] = Field(default_factory=list)
    events: List[EventRecord] = Field(default_factory=list)

    # Aggregated summaries (baseline vs exploit)
    host_summaries_baseline: List[HostSummary] = Field(default_factory=list)
    host_summaries_exploit: List[HostSummary] = Field(default_factory=list)
    hostpair_summaries_baseline: List[HostPairSummary] = Field(default_factory=list)
    hostpair_summaries_exploit: List[HostPairSummary] = Field(default_factory=list)
    change_summaries: List[ChangeSummary] = Field(default_factory=list)

    # Time context
    time_ranges: Dict[str, TimeWindow] = Field(default_factory=dict)

    # Supplementary data
    raw_packet_samples: List[str] = Field(default_factory=list)
    trafficllm_results: Optional[TrafficLLMResult] = None
    anomaly_report: Optional[AnomalyReportModel] = None

    # Source context
    pcap_filename: Optional[str] = None
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
