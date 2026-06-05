"""TemporalCorrelation model — cross-source temporal matches.

Stores links between log-derived NormalizedEvents and PCAP-derived entities
(Alerts, Connections, Findings) that share an IP within a time window.
"""

import json

from sqlalchemy import Column, Float, ForeignKey, Index, Integer, String, Text

from backend.app.database_v2 import Base


class TemporalCorrelation(Base):
    """A temporal match between a log event and a PCAP-derived event."""

    __tablename__ = "temporal_correlations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)

    # Log side (NormalizedEvent)
    log_event_id = Column(String, nullable=False, index=True)     # NE-xxx
    log_source = Column(String, nullable=True)                     # source_system
    log_source_filename = Column(String, nullable=True)            # origin log file
    log_event_type = Column(String, nullable=True)                 # event type
    log_timestamp = Column(String, nullable=False)                 # ISO-8601
    log_summary = Column(Text, nullable=True)                      # raw line / key=value digest

    # PCAP side (Alert, Connection, or Finding)
    pcap_entity_type = Column(String, nullable=False)              # "alert" | "connection" | "finding"
    pcap_entity_id = Column(String, nullable=False, index=True)    # alert_id, connection_id, or finding_id
    pcap_summary = Column(Text, nullable=True)                     # human-readable summary
    pcap_timestamp = Column(String, nullable=False)                # ISO-8601

    # Match metadata
    shared_ip = Column(String, nullable=False)                     # the IP both events reference
    time_delta_seconds = Column(Float, nullable=False)             # abs(log_ts - pcap_ts) in seconds (raw)
    match_score = Column(Float, nullable=False, default=0.0)       # 0.0–1.0 composite score
    match_type = Column(String, nullable=False, default="ip_temporal")  # "community_id" | "five_tuple" | "ip_temporal"

    # Enhanced correlation metadata (multi-key, label-aware, clock-aligned)
    community_id = Column(String, nullable=True)                   # shared community_id when matched on it
    match_keys_json = Column(Text, nullable=True)                  # JSON array of all keys that matched
    log_label = Column(String, nullable=True)                      # phase label of the log event
    pcap_label = Column(String, nullable=True)                     # phase label of the PCAP entity
    clock_offset_seconds = Column(Float, nullable=True, default=0.0)  # estimated log→PCAP clock offset applied
    adjusted_time_delta_seconds = Column(Float, nullable=True)     # abs delta after offset alignment
    confidence_band = Column(String, nullable=True)               # "high" | "medium" | "low"

    __table_args__ = (
        Index("idx_tc_job", "job_id"),
        Index("idx_tc_job_score", "job_id", "match_score"),
        Index("idx_tc_log_event", "job_id", "log_event_id"),
        Index("idx_tc_pcap_entity", "job_id", "pcap_entity_type", "pcap_entity_id"),
    )

    @property
    def match_keys(self) -> list[str]:
        """Decoded list of correlation keys that matched (from match_keys_json)."""
        if not self.match_keys_json:
            return []
        try:
            value = json.loads(self.match_keys_json)
        except (ValueError, TypeError):
            return []
        return value if isinstance(value, list) else []

    def __repr__(self) -> str:
        return (
            f"<TemporalCorrelation {self.log_event_id} ↔ {self.pcap_entity_type}:{self.pcap_entity_id} "
            f"type={self.match_type} Δ{self.time_delta_seconds:.1f}s score={self.match_score:.2f}>"
        )
