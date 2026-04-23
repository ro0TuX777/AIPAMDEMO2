"""TemporalCorrelation model — cross-source temporal matches.

Stores links between log-derived NormalizedEvents and PCAP-derived entities
(Alerts, Connections, Findings) that share an IP within a time window.
"""

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
    time_delta_seconds = Column(Float, nullable=False)             # abs(log_ts - pcap_ts) in seconds
    match_score = Column(Float, nullable=False, default=0.0)       # 0.0–1.0 proximity score
    match_type = Column(String, nullable=False, default="ip_temporal")  # "ip_temporal" | "community_id_temporal"

    __table_args__ = (
        Index("idx_tc_job", "job_id"),
        Index("idx_tc_job_score", "job_id", "match_score"),
        Index("idx_tc_log_event", "job_id", "log_event_id"),
        Index("idx_tc_pcap_entity", "job_id", "pcap_entity_type", "pcap_entity_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<TemporalCorrelation {self.log_event_id} ↔ {self.pcap_entity_type}:{self.pcap_entity_id} "
            f"Δ{self.time_delta_seconds:.1f}s score={self.match_score:.2f}>"
        )
