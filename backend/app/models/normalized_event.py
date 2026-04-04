"""Normalized event model — multi-source telemetry events with provenance.

This table stores events from any telemetry source (PCAP, logs, C2, NetFlow)
in a common schema, enabling cross-source correlation and fusion.
"""

from sqlalchemy import Column, Float, ForeignKey, Index, Integer, String, Text

from backend.app.database_v2 import Base


class NormalizedEvent(Base):
    """A single normalized telemetry event from any source."""

    __tablename__ = "normalized_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String, nullable=False, unique=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)

    # Event classification
    event_type = Column(String, nullable=False)        # NormalizedEventType value
    timestamp = Column(String, nullable=False)          # ISO-8601

    # Provenance — where this event came from
    source_type = Column(String, nullable=False)        # SourceType value
    source_system = Column(String, nullable=True)       # e.g. "sysmon", "paloalto"
    source_filename = Column(String, nullable=True)
    parser_name = Column(String, nullable=True)
    parser_version = Column(String, nullable=True)
    raw_ref = Column(Text, nullable=True)               # pointer to original record

    # Evidence lifecycle
    evidence_status = Column(String, nullable=False, default="observed")
    corroboration_score = Column(Float, nullable=True, default=0.0)

    # Correlation keys (denormalized for fast lookup)
    community_id = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    username = Column(String, nullable=True)
    session_id = Column(String, nullable=True)
    process_guid = Column(String, nullable=True)
    src_ip = Column(String, nullable=True)
    src_port = Column(Integer, nullable=True)
    dest_ip = Column(String, nullable=True)
    dest_port = Column(Integer, nullable=True)
    proto = Column(String, nullable=True)
    exercise_id = Column(String, nullable=True)

    # Flexible payload
    data_json = Column(Text, nullable=True)             # JSON blob for event-specific fields
    correlation_keys_json = Column(Text, nullable=True)  # JSON dict of all correlation keys
    tags_json = Column(Text, nullable=True)             # JSON array of tags

    # Label for multi-pcap / multi-phase analysis
    pcap_label = Column(String, nullable=True)

    __table_args__ = (
        Index("idx_ne_job_type", "job_id", "event_type"),
        Index("idx_ne_job_ts", "job_id", "timestamp"),
        Index("idx_ne_community", "job_id", "community_id"),
        Index("idx_ne_hostname", "job_id", "hostname"),
        Index("idx_ne_username", "job_id", "username"),
        Index("idx_ne_src_ip", "job_id", "src_ip"),
        Index("idx_ne_dest_ip", "job_id", "dest_ip"),
        Index("idx_ne_evidence", "job_id", "evidence_status"),
        Index("idx_ne_exercise", "exercise_id"),
        Index("idx_ne_source_type", "job_id", "source_type"),
    )

    def __repr__(self) -> str:
        return f"<NormalizedEvent {self.event_id} type={self.event_type} status={self.evidence_status}>"

