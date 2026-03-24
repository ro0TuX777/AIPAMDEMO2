"""Alert model (§12.5)."""

from sqlalchemy import Column, ForeignKey, Index, Integer, String, Text, UniqueConstraint  # noqa: F401

from backend.app.database_v2 import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    alert_id = Column(String, nullable=False)
    host_ip = Column(String, nullable=False)
    community_id = Column(String, nullable=True)
    severity = Column(String, nullable=False)
    engine = Column(String, nullable=True)
    signature = Column(Text, nullable=False)
    category = Column(String, nullable=True)
    sid = Column(String, nullable=True)
    src_ip = Column(String, nullable=True)
    src_port = Column(Integer, nullable=True)
    dest_ip = Column(String, nullable=True)
    dest_port = Column(Integer, nullable=True)
    proto = Column(String, nullable=True)
    refs_json = Column(Text, nullable=True)   # JSON array
    tags_json = Column(Text, nullable=True)   # JSON array
    ts = Column(String, nullable=False)
    pcap_label = Column(String, nullable=True)  # which PCAP generated this alert

    # Investigation Queue: analyst review status
    analyst_status = Column(String, nullable=True, default="unreviewed")  # unreviewed, confirmed, false_positive, deferred
    analyst_notes = Column(Text, nullable=True)
    reviewed_at = Column(String, nullable=True)  # ISO-8601 timestamp

    __table_args__ = (
        UniqueConstraint("job_id", "alert_id"),
        Index("idx_alerts_job_host", "job_id", "host_ip"),
        Index("idx_alerts_community", "job_id", "community_id"),
        Index("idx_alerts_severity", "job_id", "severity"),
        Index("idx_alerts_analyst_status", "job_id", "analyst_status"),
    )

    def __repr__(self) -> str:
        return f"<Alert {self.alert_id} severity={self.severity}>"

