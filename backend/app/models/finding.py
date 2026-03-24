"""Finding model (§12.5)."""

from sqlalchemy import Column, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint

from backend.app.database_v2 import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    finding_id = Column(String, nullable=False)
    sensor = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    category = Column(String, nullable=True)
    title = Column(Text, nullable=False)
    summary = Column(Text, nullable=True)
    community_id = Column(String, nullable=True)
    evidence_json = Column(Text, nullable=True)
    pcap_label = Column(String, nullable=True)  # which PCAP generated this finding
    feedback = Column(String, nullable=True)    # confirmed, false_positive, false_negative
    explanation_feedback = Column(String, nullable=True)  # useful, not_useful
    confidence = Column(Float, nullable=False, default=0.0, server_default="0.0")  # 0.0–1.0

    # Investigation Queue: analyst review status
    analyst_status = Column(String, nullable=True, default="unreviewed")  # unreviewed, confirmed, false_positive, deferred
    analyst_notes = Column(Text, nullable=True)
    reviewed_at = Column(String, nullable=True)  # ISO-8601 timestamp

    __table_args__ = (
        UniqueConstraint("job_id", "finding_id"),
        Index("idx_findings_job", "job_id"),
        Index("idx_findings_severity", "job_id", "severity"),
        Index("idx_findings_sensor", "job_id", "sensor"),
        Index("idx_findings_analyst_status", "job_id", "analyst_status"),
    )

    def __repr__(self) -> str:
        return f"<Finding {self.finding_id} severity={self.severity}>"

