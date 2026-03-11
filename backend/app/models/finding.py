"""Finding model (§12.5)."""

from sqlalchemy import Column, ForeignKey, Index, Integer, String, Text, UniqueConstraint

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

    __table_args__ = (
        UniqueConstraint("job_id", "finding_id"),
        Index("idx_findings_job", "job_id"),
        Index("idx_findings_severity", "job_id", "severity"),
        Index("idx_findings_sensor", "job_id", "sensor"),
    )

    def __repr__(self) -> str:
        return f"<Finding {self.finding_id} severity={self.severity}>"

