"""TimelineEvent model (§12.5)."""

from sqlalchemy import Column, ForeignKey, Index, Integer, String, Text

from backend.app.database_v2 import Base


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    ts = Column(String, nullable=False)
    type = Column(String, nullable=False)
    severity = Column(String, nullable=True)
    title = Column(Text, nullable=False)
    details_json = Column(Text, nullable=True)  # JSON object
    pcap_label = Column(String, nullable=True)  # which PCAP generated this event

    __table_args__ = (
        Index("idx_timeline_job", "job_id"),
        Index("idx_timeline_ts", "job_id", "ts"),
        Index("idx_timeline_type", "job_id", "type"),
    )

    def __repr__(self) -> str:
        return f"<TimelineEvent {self.ts} type={self.type}>"

