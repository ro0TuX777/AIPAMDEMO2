"""Report model — generated executive and analyst reports per job."""

from sqlalchemy import Column, Float, ForeignKey, Index, Integer, String, Text

from backend.app.database_v2 import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    report_id = Column(String, nullable=False, unique=True)

    # Report mode: "executive" or "analyst"
    mode = Column(String, nullable=False, default="analyst")
    # PCAP phase label for temporal analysis (e.g. "before", "after")
    pcap_label = Column(String, nullable=True)

    # Report metadata
    title = Column(Text, nullable=False)
    threat_level = Column(String, nullable=False, default="info")  # critical, high, medium, low, info
    confidence = Column(Float, nullable=False, default=0.5)

    # Rendered content (stored as markdown and JSON)
    content_markdown = Column(Text, nullable=False, default="")
    content_json = Column(Text, nullable=False, default="{}")  # structured sections as JSON

    # Section counts (for quick summary)
    theory_count = Column(Integer, nullable=False, default=0)
    slice_count = Column(Integer, nullable=False, default=0)
    finding_count = Column(Integer, nullable=False, default=0)
    alert_count = Column(Integer, nullable=False, default=0)
    ioc_count = Column(Integer, nullable=False, default=0)
    host_count = Column(Integer, nullable=False, default=0)
    annotation_count = Column(Integer, nullable=False, default=0)

    # Evidence references (JSON array of all referenced IDs)
    evidence_refs_json = Column(Text, nullable=True)

    created_at = Column(String, nullable=False)

    __table_args__ = (
        Index("idx_reports_job", "job_id"),
        Index("idx_reports_mode", "job_id", "mode"),
        Index("idx_reports_pcap_label", "job_id", "pcap_label"),
    )

    def __repr__(self) -> str:
        return f"<Report {self.report_id} mode={self.mode} threat={self.threat_level}>"

