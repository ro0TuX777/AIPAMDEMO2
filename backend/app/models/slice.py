"""IncidentSlice model — groups related alerts/findings into logical attack threads."""

from sqlalchemy import Column, Float, ForeignKey, Index, Integer, String, Text

from backend.app.database_v2 import Base


class IncidentSlice(Base):
    __tablename__ = "incident_slices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    slice_id = Column(String, nullable=False, unique=True)

    # Human-readable label describing the slice
    label = Column(Text, nullable=False)
    # Slice classification: "attack_thread", "recon_phase", "c2_session", "lateral", "exfil", "misc"
    slice_type = Column(String, nullable=False, default="attack_thread")

    # Severity: overall severity of the slice based on member evidence
    severity = Column(String, nullable=False, default="medium")
    # Confidence: how strongly the grouping holds together
    confidence = Column(Float, nullable=False, default=0.5)

    # Grouping criteria that formed this slice
    # JSON array of community_id values that link members
    community_ids_json = Column(Text, nullable=True)
    # JSON array of host IPs involved
    host_ips_json = Column(Text, nullable=True)

    # Time boundaries of the slice
    time_start = Column(String, nullable=True)
    time_end = Column(String, nullable=True)

    # Member evidence (JSON arrays of IDs)
    alert_ids_json = Column(Text, nullable=True)     # ["A-001", "A-003"]
    finding_ids_json = Column(Text, nullable=True)    # ["F-101", "F-102"]
    ioc_ids_json = Column(Text, nullable=True)        # ["IOC-001"]
    connection_ids_json = Column(Text, nullable=True)  # ["conn-42"]

    # Summary: brief narrative of what this slice represents
    summary = Column(Text, nullable=True)
    # Rank within the job (1 = most significant)
    rank = Column(Integer, nullable=False, default=0)

    created_at = Column(String, nullable=False)

    __table_args__ = (
        Index("idx_slices_job", "job_id"),
        Index("idx_slices_rank", "job_id", "rank"),
        Index("idx_slices_severity", "job_id", "severity"),
    )

    def __repr__(self) -> str:
        return f"<IncidentSlice {self.slice_id} type={self.slice_type} severity={self.severity}>"

