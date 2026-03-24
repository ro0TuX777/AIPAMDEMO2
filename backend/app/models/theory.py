"""Theory of the Case model — ranked hypotheses per job/host."""

from sqlalchemy import Column, Float, ForeignKey, Index, Integer, String, Text

from backend.app.database_v2 import Base


class Theory(Base):
    __tablename__ = "theories"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    theory_id = Column(String, nullable=False, unique=True)

    # Scope: "job" or "host"
    scope_type = Column(String, nullable=False, default="job")
    # For host-scoped theories, the IP address; NULL for job-scoped
    scope_id = Column(String, nullable=True)

    # Hypothesis details
    label = Column(Text, nullable=False)
    hypothesis_type = Column(String, nullable=False)  # c2, malware_delivery, recon, lateral_movement, exfiltration, admin_tools, benign, inconclusive
    score = Column(Float, nullable=False, default=0.0)  # 0.0–1.0 deterministic score
    confidence = Column(String, nullable=False, default="low")  # low, medium, high
    rank = Column(Integer, nullable=False, default=0)  # 1-based rank within scope

    # Evidence references (JSON arrays of IDs)
    supporting_evidence_json = Column(Text, nullable=True)  # ["F-102", "A-55", "IOC-21"]
    contradicting_evidence_json = Column(Text, nullable=True)  # ["F-220"]

    # Score component breakdown (JSON dict)
    score_breakdown_json = Column(Text, nullable=True)  # {"findings": 0.48, "alerts": 0.18, "iocs": 0.12, "finding_count": 3, ...}

    # LLM-generated explanations
    explanation = Column(Text, nullable=True)
    next_steps_json = Column(Text, nullable=True)  # JSON array of strings

    pcap_label = Column(String, nullable=True)  # which PCAP phase generated this theory (e.g. "before", "after")

    created_at = Column(String, nullable=False)

    # Investigation Queue: analyst review status
    analyst_status = Column(String, nullable=True, default="unreviewed")  # unreviewed, confirmed, false_positive, deferred
    analyst_notes = Column(Text, nullable=True)
    reviewed_at = Column(String, nullable=True)  # ISO-8601 timestamp

    __table_args__ = (
        Index("idx_theories_job", "job_id"),
        Index("idx_theories_scope", "job_id", "scope_type", "scope_id"),
        Index("idx_theories_rank", "job_id", "scope_type", "scope_id", "rank"),
        Index("idx_theories_pcap_label", "job_id", "pcap_label"),
        Index("idx_theories_analyst_status", "job_id", "analyst_status"),
    )

    def __repr__(self) -> str:
        return f"<Theory {self.theory_id} type={self.hypothesis_type} score={self.score}>"

