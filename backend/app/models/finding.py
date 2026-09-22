"""Finding model (§12.5)."""

import json

from sqlalchemy import Column, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint

from backend.app.database_v2 import Base
from backend.app.services import mnemos_indexing  # noqa: F401; post-commit change hooks


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

    # Correlation handles — let uploaded logs (C2, EVTX, router) match a finding
    # temporally. Sensors already emit ts/host_ip on finding records; these
    # columns stop that from being discarded at normalization time.
    ts = Column(String, nullable=True)          # ISO-8601, when the evidence occurred
    src_ip = Column(String, nullable=True)
    dest_ip = Column(String, nullable=True)

    # Evidence lifecycle — see EvidenceStatus in schemas/common.py.
    # "confirmed" means an uploaded ground-truth log (e.g. a C2 operator log)
    # independently attests to this detection.
    evidence_status = Column(String, nullable=False, default="observed", server_default="observed")
    corroboration_score = Column(Float, nullable=False, default=0.0, server_default="0.0")
    corroborating_sources_json = Column(Text, nullable=True)  # JSON list of source_system names

    # Investigation Queue: analyst review status
    analyst_status = Column(String, nullable=True, default="unreviewed")  # unreviewed, confirmed, false_positive, needs_review, deferred
    analyst_notes = Column(Text, nullable=True)
    reviewed_at = Column(String, nullable=True)  # ISO-8601 timestamp
    reviewer_id = Column(String, nullable=True)  # analyst identifier who last changed status

    __table_args__ = (
        UniqueConstraint("job_id", "finding_id"),
        Index("idx_findings_job", "job_id"),
        Index("idx_findings_severity", "job_id", "severity"),
        Index("idx_findings_sensor", "job_id", "sensor"),
        Index("idx_findings_analyst_status", "job_id", "analyst_status"),
        Index("idx_findings_evidence_status", "job_id", "evidence_status"),
    )

    @property
    def corroborating_sources(self) -> list[str]:
        """Decoded list of uploaded log sources that attest to this finding."""
        if not self.corroborating_sources_json:
            return []
        try:
            value = json.loads(self.corroborating_sources_json)
        except (ValueError, TypeError):
            return []
        return value if isinstance(value, list) else []

    def __repr__(self) -> str:
        return f"<Finding {self.finding_id} severity={self.severity} evidence={self.evidence_status}>"
