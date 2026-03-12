"""IOC model (§12.5)."""

from sqlalchemy import Column, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint

from backend.app.database_v2 import Base


class Ioc(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(String, nullable=False)
    ioc_type = Column(String, nullable=False)
    value = Column(Text, nullable=False)
    severity = Column(String, nullable=True)
    confidence = Column(Float, nullable=True)
    source_sensor = Column(String, nullable=True)
    sources_json = Column(Text, nullable=True)  # JSON array
    context = Column(Text, nullable=True)  # Human-readable reason for this IOC
    pcap_label = Column(String, nullable=True)  # which PCAP generated this IOC

    __table_args__ = (
        UniqueConstraint("job_id", "ioc_id"),
        Index("idx_iocs_job", "job_id"),
        Index("idx_iocs_type", "job_id", "ioc_type"),
        Index("idx_iocs_value", "value"),
    )

    def __repr__(self) -> str:
        return f"<Ioc {self.ioc_type}={self.value}>"

