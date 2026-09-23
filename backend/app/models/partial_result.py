"""Progressive V2 analysis snapshots, owned by the authoritative job row."""
from sqlalchemy import Column, DateTime, ForeignKey, JSON, String

from backend.app.database_v2 import Base


class PartialResult(Base):
    __tablename__ = "partial_results"

    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), primary_key=True)
    result = Column(JSON, nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)
