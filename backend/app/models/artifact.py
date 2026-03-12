"""Artifact model (§12.5)."""

from sqlalchemy import Column, ForeignKey, Index, Integer, String, Text, UniqueConstraint

from backend.app.database_v2 import Base


class Artifact(Base):
    __tablename__ = "artifacts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    artifact_id = Column(String, nullable=False)
    type = Column(String, nullable=False)
    status = Column(String, nullable=False, default="available")
    filename = Column(Text, nullable=True)
    sha256 = Column(String, nullable=True)
    size_bytes = Column(Integer, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(String, nullable=False)

    __table_args__ = (
        UniqueConstraint("job_id", "artifact_id"),
        Index("idx_artifacts_job", "job_id"),
    )

    def __repr__(self) -> str:
        return f"<Artifact {self.artifact_id} type={self.type} status={self.status}>"

