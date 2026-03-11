"""JobSensor model (§12.5)."""

from sqlalchemy import Column, ForeignKey, Index, Integer, String, Text, UniqueConstraint

from backend.app.database_v2 import Base


class JobSensor(Base):
    __tablename__ = "job_sensors"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    sensor = Column(String, nullable=False)
    status = Column(String, nullable=False, default="pending")
    started_at = Column(String, nullable=True)
    completed_at = Column(String, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    error = Column(Text, nullable=True)
    error_code = Column(String, nullable=True)
    timeout_seconds = Column(Integer, nullable=True)
    provenance_json = Column(Text, nullable=True)
    stats_json = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("job_id", "sensor"),
        Index("idx_job_sensors_job", "job_id"),
    )

    def __repr__(self) -> str:
        return f"<JobSensor {self.job_id}/{self.sensor} status={self.status}>"

