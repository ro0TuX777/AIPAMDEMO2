"""GlobalHost model to track host persistence across jobs."""

from sqlalchemy import Column, Integer, String, Text, Boolean, Index
from backend.app.database_v2 import Base

class GlobalHost(Base):
    __tablename__ = "global_hosts"

    ip = Column(String, primary_key=True)
    hostname = Column(String, nullable=True)
    first_seen = Column(String, nullable=True)
    last_seen = Column(String, nullable=True)
    job_count = Column(Integer, default=0)
    total_alerts = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    seen_as_internal = Column(Boolean, default=False)
    roles_json = Column(Text, nullable=True)  # JSON list of unique roles
    history_json = Column(Text, nullable=True)  # JSON list of {job_id, ts, role, alert_count, finding_count}

    __table_args__ = (
        Index("idx_global_hosts_last_seen", "last_seen"),
    )

    def __repr__(self) -> str:
        return f"<GlobalHost {self.ip} jobs={self.job_count}>"
