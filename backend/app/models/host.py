"""Host model (§12.5)."""

from sqlalchemy import Column, ForeignKey, Index, Integer, String, Text, UniqueConstraint

from backend.app.database_v2 import Base


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    ip = Column(String, nullable=False)
    role = Column(String, nullable=True, default="unknown")
    conn_count = Column(Integer, default=0)
    bytes_sent = Column(Integer, nullable=True)
    bytes_recv = Column(Integer, nullable=True)
    alert_count = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    first_seen = Column(String, nullable=True)
    last_seen = Column(String, nullable=True)
    top_domains_json = Column(Text, nullable=True)
    top_services_json = Column(Text, nullable=True)
    dns_query_count = Column(Integer, nullable=True)
    tls_session_count = Column(Integer, nullable=True)
    alerts_by_severity_json = Column(Text, nullable=True)
    pcap_label = Column(String, nullable=True)  # which PCAP this host was observed in

    __table_args__ = (
        UniqueConstraint("job_id", "ip", "pcap_label"),
        Index("idx_hosts_job", "job_id"),
        Index("idx_hosts_role", "job_id", "role"),
    )

    def __repr__(self) -> str:
        return f"<Host {self.ip} job={self.job_id}>"

