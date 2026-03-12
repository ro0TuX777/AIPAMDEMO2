"""DnsQuery model (§12.5)."""

from sqlalchemy import Column, ForeignKey, Index, Integer, String, Text, UniqueConstraint

from backend.app.database_v2 import Base


class DnsQuery(Base):
    __tablename__ = "dns_queries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    dns_id = Column(String, nullable=False)
    host_ip = Column(String, nullable=False)
    community_id = Column(String, nullable=True)
    src_ip = Column(String, nullable=False)
    query = Column(Text, nullable=False)
    qtype = Column(String, nullable=True)
    answers_json = Column(Text, nullable=True)  # JSON array
    rcode = Column(String, nullable=True)
    ttl_seconds = Column(Integer, nullable=True)
    dest_ip = Column(String, nullable=True)
    ts = Column(String, nullable=False)
    pcap_label = Column(String, nullable=True)  # which PCAP generated this query

    __table_args__ = (
        UniqueConstraint("job_id", "dns_id"),
        Index("idx_dns_job_host", "job_id", "host_ip"),
        Index("idx_dns_community", "job_id", "community_id"),
        Index("idx_dns_query", "job_id", "query"),
    )

    def __repr__(self) -> str:
        return f"<DnsQuery {self.query} qtype={self.qtype}>"

