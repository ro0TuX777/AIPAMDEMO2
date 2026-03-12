"""TlsSession model (§12.5)."""

from sqlalchemy import Column, ForeignKey, Index, Integer, String, UniqueConstraint

from backend.app.database_v2 import Base


class TlsSession(Base):
    __tablename__ = "tls_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    tls_id = Column(String, nullable=False)
    host_ip = Column(String, nullable=False)
    community_id = Column(String, nullable=True)
    src_ip = Column(String, nullable=False)
    dest_ip = Column(String, nullable=False)
    dest_port = Column(Integer, nullable=True)
    sni = Column(String, nullable=True)
    ja3 = Column(String, nullable=True)
    ja3s = Column(String, nullable=True)
    alpn = Column(String, nullable=True)
    version = Column(String, nullable=True)
    cert_subject = Column(String, nullable=True)
    cert_issuer = Column(String, nullable=True)
    cert_fingerprint_sha1 = Column(String, nullable=True)
    ts = Column(String, nullable=False)
    pcap_label = Column(String, nullable=True)  # which PCAP generated this session

    __table_args__ = (
        UniqueConstraint("job_id", "tls_id"),
        Index("idx_tls_job_host", "job_id", "host_ip"),
        Index("idx_tls_community", "job_id", "community_id"),
        Index("idx_tls_sni", "job_id", "sni"),
        Index("idx_tls_ja3", "job_id", "ja3"),
    )

    def __repr__(self) -> str:
        return f"<TlsSession sni={self.sni} ja3={self.ja3}>"

