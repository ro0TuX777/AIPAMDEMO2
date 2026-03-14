"""Connection model (§12.5)."""

from sqlalchemy import Column, Float, ForeignKey, Index, Integer, String, UniqueConstraint

from backend.app.database_v2 import Base


class Connection(Base):
    __tablename__ = "connections"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    connection_id = Column(String, nullable=False)
    community_id = Column(String, nullable=True)
    host_ip = Column(String, nullable=False)
    src_ip = Column(String, nullable=False)
    src_port = Column(Integer, nullable=True)
    dest_ip = Column(String, nullable=False)
    dest_port = Column(Integer, nullable=True)
    proto = Column(String, nullable=False)
    duration_seconds = Column(Float, nullable=True)
    bytes_sent = Column(Integer, nullable=True)
    bytes_recv = Column(Integer, nullable=True)
    service = Column(String, nullable=True)
    ts = Column(String, nullable=False)
    pcap_label = Column(String, nullable=True)  # which PCAP generated this connection

    __table_args__ = (
        UniqueConstraint("job_id", "connection_id"),
        Index("idx_conn_job_host", "job_id", "host_ip"),
        Index("idx_conn_community", "job_id", "community_id"),
        Index("idx_conn_ts", "job_id", "ts"),
    )

    def __repr__(self) -> str:
        return f"<Connection {self.src_ip}:{self.src_port} -> {self.dest_ip}:{self.dest_port}>"

