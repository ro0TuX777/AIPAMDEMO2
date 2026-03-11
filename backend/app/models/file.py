"""File (extracted file) model (§12.5)."""

from sqlalchemy import Column, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint

from backend.app.database_v2 import Base


class File(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    file_id = Column(String, nullable=False)
    filename = Column(String, nullable=True)
    host_ip = Column(String, nullable=True)
    community_id = Column(String, nullable=True)
    sha256 = Column(String, nullable=False)
    md5 = Column(String, nullable=True)
    ssdeep = Column(String, nullable=True)
    size_bytes = Column(Integer, nullable=False)
    mime = Column(String, nullable=True)
    entropy = Column(Float, nullable=True)
    source = Column(String, nullable=True)
    extracted_path = Column(Text, nullable=True)
    yara_matches_json = Column(Text, nullable=True)  # JSON array
    download_artifact_id = Column(String, nullable=True)
    ts = Column(String, nullable=True)
    pcap_label = Column(String, nullable=True)  # which PCAP generated this file

    __table_args__ = (
        UniqueConstraint("job_id", "file_id"),
        Index("idx_files_job", "job_id"),
        Index("idx_files_sha256", "job_id", "sha256"),
        Index("idx_files_community", "job_id", "community_id"),
    )

    def __repr__(self) -> str:
        return f"<File {self.sha256[:12]}... size={self.size_bytes}>"

    @property
    def yara_matches(self) -> list[str]:
        """Parse yara_matches_json into a list of rule names."""
        if not self.yara_matches_json:
            return []
        try:
            import json
            res = json.loads(self.yara_matches_json)
            return res if isinstance(res, list) else []
        except (json.JSONDecodeError, TypeError):
            return []

