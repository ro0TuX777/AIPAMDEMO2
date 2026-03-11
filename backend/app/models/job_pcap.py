"""JobPcap model — associates multiple PCAP uploads with a single job."""

from sqlalchemy import Column, ForeignKey, Index, Integer, String, Text

from backend.app.database_v2 import Base


class JobPcap(Base):
    __tablename__ = "job_pcaps"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    upload_id = Column(String, ForeignKey("uploads.upload_id"), nullable=False)
    label = Column(String, nullable=True)       # optional phase label: "before", "during", "after", or custom
    filename = Column(Text, nullable=False)      # original filename from upload
    ordinal = Column(Integer, nullable=False, default=0)  # display/processing order
    size_bytes = Column(Integer, nullable=True)
    sha256 = Column(String, nullable=True)

    __table_args__ = (
        Index("idx_job_pcaps_job", "job_id"),
        Index("idx_job_pcaps_ordinal", "job_id", "ordinal"),
    )

    def __repr__(self) -> str:
        return f"<JobPcap job={self.job_id} file={self.filename} label={self.label}>"

