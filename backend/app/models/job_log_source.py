"""JobLogSource model — tracks individual log files associated with a job.

Mirrors JobPcap but for log/telemetry files, providing traceability
so analysts can see exactly which log files were uploaded, their phase
labels, source systems, and integrity hashes.
"""

from sqlalchemy import Column, ForeignKey, Index, Integer, String, Text

from backend.app.database_v2 import Base


class JobLogSource(Base):
    """A single log file associated with a job (uploaded directly or extracted from archive)."""

    __tablename__ = "job_log_sources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    upload_id = Column(String, nullable=True)           # upload record that contained this file (if any)
    label = Column(String, nullable=True)               # phase label: "before", "during", "after", or custom
    filename = Column(Text, nullable=False)              # relative path within telemetry dir (or original filename)
    source_system = Column(String, nullable=True)        # e.g. "sysmon", "windows_evtx", "paloalto"
    parser_hint = Column(String, nullable=True)          # suggested parser name
    ordinal = Column(Integer, nullable=False, default=0) # display/processing order
    size_bytes = Column(Integer, nullable=True)
    sha256 = Column(String, nullable=True)

    __table_args__ = (
        Index("idx_job_log_sources_job", "job_id"),
        Index("idx_job_log_sources_ordinal", "job_id", "ordinal"),
    )

    def __repr__(self) -> str:
        return f"<JobLogSource job={self.job_id} file={self.filename} label={self.label}>"

