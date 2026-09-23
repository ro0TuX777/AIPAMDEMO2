"""Job model (§12.5)."""

from sqlalchemy import BigInteger, Column, Index, String, Integer, Text

from backend.app.database_v2 import Base


TERMINAL_JOB_STATUSES = frozenset({"completed", "completed_with_errors", "failed", "canceled", "deleted"})


class Job(Base):
    __tablename__ = "jobs"

    job_id = Column(String, primary_key=True)
    job_name = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    status = Column(
        String,
        nullable=False,
        default="queued",
        # CHECK enforced at DB level via migration
    )
    execution_profile = Column(String, nullable=False)
    priority = Column(String, nullable=False, default="normal")
    source_type = Column(String, nullable=False, default="pcap")  # SourceType enum value
    exercise_id = Column(String, nullable=True)                   # links to exercise/campaign
    upload_id = Column(String, nullable=True)
    pcap_filename = Column(Text, nullable=True)
    pcap_size_bytes = Column(Integer, nullable=True)
    pcap_sha256 = Column(String, nullable=True)
    source_manifest_json = Column(Text, nullable=True)            # JSON SourceManifest
    error_summary = Column(Text, nullable=True)
    created_at = Column(String, nullable=False)
    started_at = Column(String, nullable=True)
    completed_at = Column(String, nullable=True)
    metrics_json = Column(Text, nullable=True)  # JSON blob

    celery_task_id = Column(String, nullable=True)
    execution_attempt = Column(Integer, nullable=False, default=0, server_default="0")
    run_token = Column(String, nullable=True)
    worker_id = Column(String, nullable=True)
    worker_container_id = Column(String, nullable=True)
    executor_pid = Column(Integer, nullable=True)
    executor_pid_start_ticks = Column(BigInteger, nullable=True)
    executor_boot_id = Column(String, nullable=True)
    heartbeat_at = Column(String, nullable=True)
    dispatched_at = Column(String, nullable=True)
    cancel_requested_at = Column(String, nullable=True)
    cancel_force_at = Column(String, nullable=True)
    cancel_deadline_at = Column(String, nullable=True)
    cancel_escalation_token = Column(String, nullable=True)
    cancel_escalation_started_at = Column(String, nullable=True)
    artifact_layout_version = Column(Integer, nullable=False, default=1, server_default="2")
    accepted_run_manifest_json = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_jobs_celery_task_id", "celery_task_id"),
        Index("idx_jobs_status", "status"),
        Index("idx_jobs_created", "created_at"),
        Index("idx_jobs_profile", "execution_profile"),
    )

    def __repr__(self) -> str:
        return f"<Job {self.job_id} status={self.status}>"

