"""ContextAnnotation model — per-host 'why unusual' annotations."""

from sqlalchemy import Column, Float, ForeignKey, Index, Integer, String, Text

from backend.app.database_v2 import Base


class ContextAnnotation(Base):
    __tablename__ = "context_annotations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    annotation_id = Column(String, nullable=False, unique=True)

    # Which host this annotation is about
    host_ip = Column(String, nullable=False)

    # What metric is unusual
    metric_name = Column(String, nullable=False)  # conn_count, bytes_sent, unique_destinations, unique_services, alert_rate, etc.
    metric_category = Column(String, nullable=False, default="traffic")  # traffic, protocol, dns, alert, behavioral

    # Baseline vs observed
    baseline_value = Column(Float, nullable=True)  # job-wide average/median for this metric
    observed_value = Column(Float, nullable=True)  # this host's actual value
    deviation_factor = Column(Float, nullable=True)  # how many std deviations or ratio vs baseline
    population_size = Column(Integer, nullable=True)  # how many hosts in the baseline

    # Severity and confidence
    severity = Column(String, nullable=False, default="info")  # critical, high, medium, low, info
    confidence = Column(Float, nullable=False, default=0.5)

    # Human-readable explanation
    title = Column(Text, nullable=False)  # e.g., "Unusually High Connection Count"
    description = Column(Text, nullable=False)  # e.g., "Host 10.0.0.5 made 847 connections..."
    why_unusual = Column(Text, nullable=False)  # e.g., "The average host in this capture made 42 connections..."

    # Related evidence (JSON arrays of IDs)
    related_alert_ids_json = Column(Text, nullable=True)
    related_finding_ids_json = Column(Text, nullable=True)

    pcap_label = Column(String, nullable=True)  # which PCAP phase generated this annotation (e.g. "before", "after")

    created_at = Column(String, nullable=False)

    __table_args__ = (
        Index("idx_annotations_job", "job_id"),
        Index("idx_annotations_host", "job_id", "host_ip"),
        Index("idx_annotations_severity", "job_id", "severity"),
        Index("idx_annotations_metric", "job_id", "metric_name"),
        Index("idx_annotations_pcap_label", "job_id", "pcap_label"),
    )

    def __repr__(self) -> str:
        return f"<ContextAnnotation {self.annotation_id} host={self.host_ip} metric={self.metric_name}>"

