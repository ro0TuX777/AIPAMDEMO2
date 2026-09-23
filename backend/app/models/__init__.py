"""AIPAM V2 SQLAlchemy ORM models."""

# Re-export ALL domain/Pydantic models so `from .models import X` works
# (the old models.py was replaced by this models/ package)
from backend.app.domain_models import *  # noqa: F401,F403

from backend.app.models.job import Job, TERMINAL_JOB_STATUSES
from backend.app.models.partial_result import PartialResult
from backend.app.models.sensor import JobSensor
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.global_host import GlobalHost
from backend.app.models.connection import Connection
from backend.app.models.dns import DnsQuery
from backend.app.models.tls import TlsSession
from backend.app.models.alert import Alert
from backend.app.models.file import File
from backend.app.models.ioc import Ioc
from backend.app.models.timeline import TimelineEvent
from backend.app.models.artifact import Artifact
from backend.app.models.upload import Upload
from backend.app.models.chat import (
    ChatComparisonBranch,
    ChatComparisonGroup,
    ChatConversation,
    ChatMessage,
)
from backend.app.models.knowledge_base import KBDocument
from backend.app.models.job_pcap import JobPcap
from backend.app.models.job_log_source import JobLogSource
from backend.app.models.theory import Theory
from backend.app.models.slice import IncidentSlice
from backend.app.models.context_annotation import ContextAnnotation
from backend.app.models.report import Report
from backend.app.models.proof import Proof, ProofItem
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.temporal_correlation import TemporalCorrelation
from backend.app.models.bluescrub import (
    BlueScrubAudit,
    BlueScrubBaseline,
    BlueScrubJobLineage,
    BlueScrubProject,
    BlueScrubScoreHistory,
    BlueScrubTriageLedger,
    BlueScrubWordlist,
)

__all__ = [
    "TERMINAL_JOB_STATUSES",
    "BlueScrubAudit",
    "BlueScrubBaseline",
    "BlueScrubJobLineage",
    "BlueScrubProject",
    "BlueScrubScoreHistory",
    "BlueScrubTriageLedger",
    "BlueScrubWordlist",
    "JobStatus",
    "JobStepStatus",
    "Job",
    "PartialResult",
    "JobSensor",
    "JobPcap",
    "JobLogSource",
    "Finding",
    "Host",
    "GlobalHost",
    "Connection",
    "DnsQuery",
    "TlsSession",
    "Alert",
    "File",
    "Ioc",
    "TimelineEvent",
    "Artifact",
    "Upload",
    "ChatComparisonBranch",
    "ChatComparisonGroup",
    "ChatConversation",
    "ChatMessage",
    "KBDocument",
    "Theory",
    "IncidentSlice",
    "ContextAnnotation",
    "Report",
    "Proof",
    "ProofItem",
    "NormalizedEvent",
    "TemporalCorrelation",
]
