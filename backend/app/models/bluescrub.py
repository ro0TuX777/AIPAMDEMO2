"""BlueScrub tables.

Six new tables, no existing table altered. Three of them deliberately carry no
foreign key to ``jobs``: ``aipam.prune_old_jobs`` deletes whole jobs at
``aipam_job_retention_days`` and ``Finding`` cascades, so any state that must
outlive a job cannot be anchored to one. That applies to triage decisions,
frozen baselines, and score history.

Reference: docs/BLUESCRUB_DATA_CONTRACTS.md §0, §4.3, §5
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)

from backend.app.database_v2 import Base


class BlueScrubProject(Base):
    """Durable project identity.

    A slug or archive basename is not an identity: two projects can share a
    filename, and renaming an archive would silently split a project's history.
    """

    __tablename__ = "bluescrub_projects"

    project_id = Column(String, primary_key=True)          # generated UUID
    display_name = Column(String, nullable=False)          # renameable, carries no behaviour
    created_at = Column(String, nullable=False)
    archived = Column(Boolean, nullable=False, default=False, server_default="0")

    def __repr__(self) -> str:
        return f"<BlueScrubProject {self.project_id} {self.display_name!r}>"


class BlueScrubJobLineage(Base):
    """Per-job project binding and derivation.

    ``lineage_parent_job_id`` is resolved once, at job creation, so two
    concurrent scans of one project inherit deterministically instead of racing
    to read whichever finished last.
    """

    __tablename__ = "bluescrub_job_lineage"

    job_id = Column(
        String, ForeignKey("jobs.job_id", ondelete="CASCADE"), primary_key=True
    )
    project_id = Column(String, nullable=True, index=True)
    lineage_parent_job_id = Column(String, nullable=True)
    derived_from_job_id = Column(String, nullable=True)     # PCAP parent, re_assessment
    derived_from_file_id = Column(String, nullable=True)
    artifact_sha256 = Column(String, nullable=True)
    analysis_kind = Column(String, nullable=False, default="source_audit")
    compatibility_signature = Column(String, nullable=False)


class BlueScrubTriageLedger(Base):
    """Analyst triage, held outside the job lifecycle.

    Carry-forward reads this, never a prior job's ``Finding`` rows — those are
    deleted at the platform retention horizon, which would make triage appear
    to reset for any project scanned less often than monthly.
    """

    __tablename__ = "bluescrub_triage_ledger"

    project_id = Column(String, primary_key=True)
    finding_id = Column(String, primary_key=True)
    status = Column(String, nullable=False)
    notes = Column(Text, nullable=True)
    rule_version = Column(String, nullable=True)
    fingerprint_scheme = Column(String, nullable=False)
    decided_at = Column(String, nullable=False)
    decided_by = Column(String, nullable=True)              # self-asserted; see G9
    origin_job_id = Column(String, nullable=True)           # provenance only, may dangle

    __table_args__ = (
        Index("idx_bs_triage_project", "project_id"),
    )


class BlueScrubBaseline(Base):
    """Frozen comparison point.

    ``job_id`` is ``SET NULL`` rather than ``CASCADE``: deleting the source job
    must not destroy the snapshot the baseline exists to preserve.
    """

    __tablename__ = "bluescrub_baselines"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(String, nullable=False, index=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="SET NULL"), nullable=True)
    active = Column(Boolean, nullable=False, default=False, server_default="0")
    label = Column(String, nullable=True)
    compatibility_signature = Column(String, nullable=False)
    findings_json = Column(Text, nullable=False)
    metrics_json = Column(Text, nullable=False)
    created_at = Column(String, nullable=False)
    created_by = Column(String, nullable=True)

    __table_args__ = (
        # At most one active baseline per project, enforced by the database
        # rather than by application discipline.
        Index(
            "uq_bs_active_baseline", "project_id",
            unique=True, sqlite_where=text("active = 1"),
        ),
    )


class BlueScrubScoreHistory(Base):
    """Append-only score history. No foreign key — survives job deletion."""

    __tablename__ = "bluescrub_score_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(String, nullable=False, index=True)
    job_id = Column(String, nullable=False, unique=True)
    scanned_at = Column(String, nullable=False)
    profile = Column(String, nullable=False)
    scoring_model = Column(String, nullable=False)
    compatibility_signature = Column(String, nullable=False)
    coverage_json = Column(Text, nullable=False)
    pillars_json = Column(Text, nullable=False)
    overall_score = Column(Integer, nullable=True)          # null when incomplete
    grade = Column(String, nullable=True)
    scoped_score = Column(Integer, nullable=False)
    severity_counts_json = Column(Text, nullable=False)


class BlueScrubAudit(Base):
    """Mutation trail for baselines, wordlists, triage, purge, and key rotation.

    ``actor`` is self-asserted: AIPAM authenticates with a single shared bearer
    token and has no identity model, so this records what happened and what the
    caller claimed to be — not proof of who acted.
    """

    __tablename__ = "bluescrub_audit"

    id = Column(Integer, primary_key=True, autoincrement=True)
    actor = Column(String, nullable=True)
    at = Column(String, nullable=False)
    action = Column(String, nullable=False)
    project_id = Column(String, nullable=True, index=True)
    job_id = Column(String, nullable=True)
    old_json = Column(Text, nullable=True)
    new_json = Column(Text, nullable=True)
    reason = Column(Text, nullable=True)
    session = Column(String, nullable=True)
