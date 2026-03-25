"""Proof model — analyst-curated evidence chains with conclusions.

A Proof is a named collection of pinned evidence items (from the evidence
graph) that together support or refute a conclusion. Each ProofItem links
to an entity (host, alert, finding, theory, slice, ioc, annotation) with
an analyst-assigned role and optional note.
"""

from sqlalchemy import Column, Float, ForeignKey, Index, Integer, String, Text

from backend.app.database_v2 import Base


class Proof(Base):
    __tablename__ = "proofs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    proof_id = Column(String, nullable=False, unique=True)

    # Analyst-defined metadata
    title = Column(Text, nullable=False)
    conclusion = Column(Text, nullable=True)          # analyst's final conclusion
    status = Column(String, nullable=False, default="draft")  # draft, final, archived
    severity = Column(String, nullable=False, default="info")  # critical, high, medium, low, info
    confidence = Column(Float, nullable=False, default=0.0)    # 0.0–1.0, analyst-assessed
    mode = Column(String, nullable=False, default="soc_handoff")  # soc_handoff, ir_technical, executive_summary

    # Rendered narrative (generated from items)
    narrative_markdown = Column(Text, nullable=True)

    # Counts (denormalized for quick listing)
    item_count = Column(Integer, nullable=False, default=0)

    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)

    __table_args__ = (
        Index("idx_proofs_job", "job_id"),
        Index("idx_proofs_status", "job_id", "status"),
    )

    def __repr__(self) -> str:
        return f"<Proof {self.proof_id} status={self.status} items={self.item_count}>"


class ProofItem(Base):
    __tablename__ = "proof_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    proof_id = Column(String, ForeignKey("proofs.proof_id", ondelete="CASCADE"), nullable=False)
    item_id = Column(String, nullable=False, unique=True)

    # Reference to the evidence entity
    entity_type = Column(String, nullable=False)  # host, alert, finding, theory, slice, ioc, annotation
    entity_id = Column(String, nullable=False)     # e.g., "A-001", "10.0.0.5", "TH-001"

    # Analyst classification
    role = Column(String, nullable=False, default="supports")  # supports, contradicts, context
    analyst_note = Column(Text, nullable=True)

    # Display order within the proof
    order = Column(Integer, nullable=False, default=0)

    # Snapshot: label + severity at time of pinning (so proof is self-contained)
    label = Column(Text, nullable=True)
    severity = Column(String, nullable=True)

    created_at = Column(String, nullable=False)

    __table_args__ = (
        Index("idx_proof_items_proof", "proof_id"),
        Index("idx_proof_items_entity", "entity_type", "entity_id"),
    )

    def __repr__(self) -> str:
        return f"<ProofItem {self.item_id} {self.entity_type}:{self.entity_id} role={self.role}>"

