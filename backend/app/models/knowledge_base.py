"""Knowledge Base document models for RAG — per-job scoped."""

from sqlalchemy import Column, ForeignKey, Index, Integer, String, Text

from backend.app.database_v2 import Base


class KBDocument(Base):
    """A document uploaded to a knowledge base for RAG retrieval during chat.

    Documents are chunked, embedded, and retrieved to ground the AI's answers.
    Scope is set by ``job_id``:
      - job_id set  → belongs to that one analysis (asset inventory for a capture)
      - job_id NULL → global "reference library", available to every analysis
                      (exploit user guides, capability manuals, playbooks, …)
    Types: asset_inventory, network_map, baseline_profile, threat_intel,
    soc_playbook, policy, reference, user_guide, exploit_capability, other.
    """
    __tablename__ = "kb_documents"

    id = Column(String, primary_key=True)
    job_id = Column(String, ForeignKey("jobs.job_id"), nullable=True)  # NULL = global library
    name = Column(String, nullable=False)          # Display name
    doc_type = Column(String, nullable=False)       # asset_inventory | network_map | baseline_profile | ...
    description = Column(Text, nullable=True)       # Optional user description
    filename = Column(String, nullable=True)        # Original upload filename
    content = Column(Text, nullable=False)          # Raw text content of the document
    content_sha256 = Column(String, nullable=True)  # SHA-256 of content — for dedup
    chunk_count = Column(Integer, default=0)        # Number of chunks after splitting
    status = Column(String, default="pending")      # pending | indexed | degraded | error
    error_message = Column(Text, nullable=True)     # Error / degraded details
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)

    __table_args__ = (
        Index("idx_kb_doc_job_id", "job_id"),
        Index("idx_kb_doc_type", "doc_type"),
        Index("idx_kb_doc_status", "status"),
        Index("idx_kb_doc_sha", "content_sha256"),
    )

    @property
    def is_global(self) -> bool:
        """True for reference-library documents (not tied to a single job)."""
        return self.job_id is None

    def __repr__(self) -> str:
        return f"<KBDocument {self.id} name={self.name} type={self.doc_type}>"

