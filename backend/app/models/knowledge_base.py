"""Knowledge Base document models for RAG — per-job scoped."""

from sqlalchemy import Column, ForeignKey, Index, Integer, String, Text

from backend.app.database_v2 import Base


class KBDocument(Base):
    """A document uploaded to a job-specific knowledge base.

    Each job has its own knowledge base. Documents are chunked and embedded
    for RAG retrieval during chat, scoped to the owning job.
    Types: asset_inventory, network_map, baseline_profile, threat_intel, soc_playbook, other.
    """
    __tablename__ = "kb_documents"

    id = Column(String, primary_key=True)
    job_id = Column(String, ForeignKey("jobs.job_id"), nullable=True)  # Owning job (optional)
    name = Column(String, nullable=False)          # Display name
    doc_type = Column(String, nullable=False)       # asset_inventory | network_map | baseline_profile | ...
    description = Column(Text, nullable=True)       # Optional user description
    filename = Column(String, nullable=True)        # Original upload filename
    content = Column(Text, nullable=False)          # Raw text content of the document
    chunk_count = Column(Integer, default=0)        # Number of chunks after splitting
    status = Column(String, default="pending")      # pending | indexed | error
    error_message = Column(Text, nullable=True)     # Error details if indexing failed
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)

    __table_args__ = (
        Index("idx_kb_doc_job_id", "job_id"),
        Index("idx_kb_doc_type", "doc_type"),
        Index("idx_kb_doc_status", "status"),
    )

    def __repr__(self) -> str:
        return f"<KBDocument {self.id} name={self.name} type={self.doc_type}>"

