"""Upload model (§12.5)."""

from sqlalchemy import Column, Float, Integer, String, Text

from backend.app.database_v2 import Base


class Upload(Base):
    __tablename__ = "uploads"

    upload_id = Column(String, primary_key=True)
    filename = Column(Text, nullable=False)
    size_bytes = Column(Integer, nullable=False)
    sha256 = Column(String, nullable=False)
    is_valid = Column(Integer, nullable=True)  # 0/1/NULL
    format = Column(String, nullable=True)
    packet_count = Column(Integer, nullable=True)
    capture_duration_seconds = Column(Float, nullable=True)
    created_at = Column(String, nullable=False)

    def __repr__(self) -> str:
        return f"<Upload {self.upload_id} file={self.filename}>"

