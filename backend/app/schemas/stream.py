"""Stream forensics schemas (transcript / hexdump / carving)."""

from pydantic import BaseModel

from backend.app.schemas.common import SCHEMA_VERSION


class StreamPcapItem(BaseModel):
    """A single PCAP file available within a job for stream extraction."""
    name: str
    size_bytes: int
    label: str | None = None


class StreamPcapListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[StreamPcapItem]


class StreamTranscriptResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    protocol: str
    transcript: str
    truncated: bool
    byte_count: int


class StreamHexPacket(BaseModel):
    """One packet's hexdump: a header line plus its hex/ascii rows."""
    header: str
    lines: list[str]


class StreamHexdumpResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    protocol: str
    packets: list[StreamHexPacket]
    truncated: bool
