"""File schemas (openapi.yaml: FileItem, FileListResponse)."""

from pydantic import BaseModel, ConfigDict

from backend.app.schemas.common import SCHEMA_VERSION, PageInfo


class FileItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    file_id: str
    filename: str | None = None
    ts: str | None = None
    sha256: str
    md5: str | None = None
    ssdeep: str | None = None
    size_bytes: int
    mime: str | None = None
    entropy: float | None = None
    source: str | None = None
    host_ip: str | None = None
    pcap_label: str | None = None
    extracted_path: str | None = None
    yara_matches: list[str] = []
    download_artifact_id: str | None = None
    related_community_ids: list[str] = []


class FileListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[FileItem]
    page: PageInfo

