from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from .models import (
    AnalysisSummary,
    HostFinding,
    JobResult,
    JobStatus,
    JobStepStatus,
)


class JobStepStatusSchema(BaseModel):
    name: str
    status: JobStepStatus
    message: Optional[str] = None


class JobStatusResponse(BaseModel):
    job_id: str
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    steps: List[JobStepStatusSchema]
    error_message: Optional[str] = None


class CreateJobResponse(BaseModel):
    job_id: str
    status: JobStatus


class JobResultResponse(JobResult):
    pass


class SecurityOnionJobRequest(BaseModel):
    source: str
    time_range: Dict[str, str]
    sensors: List[str]
    mode: str
    metadata: Dict[str, object] = Field(default_factory=dict)


class ArkimeJobRequest(BaseModel):
    source: str
    filter: str
    time_range: Dict[str, str]
    mode: str
    metadata: Dict[str, object] = Field(default_factory=dict)


class Settings(BaseModel):
    llm_endpoint: Optional[str] = None
    llm_model_name: Optional[str] = None
    llm_max_tokens: Optional[int] = None
    llm_temperature: Optional[float] = None
    security_onion_mode: Optional[str] = None
    security_onion_base_pcap_path: Optional[str] = None
    security_onion_zeek_log_path: Optional[str] = None
    security_onion_suricata_log_path: Optional[str] = None
    security_onion_api_url: Optional[str] = None
    security_onion_api_token: Optional[str] = None
    arkime_api_url: Optional[str] = None
    arkime_api_username: Optional[str] = None
    arkime_api_password: Optional[str] = None
    file_storage_path: Optional[str] = None

