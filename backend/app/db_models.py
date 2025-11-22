from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from sqlmodel import Field, SQLModel
from sqlalchemy import Column
from sqlalchemy.types import JSON

from .models import JobStatus, JobStepStatus


class JobDB(SQLModel, table=True):
    """Database model for analysis jobs."""

    id: str = Field(primary_key=True, index=True)
    source: str
    mode: str
    exercise_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    status: JobStatus = Field(index=True)
    job_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    error_message: Optional[str] = None


class JobStepDB(SQLModel, table=True):
    """Database model for individual pipeline steps per job."""

    id: str = Field(primary_key=True, index=True)
    job_id: str = Field(foreign_key="jobdb.id", index=True)
    name: str
    status: JobStepStatus
    message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class JobResultDB(SQLModel, table=True):
    """Stores the final aggregated JobResult as a JSON blob per job."""

    job_id: str = Field(primary_key=True, foreign_key="jobdb.id")
    # Store the full JobResult (including summary, hosts, raw, report_urls)
    result: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )

