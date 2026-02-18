"""Partial result persistence for progressive pipeline display.

Saves intermediate analysis data (aggregations, anomaly detection, alerts)
after the aggregate step completes, so the frontend can show "early insights"
while the LLM analysis is still running.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlmodel import Session, select

from .database import engine
from .db_models import PartialJobResultDB

logger = logging.getLogger(__name__)


def save_partial_result(job_id: str, data: Dict[str, Any]) -> None:
    """Upsert a partial result row for the given job."""
    with Session(engine) as session:
        existing = session.get(PartialJobResultDB, job_id)
        now = datetime.now(timezone.utc)
        if existing:
            existing.result = data
            existing.updated_at = now
        else:
            session.add(PartialJobResultDB(
                job_id=job_id,
                result=data,
                updated_at=now,
            ))
        session.commit()
    logger.info(f"Saved partial result for job {job_id}")


def get_partial_result(job_id: str) -> Optional[Dict[str, Any]]:
    """Return the partial result dict for a job, or None if not available."""
    with Session(engine) as session:
        row = session.get(PartialJobResultDB, job_id)
        if row:
            return row.result
    return None


def delete_partial_result(job_id: str) -> None:
    """Remove the partial result once the full result is available."""
    with Session(engine) as session:
        row = session.get(PartialJobResultDB, job_id)
        if row:
            session.delete(row)
            session.commit()
