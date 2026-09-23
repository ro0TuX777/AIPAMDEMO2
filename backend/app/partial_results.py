"""Partial result persistence for progressive pipeline display.

Saves intermediate analysis data (aggregations, anomaly detection, alerts)
after the aggregate step completes, so the frontend can show "early insights"
while the LLM analysis is still running.
"""

from __future__ import annotations

from contextlib import nullcontext
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlmodel import Session

from .database import engine
from .db_models import PartialJobResultDB
from .models.partial_result import PartialResult

logger = logging.getLogger(__name__)


def save_partial_result(job_id: str, data: Dict[str, Any], *, db=None) -> None:
    """Upsert a partial result row for the given job."""
    with (nullcontext(db) if db is not None else Session(engine)) as session:
        now = datetime.now(timezone.utc)
        model = PartialResult if db is not None else PartialJobResultDB
        existing = session.get(model, job_id)
        if existing:
            existing.result = data
            existing.updated_at = now
        else:
            session.add(model(
                job_id=job_id,
                result=data,
                updated_at=now,
            ))
        session.commit()
    logger.info(f"Saved partial result for job {job_id}")


def get_partial_result(job_id: str, *, db=None) -> Optional[Dict[str, Any]]:
    """Return the partial result dict for a job, or None if not available."""
    with (nullcontext(db) if db is not None else Session(engine)) as session:
        model = PartialResult if db is not None else PartialJobResultDB
        row = session.get(model, job_id)
        if row:
            return row.result
    return None


def delete_partial_result(job_id: str, *, db=None) -> None:
    """Remove the partial result once the full result is available."""
    with (nullcontext(db) if db is not None else Session(engine)) as session:
        model = PartialResult if db is not None else PartialJobResultDB
        row = session.get(model, job_id)
        if row:
            session.delete(row)
            session.commit()
