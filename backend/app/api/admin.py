"""
Admin API — Sprint 7: Feedback-Driven Ranking.

Provides aggregate feedback analytics for the admin dashboard.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.database_v2 import get_db
from backend.app.schemas.admin import FeedbackMetricsResponse
from backend.app.services.feedback_analytics import get_feedback_metrics

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/feedback-metrics", response_model=FeedbackMetricsResponse)
def feedback_metrics(db: Session = Depends(get_db)) -> FeedbackMetricsResponse:
    """Return aggregate feedback analytics across all jobs.

    Includes:
    - **sensor_trust**: per-sensor confirmation/FP rates
    - **noisy_signatures**: signatures with high false-positive rates
    - **overall_stats**: total reviewed, confirmation rate, most/least trusted sensors
    - **time_series**: daily review counts for the last 30 days
    """
    return get_feedback_metrics(db)

