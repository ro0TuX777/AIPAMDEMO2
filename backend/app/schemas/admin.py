"""
Admin schemas — Sprint 7: Feedback-Driven Ranking.

Response models for the admin feedback-metrics endpoint.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class SensorTrustProfile(BaseModel):
    """Per-sensor confirmation/FP statistics."""
    sensor_name: str
    total_items: int = 0
    confirmed: int = 0
    false_positive: int = 0
    deferred: int = 0
    confirmation_rate: float = 0.0        # confirmed / (confirmed + false_positive)
    false_positive_rate: float = 0.0      # false_positive / (confirmed + false_positive)
    avg_confidence_delta: float = 0.0     # avg(analyst outcome – model confidence)


class NoisySignature(BaseModel):
    """A signature/category with a high false-positive rate."""
    signature_name: str
    category: str | None = None
    false_positive_rate: float = 0.0
    total_occurrences: int = 0
    false_positive_count: int = 0
    confirmed_count: int = 0
    last_seen: str | None = None           # ISO-8601


class OverallStats(BaseModel):
    """Aggregate review statistics."""
    total_reviewed: int = 0
    total_items: int = 0
    confirmation_rate: float = 0.0
    false_positive_rate: float = 0.0
    most_trusted_sensor: str | None = None
    noisiest_sensor: str | None = None


class DailyReviewCount(BaseModel):
    """Daily review breakdown."""
    date: str                             # YYYY-MM-DD
    confirmed: int = 0
    false_positive: int = 0
    deferred: int = 0
    needs_review: int = 0


class TimeSeries(BaseModel):
    """Time-series section of the feedback metrics response."""
    daily_reviews: list[DailyReviewCount] = Field(default_factory=list)


class FeedbackMetricsResponse(BaseModel):
    """Top-level response for GET /admin/feedback-metrics."""
    sensor_trust: list[SensorTrustProfile] = Field(default_factory=list)
    noisy_signatures: list[NoisySignature] = Field(default_factory=list)
    overall_stats: OverallStats = Field(default_factory=OverallStats)
    time_series: TimeSeries = Field(default_factory=TimeSeries)

