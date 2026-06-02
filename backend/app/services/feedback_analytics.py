"""
Feedback Analytics Service — Sprint 7.

Computes aggregate metrics from analyst review decisions across all jobs:
  - Sensor trust profiles (confirmation rate per sensor)
  - Noisy signatures (high false-positive-rate signatures)
  - Ranking adjustments (weight modifiers for the ranking formula)
  - Overall stats + daily time-series
"""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy import func as sa_func, select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.theory import Theory
from backend.app.schemas.admin import (
    DailyReviewCount,
    FeedbackMetricsResponse,
    NoisySignature,
    OverallStats,
    SensorTrustProfile,
    TimeSeries,
)

# Minimum reviewed items before a sensor/signature is eligible for trust scoring
_MIN_REVIEWED = 3
# FP rate threshold above which a signature is flagged as noisy
_NOISY_FP_THRESHOLD = 0.50


def compute_sensor_trust(db: Session) -> list[SensorTrustProfile]:
    """Per-sensor confirmation rate across all jobs."""
    sensor_stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "confirmed": 0, "false_positive": 0, "deferred": 0}
    )

    # Findings
    for f in db.execute(select(Finding.sensor, Finding.analyst_status)).all():
        sensor, status = f[0], f[1]
        if not sensor:
            continue
        sensor_stats[sensor]["total"] += 1
        if status in ("confirmed", "false_positive", "deferred"):
            sensor_stats[sensor][status] += 1

    # Alerts (engine = sensor)
    for a in db.execute(select(Alert.engine, Alert.analyst_status)).all():
        engine, status = a[0], a[1]
        if not engine:
            continue
        sensor_stats[engine]["total"] += 1
        if status in ("confirmed", "false_positive", "deferred"):
            sensor_stats[engine][status] += 1

    profiles: list[SensorTrustProfile] = []
    for name, s in sorted(sensor_stats.items()):
        reviewed = s["confirmed"] + s["false_positive"]
        profiles.append(SensorTrustProfile(
            sensor_name=name,
            total_items=s["total"],
            confirmed=s["confirmed"],
            false_positive=s["false_positive"],
            deferred=s["deferred"],
            confirmation_rate=s["confirmed"] / reviewed if reviewed > 0 else 0.0,
            false_positive_rate=s["false_positive"] / reviewed if reviewed > 0 else 0.0,
        ))
    return profiles


def compute_signature_noise(db: Session, top_n: int = 20) -> list[NoisySignature]:
    """Signatures/categories with the highest false-positive rates."""
    sig_stats: dict[str, dict] = defaultdict(
        lambda: {"total": 0, "confirmed": 0, "fp": 0, "category": None, "last_seen": None}
    )

    for row in db.execute(
        select(Alert.signature, Alert.category, Alert.analyst_status, Alert.ts)
    ).all():
        sig, cat, status, ts = row
        if not sig:
            continue
        sig_stats[sig]["total"] += 1
        sig_stats[sig]["category"] = cat
        if ts and (sig_stats[sig]["last_seen"] is None or ts > sig_stats[sig]["last_seen"]):
            sig_stats[sig]["last_seen"] = ts
        if status == "confirmed":
            sig_stats[sig]["confirmed"] += 1
        elif status == "false_positive":
            sig_stats[sig]["fp"] += 1

    noisy: list[NoisySignature] = []
    for sig_name, s in sig_stats.items():
        reviewed = s["confirmed"] + s["fp"]
        if reviewed < _MIN_REVIEWED:
            continue
        fp_rate = s["fp"] / reviewed
        noisy.append(NoisySignature(
            signature_name=sig_name,
            category=s["category"],
            false_positive_rate=round(fp_rate, 4),
            total_occurrences=s["total"],
            false_positive_count=s["fp"],
            confirmed_count=s["confirmed"],
            last_seen=s["last_seen"],
        ))

    noisy.sort(key=lambda x: x.false_positive_rate, reverse=True)
    return noisy[:top_n]


def compute_ranking_adjustments(db: Session) -> dict[str, float]:
    """Compute per-sensor weight adjustments for the ranking formula.

    Returns a dict mapping sensor_name → adjustment float in [-0.5, +0.5].
    Positive = trusted (boost), negative = noisy (penalize).
    """
    profiles = compute_sensor_trust(db)
    adjustments: dict[str, float] = {}
    for p in profiles:
        reviewed = p.confirmed + p.false_positive
        if reviewed < _MIN_REVIEWED:
            adjustments[p.sensor_name] = 0.0
            continue
        # Map confirmation_rate to [-0.5, +0.5]: 50% → 0.0, 100% → +0.5, 0% → -0.5
        adjustments[p.sensor_name] = round((p.confirmation_rate - 0.5), 4)
    return adjustments


def compute_signature_adjustments(db: Session) -> dict[str, float]:
    """Compute per-signature penalty based on false-positive rate.

    Returns a dict mapping signature → penalty float in [-0.5, 0.0].
    """
    noisy = compute_signature_noise(db, top_n=100)
    adjustments: dict[str, float] = {}
    for n in noisy:
        if n.false_positive_rate >= _NOISY_FP_THRESHOLD:
            # Penalize proportional to FP rate above threshold
            adjustments[n.signature_name] = round(-0.5 * n.false_positive_rate, 4)
        else:
            adjustments[n.signature_name] = 0.0
    return adjustments


def compute_overall_stats(db: Session) -> OverallStats:
    """Aggregate review statistics across all item types."""
    total = 0
    confirmed = 0
    fp = 0

    for model in (Finding, Alert, Theory):
        status_col = model.analyst_status
        total += db.scalar(select(sa_func.count()).select_from(model)) or 0
        confirmed += db.scalar(
            select(sa_func.count()).select_from(model).where(status_col == "confirmed")
        ) or 0
        fp += db.scalar(
            select(sa_func.count()).select_from(model).where(status_col == "false_positive")
        ) or 0

    reviewed = confirmed + fp
    sensor_profiles = compute_sensor_trust(db)
    most_trusted = None
    noisiest = None
    if sensor_profiles:
        trusted_sorted = [p for p in sensor_profiles if (p.confirmed + p.false_positive) >= _MIN_REVIEWED]
        if trusted_sorted:
            most_trusted = max(trusted_sorted, key=lambda p: p.confirmation_rate).sensor_name
            noisiest = max(trusted_sorted, key=lambda p: p.false_positive_rate).sensor_name

    return OverallStats(
        total_reviewed=reviewed,
        total_items=total,
        confirmation_rate=confirmed / reviewed if reviewed > 0 else 0.0,
        false_positive_rate=fp / reviewed if reviewed > 0 else 0.0,
        most_trusted_sensor=most_trusted,
        noisiest_sensor=noisiest,
    )


def compute_daily_reviews(db: Session, days: int = 30) -> list[DailyReviewCount]:
    """Daily review counts for the last N days.

    Groups by the date portion of reviewed_at.
    """
    daily: dict[str, dict[str, int]] = defaultdict(
        lambda: {"confirmed": 0, "false_positive": 0, "deferred": 0, "needs_review": 0}
    )

    for model in (Finding, Alert, Theory):
        rows = db.execute(
            select(model.reviewed_at, model.analyst_status).where(
                model.reviewed_at.isnot(None)
            )
        ).all()
        for reviewed_at, status in rows:
            if not reviewed_at or not status:
                continue
            date_str = reviewed_at[:10]  # "YYYY-MM-DD"
            if status in daily[date_str]:
                daily[date_str][status] += 1

    result = [
        DailyReviewCount(date=d, **counts)
        for d, counts in sorted(daily.items())
    ]
    # Return only last N days
    return result[-days:] if len(result) > days else result


def get_feedback_metrics(db: Session) -> FeedbackMetricsResponse:
    """Build the complete feedback metrics response."""
    return FeedbackMetricsResponse(
        sensor_trust=compute_sensor_trust(db),
        noisy_signatures=compute_signature_noise(db),
        overall_stats=compute_overall_stats(db),
        time_series=TimeSeries(daily_reviews=compute_daily_reviews(db)),
    )


