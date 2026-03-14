"""
Contextualizer — computes per-host baselines from job-local data and
generates 'why unusual' annotations for statistical outliers.

Approach (deterministic, no LLM):
  1. Gather all hosts, connections, alerts, findings, DNS queries for the job.
  2. Compute job-wide baselines: median and standard deviation per metric
     (conn_count, bytes_sent, bytes_recv, unique_destinations, unique_services,
      alert_count, finding_count, dns_query_count).
  3. For each host, compare its metrics against the baseline.
  4. Flag hosts whose metrics deviate by more than a configurable threshold
     (default: 2 standard deviations or 3x the median).
  5. Persist annotations with human-readable explanations.
"""
from __future__ import annotations

import json
import logging
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.connection import Connection
from backend.app.models.context_annotation import ContextAnnotation
from backend.app.models.finding import Finding
from backend.app.models.host import Host

logger = logging.getLogger(__name__)

# Deviation thresholds
_MIN_POPULATION = 3       # Need at least 3 hosts to compute meaningful baselines
_DEVIATION_THRESHOLD = 2.0  # Flag if > 2 std devs above mean
_RATIO_THRESHOLD = 3.0      # Or if > 3x the median

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class _HostMetrics:
    """Computed metrics for a single host within a job."""
    ip: str
    conn_count: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    unique_destinations: int = 0
    unique_services: int = 0
    unique_ports: int = 0
    alert_count: int = 0
    finding_count: int = 0
    dns_query_count: int = 0
    alert_severities: list[str] = field(default_factory=list)
    protocols: set[str] = field(default_factory=set)


@dataclass
class _MetricBaseline:
    """Job-wide baseline for a single metric."""
    metric_name: str
    mean: float
    median: float
    stdev: float
    population_size: int


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _compute_host_metrics(db: Session, job_id: str) -> dict[str, _HostMetrics]:
    """Gather per-host metrics from connections, alerts, findings, DNS."""
    metrics: dict[str, _HostMetrics] = {}

    # Start from hosts table
    hosts = db.execute(select(Host).where(Host.job_id == job_id)).scalars().all()
    for h in hosts:
        m = _HostMetrics(ip=h.ip)
        m.conn_count = h.conn_count or 0
        m.bytes_sent = h.bytes_sent or 0
        m.bytes_recv = h.bytes_recv or 0
        m.alert_count = h.alert_count or 0
        m.finding_count = h.finding_count or 0
        m.dns_query_count = h.dns_query_count or 0
        metrics[h.ip] = m

    # Compute unique destinations and services from connections
    conns = db.execute(select(Connection).where(Connection.job_id == job_id)).scalars().all()
    dest_map: dict[str, set[str]] = defaultdict(set)
    svc_map: dict[str, set[str]] = defaultdict(set)
    port_map: dict[str, set[int]] = defaultdict(set)
    proto_map: dict[str, set[str]] = defaultdict(set)

    for c in conns:
        ip = c.host_ip
        if ip not in metrics:
            metrics[ip] = _HostMetrics(ip=ip)
        dest_map[ip].add(c.dest_ip)
        if c.service:
            svc_map[ip].add(c.service)
        if c.dest_port:
            port_map[ip].add(c.dest_port)
        if c.proto:
            proto_map[ip].add(c.proto)

    for ip, m in metrics.items():
        m.unique_destinations = len(dest_map.get(ip, set()))
        m.unique_services = len(svc_map.get(ip, set()))
        m.unique_ports = len(port_map.get(ip, set()))
        m.protocols = proto_map.get(ip, set())

    # Gather alert severities
    alerts = db.execute(select(Alert).where(Alert.job_id == job_id)).scalars().all()
    for a in alerts:
        ip = a.host_ip
        if ip in metrics:
            metrics[ip].alert_severities.append(a.severity)

    return metrics


def _compute_baselines(
    all_metrics: dict[str, _HostMetrics],
) -> dict[str, _MetricBaseline]:
    """Compute job-wide baselines for each numeric metric."""
    metric_names = [
        "conn_count", "bytes_sent", "bytes_recv",
        "unique_destinations", "unique_services", "unique_ports",
        "alert_count", "finding_count", "dns_query_count",
    ]
    baselines: dict[str, _MetricBaseline] = {}
    pop_size = len(all_metrics)

    for metric in metric_names:
        values = [getattr(m, metric, 0) for m in all_metrics.values()]
        if not values:
            continue
        mean_val = statistics.mean(values)
        median_val = statistics.median(values)
        stdev_val = statistics.pstdev(values) if len(values) >= 2 else 0.0
        baselines[metric] = _MetricBaseline(
            metric_name=metric,
            mean=mean_val,
            median=median_val,
            stdev=stdev_val,
            population_size=pop_size,
        )

    return baselines


_METRIC_LABELS = {
    "conn_count": ("Connection Count", "traffic", "connections"),
    "bytes_sent": ("Bytes Sent", "traffic", "bytes sent"),
    "bytes_recv": ("Bytes Received", "traffic", "bytes received"),
    "unique_destinations": ("Unique Destinations", "behavioral", "unique destination IPs"),
    "unique_services": ("Unique Services", "protocol", "unique services"),
    "unique_ports": ("Unique Ports", "protocol", "unique destination ports"),
    "alert_count": ("Alert Count", "alert", "alerts"),
    "finding_count": ("Finding Count", "alert", "findings"),
    "dns_query_count": ("DNS Query Count", "dns", "DNS queries"),
}


def _deviation_severity(deviation: float) -> str:
    """Map deviation factor to severity."""
    if deviation >= 10.0:
        return "critical"
    elif deviation >= 5.0:
        return "high"
    elif deviation >= 3.0:
        return "medium"
    elif deviation >= 2.0:
        return "low"
    return "info"


def _deviation_confidence(deviation: float, pop_size: int) -> float:
    """Compute confidence based on deviation magnitude and population size."""
    # More hosts → more confident the baseline is meaningful
    pop_factor = min(pop_size / 10.0, 1.0)  # saturates at 10 hosts
    dev_factor = min(deviation / 5.0, 1.0)  # saturates at 5x deviation
    return round(min(0.3 + 0.5 * dev_factor + 0.2 * pop_factor, 1.0), 2)


def _format_value(metric: str, value: float) -> str:
    """Format a metric value for human display."""
    if "bytes" in metric:
        if value >= 1_000_000_000:
            return f"{value / 1_000_000_000:.1f} GB"
        elif value >= 1_000_000:
            return f"{value / 1_000_000:.1f} MB"
        elif value >= 1_000:
            return f"{value / 1_000:.1f} KB"
        return f"{int(value)} B"
    return str(int(value))


def _find_outliers(
    all_metrics: dict[str, _HostMetrics],
    baselines: dict[str, _MetricBaseline],
) -> list[dict[str, Any]]:
    """Find hosts whose metrics deviate significantly from baselines."""
    outliers: list[dict[str, Any]] = []

    for ip, host_m in all_metrics.items():
        for metric_name, baseline in baselines.items():
            observed = float(getattr(host_m, metric_name, 0))
            if observed == 0:
                continue

            # Check deviation
            deviation = 0.0
            if baseline.stdev > 0:
                deviation = (observed - baseline.mean) / baseline.stdev
            elif baseline.median > 0:
                deviation = observed / baseline.median
            else:
                # All hosts have 0 for this metric except this one
                if observed > 0:
                    deviation = float("inf")

            # Only flag if above threshold AND population is large enough
            if baseline.population_size < _MIN_POPULATION:
                continue
            if deviation < _DEVIATION_THRESHOLD and (
                baseline.median == 0 or observed / max(baseline.median, 1) < _RATIO_THRESHOLD
            ):
                continue

            label, category, unit = _METRIC_LABELS.get(
                metric_name, (metric_name, "traffic", metric_name)
            )
            severity = _deviation_severity(deviation)
            confidence = _deviation_confidence(deviation, baseline.population_size)

            ratio_str = (
                f"{observed / baseline.median:.1f}x the median"
                if baseline.median > 0
                else "while most hosts had none"
            )

            outliers.append({
                "host_ip": ip,
                "metric_name": metric_name,
                "metric_category": category,
                "baseline_value": round(baseline.median, 2),
                "observed_value": round(observed, 2),
                "deviation_factor": round(deviation, 2),
                "population_size": baseline.population_size,
                "severity": severity,
                "confidence": confidence,
                "title": f"Unusually High {label}",
                "description": (
                    f"Host {ip} had {_format_value(metric_name, observed)} {unit}, "
                    f"which is {ratio_str} across {baseline.population_size} hosts in this capture."
                ),
                "why_unusual": (
                    f"The median host in this job had {_format_value(metric_name, baseline.median)} {unit} "
                    f"(mean: {_format_value(metric_name, baseline.mean)}, "
                    f"σ: {_format_value(metric_name, baseline.stdev)}). "
                    f"This host's value of {_format_value(metric_name, observed)} is "
                    f"{deviation:.1f} standard deviations above the mean, "
                    f"making it a statistical outlier worth investigating."
                ),
            })

    return outliers


def _attach_related_evidence(
    db: Session, job_id: str, outlier: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Find alert/finding IDs related to this outlier's host."""
    host_ip = outlier["host_ip"]
    alert_ids: list[str] = []
    finding_ids: list[str] = []

    alerts = db.execute(
        select(Alert.alert_id).where(Alert.job_id == job_id, Alert.host_ip == host_ip)
    ).scalars().all()
    alert_ids = list(alerts)

    # Findings don't have host_ip directly — match by IP in title/summary
    findings = db.execute(
        select(Finding).where(Finding.job_id == job_id)
    ).scalars().all()
    for f in findings:
        text = f"{f.title or ''} {f.summary or ''}".lower()
        if host_ip in text:
            finding_ids.append(f.finding_id)

    return alert_ids, finding_ids


def generate_annotations(db: Session, job_id: str) -> list[ContextAnnotation]:
    """Main entry point: compute baselines, find outliers, persist annotations.

    Deletes any existing annotations for the job before regenerating.
    """
    # Delete existing annotations
    db.execute(
        delete(ContextAnnotation).where(ContextAnnotation.job_id == job_id)
    )
    db.flush()

    # Compute per-host metrics
    all_metrics = _compute_host_metrics(db, job_id)
    if len(all_metrics) < _MIN_POPULATION:
        logger.info(
            "Job %s has only %d hosts — too few for meaningful baselines, skipping.",
            job_id, len(all_metrics),
        )
        db.commit()
        return []

    # Compute baselines
    baselines = _compute_baselines(all_metrics)

    # Find outliers
    outliers = _find_outliers(all_metrics, baselines)

    # Sort by severity (desc) then deviation (desc)
    outliers.sort(
        key=lambda o: (_SEVERITY_RANK.get(o["severity"], 0), o["deviation_factor"]),
        reverse=True,
    )

    # Persist annotations
    annotations: list[ContextAnnotation] = []
    for outlier in outliers:
        alert_ids, finding_ids = _attach_related_evidence(db, job_id, outlier)

        ann = ContextAnnotation(
            job_id=job_id,
            annotation_id=f"CTX-{uuid4().hex[:12]}",
            host_ip=outlier["host_ip"],
            metric_name=outlier["metric_name"],
            metric_category=outlier["metric_category"],
            baseline_value=outlier["baseline_value"],
            observed_value=outlier["observed_value"],
            deviation_factor=outlier["deviation_factor"],
            population_size=outlier["population_size"],
            severity=outlier["severity"],
            confidence=outlier["confidence"],
            title=outlier["title"],
            description=outlier["description"],
            why_unusual=outlier["why_unusual"],
            related_alert_ids_json=json.dumps(alert_ids) if alert_ids else None,
            related_finding_ids_json=json.dumps(finding_ids) if finding_ids else None,
            created_at=_now_iso(),
        )
        db.add(ann)
        annotations.append(ann)

    db.commit()
    logger.info("Generated %d context annotations for job %s", len(annotations), job_id)
    return annotations

