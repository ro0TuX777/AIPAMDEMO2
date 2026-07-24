"""
Sigma log-detection endpoints (first-class log analysis).

GET  /jobs/{jobId}/sigma          – list persisted Sigma detections
POST /jobs/{jobId}/sigma/analyze  – run Sigma rules over the job's normalized
                                    events and persist hits as first-class findings
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

import backend.app.sigma as sigma_pkg
from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.models.finding import Finding
from backend.app.models.job import Job
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.schemas.sigma import (
    SigmaAnalyzeResponse,
    SigmaDetectionItem,
    SigmaDetectionListResponse,
)
from backend.app.sigma import load_rules_from_dir, run_rules

logger = logging.getLogger("aipam.sigma")

router = APIRouter(tags=["Sigma"], dependencies=[Depends(verify_token)])

SIGMA_SENSOR = "sigma"
_LEVEL_TO_SEVERITY = {
    "informational": "info",
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _rules_dir() -> Path:
    return Path(sigma_pkg.__file__).parent / "rules"


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _event_to_dict(ne: NormalizedEvent) -> dict:
    """Flatten a NormalizedEvent into a field dict for Sigma matching."""
    data: dict = {}
    if ne.data_json:
        try:
            parsed = json.loads(ne.data_json)
            if isinstance(parsed, dict):
                data.update(parsed)
        except json.JSONDecodeError:
            pass
    # Denormalized columns fill gaps without clobbering data_json fields.
    for col in ("hostname", "username", "src_ip", "src_port",
                "dest_ip", "dest_port", "proto"):
        val = getattr(ne, col, None)
        if val is not None and col not in data:
            data[col] = val
    data.setdefault("event_type", ne.event_type)
    data["_event_id"] = ne.event_id
    data["_timestamp"] = ne.timestamp
    data["_hostname"] = ne.hostname
    return data


def _finding_to_item(f: Finding) -> SigmaDetectionItem:
    evidence = json.loads(f.evidence_json) if f.evidence_json else {}
    return SigmaDetectionItem(
        finding_id=f.finding_id,
        rule_id=evidence.get("rule_id", ""),
        title=f.title,
        severity=f.severity,
        category=f.category,
        tags=evidence.get("tags", []),
        event_id=evidence.get("event_id"),
        hostname=evidence.get("hostname"),
        timestamp=evidence.get("timestamp"),
        evidence=evidence,
    )


@router.get("/jobs/{job_id}/sigma", response_model=SigmaDetectionListResponse)
async def list_sigma_detections(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """List Sigma detections already persisted as findings for this job."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    rows = db.scalars(
        select(Finding).where(
            Finding.job_id == job_id, Finding.sensor == SIGMA_SENSOR
        )
    ).all()
    items = [_finding_to_item(f) for f in rows]
    return SigmaDetectionListResponse(items=items, total=len(items))


@router.post("/jobs/{job_id}/sigma/analyze", response_model=SigmaAnalyzeResponse)
async def analyze_sigma(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Run Sigma rules over the job's normalized events; persist new hits."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    rules = load_rules_from_dir(_rules_dir())
    events_rows = db.scalars(
        select(NormalizedEvent).where(NormalizedEvent.job_id == job_id)
    ).all()
    events = [_event_to_dict(ne) for ne in events_rows]

    matches = run_rules(rules, events)
    created = 0
    for m in matches:
        ev = m.event
        finding_id = f"sigma-{m.rule_id}-{ev.get('_event_id')}"
        exists = db.scalar(
            select(Finding).where(
                Finding.job_id == job_id, Finding.finding_id == finding_id
            )
        )
        if exists:
            continue
        evidence = {
            "rule_id": m.rule_id,
            "tags": m.tags,
            "event_id": ev.get("_event_id"),
            "hostname": ev.get("_hostname"),
            "timestamp": ev.get("_timestamp"),
        }
        db.add(Finding(
            job_id=job_id,
            finding_id=finding_id,
            sensor=SIGMA_SENSOR,
            severity=_LEVEL_TO_SEVERITY.get(m.level, "medium"),
            category=(m.tags[0] if m.tags else "sigma"),
            title=m.title,
            summary=f"Sigma rule '{m.title}' matched event {ev.get('_event_id')}",
            evidence_json=json.dumps(evidence),
            confidence=0.7,
        ))
        created += 1
    db.commit()

    rows = db.scalars(
        select(Finding).where(
            Finding.job_id == job_id, Finding.sensor == SIGMA_SENSOR
        )
    ).all()
    items = [_finding_to_item(f) for f in rows]
    return SigmaAnalyzeResponse(
        rules_evaluated=len(rules),
        events_scanned=len(events),
        detections_created=created,
        detections_total=len(items),
        items=items,
    )
