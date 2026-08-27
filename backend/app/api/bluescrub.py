"""BlueScrub API — projects, project binding, and DACV+R reports.

Routes live under ``/api/v1/bluescrub``. Code-artifact upload and job creation
reuse the existing ``/uploads/artifact`` and ``/jobs`` endpoints unchanged.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.models.bluescrub import (
    BlueScrubAudit,
    BlueScrubJobLineage,
    BlueScrubProject,
)
from backend.app.models.job import Job

router = APIRouter(prefix="/bluescrub", tags=["BlueScrub"], dependencies=[Depends(verify_token)])

TERMINAL = ("completed", "completed_with_errors")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class ProjectCreate(BaseModel):
    display_name: str = Field(min_length=1, max_length=200)


class ProjectOut(BaseModel):
    project_id: str
    display_name: str
    created_at: str
    archived: bool


class ProjectBind(BaseModel):
    project_id: str | None = Field(
        default=None,
        description="Existing project to bind to. Omit and supply display_name to create one.",
    )
    display_name: str | None = Field(default=None, max_length=200)
    actor: str | None = Field(
        default=None,
        description="Self-asserted; AIPAM has no identity model. Recorded, not verified.",
    )


class ProjectBindOut(BaseModel):
    job_id: str
    project_id: str
    lineage_parent_job_id: str | None
    carry_forward_enabled: bool
    note: str


@router.get("/projects", response_model=list[ProjectOut])
async def list_projects(db: Session = Depends(get_db)):
    rows = db.scalars(
        select(BlueScrubProject).order_by(BlueScrubProject.created_at.desc())
    ).all()
    return [
        ProjectOut(
            project_id=r.project_id, display_name=r.display_name,
            created_at=r.created_at, archived=bool(r.archived),
        )
        for r in rows
    ]


@router.post("/projects", status_code=status.HTTP_201_CREATED, response_model=ProjectOut)
async def create_project(body: ProjectCreate, db: Session = Depends(get_db)):
    project = BlueScrubProject(
        project_id=str(uuid.uuid4()),
        display_name=body.display_name,
        created_at=_now(),
    )
    db.add(project)
    db.commit()
    return ProjectOut(
        project_id=project.project_id, display_name=project.display_name,
        created_at=project.created_at, archived=False,
    )


@router.put("/jobs/{job_id}/project", response_model=ProjectBindOut)
async def bind_job_to_project(
    job_id: str,
    body: ProjectBind,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Bind an ad-hoc job to a project retroactively. No re-scan.

    Ad-hoc scans exist so a twenty-second hygiene check does not require a
    project dialog first. The cost is that their triage is discarded, which is
    what makes operators stop trusting a scanner. This is the escape hatch:
    one call, no re-scan, and carry-forward works from here on.

    Findings already persisted keep the status they have; this does not
    retroactively re-triage them. It makes *future* scans of this project
    inherit from this one.
    """
    response.headers["X-Request-Id"] = request_id

    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if (job.source_type or "") != "code_artifact":
        raise HTTPException(
            status_code=400,
            detail=f"Job {job_id} is {job.source_type!r}, not a code_artifact job",
        )

    lineage = db.get(BlueScrubJobLineage, job_id)
    if lineage is None:
        raise HTTPException(status_code=404, detail="Job has no BlueScrub lineage record")
    if lineage.project_id:
        raise HTTPException(
            status_code=409,
            detail=f"Job is already bound to project {lineage.project_id}",
        )

    if body.project_id:
        project = db.get(BlueScrubProject, body.project_id)
        if project is None:
            raise HTTPException(status_code=404, detail=f"Unknown project {body.project_id}")
    elif body.display_name:
        project = BlueScrubProject(
            project_id=str(uuid.uuid4()),
            display_name=body.display_name,
            created_at=_now(),
        )
        db.add(project)
        db.flush()
    else:
        raise HTTPException(
            status_code=400, detail="Supply either project_id or display_name",
        )

    # Resolve the lineage parent now, at bind time, for the same reason it is
    # resolved at job creation: a later reader must not re-derive it and get a
    # different answer depending on what has finished since.
    parent = db.execute(
        select(Job.job_id)
        .join(BlueScrubJobLineage, BlueScrubJobLineage.job_id == Job.job_id)
        .where(
            BlueScrubJobLineage.project_id == project.project_id,
            Job.status.in_(TERMINAL),
            Job.job_id != job_id,
        )
        .order_by(Job.completed_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    old = {"project_id": None, "lineage_parent_job_id": lineage.lineage_parent_job_id}
    lineage.project_id = project.project_id
    lineage.lineage_parent_job_id = parent

    db.add(BlueScrubAudit(
        actor=body.actor, at=_now(), action="project.bind",
        project_id=project.project_id, job_id=job_id,
        old_json=json.dumps(old),
        new_json=json.dumps({
            "project_id": project.project_id, "lineage_parent_job_id": parent,
        }),
    ))
    db.commit()

    return ProjectBindOut(
        job_id=job_id,
        project_id=project.project_id,
        lineage_parent_job_id=parent,
        carry_forward_enabled=True,
        note=(
            "Bound. Triage carries forward from the next scan of this project; "
            "findings already recorded keep their current status."
        ),
    )


@router.get("/report/{job_id}")
async def get_report(job_id: str, db: Session = Depends(get_db)):
    """Full DACV+R metrics for a code-artifact job."""
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if (job.source_type or "") != "code_artifact":
        raise HTTPException(status_code=400, detail="Not a code_artifact job")
    if not job.metrics_json:
        raise HTTPException(status_code=409, detail="Analysis has not completed")

    payload = json.loads(job.metrics_json)
    lineage = db.get(BlueScrubJobLineage, job_id)
    if lineage:
        payload["lineage"] = {
            "project_id": lineage.project_id,
            "lineage_parent_job_id": lineage.lineage_parent_job_id,
            "derived_from_job_id": lineage.derived_from_job_id,
            "analysis_kind": lineage.analysis_kind,
        }
    return payload
