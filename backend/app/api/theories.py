"""
Theory of the Case API endpoints.

GET  /jobs/{jobId}/theories                          – list job-level theories
GET  /jobs/{jobId}/hosts/{ip}/theories               – list host-level theories
POST /jobs/{jobId}/theories/generate                 – trigger theory generation
POST /jobs/{jobId}/theories/{theoryId}/explain       – LLM-powered explanation
"""

import json
import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.theory import Theory
from backend.app.schemas.theory import (
    EvidenceRef,
    ScoreBreakdown,
    TheoryExplainRequest,
    TheoryExplainResponse,
    TheoryItem,
    TheoryListResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Theories"], dependencies=[Depends(verify_token)])


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _resolve_evidence_ids(db: Session, job_id: str, ids: list[str]) -> list[EvidenceRef]:
    """Resolve a list of evidence IDs into labelled EvidenceRef objects."""
    if not ids:
        return []

    # Partition IDs by prefix for efficient lookup
    ne_ids = [eid for eid in ids if eid.startswith("NE-")]
    other_ids = [eid for eid in ids if not eid.startswith("NE-")]

    # Batch-lookup alerts, findings, IOCs (non-NE IDs)
    alerts: dict = {}
    findings: dict = {}
    iocs: dict = {}
    if other_ids:
        alerts = {a.alert_id: a for a in db.execute(
            select(Alert).where(Alert.job_id == job_id, Alert.alert_id.in_(other_ids))
        ).scalars().all()}
        findings = {f.finding_id: f for f in db.execute(
            select(Finding).where(Finding.job_id == job_id, Finding.finding_id.in_(other_ids))
        ).scalars().all()}
        iocs = {i.ioc_id: i for i in db.execute(
            select(Ioc).where(Ioc.job_id == job_id, Ioc.ioc_id.in_(other_ids))
        ).scalars().all()}

    # Batch-lookup NormalizedEvents
    norm_events: dict = {}
    if ne_ids:
        norm_events = {e.event_id: e for e in db.execute(
            select(NormalizedEvent).where(
                NormalizedEvent.job_id == job_id,
                NormalizedEvent.event_id.in_(ne_ids),
            )
        ).scalars().all()}

    refs: list[EvidenceRef] = []
    for eid in ids:
        if eid in alerts:
            refs.append(EvidenceRef(id=eid, type="alert", label=alerts[eid].signature))
        elif eid in findings:
            refs.append(EvidenceRef(id=eid, type="finding", label=findings[eid].title))
        elif eid in iocs:
            ioc = iocs[eid]
            refs.append(EvidenceRef(id=eid, type="ioc", label=f"{ioc.ioc_type}: {ioc.value}"))
        elif eid in norm_events:
            ne = norm_events[eid]
            refs.append(EvidenceRef(id=eid, type="telemetry", label=_ne_label(ne)))
        else:
            refs.append(EvidenceRef(id=eid, type="unknown", label=eid))
    return refs


def _ne_label(ne: NormalizedEvent) -> str:
    """Build a concise human-readable label for a NormalizedEvent."""
    parts: list[str] = []

    # Event type (e.g. "process", "auth", "connection")
    etype = (ne.event_type or "event").replace("_", " ").title()
    parts.append(etype)

    # Try to extract a meaningful detail from data_json
    detail = ""
    if ne.data_json:
        try:
            data = json.loads(ne.data_json)
            # Pick the most informative field available
            detail = (
                data.get("CommandLine")
                or data.get("command_line")
                or data.get("Image")
                or data.get("image")
                or data.get("TargetFilename")
                or data.get("target_filename")
                or data.get("sub_type")
                or data.get("action")
                or data.get("QueryName")
                or data.get("query_name")
                or ""
            )
        except Exception:
            pass

    if detail:
        # Truncate long command lines
        if len(detail) > 80:
            detail = detail[:77] + "..."
        parts.append(detail)
    else:
        # Fall back to network tuple or hostname/username context
        context_parts = []
        if ne.src_ip:
            s = ne.src_ip
            if ne.src_port:
                s += f":{ne.src_port}"
            context_parts.append(s)
        if ne.dest_ip:
            d = ne.dest_ip
            if ne.dest_port:
                d += f":{ne.dest_port}"
            context_parts.append(f"→ {d}")
        if context_parts:
            parts.append(" ".join(context_parts))
        elif ne.hostname:
            parts.append(ne.hostname)
        elif ne.username:
            parts.append(ne.username)

    # Append source system tag
    if ne.source_system:
        parts.append(f"[{ne.source_system}]")

    return " | ".join(parts)


def _theory_to_item(t: Theory, db: Session) -> TheoryItem:
    """Convert a Theory ORM object to a TheoryItem schema with resolved evidence labels."""
    supporting_ids: list[str] = []
    if t.supporting_evidence_json:
        try:
            supporting_ids = json.loads(t.supporting_evidence_json)
        except Exception:
            pass
    contradicting_ids: list[str] = []
    if t.contradicting_evidence_json:
        try:
            contradicting_ids = json.loads(t.contradicting_evidence_json)
        except Exception:
            pass
    next_steps: list[str] = []
    if t.next_steps_json:
        try:
            next_steps = json.loads(t.next_steps_json)
        except Exception:
            pass
    breakdown: ScoreBreakdown | None = None
    if t.score_breakdown_json:
        try:
            breakdown = ScoreBreakdown(**json.loads(t.score_breakdown_json))
        except Exception:
            pass

    return TheoryItem(
        theory_id=t.theory_id,
        scope_type=t.scope_type,
        scope_id=t.scope_id,
        label=t.label,
        hypothesis_type=t.hypothesis_type,
        score=t.score,
        confidence=t.confidence,
        rank=t.rank,
        supporting_evidence=_resolve_evidence_ids(db, t.job_id, supporting_ids),
        contradicting_evidence=_resolve_evidence_ids(db, t.job_id, contradicting_ids),
        score_breakdown=breakdown,
        explanation=t.explanation,
        next_steps=next_steps,
        pcap_label=t.pcap_label,
        created_at=t.created_at,
    )


@router.get("/jobs/{job_id}/theories", response_model=TheoryListResponse)
async def list_job_theories(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    pcap_label: str | None = Query(None, description="Filter by PCAP label (before/after)"),
):
    """List job-level theories (ranked hypotheses)."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    q = select(Theory).where(Theory.job_id == job_id, Theory.scope_type == "job")
    if pcap_label:
        q = q.where(Theory.pcap_label == pcap_label)
    q = q.order_by(Theory.rank.asc())
    theories = db.execute(q).scalars().all()

    return TheoryListResponse(
        items=[_theory_to_item(t, db) for t in theories],
        job_id=job_id,
        scope_type="job",
    )


@router.get("/jobs/{job_id}/hosts/{ip}/theories", response_model=TheoryListResponse)
async def list_host_theories(
    job_id: str,
    ip: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """List host-level theories for a specific IP."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    theories = db.execute(
        select(Theory)
        .where(Theory.job_id == job_id, Theory.scope_type == "host", Theory.scope_id == ip)
        .order_by(Theory.rank.asc())
    ).scalars().all()

    return TheoryListResponse(
        items=[_theory_to_item(t, db) for t in theories],
        job_id=job_id,
        scope_type="host",
        scope_id=ip,
    )


@router.post("/jobs/{job_id}/theories/generate", response_model=TheoryListResponse)
async def generate_theories_endpoint(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Manually trigger theory generation for a job (re-generates all)."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    from backend.app.services.theory_engine import generate_all_theories

    counts = generate_all_theories(db, job_id)
    logger.info("Generated theories for job %s: %s", job_id, counts)

    # Return job-level theories
    theories = db.execute(
        select(Theory)
        .where(Theory.job_id == job_id, Theory.scope_type == "job")
        .order_by(Theory.rank.asc())
    ).scalars().all()

    return TheoryListResponse(
        items=[_theory_to_item(t, db) for t in theories],
        job_id=job_id,
        scope_type="job",
    )



# ── LLM-powered theory explanation ───────────────────────────────────────────

def _llm_explain_enabled() -> bool:
    return os.getenv("AIPAM_EXPLAIN_FINDING_USE_LLM", "").strip().lower() in {"1", "true", "yes", "on"}


def _build_theory_explain_prompt(theory: Theory, evidence_context: str) -> list[dict[str, str]]:
    """Build LLM prompt for narrating a theory's deterministic evidence."""
    breakdown_info = ""
    if theory.score_breakdown_json:
        try:
            bd = json.loads(theory.score_breakdown_json)
            breakdown_info = (
                f"\nScore breakdown: "
                f"Findings contribution: {bd.get('findings', 0):.3f} ({bd.get('finding_count', 0)} items), "
                f"Alerts contribution: {bd.get('alerts', 0):.3f} ({bd.get('alert_count', 0)} items), "
                f"IOCs contribution: {bd.get('iocs', 0):.3f} ({bd.get('ioc_count', 0)} items)"
            )
            if bd.get("reason"):
                breakdown_info += f"\nReason: {bd['reason']}"
        except Exception:
            pass

    return [
        {
            "role": "system",
            "content": (
                "You are a senior SOC analyst writing a concise, grounded explanation of a security hypothesis. "
                "Use only the evidence provided. Do not speculate beyond the data. "
                "Write 2-4 sentences explaining what the evidence shows, why it matters, and what an analyst should do next. "
                "Be specific about the evidence — reference finding IDs, alert signatures, or IOC values where possible."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Hypothesis: {theory.label}\n"
                f"Type: {theory.hypothesis_type}\n"
                f"Score: {theory.score:.0%} ({theory.confidence} confidence)\n"
                f"Rank: #{theory.rank}"
                f"{breakdown_info}\n\n"
                f"Evidence context:\n{evidence_context}\n\n"
                "Write a concise analyst-facing explanation of this hypothesis based on the evidence above."
            ),
        },
    ]


@router.post("/jobs/{job_id}/theories/{theory_id}/explain", response_model=TheoryExplainResponse)
async def explain_theory(
    job_id: str,
    theory_id: str,
    body: TheoryExplainRequest,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Generate an LLM-powered narrative explanation for a theory."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    theory = db.execute(
        select(Theory).where(Theory.job_id == job_id, Theory.theory_id == theory_id)
    ).scalar_one_or_none()
    if not theory:
        raise HTTPException(status_code=404, detail="Theory not found")

    # Build evidence context using the evidence bundle service
    from backend.app.services.evidence_bundles import build_scoped_bundle
    bundle = build_scoped_bundle(db, job_id, scope_type="theory", scope_id=theory_id)
    evidence_context = bundle.to_context(max_chars=3000)

    # Build deterministic fallback
    breakdown_parts = []
    if theory.score_breakdown_json:
        try:
            bd = json.loads(theory.score_breakdown_json)
            if bd.get("finding_count"):
                breakdown_parts.append(f"{bd['finding_count']} finding(s) contributing {bd['findings']:.1%}")
            if bd.get("alert_count"):
                breakdown_parts.append(f"{bd['alert_count']} alert(s) contributing {bd['alerts']:.1%}")
            if bd.get("ioc_count"):
                breakdown_parts.append(f"{bd['ioc_count']} IOC(s) contributing {bd['iocs']:.1%}")
            if bd.get("reason"):
                breakdown_parts.append(bd["reason"])
        except Exception:
            pass

    fallback = (
        f"This {theory.confidence}-confidence hypothesis ({theory.label}) "
        f"scored {theory.score:.0%} based on deterministic evidence matching. "
    )
    if breakdown_parts:
        fallback += "Score components: " + "; ".join(breakdown_parts) + "."
    else:
        fallback += "No detailed breakdown available."

    if not _llm_explain_enabled():
        # Store deterministic explanation
        theory.explanation = fallback
        db.commit()
        return TheoryExplainResponse(
            theory_id=theory_id,
            explanation=fallback,
            source="deterministic",
        )

    # Try LLM
    try:
        from backend.app.config_v2 import get_settings
        from backend.app.llm_client import LLMClient, LLMConfig
        from backend.app.services.embedding_models import get_runtime_llm_model, get_runtime_ollama_url

        settings = get_settings()
        ollama_base = get_runtime_ollama_url(settings.aipam_ollama_url)
        config = LLMConfig(
            endpoint=os.getenv("LLM_ENDPOINT") or f"{ollama_base}/v1/chat/completions",
            model=get_runtime_llm_model(os.getenv("LLM_MODEL_NAME", "aipam-trafficllm-v10")),
            temperature=0.2,
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "1024")),
            timeout_seconds=float(os.getenv("LLM_TIMEOUT_SECONDS", "20")),
        )
        client = LLMClient(config=config)
        prompt = _build_theory_explain_prompt(theory, evidence_context)
        llm_response = await client.chat_completion(prompt, temperature=0.2)
        explanation = llm_response.strip() if llm_response else ""
    except Exception:
        logger.warning("LLM explain failed for theory %s, using fallback", theory_id, exc_info=True)
        theory.explanation = fallback
        db.commit()
        return TheoryExplainResponse(
            theory_id=theory_id,
            explanation=fallback,
            source="fallback",
            warning="LLM unavailable; returned deterministic explanation.",
        )

    if not explanation:
        theory.explanation = fallback
        db.commit()
        return TheoryExplainResponse(
            theory_id=theory_id,
            explanation=fallback,
            source="fallback",
            warning="LLM returned empty response; returned deterministic explanation.",
        )

    # Store LLM explanation
    theory.explanation = explanation
    db.commit()
    return TheoryExplainResponse(
        theory_id=theory_id,
        explanation=explanation,
        source="llm",
    )
