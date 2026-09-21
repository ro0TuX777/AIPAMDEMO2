"""
Proof Builder — CRUD + narrative rendering for analyst-curated evidence proofs.

A "proof" is an analyst's argument: a set of pinned evidence items
with roles (supports/contradicts/context) and a conclusion.  The
builder manages creation, item management, and renders a markdown
narrative from the items.

Narrative generation supports three modes:
  - soc_handoff: Executive Summary, Key Findings, Affected Systems, Recommended Actions
  - ir_technical: Incident Summary, Attack Path, Indicator Analysis, Timeline, MITRE Mapping, Containment
  - executive_summary: Business Impact, Risk Assessment, Remediation Status, Next Steps
"""

from __future__ import annotations

import html
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.context_annotation import ContextAnnotation
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.models.proof import Proof, ProofItem
from backend.app.models.slice import IncidentSlice
from backend.app.models.theory import Theory

logger = logging.getLogger("aipam.proof_builder")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _uid() -> str:
    return str(uuid4())


# ---------------------------------------------------------------------------
# Entity label resolution
# ---------------------------------------------------------------------------

_ENTITY_QUERIES: dict[str, Any] = {
    "host": (Host, "ip", lambda h: h.ip),
    "alert": (Alert, "alert_id", lambda a: f"{a.severity}: {a.signature[:60]}"),
    "finding": (Finding, "finding_id", lambda f: f"{f.severity}: {f.title[:60]}"),
    "theory": (Theory, "theory_id", lambda t: f"{t.hypothesis_type}: {t.label[:60]}"),
    "slice": (IncidentSlice, "slice_id", lambda s: s.label[:60] if s.label else s.slice_id),
    "ioc": (Ioc, "ioc_id", lambda i: f"{i.ioc_type}: {i.value[:40]}"),
    "annotation": (ContextAnnotation, "annotation_id", lambda a: a.title[:60]),
}


def _resolve_entity(db: Session, entity_type: str, entity_id: str) -> tuple[str, str]:
    """Return (label, severity) for a given entity, or fallback values."""
    spec = _ENTITY_QUERIES.get(entity_type)
    if not spec:
        return entity_id, "info"

    model, id_col, label_fn = spec
    row = db.execute(
        select(model).where(getattr(model, id_col) == entity_id)
    ).scalars().first()

    if not row:
        return entity_id, "info"

    severity = getattr(row, "severity", "info") or "info"
    return label_fn(row), severity


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def create_proof(db: Session, job_id: str, *, title: str,
                 conclusion: str | None = None,
                 severity: str = "info",
                 confidence: float = 0.0,
                 mode: str = "soc_handoff") -> Proof:
    """Create a new empty proof for a job."""
    job = db.get(Job, job_id)
    if not job:
        raise ValueError(f"Job {job_id} not found")

    now = _now()
    proof = Proof(
        job_id=job_id,
        proof_id=f"PRF-{_uid()[:8]}",
        title=title,
        conclusion=conclusion,
        status="draft",
        severity=severity,
        confidence=confidence,
        mode=mode,
        item_count=0,
        created_at=now,
        updated_at=now,
    )
    db.add(proof)
    db.commit()
    db.refresh(proof)
    logger.info("Created proof %s for job %s", proof.proof_id, job_id)
    return proof


def update_proof(db: Session, proof_id: str, **kwargs) -> Proof:
    """Update proof metadata (title, conclusion, status, severity, confidence)."""
    proof = db.execute(
        select(Proof).where(Proof.proof_id == proof_id)
    ).scalars().first()
    if not proof:
        raise ValueError(f"Proof {proof_id} not found")

    allowed = {"title", "conclusion", "status", "severity", "confidence", "mode", "narrative_markdown"}
    for k, v in kwargs.items():
        if k in allowed and v is not None:
            setattr(proof, k, v)
    proof.updated_at = _now()
    db.commit()
    db.refresh(proof)
    return proof


def delete_proof(db: Session, proof_id: str) -> None:
    """Delete a proof and all its items."""
    proof = db.execute(
        select(Proof).where(Proof.proof_id == proof_id)
    ).scalars().first()
    if not proof:
        raise ValueError(f"Proof {proof_id} not found")
    # Items cascade-deleted via FK
    db.delete(proof)
    db.commit()


def get_proof(db: Session, proof_id: str) -> Proof | None:
    return db.execute(
        select(Proof).where(Proof.proof_id == proof_id)
    ).scalars().first()


def list_proofs(db: Session, job_id: str) -> list[Proof]:
    return list(db.execute(
        select(Proof).where(Proof.job_id == job_id)
        .order_by(Proof.updated_at.desc())
    ).scalars().all())



# ---------------------------------------------------------------------------
# Item management
# ---------------------------------------------------------------------------


def add_item(db: Session, proof_id: str, *,
             entity_type: str, entity_id: str,
             role: str = "supports",
             analyst_note: str | None = None) -> ProofItem:
    """Pin an evidence entity to a proof."""
    proof = get_proof(db, proof_id)
    if not proof:
        raise ValueError(f"Proof {proof_id} not found")

    if entity_type not in _ENTITY_QUERIES:
        raise ValueError(f"Invalid entity_type: {entity_type}")

    if role not in ("supports", "contradicts", "context"):
        raise ValueError(f"Invalid role: {role}")

    # Resolve label + severity snapshot
    label, severity = _resolve_entity(db, entity_type, entity_id)

    # Determine next order
    max_order = db.execute(
        select(ProofItem.order)
        .where(ProofItem.proof_id == proof_id)
        .order_by(ProofItem.order.desc())
    ).scalars().first()
    next_order = (max_order or 0) + 1

    item = ProofItem(
        proof_id=proof_id,
        item_id=f"PI-{_uid()[:8]}",
        entity_type=entity_type,
        entity_id=entity_id,
        role=role,
        analyst_note=analyst_note,
        order=next_order,
        label=label,
        severity=severity,
        created_at=_now(),
    )
    db.add(item)
    proof.item_count = (proof.item_count or 0) + 1
    proof.updated_at = _now()
    db.commit()
    db.refresh(item)
    return item


def remove_item(db: Session, item_id: str) -> None:
    """Remove an item from a proof."""
    item = db.execute(
        select(ProofItem).where(ProofItem.item_id == item_id)
    ).scalars().first()
    if not item:
        raise ValueError(f"ProofItem {item_id} not found")

    proof = get_proof(db, item.proof_id)
    db.delete(item)
    if proof:
        proof.item_count = max((proof.item_count or 1) - 1, 0)
        proof.updated_at = _now()
    db.commit()


def update_item(db: Session, item_id: str, **kwargs) -> ProofItem:
    """Update an item's role, note, or order."""
    item = db.execute(
        select(ProofItem).where(ProofItem.item_id == item_id)
    ).scalars().first()
    if not item:
        raise ValueError(f"ProofItem {item_id} not found")

    allowed = {"role", "analyst_note", "order"}
    for k, v in kwargs.items():
        if k in allowed and v is not None:
            setattr(item, k, v)
    db.commit()
    db.refresh(item)
    return item


def list_items(db: Session, proof_id: str) -> list[ProofItem]:
    return list(db.execute(
        select(ProofItem).where(ProofItem.proof_id == proof_id)
        .order_by(ProofItem.order.asc())
    ).scalars().all())


# ---------------------------------------------------------------------------
# Narrative rendering
# ---------------------------------------------------------------------------

_ROLE_EMOJI = {"supports": "✅", "contradicts": "❌", "context": "ℹ️"}

# ── Mode-specific prompt templates ─────────────────────────────────────

_MODE_PROMPTS: dict[str, str] = {
    "soc_handoff": (
        "You are generating a SOC handoff report. Structure it with these sections:\n"
        "1. Executive Summary — one-paragraph overview of the incident\n"
        "2. Key Findings — bullet list of the most critical evidence\n"
        "3. Affected Systems — list of hosts/IPs and their roles\n"
        "4. Recommended Actions — prioritized next steps for the receiving team\n"
    ),
    "ir_technical": (
        "You are generating a technical Incident Response report. Structure it with these sections:\n"
        "1. Incident Summary — what happened, when, and how it was detected\n"
        "2. Attack Path — reconstructed attack sequence based on evidence\n"
        "3. Indicator Analysis — IOCs, signatures, and anomalies observed\n"
        "4. Timeline — chronological sequence of events\n"
        "5. MITRE ATT&CK Mapping — techniques observed (if any)\n"
        "6. Containment Status — current state and recommended containment\n"
    ),
    "executive_summary": (
        "You are generating an Executive Summary report for non-technical leadership. Structure it with:\n"
        "1. Business Impact — what business functions are affected\n"
        "2. Risk Assessment — severity and likelihood of continued impact\n"
        "3. Remediation Status — what has been done and what remains\n"
        "4. Next Steps — recommended actions in business terms\n"
    ),
}


def _build_evidence_context(proof: Any, items: list[Any]) -> str:
    """Build a text summary of evidence for the LLM prompt."""
    lines = [f"Proof Title: {proof.title}"]
    lines.append(f"Severity: {proof.severity} | Confidence: {proof.confidence:.0%}")
    if proof.conclusion:
        lines.append(f"Analyst Conclusion: {proof.conclusion}")
    lines.append("")

    for role_key, role_label in [("supports", "Supporting Evidence"),
                                  ("contradicts", "Contradicting Evidence"),
                                  ("context", "Contextual Evidence")]:
        role_items = [i for i in items if i.role == role_key]
        if not role_items:
            continue
        lines.append(f"--- {role_label} ---")
        for i in role_items:
            lines.append(f"- [{i.entity_type.upper()}] {i.entity_id}: {i.label} (severity: {i.severity})")
            if i.analyst_note:
                lines.append(f"  Analyst note: {i.analyst_note}")
    return "\n".join(lines)


def _collect_warnings(items: list[Any], db: Session) -> list[str]:
    """Check for unconfirmed items and generate warnings."""
    warnings: list[str] = []
    unconfirmed = 0
    for item in items:
        # Check the analyst_status of the source entity
        spec = _ENTITY_QUERIES.get(item.entity_type)
        if spec:
            model, id_col, _ = spec
            row = db.execute(
                select(model).where(getattr(model, id_col) == item.entity_id)
            ).scalars().first()
            if row:
                status = getattr(row, "analyst_status", None)
                if status and status not in ("confirmed",):
                    unconfirmed += 1
    if unconfirmed:
        warnings.append(f"{unconfirmed} included item(s) are not yet confirmed by an analyst")
    if not items:
        warnings.append("No evidence items have been added to this proof")
    return warnings


def render_narrative(db: Session, proof_id: str) -> dict[str, Any]:
    """Render a Markdown narrative from a proof's items and conclusion.

    Returns dict with 'narrative' (str) and 'warnings' (list[str]).
    Uses LLM when available, falls back to template-based rendering.
    """
    proof = get_proof(db, proof_id)
    if not proof:
        raise ValueError(f"Proof {proof_id} not found")

    items = list_items(db, proof_id)
    warnings = _collect_warnings(items, db)
    mode = getattr(proof, "mode", "soc_handoff") or "soc_handoff"

    # Try LLM-powered narrative generation
    narrative = _try_llm_narrative(proof, items, mode)

    if not narrative:
        # Fallback: template-based rendering
        narrative = _template_narrative(proof, items, mode)

    # Persist rendered narrative
    proof.narrative_markdown = narrative
    proof.updated_at = _now()
    db.commit()

    return {"narrative": narrative, "warnings": warnings}


def _try_llm_narrative(proof: Any, items: list[Any], mode: str) -> str | None:
    """Attempt LLM-powered narrative generation. Returns None on failure."""
    try:
        import asyncio
        from backend.app.config_v2 import get_settings
        from backend.app.llm_client import LLMClient, LLMConfig
        from backend.app.services.embedding_models import get_runtime_ollama_url

        settings = get_settings()
        ollama_base = get_runtime_ollama_url(settings.aipam_ollama_url)
        config = LLMConfig(
            endpoint=os.getenv("LLM_ENDPOINT") or f"{ollama_base}/v1/chat/completions",
            model=os.getenv("LLM_MODEL_NAME", "aipam-trafficllm-v10"),
            temperature=0.3,
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "4096")),
            timeout_seconds=float(os.getenv("LLM_TIMEOUT_SECONDS", "120")),
        )
        client = LLMClient(config=config)

        evidence_ctx = _build_evidence_context(proof, items)
        mode_prompt = _MODE_PROMPTS.get(mode, _MODE_PROMPTS["soc_handoff"])

        system_msg = (
            "You are a cybersecurity report writer for AIPAM, an AI-powered network "
            "forensics platform. Generate a professional Markdown report based on the "
            "evidence provided. Be precise, cite specific evidence items, and maintain "
            "a factual tone. Do not invent evidence not provided.\n\n"
            f"{mode_prompt}"
        )

        messages = [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": (
                f"Generate a {mode.replace('_', ' ')} report from this evidence:\n\n"
                f"{evidence_ctx}"
            )},
        ]

        # Run async in sync context.
        #
        # The coroutine is created before run_until_complete can await it, so
        # anything that raises in between orphans it — which surfaces later as
        # a "coroutine was never awaited" RuntimeWarning during GC and leaves
        # the client's resources unreleased. Close it explicitly on that path.
        loop = asyncio.new_event_loop()
        coro = None
        try:
            asyncio.set_event_loop(loop)
            coro = client.chat_completion(messages, temperature=0.3)
            narrative = loop.run_until_complete(coro)
            coro = None
        finally:
            if coro is not None:
                coro.close()
            asyncio.set_event_loop(None)
            loop.close()

        return narrative
    except Exception as exc:
        logger.warning("LLM narrative generation failed, using template fallback: %s", exc)
        return None


def _template_narrative(proof: Any, items: list[Any], mode: str) -> str:
    """Template-based narrative fallback (no LLM required)."""
    lines: list[str] = []
    lines.append(f"# {proof.title}")
    lines.append("")
    lines.append(f"**Mode:** {mode.replace('_', ' ').title()} | **Status:** {proof.status} "
                 f"| **Severity:** {proof.severity} | **Confidence:** {proof.confidence:.0%}")
    lines.append("")

    if proof.conclusion:
        lines.append("## Conclusion")
        lines.append("")
        lines.append(proof.conclusion)
        lines.append("")

    # Group items by role
    for role_key, role_label in [("supports", "Supporting Evidence"),
                                  ("contradicts", "Contradicting Evidence"),
                                  ("context", "Contextual Evidence")]:
        role_items = [i for i in items if i.role == role_key]
        if not role_items:
            continue
        lines.append(f"## {role_label}")
        lines.append("")
        for i in role_items:
            emoji = _ROLE_EMOJI.get(i.role, "")
            lines.append(f"{emoji} **{i.entity_type.upper()}** `{i.entity_id}` — {i.label}")
            if i.analyst_note:
                lines.append(f"   > {i.analyst_note}")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def export_proof(db: Session, proof_id: str, *, fmt: str = "markdown") -> dict[str, str]:
    """Export a proof's narrative as markdown or HTML."""
    proof = get_proof(db, proof_id)
    if not proof:
        raise ValueError(f"Proof {proof_id} not found")

    narrative = proof.narrative_markdown
    if not narrative:
        # Generate if not yet rendered
        result = render_narrative(db, proof_id)
        narrative = result["narrative"]

    safe_title = re.sub(r"[^a-zA-Z0-9_-]", "_", proof.title)[:50]

    if fmt == "html":
        # Simple markdown-to-html conversion
        html_content = _markdown_to_html(narrative, proof.title)
        return {"content": html_content, "filename": f"{safe_title}.html"}

    return {"content": narrative, "filename": f"{safe_title}.md"}


def _markdown_to_html(md: str, title: str) -> str:
    """Very basic markdown-to-HTML converter (no external deps)."""
    body = html.escape(md)
    # Headers
    body = re.sub(r"^### (.+)$", r"<h3>\1</h3>", body, flags=re.MULTILINE)
    body = re.sub(r"^## (.+)$", r"<h2>\1</h2>", body, flags=re.MULTILINE)
    body = re.sub(r"^# (.+)$", r"<h1>\1</h1>", body, flags=re.MULTILINE)
    # Bold
    body = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", body)
    # Inline code
    body = re.sub(r"`(.+?)`", r"<code>\1</code>", body)
    # Bullet lists
    body = re.sub(r"^- (.+)$", r"<li>\1</li>", body, flags=re.MULTILINE)
    # Blockquotes
    body = re.sub(r"^&gt; (.+)$", r"<blockquote>\1</blockquote>", body, flags=re.MULTILINE)
    # Paragraphs (double newline)
    body = re.sub(r"\n\n", r"</p><p>", body)
    body = body.replace("\n", "<br>")
    return (
        f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title>"
        f"<style>body{{font-family:sans-serif;max-width:800px;margin:2em auto;padding:0 1em;color:#222}}"
        f"h1,h2,h3{{color:#1a365d}}code{{background:#f0f0f0;padding:2px 4px;border-radius:3px}}"
        f"blockquote{{border-left:3px solid #cbd5e0;padding-left:1em;color:#4a5568}}"
        f"li{{margin:0.3em 0}}</style>"
        f"</head><body><p>{body}</p></body></html>"
    )


# ---------------------------------------------------------------------------
# Summary for chat bundles
# ---------------------------------------------------------------------------


def proof_summary(db: Session, job_id: str) -> str:
    """Build a text summary of all proofs for a job (for LLM context)."""
    proofs = list_proofs(db, job_id)
    if not proofs:
        return "Proofs: No analyst proofs have been created for this job."

    lines = [f"Proofs: {len(proofs)} proof(s) for this job."]
    for p in proofs:
        lines.append(f"  - [{p.status}] {p.title} ({p.item_count} items, "
                     f"severity={p.severity}, confidence={p.confidence:.0%})")
        if p.conclusion:
            lines.append(f"    Conclusion: {p.conclusion[:120]}")
        items = list_items(db, p.proof_id)
        for it in items[:5]:  # limit to first 5 for brevity
            lines.append(f"      {_ROLE_EMOJI.get(it.role, '')} {it.entity_type}:{it.entity_id} — {it.label}")
        if len(items) > 5:
            lines.append(f"      ... and {len(items) - 5} more items")
    return "\n".join(lines)
