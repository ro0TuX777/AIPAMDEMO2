"""
Proof Builder — CRUD + narrative rendering for analyst-curated evidence proofs.

A "proof" is an analyst's argument: a set of pinned evidence items
with roles (supports/contradicts/context) and a conclusion.  The
builder manages creation, item management, and renders a markdown
narrative from the items.
"""

from __future__ import annotations

import logging
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
                 confidence: float = 0.0) -> Proof:
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

    allowed = {"title", "conclusion", "status", "severity", "confidence"}
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


def render_narrative(db: Session, proof_id: str) -> str:
    """Render a Markdown narrative from a proof's items and conclusion."""
    proof = get_proof(db, proof_id)
    if not proof:
        raise ValueError(f"Proof {proof_id} not found")

    items = list_items(db, proof_id)

    lines: list[str] = []
    lines.append(f"# {proof.title}")
    lines.append("")
    lines.append(f"**Status:** {proof.status} | **Severity:** {proof.severity} "
                 f"| **Confidence:** {proof.confidence:.0%}")
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

    narrative = "\n".join(lines)

    # Persist rendered narrative
    proof.narrative_markdown = narrative
    proof.updated_at = _now()
    db.commit()

    return narrative


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

