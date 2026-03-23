"""
Theory of the Case Engine — deterministic hypothesis scoring.

Gathers alerts, findings, and IOCs for a job (and per-host), then scores
each hypothesis type based on evidence patterns. No LLM calls — scoring
is pure Python. LLM explanation is added later via a separate call.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.theory import Theory

logger = logging.getLogger(__name__)

# ── Keyword / pattern matchers for hypothesis classification ──────────

_HYPOTHESIS_PATTERNS: dict[str, list[str]] = {
    "c2": [
        r"beacon", r"command.and.control", r"c2", r"callback",
        r"heartbeat", r"periodic.*connection", r"known.*c2",
        r"cobalt.?strike", r"empire", r"metasploit", r"meterpreter",
    ],
    "malware_delivery": [
        r"malware", r"trojan", r"dropper", r"payload",
        r"exploit", r"download.*executable", r"pe.*file",
        r"malicious.*file", r"virus", r"worm", r"ransomware",
    ],
    "recon": [
        r"scan", r"recon", r"enumerat", r"discovery",
        r"port.?scan", r"network.?scan", r"sweep",
        r"fingerprint", r"probe", r"info.*gather",
    ],
    "lateral_movement": [
        r"lateral", r"pass.the.hash", r"psexec", r"wmi",
        r"remote.*exec", r"smb.*spread", r"rdp.*brute",
        r"pivot", r"internal.*spread",
    ],
    "exfiltration": [
        r"exfil", r"data.*leak", r"large.*upload",
        r"dns.*tunnel", r"covert.*channel", r"staging",
        r"compress.*send", r"unusual.*outbound",
    ],
    "admin_tools": [
        r"admin", r"legitimate.*tool", r"powershell",
        r"ssh.*session", r"rdp.*session", r"remote.*admin",
        r"sysadmin", r"management",
    ],
}

_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.05}


# ── Evidence gathering ────────────────────────────────────────────────

def _gather_evidence(db: Session, job_id: str, host_ip: str | None = None, pcap_label: str | None = None) -> dict[str, Any]:
    """Collect alerts, findings, and IOCs for a job or specific host."""
    # Findings
    fq = select(Finding).where(Finding.job_id == job_id)
    if pcap_label:
        fq = fq.where(Finding.pcap_label == pcap_label)
    if host_ip:
        fq = fq.where(or_(
            Finding.title.contains(host_ip),
            Finding.summary.contains(host_ip),
            Finding.evidence_json.contains(host_ip),
        ))
    findings = db.execute(fq).scalars().all()

    # Alerts
    aq = select(Alert).where(Alert.job_id == job_id)
    if pcap_label:
        aq = aq.where(Alert.pcap_label == pcap_label)
    if host_ip:
        aq = aq.where(or_(
            Alert.src_ip == host_ip,
            Alert.dest_ip == host_ip,
            Alert.host_ip == host_ip,
        ))
    alerts = db.execute(aq).scalars().all()

    # IOCs
    iq = select(Ioc).where(Ioc.job_id == job_id)
    if host_ip:
        iq = iq.where(or_(
            Ioc.value == host_ip,
            Ioc.context.contains(host_ip) if host_ip else True,
        ))
    iocs = db.execute(iq).scalars().all()

    return {"findings": findings, "alerts": alerts, "iocs": iocs}


# ── Hypothesis scoring ────────────────────────────────────────────────

def _score_hypothesis(
    hyp_type: str,
    patterns: list[str],
    evidence: dict[str, Any],
) -> tuple[float, list[str], list[str], dict[str, Any]]:
    """Score a hypothesis against collected evidence.

    Returns (score, supporting_ids, contradicting_ids, breakdown).
    breakdown contains per-category score contributions and counts.
    """
    supporting: list[str] = []
    contradicting: list[str] = []
    findings_score = 0.0
    alerts_score = 0.0
    iocs_score = 0.0
    finding_count = 0
    alert_count = 0
    ioc_count = 0

    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]

    # Score findings
    for f in evidence["findings"]:
        text = f"{f.title} {f.summary or ''} {f.category or ''}"
        matched = any(rx.search(text) for rx in compiled)
        if matched:
            sev_w = _SEVERITY_WEIGHT.get(f.severity, 0.1)
            conf = getattr(f, "confidence", 0.5) or 0.5
            contribution = sev_w * conf * 0.4
            findings_score += contribution
            finding_count += 1
            supporting.append(f.finding_id)
        # High-confidence benign finding contradicts malicious hypotheses
        elif hyp_type != "benign" and f.severity == "info" and (getattr(f, "confidence", 0) or 0) > 0.7:
            contradicting.append(f.finding_id)

    # Score alerts
    for a in evidence["alerts"]:
        text = f"{a.signature} {a.category or ''}"
        matched = any(rx.search(text) for rx in compiled)
        if matched:
            sev_w = _SEVERITY_WEIGHT.get(a.severity, 0.1)
            contribution = sev_w * 0.3
            alerts_score += contribution
            alert_count += 1
            supporting.append(a.alert_id)

    # Score IOCs
    for ioc in evidence["iocs"]:
        text = f"{ioc.ioc_type} {ioc.context or ''} {ioc.value}"
        matched = any(rx.search(text) for rx in compiled)
        if matched:
            ioc_conf = ioc.confidence or 0.5
            contribution = ioc_conf * 0.2
            iocs_score += contribution
            ioc_count += 1
            supporting.append(ioc.ioc_id)

    raw_score = findings_score + alerts_score + iocs_score
    # Normalize to 0-1 range (cap at 1.0)
    score = min(round(raw_score, 3), 1.0)

    breakdown = {
        "findings": round(findings_score, 3),
        "alerts": round(alerts_score, 3),
        "iocs": round(iocs_score, 3),
        "finding_count": finding_count,
        "alert_count": alert_count,
        "ioc_count": ioc_count,
    }

    return score, supporting, contradicting, breakdown


def _confidence_label(score: float) -> str:
    """Map a numeric score to a confidence label."""
    if score >= 0.6:
        return "high"
    elif score >= 0.3:
        return "medium"
    return "low"


def _score_benign(evidence: dict[str, Any]) -> tuple[float, list[str], list[str], dict[str, Any]]:
    """Score the 'benign' hypothesis — high if no serious alerts/findings."""
    findings = evidence["findings"]
    alerts = evidence["alerts"]

    high_sev_count = sum(
        1 for f in findings if f.severity in ("critical", "high")
    ) + sum(
        1 for a in alerts if a.severity in ("critical", "high")
    )

    breakdown: dict[str, Any] = {
        "findings": 0.0, "alerts": 0.0, "iocs": 0.0,
        "finding_count": 0, "alert_count": 0, "ioc_count": 0,
        "reason": "",
    }

    if high_sev_count == 0 and len(findings) <= 2 and len(alerts) <= 3:
        supporting = [f.finding_id for f in findings if f.severity in ("info", "low")]
        breakdown["reason"] = "No high-severity evidence detected"
        breakdown["finding_count"] = len(supporting)
        return 0.7, supporting, [], breakdown
    elif high_sev_count <= 1:
        contra = [f.finding_id for f in findings if f.severity in ("critical", "high")]
        breakdown["reason"] = f"{high_sev_count} high-severity item found"
        return 0.3, [], contra, breakdown
    else:
        contra = [f.finding_id for f in findings if f.severity in ("critical", "high")]
        breakdown["reason"] = f"{high_sev_count} high-severity items found"
        return 0.1, [], contra, breakdown


def generate_theories(
    db: Session,
    job_id: str,
    host_ip: str | None = None,
    pcap_label: str | None = None,
) -> list[Theory]:
    """Generate ranked hypotheses for a job or specific host.

    This is the main entry point. It:
    1. Gathers all evidence (findings, alerts, IOCs)
    2. Scores each hypothesis type deterministically
    3. Ranks them by score
    4. Persists Theory records to the DB
    5. Returns the ranked list

    No LLM calls are made here — explanation is added separately.
    """
    scope_type = "host" if host_ip else "job"
    scope_id = host_ip or job_id

    # Delete any existing theories for this scope + label (re-generation)
    del_q = db.query(Theory).filter(
        Theory.job_id == job_id,
        Theory.scope_type == scope_type,
        Theory.scope_id == scope_id,
    )
    if pcap_label:
        del_q = del_q.filter(Theory.pcap_label == pcap_label)
    del_q.delete()
    db.flush()

    evidence = _gather_evidence(db, job_id, host_ip, pcap_label=pcap_label)

    # Score all hypothesis types
    scored: list[tuple[str, float, list[str], list[str], dict[str, Any]]] = []

    for hyp_type, patterns in _HYPOTHESIS_PATTERNS.items():
        score, supporting, contradicting, breakdown = _score_hypothesis(hyp_type, patterns, evidence)
        if score > 0.01:  # skip zero-score hypotheses
            scored.append((hyp_type, score, supporting, contradicting, breakdown))

    # Score benign separately (uses different logic)
    benign_score, benign_sup, benign_contra, benign_bd = _score_benign(evidence)
    scored.append(("benign", benign_score, benign_sup, benign_contra, benign_bd))

    # Always add inconclusive as fallback
    if not scored or max(s[1] for s in scored) < 0.2:
        scored.append(("inconclusive", 0.15, [], [], {
            "findings": 0.0, "alerts": 0.0, "iocs": 0.0,
            "finding_count": 0, "alert_count": 0, "ioc_count": 0,
            "reason": "Insufficient evidence for any hypothesis",
        }))

    # Sort by score descending
    scored.sort(key=lambda x: x[1], reverse=True)

    # Create Theory records
    now = datetime.now(timezone.utc).isoformat()
    theories: list[Theory] = []
    for rank, (hyp_type, score, supporting, contradicting, breakdown) in enumerate(scored, 1):
        label = _HYPOTHESIS_LABELS.get(hyp_type, hyp_type.replace("_", " ").title())
        theory = Theory(
            job_id=job_id,
            theory_id=f"TH-{uuid4().hex[:8]}",
            scope_type=scope_type,
            scope_id=scope_id,
            label=label,
            hypothesis_type=hyp_type,
            score=score,
            confidence=_confidence_label(score),
            rank=rank,
            supporting_evidence_json=json.dumps(supporting) if supporting else None,
            contradicting_evidence_json=json.dumps(contradicting) if contradicting else None,
            score_breakdown_json=json.dumps(breakdown),
            pcap_label=pcap_label,
            created_at=now,
        )
        db.add(theory)
        theories.append(theory)

    db.commit()
    logger.info(
        "Generated %d theories for job=%s scope=%s:%s (top: %s @ %.2f)",
        len(theories), job_id, scope_type, scope_id,
        theories[0].hypothesis_type if theories else "none",
        theories[0].score if theories else 0.0,
    )
    return theories


def generate_all_theories(db: Session, job_id: str, pcap_label: str | None = None) -> dict[str, int]:
    """Generate theories for the entire job and for each host.

    Returns counts: {"job": N, "hosts": M, "total": N+M}
    """
    # Job-level theories
    job_theories = generate_theories(db, job_id, pcap_label=pcap_label)

    # Per-host theories
    host_q = select(Host.ip).where(Host.job_id == job_id)
    if pcap_label:
        host_q = host_q.where(Host.pcap_label == pcap_label)
    hosts = db.execute(host_q).scalars().all()

    host_theory_count = 0
    for ip in hosts:
        host_theories = generate_theories(db, job_id, host_ip=ip, pcap_label=pcap_label)
        host_theory_count += len(host_theories)

    return {
        "job": len(job_theories),
        "hosts": host_theory_count,
        "total": len(job_theories) + host_theory_count,
    }


# ── Labels ────────────────────────────────────────────────────────────

_HYPOTHESIS_LABELS: dict[str, str] = {
    "c2": "Command & Control (C2) Beaconing",
    "malware_delivery": "Malware Delivery / Exploitation",
    "recon": "Network Reconnaissance / Scanning",
    "lateral_movement": "Lateral Movement",
    "exfiltration": "Data Exfiltration",
    "admin_tools": "Legitimate Admin Activity",
    "benign": "Benign / Normal Traffic",
    "inconclusive": "Inconclusive — Insufficient Evidence",
}

