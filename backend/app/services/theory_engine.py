"""
Theory of the Case Engine — deterministic hypothesis scoring.

Gathers alerts, findings, and IOCs for a job (and per-host), then scores
each hypothesis type based on evidence patterns. No LLM calls — scoring
is pure Python. LLM explanation is added later via a separate call.
"""
from __future__ import annotations

from backend.app.pipeline.runtime_control import checkpoint

import json
import logging
import re
import ipaddress
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.normalized_event import NormalizedEvent
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
    "credential_abuse": [
        r"brute", r"credential", r"spray", r"password",
        r"kerberoast", r"mimikatz", r"lsass", r"ntlm",
        r"pass.the.hash", r"golden.ticket", r"silver.ticket",
        r"credential.dump", r"logon.fail", r"account.lock",
    ],
}

_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.05}
AIPAM_THEORY_NAMESPACE = UUID("47b506e6-87d8-55c4-8ac2-226f111bb2a0")
_IP_IOC_TYPES = {"ip", "ipv4", "ipv6", "ip-dst", "ip-src"}


def semantic_theory_id(job_id: str, pcap_label: str | None,
                       scope_type: str, scope_id: str, theory_key: str) -> str:
    # Length-prefixed components avoid ambiguity when an input contains '|'.
    components = (job_id, pcap_label or "", scope_type, scope_id, theory_key)
    name = "".join(f"{len(value)}:{value}" for value in components)
    return f"TH-{uuid5(AIPAM_THEORY_NAMESPACE, name)}"


def _ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None


def _json_ips(raw: str | None) -> set:
    if not raw:
        return set()
    try:
        root = json.loads(raw)
    except (ValueError, TypeError):
        return set()
    found: set = set()
    def visit(value):
        if isinstance(value, str):
            address = _ip(value)
            if address is not None:
                found.add(address)
        elif isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, dict):
            for child in value.values():
                visit(child)
    visit(root)
    return found


@dataclass
class EvidenceIndex:
    findings: list[Finding]
    alerts: list[Alert]
    iocs: list[Ioc]
    telemetry: list[NormalizedEvent]
    by_host: dict[Any, dict[str, list]] = field(default_factory=dict)

    def for_host(self, host_ip: str | None) -> dict[str, list]:
        if host_ip is None:
            return {name: getattr(self, name) for name in ("findings", "alerts", "iocs", "telemetry")}
        return self.by_host.get(_ip(host_ip), {name: [] for name in ("findings", "alerts", "iocs", "telemetry")})


def _load_evidence(db: Session, job_id: str, pcap_label: str | None) -> EvidenceIndex:
    families = (("findings", Finding), ("alerts", Alert), ("iocs", Ioc),
                ("telemetry", NormalizedEvent))
    loaded = {}
    for name, model in families:
        query = select(model).where(model.job_id == job_id)
        if pcap_label is not None:
            query = query.where(model.pcap_label == pcap_label)
        loaded[name] = list(db.scalars(query))
    index = EvidenceIndex(**loaded)
    for family in ("findings", "alerts", "iocs", "telemetry"):
        for row in getattr(index, family):
            if family == "findings":
                addresses = {_ip(row.src_ip), _ip(row.dest_ip)} | _json_ips(row.evidence_json)
            elif family == "alerts":
                addresses = {_ip(row.src_ip), _ip(row.dest_ip), _ip(row.host_ip)}
            elif family == "iocs":
                addresses = {_ip(row.value)} if row.ioc_type.lower() in _IP_IOC_TYPES else set()
            else:
                if row.evidence_status not in ("corroborated", "confirmed"):
                    continue
                addresses = {_ip(row.src_ip), _ip(row.dest_ip), _ip(row.hostname)}
            for address in addresses - {None}:
                bucket = index.by_host.setdefault(address, {name: [] for name in ("findings", "alerts", "iocs", "telemetry")})
                bucket[family].append(row)
    return index


def select_relevant_hosts(hosts: list[str], evidence: EvidenceIndex) -> list[str]:
    return [host for host in hosts if _ip(host) in evidence.by_host]


# ── Evidence gathering ────────────────────────────────────────────────

def _gather_evidence(db: Session, job_id: str, host_ip: str | None = None, pcap_label: str | None = None) -> dict[str, Any]:
    """Collect phase-consistent evidence with exact host associations."""
    return _load_evidence(db, job_id, pcap_label).for_host(host_ip)


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
        checkpoint()
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
        checkpoint()
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
        checkpoint()
        text = f"{ioc.ioc_type} {ioc.context or ''} {ioc.value}"
        matched = any(rx.search(text) for rx in compiled)
        if matched:
            ioc_conf = ioc.confidence or 0.5
            contribution = ioc_conf * 0.2
            iocs_score += contribution
            ioc_count += 1
            supporting.append(ioc.ioc_id)

    # Score telemetry (NormalizedEvents)
    telemetry_score = 0.0
    telemetry_count = 0
    for evt in evidence.get("telemetry", []):
        checkpoint()
        text = f"{evt.event_type} {evt.source_system or ''} {evt.data_json or ''}"
        matched = any(rx.search(text) for rx in compiled)
        if matched:
            # Confirmed evidence (C2-corroborated) gets the highest weight
            if evt.evidence_status == "confirmed":
                status_weight = 0.9
            elif evt.evidence_status == "corroborated":
                status_weight = 0.6
            else:
                status_weight = 0.3
            corr_bonus = (evt.corroboration_score or 0.0) * 0.2
            contribution = (status_weight + corr_bonus) * 0.25
            telemetry_score += contribution
            telemetry_count += 1
            supporting.append(evt.event_id)

    raw_score = findings_score + alerts_score + iocs_score + telemetry_score
    # Normalize to 0-1 range (cap at 1.0)
    score = min(round(raw_score, 3), 1.0)

    breakdown = {
        "findings": round(findings_score, 3),
        "alerts": round(alerts_score, 3),
        "iocs": round(iocs_score, 3),
        "telemetry": round(telemetry_score, 3),
        "finding_count": finding_count,
        "alert_count": alert_count,
        "ioc_count": ioc_count,
        "telemetry_count": telemetry_count,
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
        "findings": 0.0, "alerts": 0.0, "iocs": 0.0, "telemetry": 0.0,
        "finding_count": 0, "alert_count": 0, "ioc_count": 0, "telemetry_count": 0,
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


def _existing_by_semantic_key(db: Session, rows: list[Theory], job_id: str,
                              *, consolidate_job: bool) -> tuple[list[Theory], dict[tuple[str, str, str], Theory]]:
    """Treat legacy NULL and current job IDs as one logical job scope."""
    if consolidate_job:
        groups: dict[str, list[Theory]] = {}
        for row in rows:
            if row.scope_type == "job" and row.scope_id_key in ("", job_id):
                groups.setdefault(row.theory_key, []).append(row)
        losers: set[Theory] = set()
        for group in groups.values():
            if len(group) < 2:
                continue
            def reviewed(row: Theory) -> bool:
                return (row.analyst_status not in (None, "unreviewed") or
                        any(getattr(row, name) is not None for name in
                            ("analyst_notes", "reviewed_at", "reviewer_id")))
            survivor = min(group, key=lambda row: (not reviewed(row), row.id))
            by_recency = sorted(group, key=lambda row: (row.reviewed_at or "", row.id), reverse=True)
            for name in ("analyst_status", "analyst_notes", "reviewed_at", "reviewer_id"):
                value = next((getattr(row, name) for row in by_recency
                              if getattr(row, name) is not None and
                              (name != "analyst_status" or getattr(row, name) != "unreviewed")), None)
                if value is not None:
                    setattr(survivor, name, value)
            for row in group:
                if row is not survivor:
                    db.delete(row)
                    losers.add(row)
        rows = [row for row in rows if row not in losers]
    return rows, {(row.scope_type, row.scope_id_key, row.theory_key): row for row in rows}


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
    try:
        evidence = _load_evidence(db, job_id, pcap_label)
        existing = list(db.scalars(select(Theory).where(
            Theory.job_id == job_id, Theory.phase_key == (pcap_label or ""))))
        existing, by_key = _existing_by_semantic_key(db, existing, job_id,
                                                     consolidate_job=host_ip is None)
        rows = _build_scope(db, job_id, host_ip, pcap_label,
                            evidence.for_host(host_ip), by_key)
        active = {row.theory_key for row in rows}
        scope_type = "host" if host_ip else "job"
        scope_id = host_ip or job_id
        for row in existing:
            if row.scope_type == scope_type and row.scope_id_key in ({scope_id, ""} if host_ip is None else {scope_id}) and row.theory_key not in active:
                db.delete(row)
        db.flush()
        checkpoint()
        db.commit()
        return rows
    except BaseException:
        db.rollback()
        raise


def _build_scope(db: Session, job_id: str, host_ip: str | None, pcap_label: str | None,
                 evidence: dict[str, Any], existing: dict[tuple[str, str, str], Theory]) -> list[Theory]:
    scope_type = "host" if host_ip else "job"
    scope_id = host_ip or job_id

    # Score all hypothesis types
    scored: list[tuple[str, float, list[str], list[str], dict[str, Any]]] = []

    for hyp_type, patterns in _HYPOTHESIS_PATTERNS.items():
        checkpoint()
        score, supporting, contradicting, breakdown = _score_hypothesis(hyp_type, patterns, evidence)
        if score > 0.01:  # skip zero-score hypotheses
            scored.append((hyp_type, score, supporting, contradicting, breakdown))

    # Score benign separately (uses different logic)
    benign_score, benign_sup, benign_contra, benign_bd = _score_benign(evidence)
    scored.append(("benign", benign_score, benign_sup, benign_contra, benign_bd))

    # Always add inconclusive as fallback
    if not scored or max(s[1] for s in scored) < 0.2:
        scored.append(("inconclusive", 0.15, [], [], {
            "findings": 0.0, "alerts": 0.0, "iocs": 0.0, "telemetry": 0.0,
            "finding_count": 0, "alert_count": 0, "ioc_count": 0, "telemetry_count": 0,
            "reason": "Insufficient evidence for any hypothesis",
        }))

    # Sort by score descending
    scored.sort(key=lambda x: x[1], reverse=True)

    # Create Theory records
    now = datetime.now(timezone.utc).isoformat()
    theories: list[Theory] = []
    for rank, (hyp_type, score, supporting, contradicting, breakdown) in enumerate(scored, 1):
        checkpoint()
        label = _HYPOTHESIS_LABELS.get(hyp_type, hyp_type.replace("_", " ").title())
        key = (scope_type, scope_id, hyp_type)
        theory = existing.get(key)
        if theory is None and host_ip is None:
            # Old job-scope rows can have NULL scope_id. Their normalized key
            # is empty; keep that semantic tuple and analyst-owned identity.
            theory = existing.get(("job", "", hyp_type))
        if theory is None:
            theory = Theory(job_id=job_id,
                theory_id=semantic_theory_id(job_id, pcap_label, scope_type, scope_id, hyp_type),
                scope_type=scope_type, scope_id=scope_id,
                phase_key=pcap_label or "", scope_id_key=scope_id, theory_key=hyp_type,
                created_at=now)
            db.add(theory)
        theory.label = label
        theory.hypothesis_type = hyp_type
        theory.score = score
        theory.confidence = _confidence_label(score)
        theory.rank = rank
        theory.supporting_evidence_json = json.dumps(supporting) if supporting else None
        theory.contradicting_evidence_json = json.dumps(contradicting) if contradicting else None
        theory.score_breakdown_json = json.dumps(breakdown)
        theory.pcap_label = pcap_label
        theories.append(theory)
    return theories


def generate_all_theories(db: Session, job_id: str, pcap_label: str | None = None) -> dict[str, int]:
    """Generate theories for the entire job and for each host.

    Returns counts: {"job": N, "hosts": M, "total": N+M}
    """
    start = time.monotonic()
    try:
        checkpoint()
        host_q = select(Host.ip).where(Host.job_id == job_id)
        if pcap_label is not None:
            host_q = host_q.where(Host.pcap_label == pcap_label)
        hosts = list(dict.fromkeys(db.scalars(host_q)))
        evidence = _load_evidence(db, job_id, pcap_label)
        relevant = select_relevant_hosts(hosts, evidence)
        existing = list(db.scalars(select(Theory).where(
            Theory.job_id == job_id, Theory.phase_key == (pcap_label or ""))))
        existing, by_key = _existing_by_semantic_key(db, existing, job_id,
                                                     consolidate_job=True)
        active: set[tuple[str, str, str]] = set()
        job_count = host_count = 0
        scopes = [None, *relevant]
        for offset in range(0, len(scopes), 100):
            checkpoint()
            for host_ip in scopes[offset:offset + 100]:
                checkpoint()
                rows = _build_scope(db, job_id, host_ip, pcap_label,
                                    evidence.for_host(host_ip), by_key)
                active.update((row.scope_type, row.scope_id_key, row.theory_key) for row in rows)
                if host_ip is None:
                    job_count += len(rows)
                else:
                    host_count += len(rows)
            db.flush()
        # The generated set is authoritative for this phase, including hosts
        # which lost relevance and candidate branches which no longer score.
        for row in existing:
            if (row.scope_type, row.scope_id_key, row.theory_key) not in active:
                db.delete(row)
        if db.deleted:
            db.flush()
        checkpoint()
        db.commit()
        return {"job": job_count, "hosts": host_count, "total": job_count + host_count,
                "discovered_hosts": len(hosts), "relevant_hosts": len(relevant),
                "skipped_benign_hosts": len(hosts) - len(relevant),
                "theory_scopes": len(scopes),
                "duration_ms": round((time.monotonic() - start) * 1000)}
    except BaseException:
        db.rollback()
        raise


# ── Labels ────────────────────────────────────────────────────────────

_HYPOTHESIS_LABELS: dict[str, str] = {
    "c2": "Command & Control (C2) Beaconing",
    "malware_delivery": "Malware Delivery / Exploitation",
    "recon": "Network Reconnaissance / Scanning",
    "lateral_movement": "Lateral Movement",
    "exfiltration": "Data Exfiltration",
    "admin_tools": "Legitimate Admin Activity",
    "credential_abuse": "Credential Abuse / Theft",
    "benign": "Benign / Normal Traffic",
    "inconclusive": "Inconclusive — Insufficient Evidence",
}

