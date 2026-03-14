"""Finding Adapter — Converts legacy LLMOutput into atomic Finding objects.

Bridges the existing monolithic LLMOutput (one blob per analysis) to the
new Finding model (one row per technique/anomaly).  Also handles
persistence of Finding objects as FindingDB rows.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from ..domain.finding import Finding, FindingSeverity
from ..models import LLMOutput

logger = logging.getLogger(__name__)

# Map LLMOutput severity strings to FindingSeverity enum
_SEVERITY_MAP = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
    "unknown": FindingSeverity.INFO,
}

# Source reliability weights — how trustworthy each analyzer is
_SOURCE_RELIABILITY: dict[str, float] = {
    "trafficllm": 0.15,   # ML model, moderate reliability
    "ollama": 0.10,        # LLM-based reasoning, lower baseline
    "heuristic": 0.20,     # Deterministic heuristics, highest baseline
    "suricata": 0.20,      # Signature-based IDS
    "zeek": 0.15,          # Network metadata analyzer
    "yara": 0.20,          # File/payload signature matching
}


def _map_severity(raw: str) -> FindingSeverity:
    """Map a raw severity string to the FindingSeverity enum."""
    return _SEVERITY_MAP.get(raw.lower(), FindingSeverity.INFO)


def calculate_confidence(
    *,
    analyzer_source: str = "ollama",
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    has_mitre_technique: bool = False,
    has_attack_chain_stage: bool = False,
    evidence_count: int = 0,
    affected_host_count: int = 0,
    model_score: Optional[float] = None,
) -> float:
    """Calculate a multi-factor confidence score (0.0–1.0).

    Factors and their max contributions:
      - Base score:           0.20 (every finding starts here)
      - Source reliability:   0.20 (based on analyzer trustworthiness)
      - MITRE technique:      0.15 (presence of ATT&CK mapping)
      - Attack chain stage:   0.10 (finding is part of kill-chain)
      - Severity weight:      0.10 (higher severity = higher confidence)
      - Evidence count:        0.15 (more evidence = more confidence, capped at 5)
      - Corroboration:         0.10 (multiple affected hosts = cross-validated)

    If ``model_score`` is provided (e.g. anomaly confidence from ML),
    it replaces the base + source components.
    """
    score = 0.0

    # --- Base + source reliability ---
    if model_score is not None:
        # ML model provided its own score — use it as base (scaled to 0.40 max)
        score += min(model_score, 1.0) * 0.40
    else:
        score += 0.20  # base
        score += _SOURCE_RELIABILITY.get(analyzer_source, 0.10)

    # --- MITRE ATT&CK mapping ---
    if has_mitre_technique:
        score += 0.15

    # --- Kill-chain placement ---
    if has_attack_chain_stage:
        score += 0.10

    # --- Severity weight ---
    sev_weights = {
        FindingSeverity.CRITICAL: 0.10,
        FindingSeverity.HIGH: 0.08,
        FindingSeverity.MEDIUM: 0.05,
        FindingSeverity.LOW: 0.02,
        FindingSeverity.INFO: 0.00,
    }
    score += sev_weights.get(severity, 0.0)

    # --- Evidence count (capped at 5 items for max bonus) ---
    evidence_bonus = min(evidence_count, 5) / 5.0 * 0.15
    score += evidence_bonus

    # --- Corroboration (multiple affected hosts) ---
    if affected_host_count >= 3:
        score += 0.10
    elif affected_host_count >= 2:
        score += 0.06
    elif affected_host_count >= 1:
        score += 0.03

    return round(min(score, 1.0), 2)


def llm_output_to_findings(
    job_id: str,
    llm_output: LLMOutput,
    analyzer_source: str = "ollama",
) -> List[Finding]:
    """Convert a monolithic LLMOutput into a list of atomic Findings.

    Each attack chain item produces one or more Findings (one per MITRE
    technique).  Each anomaly produces one Finding.  The overall
    classification is attached to every Finding for searchability.

    Args:
        job_id: Parent job identifier.
        llm_output: The LLM analysis output to decompose.
        analyzer_source: Name of the analyzer that produced this output.

    Returns:
        A list of Finding objects ready for persistence.
    """
    findings: List[Finding] = []
    overall_severity = _map_severity(llm_output.overall_severity)
    classification = llm_output.classification

    # --- Attack chain items → Findings ---
    for item in llm_output.attack_chain:
        # Collect affected hosts from the item's evidence
        affected_hosts: List[str] = []
        for host_finding in llm_output.host_findings:
            affected_hosts.append(host_finding.ip)

        if item.mitre_techniques:
            # One Finding per MITRE technique in this attack chain stage
            for technique in item.mitre_techniques:
                conf = calculate_confidence(
                    analyzer_source=analyzer_source,
                    severity=overall_severity,
                    has_mitre_technique=True,
                    has_attack_chain_stage=True,
                    evidence_count=len(item.evidence),
                    affected_host_count=len(affected_hosts),
                )
                findings.append(
                    Finding(
                        id=str(uuid4()),
                        job_id=job_id,
                        mitre_technique_id=technique.id,
                        mitre_technique_name=technique.name,
                        classification=classification,
                        severity=overall_severity,
                        title=f"{item.stage}: {technique.name}",
                        description=item.description,
                        evidence=item.evidence,
                        affected_hosts=affected_hosts,
                        confidence=conf,
                        analyzer_source=analyzer_source,
                        attack_chain_stage=item.stage,
                    )
                )
        else:
            # Attack chain item without specific MITRE techniques
            conf = calculate_confidence(
                analyzer_source=analyzer_source,
                severity=overall_severity,
                has_mitre_technique=False,
                has_attack_chain_stage=True,
                evidence_count=len(item.evidence),
                affected_host_count=len(affected_hosts),
            )
            findings.append(
                Finding(
                    id=str(uuid4()),
                    job_id=job_id,
                    classification=classification,
                    severity=overall_severity,
                    title=f"{item.stage}: {item.description[:80]}",
                    description=item.description,
                    evidence=item.evidence,
                    affected_hosts=affected_hosts,
                    confidence=conf,
                    analyzer_source=analyzer_source,
                    attack_chain_stage=item.stage,
                )
            )

    # --- Anomalies → Findings ---
    for anomaly in llm_output.anomalies:
        severity = FindingSeverity.MEDIUM
        if anomaly.confidence >= 0.9:
            severity = FindingSeverity.CRITICAL
        elif anomaly.confidence >= 0.8:
            severity = FindingSeverity.HIGH

        conf = calculate_confidence(
            analyzer_source=analyzer_source,
            severity=severity,
            has_mitre_technique=False,
            has_attack_chain_stage=False,
            evidence_count=0,
            affected_host_count=len(anomaly.related_hosts),
            model_score=anomaly.confidence,
        )
        findings.append(
            Finding(
                id=str(uuid4()),
                job_id=job_id,
                classification=classification,
                severity=severity,
                title=f"Anomaly: {anomaly.description[:80]}",
                description=f"{anomaly.description}\n\nReason: {anomaly.reason}",
                affected_hosts=anomaly.related_hosts,
                confidence=conf,
                analyzer_source=analyzer_source,
                attack_chain_stage=None,
            )
        )

    # --- Overall MITRE techniques not covered by attack chain ---
    attack_chain_technique_ids = set()
    for item in llm_output.attack_chain:
        for t in item.mitre_techniques:
            attack_chain_technique_ids.add(t.id)

    for technique in llm_output.mitre_techniques_overall:
        if technique.id not in attack_chain_technique_ids:
            conf = calculate_confidence(
                analyzer_source=analyzer_source,
                severity=overall_severity,
                has_mitre_technique=True,
                has_attack_chain_stage=False,
                evidence_count=0,
                affected_host_count=0,
            )
            findings.append(
                Finding(
                    id=str(uuid4()),
                    job_id=job_id,
                    mitre_technique_id=technique.id,
                    mitre_technique_name=technique.name,
                    classification=classification,
                    severity=overall_severity,
                    title=f"Detected: {technique.name}",
                    description=f"MITRE ATT&CK technique {technique.id} ({technique.name}) detected in analysis.",
                    confidence=conf,
                    analyzer_source=analyzer_source,
                )
            )

    if not findings:
        logger.debug(
            "LLMOutput for job %s produced zero findings (classification=%s)",
            job_id,
            classification,
        )

    return findings


def persist_findings(session, findings: List[Finding]) -> int:
    """Persist a list of Findings as FindingDB rows.

    Args:
        session: SQLModel Session.
        findings: Finding domain objects to persist.

    Returns:
        Number of rows inserted.
    """
    from ..db_models import FindingDB

    count = 0
    now = datetime.now(timezone.utc)
    for f in findings:
        row = FindingDB(
            id=f.id,
            job_id=f.job_id,
            mitre_technique_id=f.mitre_technique_id,
            mitre_technique_name=f.mitre_technique_name,
            classification=f.classification,
            severity=f.severity.value,
            title=f.title,
            description=f.description,
            evidence=f.evidence,
            affected_hosts=f.affected_hosts,
            confidence=f.confidence,
            analyzer_source=f.analyzer_source,
            attack_chain_stage=f.attack_chain_stage,
            created_at=now,
        )
        session.add(row)
        count += 1

    session.commit()
    return count
