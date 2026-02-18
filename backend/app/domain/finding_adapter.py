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


def _map_severity(raw: str) -> FindingSeverity:
    """Map a raw severity string to the FindingSeverity enum."""
    return _SEVERITY_MAP.get(raw.lower(), FindingSeverity.INFO)


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
                        confidence=0.7,  # Default for LLM-based findings
                        analyzer_source=analyzer_source,
                        attack_chain_stage=item.stage,
                    )
                )
        else:
            # Attack chain item without specific MITRE techniques
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
                    confidence=0.6,
                    analyzer_source=analyzer_source,
                    attack_chain_stage=item.stage,
                )
            )

    # --- Anomalies → Findings ---
    for anomaly in llm_output.anomalies:
        severity = FindingSeverity.MEDIUM
        if anomaly.confidence >= 0.8:
            severity = FindingSeverity.HIGH
        elif anomaly.confidence >= 0.9:
            severity = FindingSeverity.CRITICAL

        findings.append(
            Finding(
                id=str(uuid4()),
                job_id=job_id,
                classification=classification,
                severity=severity,
                title=f"Anomaly: {anomaly.description[:80]}",
                description=f"{anomaly.description}\n\nReason: {anomaly.reason}",
                affected_hosts=anomaly.related_hosts,
                confidence=anomaly.confidence,
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
                    confidence=0.5,
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
