"""Forensic Engine — orchestrates analyzers and applies guardrails.

The ``ForensicEngine`` coordinates multiple ``ForensicAnalyzer``
implementations, collects their ``Finding`` outputs, deduplicates by
MITRE technique, and runs ``ValidationStep`` guardrails before
returning results.

The headline analyzer is ``ChainOfThoughtAnalyzer`` — a two-stage
LLM reasoner:

1. **Triage**: "Based on these flow summaries, which 3 flows are
   most suspicious?"
2. **Deep analysis**: Fetch full details for only those flows and ask:
   "Identify the MITRE ATT&CK technique used here."

This produces ``Finding`` objects with real Flow IDs that downstream
guardrails can verify against the Evidence Store.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from sqlmodel import Session, select

from ..core.interfaces import AnalysisContext, Finding, ForensicAnalyzer
from ..db_models import AlertDB, FlowDB
from ..llm.providers.ollama import OllamaProvider
from ..llm.parsers import parse_llm_response, extract_flow_ids
from ..llm.prompt_renderer import render_prompt, get_system_prompt

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ValidationStep — base class for guardrails
# ---------------------------------------------------------------------------


class ValidationStep:
    """Base class for pre-commit guardrails.

    Subclasses validate or annotate a Finding before it is committed to
    the Evidence Store.
    """

    def validate(self, finding: Finding, session: Optional[Session] = None) -> Finding:
        """Validate a finding. Return the (possibly modified) Finding."""
        return finding


# ---------------------------------------------------------------------------
# ForensicEngine — orchestrator
# ---------------------------------------------------------------------------


@dataclass
class ForensicEngine:
    """Orchestrates multiple ForensicAnalyzers and applies guardrails.

    Usage::

        engine = ForensicEngine(
            analyzers=[ChainOfThoughtAnalyzer(provider=provider)],
            guardrails=[FlowExistenceGuardrail()],
        )
        findings = await engine.run(ctx, session=session)

    The engine:
    1. Runs all analyzers concurrently
    2. Collects and deduplicates findings
    3. Applies guardrails in order
    """

    analyzers: List[ForensicAnalyzer] = field(default_factory=list)
    guardrails: List[ValidationStep] = field(default_factory=list)

    async def run(
        self,
        ctx: AnalysisContext,
        session: Optional[Session] = None,
    ) -> List[Finding]:
        """Execute all analyzers and apply guardrails.

        Args:
            ctx: Standardized analysis context.
            session: DB session for guardrail validation. Optional
                when no DB-dependent guardrails are configured.

        Returns:
            List of validated Finding objects.
        """
        all_findings: List[Finding] = []

        for analyzer in self.analyzers:
            try:
                findings = await analyzer.analyze(ctx)
                logger.info(
                    "Analyzer '%s' produced %d findings",
                    analyzer.name, len(findings),
                )
                all_findings.extend(findings)
            except Exception as exc:
                logger.error(
                    "Analyzer '%s' failed: %s",
                    analyzer.name, exc,
                )

        # Deduplicate by MITRE technique + affected host combination
        deduped = _deduplicate_findings(all_findings)

        # Apply guardrails
        validated = []
        for finding in deduped:
            for guardrail in self.guardrails:
                finding = guardrail.validate(finding, session)
            validated.append(finding)

        return validated


# ---------------------------------------------------------------------------
# ChainOfThoughtAnalyzer
# ---------------------------------------------------------------------------


class ChainOfThoughtAnalyzer(ForensicAnalyzer):
    """Two-stage LLM reasoning: triage → deep analysis.

    Stage 1 (Triage): Sends flow/alert summaries to the LLM and asks
    "Which N flows are most suspicious?"

    Stage 2 (Deep Analysis): Fetches full details for only those flows
    from FlowDB and asks "Identify the MITRE ATT&CK technique used
    here and provide evidence."

    Attributes:
        provider: LLM backend (OllamaProvider or compatible).
        session_factory: Callable returning a DB session for reading flows.
        top_n: Number of suspicious flows to investigate deeply.
    """

    def __init__(
        self,
        provider: OllamaProvider,
        session_factory=None,
        top_n: int = 3,
    ) -> None:
        self.provider = provider
        self.session_factory = session_factory
        self.top_n = top_n

    @property
    def name(self) -> str:
        return "ChainOfThought"

    async def health_check(self) -> bool:
        return await self.provider.health_check()

    async def analyze(self, ctx: AnalysisContext) -> List[Finding]:
        """Perform two-stage chain-of-thought forensic analysis.

        Stage 1: Triage — identify most suspicious flows.
        Stage 2: Deep analysis — produce Findings with MITRE mappings.
        """
        system_prompt = get_system_prompt()

        # ---- Load data from Evidence Store ----
        flow_summaries, alert_summaries = self._load_summaries(ctx)

        if not flow_summaries:
            logger.warning("No flows to analyze for job %s", ctx.job_id)
            return []

        # ---- Stage 1: Triage ----
        logger.info(
            "[TRIAGE] Asking LLM to identify top %d suspicious flows "
            "out of %d (job=%s)",
            self.top_n, len(flow_summaries), ctx.job_id,
        )

        triage_prompt = render_prompt(
            "triage.j2",
            job_id=ctx.job_id,
            flow_count=len(flow_summaries),
            alert_count=len(alert_summaries),
            flow_summaries=flow_summaries,
            alert_summaries=alert_summaries,
            top_n=self.top_n,
        )

        triage_response = await self.provider.send(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": triage_prompt},
            ],
            response_format={"type": "json_object"},
        )

        suspicious_flow_ids = self._parse_triage_response(
            triage_response, flow_summaries,
        )

        if not suspicious_flow_ids:
            logger.warning(
                "[TRIAGE] No suspicious flows identified (job=%s)", ctx.job_id,
            )
            return []

        logger.info(
            "[TRIAGE] Selected %d suspicious flows: %s",
            len(suspicious_flow_ids), suspicious_flow_ids,
        )

        # ---- Stage 2: Deep Analysis ----
        deep_flows = self._load_full_flows(ctx, suspicious_flow_ids)
        related_alerts = [
            a for a in alert_summaries
            if any(fid in str(a) for fid in suspicious_flow_ids)
        ]

        deep_prompt = render_prompt(
            "mitre_mapping.j2",
            job_id=ctx.job_id,
            flow_count=len(deep_flows),
            flows=deep_flows,
            related_alerts=related_alerts,
        )

        deep_response = await self.provider.send(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": deep_prompt},
            ],
            response_format={"type": "json_object"},
        )

        findings = self._parse_deep_response(deep_response, ctx.job_id)

        logger.info(
            "[DEEP] Produced %d findings for job %s",
            len(findings), ctx.job_id,
        )

        return findings

    # ---- Data Loading ----

    def _load_summaries(
        self, ctx: AnalysisContext,
    ) -> tuple:
        """Load flow and alert summaries from DB for triage."""
        flow_summaries: List[Dict[str, Any]] = []
        alert_summaries: List[Dict[str, Any]] = []

        if self.session_factory is None:
            # Fallback: use IDs from context directly as lightweight summaries
            for fid in ctx.high_priority_flow_ids:
                flow_summaries.append({"id": fid, "src_ip": "?", "dst_ip": "?"})
            return flow_summaries, alert_summaries

        with self.session_factory() as session:
            # Load flows
            if ctx.high_priority_flow_ids:
                flows = session.exec(
                    select(FlowDB).where(
                        FlowDB.id.in_(ctx.high_priority_flow_ids)  # type: ignore
                    )
                ).all()
            else:
                flows = session.exec(
                    select(FlowDB).where(FlowDB.job_id == ctx.job_id)
                ).all()

            for f in flows:
                flow_summaries.append({
                    "id": f.id,
                    "src_ip": f.src_ip,
                    "src_port": f.src_port,
                    "dst_ip": f.dst_ip,
                    "dst_port": f.dst_port,
                    "transport_proto": f.transport_proto,
                    "app_proto": f.app_proto,
                    "duration_sec": f.duration_sec,
                    "bytes_from_src": f.bytes_from_src,
                    "bytes_from_dst": f.bytes_from_dst,
                    "state": f.state,
                })

            # Load alerts
            if ctx.alert_ids:
                alerts = session.exec(
                    select(AlertDB).where(
                        AlertDB.id.in_(ctx.alert_ids)  # type: ignore
                    )
                ).all()
            else:
                alerts = session.exec(
                    select(AlertDB).where(AlertDB.job_id == ctx.job_id)
                ).all()

            for a in alerts:
                alert_summaries.append({
                    "id": a.id,
                    "src_ip": a.src_ip,
                    "dst_ip": a.dst_ip,
                    "dst_port": a.dst_port,
                    "signature_name": a.signature_name,
                    "severity": a.severity,
                    "category": a.category,
                })

        return flow_summaries, alert_summaries

    def _load_full_flows(
        self,
        ctx: AnalysisContext,
        flow_ids: List[str],
    ) -> List[Dict[str, Any]]:
        """Load full flow details for deep analysis."""
        if self.session_factory is None:
            return [{"id": fid} for fid in flow_ids]

        with self.session_factory() as session:
            flows = session.exec(
                select(FlowDB).where(
                    FlowDB.id.in_(flow_ids)  # type: ignore
                )
            ).all()

            return [
                {
                    "id": f.id,
                    "src_ip": f.src_ip,
                    "src_port": f.src_port,
                    "dst_ip": f.dst_ip,
                    "dst_port": f.dst_port,
                    "transport_proto": f.transport_proto,
                    "app_proto": f.app_proto,
                    "duration_sec": f.duration_sec,
                    "bytes_from_src": f.bytes_from_src,
                    "bytes_from_dst": f.bytes_from_dst,
                    "packets_from_src": f.packets_from_src,
                    "packets_from_dst": f.packets_from_dst,
                    "tcp_flags_summary": f.tcp_flags_summary,
                    "state": f.state,
                    "extra": f.extra,
                }
                for f in flows
            ]

    # ---- Response Parsers ----

    def _parse_triage_response(
        self,
        response: str,
        known_flows: List[Dict[str, Any]],
    ) -> List[str]:
        """Parse triage response and validate flow IDs."""
        known_ids = {f["id"] for f in known_flows}

        parsed = parse_llm_response(response)
        if not parsed:
            logger.warning("Triage response was not valid JSON")
            return []

        suspicious = parsed.get("suspicious_flows", [])
        if not isinstance(suspicious, list):
            return []

        valid_ids = []
        for item in suspicious[:self.top_n]:
            if isinstance(item, dict):
                fid = item.get("flow_id", "")
                if fid in known_ids:
                    valid_ids.append(fid)
                else:
                    logger.warning(
                        "Triage cited unknown flow_id: %s (skipping)", fid,
                    )

        return valid_ids

    def _parse_deep_response(
        self,
        response: str,
        job_id: str,
    ) -> List[Finding]:
        """Parse deep analysis response into Finding objects."""
        parsed = parse_llm_response(response)
        if not parsed:
            logger.warning("Deep analysis response was not valid JSON")
            return []

        raw_findings = parsed.get("findings", [])
        if not isinstance(raw_findings, list):
            return []

        results = []
        for raw in raw_findings:
            if not isinstance(raw, dict):
                continue

            try:
                finding = Finding(
                    mitre_technique_id=raw.get("mitre_technique_id", "T0000"),
                    confidence_score=float(raw.get("confidence_score", 0.5)),
                    raw_evidence_snippet=raw.get("raw_evidence", ""),
                    rationale=raw.get("rationale", ""),
                    severity=raw.get("severity", "medium"),
                    affected_hosts=raw.get("affected_hosts", []),
                    classification=raw.get("classification"),
                    attack_chain_stage=raw.get("attack_chain_stage"),
                    cited_flow_ids=_extract_cited_ids(raw),
                )
                results.append(finding)
            except Exception as exc:
                logger.warning("Failed to create Finding: %s", exc)

        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicate by (mitre_technique_id, frozenset(affected_hosts))."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.mitre_technique_id, frozenset(f.affected_hosts))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _extract_cited_ids(raw: Dict[str, Any]) -> List[str]:
    """Extract flow IDs cited in a raw finding dict."""
    ids = []
    fid = raw.get("flow_id")
    if fid:
        ids.append(str(fid))

    # Also try to extract from evidence text
    evidence = raw.get("raw_evidence", "")
    if evidence:
        ids.extend(extract_flow_ids(evidence))

    return list(set(ids))
