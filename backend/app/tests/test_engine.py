"""Tests for app/core/engine.py — ForensicEngine + ChainOfThoughtAnalyzer."""

import json
import pytest

from unittest.mock import AsyncMock, MagicMock, patch

from app.core.interfaces import AnalysisContext, Finding, ForensicAnalyzer
from app.core.engine import (
    ForensicEngine,
    ChainOfThoughtAnalyzer,
    ValidationStep,
    _deduplicate_findings,
)


# -------------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------------


def make_ctx(**overrides):
    """Create a minimal AnalysisContext for testing."""
    defaults = {
        "job_id": "test-job-001",
        "exercise_id": "EX-001",
        "mode": "single_window",
        "high_priority_flow_ids": ["test-job-001:CdHxBc1234abcde", "test-job-001:XyZ789qrstuvwxy"],
    }
    defaults.update(overrides)
    return AnalysisContext(**defaults)


def make_finding(**overrides):
    """Create a minimal Finding for testing."""
    defaults = {
        "mitre_technique_id": "T1071.001",
        "confidence_score": 0.85,
        "raw_evidence_snippet": "TCP 192.168.1.100:49152 → 185.70.40.20:443",
        "rationale": "Long-duration TLS with beaconing pattern",
        "severity": "high",
        "affected_hosts": ["192.168.1.100"],
    }
    defaults.update(overrides)
    return Finding(**defaults)


# -------------------------------------------------------------------------
# ForensicEngine
# -------------------------------------------------------------------------

class TestForensicEngine:
    """Engine orchestration, dedup, guardrails."""

    @pytest.mark.asyncio
    async def test_runs_single_analyzer(self):
        """Engine collects findings from a single analyzer."""
        analyzer = MagicMock(spec=ForensicAnalyzer)
        analyzer.name = "test_analyzer"
        analyzer.analyze = AsyncMock(return_value=[make_finding()])

        engine = ForensicEngine(analyzers=[analyzer])
        ctx = make_ctx()
        results = await engine.run(ctx)

        assert len(results) == 1
        assert results[0].mitre_technique_id == "T1071.001"
        analyzer.analyze.assert_awaited_once_with(ctx)

    @pytest.mark.asyncio
    async def test_deduplicates_findings(self):
        """Engine deduplicates findings with same technique+hosts."""
        dup1 = make_finding()
        dup2 = make_finding()  # Same technique and hosts

        analyzer = MagicMock(spec=ForensicAnalyzer)
        analyzer.name = "test_analyzer"
        analyzer.analyze = AsyncMock(return_value=[dup1, dup2])

        engine = ForensicEngine(analyzers=[analyzer])
        results = await engine.run(make_ctx())

        assert len(results) == 1  # Deduped

    @pytest.mark.asyncio
    async def test_applies_guardrails(self):
        """Engine runs each guardrail on each finding."""
        finding = make_finding()

        analyzer = MagicMock(spec=ForensicAnalyzer)
        analyzer.name = "test_analyzer"
        analyzer.analyze = AsyncMock(return_value=[finding])

        guardrail = MagicMock(spec=ValidationStep)
        flagged = finding.model_copy(update={"requires_review": True})
        guardrail.validate = MagicMock(return_value=flagged)

        engine = ForensicEngine(analyzers=[analyzer], guardrails=[guardrail])
        results = await engine.run(make_ctx())

        assert results[0].requires_review is True
        guardrail.validate.assert_called_once()

    @pytest.mark.asyncio
    async def test_handles_analyzer_failure(self):
        """Engine logs and continues if an analyzer throws."""
        bad_analyzer = MagicMock(spec=ForensicAnalyzer)
        bad_analyzer.name = "broken_analyzer"
        bad_analyzer.analyze = AsyncMock(side_effect=RuntimeError("boom"))

        good_analyzer = MagicMock(spec=ForensicAnalyzer)
        good_analyzer.name = "good_analyzer"
        good_analyzer.analyze = AsyncMock(return_value=[make_finding()])

        engine = ForensicEngine(analyzers=[bad_analyzer, good_analyzer])
        results = await engine.run(make_ctx())

        # Good analyzer's findings still come through
        assert len(results) == 1


class TestDeduplication:
    """Finding deduplication helper."""

    def test_different_techniques_kept(self):
        f1 = make_finding(mitre_technique_id="T1071.001")
        f2 = make_finding(mitre_technique_id="T1059")
        assert len(_deduplicate_findings([f1, f2])) == 2

    def test_different_hosts_kept(self):
        f1 = make_finding(affected_hosts=["192.168.1.1"])
        f2 = make_finding(affected_hosts=["192.168.1.2"])
        assert len(_deduplicate_findings([f1, f2])) == 2

    def test_identical_deduped(self):
        f = make_finding()
        assert len(_deduplicate_findings([f, f])) == 1


# -------------------------------------------------------------------------
# ChainOfThoughtAnalyzer
# -------------------------------------------------------------------------

class TestChainOfThoughtAnalyzer:
    """Two-stage LLM reasoning — triage → deep analysis."""

    @pytest.mark.asyncio
    async def test_full_cot_pipeline(self):
        """End-to-end: triage identifies flows, deep analysis produces findings."""
        provider = MagicMock()

        # Stage 1: triage response — cites the first flow ID
        triage_json = json.dumps({
            "suspicious_flows": [
                {
                    "flow_id": "test-job-001:CdHxBc1234abcde",
                    "suspicion_score": 0.95,
                    "reason": "Abnormal TLS handshake",
                    "likely_technique": "T1071.001",
                }
            ]
        })

        # Stage 2: deep analysis response
        deep_json = json.dumps({
            "findings": [
                {
                    "flow_id": "test-job-001:CdHxBc1234abcde",
                    "mitre_technique_id": "T1071.001",
                    "mitre_technique_name": "Web Protocols",
                    "confidence_score": 0.92,
                    "raw_evidence": "TCP 192.168.1.100:49152 → 185.70.40.20:443",
                    "rationale": "Long-duration TLS with beaconing pattern",
                    "severity": "critical",
                    "classification": "IcedID",
                    "attack_chain_stage": "Command and Control",
                    "affected_hosts": ["192.168.1.100"],
                }
            ]
        })

        provider.send = AsyncMock(side_effect=[triage_json, deep_json])

        analyzer = ChainOfThoughtAnalyzer(provider=provider, top_n=1)
        ctx = make_ctx()

        findings = await analyzer.analyze(ctx)

        assert len(findings) == 1
        f = findings[0]
        assert f.mitre_technique_id == "T1071.001"
        assert f.confidence_score == 0.92
        assert f.classification == "IcedID"
        assert f.severity == "critical"
        assert "test-job-001:CdHxBc1234abcde" in f.cited_flow_ids

        # Verify 2 LLM calls were made (triage + deep)
        assert provider.send.await_count == 2

    @pytest.mark.asyncio
    async def test_triage_rejects_unknown_flow_ids(self):
        """Triage stage filters out flow IDs not in the known list."""
        provider = MagicMock()

        triage_json = json.dumps({
            "suspicious_flows": [
                {
                    "flow_id": "HALLUCINATED_FLOW_ID!",
                    "suspicion_score": 0.99,
                    "reason": "Made up",
                }
            ]
        })

        provider.send = AsyncMock(return_value=triage_json)

        analyzer = ChainOfThoughtAnalyzer(provider=provider, top_n=1)
        ctx = make_ctx()

        findings = await analyzer.analyze(ctx)

        # No valid flows → no deep analysis → no findings
        assert len(findings) == 0
        # Only 1 LLM call (triage) — deep analysis was skipped
        assert provider.send.await_count == 1

    @pytest.mark.asyncio
    async def test_handles_empty_flows(self):
        """Returns empty if no flows are available."""
        provider = MagicMock()
        analyzer = ChainOfThoughtAnalyzer(provider=provider)
        ctx = make_ctx(high_priority_flow_ids=[])

        findings = await analyzer.analyze(ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_health_check_delegates(self):
        """health_check delegates to provider."""
        provider = MagicMock()
        provider.health_check = AsyncMock(return_value=True)
        analyzer = ChainOfThoughtAnalyzer(provider=provider)
        assert await analyzer.health_check() is True

    def test_name_property(self):
        provider = MagicMock()
        analyzer = ChainOfThoughtAnalyzer(provider=provider)
        assert analyzer.name == "ChainOfThought"
