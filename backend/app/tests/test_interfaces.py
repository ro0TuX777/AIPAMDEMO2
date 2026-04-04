"""Tests for app/core/interfaces.py contracts."""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from backend.app.core.interfaces import AnalysisContext, Finding, ForensicAnalyzer


class TestAnalysisContext:
    def test_minimal_creation(self):
        ctx = AnalysisContext(
            job_id="test-001",
            exercise_id="ex-001",
            mode="single_window",
        )
        assert ctx.job_id == "test-001"
        assert ctx.high_priority_flow_ids == []
        assert ctx.alert_ids == []
        assert ctx.metadata == {}

    def test_full_creation(self):
        ctx = AnalysisContext(
            job_id="test-002",
            exercise_id="ex-002",
            mode="baseline_vs_exploit",
            zeek_log_path=Path("/tmp/zeek/conn.log"),
            suricata_log_path=Path("/tmp/suricata/eve.json"),
            high_priority_flow_ids=["flow-1", "flow-2"],
            alert_ids=["alert-1"],
            metadata={"pcap": "sample.pcap"},
        )
        assert len(ctx.high_priority_flow_ids) == 2
        assert ctx.zeek_log_path is not None
        assert ctx.metadata["pcap"] == "sample.pcap"

    def test_serialization_roundtrip(self):
        ctx = AnalysisContext(
            job_id="test-003",
            exercise_id="ex-003",
            mode="single_window",
            high_priority_flow_ids=["f1", "f2"],
        )
        dumped = ctx.model_dump(mode="json")
        restored = AnalysisContext.model_validate(dumped)
        assert restored.job_id == "test-003"
        assert restored.high_priority_flow_ids == ["f1", "f2"]


class TestFinding:
    def test_all_required_fields(self):
        """Finding requires mitre_technique_id, confidence_score, raw_evidence_snippet, rationale."""
        f = Finding(
            mitre_technique_id="T1071.001",
            confidence_score=0.85,
            raw_evidence_snippet="TCP 192.168.1.100:49152 → 185.70.40.20:443",
            rationale="Long-duration TLS with beaconing pattern",
            severity="critical",
        )
        assert f.mitre_technique_id == "T1071.001"
        assert f.confidence_score == 0.85
        assert len(f.raw_evidence_snippet) > 0
        assert len(f.rationale) > 0

    def test_missing_required_field_raises(self):
        with pytest.raises(Exception):
            Finding(
                confidence_score=0.5,
                raw_evidence_snippet="data",
                rationale="reason",
                severity="low",
                # mitre_technique_id deliberately omitted
            )

    def test_optional_fields_default(self):
        f = Finding(
            mitre_technique_id="T1566",
            confidence_score=0.6,
            raw_evidence_snippet="evidence",
            rationale="rationale",
            severity="medium",
        )
        assert f.classification is None
        assert f.attack_chain_stage is None
        assert f.affected_hosts == []

    def test_full_finding(self):
        f = Finding(
            mitre_technique_id="T1573.002",
            confidence_score=0.95,
            raw_evidence_snippet="TLS traffic to known C2",
            rationale="Asymmetric crypto channel matching IcedID TTP",
            severity="critical",
            affected_hosts=["192.168.1.100"],
            classification="IcedID",
            attack_chain_stage="Command and Control",
        )
        assert f.classification == "IcedID"
        assert f.attack_chain_stage == "Command and Control"


class TestForensicAnalyzerContract:
    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            ForensicAnalyzer()  # type: ignore

    def test_concrete_implementation_works(self):
        class DummyAnalyzer(ForensicAnalyzer):
            async def analyze(self, ctx: AnalysisContext) -> List[Finding]:
                return [
                    Finding(
                        mitre_technique_id="T1566",
                        confidence_score=0.5,
                        raw_evidence_snippet="test",
                        rationale="test",
                        severity="info",
                    )
                ]

            async def health_check(self) -> bool:
                return True

            @property
            def name(self) -> str:
                return "dummy"

        analyzer = DummyAnalyzer()
        assert analyzer.name == "dummy"

    def test_incomplete_implementation_fails(self):
        with pytest.raises(TypeError):

            class BrokenAnalyzer(ForensicAnalyzer):
                async def analyze(self, ctx):
                    return []
                # Missing health_check and name

            BrokenAnalyzer()  # type: ignore
