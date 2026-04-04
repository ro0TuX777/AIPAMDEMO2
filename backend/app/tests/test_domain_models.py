"""Tests for domain models: ForensicData, Finding, BaseAnalyzer contract."""

from __future__ import annotations

import asyncio
from typing import List

import pytest

from backend.app.domain.forensic_data import ForensicData
from backend.app.domain.finding import Finding, FindingSeverity
from backend.app.analyzers.base import BaseAnalyzer


# ---------------------------------------------------------------------------
# ForensicData tests
# ---------------------------------------------------------------------------

class TestForensicData:
    def test_minimal_creation(self):
        """ForensicData can be created with only required fields."""
        data = ForensicData(
            job_id="test-001",
            exercise_id="exercise-1",
            mode="single_window",
        )
        assert data.job_id == "test-001"
        assert data.mode == "single_window"
        assert data.flows == []
        assert data.alerts == []
        assert data.events == []
        assert data.raw_packet_samples == []
        assert data.trafficllm_results is None
        assert data.anomaly_report is None

    def test_serialization_roundtrip(self):
        """ForensicData can be serialized to dict and back."""
        data = ForensicData(
            job_id="test-002",
            exercise_id="ex-2",
            mode="baseline_vs_exploit",
            pcap_filename="malware_sample",
            source_metadata={"connector": "upload"},
        )
        dumped = data.model_dump()
        restored = ForensicData.model_validate(dumped)
        assert restored.job_id == "test-002"
        assert restored.pcap_filename == "malware_sample"
        assert restored.source_metadata == {"connector": "upload"}


# ---------------------------------------------------------------------------
# Finding tests
# ---------------------------------------------------------------------------

class TestFinding:
    def test_minimal_finding(self):
        """Finding can be created with minimal required fields."""
        finding = Finding(
            id="finding-001",
            job_id="job-001",
            severity=FindingSeverity.HIGH,
            title="C2 Beaconing Detected",
            description="Periodic HTTPS connections to suspicious domain",
            analyzer_source="ollama",
        )
        assert finding.id == "finding-001"
        assert finding.severity == FindingSeverity.HIGH
        assert finding.severity.value == "high"
        assert finding.confidence == 0.0
        assert finding.evidence == []
        assert finding.affected_hosts == []

    def test_full_finding_with_mitre(self):
        """Finding with all MITRE fields populated."""
        finding = Finding(
            id="finding-002",
            job_id="job-001",
            mitre_technique_id="T1071.001",
            mitre_technique_name="Application Layer Protocol: Web Protocols",
            classification="IcedID",
            severity=FindingSeverity.CRITICAL,
            title="IcedID C2 Communication",
            description="Detected IcedID beacon over HTTPS",
            evidence=["TLS to suspected C2 at 185.X.X.X:443"],
            affected_hosts=["192.168.1.100", "185.123.45.67"],
            confidence=0.85,
            analyzer_source="ollama",
            attack_chain_stage="command_and_control",
            raw_data={"model_version": "v4"},
        )
        assert finding.mitre_technique_id == "T1071.001"
        assert finding.classification == "IcedID"
        assert len(finding.affected_hosts) == 2
        assert finding.raw_data["model_version"] == "v4"

    def test_severity_enum_values(self):
        """All expected severity levels exist."""
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"

    def test_finding_serialization(self):
        """Finding can be serialized to JSON-compatible dict."""
        finding = Finding(
            id="f-003",
            job_id="j-002",
            severity=FindingSeverity.MEDIUM,
            title="Test",
            description="Test finding",
            analyzer_source="test",
        )
        dumped = finding.model_dump(mode="json")
        assert dumped["severity"] == "medium"
        assert isinstance(dumped, dict)


# ---------------------------------------------------------------------------
# BaseAnalyzer contract tests
# ---------------------------------------------------------------------------

class TestBaseAnalyzerContract:
    def test_cannot_instantiate_base(self):
        """BaseAnalyzer cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseAnalyzer()

    def test_concrete_subclass_works(self):
        """A properly implemented subclass can be instantiated."""

        class FakeAnalyzer(BaseAnalyzer):
            async def analyze(self, data: ForensicData) -> List[Finding]:
                return []

            async def health_check(self) -> bool:
                return True

            @property
            def name(self) -> str:
                return "Fake"

        analyzer = FakeAnalyzer()
        assert analyzer.name == "Fake"

        # Test analyze returns empty list
        data = ForensicData(
            job_id="test", exercise_id="ex", mode="single_window"
        )
        result = asyncio.run(analyzer.analyze(data))
        assert result == []

        # Test health_check
        healthy = asyncio.run(analyzer.health_check())
        assert healthy is True

    def test_incomplete_subclass_fails(self):
        """Subclass missing required methods cannot be instantiated."""

        class IncompleteAnalyzer(BaseAnalyzer):
            async def analyze(self, data: ForensicData) -> List[Finding]:
                return []
            # Missing health_check and name

        with pytest.raises(TypeError):
            IncompleteAnalyzer()
