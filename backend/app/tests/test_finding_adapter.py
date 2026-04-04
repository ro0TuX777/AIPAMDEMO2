"""Tests for the finding adapter: LLMOutput -> List[Finding] conversion."""

from __future__ import annotations


from backend.app.domain.finding_adapter import llm_output_to_findings
from backend.app.domain_models import (
    Anomaly,
    AttackChainItem,
    HostFindingLLM,
    LLMOutput,
    MitreTechnique,
)


def _make_llm_output(
    *,
    classification: str = "IcedID",
    overall_severity: str = "high",
    num_attack_chain: int = 2,
    num_anomalies: int = 1,
    num_overall_techniques: int = 3,
) -> LLMOutput:
    """Build a realistic LLMOutput for testing."""
    attack_chain = []
    technique_counter = 0
    for i in range(num_attack_chain):
        techniques = []
        for j in range(2):  # 2 techniques per stage
            technique_counter += 1
            techniques.append(MitreTechnique(
                id=f"T{1000 + technique_counter}",
                name=f"Technique {technique_counter}",
            ))
        attack_chain.append(AttackChainItem(
            stage=f"Stage {i + 1}",
            description=f"Attack description for stage {i + 1}",
            evidence=[f"Evidence item {i + 1}"],
            mitre_techniques=techniques,
        ))

    anomalies = []
    for i in range(num_anomalies):
        anomalies.append(Anomaly(
            description=f"Anomaly {i + 1}: unusual traffic pattern",
            related_hosts=["192.168.1.100"],
            confidence=0.75,
            reason=f"Reason for anomaly {i + 1}",
        ))

    # Overall techniques include attack chain techniques plus extras
    overall_techniques = []
    for i in range(num_overall_techniques):
        overall_techniques.append(MitreTechnique(
            id=f"T{2000 + i}",
            name=f"Overall Technique {i}",
        ))

    host_findings = [
        HostFindingLLM(
            ip="192.168.1.100",
            role_in_attack="victim",
            summary="Compromised workstation",
            suspicious_behaviors=["Beaconing to C2"],
        ),
    ]

    return LLMOutput(
        classification=classification,
        overall_severity=overall_severity,
        attack_chain=attack_chain,
        host_findings=host_findings,
        anomalies=anomalies,
        mitre_techniques_overall=overall_techniques,
    )


class TestLLMOutputToFindings:
    def test_attack_chain_produces_findings(self):
        """Each MITRE technique in attack chain becomes a separate Finding."""
        output = _make_llm_output(num_attack_chain=2, num_anomalies=0, num_overall_techniques=0)
        findings = llm_output_to_findings("job-001", output)

        # 2 stages × 2 techniques each = 4 findings
        assert len(findings) == 4
        for f in findings:
            assert f.job_id == "job-001"
            assert f.mitre_technique_id is not None
            assert f.classification == "IcedID"
            assert f.analyzer_source == "ollama"

    def test_anomalies_produce_findings(self):
        """Each anomaly becomes a separate Finding."""
        output = _make_llm_output(num_attack_chain=0, num_anomalies=3, num_overall_techniques=0)
        findings = llm_output_to_findings("job-002", output)

        assert len(findings) == 3
        for f in findings:
            assert "Anomaly" in f.title
            assert f.affected_hosts == ["192.168.1.100"]

    def test_overall_techniques_not_duplicated(self):
        """Overall techniques that appear in attack chain are not duplicated."""
        # Create an output where attack chain uses T1001, T1002
        # and overall techniques include T1001, T2000, T2001
        output = LLMOutput(
            classification="TestMalware",
            overall_severity="medium",
            attack_chain=[
                AttackChainItem(
                    stage="Stage 1",
                    description="Test",
                    evidence=[],
                    mitre_techniques=[
                        MitreTechnique(id="T1001", name="Data Obfuscation"),
                    ],
                ),
            ],
            host_findings=[],
            anomalies=[],
            mitre_techniques_overall=[
                MitreTechnique(id="T1001", name="Data Obfuscation"),  # duplicate
                MitreTechnique(id="T2000", name="Extra Technique"),  # unique
            ],
        )
        findings = llm_output_to_findings("job-003", output)

        technique_ids = [f.mitre_technique_id for f in findings if f.mitre_technique_id]
        # T1001 appears once (from attack chain), T2000 appears once (from overall)
        assert technique_ids.count("T1001") == 1
        assert technique_ids.count("T2000") == 1

    def test_empty_output_returns_empty_list(self):
        """LLMOutput with no attack chain, anomalies, or techniques returns empty."""
        output = LLMOutput(
            classification=None,
            overall_severity="info",
            attack_chain=[],
            host_findings=[],
            anomalies=[],
            mitre_techniques_overall=[],
        )
        findings = llm_output_to_findings("job-004", output)
        assert findings == []

    def test_finding_ids_are_unique(self):
        """Each generated Finding has a unique ID."""
        output = _make_llm_output(num_attack_chain=3, num_anomalies=2, num_overall_techniques=2)
        findings = llm_output_to_findings("job-005", output)

        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids)), "Finding IDs must be unique"

    def test_custom_analyzer_source(self):
        """Analyzer source is propagated to all findings."""
        output = _make_llm_output(num_attack_chain=1, num_anomalies=1, num_overall_techniques=0)
        findings = llm_output_to_findings(
            "job-006", output, analyzer_source="trafficllm"
        )

        for f in findings:
            assert f.analyzer_source == "trafficllm"

    def test_severity_mapping(self):
        """LLMOutput severity strings are correctly mapped to FindingSeverity."""
        for severity_str in ["critical", "high", "medium", "low", "info"]:
            output = _make_llm_output(
                num_attack_chain=1,
                num_anomalies=0,
                num_overall_techniques=0,
            )
            output.overall_severity = severity_str
            findings = llm_output_to_findings("job-007", output)
            # Attack chain findings should get the overall severity
            for f in findings:
                assert f.severity.value == severity_str
