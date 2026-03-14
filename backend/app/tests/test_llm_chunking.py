from __future__ import annotations

from typing import Dict
from datetime import datetime

from app.llm_chunking import (
    aggregate_llm_results,
    build_llm_chunks,
    score_change_summaries,
)
from app.models import (
    AlertRecord,
    AnalysisSummary,
    ChangeSummary,
    HostSummary,
    MetricChange,
    TimeWindow,
)


def _make_host(ip: str, window: TimeWindow) -> HostSummary:
    return HostSummary(
        host_ip=ip,
        role="unknown",
        time_window=window,
        total_flows=0,
        total_bytes_sent=0,
        total_bytes_received=0,
        dns_queries_count=0,
        dns_unique_domains=0,
        http_requests_count=0,
        alerts_count=0,
    )


def _make_change(host: str, ratio: float) -> ChangeSummary:
    return ChangeSummary(
        entity_type="host",
        entity_id=host,
        metric_changes=[
            MetricChange(
                metric="total_bytes_sent",
                baseline_value=100.0,
                exploit_value=100.0 * ratio,
                ratio=ratio,
            )
        ],
    )


def test_score_change_summaries_orders_by_ratio_and_alerts():
    changes = [
        _make_change("10.0.0.1", 2.0),
        _make_change("10.0.0.2", 10.0),
    ]
    alerts = [
        AlertRecord(
            id="a1",
            timestamp=datetime.utcnow(),
            src_ip="10.0.0.1",
            dst_ip="10.0.0.99",
            severity="high",
            signature_name="sig1",
            category="cat",
            alert_source="suricata",
        )
    ]

    scores = score_change_summaries(changes, alerts)

    assert scores["10.0.0.2"] > scores["10.0.0.1"]


def test_build_llm_chunks_respects_host_ordering_and_chunk_size():
    now = datetime.utcnow()
    base_window = TimeWindow(start=now, end=now)
    time_ranges: Dict[str, TimeWindow] = {
        "baseline": base_window,
        "exploit": base_window,
    }

    hosts = [_make_host(f"10.0.0.{i}", base_window) for i in range(1, 5)]

    changes = [
        _make_change("10.0.0.1", 2.0),
        _make_change("10.0.0.2", 3.0),
        _make_change("10.0.0.3", 5.0),
        _make_change("10.0.0.4", 7.0),
    ]

    bundles = build_llm_chunks(
        exercise_id="ex1",
        mode="baseline_vs_exploit",
        time_ranges=time_ranges,
        host_summaries_baseline=hosts,
        host_summaries_exploit=hosts,
        hostpair_summaries_baseline=[],
        hostpair_summaries_exploit=[],
        change_summaries=changes,
        alerts=[],
        max_hosts_per_chunk=2,
    )

    assert len(bundles) == 2
    first_hosts = {h.host_ip for h in bundles[0].host_summaries_exploit}
    assert "10.0.0.4" in first_hosts and "10.0.0.3" in first_hosts


def test_aggregate_llm_results_merges_severity_hosts_and_key_findings():
    from app.models import AttackChainItem, HostFindingLLM, LLMOutput, MitreTechnique

    outputs = [
        LLMOutput(
            overall_severity="medium",
            attack_chain=[
                AttackChainItem(
                    stage="initial_access",
                    description="phishing",
                    evidence=[],
                    mitre_techniques=[MitreTechnique(id="T1110", name="Brute Force")],
                )
            ],
            mitre_techniques_overall=[MitreTechnique(id="T1110", name="Brute Force")],
            host_findings=[
                HostFindingLLM(
                    ip="10.0.0.1",
                    role_in_attack="victim",
                    summary="compromised host",
                    suspicious_behaviors=["outbound C2"],
                )
            ],
            anomalies=[],
        ),
        LLMOutput(
            overall_severity="high",
            attack_chain=[
                AttackChainItem(
                    stage="lateral_movement",
                    description="movement",
                    evidence=[],
                    mitre_techniques=[
                        MitreTechnique(id="T1110", name="Brute Force"),
                        MitreTechnique(id="T1566", name="Phishing"),
                    ],
                )
            ],
            mitre_techniques_overall=[
                MitreTechnique(id="T1110", name="Brute Force"),
                MitreTechnique(id="T1566", name="Phishing"),
            ],
            host_findings=[
                HostFindingLLM(
                    ip="10.0.0.1",
                    role_in_attack="victim",
                    summary="data exfil",
                    suspicious_behaviors=["large transfer"],
                ),
                HostFindingLLM(
                    ip="10.0.0.2",
                    role_in_attack="attacker",
                    summary="source of attack",
                    suspicious_behaviors=[],
                ),
            ],
            anomalies=[],
        ),
    ]

    summary, hosts = aggregate_llm_results(outputs)

    assert isinstance(summary, AnalysisSummary)
    assert summary.severity == "high"
    assert any(t["id"] == "T1566" for t in summary.mitre_techniques)
    # key_findings should be flattened strings derived from the attack_chain entries.
    assert any("initial_access" in k and "phishing" in k for k in summary.key_findings)
    assert any("lateral_movement" in k and "movement" in k for k in summary.key_findings)

    by_ip = {h.ip: h for h in hosts}
    assert by_ip["10.0.0.1"].role in ("victim", "victim")
    assert any("outbound C2" in f for f in by_ip["10.0.0.1"].findings)
    assert any("large transfer" in f for f in by_ip["10.0.0.1"].findings)
    assert by_ip["10.0.0.2"].role == "attacker"

