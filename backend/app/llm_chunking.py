from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List

from .models import (
    AlertRecord,
    AnalysisSummary,
    ChangeSummary,
    HostFinding,
    HostPairSummary,
    HostSummary,
    LLMInputBundle,
    LLMOutput,
    TimeWindow,
)


# Weights used to turn ChangeSummary + alerts into a coarse anomaly score,
# tuned for a small malware detonation lab where high-severity alerts and
# big byte deltas are especially interesting and background noise is low.
_SEVERITY_WEIGHTS: Dict[str, float] = {
    "info": 0.3,
    "low": 1.0,
    "medium": 4.0,
    "high": 8.0,
    "critical": 12.0,
}

# Per-metric weights so that byte volume shifts matter more than just flow
# counts in a small lab.
_METRIC_WEIGHTS: Dict[str, float] = {
    "total_flows": 1.0,
    "total_bytes_sent": 2.0,
    "total_bytes_received": 2.5,
}

# Minimum ratio before we consider a change interesting, and a cap to avoid
# a single infinite ratio dominating everything.
_MIN_RATIO_FOR_SCORING: float = 1.2
_RATIO_CAP: float = 50.0

# Protocol bonuses: new SMB/RDP/SSH/TLS in exploit window are strong
# indicators of lateral movement or C2 in this environment.
_NEW_PROTO_BONUS_BY_NAME: Dict[str, float] = {
    "smb": 4.0,
    "rdp": 4.0,
    "ssh": 3.0,
    "tls": 2.5,
}
_NEW_PROTO_DEFAULT_BONUS: float = 1.5

# Ordering for collapsing multiple severities / roles
_SEVERITY_ORDER = ["unknown", "info", "low", "medium", "high", "critical"]
_SEVERITY_RANK: Dict[str, int] = {name: i for i, name in enumerate(_SEVERITY_ORDER)}

_ROLE_PRIORITY: Dict[str, int] = {
    "unknown": 0,
    "infrastructure": 1,
    "victim": 2,
    "attacker": 3,
}


def _alerts_by_host(alerts: List[AlertRecord]) -> Dict[str, List[AlertRecord]]:
    mapping: Dict[str, List[AlertRecord]] = defaultdict(list)
    for a in alerts:
        if a.src_ip:
            mapping[a.src_ip].append(a)
        if a.dst_ip and a.dst_ip != a.src_ip:
            mapping[a.dst_ip].append(a)
    return mapping


def score_change_summaries(
    change_summaries: List[ChangeSummary], alerts: List[AlertRecord]
) -> Dict[str, float]:
    """Compute a coarse anomaly score per host from ChangeSummary + alerts.

    The goal is ranking, not an absolute measure. We approximate the spec's
    guidance of "sum of metric ratios + severity weights" by:
    - Summing (ratio - 1) for ratios > 1 (clamped to avoid infinities)
    - Adding a small bonus per new protocol
    - Adding severity-weighted contributions from related alerts
    """

    alerts_map = _alerts_by_host(alerts)
    scores: Dict[str, float] = {}

    for ch in change_summaries:
        if ch.entity_type != "host":
            continue
        host = ch.entity_id
        score = 0.0

        # Metric ratios with per-metric weights. For a small lab, we
        # down-weight tiny changes and give more weight to byte volume
        # shifts than just flow count.
        for mc in ch.metric_changes:
            ratio = mc.ratio
            if ratio != ratio:  # NaN
                continue
            if ratio < _MIN_RATIO_FOR_SCORING:
                continue
            weight = _METRIC_WEIGHTS.get(mc.metric, 1.0)
            capped = min(ratio, _RATIO_CAP)
            score += weight * (capped - 1.0)

        # New protocols seen only in exploit window, with per-proto bonuses.
        for proto in ch.new_protocols:
            bonus = _NEW_PROTO_BONUS_BY_NAME.get(proto.lower(), _NEW_PROTO_DEFAULT_BONUS)
            score += bonus

        # Alerts associated with this host
        for a in alerts_map.get(host, []):
            sev = (a.severity or "").lower()
            score += _SEVERITY_WEIGHTS.get(sev, 0.0)

        scores[host] = score

    return scores


def _make_bundle(
    *,
    exercise_id: str,
    mode: str,
    time_ranges: Dict[str, TimeWindow],
    host_summaries_baseline: List[HostSummary],
    host_summaries_exploit: List[HostSummary],
    hostpair_summaries_baseline: List[HostPairSummary],
    hostpair_summaries_exploit: List[HostPairSummary],
    change_summaries: List[ChangeSummary],
    alerts: List[AlertRecord],
) -> LLMInputBundle:
    return LLMInputBundle(
        exercise_id=exercise_id,
        mode=mode,
        time_ranges=time_ranges,
        host_summaries_baseline=host_summaries_baseline,
        host_summaries_exploit=host_summaries_exploit,
        hostpair_summaries_baseline=hostpair_summaries_baseline,
        hostpair_summaries_exploit=hostpair_summaries_exploit,
        change_summaries=change_summaries,
        alerts=alerts,
    )


def build_llm_chunks(
    *,
    exercise_id: str,
    mode: str,
    time_ranges: Dict[str, TimeWindow],
    host_summaries_baseline: List[HostSummary],
    host_summaries_exploit: List[HostSummary],
    hostpair_summaries_baseline: List[HostPairSummary],
    hostpair_summaries_exploit: List[HostPairSummary],
    change_summaries: List[ChangeSummary],
    alerts: List[AlertRecord],
    max_hosts_per_chunk: int = 3,
) -> List[LLMInputBundle]:
    """Build one or more LLMInputBundle chunks based on anomaly scores.

    If no ChangeSummary data is available (e.g., single_window mode), this
    falls back to a single bundle containing all aggregated data, matching the
    previous behavior.
    """

    # No changes → single global bundle.
    if not change_summaries:
        return [
            _make_bundle(
                exercise_id=exercise_id,
                mode=mode,
                time_ranges=time_ranges,
                host_summaries_baseline=host_summaries_baseline,
                host_summaries_exploit=host_summaries_exploit,
                hostpair_summaries_baseline=hostpair_summaries_baseline,
                hostpair_summaries_exploit=hostpair_summaries_exploit,
                change_summaries=change_summaries,
                alerts=alerts,
            )
        ]

    scores = score_change_summaries(change_summaries, alerts)
    if not scores:
        return [
            _make_bundle(
                exercise_id=exercise_id,
                mode=mode,
                time_ranges=time_ranges,
                host_summaries_baseline=host_summaries_baseline,
                host_summaries_exploit=host_summaries_exploit,
                hostpair_summaries_baseline=hostpair_summaries_baseline,
                hostpair_summaries_exploit=hostpair_summaries_exploit,
                change_summaries=change_summaries,
                alerts=alerts,
            )
        ]

    # Order hosts by anomaly score descending.
    sorted_hosts: List[str] = [
        host for host, _ in sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    ]

    bundles: List[LLMInputBundle] = []

    for i in range(0, len(sorted_hosts), max_hosts_per_chunk):
        chunk_hosts = set(sorted_hosts[i : i + max_hosts_per_chunk])

        hs_b = [h for h in host_summaries_baseline if h.host_ip in chunk_hosts]
        hs_e = [h for h in host_summaries_exploit if h.host_ip in chunk_hosts]

        hps_b = [
            hp
            for hp in hostpair_summaries_baseline
            if hp.src_ip in chunk_hosts or hp.dst_ip in chunk_hosts
        ]
        hps_e = [
            hp
            for hp in hostpair_summaries_exploit
            if hp.src_ip in chunk_hosts or hp.dst_ip in chunk_hosts
        ]

        chgs = [
            ch
            for ch in change_summaries
            if ch.entity_type == "host" and ch.entity_id in chunk_hosts
        ]

        chunk_alerts = [
            a
            for a in alerts
            if (a.src_ip and a.src_ip in chunk_hosts)
            or (a.dst_ip and a.dst_ip in chunk_hosts)
        ]

        bundles.append(
            _make_bundle(
                exercise_id=exercise_id,
                mode=mode,
                time_ranges=time_ranges,
                host_summaries_baseline=hs_b,
                host_summaries_exploit=hs_e,
                hostpair_summaries_baseline=hps_b,
                hostpair_summaries_exploit=hps_e,
                change_summaries=chgs,
                alerts=chunk_alerts,
            )
        )

    return bundles


def aggregate_llm_results(
    llm_outputs: List[LLMOutput],
) -> tuple[AnalysisSummary, List[HostFinding]]:
    """Aggregate multiple LLM chunk outputs into a single summary + host list."""

    if not llm_outputs:
        return AnalysisSummary(severity="unknown", key_findings=[], mitre_techniques=[]), []

    # Global severity = max over chunks.
    best_sev = "unknown"
    best_rank = _SEVERITY_RANK["unknown"]
    for out in llm_outputs:
        sev = (out.overall_severity or "unknown").lower()
        rank = _SEVERITY_RANK.get(sev, _SEVERITY_RANK["unknown"])
        if rank > best_rank:
            best_rank = rank
            best_sev = sev

    # Merge attack_chain entries, deduplicating by (stage, description), and
    # flatten them into human-readable key finding strings for the summary.
    key_findings: List[str] = []
    seen_attack = set()
    for out in llm_outputs:
        for item in out.attack_chain:
            stage = (item.stage or "").strip()
            desc = (item.description or "").strip()
            key = (stage, desc)
            if key in seen_attack:
                continue
            seen_attack.add(key)

            if stage and desc:
                text = f"{stage}: {desc}"
            else:
                text = desc or stage

            if text and text not in key_findings:
                key_findings.append(text)

    # Merge MITRE techniques overall (unique by ID).
    mitre_by_id: Dict[str, Dict[str, str]] = {}
    for out in llm_outputs:
        for tech in out.mitre_techniques_overall:
            tid = tech.id
            if not tid:
                continue
            if tid not in mitre_by_id:
                mitre_by_id[tid] = {"id": tid, "name": tech.name}

    summary = AnalysisSummary(
        severity=best_sev,
        key_findings=key_findings,
        mitre_techniques=list(mitre_by_id.values()),
    )

    # Merge host findings across chunks.
    host_map: Dict[str, Dict[str, Any]] = {}
    for out in llm_outputs:
        for hf in out.host_findings:
            ip = hf.ip or "unknown"
            role_raw = (hf.role_in_attack or "unknown").lower()
            role_rank = _ROLE_PRIORITY.get(role_raw, 0)
            summary_text = hf.summary
            suspicious = hf.suspicious_behaviors or []

            entry = host_map.setdefault(
                ip, {"role": role_raw, "role_rank": role_rank, "findings": []}
            )

            if role_rank > entry["role_rank"]:
                entry["role"] = role_raw
                entry["role_rank"] = role_rank

            if summary_text:
                if summary_text not in entry["findings"]:
                    entry["findings"].append(summary_text)

            for s in suspicious:
                if s not in entry["findings"]:
                    entry["findings"].append(s)

    host_findings_models = [
        HostFinding(ip=ip, role=data["role"], findings=data["findings"])
        for ip, data in host_map.items()
    ]

    return summary, host_findings_models

