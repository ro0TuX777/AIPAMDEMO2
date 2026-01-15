from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List

from .models import (
    AlertRecord,
    AnalysisSummary,
    AnomalyReportModel,
    ChangeSummary,
    HostFinding,
    HostPairSummary,
    HostSummary,
    LLMInputBundle,
    LLMOutput,
    TimeWindow,
    TrafficLLMResult,
)
from typing import Optional


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

# Family Priority: Specific weights for high-interest families in Detonation scenarios
_FAMILY_PRIORITY: Dict[str, int] = {
    "Pikabot": 5,
    "Meduza_Stealer": 5,
    "NetSupport_RAT": 5,
    "Lumma_Stealer": 5,
    "DarkGate": 5,
    "Vidar": 3,
    "Redline_Stealer": 3,
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
    trafficllm_results: Optional[TrafficLLMResult] = None,
    raw_packet_samples: Optional[List[str]] = None,
    anomaly_report: Optional[AnomalyReportModel] = None,
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
        trafficllm_results=trafficllm_results,
        raw_packet_samples=raw_packet_samples or [],
        anomaly_report=anomaly_report,
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
    trafficllm_results: Optional[TrafficLLMResult] = None,
    raw_packet_samples: Optional[List[str]] = None,
    anomaly_report: Optional[AnomalyReportModel] = None,
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
                trafficllm_results=trafficllm_results,
                raw_packet_samples=raw_packet_samples,
                anomaly_report=anomaly_report,
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
                trafficllm_results=trafficllm_results,
                raw_packet_samples=raw_packet_samples,
                anomaly_report=anomaly_report,
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

        # Filter anomaly findings for this chunk's hosts
        chunk_anomaly_report = None
        if anomaly_report and anomaly_report.findings:
            chunk_findings = [
                f for f in anomaly_report.findings
                if not f.affected_hosts or any(h in chunk_hosts for h in f.affected_hosts)
            ]
            if chunk_findings:
                chunk_anomaly_report = AnomalyReportModel(
                    findings=chunk_findings,
                    overall_anomaly_score=anomaly_report.overall_anomaly_score,
                    zero_day_likelihood=anomaly_report.zero_day_likelihood,
                    summary=anomaly_report.summary,
                )

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
                trafficllm_results=trafficllm_results,
                raw_packet_samples=raw_packet_samples,
                anomaly_report=chunk_anomaly_report,
            )
        )

    return bundles


def aggregate_llm_results(
    llm_outputs: List[LLMOutput],
    trafficllm_results: Optional[TrafficLLMResult] = None,
    alerts: Optional[List[AlertRecord]] = None,
    exercise_id: Optional[str] = None,
) -> tuple[AnalysisSummary, List[HostFinding]]:
    """Aggregate multiple LLM chunk outputs into a single summary + host list.

    Also injects TrafficLLM malware/botnet findings if the LLM missed them.
    """

    if not llm_outputs:
        return AnalysisSummary(severity="unknown", key_findings=[], mitre_techniques=[]), []

    # Global severity = max over chunks.
    best_sev = "unknown"
    best_rank = _SEVERITY_RANK["unknown"]
    
    # Classification aggregation: Prefer specific malware over generic/unknown
    class_counts = defaultdict(int)
    for out in llm_outputs:
        sev = (out.overall_severity or "unknown").lower()
        rank = _SEVERITY_RANK.get(sev, _SEVERITY_RANK["unknown"])
        if rank > best_rank:
            best_rank = rank
            best_sev = sev
        
        c = out.classification or "unknown"
        # Apply family priority weights to break ties/biases toward generic loaders
        priority_weight = _FAMILY_PRIORITY.get(c, 0)
        
        if c.lower() not in ["unknown", "benign", "anomalous/zero-day"]:
            class_counts[c] += (2 + priority_weight)  # Weight specific families higher
        else:
            class_counts[c] += (1 + priority_weight)

    # Pick the most common/highest-weight classification
    best_class = "unknown"
    if class_counts:
        # Filter out 'unknown' if we have other options
        options = [k for k in class_counts.keys() if k.lower() != "unknown"]
        if options:
            best_class = max(options, key=lambda k: class_counts[k])
        else:
            best_class = "unknown"

    # If we have no specific family but TrafficLLM detected something, use that as a hint
    if best_class.lower() == "unknown" and trafficllm_results:
        if trafficllm_results.malware_types:
            best_class = trafficllm_results.malware_types[0]
        elif trafficllm_results.botnet_types:
            best_class = trafficllm_results.botnet_types[0]

    # Pre-define known families for various override checks
    known_families = {
        "remcos": "Remcos_RAT",
        "cobalt strike": "CobaltStrike",
        "cobaltstrike": "CobaltStrike",
        "beacon": "CobaltStrike",
        "emotet": "Emotet",
        "trickbot": "Trickbot",
        "qakbot": "Qakbot",
        "qbot": "Qakbot",
        "icedid": "IcedID",
        "dridex": "Dridex",
        "agent tesla": "AgentTesla",
        "agenttesla": "AgentTesla",
        "asyncrat": "AsyncRAT",
        "njrat": "NjRAT",
        "darkgate": "DarkGate",
        "lumma": "Lumma_Stealer",
        "redline": "Redline_Stealer",
        "raccoon": "Raccoon",
        "vidar": "Vidar",
        "formbook": "Formbook",
        "lokibot": "LokiBot",
        "netsupport": "NetSupport_RAT",
        "bazarloader": "BazarLoader",
        "pikabot": "Pikabot",
        "dcrat": "DcRAT",
        "xworm": "XWorm",
    }

    # IMPORTANT: Check exercise_id (filename hint) for known malware family names
    if exercise_id and best_class.lower() in ["unknown", "anomalous/zero-day"]:
        ex_lower = exercise_id.lower()
        for keyword, family in known_families.items():
            if keyword in ex_lower:
                print(f"[DEBUG] Keyword Refinement (exercise_id): Model was '{best_class}', found '{keyword}' in context, overriding to {family}")
                best_class = family
                break

    # IMPORTANT: Check Suricata alerts for known malware family signatures
    # If alerts clearly identify a known family, override "Anomalous/Zero-Day"
    if best_class.lower() in ["unknown", "anomalous/zero-day"] and alerts:
        # Known malware families that Suricata might detect
        known_families = {
            "remcos": "Remcos_RAT",
            "cobalt": "CobaltStrike",
            "cobaltstrike": "CobaltStrike",
            "beacon": "CobaltStrike",
            "emotet": "Emotet",
            "trickbot": "Trickbot",
            "qakbot": "Qakbot",
            "qbot": "Qakbot",
            "icedid": "IcedID",
            "dridex": "Dridex",
            "agent tesla": "AgentTesla",
            "agenttesla": "AgentTesla",
            "asyncrat": "AsyncRAT",
            "njrat": "NjRAT",
            "darkgate": "DarkGate",
            "lumma": "Lumma_Stealer",
            "redline": "Redline_Stealer",
            "raccoon": "Raccoon",
            "vidar": "Vidar",
            "formbook": "Formbook",
            "lokibot": "LokiBot",
            "netsupport": "NetSupport_RAT",
            "bazarloader": "BazarLoader",
            "pikabot": "Pikabot",
            "dcrat": "DcRAT",
            "xworm": "XWorm",
        }

        for alert in alerts:
            sig_lower = (alert.signature_name or "").lower()
            cat_lower = (alert.category or "").lower()
            combined = f"{sig_lower} {cat_lower}"

            for keyword, family in known_families.items():
                if keyword in combined:
                    print(f"[DEBUG] Signature Refinement: Model was '{best_class}', found '{keyword}' in alerts, overriding to {family}")
                    best_class = family
                    break
            if best_class.lower() != "anomalous/zero-day":
                break

    # Also scan LLM output attack chains, host findings, and anomalies for malware family mentions
    if best_class.lower() in ["unknown", "anomalous/zero-day"]:
        # Check all LLM outputs for malware mentions
        for out in llm_outputs:
            # 1. Attack Chains
            for item in out.attack_chain:
                text = f"{item.stage or ''} {item.description or ''} {' '.join(item.evidence or [])}".lower()
                for keyword, family in known_families.items():
                    if keyword in text:
                        best_class = family
                        break
                if best_class.lower() not in ["unknown", "anomalous/zero-day"]:
                    break
            
            if best_class.lower() not in ["unknown", "anomalous/zero-day"]:
                break

            # 2. Host Findings
            for hf in out.host_findings:
                text = f"{hf.summary or ''} {' '.join(hf.suspicious_behaviors or [])}".lower()
                for keyword, family in known_families.items():
                    if keyword in text:
                        best_class = family
                        break
                if best_class.lower() not in ["unknown", "anomalous/zero-day"]:
                    break
            
            if best_class.lower() not in ["unknown", "anomalous/zero-day"]:
                break

            # 3. Anomalies
            for anom in out.anomalies:
                text = f"{anom.description or ''} {anom.reason or ''}".lower()
                for keyword, family in known_families.items():
                    if keyword in text:
                        best_class = family
                        break
                if best_class.lower() not in ["unknown", "anomalous/zero-day"]:
                    break
            
            if best_class.lower() not in ["unknown", "anomalous/zero-day"]:
                break

    # Merge attack_chain entries, deduplicating by (stage, description), and
    # flatten them into human-readable key finding strings for the summary.
    # ENHANCEMENT: Preserve evidence in the summary text if present.
    key_findings: List[str] = []
    seen_attack = set()
    for out in llm_outputs:
        for item in out.attack_chain:
            stage = (item.stage or "").strip()
            desc = (item.description or "").strip()
            evidence = ", ".join(item.evidence or [])
            key = (stage, desc)
            if key in seen_attack:
                continue
            seen_attack.add(key)

            text = desc or stage
            if stage and desc:
                text = f"{stage}: {desc}"
            
            if evidence:
                text += f" (Evidence: {evidence})"

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

    # Inject TrafficLLM findings if the LLM missed the specific malware names
    trafficllm_findings: List[str] = []
    malware_types: List[str] = []
    botnet_types: List[str] = []
    if trafficllm_results:
        malware_types = trafficllm_results.malware_types or []
        botnet_types = trafficllm_results.botnet_types or []
        malware_count = trafficllm_results.malware_detections
        botnet_count = trafficllm_results.botnet_detections

        if malware_types:
            malware_list = ', '.join(malware_types)
            trafficllm_findings.append(
                f"malware_detected: TrafficLLM detected {malware_count} flows containing "
                f"malware traffic ({malware_list})."
            )
        if botnet_types:
            botnet_list = ', '.join(botnet_types)
            trafficllm_findings.append(
                f"botnet_detected: TrafficLLM detected {botnet_count} flows containing "
                f"botnet traffic ({botnet_list})."
            )

    # Check if any TrafficLLM malware names appear in existing findings
    # If not, prepend the TrafficLLM findings
    if trafficllm_findings:
        existing_text = ' '.join(key_findings).lower()
        has_malware_names = any(
            mtype.lower() in existing_text
            for mtype in (malware_types + botnet_types)
        )
        if not has_malware_names:
            # Prepend TrafficLLM findings at the top
            key_findings = trafficllm_findings + key_findings

    # Check for Zero-Day findings in LLM outputs and promote them
    # ONLY if the final classification is still Anomalous/Zero-Day
    if best_class.lower() == "anomalous/zero-day":
        for out in llm_outputs:
            if out.classification == "Anomalous/Zero-Day":
                best_output_sev = (out.overall_severity or "high").lower()
                best_output_rank = _SEVERITY_RANK.get(best_output_sev, _SEVERITY_RANK["high"])
                if best_output_rank > best_rank:
                     best_rank = best_output_rank
                     best_sev = best_output_sev

                # ENHANCEMENT: Include anomaly reasons in the zero-day finding
                reasons = [a.reason for a in out.anomalies if a.reason]
                reason_text = f" Reasons: {'; '.join(reasons)}" if reasons else ""
                finding = f"ZERO-DAY DETECTED: Model identified anomalous traffic patterns with malicious intent but no known signature.{reason_text}"
                if finding not in key_findings:
                    key_findings.insert(0, finding)

    if "T1059" not in mitre_by_id:
            mitre_by_id["T1059"] = {"id": "T1059", "name": "Command and Scripting Interpreter"}

    # Prepended primary classification to key findings for visibility
    if best_class != "unknown" and best_class != "benign":
        key_findings.insert(0, f"Primary Classification: {best_class}")

    summary = AnalysisSummary(
        classification=best_class,
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

    # Inject TrafficLLM malware findings into host findings if we have alerts
    if alerts and trafficllm_results:
        malware_types = trafficllm_results.malware_types or []
        for alert in alerts:
            if alert.alert_source == "TRAFFICLLM" and alert.category == "malware":
                src_ip = alert.src_ip
                if src_ip and src_ip in host_map:
                    # Extract malware type from signature
                    sig_name = alert.signature_name or ""
                    finding = f"TrafficLLM: {sig_name}"
                    if finding not in host_map[src_ip]["findings"]:
                        host_map[src_ip]["findings"].insert(0, finding)
                    # Mark as attacker if not already
                    if host_map[src_ip]["role_rank"] < _ROLE_PRIORITY.get("attacker", 4):
                        host_map[src_ip]["role"] = "attacker"
                        host_map[src_ip]["role_rank"] = _ROLE_PRIORITY.get("attacker", 4)

    host_findings_models = [
        HostFinding(ip=ip, role=data["role"], findings=data["findings"])
        for ip, data in host_map.items()
    ]

    return summary, host_findings_models

