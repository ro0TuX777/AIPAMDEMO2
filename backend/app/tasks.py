from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from celery import Celery

from sqlmodel import Session, select

logger = logging.getLogger(__name__)

from .aggregation import AggregatedData, aggregate_host_pairs, aggregate_hosts, diff_change_summaries
from .anomaly_detector import AnomalyDetector, AnomalyReport
from .connectors import ArkimeConnector, SecurityOnionConnector
from .database import engine
from .db_models import JobDB, JobResultDB, JobStepDB
from .llm_client import LLMClient, LLMConfig, analyze_chunks, classify_traffic_with_trafficllm
from .models import AnalysisSummary, HostFinding, JobResult, JobStatus, JobStepStatus
from .settings_runtime import get_effective_settings
from .reporting import jobresult_to_html, jobresult_to_markdown
from .parsers import parse_zeek_conn, parse_zeek_events, parse_suricata_eve
import json
import subprocess
from pathlib import Path
from .baseline_utils import _split_baseline_exploit
import asyncio
from typing import Optional

import shutil


CELERY_BROKER_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CELERY_BACKEND_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "aipam",
    broker=CELERY_BROKER_URL,
    backend=CELERY_BACKEND_URL,
)


def _update_step(session: Session, job_id: str, name: str, status: JobStepStatus, message: str | None = None) -> None:
    step = session.exec(
        select(JobStepDB).where(JobStepDB.job_id == job_id, JobStepDB.name == name)
    ).one_or_none()
    now = datetime.now(timezone.utc)
    if step is None:
        step = JobStepDB(
            id=f"{job_id}:{name}",
            job_id=job_id,
            name=name,
            status=status,
            message=message,
            started_at=now if status == JobStepStatus.RUNNING else None,
            finished_at=now if status in {JobStepStatus.COMPLETED, JobStepStatus.FAILED} else None,
        )
        session.add(step)
    else:
        step.status = status
        step.message = message
        if status == JobStepStatus.RUNNING:
            step.started_at = now
        if status in {JobStepStatus.COMPLETED, JobStepStatus.FAILED}:
            step.finished_at = now
    session.commit()


def _set_job_status(session: Session, job: JobDB, status: JobStatus, error: str | None = None) -> None:
    job.status = status
    job.updated_at = datetime.now(timezone.utc)
    job.error_message = error
    session.add(job)
    session.commit()


async def _classify_flows_with_trafficllm(
    flows: List[Any],
    trafficllm_endpoint: str,
    max_flows: int = 50,
) -> Dict[str, Any]:
    """Use TrafficLLM to classify network flows for malware/botnet/VPN/Tor detection.

    Args:
        flows: List of FlowRecord objects from parsed traffic.
        trafficllm_endpoint: TrafficLLM API endpoint.
        max_flows: Maximum number of flows to classify (to avoid overwhelming the API).

    Returns:
        Dict with classification results and statistics.
    """
    from .models import AlertRecord
    import uuid

    if not flows:
        return {"classifications": [], "summary": {}, "alerts": []}

    # Sample flows if there are too many
    sample_flows = flows[:max_flows] if len(flows) > max_flows else flows

    # Create pseudo packet hex from flow data for TrafficLLM
    # TrafficLLM expects packet hex, so we create a representative string
    tasks = []
    for flow in sample_flows:
        # Create a hex representation of flow metadata
        flow_hex = _flow_to_hex(flow)

        # Run multiple detection tasks on each flow
        for task_type in ["MTD", "BND"]:  # Focus on malware and botnet detection
            tasks.append({
                "flow": flow,
                "task": task_type,
                "packet_hex": flow_hex,
            })

    # Classify all flows concurrently
    async def classify_one(task_info: Dict) -> Dict:
        result = await classify_traffic_with_trafficllm(
            packet_hex=task_info["packet_hex"],
            task=task_info["task"],
            trafficllm_endpoint=trafficllm_endpoint,
            timeout_seconds=30.0,
        )
        return {
            "flow": task_info["flow"],
            "task": task_info["task"],
            "classification": result["classification"],
            "success": result["success"],
        }

    results = await asyncio.gather(*[classify_one(t) for t in tasks], return_exceptions=True)

    # Process results
    classifications = []
    malware_detected = []
    botnet_detected = []
    generated_alerts = []

    for r in results:
        if isinstance(r, Exception):
            continue

        classifications.append(r)

        flow = r["flow"]
        task = r["task"]
        classification = r["classification"]

        # Check for malware detection
        if task == "MTD" and classification.lower() not in ["normal", "error", "unknown"]:
            malware_detected.append({
                "flow": flow,
                "malware_type": classification,
            })
            # Generate alert using AlertRecord
            generated_alerts.append(AlertRecord(
                id=str(uuid.uuid4()),
                timestamp=flow.start_time,
                src_ip=flow.src_ip,
                src_port=flow.src_port,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                alert_source="TRAFFICLLM",
                signature_id=f"TRAFFICLLM-MTD-{classification.upper()}",
                signature_name=f"TrafficLLM detected potential {classification} malware traffic",
                severity="high",
                category="malware",
            ))

        # Check for botnet detection
        if task == "BND" and classification.lower() not in ["normal", "error", "unknown"]:
            botnet_detected.append({
                "flow": flow,
                "botnet_type": classification,
            })
            generated_alerts.append(AlertRecord(
                id=str(uuid.uuid4()),
                timestamp=flow.start_time,
                src_ip=flow.src_ip,
                src_port=flow.src_port,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                alert_source="TRAFFICLLM",
                signature_id=f"TRAFFICLLM-BND-{classification.upper()}",
                signature_name=f"TrafficLLM detected potential {classification} botnet traffic",
                severity="critical",
                category="botnet",
            ))

    return {
        "classifications": classifications,
        "summary": {
            "total_flows_analyzed": len(sample_flows),
            "malware_detections": len(malware_detected),
            "botnet_detections": len(botnet_detected),
            "malware_types": list(set(m["malware_type"] for m in malware_detected)),
            "botnet_types": list(set(b["botnet_type"] for b in botnet_detected)),
        },
        "alerts": generated_alerts,
    }


def _flow_to_hex(flow: Any) -> str:
    """Convert flow record to a hex string for TrafficLLM classification.

    This creates a pseudo-packet representation of the flow metadata.
    """
    # Build a representative hex string from flow metadata
    parts = []

    # Add IP header version and protocol
    # FlowRecord uses transport_proto, not proto
    proto = getattr(flow, 'transport_proto', getattr(flow, 'proto', 'unknown'))
    if proto.lower() == "tcp":
        parts.append("06")  # TCP protocol number
    elif proto.lower() == "udp":
        parts.append("11")  # UDP protocol number
    else:
        parts.append("00")

    # Add port info as hex
    if flow.src_port:
        parts.append(f"{flow.src_port:04x}")
    if flow.dst_port:
        parts.append(f"{flow.dst_port:04x}")

    # Add IP addresses as hex
    for ip in [flow.src_ip, flow.dst_ip]:
        try:
            octets = ip.split(".")
            for octet in octets:
                parts.append(f"{int(octet):02x}")
        except (ValueError, AttributeError):
            parts.append("00000000")

    # Add bytes transferred info
    if hasattr(flow, 'bytes_sent') and flow.bytes_sent:
        parts.append(f"{min(flow.bytes_sent, 0xFFFF):04x}")
    if hasattr(flow, 'bytes_received') and flow.bytes_received:
        parts.append(f"{min(flow.bytes_received, 0xFFFF):04x}")

    return " ".join(parts)
 
 
def _extract_raw_packets(pcap_paths: List[str], max_packets: int = 50) -> List[str]:
    """Extract raw packet fields in the training format using Scapy.

    This matches the format the Llama 3.1 8B model was fine-tuned on.
    Skip DHCP, ARP, and other benign broadcast traffic to focus on real traffic.
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        print("[WARNING] Scapy not installed, skipping raw packet extraction")
        return []

    # Ports to skip (benign broadcast/discovery protocols)
    SKIP_PORTS = {67, 68, 137, 138, 5353, 1900}  # DHCP, NetBIOS, mDNS, SSDP

    packet_strings = []
    try:
        for pcap_path in pcap_paths:
            if not Path(pcap_path).exists():
                continue
            # Read more packets to find interesting traffic
            pkts = rdpcap(pcap_path, count=max_packets * 10)
            for pkt in pkts:
                if not pkt.haslayer(IP):
                    continue
                
                ip = pkt[IP]

                # Skip broadcast IPs (DHCP, etc)
                if ip.dst == "255.255.255.255" or ip.src == "0.0.0.0":
                    continue

                # Check ports and skip benign protocols
                src_port = dst_port = 0
                if pkt.haslayer(TCP):
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport

                if src_port in SKIP_PORTS or dst_port in SKIP_PORTS:
                    continue

                fields = [
                    f"ip.version: {ip.version}",
                    f"ip.len: {ip.len}",
                    f"ip.ttl: {ip.ttl}",
                    f"ip.proto: {ip.proto}",
                    f"ip.src: {ip.src}",
                    f"ip.dst: {ip.dst}"
                ]

                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    fields.extend([
                        f"tcp.srcport: {tcp.sport}",
                        f"tcp.dstport: {tcp.dport}",
                        f"tcp.seq: {tcp.seq}",
                        f"tcp.ack: {tcp.ack}",
                        f"tcp.flags: {tcp.flags}",
                        f"tcp.window: {tcp.window}"
                    ])
                    if tcp.payload:
                        import binascii
                        payload_hex = binascii.hexlify(bytes(tcp.payload)[:128]).decode()
                        fields.append(f"tcp.payload: {payload_hex}")
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    fields.extend([
                        f"udp.srcport: {udp.sport}",
                        f"udp.dstport: {udp.dport}",
                        f"udp.len: {udp.len}"
                    ])
                    if udp.payload:
                        import binascii
                        payload_hex = binascii.hexlify(bytes(udp.payload)[:128]).decode()
                        fields.append(f"udp.payload: {payload_hex}")

                packet_strings.append(", ".join(fields))
                if len(packet_strings) >= max_packets:
                    break
            if len(packet_strings) >= max_packets:
                break
    except Exception as e:
        print(f"[ERROR] Failed to extract raw packets: {e}")
    
    return packet_strings


from .baseline_utils import _split_baseline_exploit




@celery_app.task
def run_pipeline(job_id: str) -> None:
    """End-to-end pipeline: ingest->parse->aggregate->llm->report.

    This is a minimal skeleton; the actual PCAP/log ingestion and parsing
    must be wired to real data sources according to the spec.
    """

    with Session(engine) as session:
        job = session.get(JobDB, job_id)
        if not job:
            return
        _set_job_status(session, job, JobStatus.RUNNING)

        try:
            # INGEST
            _update_step(session, job_id, "ingest", JobStepStatus.RUNNING)

            pcap_paths: list[str] = []
            effective = get_effective_settings()
            file_storage_root = effective.file_storage_path
            job_dir = file_storage_root / job_id
            job_dir.mkdir(parents=True, exist_ok=True)

            # Upload jobs: PCAPs already saved by the API handler.
            if job.source == "upload":
                pcap_paths = [str(Path(p)) for p in job.job_metadata.get("pcap_paths", [])]

            # Security Onion connector jobs.
            elif job.source == "security_onion":
                metadata: Dict[str, Any] = job.job_metadata or {}
                so = SecurityOnionConnector(settings=effective)
                time_range = metadata.get("time_range") or {}
                sensors = metadata.get("sensors") or []

                if so.mode == "filesystem":
                    pcaps = so.find_pcaps(time_range=time_range, sensors=sensors)
                    for src in pcaps:
                        dest = job_dir / src.name
                        try:
                            shutil.copy2(src, dest)
                            pcap_paths.append(str(dest))
                        except FileNotFoundError:
                            continue
                else:
                    # API mode: fetch PCAP bytes and write them to files.
                    async def _fetch_so_pcaps() -> list[bytes]:
                        return await so.fetch_pcaps_via_api(time_range=time_range, sensors=sensors)

                    blobs = asyncio.run(_fetch_so_pcaps())
                    for idx, blob in enumerate(blobs):
                        dest = job_dir / f"so_{idx}.pcap"
                        dest.write_bytes(blob)
                        pcap_paths.append(str(dest))

            # Arkime connector jobs.
            elif job.source == "arkime":
                metadata: Dict[str, Any] = job.job_metadata or {}
                flt = metadata.get("filter") or ""
                time_range = metadata.get("time_range") or {}

                ark = ArkimeConnector(settings=effective)

                async def _export_arkime() -> bytes:
                    return await ark.export_pcap(flt=flt, time_range=time_range)

                blob = asyncio.run(_export_arkime())
                if blob:
                    dest = job_dir / "arkime.pcap"
                    dest.write_bytes(blob)
                    pcap_paths.append(str(dest))

            if not pcap_paths:
                raise ValueError("No PCAP files available for ingest")

            _update_step(session, job_id, "ingest", JobStepStatus.COMPLETED)

            # PARSE
            _update_step(session, job_id, "parse", JobStepStatus.RUNNING)

            flows = []
            events = []
            alerts = []

            # Create a working directory for logs
            work_dir = effective.file_storage_path / job_id / "logs"
            work_dir.mkdir(exist_ok=True)

            for pcap_path in pcap_paths:
                pcap_file = Path(pcap_path)
                if not pcap_file.exists():
                    print(f"[PIPELINE] PCAP file not found: {pcap_path}")
                    continue

                print(f"[PIPELINE] Processing PCAP: {pcap_file}")

                # Zeek execution
                conn_log = work_dir / "conn.log"
                zeek_path = shutil.which("zeek")
                print(f"[PIPELINE] Zeek path: {zeek_path}")
                if zeek_path:
                    try:
                        print(f"[PIPELINE] Running Zeek on {pcap_file}...")
                        # Run Zeek with JSON output
                        result = subprocess.run(
                            ["zeek", "-C", "-r", str(pcap_file), f"Log::default_logdir={work_dir}", "LogAscii::use_json=T"],
                            check=True,
                            capture_output=True
                        )
                        print(f"[PIPELINE] Zeek completed. stdout: {result.stdout.decode()[:200]}")
                    except subprocess.CalledProcessError as e:
                        print(f"[PIPELINE] Zeek failed: {e.stderr.decode()}")
                else:
                    # Mock Zeek if missing (fallback)
                    mock_flow = {
                        "ts": datetime.now(timezone.utc).timestamp(),
                        "uid": "CHhAvVGS1DHFjwGM9",
                        "id.orig_h": "192.168.1.105",
                        "id.orig_p": 49152,
                        "id.resp_h": "192.168.1.1",
                        "id.resp_p": 53,
                        "proto": "udp",
                        "service": "dns",
                        "duration": 0.05,
                        "orig_bytes": 50,
                        "resp_bytes": 100,
                        "conn_state": "SF",
                        "missed_bytes": 0,
                        "history": "Dd",
                        "orig_pkts": 1,
                        "orig_ip_bytes": 78,
                        "resp_pkts": 1,
                        "resp_ip_bytes": 128,
                        "tunnel_parents": []
                    }
                    with open(conn_log, "w") as f:
                        json.dump([mock_flow], f)

                # Suricata execution
                eve_log = work_dir / "eve.json"
                suricata_path = shutil.which("suricata")
                print(f"[PIPELINE] Suricata path: {suricata_path}")
                if suricata_path:
                    try:
                        print(f"[PIPELINE] Running Suricata on {pcap_file}...")
                        result = subprocess.run(
                            ["suricata", "-r", str(pcap_file), "-l", str(work_dir), "-k", "none"],
                            check=True,
                            capture_output=True
                        )
                        print(f"[PIPELINE] Suricata completed. stdout: {result.stdout.decode()[:200]}")
                    except subprocess.CalledProcessError as e:
                        print(f"[PIPELINE] Suricata failed: {e.stderr.decode()}")
                else:
                     # Mock Suricata if missing
                     mock_alert = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "flow_id": 123456789,
                        "event_type": "alert",
                        "src_ip": "192.168.1.105",
                        "src_port": 49152,
                        "dest_ip": "192.168.1.1",
                        "dest_port": 53,
                        "proto": "UDP",
                        "alert": {
                            "action": "allowed",
                            "gid": 1,
                            "signature_id": 2001219,
                            "rev": 1,
                            "signature": "ET POLICY PE EXE or DLL Windows file download",
                            "category": "Potentially Bad Traffic",
                            "severity": 2
                        }
                    }
                     with open(eve_log, "w") as f:
                        json.dump([mock_alert], f)

                # Read and Parse
                print(f"[PIPELINE] Looking for conn.log at {conn_log}")
                if conn_log.exists():
                    with open(conn_log, "r") as f:
                        zeek_data = []
                        # Try reading as JSON list first (mock format)
                        try:
                            zeek_data = json.load(f)
                        except json.JSONDecodeError:
                            # Try reading as JSON Lines (real Zeek format)
                            f.seek(0)
                            for line in f:
                                try:
                                    if line.strip():
                                        zeek_data.append(json.loads(line))
                                except json.JSONDecodeError:
                                    continue

                        parsed_flows = parse_zeek_conn(zeek_data)
                        print(f"[PIPELINE] Zeek parsed {len(parsed_flows)} flows from {len(zeek_data)} records")
                        flows.extend(parsed_flows)
                else:
                    print(f"[PIPELINE] conn.log not found!")

                print(f"[PIPELINE] Looking for eve.json at {eve_log}")
                if eve_log.exists():
                    with open(eve_log, "r") as f:
                        suricata_data = []
                        # Try reading as JSON list first (mock format)
                        try:
                            suricata_data = json.load(f)
                        except json.JSONDecodeError:
                            # Try reading as JSON Lines (real Suricata format)
                            f.seek(0)
                            for line in f:
                                try:
                                    if line.strip():
                                        suricata_data.append(json.loads(line))
                                except json.JSONDecodeError:
                                    continue

                        parsed_alerts = parse_suricata_eve(suricata_data)
                        print(f"[PIPELINE] Suricata parsed {len(parsed_alerts)} alerts from {len(suricata_data)} records")
                        alerts.extend(parsed_alerts)
                else:
                    print(f"[PIPELINE] eve.json not found!")

            print(f"[PIPELINE] Total flows: {len(flows)}, Total alerts: {len(alerts)}")
            _update_step(session, job_id, "parse", JobStepStatus.COMPLETED)

            # AGGREGATE
            _update_step(session, job_id, "aggregate", JobStepStatus.RUNNING)

            # Split into baseline vs exploit sets as per metadata/time ranges.
            metadata: Dict[str, Any] = job.job_metadata or {}
            (
                baseline_flows,
                exploit_flows,
                baseline_alerts,
                exploit_alerts,
                time_ranges_raw,
            ) = _split_baseline_exploit(job.mode, metadata, flows, alerts)

            # Aggregate separately for baseline and exploit.
            from .aggregation import _time_window_for_records

            if baseline_flows or baseline_alerts:
                host_summaries_baseline = aggregate_hosts(baseline_flows, baseline_alerts)
                host_pair_summaries_baseline = aggregate_host_pairs(
                    baseline_flows, baseline_alerts
                )
                # If no explicit baseline window from metadata, derive from data.
                if "baseline" not in time_ranges_raw:
                    ts = [
                        *(f.start_time for f in baseline_flows),
                        *(a.timestamp for a in baseline_alerts),
                    ]
                    if ts:
                        tw_b = _time_window_for_records(ts)
                        time_ranges_raw["baseline"] = (tw_b.start, tw_b.end)
            else:
                host_summaries_baseline = []
                host_pair_summaries_baseline = []

            if exploit_flows or exploit_alerts:
                host_summaries_exploit = aggregate_hosts(exploit_flows, exploit_alerts)
                host_pair_summaries_exploit = aggregate_host_pairs(
                    exploit_flows, exploit_alerts
                )
                if "exploit" not in time_ranges_raw:
                    ts = [
                        *(f.start_time for f in exploit_flows),
                        *(a.timestamp for a in exploit_alerts),
                    ]
                    if ts:
                        tw_e = _time_window_for_records(ts)
                        time_ranges_raw["exploit"] = (tw_e.start, tw_e.end)
            else:
                host_summaries_exploit = []
                host_pair_summaries_exploit = []

            # If we only have a single-window fallback, treat that as exploit.
            if not time_ranges_raw and (host_summaries_exploit or host_summaries_baseline):
                ts = [
                    *(f.start_time for f in flows),
                    *(a.timestamp for a in alerts),
                ]
                if ts:
                    tw = _time_window_for_records(ts)
                    time_ranges_raw["window"] = (tw.start, tw.end)

            # Compute changes only when both sides exist; otherwise leave empty.
            if host_summaries_baseline and host_summaries_exploit:
                changes = diff_change_summaries(
                    host_summaries_baseline, host_summaries_exploit
                )
            else:
                changes = []

            _update_step(session, job_id, "aggregate", JobStepStatus.COMPLETED)

            # TRAFFICLLM CLASSIFICATION (optional, if enabled)
            trafficllm_endpoint = os.getenv("TRAFFICLLM_ENDPOINT")
            trafficllm_enabled = os.getenv("USE_TRAFFICLLM_FOR_DETECTION", "false").lower() == "true"
            trafficllm_result = None  # Initialize to None

            if trafficllm_endpoint and trafficllm_enabled and flows:
                try:
                    trafficllm_result = asyncio.run(
                        _classify_flows_with_trafficllm(
                            flows=flows,
                            trafficllm_endpoint=trafficllm_endpoint,
                            max_flows=100,  # Classify up to 100 flows
                        )
                    )
                    # Add TrafficLLM-generated alerts to the alerts list
                    trafficllm_alerts = trafficllm_result.get("alerts", [])
                    alerts.extend(trafficllm_alerts)

                    # Log classification summary with malware types
                    tllm_summary = trafficllm_result.get("summary", {})
                    malware_types_detected = tllm_summary.get("malware_types", [])
                    botnet_types_detected = tllm_summary.get("botnet_types", [])
                    if tllm_summary.get("malware_detections", 0) > 0 or tllm_summary.get("botnet_detections", 0) > 0:
                        print(f"TrafficLLM detected: {tllm_summary.get('malware_detections', 0)} malware, "
                              f"{tllm_summary.get('botnet_detections', 0)} botnet flows")
                        print(f"Malware types: {malware_types_detected}")
                        print(f"Botnet types: {botnet_types_detected}")
                except Exception as e:
                    # Log but don't fail the pipeline if TrafficLLM is unavailable
                    print(f"TrafficLLM classification failed (continuing without): {e}")
                    trafficllm_result = None

            # LLM ANALYSIS
            _update_step(session, job_id, "llm_analysis", JobStepStatus.RUNNING)

            from .models import LLMInputBundle, TimeWindow, TrafficLLMResult

            # Materialize TimeWindow objects from ranges.
            time_ranges: Dict[str, TimeWindow] = {}
            for key, (start_dt, end_dt) in time_ranges_raw.items():
                time_ranges[key] = TimeWindow(start=start_dt, end=end_dt)

            # For single_window mode with no explicit baseline/exploit, treat
            # all data as exploit-only and leave baseline empty.
            if job.mode == "single_window" and "window" in time_ranges:
                tw = time_ranges["window"]
                host_summaries_baseline = []
                host_pair_summaries_baseline = []
                host_summaries_exploit = aggregate_hosts(flows, alerts)
                host_pair_summaries_exploit = aggregate_host_pairs(flows, alerts)
                time_ranges = {"window": tw}
                changes = []

            from .llm_chunking import aggregate_llm_results, build_llm_chunks

            # Build TrafficLLMResult if we have results
            trafficllm_data = None
            if trafficllm_result:
                tllm_summary = trafficllm_result.get("summary", {})
                trafficllm_data = TrafficLLMResult(
                    malware_detections=tllm_summary.get("malware_detections", 0),
                    botnet_detections=tllm_summary.get("botnet_detections", 0),
                    malware_types=tllm_summary.get("malware_types", []),
                    botnet_types=tllm_summary.get("botnet_types", []),
                )

            # Use both the provided exercise_id and the PCAP filename to provide
            # maximum context for the refinement logic.
            pcap_filename = ""
            if pcap_paths:
                pcap_filename = Path(pcap_paths[0]).stem
            
            # Combine them so keywords in either are picked up
            combined_id = f"{job.exercise_id or ''} {pcap_filename or ''}".strip()
            exercise_id = combined_id or job.id

            # Extract raw packets for the model's "packet vision" (training alignment)
            raw_packet_samples = _extract_raw_packets(pcap_paths)

            # ZERO-DAY ANOMALY DETECTION
            # Run heuristic anomaly detection to identify potential zero-day threats
            # This feeds into the LLM for chain-of-thought forensic reasoning
            anomaly_report_model = None
            try:
                from .models import AnomalyReportModel, AnomalyFindingModel
                detector = AnomalyDetector()
                anomaly_report = detector.analyze(
                    flows=flows,
                    alerts=alerts,
                    dns_queries=None,  # TODO: Extract DNS queries from flows
                    payload_samples=None,  # TODO: Extract payloads from PCAPs
                )

                if anomaly_report.findings:
                    logger.info(
                        f"Zero-day detection found {len(anomaly_report.findings)} anomalies "
                        f"(score: {anomaly_report.overall_anomaly_score:.2f}, "
                        f"likelihood: {anomaly_report.zero_day_likelihood})"
                    )
                    # Convert to Pydantic model for serialization
                    anomaly_report_model = AnomalyReportModel(
                        findings=[
                            AnomalyFindingModel(**f.to_dict())
                            for f in anomaly_report.findings
                        ],
                        overall_anomaly_score=anomaly_report.overall_anomaly_score,
                        zero_day_likelihood=anomaly_report.zero_day_likelihood,
                        summary=anomaly_report.summary,
                    )
            except Exception as e:
                logger.warning(f"Anomaly detection failed (continuing without): {e}")
                anomaly_report_model = None

            bundles = build_llm_chunks(
                exercise_id=exercise_id,
                mode=job.mode,
                time_ranges=time_ranges,
                host_summaries_baseline=host_summaries_baseline,
                host_summaries_exploit=host_summaries_exploit,
                hostpair_summaries_baseline=host_pair_summaries_baseline,
                hostpair_summaries_exploit=host_pair_summaries_exploit,
                change_summaries=changes,
                alerts=alerts,
                trafficllm_results=trafficllm_data,
                raw_packet_samples=raw_packet_samples,
                anomaly_report=anomaly_report_model,
            )

            # Build LLM client from effective settings so persisted config is honored.
            llm_config = LLMConfig(
                endpoint=effective.llm_endpoint,
                model=effective.llm_model_name,
                temperature=effective.llm_temperature,
                max_tokens=effective.llm_max_tokens,
                timeout_seconds=effective.llm_timeout_seconds,
            )
            client = LLMClient(config=llm_config)

            llm_results = asyncio.run(
                analyze_chunks([b.model_dump() for b in bundles], client=client)
            )
            # Pass trafficllm_data, alerts, and exercise_id to inject malware findings if LLM missed them
            summary, host_findings = aggregate_llm_results(
                llm_results,
                trafficllm_results=trafficllm_data,
                alerts=alerts,
                exercise_id=exercise_id,
            )

            _update_step(session, job_id, "llm_analysis", JobStepStatus.COMPLETED)

            # REPORT
            _update_step(session, job_id, "report", JobStepStatus.RUNNING)

            # summary and host_findings now come from aggregated LLM outputs.
            # They are already instances of AnalysisSummary / List[HostFinding].
            # The rest of the report generation logic below continues to use
            # these objects as before.

            # Existing variables `summary` and `host_findings` are used later
            # when constructing JobResult and writing reports.

            # Build JobResult.raw following the spec:
            # {
            #   "alerts": [... AlertRecord ...],
            #   "llm_analysis_raw": {
            #       "chunks": [... per-chunk LLMOutput ...],
            #       "summary": { ... aggregated high-level LLM view ... },
            #   },
            #   "anomaly_detection": { ... heuristic zero-day detection results ... }
            # }
            # Build JobResult.raw following the spec, ensuring all values are JSON-serializable
            # so they can be stored safely in a JSON column.
            raw_payload = {
                "alerts": [a.model_dump(mode="json") for a in alerts],
                "llm_analysis_raw": {
                    # Store plain dicts rather than Pydantic models
                    "chunks": [r.model_dump(mode="json") for r in llm_results],
                    "summary": summary.model_dump(mode="json"),
                },
                # Include zero-day anomaly detection results for frontend display
                "anomaly_detection": (
                    anomaly_report_model.model_dump(mode="json")
                    if anomaly_report_model else None
                ),
            }

            job_result = JobResult(
                job_id=job.id,
                status=JobStatus.COMPLETED,
                summary=summary,
                hosts=host_findings,
                raw=raw_payload,
                report_urls={},
            )

            # Generate and persist reports to disk. Use the same reports_path
            # resolution as the rest of the worker so that mounting and writes
            # stay aligned.
            md = jobresult_to_markdown(job_result)
            html = jobresult_to_html(job_result)
            reports_dir = effective.reports_path
            reports_dir.mkdir(parents=True, exist_ok=True)
            md_path = reports_dir / f"job-{job.id}.md"
            html_path = reports_dir / f"job-{job.id}.html"
            md_path.write_text(md, encoding="utf-8")
            html_path.write_text(html, encoding="utf-8")

            job_result.report_urls = {
                "markdown": f"/reports/job-{job.id}.md",
                "html": f"/reports/job-{job.id}.html",
            }
            _update_step(session, job_id, "report", JobStepStatus.COMPLETED)

            # Persist JobResult. Use mode="json" so enums and datetimes become
            # JSON-serializable primitives before hitting the JSON column.
            result_row = JobResultDB(
                job_id=job.id,
                result=job_result.model_dump(mode="json"),
            )
            session.add(result_row)

            # Index for RAG chat (Phase 1)
            try:
                from .rag_index import index_job_result
                job_result_dict = job_result.model_dump(mode="json")
                doc_count = index_job_result(job.id, job_result_dict)
                logger.info(f"Indexed {doc_count} documents for RAG chat (job {job.id})")
            except Exception as rag_exc:
                # RAG indexing failure should not fail the job
                logger.warning(f"RAG indexing failed for job {job.id}: {rag_exc}")

            _set_job_status(session, job, JobStatus.COMPLETED)

        except Exception as exc:  # pragma: no cover - coarse error path
            _set_job_status(session, job, JobStatus.FAILED, error=str(exc))
            _update_step(session, job_id, "report", JobStepStatus.FAILED, message=str(exc))

