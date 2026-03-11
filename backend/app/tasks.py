from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from celery import Celery

from sqlmodel import Session, select

from .logging_config import configure_logging, get_logger, set_log_context
from .aggregation import AggregatedData, aggregate_host_pairs, aggregate_hosts, diff_change_summaries
from .anomaly_detector import AnomalyDetector, AnomalyReport
from .connectors import ArkimeConnector, SecurityOnionConnector
from .database import engine
from .db_models import JobDB, JobResultDB, JobStepDB, PipelineCheckpointDB, FindingDB, EvidenceDB
from .llm_client import LLMClient, LLMConfig, analyze_chunks, classify_traffic_with_trafficllm
from .models import AnalysisSummary, HostFinding, JobResult, JobStatus, JobStepStatus
from .settings_runtime import get_effective_settings
from .reporting import jobresult_to_html, jobresult_to_markdown
from .parsers import parse_zeek_conn, parse_zeek_events, parse_suricata_eve
from .bzar_validator import bzar_enabled, parse_notice_log
import json
import hashlib
import subprocess
import sys
from pathlib import Path
from .baseline_utils import _split_baseline_exploit
import asyncio
from typing import Optional

configure_logging(component="worker")

logger = get_logger(__name__)
import shutil

# DAWN high-value concepts: immutable ledger + artifact provenance
from .ledger import get_ledger
from .artifact_registry import get_registry, sha256_file


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

    # --- DAWN: append to immutable ledger ---
    try:
        get_ledger().log_event(
            job_id=job_id,
            step=name,
            status=status.value if hasattr(status, "value") else str(status),
            error=message if status == JobStepStatus.FAILED else None,
        )
    except Exception:
        logger.debug("ledger write skipped for %s/%s", job_id, name, exc_info=True)


def _set_job_status(session: Session, job: JobDB, status: JobStatus, error: str | None = None) -> None:
    job.status = status
    job.updated_at = datetime.now(timezone.utc)
    job.error_message = error
    session.add(job)
    session.commit()

    # --- DAWN: append to immutable ledger ---
    try:
        get_ledger().log_event(
            job_id=job.id,
            step="job_status",
            status=status.value if hasattr(status, "value") else str(status),
            error=error,
        )
    except Exception:
        logger.debug("ledger write skipped for job %s", job.id, exc_info=True)


# ---------------------------------------------------------------------------
# Pipeline checkpointing helpers
# ---------------------------------------------------------------------------

def _save_checkpoint(
    session: Session,
    job_id: str,
    step_name: str,
    state_data: Dict[str, Any],
) -> None:
    """Persist the output state of a completed pipeline step.

    Upserts a PipelineCheckpointDB row so that on retry the step can be
    skipped and its saved state restored.
    """
    checkpoint_id = f"{job_id}:{step_name}"
    existing = session.get(PipelineCheckpointDB, checkpoint_id)
    now = datetime.now(timezone.utc)
    if existing:
        existing.state_data = state_data
        existing.completed_at = now
        session.add(existing)
    else:
        row = PipelineCheckpointDB(
            id=checkpoint_id,
            job_id=job_id,
            step_name=step_name,
            state_data=state_data,
            completed_at=now,
        )
        session.add(row)
    session.commit()


def _load_checkpoints(session: Session, job_id: str) -> Dict[str, Dict[str, Any]]:
    """Load all completed checkpoints for a job.

    Returns:
        Dict mapping step_name -> state_data for steps that have a
        completed checkpoint.
    """
    rows = session.exec(
        select(PipelineCheckpointDB).where(
            PipelineCheckpointDB.job_id == job_id,
            PipelineCheckpointDB.completed_at.is_not(None),  # type: ignore[union-attr]
        )
    ).all()
    return {r.step_name: r.state_data for r in rows}


def _clear_checkpoints(
    session: Session, job_id: str, from_step: Optional[str] = None
) -> int:
    """Clear checkpoints for a job, optionally starting from a given step.

    If ``from_step`` is provided, only checkpoints at or after that step
    in the pipeline order are removed.  If None, all checkpoints for the
    job are cleared.

    Returns:
        Number of checkpoints deleted.
    """
    STEP_ORDER = ["ingest", "parse", "aggregate", "llm_analysis", "report"]

    rows = session.exec(
        select(PipelineCheckpointDB).where(
            PipelineCheckpointDB.job_id == job_id
        )
    ).all()

    deleted = 0
    for row in rows:
        if from_step is None:
            session.delete(row)
            deleted += 1
        else:
            try:
                step_idx = STEP_ORDER.index(row.step_name)
                from_idx = STEP_ORDER.index(from_step)
                if step_idx >= from_idx:
                    session.delete(row)
                    deleted += 1
            except ValueError:
                # Unknown step name — delete it to be safe
                session.delete(row)
                deleted += 1

    if deleted:
        session.commit()
    return deleted


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
    from .domain_models import AlertRecord
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
        logger.warning("Scapy not installed, skipping raw packet extraction")
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
        logger.error(f"Failed to extract raw packets: {e}")
    
    return packet_strings


from .baseline_utils import _split_baseline_exploit




@celery_app.task
def run_pipeline(job_id: str) -> None:
    """End-to-end pipeline: ingest->parse->aggregate->llm->report.

    This is a minimal skeleton; the actual PCAP/log ingestion and parsing
    must be wired to real data sources according to the spec.
    """

    set_log_context(job_id=job_id)
    with Session(engine) as session:
        job = session.get(JobDB, job_id)
        if not job:
            return
        _set_job_status(session, job, JobStatus.RUNNING)

        try:
            set_log_context(step="ingest")
            # Load any existing checkpoints for resume support
            existing_checkpoints = _load_checkpoints(session, job_id)
            if existing_checkpoints:
                logger.info(
                    f"[PIPELINE] Found checkpoints for steps: "
                    f"{list(existing_checkpoints.keys())} — resuming"
                )

            # INGEST
            pcap_paths: list[str] = []
            if "ingest" in existing_checkpoints:
                pcap_paths = existing_checkpoints["ingest"].get("pcap_paths", [])
                logger.info(f"[PIPELINE] Restored {len(pcap_paths)} PCAP paths from checkpoint")
                _update_step(session, job_id, "ingest", JobStepStatus.COMPLETED,
                             message="Restored from checkpoint")
            else:
                _update_step(session, job_id, "ingest", JobStepStatus.RUNNING)
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

            # --- DAWN: register ingested PCAP artifacts ---
            try:
                registry = get_registry()
                for pp in pcap_paths:
                    digest = sha256_file(pp)
                    registry.register(
                        key=f"pcap:{job_id}:{Path(pp).name}",
                        digest=digest,
                        path=pp,
                        artifact_type="pcap",
                        producer_job_id=job_id,
                        producer_step="ingest",
                    )
            except Exception:
                logger.debug("artifact registration skipped (ingest)", exc_info=True)

            _update_step(session, job_id, "ingest", JobStepStatus.COMPLETED)
            _save_checkpoint(session, job_id, "ingest", {
                "pcap_paths": pcap_paths,
            })

            # PARSE
            set_log_context(step="parse")
            _update_step(session, job_id, "parse", JobStepStatus.RUNNING)

            flows = []
            events = []
            alerts = []

            # Create a working directory for logs
            work_dir = effective.file_storage_path / job_id / "logs"
            work_dir.mkdir(exist_ok=True)
            bzar_data = {"technique_ids": [], "notices": []}

            for pcap_path in pcap_paths:
                pcap_file = Path(pcap_path)
                if not pcap_file.exists():
                    logger.warning(f"[PIPELINE] PCAP file not found: {pcap_path}")
                    continue

                logger.info(f"[PIPELINE] Processing PCAP: {pcap_file}")

                # Zeek execution
                conn_log = work_dir / "conn.log"
                zeek_path = shutil.which("zeek")
                logger.info(f"[PIPELINE] Zeek path: {zeek_path}")
                if zeek_path:
                    try:
                        logger.info(f"[PIPELINE] Running Zeek on {pcap_file}...")
                        # Run Zeek with JSON output
                        zeek_cmd = [
                            "zeek",
                            "-C",
                            "-r",
                            str(pcap_file),
                            f"Log::default_logdir={work_dir}",
                            "LogAscii::use_json=T",
                        ]
                        bzar_script = os.getenv("BZAR_ZEEK_SCRIPT")
                        if bzar_script:
                            script_path = Path(bzar_script)
                            if script_path.exists():
                                zeek_cmd.append(str(script_path))
                            else:
                                logger.warning("BZAR_ZEEK_SCRIPT not found: %s", bzar_script)
                        result = subprocess.run(
                            zeek_cmd,
                            check=True,
                            capture_output=True
                        )
                        logger.info(f"[PIPELINE] Zeek completed. stdout: {result.stdout.decode()[:200]}")
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"[PIPELINE] Zeek failed: {e.stderr.decode()}")
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
                logger.info(f"[PIPELINE] Suricata path: {suricata_path}")
                if suricata_path:
                    try:
                        logger.info(f"[PIPELINE] Running Suricata on {pcap_file}...")
                        result = subprocess.run(
                            ["suricata", "-r", str(pcap_file), "-l", str(work_dir), "-k", "none"],
                            check=True,
                            capture_output=True
                        )
                        logger.info(f"[PIPELINE] Suricata completed. stdout: {result.stdout.decode()[:200]}")
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"[PIPELINE] Suricata failed: {e.stderr.decode()}")
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
                logger.info(f"[PIPELINE] Looking for conn.log at {conn_log}")
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
                        logger.info(f"[PIPELINE] Zeek parsed {len(parsed_flows)} flows from {len(zeek_data)} records")
                        flows.extend(parsed_flows)
                else:
                    logger.warning(f"[PIPELINE] conn.log not found!")

                logger.info(f"[PIPELINE] Looking for eve.json at {eve_log}")
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
                        logger.info(f"[PIPELINE] Suricata parsed {len(parsed_alerts)} alerts from {len(suricata_data)} records")
                        alerts.extend(parsed_alerts)
                else:
                    logger.warning(f"[PIPELINE] eve.json not found!")

            if bzar_enabled():
                notice_log = work_dir / "notice.log"
                bzar_data = parse_notice_log(notice_log)
                if bzar_data.get("technique_ids"):
                    logger.info(
                        "[PIPELINE] BZAR techniques detected: %s",
                        ", ".join(bzar_data.get("technique_ids", [])),
                    )

            logger.info(f"[PIPELINE] Total flows: {len(flows)}, Total alerts: {len(alerts)}")
            _update_step(session, job_id, "parse", JobStepStatus.COMPLETED)
            _save_checkpoint(session, job_id, "parse", {
                "flow_count": len(flows),
                "alert_count": len(alerts),
                "bzar": bzar_data,
            })

            # EMBED ALL FLOWS into LanceDB for semantic retrieval
            try:
                from .flow_vectorstore import embed_flows
                flow_index_count = embed_flows(job_id, flows, alerts)
                logger.info(f"[PIPELINE] Indexed {flow_index_count} flows in LanceDB")
            except Exception as e:
                logger.warning(f"[PIPELINE] Flow vectorstore indexing failed (continuing): {e}")

            # AGGREGATE
            set_log_context(step="aggregate")
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
            _save_checkpoint(session, job_id, "aggregate", {
                "host_summaries_baseline_count": len(host_summaries_baseline),
                "host_summaries_exploit_count": len(host_summaries_exploit),
                "changes_count": len(changes),
            })

            # ZERO-DAY ANOMALY DETECTION
            # Run heuristic anomaly detection AFTER aggregate but BEFORE LLM,
            # so results are available for partial display while LLM is working.
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
                        logger.info(
                            f"TrafficLLM detected: {tllm_summary.get('malware_detections', 0)} malware, "
                            f"{tllm_summary.get('botnet_detections', 0)} botnet flows"
                        )
                        logger.info(f"Malware types: {malware_types_detected}")
                        logger.info(f"Botnet types: {botnet_types_detected}")
                except Exception as e:
                    # Log but don't fail the pipeline if TrafficLLM is unavailable
                    logger.warning(f"TrafficLLM classification failed (continuing without): {e}")
                    trafficllm_result = None

            # SEMANTIC FLOW RETRIEVAL — retrieve the most relevant flows
            # instead of using a hard cap on the first N.
            try:
                from .flow_vectorstore import retrieve_relevant_flows
                # Build a query from the job context for retrieval
                retrieval_query = (
                    f"forensic analysis {job.mode} "
                    f"{' '.join(a.signature_name or '' for a in alerts[:10])} "
                    f"anomaly malware C2 lateral movement"
                )
                relevant_flow_dicts = retrieve_relevant_flows(
                    job_id, retrieval_query, top_k=200
                )
                logger.info(
                    f"[PIPELINE] Retrieved {len(relevant_flow_dicts)} semantically "
                    f"relevant flows out of {len(flows)} total"
                )
            except Exception as e:
                logger.warning(f"[PIPELINE] Semantic flow retrieval failed (using all flows): {e}")

            # PERSIST PARTIAL RESULT — these intermediate insights are
            # available to the frontend while the slow LLM analysis runs.
            try:
                from .partial_results import save_partial_result
                partial_data = {
                    "flow_count": len(flows),
                    "alert_count": len(alerts),
                    "top_alerts": [a.model_dump(mode="json") for a in alerts[:20]],
                    "host_summaries": [
                        h.model_dump(mode="json")
                        for h in (host_summaries_exploit or host_summaries_baseline)[:30]
                    ],
                    "anomaly_detection": (
                        anomaly_report_model.model_dump(mode="json")
                        if anomaly_report_model else None
                    ),
                    "trafficllm": (
                        trafficllm_data.model_dump(mode="json")
                        if trafficllm_data else None
                    ),
                }
                save_partial_result(job_id, partial_data)
            except Exception as e:
                logger.warning(f"[PIPELINE] Partial result save failed (continuing): {e}")

            # LLM ANALYSIS
            set_log_context(step="llm_analysis")
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
            _save_checkpoint(session, job_id, "llm_analysis", {
                "classification": summary.classification,
                "severity": summary.severity,
                "technique_count": len(summary.mitre_techniques),
            })

            # Persist atomic findings for cross-job analytics
            try:
                from .domain.finding_adapter import llm_output_to_findings, persist_findings
                all_findings = []
                for llm_out in llm_results:
                    all_findings.extend(
                        llm_output_to_findings(job.id, llm_out, analyzer_source="ollama")
                    )
                finding_count = persist_findings(session, all_findings)
                logger.info(f"Persisted {finding_count} findings for job {job.id}")
            except Exception as finding_exc:
                # Finding persistence failure should not fail the job
                logger.warning(f"Finding persistence failed for job {job.id}: {finding_exc}")

            # REPORT
            set_log_context(step="report")
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
                "bzar": bzar_data if bzar_enabled() else None,
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
            finding_rows = session.exec(
                select(FindingDB).where(FindingDB.job_id == job.id)
            ).all()
            from .cti.lookup import enrich_findings
            finding_dicts = enrich_findings(session, finding_rows)
            finding_ids = [f.id for f in finding_rows]
            evidence_rows = []
            if finding_ids:
                evidence_rows = session.exec(
                    select(EvidenceDB).where(EvidenceDB.finding_id.in_(finding_ids))
                ).all()

            # Query extracted files from V2 File table
            extracted_file_rows: list[dict] = []
            try:
                from sqlalchemy.orm import Session as SASession
                from sqlalchemy import text as sa_text
                sa_session = SASession(bind=session.connection())
                rows = sa_session.execute(
                    sa_text("SELECT file_id, filename, sha256, size_bytes, mime, yara_matches_json FROM files WHERE job_id = :jid"),
                    {"jid": job.id},
                ).fetchall()
                for r in rows:
                    yara_m = []
                    if r[5]:
                        try:
                            yara_m = json.loads(r[5])
                        except Exception:
                            pass
                    extracted_file_rows.append({
                        "file_id": r[0], "filename": r[1], "sha256": r[2],
                        "size_bytes": r[3], "mime": r[4], "yara_matches": yara_m,
                    })
                logger.info("[REPORT] Found %d extracted files for report", len(extracted_file_rows))
            except Exception as exc:
                logger.warning("[REPORT] Could not query files table: %s", exc)

            md = jobresult_to_markdown(job_result, finding_dicts, evidence_rows, extracted_file_rows)
            html = jobresult_to_html(job_result, finding_dicts, evidence_rows, extracted_file_rows)
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

            # --- DAWN: register report artifacts ---
            try:
                registry = get_registry()
                for rpath in (md_path, html_path):
                    digest = sha256_file(rpath)
                    registry.register(
                        key=f"report:{job_id}:{rpath.name}",
                        digest=digest,
                        path=str(rpath),
                        artifact_type="report",
                        producer_job_id=job_id,
                        producer_step="report",
                        parent_keys=[f"pcap:{job_id}:{Path(p).name}" for p in pcap_paths],
                    )
            except Exception:
                logger.debug("artifact registration skipped (report)", exc_info=True)

            _update_step(session, job_id, "report", JobStepStatus.COMPLETED)
            _save_checkpoint(session, job_id, "report", {
                "report_urls": job_result.report_urls,
            })

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

            # Clean up partial result — full result now available
            try:
                from .partial_results import delete_partial_result
                delete_partial_result(job.id)
            except Exception:
                pass

            _set_job_status(session, job, JobStatus.COMPLETED)

        except Exception as exc:  # pragma: no cover - coarse error path
            logger.exception("Pipeline failed")
            _set_job_status(session, job, JobStatus.FAILED, error=str(exc))
            _update_step(session, job_id, "report", JobStepStatus.FAILED, message=str(exc))

@celery_app.task
def run_finetuning_pipeline() -> str:
    """Run the MLX fine-tuning pipeline as a background task.
    
    Triggered from the UI. Uses settings from the database/env.
    Updates the DAWN training ledger upon completion.
    """
    import uuid
    import hashlib
    
    job_id = str(uuid.uuid4())
    set_log_context(job_id=job_id, step="finetune")
    logger.info(f"[FINETUNE] Starting fine-tuning job {job_id}")
    
    effective = get_effective_settings()
    
    # 1. Resolve Paths
    # dataset_storage_path is already a Path object from settings_runtime
    base_data_dir = effective.dataset_storage_path
    
    # Rewrite host paths for Docker compatibility
    # e.g. /Volumes/FA -> /external_data/FA
    in_docker = os.path.exists("/.dockerenv")
    if in_docker and str(base_data_dir).startswith("/Volumes"):
        relative = str(base_data_dir).replace("/Volumes/", "", 1)
        base_data_dir = Path("/external_data") / relative
        logger.info(f"Rewriting external path {effective.dataset_storage_path} to {base_data_dir}")
    
    train_data = base_data_dir / "training" / "train.jsonl"
    val_data = base_data_dir / "training" / "validation.jsonl"

    if not train_data.exists():
        msg = f"Training data not found at {train_data}"
        logger.error(msg)
        return msg
        
    # Output directory for the model
    # We'll use a specific run directory to avoid overwriting
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_dir = base_data_dir / "models" / f"run_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 2. Get Configuration
    # We use settings from the DB (via effective settings if mapped, 
    # but settings_runtime doesn't map all fine-tune params yet, 
    # so we might need to query SettingsDB directly or update EffectiveSettings.
    # For now, let's query DB directly for the specific fine-tuning params to be safe
    # as they might not all be in EffectiveSettings yet.)
    from .database import get_session
    from .db_models import SettingsDB
    
    with get_session() as session:
        settings_row = session.get(SettingsDB, 1)
        vals = settings_row.values if settings_row else {}
        
    base_model = vals.get("finetune_base_model", "mlx-community/Meta-Llama-3.1-8B-Instruct-4bit")
    lora_rank = int(vals.get("finetune_lora_rank") or 8)
    learning_rate = float(vals.get("finetune_learning_rate") or 1e-5)
    max_seq_len = int(vals.get("finetune_max_seq_length") or 1024)
    # Default params not in settings yet
    batch_size = 2
    iters = 1000
    num_layers = 16
    
    # 3. Construct & Execute
    backend = effective.finetuning_backend.lower()
    
    # ── MLX in Docker → Delegate to host-native trainer ──
    if backend == "mlx" and in_docker:
        import urllib.request
        import urllib.error
        
        host_trainer_url = os.environ.get("HOST_TRAINER_URL", "http://host.docker.internal:8002")
        logger.info(f"[FINETUNE] MLX in Docker — delegating to host trainer at {host_trainer_url}")
        
        # Use ORIGINAL host paths (not rewritten), since host trainer runs natively on macOS
        original_base = effective.dataset_storage_path
        host_config = {
            "job_id": job_id,
            "train_data": str(original_base / "training" / "train.jsonl"),
            "val_data": str(original_base / "training" / "validation.jsonl"),
            "output_dir": str(original_base / "models" / f"run_{timestamp}"),
            "base_model": base_model,
            "batch_size": batch_size,
            "iters": iters,
            "learning_rate": learning_rate,
            "lora_rank": lora_rank,
            "num_layers": num_layers,
            "max_seq_length": max_seq_len,
        }
        
        try:
            req = urllib.request.Request(
                f"{host_trainer_url}/train",
                data=json.dumps(host_config).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                logger.info(f"[FINETUNE] Host trainer accepted job: {result}")
                return f"Delegated to host trainer: {result.get('job_id', job_id)}"
        except urllib.error.URLError as e:
            msg = (
                f"[FINETUNE] Cannot reach host trainer at {host_trainer_url}. "
                f"Start it with: python finetuning/host_trainer.py — Error: {e}"
            )
            logger.error(msg)
            return msg
        except Exception as e:
            logger.error(f"[FINETUNE] Host trainer delegation failed: {e}")
            return f"Host trainer error: {e}"
    
    # ── CUDA / local execution (subprocess) ──
    # Scripts are mounted at /data/finetuning/ inside Docker
    finetuning_dir = Path("/data/finetuning")
    if not finetuning_dir.exists():
        # Fallback for local dev
        finetuning_dir = Path(__file__).resolve().parents[2] / "finetuning"
    
    if backend == "mlx":
        script_name = "finetune_mlx.py"
        script_path = finetuning_dir / script_name
        logger.info(f"[FINETUNE] Using MLX backend (local): {script_path}")
    else:
        script_name = "finetune_llama.py"
        script_path = finetuning_dir / script_name
        logger.info(f"[FINETUNE] Using CUDA/Unsloth backend: {script_path}")

    cmd = [
        sys.executable, str(script_path),
        "--data", str(train_data),
        "--output", str(output_dir),
        "--base-model", base_model,
        "--batch-size", str(batch_size),
        "--iters", str(iters),
        "--learning-rate", str(learning_rate),
        "--lora-rank", str(lora_rank),
        "--num-layers", str(num_layers),
        "--max-seq-length", str(max_seq_len),
    ]
    
    if val_data.exists():
        cmd.extend(["--val-data", str(val_data)])
        
    logger.info(f"[FINETUNE] Executing: {' '.join(cmd)}")
    
    # 4. Record 'Start' in Ledger
    # Use writable /data/ volume (not /data/finetuning/ which is read-only)
    ledger_path = Path("/data/dawn_training_ledger.jsonl")
    if not ledger_path.parent.exists():
        # Fallback for local dev
        ledger_path = Path(__file__).resolve().parents[2] / "finetuning" / "dawn_training_ledger.jsonl"
    
    def append_ledger(entry: Dict[str, Any]):
        try:
            with open(ledger_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"[FINETUNE] Failed to write to ledger: {e}")

    config_str = f"{base_model}{lora_rank}{learning_rate}{max_seq_len}"
    config_hash = hashlib.md5(config_str.encode()).hexdigest()
    
    start_entry = {
        "event_type": "sft_training_start",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "job_id": job_id,
        "base_model": base_model,
        "config_hash": config_hash,
        "config": {
            "lora_rank": lora_rank,
            "learning_rate": learning_rate,
            "max_seq_length": max_seq_len,
            "batch_size": batch_size,
            "iters": iters
        }
    }
    append_ledger(start_entry)
    
    # 5. Execute
    start_time = datetime.now(timezone.utc)
    last_update_time = start_time
    
    # Regex patterns for progress parsing
    import re
    mlx_pattern = re.compile(r"Iter (\d+): Val loss ([\d\.]+), Train loss ([\d\.]+)")
    
    try:
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        logs = []
        if process.stdout:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                    
                logger.info(f"[FINETUNE_SCRIPT] {line}")
                logs.append(line)
                
                now = datetime.now(timezone.utc)
                if (now - last_update_time).total_seconds() > 5:
                    
                    mlx_match = mlx_pattern.search(line)
                    if mlx_match:
                        iter_num = int(mlx_match.group(1))
                        val_loss = float(mlx_match.group(2))
                        train_loss = float(mlx_match.group(3))
                        
                        progress_entry = {
                            "event_type": "sft_training_progress",
                            "timestamp": now.isoformat(),
                            "job_id": job_id,
                            "base_model": base_model,
                            "phase_label": f"Iter {iter_num}/{iters}",
                            "metrics": {
                                "current_iter": iter_num,
                                "total_iters": iters,
                                "train_loss": train_loss,
                                "eval_loss": val_loss,
                                "progress_percent": (iter_num / iters) * 100
                            }
                        }
                        append_ledger(progress_entry)
                        last_update_time = now
                        continue

                    if line.startswith("{") and "'loss':" in line:
                         try:
                             loss_match = re.search(r"'loss':\s*([\d\.]+)", line)
                             epoch_match = re.search(r"'epoch':\s*([\d\.]+)", line)
                             
                             if loss_match:
                                 train_loss = float(loss_match.group(1))
                                 epoch = float(epoch_match.group(1)) if epoch_match else 0.0
                                 
                                 progress_entry = {
                                    "event_type": "sft_training_progress",
                                    "timestamp": now.isoformat(),
                                    "job_id": job_id,
                                    "base_model": base_model,
                                    "phase_label": f"Epoch {epoch:.2f}",
                                    "metrics": {
                                        "train_loss": train_loss,
                                        "epoch": epoch
                                    }
                                 }
                                 append_ledger(progress_entry)
                                 last_update_time = now
                                 continue
                         except Exception:
                             pass

        process.wait()
        
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, cmd)
            
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        # 6. Record 'Success' in Ledger
        success_entry = {
            "event_type": "sft_training_complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "job_id": job_id,
            "base_model": base_model,
            "config_hash": config_hash,
            "duration_seconds": duration,
            "max_seq_length": max_seq_len,
            "lora_r": lora_rank,
            "lora_alpha": lora_rank * 2,
            "metrics": {
                "train_loss": 0.0,
                "output_dir": str(output_dir)
            }
        }
        
        for line in reversed(logs):
             mlx_match = mlx_pattern.search(line)
             if mlx_match:
                 success_entry["metrics"]["train_loss"] = float(mlx_match.group(3))
                 success_entry["metrics"]["eval_loss"] = float(mlx_match.group(2))
                 break
                 
        append_ledger(success_entry)
        logger.info(f"[FINETUNE] Job {job_id} completed successfully in {duration:.1f}s")
        return f"Success: {job_id}"
        
    except Exception as e:
        logger.error(f"[FINETUNE] Job {job_id} failed: {e}")
        failure_entry = {
            "event_type": "sft_training_failed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "job_id": job_id,
            "base_model": base_model,
            "error": str(e)
        }
        append_ledger(failure_entry)
        raise e

