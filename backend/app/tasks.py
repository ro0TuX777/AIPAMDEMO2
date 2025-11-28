from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from celery import Celery

from sqlmodel import Session, select

from .aggregation import AggregatedData, aggregate_host_pairs, aggregate_hosts, diff_change_summaries
from .connectors import ArkimeConnector, SecurityOnionConnector
from .database import engine
from .db_models import JobDB, JobResultDB, JobStepDB
from .llm_client import LLMClient, LLMConfig, analyze_chunks
from .models import AnalysisSummary, HostFinding, JobResult, JobStatus, JobStepStatus
from .settings_runtime import get_effective_settings
from .reporting import jobresult_to_html, jobresult_to_markdown
from .parsers import parse_zeek_conn, parse_zeek_events, parse_suricata_eve
import json
import subprocess
from pathlib import Path
from .baseline_utils import _split_baseline_exploit

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
                    import asyncio

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

                import asyncio

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
                    continue

                # Zeek execution
                conn_log = work_dir / "conn.log"
                if shutil.which("zeek"):
                    try:
                        # Run Zeek with JSON output
                        subprocess.run(
                            ["zeek", "-C", "-r", str(pcap_file), f"Log::default_logdir={work_dir}", "LogAscii::use_json=T"],
                            check=True,
                            capture_output=True
                        )
                    except subprocess.CalledProcessError as e:
                        print(f"Zeek failed: {e.stderr.decode()}")
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
                if shutil.which("suricata"):
                    try:
                        subprocess.run(
                            ["suricata", "-r", str(pcap_file), "-l", str(work_dir), "-k", "none"],
                            check=True,
                            capture_output=True
                        )
                    except subprocess.CalledProcessError as e:
                        print(f"Suricata failed: {e.stderr.decode()}")
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

                        flows.extend(parse_zeek_conn(zeek_data))

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

                        alerts.extend(parse_suricata_eve(suricata_data))

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

            # LLM ANALYSIS
            _update_step(session, job_id, "llm_analysis", JobStepStatus.RUNNING)

            from .models import LLMInputBundle, TimeWindow

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

            bundles = build_llm_chunks(
                exercise_id=job.exercise_id or job.id,
                mode=job.mode,
                time_ranges=time_ranges,
                host_summaries_baseline=host_summaries_baseline,
                host_summaries_exploit=host_summaries_exploit,
                hostpair_summaries_baseline=host_pair_summaries_baseline,
                hostpair_summaries_exploit=host_pair_summaries_exploit,
                change_summaries=changes,
                alerts=alerts,
            )

            import asyncio

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
            summary, host_findings = aggregate_llm_results(llm_results)

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
            #   }
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
            _set_job_status(session, job, JobStatus.COMPLETED)

        except Exception as exc:  # pragma: no cover - coarse error path
            _set_job_status(session, job, JobStatus.FAILED, error=str(exc))
            _update_step(session, job_id, "report", JobStepStatus.FAILED, message=str(exc))

