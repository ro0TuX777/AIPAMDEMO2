"""Decoupled forensic pipeline — 4 distinct Celery tasks.

Replaces the monolithic ``run_pipeline`` with four independently
retryable tasks chained via ``celery.chain()``:

1. ``ingest_pcap`` — Unpack and verify PCAP files.
2. ``extract_features`` — Run Zeek/Suricata, populate FlowDB + AlertDB.
3. ``analyze_traffic`` — AI/LLM layer (reads Flows from DB, produces Findings).
4. ``generate_report`` — Compile final forensic summary from DB tables.

Each task checks PipelineCheckpointDB at entry: if its step is already
completed, it returns immediately (resume-ability).

Usage::

    from celery import chain
    from app.pipeline import ingest_pcap, extract_features, analyze_traffic, generate_report

    pipeline = chain(
        ingest_pcap.s(job_id),
        extract_features.s(),
        analyze_traffic.s(),
        generate_report.s(),
    )
    pipeline.apply_async()
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import asyncio
from pathlib import Path
from typing import Any, Dict, List

from celery import chain as celery_chain
from sqlmodel import Session, select

from .database import engine
from .db_models import (
    AlertDB,
    EvidenceDB,
    FindingDB,
    FlowDB,
    JobDB,
    JobResultDB,
)
from .models import (
    AnalysisSummary,
    HostFinding,
    JobResult,
    JobStatus,
    JobStepStatus,
)
from .logging_config import get_logger, set_log_context
from .tasks import (
    _load_checkpoints,
    _save_checkpoint,
    _set_job_status,
    _update_step,
    celery_app,
)
from .bzar_validator import bzar_enabled, parse_notice_log

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _step_already_done(checkpoints: Dict[str, Any], step_name: str) -> bool:
    """Return True if this step has a completed checkpoint."""
    return step_name in checkpoints


# ---------------------------------------------------------------------------
# Task 1: Ingest PCAP
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="pipeline.ingest_pcap", max_retries=2)
def ingest_pcap(self, job_id: str) -> str:
    """Unpack and verify PCAP files.

    Handles all data source connectors (upload, Security Onion, Arkime)
    and saves PCAP paths.  Returns ``job_id`` for chaining.
    """
    set_log_context(job_id=job_id, step="ingest")
    with Session(engine) as session:
        job = session.get(JobDB, job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")

        _set_job_status(session, job, JobStatus.RUNNING)
        checkpoints = _load_checkpoints(session, job_id)

        if _step_already_done(checkpoints, "ingest"):
            logger.info("[INGEST] Checkpoint found — skipping (job %s)", job_id)
            _update_step(session, job_id, "ingest", JobStepStatus.COMPLETED,
                         message="Restored from checkpoint")
            return job_id

        _update_step(session, job_id, "ingest", JobStepStatus.RUNNING)

        try:
            from .settings_runtime import get_effective_settings
            from .connectors import ArkimeConnector, SecurityOnionConnector

            effective = get_effective_settings()
            file_storage_root = effective.file_storage_path
            job_dir = file_storage_root / job_id
            job_dir.mkdir(parents=True, exist_ok=True)

            pcap_paths: List[str] = []

            if job.source == "upload":
                pcap_paths = [str(Path(p)) for p in job.job_metadata.get("pcap_paths", [])]

            elif job.source == "security_onion":
                metadata = job.job_metadata or {}
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
                    async def _fetch():
                        return await so.fetch_pcaps_via_api(
                            time_range=time_range, sensors=sensors
                        )
                    blobs = asyncio.run(_fetch())
                    for idx, blob in enumerate(blobs):
                        dest = job_dir / f"so_{idx}.pcap"
                        dest.write_bytes(blob)
                        pcap_paths.append(str(dest))

            elif job.source == "arkime":
                metadata = job.job_metadata or {}
                flt = metadata.get("filter") or ""
                time_range = metadata.get("time_range") or {}
                ark = ArkimeConnector(settings=effective)

                async def _export():
                    return await ark.export_pcap(flt=flt, time_range=time_range)

                blob = asyncio.run(_export())
                if blob:
                    dest = job_dir / "arkime.pcap"
                    dest.write_bytes(blob)
                    pcap_paths.append(str(dest))

            if not pcap_paths:
                raise ValueError("No PCAP files available for ingest")

            _update_step(session, job_id, "ingest", JobStepStatus.COMPLETED)
            _save_checkpoint(session, job_id, "ingest", {"pcap_paths": pcap_paths})

        except Exception as exc:
            logger.exception("Ingest failed")
            _update_step(session, job_id, "ingest", JobStepStatus.FAILED,
                         message=str(exc))
            _set_job_status(session, job, JobStatus.FAILED, error=str(exc))
            raise

    return job_id


# ---------------------------------------------------------------------------
# Task 2: Extract Features
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="pipeline.extract_features", max_retries=2)
def extract_features(job_id: str) -> str:
    """Run Zeek/Suricata on PCAPs and populate FlowDB + AlertDB.

    Reads PCAP paths from the ingest checkpoint, runs tools, parses
    output, and persists structured rows.  Returns ``job_id``.
    """
    set_log_context(job_id=job_id, step="extract")
    with Session(engine) as session:
        job = session.get(JobDB, job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")

        checkpoints = _load_checkpoints(session, job_id)

        if _step_already_done(checkpoints, "extract"):
            logger.info("[EXTRACT] Checkpoint found — skipping (job %s)", job_id)
            _update_step(session, job_id, "extract", JobStepStatus.COMPLETED,
                         message="Restored from checkpoint")
            return job_id

        # Ingest checkpoint MUST exist
        if "ingest" not in checkpoints:
            raise ValueError("Cannot extract features: ingest checkpoint missing")

        pcap_paths = checkpoints["ingest"].get("pcap_paths", [])
        _update_step(session, job_id, "extract", JobStepStatus.RUNNING)

        try:
            from .settings_runtime import get_effective_settings
            from .parsers import parse_zeek_conn, parse_zeek_events, parse_suricata_eve
            from .domain.evidence_store import persist_flows, persist_alerts

            effective = get_effective_settings()
            file_storage_root = effective.file_storage_path
            job_dir = file_storage_root / job_id

            all_flows = []
            all_alerts = []
            all_events = []
            bzar_data = {"technique_ids": [], "notices": []}

            for pcap_path in pcap_paths:
                pcap = Path(pcap_path)
                if not pcap.exists():
                    logger.warning("PCAP not found: %s", pcap_path)
                    continue

                # Run Zeek
                zeek_dir = job_dir / "zeek" / pcap.stem
                zeek_dir.mkdir(parents=True, exist_ok=True)
                try:
                    zeek_cmd = ["zeek", "-r", str(pcap), "LogAscii::use_json=T"]

                    # Enable file extraction
                    extract_script = Path("/opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek")
                    if extract_script.exists():
                        zeek_cmd.append(str(extract_script))

                    bzar_script = os.getenv("BZAR_ZEEK_SCRIPT")
                    if bzar_script:
                        script_path = Path(bzar_script)
                        if script_path.exists():
                            zeek_cmd.append(str(script_path))
                        else:
                            logger.warning("BZAR_ZEEK_SCRIPT not found: %s", bzar_script)
                    subprocess.run(
                        zeek_cmd,
                        cwd=str(zeek_dir),
                        timeout=300,
                        check=False,
                        capture_output=True,
                    )
                except FileNotFoundError:
                    logger.warning("Zeek binary not found — skipping Zeek analysis")

                # Parse Zeek conn.log
                conn_log = zeek_dir / "conn.log"
                if conn_log.exists():
                    with open(conn_log) as f:
                        raw = [json.loads(line) for line in f if line.strip()
                               and not line.startswith("#")]
                    flows = parse_zeek_conn(raw)
                    all_flows.extend(flows)

                if bzar_enabled():
                    notice_log = zeek_dir / "notice.log"
                    parsed = parse_notice_log(notice_log)
                    if parsed.get("technique_ids"):
                        bzar_data["technique_ids"] = sorted(
                            set(bzar_data["technique_ids"]) | set(parsed["technique_ids"])
                        )
                    if parsed.get("notices"):
                        bzar_data["notices"].extend(parsed["notices"])

                # Parse Zeek events (DNS, HTTP, etc.)
                for event_log_name in ["dns.log", "http.log", "ssl.log"]:
                    event_path = zeek_dir / event_log_name
                    if event_path.exists():
                        with open(event_path) as f:
                            raw_events = [json.loads(line) for line in f
                                          if line.strip() and not line.startswith("#")]
                        events = parse_zeek_events(raw_events)
                        all_events.extend(events)

                # Run Suricata
                suricata_dir = job_dir / "suricata" / pcap.stem
                suricata_dir.mkdir(parents=True, exist_ok=True)
                eve_json = suricata_dir / "eve.json"
                try:
                    subprocess.run(
                        ["suricata", "-r", str(pcap), "-l", str(suricata_dir)],
                        timeout=300,
                        check=False,
                        capture_output=True,
                    )
                except FileNotFoundError:
                    logger.warning("Suricata binary not found — skipping Suricata analysis")

                if eve_json.exists():
                    with open(eve_json) as f:
                        raw_alerts = [json.loads(line) for line in f if line.strip()]
                    alerts = parse_suricata_eve(raw_alerts)
                    all_alerts.extend(alerts)

                # File triage on Zeek-extracted files
                extract_files_dir = zeek_dir / "extract_files"
                if extract_files_dir.exists():
                    import hashlib as _hashlib
                    from .pipeline.sensor_handlers import _detect_file_type
                    for fpath in extract_files_dir.iterdir():
                        if fpath.is_file():
                            file_bytes = fpath.read_bytes()
                            ftype = _detect_file_type(file_bytes)
                            sha = _hashlib.sha256(file_bytes).hexdigest()
                            logger.info(
                                "[EXTRACT] Extracted file: %s type=%s size=%d sha256=%s",
                                fpath.name, ftype, len(file_bytes), sha,
                            )

            # Persist to Evidence Store
            flow_count = persist_flows(session, job_id, all_flows)
            alert_count = persist_alerts(session, job_id, all_alerts)

            logger.info(
                "[EXTRACT] job=%s flows=%d alerts=%d events=%d",
                job_id, flow_count, alert_count, len(all_events),
            )

            _update_step(session, job_id, "extract", JobStepStatus.COMPLETED)
            _save_checkpoint(session, job_id, "extract", {
                "flow_count": flow_count,
                "alert_count": alert_count,
                "event_count": len(all_events),
                "bzar": bzar_data,
            })

        except Exception as exc:
            logger.exception("Extract failed")
            _update_step(session, job_id, "extract", JobStepStatus.FAILED,
                         message=str(exc))
            _set_job_status(session, job, JobStatus.FAILED, error=str(exc))
            raise

    return job_id


# ---------------------------------------------------------------------------
# Task 3: Analyze Traffic
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="pipeline.analyze_traffic", max_retries=2)
def analyze_traffic(job_id: str) -> str:
    """AI/LLM analysis.  Reads Flow IDs from FlowDB, produces FindingDB rows.

    Builds an AnalysisContext from the Evidence Store, runs the analyzer,
    and persists all findings + evidence links.  Returns ``job_id``.
    """
    set_log_context(job_id=job_id, step="analyze")
    with Session(engine) as session:
        job = session.get(JobDB, job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")

        checkpoints = _load_checkpoints(session, job_id)

        if _step_already_done(checkpoints, "analyze"):
            logger.info("[ANALYZE] Checkpoint found — skipping (job %s)", job_id)
            _update_step(session, job_id, "analyze", JobStepStatus.COMPLETED,
                         message="Restored from checkpoint")
            return job_id

        if "extract" not in checkpoints:
            raise ValueError("Cannot analyze: extract checkpoint missing")

        extract_data = checkpoints.get("extract", {})
        bzar_data = extract_data.get("bzar")
        _update_step(session, job_id, "analyze", JobStepStatus.RUNNING)

        try:
            from .core.interfaces import AnalysisContext
            from .domain.finding_adapter import llm_output_to_findings, persist_findings as persist_domain_findings
            from .llm_client import LLMClient, LLMConfig
            from .llm_chunking import build_llm_chunks, aggregate_llm_results
            from .aggregation import aggregate_hosts, aggregate_host_pairs, diff_change_summaries
            from .settings_runtime import get_effective_settings
            from .baseline_utils import _split_baseline_exploit

            # Load flows and alerts from Evidence Store
            db_flows = session.exec(
                select(FlowDB).where(FlowDB.job_id == job_id)
            ).all()
            db_alerts = session.exec(
                select(AlertDB).where(AlertDB.job_id == job_id)
            ).all()

            # Convert DB rows back to Pydantic models for existing pipeline
            from .domain_models import FlowRecord, AlertRecord

            flows = [
                FlowRecord(
                    id=f.id.split(":", 1)[1] if ":" in f.id else f.id,
                    src_ip=f.src_ip, src_port=f.src_port,
                    dst_ip=f.dst_ip, dst_port=f.dst_port,
                    transport_proto=f.transport_proto, app_proto=f.app_proto,
                    start_time=f.start_time, end_time=f.end_time,
                    duration_sec=f.duration_sec,
                    bytes_from_src=f.bytes_from_src, bytes_from_dst=f.bytes_from_dst,
                    packets_from_src=f.packets_from_src, packets_from_dst=f.packets_from_dst,
                    tcp_flags_summary=f.tcp_flags_summary, state=f.state,
                    extra=f.extra or {},
                )
                for f in db_flows
            ]

            alerts = [
                AlertRecord(
                    id=a.id.split(":", 1)[1] if ":" in a.id else a.id,
                    timestamp=a.timestamp,
                    src_ip=a.src_ip, dst_ip=a.dst_ip,
                    src_port=a.src_port, dst_port=a.dst_port,
                    alert_source=a.alert_source,
                    signature_id=a.signature_id,
                    signature_name=a.signature_name,
                    severity=a.severity,
                    category=a.category,
                    flow_id=a.flow_id,
                    extra=a.extra or {},
                )
                for a in db_alerts
            ]

            # Build AnalysisContext for the architect's interface
            high_priority_flow_ids = [f.id for f in db_flows]
            alert_ids = [a.id for a in db_alerts]

            ctx = AnalysisContext(
                job_id=job_id,
                exercise_id=job.exercise_id or job_id,
                mode=job.mode,
                high_priority_flow_ids=high_priority_flow_ids,
                alert_ids=alert_ids,
                metadata=job.job_metadata or {},
            )

            # Aggregate for LLM input
            effective = get_effective_settings()
            mode = job.mode or "single_window"

            if mode == "baseline_vs_exploit":
                baseline_flows, exploit_flows = _split_baseline_exploit(
                    flows, job.job_metadata or {}
                )
                host_summaries_baseline = aggregate_hosts(baseline_flows, [])
                host_summaries_exploit = aggregate_hosts(exploit_flows, alerts)
                hp_baseline = aggregate_host_pairs(baseline_flows, [])
                hp_exploit = aggregate_host_pairs(exploit_flows, alerts)
                changes = diff_change_summaries(
                    host_summaries_baseline, host_summaries_exploit,
                    hp_baseline, hp_exploit,
                )
            else:
                host_summaries_baseline = []
                host_summaries_exploit = aggregate_hosts(flows, alerts)
                hp_baseline = []
                hp_exploit = aggregate_host_pairs(flows, alerts)
                changes = []

            # Build LLM chunks and analyze

            bundles = build_llm_chunks(
                exercise_id=ctx.exercise_id,
                mode=mode,
                time_ranges={},
                host_summaries_baseline=host_summaries_baseline,
                host_summaries_exploit=host_summaries_exploit,
                hostpair_summaries_baseline=hp_baseline,
                hostpair_summaries_exploit=hp_exploit,
                change_summaries=changes,
                alerts=alerts,
            )

            llm_config = LLMConfig(
                endpoint=effective.llm_endpoint,
                model=effective.llm_model,
            )
            client = LLMClient(config=llm_config)

            from .llm_client import analyze_chunks as run_llm_chunks

            llm_results = asyncio.run(
                run_llm_chunks([b.model_dump() for b in bundles], client=client)
            )

            summary, host_findings = aggregate_llm_results(
                llm_results,
                trafficllm_results=None,
                alerts=alerts,
                exercise_id=ctx.exercise_id,
            )

            # Persist findings
            all_findings = []
            for llm_out in llm_results:
                all_findings.extend(
                    llm_output_to_findings(job_id, llm_out, analyzer_source="ollama")
                )
            finding_count = persist_domain_findings(session, all_findings)

            logger.info(
                "[ANALYZE] job=%s findings=%d classification=%s",
                job_id, finding_count, summary.classification,
            )

            # Store aggregated summary for report step
            _update_step(session, job_id, "analyze", JobStepStatus.COMPLETED)
            _save_checkpoint(session, job_id, "analyze", {
                "classification": summary.classification,
                "severity": summary.severity,
                "technique_count": len(summary.mitre_techniques),
                "finding_count": finding_count,
                "summary": summary.model_dump(mode="json"),
                "host_findings": [hf.model_dump(mode="json") for hf in host_findings],
                "llm_results_raw": [r.model_dump(mode="json") for r in llm_results],
                "bzar": bzar_data,
            })

        except Exception as exc:
            logger.exception("Analyze failed")
            _update_step(session, job_id, "analyze", JobStepStatus.FAILED,
                         message=str(exc))
            _set_job_status(session, job, JobStatus.FAILED, error=str(exc))
            raise

    return job_id


# ---------------------------------------------------------------------------
# Task 4: Generate Report
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="pipeline.generate_report", max_retries=2)
def generate_report(job_id: str) -> str:
    """Compile final forensic summary from DB tables.

    Reads findings, flows, and alerts from the database, generates
    Markdown + HTML reports, and stores the final JobResult.
    Returns ``job_id``.
    """
    set_log_context(job_id=job_id, step="report")
    with Session(engine) as session:
        job = session.get(JobDB, job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")

        checkpoints = _load_checkpoints(session, job_id)

        if _step_already_done(checkpoints, "report"):
            logger.info("[REPORT] Checkpoint found — skipping (job %s)", job_id)
            _update_step(session, job_id, "report", JobStepStatus.COMPLETED,
                         message="Restored from checkpoint")
            return job_id

        if "analyze" not in checkpoints:
            raise ValueError("Cannot generate report: analyze checkpoint missing")

        _update_step(session, job_id, "report", JobStepStatus.RUNNING)

        try:
            from .reporting import jobresult_to_html, jobresult_to_markdown
            from .settings_runtime import get_effective_settings

            effective = get_effective_settings()
            analyze_data = checkpoints["analyze"]

            # Reconstruct summary from checkpoint
            summary = AnalysisSummary.model_validate(analyze_data["summary"])
            host_findings = [
                HostFinding.model_validate(hf)
                for hf in analyze_data.get("host_findings", [])
            ]

            # Build JobResult
            job_result = JobResult(
                job_id=job_id,
                status=JobStatus.COMPLETED,
                summary=summary,
                hosts=host_findings,
                raw={
                    "llm_analysis_raw": analyze_data.get("llm_results_raw", []),
                    "bzar": analyze_data.get("bzar"),
                },
                report_urls={},
            )

            finding_rows = session.exec(
                select(FindingDB).where(FindingDB.job_id == job_id)
            ).all()
            finding_ids = [f.id for f in finding_rows]
            evidence_rows = []
            if finding_ids:
                evidence_rows = session.exec(
                    select(EvidenceDB).where(EvidenceDB.finding_id.in_(finding_ids))
                ).all()
            from .cti.lookup import enrich_findings
            finding_dicts = enrich_findings(session, finding_rows)

            # Query extracted files from V2 File table
            extracted_file_rows: list[dict] = []
            try:
                from sqlalchemy.orm import Session as SASession
                from sqlalchemy import text as sa_text
                sa_session = SASession(bind=session.connection())
                rows = sa_session.execute(
                    sa_text("SELECT file_id, filename, sha256, size_bytes, mime, yara_matches_json FROM files WHERE job_id = :jid"),
                    {"jid": job_id},
                ).fetchall()
                for r in rows:
                    import json as _json
                    yara_matches = []
                    if r[5]:
                        try:
                            yara_matches = _json.loads(r[5])
                        except Exception:
                            pass
                    extracted_file_rows.append({
                        "file_id": r[0], "filename": r[1], "sha256": r[2],
                        "size_bytes": r[3], "mime": r[4], "yara_matches": yara_matches,
                    })
                logger.info("[REPORT] Found %d extracted files for report", len(extracted_file_rows))
            except Exception as exc:
                logger.warning("[REPORT] Could not query files table: %s", exc)

            # Generate reports
            reports_root = effective.reports_path
            reports_root.mkdir(parents=True, exist_ok=True)

            md_text = jobresult_to_markdown(job_result, finding_dicts, evidence_rows, extracted_file_rows)
            md_path = reports_root / f"job-{job_id}.md"
            md_path.write_text(md_text, encoding="utf-8")

            html_text = jobresult_to_html(job_result, finding_dicts, evidence_rows, extracted_file_rows)
            html_path = reports_root / f"job-{job_id}.html"
            html_path.write_text(html_text, encoding="utf-8")

            job_result.report_urls = {
                "markdown": f"/reports/job-{job_id}.md",
                "html": f"/reports/job-{job_id}.html",
            }

            # Persist final result
            result_row = session.get(JobResultDB, job_id)
            result_payload = job_result.model_dump(mode="json")
            if result_row:
                result_row.result = result_payload
                session.add(result_row)
            else:
                session.add(JobResultDB(job_id=job_id, result=result_payload))

            _set_job_status(session, job, JobStatus.COMPLETED)
            _update_step(session, job_id, "report", JobStepStatus.COMPLETED)
            _save_checkpoint(session, job_id, "report", {
                "report_urls": job_result.report_urls,
            })
            session.commit()

            logger.info("[REPORT] job=%s reports generated", job_id)

        except Exception as exc:
            logger.exception("Report failed")
            _update_step(session, job_id, "report", JobStepStatus.FAILED,
                         message=str(exc))
            _set_job_status(session, job, JobStatus.FAILED, error=str(exc))
            raise

    return job_id


# ---------------------------------------------------------------------------
# Orchestrator: Chain the 4 tasks
# ---------------------------------------------------------------------------


def start_pipeline(job_id: str) -> None:
    """Launch the 4-stage forensic pipeline for a job.

    Uses Celery's ``chain()`` to execute tasks sequentially, passing
    ``job_id`` through each stage.
    """
    pipeline = celery_chain(
        ingest_pcap.s(job_id),
        extract_features.s(),
        analyze_traffic.s(),
        generate_report.s(),
    )
    pipeline.apply_async()
    logger.info("Pipeline started for job %s", job_id)
