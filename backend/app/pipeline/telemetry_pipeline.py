"""
Telemetry Correlation Pipeline — orchestrates parsing, persistence, and correlation.

Entry point: ``run_telemetry_pipeline(job_id, job_dir, db)``

Flow:
  1. Read ``source_manifest.json`` from job_dir
  2. For each manifest entry, find a parser and parse the file
  3. Persist all ParserResults as NormalizedEvent rows
  4. Run TelemetryCorrelator to build clusters and upgrade evidence status
  5. Return pipeline summary stats
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from backend.app.parsers import register_all_parsers
from backend.app.parsers.base import ParserResult
from backend.app.parsers.registry import get_parser_registry
from backend.app.schemas.common import SourceType
from backend.app.schemas.telemetry import SourceManifest
from backend.app.sensors.behavioral import run_behavioral_detectors
from backend.app.sensors.c2_fusion import run_c2_fusion
from backend.app.services.behavioral_memory import extract_all_fingerprints
from backend.app.services.storyline import reconstruct_storyline
from backend.app.services.telemetry_correlator import (
    correlate_and_upgrade,
    persist_parser_results,
)

logger = logging.getLogger("aipam.telemetry_pipeline")


# ── Diagnostics dataclasses ─────────────────────────────────────────────────

@dataclass
class FileDiagnostic:
    """Per-file parsing diagnostic record."""
    filename: str
    parser_name: str | None = None
    status: str = "skipped"  # ok | skipped | error
    events_produced: int = 0
    duration_ms: float = 0.0
    error: str | None = None
    file_size_bytes: int = 0


@dataclass
class PipelineDiagnostics:
    """Aggregate diagnostics for a full pipeline run."""
    job_id: str = ""
    started_at: str = ""
    completed_at: str = ""
    total_duration_ms: float = 0.0
    files: list[FileDiagnostic] = field(default_factory=list)
    phase_durations_ms: dict[str, float] = field(default_factory=dict)
    error_budget_remaining: int = 0

    @property
    def files_ok(self) -> int:
        return sum(1 for f in self.files if f.status == "ok")

    @property
    def files_error(self) -> int:
        return sum(1 for f in self.files if f.status == "error")

    @property
    def files_skipped(self) -> int:
        return sum(1 for f in self.files if f.status == "skipped")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["files_ok"] = self.files_ok
        d["files_error"] = self.files_error
        d["files_skipped"] = self.files_skipped
        return d


def _load_manifest(job_dir: Path) -> SourceManifest | None:
    """Load the source manifest from the job directory."""
    manifest_path = job_dir / "source_manifest.json"
    if not manifest_path.exists():
        logger.warning("No source_manifest.json in %s", job_dir)
        return None
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        return SourceManifest(**data)
    except Exception as exc:
        logger.error("Failed to parse source_manifest.json: %s", exc)
        return None


def _parse_entry(
    file_path: Path,
    job_id: str,
    source_type: SourceType,
    parser_hint: str | None = None,
    exercise_id: str | None = None,
) -> tuple[list[ParserResult], FileDiagnostic]:
    """Parse a single file using the registry, returning results and a diagnostic."""
    file_size = file_path.stat().st_size if file_path.exists() else 0
    diag = FileDiagnostic(filename=file_path.name, file_size_bytes=file_size)

    registry = get_parser_registry()
    parser = registry.find_for_file(file_path, hint=parser_hint)
    if parser is None:
        logger.warning("No parser found for %s (hint=%s)", file_path.name, parser_hint)
        diag.status = "skipped"
        diag.error = f"No parser found (hint={parser_hint})"
        return [], diag

    diag.parser_name = parser.name
    results: list[ParserResult] = []
    t0 = time.monotonic()
    try:
        for result in parser.parse(
            file_path,
            job_id=job_id,
            source_type=source_type,
            exercise_id=exercise_id,
        ):
            results.append(result)
        diag.status = "ok"
    except Exception as exc:
        logger.error("Parser %s failed on %s: %s", parser.name, file_path.name, exc)
        diag.status = "error"
        diag.error = str(exc)

    diag.duration_ms = round((time.monotonic() - t0) * 1000, 2)
    diag.events_produced = len(results)

    logger.info(
        "Parsed %d events from %s using %s (%.1fms, status=%s)",
        len(results), file_path.name, parser.name, diag.duration_ms, diag.status,
    )
    return results, diag


def _save_diagnostics(job_dir: Path, diagnostics: PipelineDiagnostics) -> None:
    """Persist pipeline diagnostics as JSON in the job directory."""
    diag_path = job_dir / "telemetry_diagnostics.json"
    try:
        diag_path.write_text(
            json.dumps(diagnostics.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        logger.debug("Diagnostics written to %s", diag_path)
    except Exception as exc:
        logger.warning("Failed to write diagnostics: %s", exc)


def _phase_timer(diagnostics: PipelineDiagnostics, phase_name: str):
    """Context-manager-style helper returning a callable to record phase duration."""
    class _Timer:
        def __init__(self):
            self.t0 = time.monotonic()
        def stop(self):
            diagnostics.phase_durations_ms[phase_name] = round(
                (time.monotonic() - self.t0) * 1000, 2
            )
    return _Timer()


# Default: allow up to 50% of files to fail before aborting
_DEFAULT_ERROR_BUDGET_PCT = 50


def run_telemetry_pipeline(
    job_id: str,
    input_root: Path,
    db: Session,
    *,
    run_output_dir: Path,
    exercise_id: str | None = None,
    error_budget_pct: int = _DEFAULT_ERROR_BUDGET_PCT,
) -> dict[str, Any]:
    """Execute the full telemetry pipeline for a bundle job.

    Returns a summary dict with parsing and correlation statistics.
    Writes ``telemetry_diagnostics.json`` into *run_output_dir* for support bundles.
    """
    from datetime import datetime, timezone

    pipeline_t0 = time.monotonic()
    diagnostics = PipelineDiagnostics(
        job_id=job_id,
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    # Ensure parsers are registered
    register_all_parsers()

    manifest = _load_manifest(input_root)
    if manifest is None:
        diagnostics.completed_at = datetime.now(timezone.utc).isoformat()
        diagnostics.total_duration_ms = round((time.monotonic() - pipeline_t0) * 1000, 2)
        _save_diagnostics(run_output_dir, diagnostics)
        return {"error": "no_manifest", "parsed": 0, "correlated": 0}

    # Derive source type from first entry (all entries share source_type)
    if manifest.entries:
        source_type_enum = SourceType(manifest.entries[0].source_type)
    else:
        source_type_enum = SourceType.log_bundle
    eid = exercise_id or manifest.exercise_id

    # Error budget: max number of file failures before aborting
    total_files = len(manifest.entries)
    max_errors = max(1, (total_files * error_budget_pct) // 100)
    error_count = 0

    # Phase 1: Parse all manifest entries
    parse_timer = _phase_timer(diagnostics, "parse")
    all_results: list[ParserResult] = []

    for entry in manifest.entries:
        file_path = input_root / "input" / "telemetry" / entry.filename
        if not file_path.exists():
            logger.warning("Manifest entry not found on disk: %s", entry.filename)
            diagnostics.files.append(FileDiagnostic(
                filename=entry.filename,
                status="skipped",
                error="File not found on disk",
            ))
            continue

        results, diag = _parse_entry(
            file_path,
            job_id=job_id,
            source_type=source_type_enum,
            parser_hint=entry.parser_hint,
            exercise_id=eid,
        )
        diagnostics.files.append(diag)

        if diag.status == "error":
            error_count += 1
            if error_count >= max_errors:
                logger.error(
                    "Error budget exhausted (%d/%d failures) — aborting parse phase",
                    error_count, max_errors,
                )
                break

        if results:
            for r in results:
                if r.source_system is None and entry.source_system:
                    r.source_system = entry.source_system
                # Apply phase label from manifest entry
                if r.pcap_label is None and entry.label:
                    r.pcap_label = entry.label
            all_results.extend(results)

    parse_timer.stop()
    diagnostics.error_budget_remaining = max_errors - error_count

    # Phase 2: Persist
    pt = _phase_timer(diagnostics, "persist")
    rows = persist_parser_results(all_results, job_id, db)
    pt.stop()

    # Phase 3: Correlate
    ct = _phase_timer(diagnostics, "correlate")
    correlation_stats = correlate_and_upgrade(job_id, db)
    ct.stop()

    # Phase 4: Behavioral detection
    bt = _phase_timer(diagnostics, "behavioral")
    behavioral_findings = run_behavioral_detectors(db, job_id)
    bt.stop()

    # Phase 5: C2 fusion
    ft = _phase_timer(diagnostics, "c2_fusion")
    c2_findings = run_c2_fusion(db, job_id)
    ft.stop()

    # Phase 6: Storyline reconstruction
    st = _phase_timer(diagnostics, "storyline")
    storyline_result = reconstruct_storyline(db, job_id)
    st.stop()

    # Phase 7: Memory indexing
    mt = _phase_timer(diagnostics, "memory")
    fingerprints = extract_all_fingerprints(db, job_id, exercise_id=eid or "")
    memory_indexed = 0
    if fingerprints:
        try:
            from backend.app.forensic_memory import store_behavioral_fingerprints
            fp_dicts = [fp.to_dict() for fp in fingerprints]
            memory_indexed = store_behavioral_fingerprints(
                job_id=job_id,
                project_id="",
                fingerprints=fp_dicts,
            )
        except Exception:
            logger.debug("Memory indexing unavailable — skipping", exc_info=True)
    mt.stop()

    db.commit()

    # Finalize diagnostics
    diagnostics.completed_at = datetime.now(timezone.utc).isoformat()
    diagnostics.total_duration_ms = round((time.monotonic() - pipeline_t0) * 1000, 2)
    _save_diagnostics(run_output_dir, diagnostics)

    summary = {
        "files_total": total_files,
        "files_parsed": diagnostics.files_ok,
        "files_skipped": diagnostics.files_skipped,
        "files_error": diagnostics.files_error,
        "events_total": len(rows),
        "behavioral_findings": len(behavioral_findings),
        "c2_fusion_findings": len(c2_findings),
        "storyline_stages": len(storyline_result.stages),
        "memory_fingerprints": len(fingerprints),
        "memory_indexed": memory_indexed,
        "phase_durations_ms": diagnostics.phase_durations_ms,
        **correlation_stats,
    }
    logger.info("Telemetry pipeline complete for job %s: %s", job_id, summary)
    return summary
