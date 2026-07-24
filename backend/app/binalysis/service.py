"""
Persistence service for binary / YARA analysis.

Shared by the binary API endpoints and the job pipeline so a single
implementation handles compiling rules, analyzing a file, upserting the
``File`` row, and creating ``Finding`` rows for YARA hits. All operations
are idempotent: re-running on the same file updates the File row in place
and never duplicates findings.
"""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.binalysis.engine import (
    BinaryAnalysis,
    analyze_file,
    compile_yara_rules,
)
from backend.app.models.file import File
from backend.app.models.finding import Finding

BINARY_SENSOR = "yara"
_SEVERITY_MAP = {"info", "low", "medium", "high", "critical"}


def default_rules_dir() -> Path:
    """Return the directory holding bundled YARA rules."""
    return Path(__file__).resolve().parent / "rules"


def persist_analysis(
    db: Session, job_id: str, a: BinaryAnalysis, dest: Path
) -> tuple[File, int]:
    """Upsert a File row for the analysis and create Findings for YARA hits.

    Returns a ``(file_row, findings_created)`` tuple. Idempotent: existing
    File rows are updated in place and duplicate findings are skipped.
    """
    match_dicts = [
        {"rule": m.rule, "tags": m.tags, "meta": m.meta, "strings": m.strings}
        for m in a.yara_matches
    ]
    existing = db.scalar(
        select(File).where(File.job_id == job_id, File.sha256 == a.sha256)
    )
    if existing:
        existing.yara_matches_json = json.dumps(match_dicts)
        existing.entropy = a.entropy
        file_row = existing
    else:
        file_row = File(
            job_id=job_id, file_id=a.sha256, filename=a.filename, sha256=a.sha256,
            md5=a.md5, size_bytes=a.size_bytes, mime=a.format, entropy=a.entropy,
            source=BINARY_SENSOR, extracted_path=str(dest),
            yara_matches_json=json.dumps(match_dicts),
        )
        db.add(file_row)

    created = 0
    for m in a.yara_matches:
        finding_id = f"yara-{a.sha256[:12]}-{m.rule}"
        if db.scalar(select(Finding).where(
                Finding.job_id == job_id, Finding.finding_id == finding_id)):
            continue
        sev = str(m.meta.get("severity", "")).lower()
        db.add(Finding(
            job_id=job_id, finding_id=finding_id, sensor=BINARY_SENSOR,
            severity=sev if sev in _SEVERITY_MAP else "medium",
            category=str(m.meta.get("category", "yara")),
            title=f"YARA: {m.rule}",
            summary=str(m.meta.get("description", f"YARA rule '{m.rule}' matched {a.filename}")),
            evidence_json=json.dumps({
                "rule": m.rule, "tags": m.tags, "strings": m.strings,
                "sha256": a.sha256, "filename": a.filename,
            }),
            confidence=0.6,
        ))
        created += 1
    db.commit()
    return file_row, created


def analyze_and_persist(
    db: Session,
    job_id: str,
    path: Path,
    filename: str | None = None,
    rules_dir: Path | None = None,
) -> tuple[BinaryAnalysis, File, int]:
    """Compile rules, analyze ``path``, and persist results for ``job_id``.

    Returns ``(analysis, file_row, findings_created)``.
    """
    compiled = compile_yara_rules(rules_dir or default_rules_dir())
    analysis = analyze_file(path, compiled, filename)
    file_row, created = persist_analysis(db, job_id, analysis, path)
    return analysis, file_row, created
