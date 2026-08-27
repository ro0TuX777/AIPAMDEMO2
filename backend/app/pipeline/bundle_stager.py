"""Bundle Stager — extract and manifest log/C2/netflow bundles into job workspace.

Accepts uploaded archives (zip, tar.gz, tar.bz2) or directories of log files,
extracts them into the job's ``input/telemetry/`` directory, generates a
SourceManifest, and stores it as ``source_manifest.json`` in the job directory.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.app.schemas.common import SourceType
from backend.app.schemas.telemetry import SourceEntry, SourceManifest

_logger = logging.getLogger("aipam.bundle_stager")

# Maximum allowed total extracted size (10 GB), matching MAX_LOG_BYTES_PER_JOB.
# Bundles are bounded by bytes only — a syslog directory or an EVTX export can
# legitimately hold tens of thousands of files, and refusing them on count alone
# is what stops those perspectives reaching correlation.
MAX_EXTRACT_BYTES = 10 * 1024 * 1024 * 1024


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 of a file in 256 KB chunks."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(262_144):
            sha.update(chunk)
    return sha.hexdigest()


def _safe_name(name: str) -> str:
    """Sanitise an archive member name to prevent path-traversal attacks."""
    # Strip leading slashes / dots and collapse to basename
    parts = Path(name).parts
    safe_parts = [p for p in parts if p not in ("..", ".", "/", "\\")]
    if not safe_parts:
        return "unnamed"
    return str(Path(*safe_parts))


# Extensions recognized as archives (everything else is treated as a raw log file)
_ARCHIVE_EXTENSIONS = (".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar")


def _is_archive(path: Path) -> bool:
    """Return True if the file looks like a supported archive."""
    name = path.name.lower()
    return any(name.endswith(ext) for ext in _ARCHIVE_EXTENSIONS)


def extract_bundle(
    archive_path: Path,
    dest_dir: Path,
) -> list[Path]:
    """Extract an archive — or copy a raw log file — into *dest_dir*.

    Supports archives: ``.zip``, ``.tar.gz``, ``.tgz``, ``.tar.bz2``, ``.tar``.
    Raw log files (``.json``, ``.evtx``, ``.log``, ``.csv``, etc.) are copied as-is.
    Raises ``ValueError`` on safety violations.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []

    # ── Raw (non-archive) file: just copy into telemetry dir ──
    if not _is_archive(archive_path):
        target = dest_dir / _safe_name(archive_path.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(archive_path, target)
        extracted.append(target)
        _logger.info("Copied raw log file %s into %s", archive_path.name, dest_dir)
        return extracted

    # ── Archive extraction ──
    suffix = archive_path.name.lower()

    if suffix.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            total_size = sum(i.file_size for i in zf.infolist() if not i.is_dir())
            if total_size > MAX_EXTRACT_BYTES:
                raise ValueError(f"Archive uncompressed size ({total_size}) exceeds limit")
            for info in zf.infolist():
                if info.is_dir():
                    continue
                safe = _safe_name(info.filename)
                target = dest_dir / safe
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                extracted.append(target)

    elif suffix.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
        mode = "r:gz" if suffix.endswith((".tar.gz", ".tgz")) else (
            "r:bz2" if suffix.endswith(".tar.bz2") else "r:"
        )
        with tarfile.open(archive_path, mode) as tf:
            members = [m for m in tf.getmembers() if m.isfile()]
            total_size = sum(m.size for m in members)
            if total_size > MAX_EXTRACT_BYTES:
                raise ValueError(f"Archive uncompressed size ({total_size}) exceeds limit")
            for member in members:
                safe = _safe_name(member.name)
                target = dest_dir / safe
                target.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(member)
                if src is None:
                    continue
                with open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                extracted.append(target)
    else:
        raise ValueError(f"Unsupported archive format: {archive_path.name}")

    _logger.info("Extracted %d files from %s into %s", len(extracted), archive_path.name, dest_dir)
    return extracted


def build_manifest(
    job_id: str,
    source_type: SourceType,
    extracted_files: list[Path],
    telemetry_dir: Path,
    exercise_id: str | None = None,
    bundle_entries: list[dict[str, Any]] | None = None,
    label: str | None = None,
) -> SourceManifest:
    """Build a SourceManifest from extracted files.

    If *bundle_entries* is provided (from the API request), use those hints
    to match filenames to source_system / parser_hint metadata.
    If *label* is provided, it is applied to all entries as a default phase
    label (individual entry hints can override).
    """
    hints: dict[str, dict[str, Any]] = {}
    if bundle_entries:
        for entry in bundle_entries:
            hints[entry.get("filename", "")] = entry

    entries: list[SourceEntry] = []
    for fpath in sorted(extracted_files):
        rel = fpath.relative_to(telemetry_dir)
        fname = str(rel)
        hint = hints.get(fname, hints.get(fpath.name, {}))
        # Per-entry hint label overrides the bundle-level label
        entry_label = hint.get("label") or label
        entries.append(SourceEntry(
            filename=fname,
            source_type=source_type,
            source_system=hint.get("source_system"),
            parser_hint=hint.get("parser_hint"),
            size_bytes=fpath.stat().st_size,
            sha256=_sha256_file(fpath),
            label=entry_label,
        ))

    manifest = SourceManifest(
        job_id=job_id,
        exercise_id=exercise_id,
        created_at=datetime.now(timezone.utc),
        entries=entries,
    )
    return manifest


def stage_bundle(
    archive_path: Path,
    job_dir: Path,
    job_id: str,
    source_type: SourceType,
    exercise_id: str | None = None,
    bundle_entries: list[dict[str, Any]] | None = None,
    label: str | None = None,
) -> SourceManifest:
    """Full staging pipeline: extract → manifest → persist.

    Returns the SourceManifest and writes ``source_manifest.json`` to the job dir.
    If *label* is provided, all entries in this bundle are tagged with that phase label.
    """
    telemetry_dir = job_dir / "input" / "telemetry"
    extracted = extract_bundle(archive_path, telemetry_dir)
    manifest = build_manifest(
        job_id, source_type, extracted, telemetry_dir,
        exercise_id=exercise_id,
        bundle_entries=bundle_entries,
        label=label,
    )
    # Persist manifest
    manifest_path = job_dir / "source_manifest.json"
    manifest_path.write_text(
        manifest.model_dump_json(indent=2),
        encoding="utf-8",
    )
    _logger.info("Wrote manifest with %d entries to %s", len(manifest.entries), manifest_path)
    return manifest

