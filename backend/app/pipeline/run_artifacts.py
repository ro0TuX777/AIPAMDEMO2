"""Filesystem acceptance boundary; only owned finalization stores the manifest.

Pipeline writers receive their output directory explicitly. These resolvers are
for external/post-finalization readers and never create or accept execution data.
"""
from __future__ import annotations

import json
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from uuid import UUID

from backend.app.models.job import TERMINAL_JOB_STATUSES


@dataclass(frozen=True)
class RunManifestEntry:
    run_token: str
    phase_label: str | None
    bundle_sha256: str | None = None


def _uuid(value: str) -> str:
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Expected a canonical UUID")
    return value


def safe_artifact_path(root: Path, relative: str | Path) -> Path:
    """Reject traversal and links, including links into another run in this job."""
    root = Path(root)
    text = str(relative).replace("\\", "/")
    parts = PurePosixPath(text).parts
    if not parts or text.startswith("/") or any(p in ("..", ".") or ":" in p for p in parts):
        raise ValueError("Invalid artifact path")
    target = root.joinpath(*parts)
    # Check ancestors too: a replaced .runs or job directory must not redirect reads.
    for path in (target, *target.parents):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ValueError("Artifact links are not allowed")
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError("Artifact escapes its root")
    return target


def _job_dir(job_root: Path, job_id: str) -> Path:
    if not isinstance(job_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", job_id):
        raise ValueError("Invalid job ID")
    return safe_artifact_path(job_root, job_id)


def create_run_output_dir(job_root: Path, job_id: str, run_token: str) -> Path:
    directory = safe_artifact_path(_job_dir(job_root, job_id), f".runs/{_uuid(run_token)}")
    directory.mkdir(parents=True, exist_ok=False)
    for name in ("sensors", "artifacts", "metrics", "logs", "extracted_files/files", "normalized", "report"):
        (directory / name).mkdir(parents=True)
    return directory


def _entries(current) -> list[dict]:
    if isinstance(current, str):
        current = json.loads(current)
    if not isinstance(current, list):
        raise ValueError("Manifest must be a list")
    result, phases, tokens = [], set(), set()
    for entry in current:
        if isinstance(entry, RunManifestEntry):
            entry = asdict(entry)
        if not isinstance(entry, dict) or set(entry) - {"run_token", "phase_label", "bundle_sha256"}:
            raise ValueError("Invalid manifest entry")
        run_token = _uuid(entry.get("run_token"))
        if "phase_label" not in entry:
            raise ValueError("Missing phase label")
        phase = entry["phase_label"]
        if phase is not None and (not isinstance(phase, str) or not phase.strip()):
            raise ValueError("Invalid phase label")
        digest = entry.get("bundle_sha256")
        if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)):
            raise ValueError("Invalid bundle digest")
        if phase in phases or run_token in tokens:
            raise ValueError("Duplicate manifest entry")
        phases.add(phase)
        tokens.add(run_token)
        value = {"run_token": run_token, "phase_label": phase}
        if digest is not None:
            value["bundle_sha256"] = digest
        result.append(value)
    return sorted(result, key=lambda entry: (entry["phase_label"] is not None, entry["phase_label"] or ""))


def build_accepted_manifest(current, run_token: str, phase_label: str | None,
                            bundle_sha256: str | None = None) -> str:
    entries = _entries([] if current is None else current)
    entries = [entry for entry in entries if entry["phase_label"] != phase_label]
    entries.append(asdict(RunManifestEntry(run_token, phase_label, bundle_sha256)))
    return json.dumps(_entries(entries), separators=(",", ":"))


def resolve_accepted_run_dirs(job, job_root: Path, *, phase_label: str | None = None) -> list[Path]:
    """Fail closed on any invalid manifest/path; terminal layout 1 alone may fall back."""
    try:
        root = _job_dir(job_root, job.job_id)
        manifest = job.accepted_run_manifest_json
        if manifest is None:
            if job.artifact_layout_version == 1 and job.status in TERMINAL_JOB_STATUSES and root.is_dir():
                return [root]
            return []
        entries = _entries(manifest)
        paths = [safe_artifact_path(root, f".runs/{entry['run_token']}") for entry in entries]
        if any(not path.is_dir() for path in paths):
            return []
        return [path for entry, path in zip(entries, paths)
                if phase_label is None or entry["phase_label"] in (None, phase_label)]
    except (ValueError, TypeError, OSError):
        return []


def resolve_published_artifact_dir(job, job_root: Path, artifact_id: str) -> Path:
    if job.status not in TERMINAL_JOB_STATUSES:
        raise ValueError("Artifacts can only be published for terminal jobs")
    return safe_artifact_path(_job_dir(job_root, job.job_id), f"published/{_uuid(artifact_id)}")


def iter_run_files(run_dir: Path, pattern: str = "*"):
    """Yield safe execution files only, never stable inputs or nested run/published trees."""
    allowed = {"sensors", "artifacts", "metrics", "logs", "extracted_files", "normalized", "report", "telemetry_diagnostics.json"}

    def walk(path: Path):
        try:
            # Validate before listing a directory, including links/junctions
            # nested under an allowed execution subtree.
            path = safe_artifact_path(run_dir, path.relative_to(run_dir))
            if path.is_dir():
                children = sorted(path.iterdir())
            elif path.is_file() and path.match(pattern):
                yield path
                return
            else:
                return
        except (OSError, ValueError):
            return
        for child in children:
            yield from walk(child)

    # Do not recursively enumerate the job root: layout 1 also contains stable
    # inputs, publications and abandoned .runs trees that readers may not enter.
    for name in sorted(allowed):
        yield from walk(run_dir / name)


def run_archive_prefix(job, run_dir: Path) -> str:
    """UUID disambiguates phase replacements without exposing labels as paths."""
    return f"runs/{run_dir.name}/" if run_dir.parent.name == ".runs" else ""


def cleanup_unaccepted_runs(job, job_root: Path) -> list[Path]:
    """Remove abandoned runs, conservatively preserving accepted and active tokens."""
    try:
        entries = _entries(job.accepted_run_manifest_json) if job.accepted_run_manifest_json is not None else []
        keep = {entry["run_token"] for entry in entries}
        if getattr(job, "run_token", None):
            keep.add(_uuid(job.run_token))
        runs = safe_artifact_path(_job_dir(job_root, job.job_id), ".runs")
        candidates = list(runs.iterdir()) if runs.is_dir() else []
        removed = []
        for candidate in candidates:
            try:
                name = _uuid(candidate.name)
                path = safe_artifact_path(runs, name)
            except (ValueError, OSError):
                continue
            if name not in keep and path.is_dir():
                shutil.rmtree(path)
                removed.append(path)
        return removed
    except (ValueError, TypeError, OSError):
        return []
