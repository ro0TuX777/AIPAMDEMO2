"""
Job Directory Manager (§2) — filesystem IPC contract.

Creates and manages the on-disk directory layout for each job.
Every job gets a deterministic tree under AIPAM_JOB_ROOT/<job_id>/.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def create_job_directory(job_root: Path, job_id: str) -> Path:
    """Create the full job directory tree (§2).

    Returns the job directory path.
    """
    job_dir = job_root / job_id

    # Core directories
    (job_dir / "input").mkdir(parents=True, exist_ok=True)
    (job_dir / "runtime").mkdir(exist_ok=True)
    (job_dir / "extracted_files" / "files").mkdir(parents=True, exist_ok=True)
    (job_dir / "sensors").mkdir(exist_ok=True)
    (job_dir / "normalized").mkdir(exist_ok=True)
    (job_dir / "report").mkdir(exist_ok=True)

    return job_dir


def create_sensor_output_dir(job_dir: Path, sensor_name: str) -> Path:
    """Create the output directory for a specific sensor.

    Returns: /jobs/<job_id>/sensors/<sensor_name>/
    """
    sensor_dir = job_dir / "sensors" / sensor_name
    sensor_dir.mkdir(parents=True, exist_ok=True)
    (sensor_dir / "raw").mkdir(exist_ok=True)
    return sensor_dir


def link_pcap(job_dir: Path, pcap_source: Path) -> Path:
    """Copy (or hardlink) the uploaded PCAP into the job input directory.

    Returns the destination path (/jobs/<job_id>/input/pcap.pcap).
    """
    dest = job_dir / "input" / "pcap.pcap"
    if dest.exists():
        return dest

    # Try hardlink first (saves disk); fall back to copy
    try:
        dest.hardlink_to(pcap_source)
    except OSError:
        shutil.copy2(pcap_source, dest)

    return dest


def link_pcap_labeled(job_dir: Path, pcap_source: Path, label: str) -> Path:
    """Copy a PCAP into the job input directory with a label-based name.

    For multi-PCAP jobs, each file is stored as input/<label>.pcap.
    Also creates a symlink from input/pcap.pcap -> first PCAP for backward compat.
    Returns the destination path.
    """
    # Sanitize label for use as filename
    safe_label = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)
    suffix = pcap_source.suffix or ".pcap"
    dest = job_dir / "input" / f"{safe_label}{suffix}"
    if dest.exists():
        return dest

    try:
        dest.hardlink_to(pcap_source)
    except OSError:
        shutil.copy2(pcap_source, dest)

    # Backward compat: if pcap.pcap doesn't exist, symlink to first file
    default = job_dir / "input" / "pcap.pcap"
    if not default.exists():
        try:
            default.symlink_to(dest.name)
        except OSError:
            shutil.copy2(pcap_source, default)

    return dest


def compute_pcap_sha256(pcap_path: Path) -> str:
    """Compute SHA-256 of a PCAP file in 256 KB chunks."""
    sha = hashlib.sha256()
    with open(pcap_path, "rb") as f:
        while chunk := f.read(262_144):
            sha.update(chunk)
    return sha.hexdigest()


def write_input_meta(
    job_dir: Path,
    *,
    job_id: str,
    pcap_filename: str,
    pcap_sha256: str,
    execution_profile: str,
    job_options: dict[str, Any] | None = None,
    submitted_by: str = "system",
) -> Path:
    """Write input.meta.json into the job input directory (§2).

    Returns the path to the written file.
    """
    meta = {
        "job_id": job_id,
        "pcap_filename": pcap_filename,
        "pcap_sha256": pcap_sha256,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "submitted_by": submitted_by,
        "execution_profile": execution_profile,
        "job_options": job_options or {},
    }

    meta_path = job_dir / "input" / "input.meta.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta_path


def read_input_meta(job_dir: Path) -> dict[str, Any]:
    """Read and parse input.meta.json. Raises FileNotFoundError if missing."""
    meta_path = job_dir / "input" / "input.meta.json"
    return json.loads(meta_path.read_text(encoding="utf-8"))


def get_job_disk_usage(job_dir: Path) -> int:
    """Calculate total disk usage of a job directory in bytes."""
    total = 0
    for f in job_dir.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
    return total


def cleanup_job_directory(job_root: Path, job_id: str) -> bool:
    """Remove a job directory entirely. Returns True if deleted."""
    job_dir = job_root / job_id
    if job_dir.exists():
        shutil.rmtree(job_dir)
        return True
    return False

