"""
Disk Guardrails / Preflight Checks (§2.5).

Before starting a job, verify sufficient disk space and enforce per-job quotas.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PreflightResult:
    """Result of a preflight disk check."""

    ok: bool
    required_bytes: int
    available_bytes: int
    message: str = ""


def check_disk_space(
    pcap_size_bytes: int,
    job_root: Path,
    preflight_multiplier: int = 4,
) -> PreflightResult:
    """Check whether there is enough free disk to run a job (§2.5).

    Required space = pcap_size * preflight_multiplier.
    Returns PreflightResult with ok=True if sufficient.
    """
    required = pcap_size_bytes * preflight_multiplier
    disk = shutil.disk_usage(job_root)
    available = disk.free

    if available < required:
        return PreflightResult(
            ok=False,
            required_bytes=required,
            available_bytes=available,
            message=(
                f"Insufficient disk: need {required:,} bytes "
                f"({pcap_size_bytes:,} × {preflight_multiplier}), "
                f"only {available:,} available"
            ),
        )
    return PreflightResult(
        ok=True,
        required_bytes=required,
        available_bytes=available,
    )


def check_disk_thresholds(
    job_root: Path,
    warn_pct: int = 80,
    critical_pct: int = 95,
) -> tuple[bool, bool, float]:
    """Check overall disk usage against warning/critical thresholds.

    Returns (warn_exceeded, critical_exceeded, usage_pct).
    """
    disk = shutil.disk_usage(job_root)
    usage_pct = ((disk.total - disk.free) / disk.total) * 100 if disk.total > 0 else 0.0

    return (
        usage_pct >= warn_pct,
        usage_pct >= critical_pct,
        round(usage_pct, 1),
    )


def check_job_quota(
    job_dir: Path,
    max_job_disk_bytes: int,
) -> bool:
    """Check if a job directory has exceeded its disk quota.

    Returns True if quota exceeded.
    """
    total = 0
    for f in job_dir.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
            if total > max_job_disk_bytes:
                return True
    return False


def check_extracted_quota(
    job_dir: Path,
    max_extracted_bytes: int,
) -> bool:
    """Check if extracted files exceed the extraction quota.

    Returns True if quota exceeded.
    """
    extracted_dir = job_dir / "extracted_files"
    if not extracted_dir.exists():
        return False

    total = 0
    for f in extracted_dir.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
            if total > max_extracted_bytes:
                return True
    return False

