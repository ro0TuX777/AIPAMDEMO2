#!/usr/bin/env python3
"""
aipam-admin CLI — operational tools for AIPAM V2.

Usage:
    python -m backend.app.cli smoke-test [--pcap PATH] [--base-url URL]
    python -m backend.app.cli parity-check [--pcaps DIR]
    python -m backend.app.cli cleanup-jobs [--older-than DAYS] [--dry-run | --confirm]
    python -m backend.app.cli support-bundle [--job ID | --all-recent] [--output PATH]
    python -m backend.app.cli apply-update <zip-path>

Exit codes:
    0  All checks passed / operation succeeded
    1  One or more checks failed
    2  Usage / configuration error
"""

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Default base URL for local dev
DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_TOKEN = os.environ.get("AIPAM_API_TOKEN", "")


def _get_session(base_url: str, token: str):
    """Create a requests session with auth headers."""
    import requests
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    s.base_url = base_url  # type: ignore[attr-defined]
    return s


# ---------------------------------------------------------------------------
# Smoke Test
# ---------------------------------------------------------------------------


def _smoke_test_with_client(pcap_path: Path):
    """Run smoke test using FastAPI TestClient (no server needed)."""
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import Session
    from fastapi.testclient import TestClient
    from backend.app.database_v2 import Base, _set_sqlite_pragmas, get_db
    from backend.app.config_v2 import Settings, get_settings
    from backend.app.main_v2 import create_app

    import tempfile

    token = os.environ.get("AIPAM_API_TOKEN", "test-token-v2")
    AUTH = {"Authorization": f"Bearer {token}"}

    # Setup in-memory DB
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(bind=engine)
    connection = engine.connect()

    app = create_app()

    def _override_db():
        db = Session(bind=connection)
        try:
            yield db
        finally:
            db.close()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        upload_dir = tmp / "uploads"
        upload_dir.mkdir()
        job_dir = tmp / "jobs"
        job_dir.mkdir()

        settings = Settings(
            aipam_api_token=token,
            aipam_upload_root=upload_dir,
            aipam_job_root=job_dir,
            aipam_db_path=Path("/tmp/unused.db"),
        )
        app.dependency_overrides[get_db] = _override_db
        app.dependency_overrides[get_settings] = lambda: settings

        client = TestClient(app)
        results = _run_smoke_checks(client, AUTH, pcap_path)

    connection.close()
    engine.dispose()
    return results


def _run_smoke_checks(client, auth: dict, pcap_path: Path) -> list[dict]:
    """Execute all smoke test checks. Returns list of {name, passed, detail}."""
    checks = []

    def check(name: str, passed: bool, detail: str = ""):
        status = "PASS" if passed else "FAIL"
        checks.append({"name": name, "passed": passed, "detail": detail})
        print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))

    print(f"\n{'='*60}")
    print(f"AIPAM Smoke Test — {pcap_path.name}")
    print(f"{'='*60}\n")

    # 1. Upload
    data = pcap_path.read_bytes()
    r = client.post(f"/api/v1/uploads?filename={pcap_path.name}", content=data, headers=auth)
    check("Upload PCAP", r.status_code == 201, f"status={r.status_code}")
    if r.status_code != 201:
        return checks
    upload = r.json()
    upload_id = upload["upload_id"]
    check("Upload response has upload_id", bool(upload_id))
    check("Upload response has sha256", bool(upload.get("sha256")))

    # 2. Validate
    r = client.post(f"/api/v1/uploads/{upload_id}/validate", headers=auth)
    check("Validate upload", r.status_code == 200, f"status={r.status_code}")
    val = r.json()
    check("Validation is_valid", val.get("is_valid") is True)
    check("Validation format", val.get("format") is not None, f"format={val.get('format')}")

    # 3. Create job
    r = client.post("/api/v1/jobs", json={
        "upload_id": upload_id, "execution_profile": "standard", "job_name": "smoke-test",
    }, headers=auth)
    check("Create job", r.status_code == 201, f"status={r.status_code}")
    if r.status_code != 201:
        return checks
    job_id = r.json()["job_id"]

    # 4. Get job detail
    r = client.get(f"/api/v1/jobs/{job_id}", headers=auth)
    check("Get job detail", r.status_code == 200)
    detail = r.json()
    check("Job has correct status", detail["job"]["status"] in ("queued", "running", "completed"))
    check("Job has schema_version", "schema_version" in detail)

    # 5. List jobs
    r = client.get("/api/v1/jobs", headers=auth)
    check("List jobs", r.status_code == 200)
    check("Jobs list has page info", "page" in r.json())

    # 6. Sub-resources respond correctly
    for sub in ["hosts", "findings", "timeline", "iocs", "sensors"]:
        r = client.get(f"/api/v1/jobs/{job_id}/{sub}", headers=auth)
        check(f"GET /jobs/{{id}}/{sub}", r.status_code == 200)
        check(f"{sub} has items array", "items" in r.json())

    # 7. Summary
    r = client.get(f"/api/v1/jobs/{job_id}/summary", headers=auth)
    check("Job summary", r.status_code == 200)

    # 8. Health
    r = client.get("/api/v1/health", headers=auth)
    check("Health endpoint", r.status_code == 200)

    return checks


def cmd_smoke_test(args):
    """Run the smoke test."""
    pcap_path = Path(args.pcap) if args.pcap else None

    # If no PCAP specified, use a golden PCAP
    if pcap_path is None:
        golden_dir = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "golden"
        candidates = list(golden_dir.glob("*.pcap"))
        if not candidates:
            print("ERROR: No golden PCAPs found. Run: python -m tests.fixtures.golden.generate_golden_pcaps")
            sys.exit(2)
        pcap_path = candidates[0]

    if not pcap_path.exists():
        print(f"ERROR: PCAP not found: {pcap_path}")
        sys.exit(2)

    checks = _smoke_test_with_client(pcap_path)

    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])

    print(f"\n{'='*60}")
    print(f"Results: {passed} passed, {failed} failed out of {len(checks)} checks")
    print(f"{'='*60}\n")

    sys.exit(0 if failed == 0 else 1)


# ---------------------------------------------------------------------------
# Parity Check
# ---------------------------------------------------------------------------

def cmd_parity_check(args):
    """Compare V1 vs V2 pipeline outputs on golden PCAPs."""
    pcaps_dir = Path(args.pcaps) if args.pcaps else None

    if pcaps_dir is None:
        pcaps_dir = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "golden"

    if not pcaps_dir.exists():
        print(f"ERROR: PCAPs directory not found: {pcaps_dir}")
        sys.exit(2)

    pcap_files = sorted(pcaps_dir.glob("*.pcap"))
    if not pcap_files:
        print(f"ERROR: No PCAPs found in {pcaps_dir}")
        sys.exit(2)

    print(f"\n{'='*60}")
    print(f"AIPAM Parity Check — {len(pcap_files)} PCAPs")
    print(f"{'='*60}\n")

    all_passed = True
    results = []

    for pcap_path in pcap_files:
        print(f"\n--- {pcap_path.name} ---")

        # Run V2 pipeline (via TestClient)
        v2_checks = _smoke_test_with_client(pcap_path)
        v2_pass = all(c["passed"] for c in v2_checks)

        result = {
            "pcap": pcap_path.name,
            "v2_checks_passed": sum(1 for c in v2_checks if c["passed"]),
            "v2_checks_total": len(v2_checks),
            "v2_pass": v2_pass,
            # V1 comparison would go here in bridge mode
            "parity_status": "v2_only" if v2_pass else "v2_failed",
        }
        results.append(result)

        if not v2_pass:
            all_passed = False

    # Write report
    report_dir = Path(args.output) if args.output else Path("parity_output")
    report_dir.mkdir(parents=True, exist_ok=True)

    report_path = report_dir / "parity_report.json"
    report_path.write_text(json.dumps({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pcap_count": len(pcap_files),
        "all_passed": all_passed,
        "results": results,
    }, indent=2) + "\n")

    # Summary
    summary_path = report_dir / "diff_summary.md"
    lines = [
        "# Parity Check Report\n",
        f"**Date**: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}\n",
        f"**PCAPs tested**: {len(pcap_files)}\n",
        f"**Overall**: {'PASS' if all_passed else 'FAIL'}\n\n",
        "| PCAP | V2 Checks | Status |\n",
        "|---|---|---|\n",
    ]
    for r in results:
        lines.append(f"| {r['pcap']} | {r['v2_checks_passed']}/{r['v2_checks_total']} | {r['parity_status']} |\n")
    summary_path.write_text("".join(lines))

    print(f"\n{'='*60}")
    print(f"Parity report: {report_path}")
    print(f"Summary: {summary_path}")
    print(f"Overall: {'PASS' if all_passed else 'FAIL'}")
    print(f"{'='*60}\n")

    sys.exit(0 if all_passed else 1)


# ---------------------------------------------------------------------------
# Cleanup Jobs (§18)
# ---------------------------------------------------------------------------

_TERMINAL_STATUSES = ("completed", "failed", "cancelled")

logger = logging.getLogger("aipam.cli")


def _parse_duration(value: str) -> int:
    """Parse a human duration like '30d' or '14d' into days. Plain int also accepted."""
    m = re.match(r"^(\d+)\s*d?$", value.strip())
    if not m:
        print(f"ERROR: Cannot parse duration '{value}'. Use e.g. '30d' or '30'.")
        sys.exit(2)
    return int(m.group(1))


def cmd_cleanup_jobs(args):
    """Delete expired jobs (filesystem + DB rows) per §18 retention policy."""
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker
    from backend.app.database_v2 import _set_sqlite_pragmas
    from backend.app.models.job import Job

    dry_run = args.dry_run
    confirm = args.confirm
    older_than_days = _parse_duration(args.older_than)

    if not dry_run and not confirm:
        print("ERROR: Must specify --dry-run or --confirm.")
        sys.exit(2)

    # Resolve settings
    job_root = Path(os.environ.get("AIPAM_JOB_ROOT", "/jobs"))
    db_path = Path(os.environ.get("AIPAM_DB_PATH", "/data/aipam.db"))

    if not db_path.exists():
        print(f"ERROR: Database not found at {db_path}")
        sys.exit(2)

    db_url = f"sqlite:///{db_path}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    SessionLocal = sessionmaker(bind=engine)

    cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )

    print(f"\n{'='*60}")
    print(f"AIPAM Job Cleanup — {'DRY RUN' if dry_run else 'LIVE'}")
    print(f"  Retention: {older_than_days} days")
    print(f"  Cutoff:    {cutoff}")
    print(f"  Job root:  {job_root}")
    print(f"{'='*60}\n")

    with SessionLocal() as db:
        expired_jobs = (
            db.query(Job)
            .filter(
                Job.status.in_(_TERMINAL_STATUSES),
                Job.completed_at < cutoff,
            )
            .all()
        )

        if not expired_jobs:
            print("No expired jobs found.")
            engine.dispose()
            return

        print(f"Found {len(expired_jobs)} expired job(s):\n")
        for job in expired_jobs:
            job_dir = job_root / job.job_id
            dir_exists = job_dir.exists()
            dir_size = _dir_size(job_dir) if dir_exists else 0
            size_str = _human_bytes(dir_size)
            print(
                f"  {job.job_id[:12]}…  status={job.status}  "
                f"completed_at={job.completed_at}  dir={'yes' if dir_exists else 'no'}  "
                f"size={size_str}"
            )

        if dry_run:
            print(f"\nDry run complete. {len(expired_jobs)} job(s) would be deleted.")
            engine.dispose()
            return

        # Live deletion
        deleted = 0
        errors = 0
        for job in expired_jobs:
            job_dir = job_root / job.job_id
            jid = job.job_id
            try:
                # 1. Delete filesystem directory
                if job_dir.exists():
                    shutil.rmtree(job_dir)
                # 2. Delete DB row (ON DELETE CASCADE handles children)
                db.delete(job)
                db.commit()
                deleted += 1
                logger.info("job_cleaned job_id=%s", jid)
                print(f"  [DELETED] {jid[:12]}…")
            except Exception as exc:
                db.rollback()
                errors += 1
                logger.error("cleanup_failed job_id=%s error=%s", jid, exc)
                print(f"  [ERROR]   {jid[:12]}… — {exc}")

        print(f"\nCleanup complete: {deleted} deleted, {errors} errors.")
    engine.dispose()
    sys.exit(1 if errors else 0)


def _dir_size(path: Path) -> int:
    """Total bytes used by a directory tree."""
    total = 0
    try:
        for f in path.rglob("*"):
            if f.is_file():
                total += f.stat().st_size
    except OSError:
        pass
    return total


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} TB"


# ---------------------------------------------------------------------------
# Support Bundle (§22)
# ---------------------------------------------------------------------------


def cmd_support_bundle(args):
    """Generate a support bundle tar.gz for air-gapped debugging."""
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker
    from backend.app.database_v2 import _set_sqlite_pragmas
    from backend.app.models.job import Job
    from backend.app.models.sensor import JobSensor

    job_root = Path(os.environ.get("AIPAM_JOB_ROOT", "/jobs"))
    db_path = Path(os.environ.get("AIPAM_DB_PATH", "/data/aipam.db"))
    log_dir = Path(os.environ.get("AIPAM_LOG_DIR", "/opt/aipam/logs"))

    if not db_path.exists():
        print(f"ERROR: Database not found at {db_path}")
        sys.exit(2)

    db_url = f"sqlite:///{db_path}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    SessionLocal = sessionmaker(bind=engine)

    # Determine which jobs to include
    with SessionLocal() as db:
        if args.job:
            jobs = db.query(Job).filter(Job.job_id == args.job).all()
            if not jobs:
                print(f"ERROR: Job {args.job} not found.")
                engine.dispose()
                sys.exit(2)
        elif args.all_recent:
            cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime(
                "%Y-%m-%dT%H:%M:%S"
            )
            jobs = db.query(Job).filter(Job.created_at >= cutoff_24h).all()
        else:
            print("ERROR: Must specify --job <id> or --all-recent.")
            engine.dispose()
            sys.exit(2)

        timestamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        output_path = Path(args.output) if args.output else Path(f"support_bundle_{timestamp}.tar.gz")

        print(f"\n{'='*60}")
        print("AIPAM Support Bundle")
        print(f"  Jobs:   {len(jobs)}")
        print(f"  Output: {output_path}")
        print(f"{'='*60}\n")

        with tarfile.open(str(output_path), "w:gz") as tar:
            bundle_root = f"support_bundle_{timestamp}"

            # 1. Job metadata
            for job in jobs:
                job_meta = {
                    "job_id": job.job_id,
                    "job_name": job.job_name,
                    "status": job.status,
                    "execution_profile": job.execution_profile,
                    "priority": job.priority,
                    "pcap_filename": job.pcap_filename,
                    "pcap_size_bytes": job.pcap_size_bytes,
                    "created_at": job.created_at,
                    "started_at": job.started_at,
                    "completed_at": job.completed_at,
                    "error_summary": job.error_summary,
                }
                _add_json_to_tar(tar, f"{bundle_root}/jobs/{job.job_id}/metadata.json", job_meta)

                # Sensor statuses
                sensors = db.query(JobSensor).filter(JobSensor.job_id == job.job_id).all()
                sensor_list = []
                for s in sensors:
                    sensor_list.append({
                        "sensor": s.sensor,
                        "status": s.status,
                        "started_at": s.started_at,
                        "completed_at": s.completed_at,
                        "duration_ms": s.duration_ms,
                        "error": s.error,
                    })
                _add_json_to_tar(tar, f"{bundle_root}/jobs/{job.job_id}/sensors.json", sensor_list)

                # Job metrics file
                metrics_path = job_root / job.job_id / "metrics" / "job_metrics.json"
                if metrics_path.exists():
                    tar.add(str(metrics_path), arcname=f"{bundle_root}/jobs/{job.job_id}/job_metrics.json")

                # Telemetry pipeline diagnostics
                diag_path = job_root / job.job_id / "telemetry_diagnostics.json"
                if diag_path.exists():
                    tar.add(str(diag_path), arcname=f"{bundle_root}/jobs/{job.job_id}/telemetry_diagnostics.json")

                # Source manifest (useful for understanding what was ingested)
                manifest_path = job_root / job.job_id / "source_manifest.json"
                if manifest_path.exists():
                    tar.add(str(manifest_path), arcname=f"{bundle_root}/jobs/{job.job_id}/source_manifest.json")

                # Sensor container logs (NOT raw pcap data)
                sensors_dir = job_root / job.job_id / "sensors"
                if sensors_dir.exists():
                    for container_log in sensors_dir.rglob("container.log"):
                        rel = container_log.relative_to(job_root / job.job_id)
                        tar.add(str(container_log), arcname=f"{bundle_root}/jobs/{job.job_id}/{rel}")

            # 2. Health snapshot
            health = _collect_health_snapshot(job_root)
            _add_json_to_tar(tar, f"{bundle_root}/system/health.json", health)

            # 3. Non-sensitive config snapshot
            config_snap = _collect_config_snapshot()
            _add_json_to_tar(tar, f"{bundle_root}/system/config.json", config_snap)

            # 4. Disk usage
            disk_info = _collect_disk_info(job_root)
            _add_json_to_tar(tar, f"{bundle_root}/system/disk.json", disk_info)

            # 5. Recent logs (last 1000 lines each, exclude secrets)
            if log_dir.exists():
                for log_file in sorted(log_dir.glob("*.log"))[:10]:
                    try:
                        lines = log_file.read_text(errors="replace").splitlines()[-1000:]
                        content = "\n".join(lines)
                        # Redact tokens
                        content = re.sub(
                            r"(Bearer\s+|AIPAM_API_TOKEN=)\S+",
                            r"\1[REDACTED]",
                            content,
                        )
                        _add_text_to_tar(tar, f"{bundle_root}/logs/{log_file.name}", content)
                    except Exception:
                        pass

        print(f"Bundle created: {output_path} ({_human_bytes(output_path.stat().st_size)})")

    engine.dispose()


def _add_json_to_tar(tar: tarfile.TarFile, arcname: str, data) -> None:
    """Add a JSON-serializable object as a file in the tar."""
    content = json.dumps(data, indent=2, default=str).encode()
    import io
    info = tarfile.TarInfo(name=arcname)
    info.size = len(content)
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(content))


def _add_text_to_tar(tar: tarfile.TarFile, arcname: str, text: str) -> None:
    """Add a text string as a file in the tar."""
    content = text.encode()
    import io
    info = tarfile.TarInfo(name=arcname)
    info.size = len(content)
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(content))


def _collect_health_snapshot(job_root: Path) -> dict:
    """Collect a health snapshot similar to GET /health."""
    try:
        total, used, free = shutil.disk_usage(str(job_root))
        pct_used = int((used / total) * 100) if total else 100
    except Exception:
        total = used = free = 0
        pct_used = -1

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "disk_total_bytes": total,
        "disk_used_bytes": used,
        "disk_free_bytes": free,
        "disk_used_pct": pct_used,
    }


def _collect_config_snapshot() -> dict:
    """Collect non-sensitive configuration values."""
    # Only include non-secret env vars
    safe_keys = [
        "AIPAM_MAX_CONCURRENT_JOBS", "AIPAM_SENSOR_PARALLELISM",
        "AIPAM_MAX_JOB_DISK_BYTES", "AIPAM_MAX_EXTRACTED_BYTES",
        "AIPAM_PREFLIGHT_MULTIPLIER", "AIPAM_JOB_RETENTION_DAYS",
        "AIPAM_LOG_RETENTION_DAYS", "AIPAM_LOG_MAX_MB",
        "AIPAM_DISK_WARN_PCT", "AIPAM_DISK_CRITICAL_PCT",
        "AIPAM_JOB_ROOT", "AIPAM_UPLOAD_ROOT", "AIPAM_DB_PATH",
    ]
    return {k: os.environ.get(k, "") for k in safe_keys}


def _collect_disk_info(job_root: Path) -> dict:
    """Collect disk usage details for job root."""
    try:
        total, used, free = shutil.disk_usage(str(job_root))
    except Exception:
        total = used = free = 0

    # Count job directories
    job_count = 0
    jobs_size = 0
    if job_root.exists():
        for d in job_root.iterdir():
            if d.is_dir():
                job_count += 1
                jobs_size += _dir_size(d)

    return {
        "job_root": str(job_root),
        "partition_total_bytes": total,
        "partition_used_bytes": used,
        "partition_free_bytes": free,
        "job_directory_count": job_count,
        "job_directories_total_bytes": jobs_size,
    }


# ---------------------------------------------------------------------------
# Offline Update (§13)
# ---------------------------------------------------------------------------

# Default paths per §13
_UPDATE_LOG = Path("/opt/aipam/logs/updates.log")
_APPLIED_JSON = Path("/opt/aipam/offline_updates/applied.json")
_BACKUP_ROOT = Path("/opt/aipam/backups")
_RULES_YARA = Path("/opt/aipam/rules/yara")
_RULES_SURICATA = Path("/opt/aipam/rules/suricata")
_TI_BUNDLES = Path("/opt/aipam/ti/bundles")


def cmd_apply_update(args):
    """Apply an offline update bundle (ZIP) with integrity verification (§13.1)."""
    zip_path = Path(args.zip_path)
    if not zip_path.exists():
        print(f"ERROR: Update bundle not found: {zip_path}")
        sys.exit(2)
    if not zipfile.is_zipfile(str(zip_path)):
        print(f"ERROR: Not a valid ZIP file: {zip_path}")
        sys.exit(2)

    print(f"\n{'='*60}")
    print(f"AIPAM Offline Update — {zip_path.name}")
    print(f"{'='*60}\n")

    with zipfile.ZipFile(str(zip_path), "r") as zf:
        # 1. Parse manifest.json
        if "manifest.json" not in zf.namelist():
            print("ERROR: manifest.json not found in bundle.")
            _log_update("FAIL", zip_path.name, "Missing manifest.json")
            sys.exit(1)

        manifest = json.loads(zf.read("manifest.json"))
        bundle_version = manifest.get("bundle_version", "unknown")
        files = manifest.get("files", [])

        print(f"  Bundle version: {bundle_version}")
        print(f"  Files: {len(files)}\n")

        # Check if already applied
        applied = _load_applied()
        if bundle_version in applied:
            print(f"  WARNING: Bundle {bundle_version} was previously applied.")
            print("  Continuing anyway (re-application allowed).\n")

        # 2. Verify SHA256 checksums for every file (§13.1)
        print("  Verifying checksums...")
        all_ok = True
        for entry in files:
            fname = entry["path"]
            expected_sha = entry["sha256"]
            if fname not in zf.namelist():
                print(f"    [MISSING] {fname}")
                _log_update("FAIL", zip_path.name, f"Missing file: {fname}")
                all_ok = False
                continue
            actual_sha = hashlib.sha256(zf.read(fname)).hexdigest()
            if actual_sha != expected_sha:
                print(f"    [MISMATCH] {fname}  expected={expected_sha[:16]}… got={actual_sha[:16]}…")
                _log_update("FAIL", zip_path.name, f"Checksum mismatch: {fname}")
                all_ok = False
            else:
                print(f"    [OK] {fname}")

        if not all_ok:
            print("\n  ERROR: Integrity check failed. Update NOT applied.")
            sys.exit(1)

        # 3. Create backup of current state (§13.3)
        backup_ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        backup_dir = _BACKUP_ROOT / backup_ts
        print(f"\n  Creating backup → {backup_dir}")
        _create_backup(backup_dir)

        # Prune old backups (keep last 3)
        _prune_backups(keep=3)

        # 4. Unpack files to their destinations
        print("\n  Applying update...")
        for entry in files:
            fname = entry["path"]
            dest_type = entry.get("type", "")
            data = zf.read(fname)

            if dest_type == "yara":
                dest = _RULES_YARA / Path(fname).name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                print(f"    [YARA]     {dest}")
            elif dest_type == "suricata":
                dest = _RULES_SURICATA / Path(fname).name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                print(f"    [SURICATA] {dest}")
            elif dest_type == "ti":
                dest = _TI_BUNDLES / Path(fname).name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                print(f"    [TI]       {dest}")
            elif dest_type == "docker_image":
                # Write to temp file, then docker load
                with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tf:
                    tf.write(data)
                    tf.flush()
                    print(f"    [DOCKER]   Loading {fname}...")
                    ret = os.system(f"docker load -i {tf.name}")
                    os.unlink(tf.name)
                    if ret != 0:
                        print(f"    [WARN]     docker load failed for {fname}")
            else:
                print(f"    [SKIP]     {fname} (unknown type: {dest_type})")

        # 5. Record applied version
        applied[bundle_version] = {
            "applied_at": datetime.now(timezone.utc).isoformat(),
            "file": zip_path.name,
            "file_count": len(files),
        }
        _save_applied(applied)
        _log_update("OK", zip_path.name, f"Applied bundle {bundle_version}, {len(files)} files")

    print(f"\n  Update applied successfully. Bundle version: {bundle_version}")
    print(f"{'='*60}\n")


def _load_applied() -> dict:
    if _APPLIED_JSON.exists():
        try:
            return json.loads(_APPLIED_JSON.read_text())
        except Exception:
            return {}
    return {}


def _save_applied(data: dict) -> None:
    _APPLIED_JSON.parent.mkdir(parents=True, exist_ok=True)
    _APPLIED_JSON.write_text(json.dumps(data, indent=2) + "\n")


def _create_backup(backup_dir: Path) -> None:
    """Backup current rules and TI bundles before update."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    for src, label in [(_RULES_YARA, "rules/yara"), (_RULES_SURICATA, "rules/suricata"), (_TI_BUNDLES, "ti/bundles")]:
        if src.exists():
            dest = backup_dir / label
            shutil.copytree(str(src), str(dest), dirs_exist_ok=True)


def _prune_backups(keep: int = 3) -> None:
    """Keep only the N most recent backups."""
    if not _BACKUP_ROOT.exists():
        return
    backups = sorted(_BACKUP_ROOT.iterdir(), reverse=True)
    for old in backups[keep:]:
        if old.is_dir():
            shutil.rmtree(old)


def _log_update(status: str, bundle_name: str, detail: str) -> None:
    """Append a line to the update log."""
    try:
        _UPDATE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(_UPDATE_LOG, "a") as f:
            ts = datetime.now(timezone.utc).isoformat()
            f.write(f"{ts} [{status}] {bundle_name}: {detail}\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def cmd_perf_gate(args):
    """Check job runtimes against performance SLOs (§8.6)."""

    # SLO definitions: (profile, pcap_size_mb_max, target_seconds)
    SLOS = [
        ("triage",   100,    3 * 60),
        ("standard", 100,    8 * 60),
        ("standard", 1024,  45 * 60),
        ("deep",     1024,  90 * 60),
    ]

    job_root = Path(args.job_root)
    if not job_root.exists():
        print(f"ERROR: Job root not found: {job_root}")
        sys.exit(2)

    job_dirs = sorted(
        [d for d in job_root.iterdir() if d.is_dir() and (d / "metrics" / "job_metrics.json").exists()]
    )

    if not job_dirs:
        print("No jobs with job_metrics.json found.")
        sys.exit(0)

    violations = 0
    checked = 0

    for jd in job_dirs:
        metrics_path = jd / "metrics" / "job_metrics.json"
        input_meta_path = jd / "input" / "input.meta.json"
        try:
            metrics = json.loads(metrics_path.read_text())
            profile = "standard"
            if input_meta_path.exists():
                meta = json.loads(input_meta_path.read_text())
                profile = meta.get("execution_profile", "standard")

            runtime_sec = metrics.get("total_runtime_sec", 0)
            pcap_mb = metrics.get("pcap_size_bytes", 0) / (1024 * 1024)

            # Find the applicable SLO
            applicable_slo = None
            for slo_profile, slo_max_mb, slo_target in SLOS:
                if slo_profile == profile and pcap_mb <= slo_max_mb:
                    applicable_slo = (slo_max_mb, slo_target)
                    break

            if applicable_slo is None:
                continue

            checked += 1
            slo_target = applicable_slo[1]
            status = "✅" if runtime_sec <= slo_target else "❌"
            if runtime_sec > slo_target:
                violations += 1

            print(
                f"{status} {jd.name}  profile={profile}  "
                f"pcap={pcap_mb:.1f}MB  runtime={runtime_sec}s  "
                f"SLO={slo_target}s"
            )
        except Exception as exc:
            print(f"⚠️  {jd.name}: {exc}")

    print(f"\nChecked {checked} jobs, {violations} SLO violations")
    sys.exit(1 if violations > 0 else 0)


def cmd_benchmark(args):
    """Run benchmark evaluation on a manifest of PCAPs (§14.10).

    Wraps the standalone ``benchmark/evaluate.py`` logic so it can be invoked
    via ``aipam-admin benchmark``.
    """
    # Resolve paths relative to the repo root so the command works from any cwd.
    repo_root = Path(__file__).resolve().parent.parent.parent
    benchmark_dir = repo_root / "benchmark"

    # Ensure the benchmark package is importable.
    if str(benchmark_dir.parent) not in sys.path:
        sys.path.insert(0, str(benchmark_dir.parent))

    try:
        from benchmark.evaluate import run_benchmark  # type: ignore[import-untyped]
        from benchmark.inference import InferenceConfig  # type: ignore[import-untyped]
    except ImportError as exc:
        print(f"ERROR: Could not import benchmark modules: {exc}")
        print("Make sure the benchmark/ directory is present at the repo root.")
        sys.exit(2)

    # Resolve manifest — fall back to the default trained-families manifest.
    manifest = args.manifest
    if manifest is None:
        manifest = str(benchmark_dir / "manifests" / "benchmark_manifest.json")
        if not Path(manifest).exists():
            # Try the trained families manifest as a second fallback
            manifest = str(benchmark_dir / "manifests" / "trained_families_benchmark.json")
    manifest = str(Path(manifest).resolve())

    if not Path(manifest).exists():
        print(f"ERROR: Manifest not found: {manifest}")
        sys.exit(2)

    config = InferenceConfig(
        endpoint=args.endpoint,
        model=args.model,
    )

    output_dir = args.output or str(benchmark_dir / "benchmark_results")

    # --- Baseline comparison (§14.10) -----------------------------------------
    baseline_path = args.baseline
    report = run_benchmark(
        manifest,
        config=config,
        output_dir=output_dir,
        limit=args.limit or None,
        filter_set=args.set or None,
    )

    if baseline_path and Path(baseline_path).exists():
        import json as _json
        with open(baseline_path) as f:
            baseline = _json.load(f)

        baseline_time = baseline.get("avg_inference_time", 0)
        baseline_acc = baseline.get("accuracy", 0)

        time_delta = (
            (report.avg_inference_time - baseline_time) / baseline_time * 100
            if baseline_time
            else 0
        )
        acc_delta = (report.accuracy - baseline_acc) * 100

        print("\n--- Baseline Comparison ---")
        print(f"Accuracy   : {report.accuracy:.2%} vs {baseline_acc:.2%} ({acc_delta:+.1f}pp)")
        print(f"Avg Time   : {report.avg_inference_time:.2f}s vs {baseline_time:.2f}s ({time_delta:+.1f}%)")

        if time_delta > 20:
            print("⚠️  Runtime regression > 20% — review before merging.")
            sys.exit(1)
    elif baseline_path:
        print(f"\nWARN: Baseline file not found ({baseline_path}), skipping comparison.")

    sys.exit(0)


# ---------------------------------------------------------------------------
# MNEMOS finding reconciliation
# ---------------------------------------------------------------------------


def reconcile_mnemos_findings(
    db,
    *,
    client: Any,
    batch_size: int = 100,
) -> dict[str, int]:
    """Upsert all confirmed findings into MNEMOS in deterministic batches."""
    from sqlalchemy import select

    from backend.app.forensic_memory import mnemos_document_for_finding
    from backend.app.models.bluescrub import BlueScrubJobLineage
    from backend.app.models.finding import Finding

    rows = db.execute(
        select(Finding, BlueScrubJobLineage.project_id)
        .outerjoin(
            BlueScrubJobLineage,
            BlueScrubJobLineage.job_id == Finding.job_id,
        )
        .where(Finding.analyst_status == "confirmed")
        .order_by(Finding.job_id, Finding.finding_id)
    ).all()
    counts = {
        "discovered": len(rows),
        "indexed": 0,
        "skipped": 0,
        "failed": 0,
    }
    if client is None:
        counts["failed"] = counts["discovered"]
        return counts

    documents: list[dict[str, Any]] = []
    for finding, project_id in rows:
        try:
            documents.append(
                mnemos_document_for_finding(finding, project_id=project_id)
            )
        except Exception:
            counts["skipped"] += 1

    bounded_batch_size = max(1, batch_size)
    for start in range(0, len(documents), bounded_batch_size):
        batch = documents[start:start + bounded_batch_size]
        try:
            indexed = client.index(batch)
        except Exception:
            indexed = None
        if indexed is None:
            counts["failed"] += len(batch)
        elif indexed == len(batch):
            counts["indexed"] += indexed
        elif isinstance(indexed, int) and 0 <= indexed < len(batch):
            counts["indexed"] += indexed
            counts["failed"] += len(batch) - indexed
        else:
            counts["failed"] += len(batch)
    return counts


def cmd_reconcile_mnemos_findings(args) -> int:
    """Reconcile confirmed database findings to stable MNEMOS documents."""
    from backend.app.database_v2 import get_session_factory
    from backend.app.mnemos_boundary import get_mnemos_client

    try:
        client = get_mnemos_client()
    except Exception:
        client = None
    with get_session_factory()() as db:
        counts = reconcile_mnemos_findings(db, client=client)
    print(
        f"discovered={counts['discovered']} indexed={counts['indexed']} "
        f"skipped={counts['skipped']} failed={counts['failed']}"
    )
    return 1 if client is None or counts["failed"] else 0


def main():
    parser = argparse.ArgumentParser(prog="aipam-admin", description="AIPAM V2 Admin CLI")
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # smoke-test
    p_smoke = sub.add_parser("smoke-test", help="Run E2E smoke test")
    p_smoke.add_argument("--pcap", help="Path to PCAP file (default: first golden PCAP)")
    p_smoke.add_argument("--base-url", default=DEFAULT_BASE_URL, help="API base URL")

    # parity-check
    p_parity = sub.add_parser("parity-check", help="Run V1/V2 parity check")
    p_parity.add_argument("--pcaps", help="Directory containing PCAPs")
    p_parity.add_argument("--output", help="Output directory for reports (default: parity_output/)")

    # cleanup-jobs (§18)
    p_cleanup = sub.add_parser("cleanup-jobs", help="Delete expired jobs (§18)")
    p_cleanup.add_argument(
        "--older-than", default="30d",
        help="Retention period, e.g. '30d' or '14d' (default: 30d)",
    )
    p_cleanup.add_argument("--dry-run", action="store_true", help="List jobs without deleting")
    p_cleanup.add_argument("--confirm", action="store_true", help="Actually delete expired jobs")

    # support-bundle (§22)
    p_bundle = sub.add_parser("support-bundle", help="Generate support bundle (§22)")
    p_bundle.add_argument("--job", help="Specific job ID to include")
    p_bundle.add_argument("--all-recent", action="store_true", help="Include all jobs from last 24h")
    p_bundle.add_argument("--output", help="Output path for tar.gz")

    # apply-update (§13)
    p_update = sub.add_parser("apply-update", help="Apply offline update bundle (§13)")
    p_update.add_argument("zip_path", help="Path to update ZIP bundle")

    # perf-gate (§8.6)
    p_perf = sub.add_parser("perf-gate", help="Check job runtimes against SLOs (§8.6)")
    p_perf.add_argument(
        "--job-root", default=os.environ.get("AIPAM_JOB_ROOT", "/data/jobs"),
        help="Root directory for job data",
    )

    # benchmark (§14.10)
    p_bench = sub.add_parser("benchmark", help="Run benchmark evaluation (§14.10)")
    p_bench.add_argument("--manifest", help="Path to benchmark manifest JSON (default: benchmark/manifests/benchmark_manifest.json)")
    p_bench.add_argument("--model", default="aipam-trafficllm-v5", help="Ollama model name")
    p_bench.add_argument("--endpoint", default="http://localhost:11434/v1/chat/completions", help="LLM endpoint URL")
    p_bench.add_argument("--output", help="Output directory for reports (default: benchmark/benchmark_results/)")
    p_bench.add_argument("--limit", type=int, default=0, help="Limit number of samples (0 = all)")
    p_bench.add_argument("--set", dest="set", help="Filter by set (benchmark, leakage, etc)")
    p_bench.add_argument("--baseline", help="Path to baseline JSON for regression comparison")

    sub.add_parser(
        "reconcile-mnemos-findings",
        help="Reconcile confirmed findings into MNEMOS",
    )

    args = parser.parse_args()

    if args.command == "smoke-test":
        cmd_smoke_test(args)
    elif args.command == "parity-check":
        cmd_parity_check(args)
    elif args.command == "cleanup-jobs":
        cmd_cleanup_jobs(args)
    elif args.command == "support-bundle":
        cmd_support_bundle(args)
    elif args.command == "apply-update":
        cmd_apply_update(args)
    elif args.command == "perf-gate":
        cmd_perf_gate(args)
    elif args.command == "benchmark":
        cmd_benchmark(args)
    elif args.command == "reconcile-mnemos-findings":
        exit_code = cmd_reconcile_mnemos_findings(args)
        if exit_code:
            sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
