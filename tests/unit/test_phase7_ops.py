"""Phase 7 tests — Ops Tooling (§14.9).

Tests:
  - cleanup-jobs: dry-run, live deletion, recent job safety
  - support-bundle: contents, exclusions
  - apply-update: integrity verification, checksum mismatch rejection
"""

import hashlib
import json
import os
import tarfile
import tempfile
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

os.environ.setdefault("AIPAM_API_TOKEN", "test-token-v2")

from backend.app.database_v2 import Base, _set_sqlite_pragmas
from backend.app.models.job import Job
from backend.app.models.sensor import JobSensor
from backend.app.models.finding import Finding


def _uuid():
    return str(uuid.uuid4())


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@pytest.fixture()
def cleanup_env(tmp_path):
    """Set up a DB + filesystem with old and recent jobs."""
    db_path = tmp_path / "aipam.db"
    job_root = tmp_path / "jobs"
    job_root.mkdir()

    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)

    now = datetime.now(timezone.utc)
    old_time = _iso(now - timedelta(days=60))
    recent_time = _iso(now - timedelta(hours=1))

    with SessionLocal() as db:
        # Old completed job (should be cleaned)
        old_id = _uuid()
        db.add(Job(
            job_id=old_id, status="completed", execution_profile="standard",
            priority="normal", created_at=old_time, completed_at=old_time,
            pcap_filename="old.pcap", pcap_size_bytes=100,
        ))
        # Old job directory with files
        old_dir = job_root / old_id
        old_dir.mkdir()
        (old_dir / "test.pcap").write_bytes(b"oldpcap")

        # Recent completed job (should NOT be cleaned)
        recent_id = _uuid()
        db.add(Job(
            job_id=recent_id, status="completed", execution_profile="standard",
            priority="normal", created_at=recent_time, completed_at=recent_time,
            pcap_filename="recent.pcap", pcap_size_bytes=200,
        ))
        (job_root / recent_id).mkdir()

        # Running job (should NOT be cleaned even if old)
        running_id = _uuid()
        db.add(Job(
            job_id=running_id, status="running", execution_profile="standard",
            priority="normal", created_at=old_time,
            pcap_filename="running.pcap", pcap_size_bytes=300,
        ))
        db.commit()

    yield {
        "db_path": db_path, "job_root": job_root, "engine": engine,
        "SessionLocal": SessionLocal,
        "old_id": old_id, "recent_id": recent_id, "running_id": running_id,
    }
    engine.dispose()


class TestCleanupJobs:
    """§14.9.1 — Retention policy tests."""

    def test_dry_run_no_deletion(self, cleanup_env):
        """cleanup-jobs --dry-run → no deletion occurs."""
        import argparse
        env = cleanup_env
        with patch.dict(os.environ, {
            "AIPAM_JOB_ROOT": str(env["job_root"]),
            "AIPAM_DB_PATH": str(env["db_path"]),
        }):
            from backend.app.cli import cmd_cleanup_jobs
            args = argparse.Namespace(older_than="30d", dry_run=True, confirm=False)
            cmd_cleanup_jobs(args)

        # Old job should still exist
        with env["SessionLocal"]() as db:
            assert db.query(Job).filter(Job.job_id == env["old_id"]).first() is not None
        assert (env["job_root"] / env["old_id"]).exists()

    def test_confirm_deletes_old_job(self, cleanup_env):
        """cleanup-jobs --older-than 30d --confirm → deletes old job folder + DB rows."""
        import argparse
        env = cleanup_env
        with patch.dict(os.environ, {
            "AIPAM_JOB_ROOT": str(env["job_root"]),
            "AIPAM_DB_PATH": str(env["db_path"]),
        }):
            from backend.app.cli import cmd_cleanup_jobs
            args = argparse.Namespace(older_than="30d", dry_run=False, confirm=True)
            try:
                cmd_cleanup_jobs(args)
            except SystemExit as e:
                assert e.code == 0

        with env["SessionLocal"]() as db:
            # Old completed job deleted
            assert db.query(Job).filter(Job.job_id == env["old_id"]).first() is None
            # Recent job preserved
            assert db.query(Job).filter(Job.job_id == env["recent_id"]).first() is not None
            # Running job preserved (not terminal)
            assert db.query(Job).filter(Job.job_id == env["running_id"]).first() is not None

        # Filesystem cleaned
        assert not (env["job_root"] / env["old_id"]).exists()
        # Recent job dir still there
        assert (env["job_root"] / env["recent_id"]).exists()

    def test_running_jobs_never_deleted(self, cleanup_env):
        """Running jobs are never deleted regardless of age."""
        import argparse
        env = cleanup_env
        with patch.dict(os.environ, {
            "AIPAM_JOB_ROOT": str(env["job_root"]),
            "AIPAM_DB_PATH": str(env["db_path"]),
        }):
            from backend.app.cli import cmd_cleanup_jobs
            args = argparse.Namespace(older_than="1d", dry_run=False, confirm=True)
            try:
                cmd_cleanup_jobs(args)
            except SystemExit:
                pass

        with env["SessionLocal"]() as db:
            assert db.query(Job).filter(Job.job_id == env["running_id"]).first() is not None


class TestSupportBundle:
    """§14.9.2 — Support bundle validation tests."""

    def test_bundle_contains_job_metadata(self, cleanup_env):
        """Bundle includes job metadata JSON for specified job."""
        import argparse
        env = cleanup_env
        with patch.dict(os.environ, {
            "AIPAM_JOB_ROOT": str(env["job_root"]),
            "AIPAM_DB_PATH": str(env["db_path"]),
            "AIPAM_LOG_DIR": str(env["job_root"].parent / "logs"),
        }):
            output = env["job_root"].parent / "test_bundle.tar.gz"
            from backend.app.cli import cmd_support_bundle
            args = argparse.Namespace(job=env["recent_id"], all_recent=False, output=str(output))
            cmd_support_bundle(args)

        assert output.exists()
        with tarfile.open(str(output), "r:gz") as tar:
            names = tar.getnames()
            # Should contain job metadata
            meta_files = [n for n in names if "metadata.json" in n]
            assert len(meta_files) == 1
            # Should contain system health
            health_files = [n for n in names if "health.json" in n]
            assert len(health_files) == 1
            # Should contain config snapshot
            config_files = [n for n in names if "config.json" in n]
            assert len(config_files) == 1

    def test_bundle_excludes_pcap_data(self, cleanup_env):
        """Bundle must NOT contain raw PCAP data."""
        import argparse
        env = cleanup_env
        with patch.dict(os.environ, {
            "AIPAM_JOB_ROOT": str(env["job_root"]),
            "AIPAM_DB_PATH": str(env["db_path"]),
            "AIPAM_LOG_DIR": str(env["job_root"].parent / "logs"),
        }):
            output = env["job_root"].parent / "test_bundle2.tar.gz"
            from backend.app.cli import cmd_support_bundle
            args = argparse.Namespace(job=env["old_id"], all_recent=False, output=str(output))
            cmd_support_bundle(args)

        with tarfile.open(str(output), "r:gz") as tar:
            names = tar.getnames()
            pcap_files = [n for n in names if n.endswith(".pcap") or n.endswith(".pcapng")]
            assert pcap_files == [], f"Bundle should not contain PCAPs: {pcap_files}"

    def test_bundle_excludes_secrets(self, cleanup_env):
        """Bundle config snapshot must NOT contain API tokens."""
        import argparse
        env = cleanup_env
        # Set a fake token to verify it's excluded
        with patch.dict(os.environ, {
            "AIPAM_JOB_ROOT": str(env["job_root"]),
            "AIPAM_DB_PATH": str(env["db_path"]),
            "AIPAM_LOG_DIR": str(env["job_root"].parent / "logs"),
            "AIPAM_API_TOKEN": "super-secret-token-12345",
        }):
            output = env["job_root"].parent / "test_bundle3.tar.gz"
            from backend.app.cli import cmd_support_bundle
            args = argparse.Namespace(job=env["recent_id"], all_recent=False, output=str(output))
            cmd_support_bundle(args)

        with tarfile.open(str(output), "r:gz") as tar:
            # Read all file contents and check for token
            for member in tar.getmembers():
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode(errors="replace")
                    assert "super-secret-token-12345" not in content, \
                        f"Secret token found in {member.name}"


class TestApplyUpdate:
    """§13.1 — Offline update integrity tests."""

    def _make_bundle(self, tmp_path, files_ok=True):
        """Create a test update ZIP with manifest."""
        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir(exist_ok=True)

        # Create test files
        rule_content = b"rule test { condition: true }"
        rule_sha = hashlib.sha256(rule_content).hexdigest()

        ti_content = b'{"iocs": ["evil.com"]}'
        ti_sha = hashlib.sha256(ti_content).hexdigest()

        manifest = {
            "bundle_version": "2026.03.test",
            "files": [
                {"path": "rules/test.yar", "sha256": rule_sha, "type": "yara"},
                {"path": "ti/evil.json", "sha256": ti_sha if files_ok else "bad_hash", "type": "ti"},
            ],
        }

        zip_path = tmp_path / "update.zip"
        with zipfile.ZipFile(str(zip_path), "w") as zf:
            zf.writestr("manifest.json", json.dumps(manifest))
            zf.writestr("rules/test.yar", rule_content)
            zf.writestr("ti/evil.json", ti_content)
        return zip_path

    def test_apply_update_verifies_checksums(self, tmp_path):
        """apply-update verifies SHA256 and succeeds on valid bundle."""
        import argparse
        zip_path = self._make_bundle(tmp_path, files_ok=True)

        # Override paths to use tmp_path
        with patch("backend.app.cli._RULES_YARA", tmp_path / "rules" / "yara"), \
             patch("backend.app.cli._TI_BUNDLES", tmp_path / "ti" / "bundles"), \
             patch("backend.app.cli._RULES_SURICATA", tmp_path / "rules" / "suricata"), \
             patch("backend.app.cli._APPLIED_JSON", tmp_path / "applied.json"), \
             patch("backend.app.cli._BACKUP_ROOT", tmp_path / "backups"), \
             patch("backend.app.cli._UPDATE_LOG", tmp_path / "updates.log"):
            from backend.app.cli import cmd_apply_update
            args = argparse.Namespace(zip_path=str(zip_path))
            cmd_apply_update(args)

        # Verify files were unpacked
        assert (tmp_path / "rules" / "yara" / "test.yar").exists()
        assert (tmp_path / "ti" / "bundles" / "evil.json").exists()

        # Verify applied.json was updated
        applied = json.loads((tmp_path / "applied.json").read_text())
        assert "2026.03.test" in applied

    def test_apply_update_refuses_bad_checksum(self, tmp_path):
        """apply-update refuses to apply if any checksum mismatches (§13.1)."""
        import argparse
        zip_path = self._make_bundle(tmp_path, files_ok=False)

        with patch("backend.app.cli._RULES_YARA", tmp_path / "rules" / "yara"), \
             patch("backend.app.cli._TI_BUNDLES", tmp_path / "ti" / "bundles"), \
             patch("backend.app.cli._RULES_SURICATA", tmp_path / "rules" / "suricata"), \
             patch("backend.app.cli._APPLIED_JSON", tmp_path / "applied.json"), \
             patch("backend.app.cli._BACKUP_ROOT", tmp_path / "backups"), \
             patch("backend.app.cli._UPDATE_LOG", tmp_path / "updates.log"):
            from backend.app.cli import cmd_apply_update
            args = argparse.Namespace(zip_path=str(zip_path))
            with pytest.raises(SystemExit) as exc_info:
                cmd_apply_update(args)
            assert exc_info.value.code == 1

        # Verify files were NOT unpacked
        assert not (tmp_path / "rules" / "yara" / "test.yar").exists()
