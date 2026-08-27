"""Phase 1 tests — bundle staging, manifest building, schema extensions.

Tests cover:
- Bundle extraction (zip / tar.gz)
- Manifest generation with SHA-256 and size tracking
- Path-traversal safety checks
- JobCreateRequest schema with new telemetry fields
- Unsupported archive format rejection
- Full stage_bundle pipeline round-trip
"""

import json
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path


from backend.app.pipeline.bundle_stager import (
    build_manifest,
    extract_bundle,
    stage_bundle,
    _safe_name,
    _sha256_file,
)
from backend.app.schemas.common import SourceType
from backend.app.schemas.job import BundleSourceEntry, JobCreateRequest
from backend.app.schemas.telemetry import SourceManifest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_zip(tmp_path: Path, files: dict[str, str]) -> Path:
    """Create a zip archive with given {name: content} mapping."""
    archive = tmp_path / "test_bundle.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return archive


def _create_tar_gz(tmp_path: Path, files: dict[str, str]) -> Path:
    """Create a tar.gz archive with given {name: content} mapping."""
    archive = tmp_path / "test_bundle.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        for name, content in files.items():
            import io
            data = content.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return archive


# ---------------------------------------------------------------------------
# _safe_name tests
# ---------------------------------------------------------------------------

class TestSafeName:
    def test_strips_parent_traversal(self):
        assert ".." not in _safe_name("../../etc/passwd")

    def test_strips_leading_slash(self):
        result = _safe_name("/etc/shadow")
        assert not result.startswith("/")

    def test_preserves_normal_path(self):
        assert _safe_name("logs/auth.log") == "logs/auth.log"

    def test_empty_parts_fallback(self):
        assert _safe_name("..") == "unnamed"


# ---------------------------------------------------------------------------
# extract_bundle tests
# ---------------------------------------------------------------------------

class TestExtractBundle:
    def test_extract_zip(self, tmp_path):
        archive = _create_zip(tmp_path, {
            "auth.log": "Mar 15 sshd login",
            "subdir/firewall.json": '{"action": "allow"}',
        })
        dest = tmp_path / "extracted"
        files = extract_bundle(archive, dest)
        assert len(files) == 2
        assert (dest / "auth.log").exists()
        assert (dest / "subdir" / "firewall.json").exists()

    def test_extract_tar_gz(self, tmp_path):
        archive = _create_tar_gz(tmp_path, {
            "sysmon.json": '{"EventID": 1}',
            "dns.log": "query example.com",
        })
        dest = tmp_path / "extracted"
        files = extract_bundle(archive, dest)
        assert len(files) == 2
        assert (dest / "sysmon.json").exists()

    def test_non_archive_treated_as_raw_file(self, tmp_path):
        """Non-archive files are copied as raw log files (not rejected)."""
        raw_file = tmp_path / "data.xlsx"
        raw_file.write_text("not an archive")
        dest = tmp_path / "out"
        files = extract_bundle(raw_file, dest)
        assert len(files) == 1
        assert files[0].name == "data.xlsx"
        assert files[0].read_text() == "not an archive"

    def test_path_traversal_blocked(self, tmp_path):
        """Ensure files with ../ in names are safely contained."""
        archive = _create_zip(tmp_path, {
            "../../etc/passwd": "root:x:0:0",
            "normal.log": "safe data",
        })
        dest = tmp_path / "extracted"
        files = extract_bundle(archive, dest)
        # Should extract but not escape dest directory
        for f in files:
            assert str(f).startswith(str(dest))

    def test_empty_zip(self, tmp_path):
        archive = tmp_path / "empty.zip"
        with zipfile.ZipFile(archive, "w"):
            pass
        dest = tmp_path / "extracted"
        files = extract_bundle(archive, dest)
        assert files == []


# ---------------------------------------------------------------------------
# build_manifest tests
# ---------------------------------------------------------------------------

class TestBuildManifest:
    def test_basic_manifest(self, tmp_path):
        # Create some files in a "telemetry" dir
        tel_dir = tmp_path / "telemetry"
        tel_dir.mkdir()
        (tel_dir / "auth.log").write_text("login data")
        (tel_dir / "dns.json").write_text('{"query": "evil.com"}')

        files = list(tel_dir.iterdir())
        manifest = build_manifest(
            job_id="job-test",
            source_type=SourceType.log_bundle,
            extracted_files=files,
            telemetry_dir=tel_dir,
        )
        assert manifest.job_id == "job-test"
        assert len(manifest.entries) == 2
        # All entries should have sha256 and size
        for entry in manifest.entries:
            assert entry.sha256 is not None
            assert entry.size_bytes is not None
            assert entry.source_type == SourceType.log_bundle

    def test_manifest_with_hints(self, tmp_path):
        tel_dir = tmp_path / "telemetry"
        tel_dir.mkdir()
        (tel_dir / "auth.log").write_text("sshd login")

        files = [tel_dir / "auth.log"]
        hints = [{"filename": "auth.log", "source_system": "linux_auth", "parser_hint": "linux_auth"}]
        manifest = build_manifest(
            job_id="job-hint",
            source_type=SourceType.log_bundle,
            extracted_files=files,
            telemetry_dir=tel_dir,
            bundle_entries=hints,
        )
        assert manifest.entries[0].source_system == "linux_auth"
        assert manifest.entries[0].parser_hint == "linux_auth"

    def test_manifest_with_exercise_id(self, tmp_path):
        tel_dir = tmp_path / "telemetry"
        tel_dir.mkdir()
        (tel_dir / "events.json").write_text('[{"id": 1}]')

        files = [tel_dir / "events.json"]
        manifest = build_manifest(
            job_id="job-ex",
            source_type=SourceType.exercise_bundle,
            extracted_files=files,
            telemetry_dir=tel_dir,
            exercise_id="exercise-bravo",
        )
        assert manifest.exercise_id == "exercise-bravo"


# ---------------------------------------------------------------------------
# stage_bundle (full pipeline) tests
# ---------------------------------------------------------------------------

class TestStageBundlePipeline:
    def test_full_stage_zip(self, tmp_path):
        """Full round-trip: zip -> extract -> manifest -> persisted JSON."""
        archive = _create_zip(tmp_path, {
            "windows/security.evtx.json": '[{"EventID": 4624}]',
            "linux/auth.log": "Mar 15 sshd login",
        })
        job_dir = tmp_path / "job-001"
        job_dir.mkdir()
        (job_dir / "input").mkdir()

        manifest = stage_bundle(
            archive_path=archive,
            job_dir=job_dir,
            job_id="job-001",
            source_type=SourceType.log_bundle,
        )
        assert len(manifest.entries) == 2
        assert manifest.job_id == "job-001"

        # Verify manifest was persisted to disk
        manifest_path = job_dir / "source_manifest.json"
        assert manifest_path.exists()
        loaded = json.loads(manifest_path.read_text())
        assert loaded["job_id"] == "job-001"
        assert len(loaded["entries"]) == 2

    def test_full_stage_tar_gz(self, tmp_path):
        archive = _create_tar_gz(tmp_path, {
            "c2/callbacks.json": '[{"agent": "beacon-001"}]',
        })
        job_dir = tmp_path / "job-002"
        job_dir.mkdir()
        (job_dir / "input").mkdir()

        manifest = stage_bundle(
            archive_path=archive,
            job_dir=job_dir,
            job_id="job-002",
            source_type=SourceType.c2_bundle,
            exercise_id="red-team-01",
        )
        assert len(manifest.entries) == 1
        assert manifest.exercise_id == "red-team-01"

    def test_stage_with_bundle_entries(self, tmp_path):
        archive = _create_zip(tmp_path, {
            "auth.log": "sshd data",
        })
        job_dir = tmp_path / "job-003"
        job_dir.mkdir()
        (job_dir / "input").mkdir()

        manifest = stage_bundle(
            archive_path=archive,
            job_dir=job_dir,
            job_id="job-003",
            source_type=SourceType.log_bundle,
            bundle_entries=[{"filename": "auth.log", "source_system": "linux_auth"}],
        )
        assert manifest.entries[0].source_system == "linux_auth"


# ---------------------------------------------------------------------------
# SHA-256 utility tests
# ---------------------------------------------------------------------------

class TestSha256:
    def test_sha256_file(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"hello world")
        h = _sha256_file(f)
        assert len(h) == 64  # hex digest length
        assert h == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"


# ---------------------------------------------------------------------------
# Schema extension tests
# ---------------------------------------------------------------------------

class TestJobCreateRequestSchema:
    def test_default_source_type_is_pcap(self):
        req = JobCreateRequest(
            upload_id="u-001",
            execution_profile="triage",
        )
        assert req.source_type == SourceType.pcap
        assert req.exercise_id is None
        assert req.bundle_entries is None

    def test_bundle_source_type(self):
        req = JobCreateRequest(
            upload_id="u-002",
            execution_profile="standard",
            source_type=SourceType.log_bundle,
            exercise_id="exercise-alpha",
            bundle_entries=[
                BundleSourceEntry(
                    filename="auth.log",
                    source_system="linux_auth",
                    parser_hint="linux_auth",
                ),
            ],
        )
        assert req.source_type == SourceType.log_bundle
        assert req.exercise_id == "exercise-alpha"
        assert len(req.bundle_entries) == 1
        assert req.bundle_entries[0].source_system == "linux_auth"

    def test_c2_bundle_type(self):
        req = JobCreateRequest(
            upload_id="u-003",
            execution_profile="deep",
            source_type=SourceType.c2_bundle,
        )
        assert req.source_type == SourceType.c2_bundle


# ---------------------------------------------------------------------------
# Manifest serialization round-trip
# ---------------------------------------------------------------------------

class TestManifestSerialization:
    def test_manifest_json_roundtrip(self):
        manifest = SourceManifest(
            job_id="job-rt",
            exercise_id="ex-01",
            created_at=datetime(2026, 3, 15, 14, 0, tzinfo=timezone.utc),
            entries=[],
        )
        json_str = manifest.model_dump_json()
        loaded = SourceManifest.model_validate_json(json_str)
        assert loaded.job_id == "job-rt"
        assert loaded.exercise_id == "ex-01"



# ---------------------------------------------------------------------------
# Log upload budget — bounded by bytes, never by file count
# ---------------------------------------------------------------------------

class TestLogUploadLimits:
    def test_many_small_files_are_all_extracted(self, tmp_path):
        """No file-count ceiling: stacking perspectives is the point of log correlation."""
        archive = _create_zip(tmp_path, {f"host{i}/auth.log": f"line {i}" for i in range(6_000)})
        dest = tmp_path / "extracted"
        files = extract_bundle(archive, dest)
        assert len(files) == 6_000

    def test_oversized_archive_still_rejected(self, tmp_path):
        """The byte budget is what bounds a bundle."""
        import pytest
        from backend.app.pipeline import bundle_stager

        archive = _create_zip(tmp_path, {"huge.log": "x" * 1024})
        monkey = bundle_stager.MAX_EXTRACT_BYTES
        bundle_stager.MAX_EXTRACT_BYTES = 100
        try:
            with pytest.raises(ValueError, match="exceeds limit"):
                extract_bundle(archive, tmp_path / "out")
        finally:
            bundle_stager.MAX_EXTRACT_BYTES = monkey

    def test_per_job_log_budget_rejects_oversized_set(self):
        import pytest
        from fastapi import HTTPException

        from backend.app.api.jobs import MAX_LOG_BYTES_PER_JOB, _enforce_log_budget
        from backend.app.models.upload import Upload

        half = MAX_LOG_BYTES_PER_JOB // 2 + 1
        uploads = [
            Upload(upload_id="u1", filename="a.log", size_bytes=half, sha256="x", created_at="t"),
            Upload(upload_id="u2", filename="b.log", size_bytes=half, sha256="y", created_at="t"),
        ]
        with pytest.raises(HTTPException) as exc:
            _enforce_log_budget(uploads)
        assert exc.value.status_code == 400
        assert "no limit on how many log files" in exc.value.detail.lower()

    def test_per_job_log_budget_allows_many_files_under_budget(self):
        from backend.app.api.jobs import _enforce_log_budget
        from backend.app.models.upload import Upload

        uploads = [
            Upload(upload_id=f"u{i}", filename=f"{i}.log", size_bytes=1024,
                   sha256="z", created_at="t")
            for i in range(500)
        ]
        _enforce_log_budget(uploads)   # 500 files, well under budget — no raise
