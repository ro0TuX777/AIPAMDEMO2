import hashlib
import json
import multiprocessing
import sqlite3
from types import SimpleNamespace
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from backend.app.schema_bootstrap import (
    UnsupportedLegacySchema,
    inspect_schema_profile,
    adopt_legacy_database,
    assert_schema_current,
    MigrationInProgress,
    schema_lock,
    restore_database_backup,
)
from backend.app.schema_bootstrap import (
    SchemaBootstrapError,
    _backup,
    _database_content_sha256,
    _is_original_source,
    _table_row_counts,
    _recover_prepared_receipts,
)


FIXTURES = Path(__file__).parent / "fixtures" / "schema"
REPO_ROOT = Path(__file__).resolve().parents[3]


def _copy_fixture(tmp_path, name):
    path = tmp_path / "aipam.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    try:
        db.executescript((FIXTURES / name).read_text(encoding="utf-8"))
    finally:
        db.close()
    return path


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_empty_database_profile_is_explicit(tmp_path):
    path = tmp_path / "empty.db"
    path.touch()
    assert inspect_schema_profile(path).profile_id == "fresh-empty-v1"


def test_unrecognized_schema_fails_without_modifying_source(tmp_path):
    path = tmp_path / "unknown.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE user_data (id INTEGER PRIMARY KEY, value TEXT)")
    before = _sha(path)
    with pytest.raises(UnsupportedLegacySchema):
        adopt_legacy_database(path)
    assert _sha(path) == before


@pytest.mark.parametrize("revision", ["", "future-revision-not-in-this-image"])
def test_empty_or_ahead_alembic_revision_refuses_without_modifying_source(tmp_path, revision):
    path = tmp_path / "unsupported-version.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        if revision:
            db.execute("INSERT INTO alembic_version VALUES (?)", (revision,))
    before = _sha(path)
    with pytest.raises(UnsupportedLegacySchema):
        adopt_legacy_database(path)
    assert _sha(path) == before


def test_populated_partial_chat_schema_refuses_without_modifying_source(tmp_path):
    path = _copy_fixture(tmp_path, "legacy_partial_chat_populated.sql")
    before = _sha(path)
    with pytest.raises(UnsupportedLegacySchema):
        adopt_legacy_database(path)
    assert _sha(path) == before


@pytest.mark.parametrize("status", ["queued", "running", "canceling", "deleting"])
def test_active_jobs_refuse_adoption_without_modifying_source(tmp_path, status):
    path = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO jobs (job_id, status, execution_profile, priority, source_type, created_at) VALUES ('active', ?, 'standard', 'normal', 'pcap', '2026-01-01')", (status,))
    before = _sha(path)
    with pytest.raises(UnsupportedLegacySchema, match="active jobs"):
        adopt_legacy_database(path)
    assert _sha(path) == before


def test_backup_failure_refuses_without_modifying_source(tmp_path, monkeypatch):
    path = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    before = _sha(path)

    def fail_backup(*_args, **_kwargs):
        raise OSError("injected backup failure")

    monkeypatch.setattr("backend.app.schema_bootstrap._backup", fail_backup)
    with pytest.raises(OSError, match="injected backup failure"):
        adopt_legacy_database(path)
    assert _sha(path) == before


def test_insufficient_disk_space_refuses_without_modifying_source(tmp_path, monkeypatch):
    path = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    before = _sha(path)
    monkeypatch.setattr("backend.app.schema_bootstrap.shutil.disk_usage", lambda _path: SimpleNamespace(free=0))
    with pytest.raises(SchemaBootstrapError, match="insufficient free disk space"):
        adopt_legacy_database(path)
    assert _sha(path) == before


def test_partial_chat_drift_is_not_accepted(tmp_path):
    path = _copy_fixture(tmp_path, "legacy_partial_chat_empty.sql")
    with sqlite3.connect(path) as db:
        db.execute("DROP INDEX idx_chat_comparison_group_job")
    with pytest.raises(UnsupportedLegacySchema):
        inspect_schema_profile(path)


def test_named_view_drift_is_not_accepted(tmp_path):
    path = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    with sqlite3.connect(path) as db:
        db.execute("CREATE VIEW unexpected_view AS SELECT job_id FROM jobs")
    with pytest.raises(UnsupportedLegacySchema):
        inspect_schema_profile(path)


def test_foreign_key_drift_is_not_accepted(tmp_path):
    path = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA foreign_keys=OFF")
        db.executescript("""
            CREATE TABLE chat_conversations_new (
                id VARCHAR NOT NULL PRIMARY KEY, job_id VARCHAR NOT NULL, title TEXT,
                created_at VARCHAR NOT NULL, updated_at VARCHAR NOT NULL
            );
            INSERT INTO chat_conversations_new SELECT id, job_id, title, created_at, updated_at FROM chat_conversations;
            DROP TABLE chat_conversations;
            ALTER TABLE chat_conversations_new RENAME TO chat_conversations;
            CREATE INDEX idx_chat_conv_job ON chat_conversations (job_id);
        """)
    with pytest.raises(UnsupportedLegacySchema):
        inspect_schema_profile(path)


@pytest.mark.parametrize("drift", ["column", "trigger"])
def test_semantic_schema_drift_is_not_accepted(tmp_path, drift):
    path = _copy_fixture(tmp_path, "legacy_partial_chat_empty.sql")
    with sqlite3.connect(path) as db:
        if drift == "column":
            db.execute("ALTER TABLE chat_messages ADD COLUMN unexpected TEXT")
        else:
            db.execute("DROP TRIGGER chat_comparison_branch_provenance_immutable")
    with pytest.raises(UnsupportedLegacySchema):
        inspect_schema_profile(path)


def test_reviewed_precomparison_fixture_is_allowlisted(tmp_path):
    path = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    profile = inspect_schema_profile(path)
    assert profile.profile_id == "legacy-unversioned-precomparison-v1"
    assert profile.fingerprint == "11eff09f2da25a1e9f838eaa8075c50af068b6df0ea2648b4c2f2aef848e45e1"


def test_reviewed_partial_comparison_fixture_has_exact_canonical_fingerprint(tmp_path):
    path = _copy_fixture(tmp_path, "legacy_partial_chat_empty.sql")
    profile = inspect_schema_profile(path)
    assert profile.profile_id == "legacy-unversioned-partial-comparison-v1"
    assert profile.fingerprint == "d4858a0eda25c179786d1ac38b8616e8cf2e546e9242456286f7d04208fb9a2d"


def test_empty_partial_chat_fixture_migrates_from_verified_backup(tmp_path):
    path = _copy_fixture(tmp_path, "legacy_partial_chat_empty.sql")
    db = sqlite3.connect(path)
    try:
        db.execute("INSERT INTO jobs (job_id, status, execution_profile, priority, source_type, created_at) VALUES ('j1', 'completed', 'standard', 'normal', 'pcap', '2026-01-01')")
        db.execute("INSERT INTO chat_conversations (id, job_id, title, created_at, updated_at) VALUES ('c1', 'j1', 'MNEMOS baseline', '2026-01-01', '2026-01-01')")
        db.execute("INSERT INTO chat_messages (id, conversation_id, role, content, created_at) VALUES ('m1', 'c1', 'assistant', 'preserve this answer', '2026-01-01')")
        db.commit()
    finally:
        db.close()
    receipt = adopt_legacy_database(path)
    assert receipt["status"] == "committed"
    assert receipt["profile_id"] == "legacy-unversioned-partial-comparison-v1"
    assert_schema_current(path)
    assert Path(receipt["backup"]).is_file()
    assert _sha(Path(receipt["backup"])) == receipt["backup_sha256"]
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM chat_comparison_groups").fetchone()[0] == 1
        assert db.execute("SELECT mode FROM chat_conversations WHERE id='c1'").fetchone() == ("baseline",)
        assert db.execute("SELECT content FROM chat_messages WHERE id='m1'").fetchone() == ("preserve this answer",)


def test_fresh_database_runs_migrations_and_writes_receipt(tmp_path):
    path = tmp_path / "fresh.db"
    path.touch()
    receipt = adopt_legacy_database(path)
    assert receipt["status"] == "committed"
    assert_schema_current(path)


def test_restore_backup_dry_run_then_atomic_restore(tmp_path):
    path = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    migration = adopt_legacy_database(path)
    migrated_sha = _sha(path)
    receipt_path = Path(path.parent) / "schema-receipts" / f"{migration['operation_id']}.json"
    result = restore_database_backup(path, migration["backup"], receipt_path)
    assert result["status"] == "dry-run-passed"
    assert _sha(path) == migrated_sha
    restored = restore_database_backup(path, migration["backup"], receipt_path, commit=True)
    assert restored["status"] == "restored"
    assert inspect_schema_profile(path).profile_id == "legacy-unversioned-precomparison-v1"
    assert Path(restored["current_backup"]).is_file()
    assert _sha(Path(restored["current_backup"])) == restored["current_backup_sha256"]


def test_restore_receipt_cannot_be_replayed_against_another_database_path(tmp_path):
    original = _copy_fixture(tmp_path / "original", "legacy_unversioned.sql")
    migration = adopt_legacy_database(original)
    receipt_path = Path(original.parent) / "schema-receipts" / f"{migration['operation_id']}.json"
    other = _copy_fixture(tmp_path / "other", "legacy_unversioned.sql")
    with pytest.raises(SchemaBootstrapError, match="different database path"):
        restore_database_backup(other, migration["backup"], receipt_path)


def test_current_schema_component_detects_compatibility_table_drift(tmp_path):
    path = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    adopt_legacy_database(path)
    assert_schema_current(path)
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE settingsdb ADD COLUMN unexpected TEXT")
    with pytest.raises(SchemaBootstrapError, match="compatibility schema differs"):
        assert_schema_current(path)
    before = _sha(path)
    with pytest.raises(SchemaBootstrapError, match="compatibility schema differs"):
        adopt_legacy_database(path)
    assert _sha(path) == before


def test_recovery_requires_logical_content_match_not_only_row_counts(tmp_path):
    path = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    before = inspect_schema_profile(path)
    payload = {
        "profile_id": before.profile_id,
        "source_profile_id": before.profile_id,
        "source_fingerprint": before.fingerprint,
        "source_row_counts": _table_row_counts(path),
        "source_content_sha256": _database_content_sha256(path),
    }
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO settingsdb (id, \"values\") VALUES (1, 'changed')")
    assert not _is_original_source(path, payload)


def test_recovery_quarantines_candidate_after_checkpoint_changed_file_layout(tmp_path):
    path = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    profile = inspect_schema_profile(path)
    original_sha = _sha(path)
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO settingsdb (id, \"values\") VALUES (9876, 'temporary')")
        db.execute("DELETE FROM settingsdb WHERE id=9876")
    assert _sha(path) != original_sha
    operation = "prepared-before-replace"
    receipt_dir = tmp_path / "schema-receipts"
    receipt_dir.mkdir()
    candidate = tmp_path / ".candidate"
    candidate.write_bytes(b"not installed")
    receipt_path = receipt_dir / f"{operation}.json"
    receipt_path.write_text(json.dumps({
        "status": "prepared", "source": str(path.resolve()), "candidate": str(candidate),
        "candidate_sha256": "0" * 64, "source_sha256": original_sha,
        "profile_id": profile.profile_id, "source_profile_id": profile.profile_id,
        "source_fingerprint": profile.fingerprint,
        "source_row_counts": _table_row_counts(path),
        "source_content_sha256": _database_content_sha256(path),
    }), encoding="utf-8")
    _recover_prepared_receipts(path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "abandoned-before-replacement"
    assert Path(receipt["quarantined_candidate"]).is_file()


def test_recovery_commits_receipt_after_candidate_replacement(tmp_path):
    path = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    migration = adopt_legacy_database(path)
    receipt_path = tmp_path / "schema-receipts" / f"{migration['operation_id']}.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["status"] = "prepared"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    _recover_prepared_receipts(path)
    recovered = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert recovered["status"] == "committed"


@pytest.mark.parametrize("revision", ["d4e5f6a7b8c9", "c7d4f6a1e2b3", "e2a9f4b71d83"])
def test_known_ancestor_or_branch_migrates_on_candidate(tmp_path, revision):
    path = tmp_path / "ancestor.db"
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "backend" / "alembic"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{path.as_posix()}")
    command.upgrade(config, revision)
    before = _sha(path)
    receipt = adopt_legacy_database(path)
    assert receipt["status"] == "committed"
    assert receipt["profile_id"].startswith(f"alembic:{revision}")
    assert receipt["source_sha256"] == before
    with sqlite3.connect(receipt["backup"]) as db:
        assert db.execute("PRAGMA quick_check").fetchone() == ("ok",)
    assert_schema_current(path)


def test_known_two_head_branch_state_migrates_on_candidate(tmp_path):
    path = tmp_path / "two-heads.db"
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "backend" / "alembic"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{path.as_posix()}")
    command.upgrade(config, "c7d4f6a1e2b3")
    command.upgrade(config, "e2a9f4b71d83")
    before = _sha(path)
    profile = inspect_schema_profile(path)
    assert set(profile.revisions) == {"c7d4f6a1e2b3", "e2a9f4b71d83"}
    receipt = adopt_legacy_database(path)
    assert receipt["status"] == "committed"
    assert receipt["source_sha256"] == before
    assert_schema_current(path)


def test_alembic_failure_keeps_source_bytes_unchanged(tmp_path, monkeypatch):
    path = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    before = _sha(path)

    def fail_upgrade(*_args, **_kwargs):
        raise RuntimeError("injected migration failure")

    monkeypatch.setattr("backend.app.schema_bootstrap.command.upgrade", fail_upgrade)
    with pytest.raises(RuntimeError, match="injected migration failure"):
        adopt_legacy_database(path)
    assert _sha(path) == before


def test_candidate_validation_failure_keeps_source_bytes_unchanged(tmp_path, monkeypatch):
    path = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    before = _sha(path)

    def fail_validation(*_args, **_kwargs):
        raise SchemaBootstrapError("injected candidate validation failure")

    monkeypatch.setattr("backend.app.schema_bootstrap._create_v1_compatibility_tables", fail_validation)
    with pytest.raises(SchemaBootstrapError, match="injected candidate validation failure"):
        adopt_legacy_database(path)
    assert _sha(path) == before


def _lock_holder(path, acquired, release):
    with schema_lock(path, exclusive=True):
        acquired.set()
        release.wait(10)


def test_lock_is_process_owned_and_stale_file_does_not_block_reacquisition(tmp_path):
    path = tmp_path / "locked.db"
    context = multiprocessing.get_context("spawn")
    acquired = context.Event()
    release = context.Event()
    process = context.Process(
        target=_lock_holder, args=(str(path), acquired, release)
    )
    process.start()
    assert acquired.wait(10)
    with pytest.raises(MigrationInProgress):
        with schema_lock(path, exclusive=True, timeout=0.1):
            pass
    process.terminate()
    process.join(10)
    assert process.exitcode is not None
    # The lock metadata intentionally remains; the OS descriptor owns the lock.
    with schema_lock(path, exclusive=True, timeout=1):
        pass


def test_backup_api_includes_committed_wal_contents(tmp_path):
    source = _copy_fixture(tmp_path, "legacy_unversioned.sql")
    backup = tmp_path / "backup.db"
    writer = sqlite3.connect(source)
    assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
    writer.execute("INSERT INTO settingsdb (id, \"values\") VALUES (1, '{}')")
    writer.commit()
    assert Path(str(source) + "-wal").exists()
    _backup(source, backup)
    with sqlite3.connect(backup) as db:
        assert db.execute("SELECT count(*) FROM settingsdb").fetchone()[0] == 1
    writer.close()
