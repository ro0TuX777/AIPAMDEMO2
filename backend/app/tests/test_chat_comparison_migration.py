from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


REPO_ROOT = Path(__file__).resolve().parents[3]
BASE_REVISION = "d4e5f6a7b8c9"
COMPARISON_REVISION = "6f3a2b9c1d4e"


def _config(database_path: Path) -> Config:
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "backend" / "alembic"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")
    return config


def _create_legacy_schema(database_path: Path) -> None:
    """Create the real declared predecessor, including non-chat tables."""
    command.upgrade(_config(database_path), BASE_REVISION)
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO jobs (
                job_id, status, execution_profile, priority, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            ("job-legacy", "completed", "standard", "normal", "2026-09-22T00:00:00Z"),
        )
        connection.execute(
            """
            INSERT INTO chat_conversations (id, job_id, title, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "legacy-1",
                "job-legacy",
                "Legacy title",
                "2026-09-22T01:00:00Z",
                "2026-09-22T01:00:02Z",
            ),
        )
        connection.executemany(
            """
            INSERT INTO chat_messages (
                id, conversation_id, role, content, citations_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "z-message",
                    "legacy-1",
                    "assistant",
                    "second",
                    None,
                    "2026-09-22T01:00:01Z",
                ),
                (
                    "b-message",
                    "legacy-1",
                    "user",
                    "first by id tie-break",
                    None,
                    "2026-09-22T01:00:00Z",
                ),
                (
                    "a-message",
                    "legacy-1",
                    "user",
                    "first by timestamp and id",
                    None,
                    "2026-09-22T01:00:00Z",
                ),
            ],
        )


def _populate_copy(database_path):
    with sqlite3.connect(database_path) as db:
        db.execute("INSERT INTO chat_conversations (id, job_id, comparison_group_id, mode, parent_branch_id, source_message_id, history_cutoff_sequence, created_at, updated_at) VALUES ('copy', 'job-legacy', 'group:legacy-1', 'mnemos', 'legacy-1', 'b-message', 1, '2026-09-22', '2026-09-22')")
        db.execute("INSERT INTO chat_comparison_branches (id, group_id, conversation_id, label, source_message_id, history_cutoff_sequence, created_at, updated_at) VALUES ('branch', 'group:legacy-1', 'copy', 'Copy', 'b-message', 1, '2026-09-22', '2026-09-22')")
        db.execute("INSERT INTO chat_messages (id, conversation_id, sequence, role, content, created_at) VALUES ('historical-answer', 'copy', 1, 'assistant', 'Historical comparison: sensitive historical appendix', '2026-09-22')")


def test_migrated_whole_job_delete_preserves_provenance_until_group_removed(tmp_path, monkeypatch):
    monkeypatch.delenv("AIPAM_DB_PATH", raising=False)
    path = tmp_path / "delete.db"
    _create_legacy_schema(path)
    command.upgrade(_config(path), COMPARISON_REVISION)
    _populate_copy(path)
    command.upgrade(_config(path), "head")
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("DELETE FROM chat_messages WHERE id='b-message'")
            db.commit()
        db.rollback()
        assert db.execute("SELECT source_message_id FROM chat_conversations WHERE id='copy'").fetchone() == ("b-message",)
        db.execute("DELETE FROM jobs WHERE job_id='job-legacy'")
        db.commit()
        for table in ("chat_messages", "chat_conversations", "chat_comparison_groups", "chat_comparison_branches"):
            assert db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_populated_downgrade_reupgrade_never_reclassifies_mnemos_as_baseline(tmp_path, monkeypatch):
    monkeypatch.delenv("AIPAM_DB_PATH", raising=False)
    path = tmp_path / "rollback.db"
    _create_legacy_schema(path)
    command.upgrade(_config(path), "head")
    _populate_copy(path)
    command.downgrade(_config(path), BASE_REVISION)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT id FROM chat_conversations").fetchall() == [("legacy-1",)]
        assert db.execute("SELECT content FROM chat_messages WHERE id='historical-answer'").fetchall() == []
        assert db.execute("SELECT content FROM chat_messages WHERE id='z-message'").fetchone() == ("second",)
    command.upgrade(_config(path), "head")
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT id, mode FROM chat_conversations").fetchall() == [("legacy-1", "baseline")]


@pytest.mark.parametrize("fail_commit", [False, True])
def test_retention_on_migrated_copy_commits_before_removing_files(tmp_path, monkeypatch, fail_commit):
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import Session
    from backend.app.database_v2 import _set_sqlite_pragmas
    from backend.app.models.job import Job
    from backend.app.config_v2 import Settings
    from backend.app.services.cleanup import cleanup_old_jobs
    monkeypatch.delenv("AIPAM_DB_PATH", raising=False)
    path = tmp_path / "retention.db"
    _create_legacy_schema(path)
    command.upgrade(_config(path), COMPARISON_REVISION)
    _populate_copy(path)
    command.upgrade(_config(path), "head")
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    event.listen(engine, "connect", _set_sqlite_pragmas)
    with engine.begin() as connection:
        existing = {row[1] for row in connection.exec_driver_sql("PRAGMA table_info(jobs)")}
        for column in Job.__table__.columns:
            if column.name not in existing:
                connection.exec_driver_sql(f"ALTER TABLE jobs ADD COLUMN {column.name} {column.type.compile(dialect=engine.dialect)}")
        connection.exec_driver_sql("UPDATE jobs SET created_at='2000-01-01T00:00:00Z'")
    folder = tmp_path / "job-legacy"
    folder.mkdir()
    (folder / "evidence.txt").write_text("retain until database commit")
    with Session(engine) as db:
        if fail_commit:
            def fail(): raise RuntimeError("commit failed")
            monkeypatch.setattr(db, "commit", fail)
            with pytest.raises(RuntimeError): cleanup_old_jobs(db, Settings(aipam_api_token="test", aipam_job_root=tmp_path, aipam_job_retention_days=1))
            assert (folder / "evidence.txt").exists()
        else:
            assert cleanup_old_jobs(db, Settings(aipam_api_token="test", aipam_job_root=tmp_path, aipam_job_retention_days=1)) == 1
            assert not folder.exists()
            assert db.get(Job, "job-legacy") is None
    engine.dispose()


def test_upgrade_backfills_a_legacy_conversation_as_a_baseline_group(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.delenv("AIPAM_DB_PATH", raising=False)
    database_path = tmp_path / "legacy.db"
    config = _config(database_path)
    _create_legacy_schema(database_path)

    command.upgrade(config, COMPARISON_REVISION)

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        group = connection.execute(
            "SELECT * FROM chat_comparison_groups WHERE root_conversation_id = ?",
            ("legacy-1",),
        ).fetchone()
        conversation = connection.execute(
            "SELECT * FROM chat_conversations WHERE id = ?",
            ("legacy-1",),
        ).fetchone()
        messages = connection.execute(
            """
            SELECT id, sequence FROM chat_messages
            WHERE conversation_id = ? ORDER BY sequence
            """,
            ("legacy-1",),
        ).fetchall()

    assert group is not None
    assert group["job_id"] == "job-legacy"
    assert group["title"] == "Legacy title"
    assert conversation["mode"] == "baseline"
    assert conversation["comparison_group_id"] == group["id"]
    assert [(row["id"], row["sequence"]) for row in messages] == [
        ("a-message", 1),
        ("b-message", 2),
        ("z-message", 3),
    ]


def test_migration_enforces_immutable_mode_and_has_reversible_schema(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.delenv("AIPAM_DB_PATH", raising=False)
    database_path = tmp_path / "roundtrip.db"
    config = _config(database_path)
    _create_legacy_schema(database_path)
    command.upgrade(config, COMPARISON_REVISION)

    with sqlite3.connect(database_path) as connection:
        try:
            connection.execute(
                "UPDATE chat_conversations SET mode = 'mnemos' WHERE id = 'legacy-1'"
            )
        except sqlite3.IntegrityError as exc:
            assert "immutable" in str(exc)
        else:
            raise AssertionError("conversation mode update unexpectedly succeeded")

        group_id = connection.execute(
            """
            SELECT id FROM chat_comparison_groups
            WHERE root_conversation_id = 'legacy-1'
            """
        ).fetchone()[0]
        connection.execute(
            """
            INSERT INTO chat_conversations (
                id, job_id, comparison_group_id, mode, parent_branch_id,
                history_cutoff_sequence, created_at, updated_at
            ) VALUES (
                'mnemos-1', 'job-legacy', ?, 'mnemos', 'legacy-1',
                0, '2026-09-22', '2026-09-22'
            )
            """,
            (group_id,),
        )
        connection.execute(
            """
            INSERT INTO chat_comparison_branches (
                id, group_id, conversation_id, label,
                history_cutoff_sequence, created_at, updated_at
            ) VALUES (
                'branch-1', ?, 'mnemos-1', 'Snapshot',
                0, '2026-09-22', '2026-09-22'
            )
            """,
            (group_id,),
        )
        with pytest.raises(sqlite3.IntegrityError, match="branch provenance is immutable"):
            connection.execute(
                """
                UPDATE chat_comparison_branches
                SET history_cutoff_sequence = 3
                WHERE id = 'branch-1'
                """
            )

    command.downgrade(config, BASE_REVISION)

    with sqlite3.connect(database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        conversation_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(chat_conversations)")
        }
        message_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(chat_messages)")
        }
        legacy_title = connection.execute(
            "SELECT title FROM chat_conversations WHERE id = 'legacy-1'"
        ).fetchone()[0]

    assert "chat_comparison_groups" not in tables
    assert "chat_comparison_branches" not in tables
    assert "mode" not in conversation_columns
    assert "sequence" not in message_columns
    assert legacy_title == "Legacy title"


def test_migration_allows_initial_group_binding_then_freezes_provenance(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.delenv("AIPAM_DB_PATH", raising=False)
    database_path = tmp_path / "immutable.db"
    config = _config(database_path)
    _create_legacy_schema(database_path)
    command.upgrade(config, COMPARISON_REVISION)

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO jobs (
                job_id, status, execution_profile, priority, created_at
            ) VALUES ('job-new', 'completed', 'standard', 'normal', '2026-09-22')
            """
        )
        connection.execute(
            """
            INSERT INTO chat_conversations (
                id, job_id, mode, created_at, updated_at
            ) VALUES ('root-new', 'job-new', 'baseline', '2026-09-22', '2026-09-22')
            """
        )
        connection.execute(
            """
            INSERT INTO chat_comparison_groups (
                id, job_id, root_conversation_id, created_at, updated_at
            ) VALUES ('group-new', 'job-new', 'root-new', '2026-09-22', '2026-09-22')
            """
        )

        connection.execute(
            """
            UPDATE chat_conversations
            SET comparison_group_id = 'group-new'
            WHERE id = 'root-new'
            """
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                """
                UPDATE chat_conversations
                SET comparison_group_id = NULL
                WHERE id = 'root-new'
                """
            )
