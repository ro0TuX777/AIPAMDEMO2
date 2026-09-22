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
    """Build the tables this migration owns and mark the DB at its parent.

    Earlier repository migrations include a historical dependency gap for an
    unrelated temporal-correlations table, so this regression fixture starts
    at the declared parent revision instead of retesting that old chain.
    """
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            PRAGMA foreign_keys = ON;
            CREATE TABLE alembic_version (
                version_num VARCHAR(32) NOT NULL PRIMARY KEY
            );
            INSERT INTO alembic_version (version_num) VALUES ('d4e5f6a7b8c9');
            CREATE TABLE jobs (
                job_id VARCHAR NOT NULL PRIMARY KEY,
                status VARCHAR NOT NULL,
                execution_profile VARCHAR NOT NULL,
                priority VARCHAR NOT NULL,
                created_at VARCHAR NOT NULL
            );
            CREATE TABLE chat_conversations (
                id VARCHAR NOT NULL PRIMARY KEY,
                job_id VARCHAR NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
                title TEXT,
                created_at VARCHAR NOT NULL,
                updated_at VARCHAR NOT NULL
            );
            CREATE INDEX idx_chat_conv_job ON chat_conversations(job_id);
            CREATE TABLE chat_messages (
                id VARCHAR NOT NULL PRIMARY KEY,
                conversation_id VARCHAR NOT NULL
                    REFERENCES chat_conversations(id) ON DELETE CASCADE,
                role VARCHAR NOT NULL,
                content TEXT NOT NULL,
                citations_json TEXT,
                created_at VARCHAR NOT NULL
            );
            CREATE INDEX idx_chat_msg_conv ON chat_messages(conversation_id);
            """
        )
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
