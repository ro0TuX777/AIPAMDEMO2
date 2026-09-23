"""File-backed migration tests: no metadata create_all bootstrap on fresh paths."""
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from backend.app.database_v2 import Base
import backend.app.models  # noqa: F401

ROOT = Path(__file__).resolve().parents[3]
PREDECESSOR = "7a4d8e2c9b10"
CONVERGENCE = "7f2c9a4e8b11"
RUNTIME = "8b6f4d2a1c90"
METADATA_ONLY = {
    "context_annotations",
    "incident_slices",
    "job_log_sources",
    "normalized_events",
    "proofs",
    "reports",
    "theories",
    "proof_items",
}
RUNTIME_TABLES = METADATA_ONLY | {
    "jobs",
    "alerts",
    "files",
    "findings",
    "hosts",
    "kb_documents",
    "temporal_correlations",
}
RUNTIME_COLUMNS = {
    "celery_task_id",
    "execution_attempt",
    "run_token",
    "worker_id",
    "worker_container_id",
    "executor_pid",
    "executor_pid_start_ticks",
    "executor_boot_id",
    "heartbeat_at",
    "dispatched_at",
    "cancel_requested_at",
    "cancel_force_at",
    "cancel_deadline_at",
    "cancel_escalation_token",
    "cancel_escalation_started_at",
    "artifact_layout_version",
    "accepted_run_manifest_json",
}


@pytest.fixture
def alembic_db(tmp_path, monkeypatch):
    monkeypatch.delenv("AIPAM_DB_PATH", raising=False)
    path = tmp_path / "migration.db"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "backend/alembic"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{path.as_posix()}")
    engine = sa.create_engine(f"sqlite:///{path.as_posix()}")
    yield config, engine
    engine.dispose()


def assert_metadata_parity(engine):
    inspector = sa.inspect(engine)
    for name in sorted(RUNTIME_TABLES):
        table = Base.metadata.tables[name]
        actual = {c["name"]: c for c in inspector.get_columns(name)}
        assert set(actual) == set(table.c.keys()), name
        for col in table.c:
            assert actual[col.name]["type"]._type_affinity == col.type._type_affinity, (
                name,
                col.name,
            )
            assert actual[col.name]["nullable"] == col.nullable, (name, col.name)
        assert set(inspector.get_pk_constraint(name)["constrained_columns"]) == {
            c.name for c in table.primary_key
        }, name
        assert {
            tuple(c["column_names"]) for c in inspector.get_unique_constraints(name)
        } == {
            tuple(c.name for c in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, sa.UniqueConstraint)
        }, name
        assert {
            (i["name"], tuple(i["column_names"]), bool(i["unique"]))
            for i in inspector.get_indexes(name)
        } == {
            (i.name, tuple(c.name for c in i.columns), i.unique) for i in table.indexes
        }, name
        assert {
            (
                tuple(f["constrained_columns"]),
                f["referred_table"],
                tuple(f["referred_columns"]),
                f["options"].get("ondelete"),
            )
            for f in inspector.get_foreign_keys(name)
        } == {
            (
                tuple(c.name for c in f.columns),
                f.referred_table.name,
                tuple(e.column.name for e in f.elements),
                f.ondelete,
            )
            for f in table.foreign_key_constraints
        }, name


def test_runtime_migration_adds_nullable_ownership_and_manifest_columns(alembic_db):
    config, engine = alembic_db
    command.upgrade(config, "head")
    columns = {c["name"]: c for c in sa.inspect(engine).get_columns("jobs")}
    assert RUNTIME_COLUMNS <= columns.keys()
    assert all(
        columns[c]["nullable"]
        for c in RUNTIME_COLUMNS - {"execution_attempt", "artifact_layout_version"}
    )
    assert str(columns["artifact_layout_version"]["default"]).strip("'\"") == "2"


def test_empty_database_upgrades_to_head_with_runtime_metadata_parity(alembic_db):
    config, engine = alembic_db
    command.upgrade(config, "head")
    assert_metadata_parity(engine)


def test_populated_runtime_roundtrip_preserves_jobs_and_backfills(alembic_db):
    config, engine = alembic_db
    command.upgrade(config, PREDECESSOR)
    assert METADATA_ONLY.isdisjoint(sa.inspect(engine).get_table_names())
    with engine.begin() as db:
        db.exec_driver_sql(
            "INSERT INTO jobs (job_id, job_name, notes, status, execution_profile, priority, created_at, metrics_json) VALUES ('existing', 'Keep me', 'notes', 'completed', 'standard', 'high', '2026-01-01T00:00:00Z', ? )",
            ('{"count":1}',),
        )
        db.exec_driver_sql(
            "INSERT INTO findings (job_id, finding_id, sensor, severity, title) VALUES ('existing', 'f1', 'zeek', 'info', 'Keep finding')"
        )
        db.exec_driver_sql(
            "INSERT INTO hosts (job_id, ip, pcap_label) VALUES ('existing', '10.0.0.1', 'before')"
        )
    command.upgrade(config, CONVERGENCE)
    with engine.begin() as db:
        assert db.exec_driver_sql("SELECT source_type FROM jobs").scalar() == "pcap"
        assert db.exec_driver_sql(
            "SELECT confidence, evidence_status, corroboration_score FROM findings"
        ).one() == (0.0, "observed", 0.0)
        db.exec_driver_sql(
            "INSERT INTO hosts (job_id, ip, pcap_label) VALUES ('existing', '10.0.0.1', 'after')"
        )
    for target in (RUNTIME, CONVERGENCE, RUNTIME):
        (command.downgrade if target == CONVERGENCE else command.upgrade)(
            config, target
        )
        with engine.connect() as db:
            assert db.exec_driver_sql(
                "SELECT job_name, notes, status, priority, metrics_json FROM jobs"
            ).one() == ("Keep me", "notes", "completed", "high", '{"count":1}')
            if target == RUNTIME:
                assert db.exec_driver_sql(
                    "SELECT artifact_layout_version, execution_attempt, run_token FROM jobs"
                ).one() == (1, 0, None)
    assert_metadata_parity(engine)


@pytest.mark.parametrize("profile", ["precomparison", "partial_comparison"])
def test_both_allowlisted_create_all_schemas_converge(alembic_db, profile):
    import sqlite3

    config, engine = alembic_db
    fixture = ROOT / f"backend/app/tests/fixtures/schema/legacy_{profile}_v2.sql"
    with sqlite3.connect(engine.url.database) as connection:
        connection.executescript(fixture.read_text())
        expected_count = 48 if profile == "precomparison" else 50
        assert (
            connection.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table'"
            ).fetchone()[0]
            == expected_count
        )
        if profile == "partial_comparison":
            # Task 10 performs this exact allowlisted normalization on a copy.
            connection.executescript(
                "DROP TRIGGER chat_comparison_branch_provenance_immutable; DROP TABLE chat_comparison_branches; DROP TABLE chat_comparison_groups;"
            )
    command.stamp(config, "d4e5f6a7b8c9")
    command.upgrade(config, "head")
    assert_metadata_parity(engine)


@pytest.mark.parametrize(
    "drift", ["column_default", "extra_index", "foreign_key", "missing_column"]
)
def test_convergence_refuses_unsupported_existing_metadata_table(alembic_db, drift):
    config, engine = alembic_db
    command.upgrade(config, PREDECESSOR)
    table = Base.metadata.tables["job_log_sources"].to_metadata(sa.MetaData())
    # Attach the external target for DDL FK resolution only.
    sa.Table("jobs", table.metadata, sa.Column("job_id", sa.String(), primary_key=True))
    if drift == "column_default":
        table.c.filename.server_default = sa.DefaultClause("unexpected")
    elif drift == "extra_index":
        sa.Index("unknown_runtime_index", table.c.filename)
    elif drift == "foreign_key":
        for constraint in list(table.foreign_key_constraints):
            table.constraints.remove(constraint)
    elif drift == "missing_column":
        table._columns.remove(table.c.filename)
    table.create(engine)
    with pytest.raises(RuntimeError, match="Unsupported"):
        command.upgrade(config, CONVERGENCE)
