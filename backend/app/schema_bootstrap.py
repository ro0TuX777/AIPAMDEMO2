"""Fail-closed SQLite schema inspection and crash-safe adoption."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import time
from uuid import uuid4

from alembic import command
from alembic.config import Config

if os.name == "nt":
    import msvcrt
else:
    import fcntl


@contextmanager
def _sqlite_connection(*args, **kwargs):
    connection = sqlite3.connect(*args, **kwargs)
    try:
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


class SchemaBootstrapError(RuntimeError):
    pass


class UnsupportedLegacySchema(SchemaBootstrapError):
    pass


class MigrationInProgress(SchemaBootstrapError):
    pass


class SchemaNotCurrent(SchemaBootstrapError):
    pass


SCHEMA_COMPONENT = "sqlmodel-v1-compat"
SCHEMA_COMPONENT_VERSION = "1"


# These hashes use aipam-schema-fingerprint-v1 over the reviewed frozen SQL
# fixtures. Source commit metadata is retained alongside each signature.
LEGACY_PROFILES = {
    "11eff09f2da25a1e9f838eaa8075c50af068b6df0ea2648b4c2f2aef848e45e1":
        ("legacy-unversioned-precomparison-v1", "f6583ecb4aa439f77296022cec91ed20ac92685b", "d4e5f6a7b8c9"),
    "d4858a0eda25c179786d1ac38b8616e8cf2e546e9242456286f7d04208fb9a2d":
        ("legacy-unversioned-partial-comparison-v1", "26170e2686504edce4d2f91a7ea345084382c3b7", "d4e5f6a7b8c9"),
}


@dataclass(frozen=True)
class SchemaProfile:
    profile_id: str
    fingerprint: str
    revisions: tuple[str, ...] = ()


def _normalized_sql(sql: str | None) -> str | None:
    if sql is None:
        return None
    return re.sub(r"\s+", " ", sql.strip()).rstrip(";")


def _sqlite_type_affinity(declared: str | None) -> str:
    value = (declared or "").upper()
    if "INT" in value:
        return "INTEGER"
    if any(token in value for token in ("CHAR", "CLOB", "TEXT")):
        return "TEXT"
    if "BLOB" in value or not value.strip():
        return "BLOB"
    if any(token in value for token in ("REAL", "FLOA", "DOUB")):
        return "REAL"
    return "NUMERIC"


def _canonical_schema_payload(db: sqlite3.Connection) -> dict:
    tables = []
    table_names = [row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )]
    for table in table_names:
        quoted = '"' + table.replace('"', '""') + '"'
        columns = db.execute(f"PRAGMA table_info({quoted})").fetchall()
        column_payload = [
            {"name": row[1], "type": _sqlite_type_affinity(row[2]), "not_null": bool(row[3]),
             "default": _normalized_sql(str(row[4])) if row[4] is not None else None,
             "primary_key_position": int(row[5])}
            for row in columns
        ]
        table_sql = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        uniques = []
        named_indexes = []
        for index in db.execute(f"PRAGMA index_list({quoted})").fetchall():
            index_name, unique, origin, partial = index[1], bool(index[2]), index[3], bool(index[4]) if len(index) > 4 else False
            index_quoted = '"' + index_name.replace('"', '""') + '"'
            info = db.execute(f"PRAGMA index_info({index_quoted})").fetchall()
            index_columns = [row[2] for row in info]
            if origin == "u":
                uniques.append(sorted(index_columns))
            elif not index_name.startswith("sqlite_autoindex"):
                index_sql = db.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (index_name,)).fetchone()
                sql = index_sql[0] if index_sql else None
                predicate = None
                if sql and re.search(r"\bwhere\b", sql, re.IGNORECASE):
                    predicate = re.split(r"\bwhere\b", sql, maxsplit=1, flags=re.IGNORECASE)[1]
                named_indexes.append({"name": index_name, "unique": unique, "columns": index_columns,
                                      "partial": partial, "predicate": _normalized_sql(predicate),
                                      "definition": _normalized_sql(sql)})
        fk_groups: dict[int, list[tuple]] = {}
        for row in db.execute(f"PRAGMA foreign_key_list({quoted})").fetchall():
            fk_groups.setdefault(row[0], []).append(row)
        foreign_keys = []
        for rows in fk_groups.values():
            rows.sort(key=lambda row: row[1])
            foreign_keys.append({
                "columns": [row[3] for row in rows], "target_table": rows[0][2],
                "target_columns": [row[4] for row in rows], "on_update": rows[0][5].upper(),
                "on_delete": rows[0][6].upper(), "match": rows[0][7].upper(),
            })
        tables.append({"name": table, "definition": _normalized_sql(table_sql[0] if table_sql else None),
                       "columns": column_payload,
                       "unique_sets": sorted(uniques, key=lambda value: tuple(value)),
                       "foreign_keys": sorted(foreign_keys, key=lambda value: json.dumps(value, sort_keys=True)),
                       "indexes": sorted(named_indexes, key=lambda value: value["name"])})
    triggers = [{"name": name, "sql": _normalized_sql(sql)} for name, sql in db.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
    )]
    views = [{"name": name, "sql": _normalized_sql(sql)} for name, sql in db.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='view' ORDER BY name"
    )]
    return {"format": "aipam-schema-fingerprint-v1", "tables": tables, "triggers": triggers, "views": views}


def schema_fingerprint(db: sqlite3.Connection) -> str:
    payload = json.dumps(_canonical_schema_payload(db), ensure_ascii=False,
                         separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _empty_schema_fingerprint() -> str:
    return hashlib.sha256(json.dumps(
        {"format": "aipam-schema-fingerprint-v1", "tables": [], "triggers": [], "views": []},
        ensure_ascii=False, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")).hexdigest()


def _revision_state(db: sqlite3.Connection) -> tuple[str, ...] | None:
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='alembic_version'").fetchone()
    if not exists:
        return None
    columns = [r[1] for r in db.execute("PRAGMA table_info(alembic_version)")]
    if columns != ["version_num"]:
        raise UnsupportedLegacySchema("malformed alembic_version table")
    rows = db.execute("SELECT version_num FROM alembic_version ORDER BY version_num").fetchall()
    if not rows or any(not row[0] for row in rows) or len({r[0] for r in rows}) != len(rows):
        raise UnsupportedLegacySchema("empty or inconsistent alembic_version table")
    return tuple(r[0] for r in rows)


def _known_ancestors() -> set[str]:
    from alembic.script import ScriptDirectory
    config = _alembic_config(Path(os.environ.get("AIPAM_DB_PATH", "/data/aipam.db")))
    scripts = ScriptDirectory.from_config(config)
    heads = scripts.get_heads()
    ancestors = set(heads)
    for revision in scripts.walk_revisions():
        if any(_is_ancestor(scripts, revision.revision, head) for head in heads):
            ancestors.add(revision.revision)
    return ancestors


def inspect_schema_profile(database_path: str | Path) -> SchemaProfile:
    path = Path(database_path)
    if not path.exists() or path.stat().st_size == 0:
        return SchemaProfile("fresh-empty-v1", _empty_schema_fingerprint())
    db = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)
    try:
        integrity = db.execute("PRAGMA quick_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise UnsupportedLegacySchema("SQLite quick_check failed")
        revisions = _revision_state(db)
        fingerprint = schema_fingerprint(db)
        if revisions is not None:
            known = _known_ancestors()
            if any(r not in known for r in revisions):
                raise UnsupportedLegacySchema("unknown or ahead Alembic revision")
            from alembic.script import ScriptDirectory
            scripts = ScriptDirectory.from_config(_alembic_config(path))
            for left, right in itertools.combinations(revisions, 2):
                if _is_ancestor(scripts, left, right) or _is_ancestor(scripts, right, left):
                    raise UnsupportedLegacySchema("inconsistent Alembic revision set")
            return SchemaProfile(f"alembic:{','.join(revisions)}", fingerprint, revisions)
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        if not names:
            return SchemaProfile("fresh-empty-v1", fingerprint)
        if {"chat_comparison_groups", "chat_comparison_branches"}.issubset(names):
            counts = [db.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0]
                      for t in ("chat_comparison_groups", "chat_comparison_branches")]
            if any(counts):
                raise UnsupportedLegacySchema("partial comparison tables contain data")
        if fingerprint in LEGACY_PROFILES:
            return SchemaProfile(LEGACY_PROFILES[fingerprint][0], fingerprint)
        raise UnsupportedLegacySchema("unrecognized unversioned schema fingerprint")
    finally:
        db.close()


def _alembic_config(database_path: Path) -> Config:
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "backend" / "alembic"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")
    return config


def _is_ancestor(scripts, ancestor: str, descendant: str) -> bool:
    revision = scripts.get_revision(descendant)
    pending = list(revision.down_revision or ()) if isinstance(revision.down_revision, tuple) else ([revision.down_revision] if revision.down_revision else [])
    seen = set()
    while pending:
        current = pending.pop()
        if current == ancestor:
            return True
        if current in seen:
            continue
        seen.add(current)
        parent = scripts.get_revision(current)
        down = parent.down_revision
        pending.extend(down if isinstance(down, tuple) else ([down] if down else []))
    return False


@contextmanager
def schema_lock(database_path: str | Path, *, exclusive: bool, timeout: float = 30):
    path = Path(database_path)
    lock_path = path.parent / f".{path.name}.schema.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                if os.name == "nt":
                    os.write(fd, b"\0") if os.fstat(fd).st_size == 0 else None
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                    fcntl.flock(fd, mode | fcntl.LOCK_NB)
                break
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    raise MigrationInProgress("schema lock acquisition timed out")
                time.sleep(0.05)
        if exclusive:
            metadata = json.dumps({"pid": os.getpid(), "host": socket.gethostname(),
                                   "operation_id": uuid4().hex,
                                   "started_at": datetime.now(timezone.utc).isoformat(),
                                   "database": path.name}).encode()
            os.ftruncate(fd, 0)
            os.write(fd, metadata)
            os.fsync(fd)
        yield fd
    finally:
        if os.name == "nt":
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        os.close(fd)


def _backup(source: Path, target: Path) -> None:
    with _sqlite_connection(f"file:{source.resolve().as_posix()}?mode=ro", uri=True) as src:
        with _sqlite_connection(target) as dst:
            src.backup(dst)
            dst.execute("PRAGMA journal_mode=DELETE")
            result = dst.execute("PRAGMA quick_check").fetchone()
            if not result or result[0] != "ok":
                raise SchemaBootstrapError("backup quick_check failed")


def _create_v1_compatibility_tables(candidate: Path) -> None:
    """Apply and record the separately versioned SQLModel compatibility schema."""
    from sqlmodel import SQLModel
    from sqlalchemy import create_engine
    from backend.app import db_models  # noqa: F401
    engine = create_engine(f"sqlite:///{candidate.as_posix()}")
    try:
        SQLModel.metadata.create_all(engine)
    finally:
        engine.dispose()
    table_names = sorted(SQLModel.metadata.tables)
    with _sqlite_connection(candidate) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS aipam_schema_components (
            component TEXT PRIMARY KEY, version TEXT NOT NULL, fingerprint TEXT NOT NULL
        )""")
        fingerprint = _component_fingerprint(db, table_names)
        db.execute(
            "INSERT INTO aipam_schema_components(component, version, fingerprint) VALUES (?, ?, ?) "
            "ON CONFLICT(component) DO UPDATE SET version=excluded.version, fingerprint=excluded.fingerprint",
            (SCHEMA_COMPONENT, SCHEMA_COMPONENT_VERSION, fingerprint),
        )


def _component_fingerprint(db: sqlite3.Connection, table_names: list[str]) -> str:
    placeholders = ",".join("?" for _ in table_names)
    rows = db.execute(
        f"SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' "
        f"AND (name IN ({placeholders}) OR tbl_name IN ({placeholders})) "
        "AND type IN ('table','index','trigger','view') ORDER BY type, name",
        [*table_names, *table_names],
    ).fetchall() if table_names else []
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def _database_content_sha256(path: Path) -> str:
    """Hash logical SQLite contents, independent of pages, WAL, and file layout."""
    if not path.exists() or not path.stat().st_size:
        return hashlib.sha256(b"aipam-empty-database-v1").hexdigest()
    digest = hashlib.sha256()
    with _sqlite_connection(f"file:{path.resolve().as_posix()}?mode=ro", uri=True) as db:
        tables = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        for (table,) in tables:
            columns = db.execute(f'PRAGMA table_info("{table}")').fetchall()
            primary = [row[1] for row in columns if row[5]]
            ordering = ",".join('"' + name.replace('"', '""') + '"' for name in primary) or "rowid"
            quoted = '"' + table.replace('"', '""') + '"'
            digest.update(json.dumps([table, columns], separators=(",", ":"), default=str).encode())
            for row in db.execute(f"SELECT * FROM {quoted} ORDER BY {ordering}"):
                encoded = json.dumps(row, separators=(",", ":"), ensure_ascii=False, default=str).encode()
                digest.update(len(encoded).to_bytes(8, "big"))
                digest.update(encoded)
    return digest.hexdigest()


def _require_disk_space(path: Path, *, copies: int) -> None:
    pages, page_size = 0, 4096
    if path.exists() and path.stat().st_size:
        with _sqlite_connection(f"file:{path.resolve().as_posix()}?mode=ro", uri=True) as db:
            pages = db.execute("PRAGMA page_count").fetchone()[0]
            page_size = db.execute("PRAGMA page_size").fetchone()[0]
    required = pages * page_size * copies + 256 * 1024 * 1024
    if shutil.disk_usage(path.parent).free < required:
        raise SchemaBootstrapError("insufficient free disk space for safe schema operation")


def _schema_component_record(path: Path) -> tuple[str, str] | None:
    if not path.exists() or not path.stat().st_size:
        return None
    with _sqlite_connection(f"file:{path.resolve().as_posix()}?mode=ro", uri=True) as db:
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='aipam_schema_components'"
        ).fetchone()
        if not exists:
            return None
        row = db.execute(
            "SELECT version, fingerprint FROM aipam_schema_components WHERE component=?",
            (SCHEMA_COMPONENT,),
        ).fetchone()
        return tuple(row) if row else None


def adopt_legacy_database(database_path: str | Path, *, lock_timeout: float = 30) -> dict:
    source = Path(database_path).resolve()
    source.parent.mkdir(parents=True, exist_ok=True)
    with schema_lock(source, exclusive=True, timeout=lock_timeout):
        _recover_prepared_receipts(source)
        profile = inspect_schema_profile(source)
        if profile.profile_id not in {"fresh-empty-v1", *[v[0] for v in LEGACY_PROFILES.values()]} and not profile.profile_id.startswith("alembic:"):
            raise UnsupportedLegacySchema(f"unsupported adoption profile: {profile.profile_id}")
        if profile.profile_id.startswith("alembic:") and set(profile.revisions) == set(_alembic_heads()):
            component = _schema_component_record(source)
            if component and component[0] != SCHEMA_COMPONENT_VERSION:
                raise SchemaNotCurrent("SQLModel compatibility schema component has an unsupported version")
            try:
                assert_schema_current(source)
                return {"profile_id": profile.profile_id, "revision": ",".join(profile.revisions), "source_sha256": _file_sha(source)}
            except SchemaNotCurrent:
                if component is not None:
                    raise
                # A current Alembic head can still lack the separately tracked
                # SQLModel compatibility component; adopt it through a candidate.
                pass
        _refuse_active_jobs(source)
        operation = uuid4().hex
        source_counts = _table_row_counts(source)
        source_primary_keys = _primary_key_fingerprints(source)
        backups = source.parent / "schema-backups"
        receipts = source.parent / "schema-receipts"
        backups.mkdir(exist_ok=True)
        receipts.mkdir(exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = backups / f"aipam.{timestamp}.{operation}.sqlite3"
        candidate = source.parent / f".{source.name}.{operation}.candidate"
        receipt_path = receipts / f"{operation}.json"
        staging = receipts / f".{operation}.receipt.tmp"
        try:
            _require_disk_space(source, copies=3)
            if source.exists() and source.stat().st_size:
                _backup(source, backup)
            else:
                with _sqlite_connection(backup):
                    pass
            _fsync_file(backup)
            os.chmod(backup, 0o444)
            _backup(backup, candidate)
            if profile.profile_id == "legacy-unversioned-partial-comparison-v1":
                with _sqlite_connection(candidate) as db:
                    db.execute("DROP TRIGGER IF EXISTS chat_conversation_provenance_immutable")
                    db.execute("DROP TRIGGER IF EXISTS chat_comparison_branch_provenance_immutable")
                    db.execute("DROP TABLE chat_comparison_branches")
                    db.execute("DROP TABLE chat_comparison_groups")
            if profile.profile_id.startswith("legacy-unversioned-"):
                command.stamp(_alembic_config(candidate), "d4e5f6a7b8c9")
            with _sqlite_connection(candidate) as db:
                state = _revision_state(db)
                if state is None:
                    # Empty databases migrate from base; legacy stamping is enabled
                    # only after an exact reviewed fingerprint is registered.
                    pass
                db.execute("PRAGMA integrity_check")
                if db.execute("PRAGMA foreign_key_check").fetchone():
                    raise SchemaBootstrapError("candidate foreign_key_check failed")
            command.upgrade(_alembic_config(candidate), "heads")
            _create_v1_compatibility_tables(candidate)
            with _sqlite_connection(candidate) as db:
                check = db.execute("PRAGMA integrity_check").fetchone()
                if not check or check[0] != "ok" or db.execute("PRAGMA foreign_key_check").fetchone():
                    raise SchemaBootstrapError("migrated candidate validation failed")
                revisions = _revision_state(db)
                table_count = db.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchone()[0]
            candidate_counts = _table_row_counts(candidate)
            candidate_primary_keys = _primary_key_fingerprints(candidate)
            generated_or_migrated = {
                "theories", "chat_comparison_groups", "chat_comparison_branches", "alembic_version"
            }
            count_mismatches = {
                name: (count, candidate_counts.get(name))
                for name, count in source_counts.items()
                if name not in generated_or_migrated and candidate_counts.get(name) != count
            }
            if count_mismatches:
                raise SchemaBootstrapError("candidate row-count invariants failed")
            key_mismatches = {
                name: (fingerprint, candidate_primary_keys.get(name))
                for name, fingerprint in source_primary_keys.items()
                if name not in generated_or_migrated and candidate_primary_keys.get(name) != fingerprint
            }
            if key_mismatches:
                raise SchemaBootstrapError(
                    "candidate primary-key invariants failed for: " + ",".join(sorted(key_mismatches))
                )
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(candidate) + suffix)
                if sidecar.exists() and sidecar.stat().st_size:
                    raise SchemaBootstrapError("candidate has non-empty SQLite sidecar")
                sidecar.unlink(missing_ok=True)
            _fsync_file(candidate)
            payload = {"operation_id": operation, "profile_id": profile.profile_id,
                       "source": str(source), "backup": str(backup), "candidate": str(candidate), "candidate_sha256": _file_sha(candidate),
                       "backup_sha256": _file_sha(backup), "source_sha256": _file_sha(source) if source.exists() else None,
                       "source_fingerprint": profile.fingerprint,
                       "source_content_sha256": _database_content_sha256(source),
                       "candidate_fingerprint": inspect_schema_profile(candidate).fingerprint,
                       "previous_image": os.environ.get("AIPAM_PREVIOUS_IMAGE", "aipam-app:pre-schema-rollback"),
                       "revisions": revisions, "table_count": table_count,
                       "source_row_counts": source_counts,
                       "candidate_row_counts": candidate_counts,
                       "source_primary_key_fingerprints": source_primary_keys,
                       "candidate_primary_key_fingerprints": candidate_primary_keys,
                       "chat_row_counts": {name: count for name, count in source_counts.items() if name.startswith("chat_")},
                       "status": "prepared", "created_at": datetime.now(timezone.utc).isoformat()}
            _atomic_json(staging, receipt_path, payload)
            with _sqlite_connection(source) as db:
                if db.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal":
                    checkpoint = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                    if checkpoint and checkpoint[0] != 0:
                        raise SchemaBootstrapError("source WAL checkpoint was busy")
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(source) + suffix)
                if sidecar.exists() and sidecar.stat().st_size:
                    raise SchemaBootstrapError("source SQLite sidecar remains after checkpoint")
            os.replace(candidate, source)
            _fsync_dir(source.parent)
            if _file_sha(source) != payload["candidate_sha256"]:
                raise SchemaBootstrapError("replaced database checksum differs from candidate")
            with _sqlite_connection(f"file:{source.as_posix()}?mode=ro", uri=True) as db:
                if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise SchemaBootstrapError("replaced database quick_check failed")
                if db.execute("PRAGMA foreign_key_check").fetchone():
                    raise SchemaBootstrapError("replaced database foreign_key_check failed")
            assert_schema_current(source)
            payload["status"] = "committed"
            payload["committed_at"] = datetime.now(timezone.utc).isoformat()
            _atomic_json(staging, receipt_path, payload)
            return payload
        finally:
            candidate.unlink(missing_ok=True)
            staging.unlink(missing_ok=True)


def restore_database_backup(database_path: str | Path, backup_path: str | Path,
                            migration_receipt_path: str | Path, *, commit: bool = False) -> dict:
    """Verify a retained adoption backup, optionally restoring it atomically."""
    source = Path(database_path).resolve()
    backup = Path(backup_path).resolve()
    migration_receipt = json.loads(Path(migration_receipt_path).read_text(encoding="utf-8"))
    if migration_receipt.get("status") != "committed" or migration_receipt.get("backup") != str(backup):
        raise SchemaBootstrapError("restore backup is not bound to a committed migration receipt")
    if Path(migration_receipt.get("source", "")).resolve() != source:
        raise SchemaBootstrapError("migration receipt belongs to a different database path")
    if _file_sha(backup) != migration_receipt.get("backup_sha256"):
        raise SchemaBootstrapError("restore backup checksum does not match migration receipt")
    expected_profile = migration_receipt.get("profile_id")
    with schema_lock(source, exclusive=True):
        _recover_prepared_receipts(source)
        current = inspect_schema_profile(source)
        if current.fingerprint != migration_receipt.get("candidate_fingerprint"):
            raise SchemaBootstrapError("current database schema does not match the migrated schema in the receipt")
        if tuple(current.revisions) != tuple(migration_receipt.get("revisions", ())):
            raise SchemaBootstrapError("current database revisions do not match the migration receipt")
        assert_schema_current(source)
        profile = inspect_schema_profile(backup)
        if profile.profile_id != expected_profile:
            raise SchemaBootstrapError("restore backup schema profile does not match receipt")
        _refuse_active_jobs(source)
        operation = uuid4().hex
        candidate = source.parent / f".{source.name}.{operation}.restore-candidate"
        try:
            _require_disk_space(source, copies=2 if commit else 1)
            _backup(backup, candidate)
            with _sqlite_connection(candidate) as db:
                if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise SchemaBootstrapError("restore candidate quick_check failed")
                if db.execute("PRAGMA foreign_key_check").fetchone():
                    raise SchemaBootstrapError("restore candidate foreign_key_check failed")
            candidate_profile = inspect_schema_profile(candidate)
            if candidate_profile.profile_id != expected_profile:
                raise SchemaBootstrapError("restore candidate profile does not match receipt")
            candidate_sha = _file_sha(candidate)
            if not commit:
                return {"status": "dry-run-passed", "profile_id": expected_profile,
                        "candidate_sha256": candidate_sha, "backup_sha256": migration_receipt["backup_sha256"]}

            restore_backups = source.parent / "schema-backups"
            restore_receipts = source.parent / "schema-receipts"
            restore_backups.mkdir(exist_ok=True)
            restore_receipts.mkdir(exist_ok=True)
            current_backup = restore_backups / f"aipam.pre-restore.{operation}.sqlite3"
            if source.exists() and source.stat().st_size:
                _backup(source, current_backup)
                _fsync_file(current_backup)
                os.chmod(current_backup, 0o444)
            original_sha = _file_sha(source) if source.exists() else None
            original_profile = inspect_schema_profile(source)
            original_counts = _table_row_counts(source)
            staging = restore_receipts / f".{operation}.receipt.tmp"
            receipt_path = restore_receipts / f"{operation}.json"
            receipt = {"operation_id": operation, "status": "restore-prepared",
                       "source": str(source), "migration_receipt": str(Path(migration_receipt_path).resolve()),
                       "restore_backup": str(backup), "restore_backup_sha256": migration_receipt["backup_sha256"],
                       "candidate": str(candidate), "candidate_sha256": candidate_sha,
                       "current_backup": str(current_backup) if current_backup.exists() else None,
                       "current_backup_sha256": _file_sha(current_backup) if current_backup.exists() else None,
                       "source_sha256": original_sha, "profile_id": expected_profile,
                       "source_profile_id": original_profile.profile_id,
                       "source_fingerprint": original_profile.fingerprint,
                       "source_content_sha256": _database_content_sha256(source),
                       "source_row_counts": original_counts,
                       "previous_image": migration_receipt.get("previous_image"),
                       "created_at": datetime.now(timezone.utc).isoformat()}
            _atomic_json(staging, receipt_path, receipt)
            if source.exists() and source.stat().st_size:
                with _sqlite_connection(source) as db:
                    if db.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal":
                        result = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                        if result and result[0] != 0:
                            raise SchemaBootstrapError("source WAL checkpoint was busy")
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(source) + suffix)
                if sidecar.exists() and sidecar.stat().st_size:
                    raise SchemaBootstrapError("source SQLite sidecar remains after checkpoint")
            os.replace(candidate, source)
            _fsync_dir(source.parent)
            if _file_sha(source) != candidate_sha or inspect_schema_profile(source).profile_id != expected_profile:
                raise SchemaBootstrapError("restored database validation failed")
            receipt["status"] = "restored"
            receipt["restored_at"] = datetime.now(timezone.utc).isoformat()
            _atomic_json(staging, receipt_path, receipt)
            return receipt
        finally:
            candidate.unlink(missing_ok=True)


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDWR)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_dir(path: Path) -> None:
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _atomic_json(staging: Path, target: Path, payload: dict) -> None:
    staging.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    _fsync_file(staging)
    os.replace(staging, target)
    _fsync_dir(target.parent)


def _recover_prepared_receipts(source: Path) -> None:
    receipt_dir = source.parent / "schema-receipts"
    if not receipt_dir.is_dir():
        return
    actual = _file_sha(source) if source.exists() else None
    for receipt_path in sorted(receipt_dir.glob("*.json")):
        payload = json.loads(receipt_path.read_text(encoding="utf-8"))
        if payload.get("status") not in {"prepared", "restore-prepared"} or Path(payload.get("source", "")).resolve() != source:
            continue
        candidate = Path(payload["candidate"])
        if actual == payload.get("candidate_sha256"):
            if payload["status"] == "prepared":
                assert_schema_current(source)
                payload["status"] = "committed"
                payload["committed_at"] = datetime.now(timezone.utc).isoformat()
            else:
                if inspect_schema_profile(source).profile_id != payload["profile_id"]:
                    raise SchemaBootstrapError("prepared restore candidate profile differs from source")
                payload["status"] = "restored"
                payload["restored_at"] = datetime.now(timezone.utc).isoformat()
        elif _is_original_source(source, payload):
            if candidate.exists():
                quarantine = candidate.with_name(candidate.name + ".quarantined")
                os.replace(candidate, quarantine)
                payload["quarantined_candidate"] = str(quarantine)
            payload["status"] = "restore-abandoned-before-replacement" if payload.get("status") == "restore-prepared" else "abandoned-before-replacement"
        else:
            raise SchemaBootstrapError("prepared migration receipt does not match source or candidate")
        _atomic_json(receipt_path.with_suffix(".tmp"), receipt_path, payload)


def _is_original_source(source: Path, payload: dict) -> bool:
    if not source.exists():
        return payload.get("source_sha256") is None
    try:
        profile = inspect_schema_profile(source)
        return (profile.profile_id == payload.get("source_profile_id", payload.get("profile_id"))
                and profile.fingerprint == payload.get("source_fingerprint")
                and _table_row_counts(source) == payload.get("source_row_counts", {})
                and _database_content_sha256(source) == payload.get("source_content_sha256"))
    except SchemaBootstrapError:
        return False


def assert_schema_current(database_path: str | Path) -> None:
    profile = inspect_schema_profile(database_path)
    if not profile.profile_id.startswith("alembic:"):
        raise SchemaNotCurrent(f"database schema is not versioned: {profile.profile_id}")
    from alembic.script import ScriptDirectory
    scripts = ScriptDirectory.from_config(_alembic_config(Path(database_path)))
    if set(profile.revisions) != set(scripts.get_heads()):
        raise SchemaNotCurrent(f"database schema is behind or ahead: {profile.revisions}")
    from backend.app.database_v2 import Base
    from sqlmodel import SQLModel
    import backend.app.models  # noqa: F401
    import backend.app.db_models  # noqa: F401
    expected = set(Base.metadata.tables) | set(SQLModel.metadata.tables)
    with _sqlite_connection(f"file:{Path(database_path).resolve().as_posix()}?mode=ro", uri=True) as db:
        actual = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing = expected - actual
    if missing:
        raise SchemaNotCurrent(f"database is missing required tables: {','.join(sorted(missing))}")
    with _sqlite_connection(f"file:{Path(database_path).resolve().as_posix()}?mode=ro", uri=True) as db:
        component = db.execute(
            "SELECT version, fingerprint FROM aipam_schema_components WHERE component=?",
            (SCHEMA_COMPONENT,),
        ).fetchone() if "aipam_schema_components" in actual else None
        if not component or component[0] != SCHEMA_COMPONENT_VERSION:
            raise SchemaNotCurrent("SQLModel compatibility schema component is missing or has an unsupported version")
        model_tables = sorted(SQLModel.metadata.tables)
        fingerprint = _component_fingerprint(db, model_tables)
        if fingerprint != component[1]:
            raise SchemaNotCurrent("SQLModel compatibility schema differs from its recorded fingerprint")


def _alembic_heads() -> set[str]:
    from alembic.script import ScriptDirectory
    path = Path(os.environ.get("AIPAM_DB_PATH", "/data/aipam.db"))
    return set(ScriptDirectory.from_config(_alembic_config(path)).get_heads())


def _refuse_active_jobs(path: Path) -> None:
    if not path.exists() or not path.stat().st_size:
        return
    with _sqlite_connection(f"file:{path.as_posix()}?mode=ro", uri=True) as db:
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='jobs'").fetchone()
        if not exists:
            return
        cols = {row[1] for row in db.execute("PRAGMA table_info(jobs)")}
        if "status" in cols:
            active = db.execute("SELECT count(*) FROM jobs WHERE lower(status) IN ('queued','running','canceling','deleting')").fetchone()[0]
            if active:
                raise UnsupportedLegacySchema("active jobs prevent schema adoption")


def _table_row_counts(path: Path) -> dict[str, int]:
    if not path.exists() or not path.stat().st_size:
        return {}
    with _sqlite_connection(f"file:{path.resolve().as_posix()}?mode=ro", uri=True) as db:
        names = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        return {name: db.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0] for name in names}


def _primary_key_fingerprints(path: Path) -> dict[str, str]:
    if not path.exists() or not path.stat().st_size:
        return {}
    result = {}
    with _sqlite_connection(f"file:{path.resolve().as_posix()}?mode=ro", uri=True) as db:
        tables = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            columns = db.execute(f"PRAGMA table_info({quoted})").fetchall()
            primary_key = [row[1] for row in sorted((row for row in columns if row[5]), key=lambda row: row[5])]
            if not primary_key:
                continue
            selected = ",".join('"' + name.replace('"', '""') + '"' for name in primary_key)
            digest = hashlib.sha256()
            digest.update(json.dumps([table, primary_key], separators=(",", ":")).encode())
            for row in db.execute(f"SELECT {selected} FROM {quoted} ORDER BY {selected}"):
                encoded = json.dumps(row, separators=(",", ":"), ensure_ascii=False, default=str).encode()
                digest.update(len(encoded).to_bytes(8, "big"))
                digest.update(encoded)
            result[table] = digest.hexdigest()
    return result
