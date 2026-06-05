"""
AIPAM V2 database engine — SQLite with WAL mode (§1.5).

Concurrency policy:
  - WAL mode for concurrent readers + single writer
  - busy_timeout = 5000 ms (writer retries for 5s before raising)
  - synchronous = NORMAL (safe with WAL, ~2x faster than FULL)
  - journal_size_limit = 64 MB (prevent unbounded WAL growth)
  - SQLAlchemy pool: StaticPool for SQLite (single connection per process)
  - check_same_thread = False (required for FastAPI thread pool)
"""

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.app.config_v2 import get_settings


class Base(DeclarativeBase):
    """Base class for all V2 ORM models."""
    pass


def _set_sqlite_pragmas(dbapi_conn, connection_record):
    """Set SQLite pragmas on every new connection (§1.5)."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=15000")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA journal_size_limit=67108864")  # 64 MB
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def create_v2_engine(database_url: str | None = None) -> Engine:
    """Create the SQLAlchemy engine with WAL pragmas.

    Args:
        database_url: Override for testing. Defaults to settings.database_url.
    """
    if database_url is None:
        settings = get_settings()
        database_url = settings.database_url

    engine = create_engine(
        database_url,
        echo=False,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
    )
    event.listen(engine, "connect", _set_sqlite_pragmas)
    return engine


# Default engine and session factory (initialized lazily)
_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Get or create the default engine."""
    global _engine
    if _engine is None:
        _engine = create_v2_engine()
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Get or create the default session factory."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=get_engine(),
            autocommit=False,
            autoflush=False,
        )
    return _SessionLocal


def get_db() -> Session:
    """FastAPI dependency: yields a DB session, auto-closes after request.

    Usage:
        @app.get("/items")
        def list_items(db: Session = Depends(get_db)):
            ...
    """
    session_factory = get_session_factory()
    db = session_factory()
    try:
        yield db
    finally:
        db.close()


def init_v2_db() -> None:
    """Create all V2 tables. For development only — use Alembic in production."""
    # Import all models so they register with Base.metadata
    import backend.app.models  # noqa: F401
    engine = get_engine()
    Base.metadata.create_all(bind=engine)

    # Development/self-hosted compatibility: persisted local SQLite volumes may
    # contain older V2 tables created before newer nullable columns existed.
    # `create_all()` will not add those columns to existing tables, so patch the
    # minimal known compatibility case needed by the explain workflow.
    inspector = inspect(engine)
    if inspector.has_table("findings"):
        column_names = {column["name"] for column in inspector.get_columns("findings")}
        with engine.begin() as connection:
            if "explanation_feedback" not in column_names:
                connection.execute(
                    text("ALTER TABLE findings ADD COLUMN explanation_feedback VARCHAR")
                )
            if "confidence" not in column_names:
                connection.execute(
                    text("ALTER TABLE findings ADD COLUMN confidence REAL DEFAULT 0.0")
                )

    # Add pcap_label column to tables that need temporal analysis support
    _pcap_label_tables = [
        "theories", "incident_slices", "context_annotations", "reports",
        "alerts", "findings", "hosts", "connections", "iocs",
        "files", "dns_queries", "tls_sessions", "timeline_events",
    ]
    for table_name in _pcap_label_tables:
        if inspector.has_table(table_name):
            cols = {c["name"] for c in inspector.get_columns(table_name)}
            if "pcap_label" not in cols:
                with engine.begin() as connection:
                    connection.execute(
                        text(f"ALTER TABLE {table_name} ADD COLUMN pcap_label VARCHAR")
                    )

    # Add score_breakdown_json to theories if missing
    if inspector.has_table("theories"):
        theory_cols = {c["name"] for c in inspector.get_columns("theories")}
        if "score_breakdown_json" not in theory_cols:
            with engine.begin() as connection:
                connection.execute(
                    text("ALTER TABLE theories ADD COLUMN score_breakdown_json TEXT")
                )

    # Investigation Queue: add analyst_status, analyst_notes, reviewed_at columns
    _investigation_tables = ["findings", "alerts", "theories"]
    _investigation_cols = [
        ("analyst_status", "VARCHAR DEFAULT 'unreviewed'"),
        ("analyst_notes", "TEXT"),
        ("reviewed_at", "VARCHAR"),
        ("reviewer_id", "VARCHAR"),
    ]
    for table_name in _investigation_tables:
        if inspector.has_table(table_name):
            cols = {c["name"] for c in inspector.get_columns(table_name)}
            for col_name, col_type in _investigation_cols:
                if col_name not in cols:
                    with engine.begin() as connection:
                        connection.execute(
                            text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")
                        )

    # Proof Builder: add mode column to proofs table if missing
    if inspector.has_table("proofs"):
        proof_cols = {c["name"] for c in inspector.get_columns("proofs")}
        if "mode" not in proof_cols:
            with engine.begin() as connection:
                connection.execute(
                    text("ALTER TABLE proofs ADD COLUMN mode VARCHAR DEFAULT 'soc_handoff'")
                )

    # Telemetry Fusion: add source_type, exercise_id, source_manifest_json to jobs
    if inspector.has_table("jobs"):
        job_cols = {c["name"] for c in inspector.get_columns("jobs")}
        _new_job_cols = [
            ("source_type", "VARCHAR DEFAULT 'pcap'"),
            ("exercise_id", "VARCHAR"),
            ("source_manifest_json", "TEXT"),
        ]
        for col_name, col_type in _new_job_cols:
            if col_name not in job_cols:
                with engine.begin() as connection:
                    connection.execute(
                        text(f"ALTER TABLE jobs ADD COLUMN {col_name} {col_type}")
                    )

    # Temporal Correlation: add enriched log summary columns for side-by-side display
    # plus enhanced multi-key / label-aware / clock-aligned correlation metadata.
    if inspector.has_table("temporal_correlations"):
        tc_cols = {c["name"] for c in inspector.get_columns("temporal_correlations")}
        _new_tc_cols = [
            ("log_summary", "TEXT"),
            ("log_source_filename", "VARCHAR"),
            ("community_id", "VARCHAR"),
            ("match_keys_json", "TEXT"),
            ("log_label", "VARCHAR"),
            ("pcap_label", "VARCHAR"),
            ("clock_offset_seconds", "REAL DEFAULT 0.0"),
            ("adjusted_time_delta_seconds", "REAL"),
            ("confidence_band", "VARCHAR"),
        ]
        for col_name, col_type in _new_tc_cols:
            if col_name not in tc_cols:
                with engine.begin() as connection:
                    connection.execute(
                        text(f"ALTER TABLE temporal_correlations ADD COLUMN {col_name} {col_type}")
                    )

def reset_engine() -> None:
    """Reset engine and session factory. Used in tests."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None

