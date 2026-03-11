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

from sqlalchemy import create_engine, event
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
    
    # Alembic handles all schema migrations now; manual ALTERS removed.

def reset_engine() -> None:
    """Reset engine and session factory. Used in tests."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None

