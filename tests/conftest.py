"""AIPAM V2 test fixtures.

Provides:
  - In-memory SQLite DB with WAL pragmas
  - Pre-populated session factory
  - FastAPI test client with auth header
  - Sample data factories
"""

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

# Set required env vars before importing app modules
os.environ.setdefault("AIPAM_API_TOKEN", "test-token-v2")

from backend.app.database_v2 import Base, _set_sqlite_pragmas, get_db
from backend.app.models import (
    Host,
    Job,
    Upload,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# DB fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db_engine():
    """Create an in-memory SQLite engine with all V2 tables."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def db_session(db_engine):
    """Provide a transactional DB session that rolls back after each test."""
    connection = db_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture()
def db_session_factory(db_engine):
    """Session factory bound to the test engine."""
    return sessionmaker(bind=db_engine, autocommit=False, autoflush=False)


# ---------------------------------------------------------------------------
# Sample data factories
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_job(db_session) -> Job:
    """Insert and return a sample job."""
    job = Job(
        job_id=_uuid(),
        job_name="Test Job",
        status="queued",
        execution_profile="standard",
        priority="normal",
        pcap_filename="test.pcap",
        pcap_size_bytes=1024,
        pcap_sha256="abc123",
        created_at=_now_iso(),
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)
    return job


@pytest.fixture()
def sample_upload(db_session) -> Upload:
    """Insert and return a sample upload."""
    upload = Upload(
        upload_id=_uuid(),
        filename="test.pcap",
        size_bytes=1024,
        sha256="abc123def456",
        created_at=_now_iso(),
    )
    db_session.add(upload)
    db_session.commit()
    db_session.refresh(upload)
    return upload


@pytest.fixture()
def sample_host(db_session, sample_job) -> Host:
    """Insert and return a sample host linked to sample_job."""
    host = Host(
        job_id=sample_job.job_id,
        ip="10.0.0.5",
        role="internal",
        conn_count=42,
        alert_count=3,
        finding_count=1,
        first_seen=_now_iso(),
        last_seen=_now_iso(),
    )
    db_session.add(host)
    db_session.commit()
    db_session.refresh(host)
    return host


# ---------------------------------------------------------------------------
# FastAPI test client fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_dirs(tmp_path):
    """Create temporary upload and job directories."""
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    job_dir = tmp_path / "jobs"
    job_dir.mkdir()
    return {"upload_root": upload_dir, "job_root": job_dir}


@pytest.fixture()
def app_client(db_engine, tmp_dirs):
    """FastAPI TestClient with in-memory DB and temp directories.

    Yields (client, db_session) tuple.

    Uses a single shared connection so all sessions see the same
    in-memory SQLite tables.
    """
    from unittest.mock import patch
    from fastapi.testclient import TestClient
    from backend.app.main_v2 import create_app
    from backend.app.config_v2 import Settings, get_settings

    app = create_app()

    # Share ONE connection for all sessions (in-memory SQLite requirement)
    connection = db_engine.connect()

    def _override_db():
        db = Session(bind=connection)
        try:
            yield db
        finally:
            db.close()

    # Override settings for temp paths
    _test_settings = Settings(
        aipam_api_token="test-token-v2",
        aipam_upload_root=tmp_dirs["upload_root"],
        aipam_job_root=tmp_dirs["job_root"],
        aipam_db_path=Path("/tmp/unused.db"),
    )

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_settings] = lambda: _test_settings

    # Patch Celery dispatch so tests don't block trying to reach Redis
    with patch("backend.app.api.jobs._dispatch_job"):
        client = TestClient(app)
        db = Session(bind=connection)
        yield client, db
        db.close()
    connection.close()

