"""Shared test fixtures for AIPAM backend tests.

This conftest ensures the V1 database module uses an in-memory SQLite
engine during tests (instead of the default /data/aipam.db) and creates
all SQLModel tables once per session.
"""

import pytest
from sqlmodel import create_engine

from backend.app import database as _v1_db


@pytest.fixture(scope="session", autouse=True)
def _ensure_db_tables(tmp_path_factory):
    """Redirect V1 database engine to a temp file and create tables."""
    db_path = tmp_path_factory.mktemp("db") / "test_v1.db"
    test_engine = create_engine(f"sqlite:///{db_path}", echo=False)
    _v1_db.engine = test_engine
    _v1_db.init_db()


@pytest.fixture(scope="session", autouse=True)
def _validate_bluescrub_contracts():
    """Enforce the BlueScrub JSON contracts for the whole suite.

    The schemas were enforced only where a test happened to call them, and a
    test validates whatever object it was handed — which is not always the
    object that ships. Turning this on globally makes every existing test that
    runs the pipeline a contract check as well, at no authoring cost.

    Off in production: validating thousands of findings per job costs real
    time, and a contract violation must never lose a scan.
    """
    import os

    from backend.app.bluescrub import validation

    previous = os.environ.get(validation.ENV)
    os.environ[validation.ENV] = "1"
    yield
    if previous is None:
        os.environ.pop(validation.ENV, None)
    else:
        os.environ[validation.ENV] = previous
