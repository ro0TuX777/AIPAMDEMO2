"""Shared test fixtures for AIPAM backend tests.

This conftest ensures the V1 database module uses an in-memory SQLite
engine during tests (instead of the default /data/aipam.db) and creates
all SQLModel tables once per session.
"""

import pytest
from sqlmodel import SQLModel, create_engine

from backend.app import database as _v1_db


@pytest.fixture(scope="session", autouse=True)
def _ensure_db_tables(tmp_path_factory):
    """Redirect V1 database engine to a temp file and create tables."""
    db_path = tmp_path_factory.mktemp("db") / "test_v1.db"
    test_engine = create_engine(f"sqlite:///{db_path}", echo=False)
    _v1_db.engine = test_engine
    _v1_db.init_db()
