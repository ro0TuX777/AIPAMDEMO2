"""Shared test fixtures for AIPAM backend tests.

This conftest ensures the database is initialized before any test
runs, preventing ordering-dependent failures when connector tests
call ``get_effective_settings()`` which queries ``SettingsDB``.
"""

import pytest

from app.database import init_db


@pytest.fixture(scope="session", autouse=True)
def _ensure_db_tables():
    """Create all SQLModel tables once per test session."""
    init_db()
