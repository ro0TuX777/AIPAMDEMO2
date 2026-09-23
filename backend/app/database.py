from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

from sqlmodel import Session, SQLModel, create_engine


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./aipam.db")
_engine = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = create_engine(os.getenv("DATABASE_URL", DATABASE_URL), echo=False)
    return _engine


def create_test_schema() -> None:
    """Create V1 tables for isolated test databases only."""

    from . import db_models  # noqa: F401

    SQLModel.metadata.create_all(get_engine())


@contextmanager
def get_session() -> Iterator[Session]:
    with Session(get_engine()) as session:
        yield session



def __getattr__(name):
    if name == "engine":
        return get_engine()
    raise AttributeError(name)
