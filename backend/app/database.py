from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

from sqlmodel import Session, SQLModel, create_engine


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./aipam.db")
engine = create_engine(DATABASE_URL, echo=False)


def init_db() -> None:
    """Create all tables. Call this at startup or via a migration command."""

    from . import db_models  # noqa: F401

    SQLModel.metadata.create_all(engine)


@contextmanager
def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session

