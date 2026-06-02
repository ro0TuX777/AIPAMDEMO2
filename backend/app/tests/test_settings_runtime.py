from __future__ import annotations

from pathlib import Path

import pytest
from sqlmodel import SQLModel, create_engine

from backend.app.settings_runtime import EffectiveSettings, get_effective_settings
from backend.app.db_models import SettingsDB
from backend.app import database as database_mod
from backend.app.database import get_session


@pytest.fixture(autouse=True)
def _in_memory_db(tmp_path, monkeypatch):
    """Use an in-memory DB so tests don't need /data/aipam.db."""
    test_engine = create_engine("sqlite:///:memory:")
    from backend.app import db_models  # noqa: F401
    SQLModel.metadata.create_all(test_engine)
    monkeypatch.setattr(database_mod, "engine", test_engine)


def test_effective_settings_fall_back_to_env(tmp_path, monkeypatch) -> None:
    # Point FILE_STORAGE_PATH env at a temp dir and ensure EffectiveSettings reflects it
    monkeypatch.setenv("FILE_STORAGE_PATH", str(tmp_path / "storage_env"))

    settings = get_effective_settings()
    assert isinstance(settings, EffectiveSettings)
    assert settings.file_storage_path == Path(tmp_path / "storage_env")


def test_effective_settings_use_persisted_values(tmp_path, monkeypatch) -> None:
    base = tmp_path / "storage_settings"

    with get_session() as session:
        row = SettingsDB(id=1, values={"file_storage_path": str(base)})
        session.add(row)
        session.commit()

    settings = get_effective_settings()
    assert settings.file_storage_path == base

