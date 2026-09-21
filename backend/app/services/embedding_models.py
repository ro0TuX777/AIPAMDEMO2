"""Runtime selection and validation for Ollama embedding models.

The selected model and its observed vector dimension are persisted together.
Consumers use this module instead of embedding a model name in their own
configuration, which keeps vector collections compatible when operators move
to a newer model.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from typing import Any, Callable

import requests


_VALIDATION_INPUT = "AIPAM embedding validation"
_REQUEST_TIMEOUT_SECONDS = 30


class EmbeddingModelUnavailable(RuntimeError):
    """Raised when the configured Ollama service cannot be queried."""


class EmbeddingModelValidationError(ValueError):
    """Raised when a selected model cannot produce a usable embedding."""


@dataclass(frozen=True)
class EmbeddingModelConfig:
    """A validated embedding model and the collection it owns."""

    model: str
    dimension: int
    collection_name: str


def collection_name_for(model: str, dimension: int) -> str:
    """Return a stable, Chroma-safe collection name for a model dimension pair."""
    normalized = f"{model.strip()}:{dimension}".encode("utf-8")
    return f"aipam_kb_{sha256(normalized).hexdigest()[:16]}"


def _ensure_settings_table() -> None:
    try:
        from sqlmodel import SQLModel

        from backend.app import db_models
        from backend.app.database import engine

        SQLModel.metadata.create_all(engine, tables=[db_models.SettingsDB.__table__])
    except Exception:
        # The read/write helpers preserve their own failure semantics.
        pass


def _load_settings_values() -> dict[str, Any]:
    """Read persisted runtime settings without coupling callers to FastAPI."""
    try:
        _ensure_settings_table()
        from backend.app.database import get_session
        from backend.app.db_models import SettingsDB

        with get_session() as session:
            row = session.get(SettingsDB, 1)
            return dict(row.values) if row and row.values else {}
    except Exception:
        return {}


def _save_settings_values(updates: dict[str, Any]) -> dict[str, Any]:
    """Merge embedding configuration into the singleton settings record."""
    _ensure_settings_table()
    from backend.app.database import get_session
    from backend.app.db_models import SettingsDB

    with get_session() as session:
        row = session.get(SettingsDB, 1)
        if row is None:
            row = SettingsDB(id=1, values={})
            session.add(row)
        values = dict(row.values) if row.values else {}
        values.update(updates)
        row.values = values
        session.commit()
        session.refresh(row)
        return dict(row.values)


class EmbeddingModelService:
    """Ollama-backed model discovery, validation, and active-model storage."""

    def __init__(
        self,
        ollama_url: str,
        *,
        request: Callable[..., Any] = requests.request,
    ) -> None:
        self._base_url = ollama_url.rstrip("/")
        self._request = request

    def list_models(self) -> list[dict[str, Any]]:
        """Return the models installed in the configured Ollama runtime."""
        try:
            response = self._request(
                "GET",
                f"{self._base_url}/api/tags",
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            raise EmbeddingModelUnavailable("Ollama is unavailable") from exc
        if response.status_code != 200:
            raise EmbeddingModelUnavailable(
                f"Ollama model listing returned HTTP {response.status_code}"
            )
        try:
            models = response.json().get("models", [])
        except Exception as exc:
            raise EmbeddingModelUnavailable("Ollama returned an invalid model list") from exc
        return [model for model in models if isinstance(model, dict) and model.get("name")]

    def validate(self, model: str) -> EmbeddingModelConfig:
        """Verify that an installed model returns a numeric embedding vector."""
        normalized = model.strip()
        if not normalized or len(normalized) > 256:
            raise EmbeddingModelValidationError("An embedding model name is required")

        installed_names = {str(item["name"]) for item in self.list_models()}
        if normalized not in installed_names:
            raise EmbeddingModelValidationError(
                f"Embedding model '{normalized}' is not installed in Ollama"
            )

        try:
            response = self._request(
                "POST",
                f"{self._base_url}/api/embed",
                json={"model": normalized, "input": [_VALIDATION_INPUT]},
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            raise EmbeddingModelValidationError(
                f"Unable to validate embedding model '{normalized}'"
            ) from exc
        if response.status_code != 200:
            raise EmbeddingModelValidationError(
                f"Embedding model '{normalized}' returned HTTP {response.status_code}"
            )
        try:
            embeddings = response.json().get("embeddings")
            vector = embeddings[0] if isinstance(embeddings, list) and embeddings else None
        except Exception as exc:
            raise EmbeddingModelValidationError(
                f"Embedding model '{normalized}' returned an invalid response"
            ) from exc
        if not isinstance(vector, list) or not vector or not all(
            isinstance(value, (int, float)) and not isinstance(value, bool)
            for value in vector
        ):
            raise EmbeddingModelValidationError(
                f"Embedding model '{normalized}' did not return a numeric vector"
            )
        dimension = len(vector)
        return EmbeddingModelConfig(
            model=normalized,
            dimension=dimension,
            collection_name=collection_name_for(normalized, dimension),
        )

    def select(self, model: str) -> EmbeddingModelConfig:
        """Validate first, then atomically replace the active model selection."""
        config = self.validate(model)
        _save_settings_values(
            {
                "embedding_model_name": config.model,
                "embedding_model_dimension": config.dimension,
            }
        )
        return config

    def get_active(self) -> EmbeddingModelConfig | None:
        """Return the persisted selection, or an explicit environment fallback."""
        values = _load_settings_values()
        model = values.get("embedding_model_name") or os.getenv("AIPAM_EMBEDDING_MODEL")
        dimension = values.get("embedding_model_dimension")
        if not isinstance(model, str) or not model.strip():
            return None
        if isinstance(dimension, int) and dimension > 0:
            normalized = model.strip()
            return EmbeddingModelConfig(
                model=normalized,
                dimension=dimension,
                collection_name=collection_name_for(normalized, dimension),
            )
        # An environment model has no persisted dimension, so probe it before use.
        return self.validate(model)


def get_embedding_model_service(ollama_url: str) -> EmbeddingModelService:
    """Factory kept small so APIs and workers can share the same service."""
    return EmbeddingModelService(ollama_url)
