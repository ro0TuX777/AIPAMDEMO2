from __future__ import annotations

import json

import pytest


class _Response:
    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body)

    def json(self) -> dict:
        return self._body


def _request(method: str, url: str, **kwargs) -> _Response:
    if method == "GET" and url.endswith("/api/tags"):
        return _Response(200, {"models": [{"name": "new-embed", "details": {}}]})
    if method == "POST" and url.endswith("/api/embed"):
        assert kwargs["json"] == {"model": "new-embed", "input": ["AIPAM embedding validation"]}
        return _Response(200, {"embeddings": [[0.1, 0.2, 0.3]]})
    raise AssertionError(f"unexpected request: {method} {url}")


def test_select_persists_validated_model_and_dimension(monkeypatch):
    from backend.app.services import embedding_models

    saved: dict[str, object] = {}
    monkeypatch.setattr(embedding_models, "_load_settings_values", lambda: {})
    monkeypatch.setattr(
        embedding_models,
        "_save_settings_values",
        lambda values: saved.update(values) or dict(saved),
    )
    service = embedding_models.EmbeddingModelService(
        "http://ollama:11434",
        request=_request,
    )

    selected = service.select("new-embed")

    assert selected.model == "new-embed"
    assert selected.dimension == 3
    assert selected.collection_name == embedding_models.collection_name_for("new-embed", 3)
    assert saved == {
        "embedding_model_name": "new-embed",
        "embedding_model_dimension": 3,
    }


def test_select_rejects_model_that_cannot_embed_without_replacing_existing_selection(monkeypatch):
    from backend.app.services import embedding_models

    saved: dict[str, object] = {}

    def unavailable_request(method: str, url: str, **kwargs) -> _Response:
        if method == "GET":
            return _Response(200, {"models": [{"name": "chat-only", "details": {}}]})
        return _Response(404, {"error": "model does not support embeddings"})

    monkeypatch.setattr(
        embedding_models,
        "_load_settings_values",
        lambda: {"embedding_model_name": "working", "embedding_model_dimension": 1024},
    )
    monkeypatch.setattr(
        embedding_models,
        "_save_settings_values",
        lambda values: saved.update(values) or dict(saved),
    )
    service = embedding_models.EmbeddingModelService(
        "http://ollama:11434",
        request=unavailable_request,
    )

    with pytest.raises(embedding_models.EmbeddingModelValidationError):
        service.select("chat-only")

    assert saved == {}


def test_collection_identity_is_stable_and_model_scoped():
    from backend.app.services.embedding_models import collection_name_for

    assert collection_name_for("nomic-embed-text", 768) == collection_name_for("nomic-embed-text", 768)
    assert collection_name_for("nomic-embed-text", 768) != collection_name_for("mxbai-embed-large", 1024)
