from __future__ import annotations

import asyncio

from backend.app.config_v2 import Settings
from backend.app.services.embedding_models import EmbeddingModelConfig


def _settings() -> Settings:
    return Settings(aipam_api_token="test-token", aipam_ollama_url="http://ollama:11434")


def test_select_endpoint_returns_validated_model(monkeypatch):
    from backend.app.api import system
    from backend.app.schemas.system import EmbeddingModelSelectRequest

    config = EmbeddingModelConfig("new-embed", 768, "aipam_kb_newembed")

    class Service:
        def select(self, model: str):
            assert model == "new-embed"
            return config

    monkeypatch.setattr(system, "_embedding_service", lambda settings: Service())

    response = asyncio.run(
        system.select_embedding_model(EmbeddingModelSelectRequest(model="new-embed"), _settings())
    )

    assert response.model == "new-embed"
    assert response.dimension == 768
    assert response.collection_name == "aipam_kb_newembed"


def test_pull_endpoint_tracks_background_download(monkeypatch):
    from fastapi import BackgroundTasks

    from backend.app.api import system
    from backend.app.schemas.system import EmbeddingModelPullRequest

    background = BackgroundTasks()
    monkeypatch.setattr(system, "_embedding_service", lambda settings: object())
    system._embedding_pull_states.clear()

    response = asyncio.run(
        system.pull_embedding_model(
            EmbeddingModelPullRequest(model="new-embed"),
            background,
            _settings(),
        )
    )

    assert response.model == "new-embed"
    assert response.status == "starting"
    assert len(background.tasks) == 1


def test_embedding_runtime_endpoint_persists_custom_ollama_url(monkeypatch):
    from backend.app.api import system
    from backend.app.schemas.system import OllamaRuntimeConfigRequest

    from backend.app.services import embedding_models

    monkeypatch.setattr(embedding_models, "set_runtime_ollama_url", lambda url: url.rstrip("/"))

    response = asyncio.run(
        system.save_embedding_runtime(
            OllamaRuntimeConfigRequest(ollama_url="http://ollama-host:12567/"),
            _settings(),
        )
    )

    assert response.ollama_url == "http://ollama-host:12567"
