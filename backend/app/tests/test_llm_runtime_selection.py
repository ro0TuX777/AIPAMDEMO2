from __future__ import annotations


def test_chat_uses_saved_ollama_runtime_when_no_external_llm_endpoint(monkeypatch):
    from backend.app.api import chat
    from backend.app.config_v2 import Settings

    monkeypatch.setenv("LLM_ENDPOINT", "http://legacy-ollama:11434/v1/chat/completions")
    monkeypatch.setattr(
        chat,
        "get_runtime_llm_endpoint",
        lambda default_url, fallback_endpoint: "http://host.docker.internal:7777/v1/chat/completions",
    )

    client = chat._make_llm_client(
        Settings(aipam_api_token="test-token", aipam_ollama_url="http://ollama:11434")
    )

    assert client.config.endpoint == "http://host.docker.internal:7777/v1/chat/completions"


def test_saved_ollama_url_overrides_legacy_llm_endpoint(monkeypatch):
    from backend.app.services import embedding_models

    monkeypatch.setattr(
        embedding_models,
        "_load_settings_values",
        lambda: {"ollama_base_url": "http://host.docker.internal:7777"},
    )

    assert embedding_models.get_runtime_llm_endpoint(
        "http://ollama:11434", "http://legacy-ollama:11434/v1/chat/completions"
    ) == "http://host.docker.internal:7777/v1/chat/completions"


def test_saved_llm_base_url_is_normalized_to_chat_endpoint(monkeypatch):
    from backend.app.services import embedding_models

    monkeypatch.setattr(
        embedding_models,
        "_load_settings_values",
        lambda: {"llm_endpoint": "http://host.docker.internal:7777"},
    )

    assert embedding_models.get_runtime_llm_endpoint("http://ollama:11434") == (
        "http://host.docker.internal:7777/v1/chat/completions"
    )


def test_chat_uses_model_saved_in_settings(monkeypatch):
    from backend.app.api import chat
    from backend.app.config_v2 import Settings

    monkeypatch.setattr(chat, "get_runtime_llm_model", lambda default_model: "gemma3:12b")

    client = chat._make_llm_client(
        Settings(aipam_api_token="test-token", aipam_ollama_url="http://ollama:11434")
    )

    assert client.config.model == "gemma3:12b"


def test_llm_model_falls_back_to_forensic_role_selection(monkeypatch):
    from backend.app.services import embedding_models

    monkeypatch.setattr(
        embedding_models,
        "_load_settings_values",
        lambda: {"forensic_model_name": "qwen3:8b"},
    )

    assert embedding_models.get_runtime_llm_model("deployment-default") == "qwen3:8b"
