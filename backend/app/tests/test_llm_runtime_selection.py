from __future__ import annotations


def test_chat_uses_saved_ollama_runtime_when_no_external_llm_endpoint(monkeypatch):
    from backend.app.api import chat
    from backend.app.config_v2 import Settings

    monkeypatch.delenv("LLM_ENDPOINT", raising=False)
    monkeypatch.setattr(
        chat,
        "get_runtime_ollama_url",
        lambda default_url: "http://host.docker.internal:7777",
    )

    client = chat._make_llm_client(
        Settings(aipam_api_token="test-token", aipam_ollama_url="http://ollama:11434")
    )

    assert client.config.endpoint == "http://host.docker.internal:7777/v1/chat/completions"


def test_chat_uses_model_saved_in_settings(monkeypatch):
    from backend.app.api import chat
    from backend.app.config_v2 import Settings

    monkeypatch.setattr(chat, "get_runtime_llm_model", lambda default_model: "gemma3:12b")

    client = chat._make_llm_client(
        Settings(aipam_api_token="test-token", aipam_ollama_url="http://ollama:11434")
    )

    assert client.config.model == "gemma3:12b"
