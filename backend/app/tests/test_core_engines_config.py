"""Tests for app/core_engines/config/model_config_manager.py."""

from __future__ import annotations

import configparser
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.core_engines.config.model_config_manager import (
    ModelConfig,
    ModelConfigManager,
    get_model_config_manager,
)


# -------------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------------


@pytest.fixture()
def conf_dir(tmp_path: Path) -> Path:
    """Create a temporary models.conf and return its path."""
    conf = tmp_path / "models.conf"
    conf.write_text(
        """\
[embedding_model]
name = "sentence-transformers/all-MiniLM-L6-v2"
provider = "ollama"
embedding_dimension = 384

[llm_model]
provider = "ollama"
api_url = "http://localhost:11434"
default_model = "aipam-trafficllm-v4"
smart_selection = true
forensic_model = "aipam-trafficllm-v4"
classification_model = "aipam-trafficllm-v4"
general_model = "aipam-trafficllm-v4"

[model_settings]
max_context_length = 4096
temperature = 0.1
max_tokens = 2000
timeout_seconds = 600
"""
    )
    return conf


@pytest.fixture()
def manager(conf_dir: Path) -> ModelConfigManager:
    """Return a fresh ``ModelConfigManager`` pointing at the temp config."""
    ModelConfigManager._reset_instance()
    return ModelConfigManager(config_path=conf_dir)


# -------------------------------------------------------------------------
# Tests
# -------------------------------------------------------------------------


class TestLoadConfig:
    """Loading and default behaviour."""

    def test_load_config_from_file(self, manager: ModelConfigManager) -> None:
        config = manager.load_config()
        assert config["forensic_model"] == "aipam-trafficllm-v4"
        assert config["classification_model"] == "aipam-trafficllm-v4"
        assert config["general_model"] == "aipam-trafficllm-v4"
        assert config["temperature"] == 0.1
        assert config["max_tokens"] == 2000
        assert config["timeout_seconds"] == 600

    def test_load_config_defaults_when_missing(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent" / "models.conf"
        mgr = ModelConfigManager(config_path=missing)
        config = mgr.load_config()
        assert config["forensic_model"] == "aipam-trafficllm-v4"
        assert config["smart_selection"] is True

    def test_embedding_config(self, manager: ModelConfigManager) -> None:
        config = manager.load_config()
        assert config["embedding_model"] == "sentence-transformers/all-MiniLM-L6-v2"
        assert config["embedding_dimension"] == 384


class TestSaveConfig:
    """Saving configuration round-trip."""

    def test_save_and_reload(self, manager: ModelConfigManager) -> None:
        manager.save_config({
            "forensic_model": "deepseek-r1:32b",
            "classification_model": "aipam-trafficllm-v4",
        })

        reloaded = manager.load_config()
        assert reloaded["forensic_model"] == "deepseek-r1:32b"
        # Classification unchanged
        assert reloaded["classification_model"] == "aipam-trafficllm-v4"


class TestOllamaAPI:
    """Ollama API queries (mocked)."""

    def test_validate_model_available(self, manager: ModelConfigManager) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "models": [
                {"name": "aipam-trafficllm-v4", "size": 4_000_000_000,
                 "details": {"family": "llama", "parameter_size": "8B"}},
            ]
        }

        with patch("app.core_engines.config.model_config_manager.httpx.Client") as mock_client:
            mock_client.return_value.__enter__ = MagicMock(return_value=MagicMock(get=MagicMock(return_value=mock_resp)))
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            assert manager.validate_model("aipam-trafficllm-v4") is True

    def test_validate_model_unavailable(self, manager: ModelConfigManager) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"models": []}

        with patch("app.core_engines.config.model_config_manager.httpx.Client") as mock_client:
            mock_client.return_value.__enter__ = MagicMock(return_value=MagicMock(get=MagicMock(return_value=mock_resp)))
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            assert manager.validate_model("nonexistent-model") is False


class TestSingleton:
    """Singleton accessor."""

    def test_get_instance_returns_same(self, conf_dir: Path) -> None:
        ModelConfigManager._reset_instance()
        a = ModelConfigManager.get_instance(conf_dir)
        b = ModelConfigManager.get_instance(conf_dir)
        assert a is b
        ModelConfigManager._reset_instance()


class TestCurrentSelection:
    """Role → ModelConfig mapping."""

    def test_get_current_selection_structure(self, manager: ModelConfigManager) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "models": [
                {"name": "aipam-trafficllm-v4", "size": 4_000_000_000,
                 "details": {"family": "llama", "parameter_size": "8B"}},
            ]
        }

        with patch("app.core_engines.config.model_config_manager.httpx.Client") as mock_client:
            mock_client.return_value.__enter__ = MagicMock(return_value=MagicMock(get=MagicMock(return_value=mock_resp)))
            mock_client.return_value.__exit__ = MagicMock(return_value=False)

            selection = manager.get_current_selection()

            assert "forensic" in selection
            assert isinstance(selection["forensic"], ModelConfig)
            assert selection["forensic"].model_name == "aipam-trafficllm-v4"
            assert selection["forensic"].is_available is True
