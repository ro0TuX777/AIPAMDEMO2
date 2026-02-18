"""
Model Configuration Manager for AIPAM

Provides unified model configuration management for the Core Engines
module. Synchronizes models.conf with runtime model selection and
manages Ollama model lifecycle (load, unload, switch).

Adapted from SAM CoreEngines for AIPAM's forensic analysis domain.
"""

from __future__ import annotations

import configparser
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class ModelConfig:
    """Configuration for a specific model role."""

    model_name: str
    role: str  # 'forensic', 'classification', 'general', 'default', 'embedding'
    is_available: bool
    family: Optional[str] = None
    size: Optional[str] = None
    parameter_count: Optional[str] = None


class ModelConfigManager:
    """Manages unified model configuration across AIPAM.

    Responsibilities:
    - Load/save ``models.conf``
    - Query Ollama for available models
    - Validate model availability
    - Thread-safe configuration updates
    - Model load/unload/switch lifecycle

    Usage::

        manager = get_model_config_manager()
        config = manager.load_config()
        manager.switch_model("deepseek-r1:32b", old_model="aipam-trafficllm-v4")
    """

    _instance: Optional["ModelConfigManager"] = None
    _lock = threading.Lock()

    def __init__(self, config_path: Optional[Path] = None) -> None:
        if config_path is None:
            config_path = Path(__file__).parent / "models.conf"

        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self._ollama_cache: Optional[List[Dict[str, Any]]] = None
        self._cache_timestamp: float = 0
        self._cache_ttl: int = 60  # seconds

        logger.info("ModelConfigManager initialized with config: %s", self.config_path)

    @classmethod
    def get_instance(cls, config_path: Optional[Path] = None) -> "ModelConfigManager":
        """Get or create singleton instance (thread-safe)."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(config_path)
        return cls._instance

    @classmethod
    def _reset_instance(cls) -> None:
        """Reset singleton — used by tests only."""
        with cls._lock:
            cls._instance = None

    # ------------------------------------------------------------------
    # Configuration I/O
    # ------------------------------------------------------------------

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from ``models.conf``.

        Returns:
            Dictionary with model configuration fields.
        """
        try:
            if not self.config_path.exists():
                logger.warning("Config file not found: %s — using defaults", self.config_path)
                return self._get_default_config()

            self.config.read(self.config_path)

            config_dict: Dict[str, Any] = {
                # LLM models
                "default_model": self.config.get(
                    "llm_model", "default_model", fallback="aipam-trafficllm-v4"
                ).strip('"'),
                "forensic_model": self.config.get(
                    "llm_model", "forensic_model", fallback="aipam-trafficllm-v4"
                ).strip('"'),
                "classification_model": self.config.get(
                    "llm_model", "classification_model", fallback="aipam-trafficllm-v4"
                ).strip('"'),
                "general_model": self.config.get(
                    "llm_model", "general_model", fallback="aipam-trafficllm-v4"
                ).strip('"'),
                "embedding_model": self.config.get(
                    "embedding_model", "name", fallback="sentence-transformers/all-MiniLM-L6-v2"
                ).strip('"'),
                "embedding_dimension": self.config.getint(
                    "embedding_model", "embedding_dimension", fallback=384
                ),
                # Ollama settings
                "api_url": self.config.get(
                    "llm_model", "api_url", fallback="http://localhost:11434"
                ).strip('"'),
                "smart_selection": self.config.getboolean(
                    "llm_model", "smart_selection", fallback=True
                ),
                # Model settings
                "max_context_length": self.config.getint(
                    "model_settings", "max_context_length", fallback=4096
                ),
                "temperature": self.config.getfloat(
                    "model_settings", "temperature", fallback=0.1
                ),
                "max_tokens": self.config.getint(
                    "model_settings", "max_tokens", fallback=2000
                ),
                "timeout_seconds": self.config.getint(
                    "model_settings", "timeout_seconds", fallback=600
                ),
            }

            logger.info(
                "Loaded model configuration — Forensic: %s, Classification: %s, General: %s",
                config_dict["forensic_model"],
                config_dict["classification_model"],
                config_dict["general_model"],
            )

            return config_dict

        except Exception as exc:
            logger.error("Error loading config: %s", exc)
            return self._get_default_config()

    def save_config(self, config: Dict[str, str]) -> bool:
        """Save configuration to ``models.conf``.

        Args:
            config: Dictionary with model names for each role.

        Returns:
            True if saved successfully.
        """
        try:
            with self._lock:
                if self.config_path.exists():
                    self.config.read(self.config_path)

                # Ensure sections exist
                for section in ("llm_model", "embedding_model", "model_settings"):
                    if not self.config.has_section(section):
                        self.config.add_section(section)

                # Map of config keys → INI (section, key)
                key_map = {
                    "forensic_model": ("llm_model", "forensic_model"),
                    "classification_model": ("llm_model", "classification_model"),
                    "general_model": ("llm_model", "general_model"),
                    "default_model": ("llm_model", "default_model"),
                    "embedding_model": ("embedding_model", "name"),
                }

                for key, (section, ini_key) in key_map.items():
                    if key in config:
                        self.config.set(section, ini_key, f'"{config[key]}"')

                with open(self.config_path, "w") as fh:
                    self.config.write(fh)

                logger.info("Saved model configuration to models.conf")
                return True

        except Exception as exc:
            logger.error("Error saving config: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Ollama API
    # ------------------------------------------------------------------

    def get_ollama_models(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """Get list of available models from Ollama.

        Results are cached for ``_cache_ttl`` seconds.

        Args:
            force_refresh: Bypass cache.

        Returns:
            List of model info dicts.
        """
        now = time.time()
        if not force_refresh and self._ollama_cache and (now - self._cache_timestamp) < self._cache_ttl:
            return self._ollama_cache

        try:
            config = self.load_config()
            api_url = config.get("api_url", "http://localhost:11434")

            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{api_url}/api/tags")

            if resp.status_code == 200:
                data = resp.json()
                models = []
                for m in data.get("models", []):
                    models.append({
                        "name": m.get("name"),
                        "size": m.get("size", 0),
                        "modified": m.get("modified_at"),
                        "family": m.get("details", {}).get("family", "Unknown"),
                        "parameter_size": m.get("details", {}).get("parameter_size", "N/A"),
                        "quantization": m.get("details", {}).get("quantization_level", "Unknown"),
                    })

                self._ollama_cache = models
                self._cache_timestamp = now
                logger.info("Found %d models in Ollama", len(models))
                return models
            else:
                logger.error("Ollama API returned status %d", resp.status_code)
                return []

        except Exception as exc:
            logger.error("Error fetching Ollama models: %s", exc)
            return []

    def validate_model(self, model_name: str) -> bool:
        """Check if a model is available in Ollama."""
        models = self.get_ollama_models()
        return any(m["name"] == model_name for m in models)

    def get_model_details(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific model."""
        for m in self.get_ollama_models():
            if m["name"] == model_name:
                return m
        return None

    # ------------------------------------------------------------------
    # Model Lifecycle
    # ------------------------------------------------------------------

    def check_model_status(self, model_name: str) -> Dict[str, Any]:
        """Check if a model is currently loaded in Ollama memory."""
        try:
            config = self.load_config()
            api_url = config.get("api_url", "http://localhost:11434")

            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{api_url}/api/ps")

            if resp.status_code == 200:
                for m in resp.json().get("models", []):
                    if m.get("name") == model_name:
                        return {
                            "loaded": True,
                            "size": m.get("size", "Unknown"),
                            "size_vram": m.get("size_vram", 0),
                            "modified": m.get("modified_at", "Unknown"),
                        }
            return {"loaded": False}

        except Exception as exc:
            logger.error("Error checking model status: %s", exc)
            return {"loaded": False, "error": str(exc)}

    def get_active_models(self) -> List[Dict[str, Any]]:
        """Get list of currently loaded models."""
        try:
            config = self.load_config()
            api_url = config.get("api_url", "http://localhost:11434")

            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{api_url}/api/ps")

            if resp.status_code == 200:
                models = resp.json().get("models", [])
                logger.info("Found %d active models", len(models))
                return models
            return []

        except Exception as exc:
            logger.error("Error getting active models: %s", exc)
            return []

    def load_model(self, model_name: str, keep_alive: int = -1) -> bool:
        """Load a model into Ollama memory.

        Args:
            model_name: Name of the model to load.
            keep_alive: -1 = forever, 0 = unload immediately.
        """
        try:
            config = self.load_config()
            api_url = config.get("api_url", "http://localhost:11434")

            logger.info("Loading model: %s", model_name)

            with httpx.Client(timeout=120.0) as client:
                resp = client.post(
                    f"{api_url}/api/generate",
                    json={"model": model_name, "prompt": "", "keep_alive": keep_alive, "stream": False},
                )

            if resp.status_code == 200:
                logger.info("Model loaded: %s", model_name)
                return True
            else:
                logger.error("Failed to load model %s: %d", model_name, resp.status_code)
                return False

        except Exception as exc:
            logger.error("Error loading model %s: %s", model_name, exc)
            return False

    def unload_model(self, model_name: str) -> bool:
        """Unload a model from Ollama memory."""
        try:
            config = self.load_config()
            api_url = config.get("api_url", "http://localhost:11434")

            # Check if model is actually active before attempting unload
            status = self.check_model_status(model_name)
            if not status.get("loaded"):
                logger.info("Model %s is not currently active. Skipping unload.", model_name)
                return True

            logger.info("Unloading model: %s", model_name)

            with httpx.Client(timeout=30.0) as client:
                resp = client.post(
                    f"{api_url}/api/generate",
                    json={"model": model_name, "prompt": "", "keep_alive": 0, "stream": False},
                )

            if resp.status_code == 200:
                logger.info("Model unloaded: %s", model_name)
                return True
            elif resp.status_code == 404:
                logger.warning("Model %s not found by Ollama (404). Treating as unloaded.", model_name)
                return True
            else:
                logger.error("Failed to unload model %s: %d", model_name, resp.status_code)
                return False

        except Exception as exc:
            logger.error("Error unloading model %s: %s", model_name, exc)
            return False

    def switch_model(
        self, new_model: str, old_model: Optional[str] = None
    ) -> Dict[str, Any]:
        """Switch from one model to another with automatic load/unload.

        Args:
            new_model: Model to load.
            old_model: Model to unload (optional).

        Returns:
            Dict with ``success``, ``new_model_loaded``,
            ``old_model_unloaded``, and ``message``.
        """
        result: Dict[str, Any] = {
            "success": False,
            "new_model_loaded": False,
            "old_model_unloaded": False,
            "message": "",
        }

        try:
            if not self.validate_model(new_model):
                result["message"] = f"Model '{new_model}' not found in Ollama"
                return result

            logger.info("Switching to model: %s", new_model)
            if self.load_model(new_model):
                result["new_model_loaded"] = True

                time.sleep(2)

                status = self.check_model_status(new_model)
                if not status.get("loaded"):
                    result["message"] = f"Model {new_model} loaded but not showing as active"
                    return result

                if old_model and old_model != new_model:
                    if self.unload_model(old_model):
                        result["old_model_unloaded"] = True
                    else:
                        result["message"] = f"Loaded {new_model} but failed to unload {old_model}"
                        result["success"] = True  # partial success
                        return result

                result["success"] = True
                result["message"] = f"Successfully switched to {new_model}"
                logger.info("Model switch complete: %s", new_model)
                return result
            else:
                result["message"] = f"Failed to load {new_model}"
                return result

        except Exception as exc:
            result["message"] = f"Error during switch: {exc}"
            logger.error("Model switch failed: %s", exc)
            return result

    # ------------------------------------------------------------------
    # Role Selection
    # ------------------------------------------------------------------

    def get_current_selection(self) -> Dict[str, ModelConfig]:
        """Get current model selection with availability status.

        Returns:
            Dictionary mapping role name → ``ModelConfig``.
        """
        config = self.load_config()
        models = self.get_ollama_models()
        model_map = {m["name"]: m for m in models}

        result: Dict[str, ModelConfig] = {}
        for role in ("forensic", "classification", "general", "embedding", "default"):
            key = "embedding_model" if role == "embedding" else f"{role}_model"
            model_name = config.get(key, "")

            if model_name:
                is_available = model_name in model_map
                info = model_map.get(model_name, {})
                result[role] = ModelConfig(
                    model_name=model_name,
                    role=role,
                    is_available=is_available,
                    family=info.get("family"),
                    size=info.get("parameter_size"),
                    parameter_count=info.get("parameter_size"),
                )

        return result

    # ------------------------------------------------------------------
    # Defaults
    # ------------------------------------------------------------------

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration when models.conf is missing."""
        return {
            "default_model": "aipam-trafficllm-v4",
            "forensic_model": "aipam-trafficllm-v4",
            "classification_model": "aipam-trafficllm-v4",
            "general_model": "aipam-trafficllm-v4",
            "embedding_model": "sentence-transformers/all-MiniLM-L6-v2",
            "embedding_dimension": 384,
            "api_url": "http://localhost:11434",
            "smart_selection": True,
            "max_context_length": 4096,
            "temperature": 0.1,
            "max_tokens": 2000,
            "timeout_seconds": 600,
        }


# ------------------------------------------------------------------
# Global accessor
# ------------------------------------------------------------------

_manager_instance: Optional[ModelConfigManager] = None


def get_model_config_manager(config_path: Optional[Path] = None) -> ModelConfigManager:
    """Get or create global ``ModelConfigManager`` instance."""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = ModelConfigManager.get_instance(config_path)
    return _manager_instance
