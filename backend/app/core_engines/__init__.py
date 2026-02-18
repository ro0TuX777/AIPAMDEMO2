"""Core Engines — Reusable Model-Switching Framework for AIPAM.

Provides role-based model configuration, Ollama lifecycle management,
and smart query routing for forensic analysis models.

Usage::

    from app.core_engines import get_model_config_manager, get_model_selector

    # Get config manager (singleton)
    manager = get_model_config_manager()
    config = manager.load_config()

    # Select model by query
    selector = get_model_selector()
    result = selector.select_model("Analyze this PCAP for C2 beaconing")
    print(result.model_name)   # → forensic model
    print(result.model_type)   # → "forensic"
"""

from .config.model_config_manager import ModelConfigManager, get_model_config_manager
from .selection.smart_model_selector import SmartModelSelector, get_model_selector

__all__ = [
    "ModelConfigManager",
    "get_model_config_manager",
    "SmartModelSelector",
    "get_model_selector",
]
