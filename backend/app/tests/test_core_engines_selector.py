"""Tests for app/core_engines/selection/smart_model_selector.py."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from backend.app.core_engines.selection.smart_model_selector import (
    ModelSelection,
    SmartModelSelector,
)


# -------------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------------


@pytest.fixture()
def selector() -> SmartModelSelector:
    """SmartModelSelector using default models (no config file needed)."""
    with patch(
        "backend.app.core_engines.config.model_config_manager.get_model_config_manager",
        side_effect=ImportError("no config in test"),
    ):
        sel = SmartModelSelector()
    return sel


# -------------------------------------------------------------------------
# Tests
# -------------------------------------------------------------------------


class TestForensicRouting:
    """Forensic-domain queries route to the forensic model."""

    @pytest.mark.parametrize(
        "query",
        [
            "Analyze this PCAP for C2 beaconing",
            "Investigate the network traffic for lateral movement",
            "Map findings to MITRE ATT&CK technique T1071",
            "What does the attack chain look like?",
            "Run forensic analysis on the capture",
            "Check for anomalies and suspicious flows",
        ],
    )
    def test_forensic_queries(self, selector: SmartModelSelector, query: str) -> None:
        result = selector.select_model(query)
        assert result.model_type == "forensic", f"Expected forensic for '{query}', got {result.model_type}"
        assert result.confidence > 0.3


class TestClassificationRouting:
    """Classification-domain queries route to the classification model."""

    @pytest.mark.parametrize(
        "query",
        [
            "Classify this traffic as malware or benign",
            "Detect botnet traffic in these flows",
            "Identify the malware family for this traffic",
            "Flow-level classification of the packets",
        ],
    )
    def test_classification_queries(self, selector: SmartModelSelector, query: str) -> None:
        result = selector.select_model(query)
        assert result.model_type == "classification", (
            f"Expected classification for '{query}', got {result.model_type}"
        )
        assert result.confidence > 0.3


class TestGeneralFallback:
    """Non-forensic, non-classification queries fall back to general."""

    @pytest.mark.parametrize(
        "query",
        [
            "What time is it?",
            "Tell me a joke",
            "How do I configure my editor?",
        ],
    )
    def test_general_queries(self, selector: SmartModelSelector, query: str) -> None:
        result = selector.select_model(query)
        assert result.model_type == "general"
        assert result.confidence == 0.5


class TestExplicitOverride:
    """Explicit task_type bypasses pattern matching."""

    def test_override_forensic(self, selector: SmartModelSelector) -> None:
        result = selector.select_model("hello", task_type="forensic")
        assert result.model_type == "forensic"
        assert result.confidence == 1.0

    def test_override_classification(self, selector: SmartModelSelector) -> None:
        result = selector.select_model("hello", task_type="classification")
        assert result.model_type == "classification"

    def test_override_invalid_falls_through(self, selector: SmartModelSelector) -> None:
        result = selector.select_model("hello", task_type="nonexistent")
        # Should fall through to pattern matching / general
        assert result.model_type == "general"


class TestUsageStats:
    """Usage counters increment correctly."""

    def test_stats_tracking(self, selector: SmartModelSelector) -> None:
        selector.select_model("analyze this pcap for C2")
        selector.select_model("classify this traffic")
        selector.select_model("what time is it?")

        stats = selector.get_usage_stats()
        assert stats["total_selections"] == 3
        assert stats["model_usage"]["forensic"] >= 1
        assert stats["model_usage"]["general"] >= 1


class TestReloadConfig:
    """Config reload changes model names in subsequent selections."""

    def test_reload_updates_models(self) -> None:
        mock_manager = MagicMock()
        mock_manager.load_config.return_value = {
            "forensic_model": "deepseek-r1:32b",
            "classification_model": "aipam-trafficllm-v4",
            "general_model": "llama3.2:3b",
        }

        with patch(
            "backend.app.core_engines.config.model_config_manager.get_model_config_manager",
            return_value=mock_manager,
        ):
            sel = SmartModelSelector()

        assert sel.MODELS["forensic"]["name"] == "deepseek-r1:32b"
        assert sel.MODELS["general"]["name"] == "llama3.2:3b"

        # Simulate config change
        mock_manager.load_config.return_value["forensic_model"] = "new-forensic-model:70b"
        with patch(
            "backend.app.core_engines.config.model_config_manager.get_model_config_manager",
            return_value=mock_manager,
        ):
            sel.reload_config()

        assert sel.MODELS["forensic"]["name"] == "new-forensic-model:70b"


class TestModelSelection:
    """ModelSelection dataclass."""

    def test_model_id_alias(self) -> None:
        ms = ModelSelection(
            model_name="test-model", model_type="forensic",
            confidence=0.9, reason="test",
        )
        assert ms.model_id == ms.model_name
