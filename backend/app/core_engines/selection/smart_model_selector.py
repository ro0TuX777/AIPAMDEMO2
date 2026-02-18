"""
Smart Model Selector for AIPAM

Automatically selects the best LLM model based on query type and intent,
specialised for the forensic network analysis domain.

Model Selection Strategy:
- forensic_model:       Deep PCAP analysis, MITRE ATT&CK mapping, attack
                        chain reconstruction, anomaly investigation.
- classification_model: Flow-level traffic classification, malware family
                        detection, botnet identification.
- general_model:        Fallback for lightweight or general queries.

Adapted from SAM CoreEngines SmartModelSelector.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class ModelSelection:
    """Result of model selection."""

    model_name: str
    model_type: str  # 'forensic', 'classification', 'general'
    confidence: float
    reason: str

    @property
    def model_id(self) -> str:
        """Alias for model_name to support legacy code."""
        return self.model_name


class SmartModelSelector:
    """Intelligent model selector optimised for AIPAM forensic analysis.

    Chooses the correct model based on regex pattern matching against
    forensic-domain keywords. Dynamically loads model names from
    ``ModelConfigManager``.
    """

    # Default model configs (fallback if config unavailable)
    DEFAULT_MODELS: Dict[str, Dict[str, Any]] = {
        "forensic": {
            "name": "aipam-trafficllm-v4",
            "description": "Forensic reasoning LLM — deep analysis, MITRE mapping, attack chains",
            "strengths": [
                "pcap analysis", "mitre mapping", "attack chain reconstruction",
                "anomaly investigation", "kill chain", "threat hunting",
            ],
        },
        "classification": {
            "name": "aipam-trafficllm-v4",
            "description": "Traffic classification LLM — flow-level malware & botnet detection",
            "strengths": [
                "traffic classification", "malware detection", "botnet detection",
                "flow analysis", "packet inspection",
            ],
        },
        "general": {
            "name": "aipam-trafficllm-v4",
            "description": "General-purpose model for lightweight queries",
            "strengths": ["general chat", "simple queries", "quick responses"],
        },
    }

    # Runtime models (loaded from config)
    MODELS: Dict[str, Dict[str, Any]] = {}

    # ---- Pattern groups ----

    # Forensic reasoning patterns (highest priority)
    FORENSIC_PATTERNS = [
        # PCAP / forensic analysis
        r"\b(analyze|analyse|investigate|inspect)\s+(this\s+|the\s+)?(pcap|capture|traffic|network)\b",
        r"\b(forensic|forensics|incident\s+response|threat\s+hunt)\b",
        r"\b(attack\s+chain|kill\s+chain|attack\s+narrative|attack\s+path)\b",

        # MITRE ATT&CK
        r"\bmitre\b",
        r"\batt&ck\b",
        r"\b(technique|tactic|t[0-9]{4})\b",

        # Anomaly investigation
        r"\b(anomal|beacon|lateral\s+movement|exfiltrat|c2|command\s+and\s+control)\b",
        r"\b(suspicious|compromise|intrusion|adversar)\b",
        r"\b(zero[\-\s]?day|apt|advanced\s+persistent)\b",

        # Evidence reasoning
        r"\b(evidence|finding|rationale|confidence|severity)\b",
        r"\b(host\s+summary|flow\s+summary|alert\s+summary)\b",
    ]

    # Classification patterns (medium priority)
    CLASSIFICATION_PATTERNS = [
        r"\b(classif|detect|identif)\w*\s+(this\s+|the\s+)?(traffic|flow|packet|malware|botnet)\b",
        r"\b(malware|botnet|trojan|ransomware|worm|virus)\s+(family|type|detection|classification)\b",
        r"\b(flow[\-\s]?level|packet[\-\s]?level)\s+(classif|detect|analys)\b",
        r"\b(signature|pattern)\s+match\b",
        r"\b(encrypted\s+vpn|tor\s+traffic|web\s+attack)\s+detect\b",
        # Catch reversed word order: "classification of the traffic/flow/packets"
        r"\bclassification\s+of\s+(the\s+)?(traffic|flow|packet|malware)\w*\b",
    ]

    def __init__(self) -> None:
        self.selection_count = 0
        self.model_usage_stats: Dict[str, int] = {
            "forensic": 0,
            "classification": 0,
            "general": 0,
        }
        self._load_models_from_config()

        logger.info("SmartModelSelector initialized")
        for role, info in self.MODELS.items():
            logger.info("  %s: %s", role.capitalize(), info["name"])

    # ------------------------------------------------------------------
    # Configuration loading
    # ------------------------------------------------------------------

    def _load_models_from_config(self) -> None:
        """Load model names from ``ModelConfigManager``."""
        try:
            from ..config.model_config_manager import get_model_config_manager

            manager = get_model_config_manager()
            config = manager.load_config()

            self.MODELS = {
                "forensic": {
                    **self.DEFAULT_MODELS["forensic"],
                    "name": config.get("forensic_model", self.DEFAULT_MODELS["forensic"]["name"]),
                },
                "classification": {
                    **self.DEFAULT_MODELS["classification"],
                    "name": config.get(
                        "classification_model", self.DEFAULT_MODELS["classification"]["name"]
                    ),
                },
                "general": {
                    **self.DEFAULT_MODELS["general"],
                    "name": config.get("general_model", self.DEFAULT_MODELS["general"]["name"]),
                },
            }
            logger.info("Loaded models from configuration")

        except Exception as exc:
            logger.warning("Failed to load config, using defaults: %s", exc)
            self.MODELS = {k: dict(v) for k, v in self.DEFAULT_MODELS.items()}

    def reload_config(self) -> None:
        """Reload model configuration from ``ModelConfigManager``.

        Call this when the user changes model selection via the UI or API
        to immediately apply the new configuration.
        """
        logger.info("Reloading model configuration …")
        self._load_models_from_config()
        logger.info("Model configuration reloaded")

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def select_model(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
        task_type: Optional[str] = None,
    ) -> ModelSelection:
        """Select the optimal model for the given query or task.

        Args:
            query: User query string or task description.
            context: Optional context information.
            task_type: Explicit task type override — ``'forensic'``,
                ``'classification'``, or ``'general'``.

        Returns:
            ``ModelSelection`` with chosen model and reasoning.
        """
        self.selection_count += 1
        query_lower = (query or "").lower()

        # Priority 1: Explicit override
        if task_type and task_type in self.MODELS:
            logger.info(
                "Explicit task type '%s' — selecting %s",
                task_type, self.MODELS[task_type]["name"],
            )
            self.model_usage_stats[task_type] += 1
            return ModelSelection(
                model_name=self.MODELS[task_type]["name"],
                model_type=task_type,
                confidence=1.0,
                reason=f"Explicit task type override: {task_type}",
            )

        # Priority 2: Forensic reasoning patterns
        forensic_score = self._calculate_pattern_score(query_lower, self.FORENSIC_PATTERNS)
        if forensic_score > 0.3:
            logger.info(
                "Forensic task detected (score: %.2f) — selecting %s",
                forensic_score, self.MODELS["forensic"]["name"],
            )
            self.model_usage_stats["forensic"] += 1
            return ModelSelection(
                model_name=self.MODELS["forensic"]["name"],
                model_type="forensic",
                confidence=min(forensic_score, 1.0),
                reason=f"Forensic analysis query detected (confidence: {forensic_score:.2f})",
            )

        # Priority 3: Classification patterns
        classification_score = self._calculate_pattern_score(
            query_lower, self.CLASSIFICATION_PATTERNS
        )
        if classification_score > 0.3:
            logger.info(
                "Classification task detected (score: %.2f) — selecting %s",
                classification_score, self.MODELS["classification"]["name"],
            )
            self.model_usage_stats["classification"] += 1
            return ModelSelection(
                model_name=self.MODELS["classification"]["name"],
                model_type="classification",
                confidence=min(classification_score, 1.0),
                reason=f"Traffic classification query detected (confidence: {classification_score:.2f})",
            )

        # Priority 4: General fallback
        logger.info("General query detected — selecting %s", self.MODELS["general"]["name"])
        self.model_usage_stats["general"] += 1
        return ModelSelection(
            model_name=self.MODELS["general"]["name"],
            model_type="general",
            confidence=0.5,
            reason="General query — using default model",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_pattern_score(query: str, patterns: list) -> float:
        """Calculate a relevance score based on regex pattern matches."""
        score = 0.0
        matches = 0
        for pattern in patterns:
            if re.search(pattern, query, re.IGNORECASE):
                matches += 1
                score += 0.5
        if matches > 1:
            score += 0.3 * (matches - 1)
        return score

    def get_model_info(self, model_type: str) -> Dict[str, Any]:
        """Get information about a specific model type."""
        return self.MODELS.get(model_type, {})

    def get_usage_stats(self) -> Dict[str, Any]:
        """Get usage statistics for all models."""
        total = sum(self.model_usage_stats.values())
        return {
            "total_selections": self.selection_count,
            "model_usage": dict(self.model_usage_stats),
            "usage_percentages": {
                mt: (count / total * 100) if total > 0 else 0
                for mt, count in self.model_usage_stats.items()
            },
        }

    def override_model(self, model_type: str) -> Optional[str]:
        """Manually override model selection by role.

        Returns:
            Model name if valid role, ``None`` otherwise.
        """
        info = self.MODELS.get(model_type)
        return info["name"] if info else None


# ------------------------------------------------------------------
# Global accessor
# ------------------------------------------------------------------

_selector_instance: Optional[SmartModelSelector] = None


def get_model_selector() -> SmartModelSelector:
    """Get or create the global ``SmartModelSelector`` instance."""
    global _selector_instance
    if _selector_instance is None:
        _selector_instance = SmartModelSelector()
    return _selector_instance
